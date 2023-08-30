// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause
/*
  libaslrmalloc is a LD_PRELOADed library which replaces malloc() and
  other memory allocation functions from C library. The main design
  goal is not performance or memory consumption but to increase
  address space layout randomization (ASLR), hence the name. This is
  achieved by not trying to keep the pages together, forcing the
  kernel to map pages at random addresses and unmapping old memory
  immediately when possible.

  Compile as a shared library:
    gcc -o libaslrmalloc.so libaslrmalloc.c -fPIC -Wall -g -nostdlib -shared -O
  or as a test program:
    gcc -o test libaslrmalloc.c -Wall -g -DDEBUG=1
  or to verify that libc malloc agrees with the test suite:
    gcc -o test libaslrmalloc.c -Wall -g -DDEBUG=1 -DLIBC

  Usage:
    LD_PRELOAD=/path/to/libaslrmalloc.so program
*/

// Fill character for free()d memory
#define FILL_JUNK 'Z'

#if !LIBC
#if DEBUG
#define malloc xmalloc
#define malloc_usable_size xmalloc_usable_size
#define free xfree
#define calloc xcalloc
#define realloc xrealloc
#define reallocarray xreallocarray
#define posix_memalign xposix_memalign
#define aligned_alloc xaligned_alloc
/* Flawfinder: ignore */
#define memalign xmemalign
#define valloc xvalloc
#define pvalloc xpvalloc
#endif // DEBUG
#endif // !LIBC

// For secure_getenv()
#define _GNU_SOURCE
#include <assert.h>
#include <cpuid.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/random.h>
#include <unistd.h>

#include "config.h"
#if !LIBC
// TODO assumes page size of 4096
#define PAGE_BITS 12
#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(size) (((size) + (PAGE_SIZE - 1)) & PAGE_MASK)

// TODO assumes 64 bit longs
#define ULONG_BITS 6
#define ULONG_SIZE (1 << ULONG_BITS)
#define ULONG_MASK (~(ULONG_SIZE - 1))
#define ULONG_ALIGN_UP(size) (((size) + (ULONG_SIZE - 1)) & ULONG_MASK)

#define BITS_PER_BYTE 8

// Avoid addresses within ±32MB of stack
#define STACK_ZONE (32 * 1024 * 1024)
// Avoid addresses in lowest 1MB
#define LOW_ZONE (1 * 1024 * 1024)

#define MIN_ALLOC_BITS 4
#define MIN_ALLOC_SIZE (1 << MIN_ALLOC_BITS)
#define MIN_ALLOC_MASK (~(MIN_ALLOC_SIZE - 1))

#define MAX_SIZE_CLASSES (PAGE_BITS - MIN_ALLOC_BITS)

// Worst case: one bit for each smallest item (MIN_ALLOC_SIZE) per page
#define BITMAP_ULONGS (PAGE_SIZE / MIN_ALLOC_SIZE / ULONG_SIZE)

/*
  small_pagelist is used for allocating small (16 ... 2048) byte
  slabs.
*/
struct small_pagelist {
	void *page; // Must be first
	unsigned int index;
	unsigned long bitmap[BITMAP_ULONGS];
	unsigned long access_randomizer_state;
};

/*
  internal_pagelist is used for allocating page tables for internal
  use.
*/
// TODO Internal page tables could also use multi level page table
// approach to speed up `pagetable_free()`.
struct internal_pagelist {
	struct small_pagelist s; // page must be first
	struct internal_pagelist *next, *prev;
};

/*
  large_pagelist is used for allocating multiples of page size blocks.
*/
struct large_pagelist {
	void *page; // Must be first
	size_t size;
};

/*
  Each middle table contains MID_PAGE_SIZE number of pointers to small
  or large pagelists, or further middle tables. The table is indexed
  by bits of the address (like CPU page tables) and the type of an
  entry is identified by low bits of the address. Leaf entries can
  exist at any level.
 */
#define MIDDLE_PAGE_BITS 6
#define MIDDLE_PAGE_SIZE (1UL << MIDDLE_PAGE_BITS)
#define MIDDLE_PAGE_MASK (~(MIDDLE_PAGE_SIZE - 1))

#define MIDDLE_PAGE_TYPE_MASK ~3UL
#define MIDDLE_PAGE_TYPE_MIDDLE 0
#define MIDDLE_PAGE_TYPE_SMALL 1
#define MIDDLE_PAGE_TYPE_LARGE 2

union pagelist;
struct middle_page_table {
	union pagelist *table[MIDDLE_PAGE_SIZE];
};

union pagelist {
	struct middle_page_table m;
	struct small_pagelist s;
	struct large_pagelist l;
};

/*
  Global state for the library.
*/
struct malloc_state {
	struct internal_pagelist *pagetables;
	struct internal_pagelist *middle_pagetables;
	union pagelist *small_pages[MAX_SIZE_CLASSES];
	union pagelist *large_pages;
	union pagelist *all_pages;
	unsigned long small_count[MAX_SIZE_CLASSES];
	unsigned long large_count;
};
static struct malloc_state *state;

static pthread_mutex_t malloc_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long malloc_random_address_mask;
static int malloc_getrandom_bytes;
static int malloc_user_va_space_bits;

// Runtime options
static bool malloc_debug;
static bool malloc_debug_stats;
static char malloc_fill_junk = FILL_JUNK;
static bool malloc_passthrough;
static bool malloc_strict_malloc0;
static bool malloc_strict_posix_memalign_errno;

static void *(*libc_malloc)(size_t);
static size_t (*libc_malloc_usable_size)(void *);
static void (*libc_free)(void *);
static void *(*libc_calloc)(size_t, size_t);
static void *(*libc_realloc)(void *, size_t);
static void *(*libc_reallocarray)(void *, size_t, size_t);
static int (*libc_posix_memalign)(void **, size_t, size_t);
static void *(*libc_aligned_alloc)(size_t, size_t);
static void *(*libc_memalign)(size_t, size_t);
static void *(*libc_valloc)(size_t);
static void *(*libc_pvalloc)(size_t);

static union pagelist *pagetable_new(struct internal_pagelist **pagetable,
				     size_t size);
static void pagetable_free(struct internal_pagelist **pagetable,
			   union pagelist *entry);

#define DPRINTF(format, ...)                                                 \
	do {                                                                 \
		if (malloc_debug) {                                          \
			/* Flawfinder: ignore */			     \
			char _buf[1024];                                     \
			/* Flawfinder: ignore */			     \
			int _r = snprintf(_buf, sizeof(_buf), "%s: " format, \
					  __FUNCTION__, ##__VA_ARGS__);      \
			if (_r > 0)                                          \
				_r = write(2, _buf, _r);                     \
			(void)_r;                                            \
		}                                                            \
	} while (0)

#define DPRINTF_NOPREFIX(format, ...)                                 \
	do {                                                          \
		if (malloc_debug) {                                   \
			/* Flawfinder: ignore */		      \
			char _buf[1024];                              \
			/* Flawfinder: ignore */		      \
			int _r = snprintf(_buf, sizeof(_buf), format, \
					  ##__VA_ARGS__);             \
			if (_r > 0)                                   \
				_r = write(2, _buf, _r);              \
			(void)_r;                                     \
		}                                                     \
	} while (0)

#if DEBUG_BITMAPS
#define DPRINTF_BM DPRINTF
#else
#define DPRINTF_BM(format, ...) do { } while (0)
#endif

// TODO Maybe the guard pages could be even larger than one page, for
// example fill the entire 2MB page table entry, especially for large
// allocations. If they hold a small number of large items (as opposed
// to large number of small items), a small guard may not be enough.
static unsigned long get_guard_size(size_t size) {
	return PAGE_SIZE;
}

/*
  Get needed random bytes, never giving up.
*/
static void get_random(void *data, size_t bytes) {
	for (;;) {
		ssize_t r = getrandom(data, bytes, GRND_RANDOM);
		if (r == bytes)
			return;
	}
}

/*
  Randomize within [start ... end], inclusive.
*/
static unsigned int randomize_int(unsigned int start, unsigned int end) {
	unsigned int randomizer;
	get_random(&randomizer, sizeof(randomizer));
	return start + randomizer % (end - start + 1);
}

// TODO: possibly use MAP_HUGETLB | MAP_HUGE_2MB in case the alignment
// is already that high
/*
  map pages at a random address, possibly aligned more strictly.
  MAP_FIXED_NOREPLACE is used to avoid already existing mappings. If
  that happens (errno == EEXIST), retry,
*/
static void *mmap_random(size_t size, unsigned long extra_mask) {
	unsigned long stack = (unsigned long)__builtin_frame_address(0);
	unsigned long guard_size = get_guard_size(size);
	for (;;) {
		unsigned long addr;
		get_random(&addr, malloc_getrandom_bytes);

		addr <<= PAGE_BITS;
		addr &= malloc_random_address_mask & extra_mask;

		/*
		  Don't exceed VA space, get too close to the stack
		  or try use too low addresses.
		*/
		if (addr + size + guard_size > (1ULL << malloc_user_va_space_bits) ||
		    (addr + size + guard_size >= stack - STACK_ZONE &&
		     addr - guard_size <= stack + STACK_ZONE) ||
		    addr < LOW_ZONE)
			continue;

		addr -= guard_size;

		void *ret = mmap((void *)addr, size + 2 * guard_size,
				 PROT_READ | PROT_WRITE,
				 MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_PRIVATE,
				 -1, 0);
		if (ret == MAP_FAILED) {
			/*
			  Sadly mmap() can return ENOMEM in case the
			  address supplied exceeds VA space, so this
			  isn't 100% watertight, but we try hard above
			  not to give such addresses to kernel.
			*/
			if (errno == ENOMEM)
				return ret;
			continue;
		}

		unsigned long lower_guard = (unsigned long)ret;
		int r = mprotect((void *)lower_guard, guard_size, PROT_NONE);
		if (r < 0) {
			perror("mprotect lower guard");
			abort();
		}

		unsigned long higher_guard = (unsigned long)ret + guard_size +
			size;
		r = mprotect((void *)higher_guard, guard_size, PROT_NONE);
		if (r < 0) {
			perror("mprotect higher guard");
			abort();
		}

		ret = (void *)((unsigned long)ret + guard_size);
		DPRINTF("returning %p, guard pages at %lx+%lu, %lx+%lu\n", ret,
			lower_guard, guard_size, higher_guard, guard_size);
		return ret;
	}
}

/*
  Find a slab class suitable for the size of the (small) allocation.
*/
static unsigned int get_index(size_t size) {
	for (unsigned int index = MIN_ALLOC_BITS; index < PAGE_BITS; index++)
		if (size <= (1UL << index))
			return index - MIN_ALLOC_BITS;
	return -1;
}

/*
  Index for a slab at the end of page, used for managing the page itself.
*/
static unsigned int last_index(size_t size) {
	for (unsigned int index = MIN_ALLOC_BITS; index < PAGE_BITS; index++)
		if (size <= (1UL << index))
			return (PAGE_SIZE / (1UL << index)) - 1;
	abort();
}

/*
  Get size aligned up to suitable slab size (all powers of 2 from 16 up to
  page size).
*/
static unsigned int align_up_size(size_t size) {
	for (unsigned int index = MIN_ALLOC_BITS; index < PAGE_BITS; index++)
		if (size <= (1UL << index))
			return 1UL << index;
	abort();
}

/*
  Get number of bits in a bitmap: number of slabs in one complete page.
*/
static unsigned int bitmap_bits(size_t size) {
	return PAGE_SIZE / align_up_size(size);
}


// Get a bit from bitmap.
static int bitmap_bit(unsigned long *bitmap, unsigned int bit) {
	return !!(bitmap[bit >> ULONG_BITS] & (1UL << (bit & ~ULONG_MASK)));
}

/*
  Set bit in bitmap: indicates that the slab is in use.
*/
static void bitmap_set(unsigned long *bitmap, unsigned int bit) {
	assert(bitmap_bit(bitmap, bit) == 0);
	bitmap[bit >> ULONG_BITS] |= 1UL << (bit & ~ULONG_MASK);
}

/*
  Clear bit in bitmap: slab is free.
*/
static void bitmap_clear(unsigned long *bitmap, unsigned int bit) {
	assert(bitmap_bit(bitmap, bit) == 1);
	bitmap[bit >> ULONG_BITS] &= ~(1UL << (bit & ~ULONG_MASK));
}

// TODO Use cryptographically secure, but perfect (no collisions) hash
// or randomization function
// https://en.wikipedia.org/wiki/Cryptographically-secure_pseudorandom_number_generator
// https://en.wikipedia.org/wiki/Perfect_hash_function
// https://en.wikipedia.org/wiki/Randomization_function
/*
  Scramble bitmap index. Given an index, maximum index number and
  state, the function computes a pseudorandomized index. The goal is
  that, given an address of an allocated memory block, it's impossible
  to determine addresses of previous or future allocations in the same
  slab page without knowing the secret (which is not in the same
  page). This is also helped by having a separate state for each slab
  page. Of course the number of entries in a page is always very
  small.
*/
static unsigned int scramble_index(unsigned int index, unsigned int max,
				   unsigned long access_randomizer_state) {
	assert(max > 0);
	unsigned int ret = (index + access_randomizer_state) % max;
	DPRINTF_BM("scrambled %u -> %u (max %u state %lx)\n", index, ret, max,
		   access_randomizer_state);
	return ret;
}

/*
  Find a clear (free slab) bit in the bitmap. Not all words in the
  bitmap are used in full.
*/
static int bitmap_find_clear(const unsigned long *bitmap,
			     unsigned int bitmap_bits,
			     unsigned long access_randomizer_state) {
	DPRINTF_BM("bitmap_bits %u (%u words)\n", bitmap_bits,
		   bitmap_bits >> ULONG_BITS);

	for (unsigned int bit = 0; bit < bitmap_bits; bit++) {
		unsigned int scrambled_bit = scramble_index(
			bit, bitmap_bits, access_randomizer_state);

		unsigned int word_index = scrambled_bit >> ULONG_BITS;
		unsigned int bit_index = scrambled_bit & ~ULONG_MASK;
		unsigned long mask = (unsigned long)-1;
		if (bitmap_bits - (scrambled_bit & ULONG_MASK) < ULONG_SIZE)
			mask = (1UL
				<< (bitmap_bits - (scrambled_bit & ULONG_MASK))) -
				1;
		unsigned long word = bitmap[word_index] & mask;

		DPRINTF_BM("checking index %u+%u word %lx mask %lx bit %d "
			   "(original %d) bits left %d\n",
			   word_index, bit_index, word, mask, scrambled_bit, bit,
			   bitmap_bits - scrambled_bit);
		if ((word & (1UL << bit_index)) == 0) {
			DPRINTF_BM("returning %d\n", scrambled_bit);
			return scrambled_bit;
		}
	}
	DPRINTF_BM("returning -1\n");
	return -1;
}

/*
  Check if all bits in the bitmap are clear. Not all words in the
  bitmap are used in full.
*/
static bool bitmap_is_empty(const unsigned long *bitmap,
			    unsigned int bitmap_bits) {
	DPRINTF_BM("bitmap_bits %u (%u words)\n", bitmap_bits,
		bitmap_bits >> ULONG_BITS);

	for (unsigned int b = 0; b < bitmap_bits; b += 1 << ULONG_BITS) {
		unsigned int i = b >> ULONG_BITS;
		unsigned long mask = (unsigned long)-1;

		if (bitmap_bits - b < ULONG_SIZE)
			mask = (1UL << (bitmap_bits - b)) - 1;
		unsigned long word = bitmap[i] & mask;

		DPRINTF_BM("checking index %u word %lx mask %lx bits left %d\n", i,
			word, mask, bitmap_bits - b);
		if (word != 0) {
			DPRINTF_BM("returning false\n");
			return false;
		}
	}
	DPRINTF_BM("returning true\n");
	return true;
}

/*
  Given a page, size class index of a slab and the number of the
  position of the slab, return an address in the page.
*/
static void *ptr_to_offset_in_page(void *page, unsigned int size_index, int num) {
	assert(size_index <= MAX_SIZE_CLASSES);
	unsigned long offset = (1UL << (size_index + MIN_ALLOC_BITS)) * (unsigned long)num;
	unsigned long address = ((unsigned long)page) + offset;
	DPRINTF("offsetting page %p size index %u (0x%x) item number "
		"%d -> 0x%lx\n",
		page, size_index, 1 << (size_index + MIN_ALLOC_BITS), num,
		address);
	return (void *)address;
}

/*
  Dump one table entry.
*/
static void middle_table_dump(const union pagelist *midptr, const char *label,
			      int search_bits, unsigned long addr) {
	if (!midptr)
		return;

	assert(search_bits >= MIN_ALLOC_BITS);

	switch ((unsigned long)midptr & ~MIDDLE_PAGE_TYPE_MASK) {
	case MIDDLE_PAGE_TYPE_MIDDLE:
		unsigned int count = 0;
		for (unsigned int i = 0; i < MIDDLE_PAGE_SIZE; i++)
			if (midptr->m.table[i]) {
				count++;
				unsigned long lower_addr = addr |
					(unsigned long)i <<
					(search_bits - MIDDLE_PAGE_BITS);
				DPRINTF("%s: middle page %p [%u] (0x%lx): %p\n",
					label, &midptr->m.table[i], i, lower_addr,
					midptr->m.table[i]);
				middle_table_dump(midptr->m.table[i], label,
						  search_bits - MIDDLE_PAGE_BITS,
						  lower_addr);
			}
		assert(count != 0);
		break;
	case MIDDLE_PAGE_TYPE_SMALL: {
		const struct small_pagelist *p = (const struct small_pagelist *)
			((unsigned long)midptr & MIDDLE_PAGE_TYPE_MASK);
		DPRINTF("%s: small page (%p) .page=%p .index=%u .rnd=%lx bm=",
			label, p, p->page, p->index,
			p->access_randomizer_state);
		for (unsigned int i = 0; i < BITMAP_ULONGS; i++)
			DPRINTF_NOPREFIX("%lx ", p->bitmap[i]);
		DPRINTF_NOPREFIX("\n");
		break;
	}
	case MIDDLE_PAGE_TYPE_LARGE: {
		const struct large_pagelist *p = (const struct large_pagelist *)
			((unsigned long)midptr & MIDDLE_PAGE_TYPE_MASK);
		DPRINTF("%s: large page (%p) .page=%p .size=%lx\n", label,
			p, p->page, p->size);
		break;
	}
	}
}

/*
  Insert an entry into table based on the related address.
*/
static void middle_table_insert(union pagelist **midptr, union pagelist *entry,
				void *ptr, int search_bits, int type) {
	assert(midptr);
	assert(search_bits >= MIN_ALLOC_BITS);

	if (!*midptr) {
		*midptr = (void*)((unsigned long)entry | type);
		DPRINTF("Replaced NULL entry at %p with %p\n",
			midptr, *midptr);
		return;
	}

	int old_type = (unsigned long)*midptr & ~MIDDLE_PAGE_TYPE_MASK;
	switch (old_type) {
	case MIDDLE_PAGE_TYPE_MIDDLE: {
		unsigned int i = ((unsigned long)ptr >>
				  (search_bits - MIDDLE_PAGE_BITS))
			& ~MIDDLE_PAGE_MASK;
		DPRINTF("Recursing into middle page %p [%u]\n",
			*midptr, i);
		middle_table_insert(&((*midptr)->m.table[i]), entry, ptr,
				    search_bits - MIDDLE_PAGE_BITS, type);
		break;
	}
	case MIDDLE_PAGE_TYPE_SMALL:
	case MIDDLE_PAGE_TYPE_LARGE: {
		// Need to insert a new middle page
		union pagelist *new = pagetable_new(&state->middle_pagetables,
						    sizeof(struct middle_page_table));
		union pagelist *old = (union pagelist *)((unsigned long)*midptr &
							 MIDDLE_PAGE_TYPE_MASK);
		memset(new, 0, sizeof(struct middle_page_table));
		*midptr = new;
		DPRINTF("Replacing existing middle page %p (.page %p) with %p (.page %p)\n",
			old, old->s.page, new, ptr);
		middle_table_insert(midptr, old, old->s.page, search_bits, old_type);
		middle_table_insert(midptr, entry, ptr, search_bits, type);
		break;
	}
	}
}

/*
  Delete an entry from a table based on the related address.
*/
static void middle_table_delete(union pagelist **midptr, unsigned long address,
				int search_bits) {
	assert(midptr);
	assert(search_bits >= MIN_ALLOC_BITS);

	DPRINTF("Delete checking middle page %p from %p address %lx search_bits %d\n",
		*midptr, midptr, address, search_bits);

	if (!*midptr)
		return;

	int type = (unsigned long)*midptr & ~MIDDLE_PAGE_TYPE_MASK;
	switch (type) {
	case MIDDLE_PAGE_TYPE_MIDDLE: {
		unsigned int i = (address >> (search_bits - MIDDLE_PAGE_BITS))
			& ~MIDDLE_PAGE_MASK;
		DPRINTF("Delete recursing into middle page %p [%u]\n",
			*midptr, i);
		middle_table_delete(&((*midptr)->m.table[i]), address,
				    search_bits - MIDDLE_PAGE_BITS);

		unsigned int count = 0;
		union pagelist *found = NULL;
		for (i = 0; i < MIDDLE_PAGE_SIZE; i++)
			if ((*midptr)->m.table[i]) {
				count++;
				found = (*midptr)->m.table[i];
			}

		if (count > 1) {
			DPRINTF("Middle page %p still has %u entries\n",
			        *midptr, count);
			return;
		}
		if (count == 1) {
			DPRINTF("Replacing middle page %p with %p\n",
			        *midptr, found);
			pagetable_free(&state->middle_pagetables, *midptr);
			*midptr = found;
			return;
		}
		// All empty, let's delete the middle table
		DPRINTF("Freeing page table %p\n", *midptr);
		pagetable_free(&state->middle_pagetables, *midptr);
		break;
	}
	case MIDDLE_PAGE_TYPE_SMALL:
	case MIDDLE_PAGE_TYPE_LARGE: {
		DPRINTF("Setting middle page %p to NULL\n", *midptr);
		*midptr = NULL;
		break;
	}
	}
}

/*
  Find an entry in the table based on the related address.
*/
static union pagelist **middle_table_find(union pagelist **midptr,
					  unsigned long address,
					  int search_bits) {
	assert(midptr);
	DPRINTF("Finding at %p address %lx\n",
		*midptr, address & ~((1 << search_bits) - 1));
	if (!*midptr || search_bits < MIDDLE_PAGE_BITS) {
		DPRINTF("Middle page %p is NULL or ran out of search bits %d\n",
			*midptr, search_bits);
		return NULL;
	}

	switch ((unsigned long)*midptr & ~MIDDLE_PAGE_TYPE_MASK) {
	case MIDDLE_PAGE_TYPE_MIDDLE: {
		unsigned int i = (address >> (search_bits - MIDDLE_PAGE_BITS))
			& ~MIDDLE_PAGE_MASK;
		DPRINTF("Trying middle page %p [%u] with new search bits %d\n",
			&((*midptr)->m.table[i]), i, search_bits - MIDDLE_PAGE_BITS);
		return middle_table_find(&((*midptr)->m.table[i]), address,
					 search_bits - MIDDLE_PAGE_BITS);
	}
	case MIDDLE_PAGE_TYPE_SMALL:
	case MIDDLE_PAGE_TYPE_LARGE: {
		DPRINTF("Found middle page %p with search bits %d\n",
			*midptr, search_bits);
		return midptr;
	}
	}
	return NULL;
}

/*
  Return true to stop iterating.
*/
typedef bool (middle_table_iterator_fn)(union pagelist *entry, void *data);

/*
  Iterate the non-empty entries of a table using callback.
*/
static bool middle_table_iterate(union pagelist *midptr,
				 middle_table_iterator_fn *cb, void *data) {
	if (!midptr)
		return false;

	switch ((unsigned long)midptr & ~MIDDLE_PAGE_TYPE_MASK) {
	case MIDDLE_PAGE_TYPE_MIDDLE:
		for (unsigned int i = 0; i < MIDDLE_PAGE_SIZE; i++)
			if (midptr->m.table[i])
				if (middle_table_iterate(midptr->m.table[i], cb, data))
					return true;
		break;
	case MIDDLE_PAGE_TYPE_SMALL:
	case MIDDLE_PAGE_TYPE_LARGE: {
		union pagelist *p = (union pagelist *)
			((unsigned long)midptr & MIDDLE_PAGE_TYPE_MASK);
		return (cb(p, data));
	}
	}
	return false;
}

struct small_page_find_cb_data {
	/* in */
	const unsigned int index;
	const unsigned long extra_mask;
	const size_t size;
	const size_t real_size;
	/* out */
	void *alloc_start, *ret;
};

/*
  Callback for allocating small pages.
*/
static bool small_page_find_cb(union pagelist *p, void *data) {
	struct small_page_find_cb_data *s = data;

	if ((unsigned long)p->s.page & ~s->extra_mask)
		return false;

	int offset = bitmap_find_clear(p->s.bitmap, bitmap_bits(s->real_size),
				       p->s.access_randomizer_state);
	if (offset < 0)
		return false;

	DPRINTF("found offset %d ptr %p index %u (want %u)\n",
		offset, p->s.page, p->s.index, s->index);
	assert(p->s.index == s->index);

	void *ret = ptr_to_offset_in_page(p->s.page, s->index, offset);

	bitmap_set(p->s.bitmap, offset);
	/*
	  Randomize start of for example 1600 byte allocation with 32
	  byte alignment in a 2048 byte slab
	*/
	unsigned int align_bits = __builtin_ctzl(s->extra_mask & MIN_ALLOC_MASK);
	unsigned long page_offset = 0;
	if (align_bits < (s->index + MIN_ALLOC_BITS)) {
		unsigned long slack = (s->real_size - s->size) >> align_bits;
		if (slack) {
			page_offset = randomize_int(0, slack) << align_bits;
			DPRINTF("randomized %p with offset %lu (%lu positions, %d bits)\n",
				ret, page_offset, slack, align_bits);
		}
	}
	s->alloc_start = ret;
	s->ret = (void *)((unsigned long)ret + page_offset);
	return true;
}

/*
  Dump all pagetables for debugging.
*/
static void pagetables_dump(const char *label) {
	if (!malloc_debug || malloc_passthrough)
		return;

	unsigned int count;
	struct internal_pagelist *p;
	for (p = state->pagetables, count = 0; p; p = p->next, count++) {
		DPRINTF("%s: pagetables (%p) [%u] .page=%p .index=%u rnd=%lx bm=",
			label, p, count, p->s.page, p->s.index,
			p->s.access_randomizer_state);
		for (int i = 0; i < BITMAP_ULONGS; i++)
			DPRINTF_NOPREFIX("%lx ", p->s.bitmap[i]);
		DPRINTF_NOPREFIX("\n");
	}

	for (p = state->middle_pagetables, count = 0; p; p = p->next, count++) {
		DPRINTF("%s: middle_pagetables (%p) [%u] .page=%p .index=%u rnd=%lx bm=",
			label, p, count, p->s.page, p->s.index,
			p->s.access_randomizer_state);
		for (int i = 0; i < BITMAP_ULONGS; i++)
			DPRINTF_NOPREFIX("%lx ", p->s.bitmap[i]);
		DPRINTF_NOPREFIX("\n");
	}

	DPRINTF("small_pages\n");
	for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++)
		middle_table_dump(state->small_pages[i], label,
				  malloc_user_va_space_bits, 0);

	DPRINTF("large_pages\n");
	middle_table_dump(state->large_pages, label, malloc_user_va_space_bits, 0);

	DPRINTF("all_pages\n");
	middle_table_dump(state->all_pages, label, malloc_user_va_space_bits, 0);
}

/*
  Allocate a page table entry for internal use from dedicated page
  table slabs.
*/
static union pagelist *pagetable_new(struct internal_pagelist **pagetable,
				     size_t size) {
	union pagelist *ret;

	unsigned int index = get_index(size);
	for (;;) {
		for (struct internal_pagelist *p = *pagetable; p; p = p->next) {
			int offset = bitmap_find_clear(
				p->s.bitmap, bitmap_bits(size),
				p->s.access_randomizer_state);

			if (offset >= 0) {
				ret = ptr_to_offset_in_page(p->s.page, index,
							    offset);
				bitmap_set(p->s.bitmap, offset);
				goto found;
			}
		}

		// No free entries found, let's allocate a new page.
		void *page = mmap_random(PAGE_SIZE, -1);
		if (page == MAP_FAILED)
			goto oom;

		struct internal_pagelist *new;
		if (pagetable == &state->pagetables) {
			/*
			  Page is managed by taking a piece of it for
			  internal_pagelist. Mark allocation for the
			  page table entry for managing the page
			  itself in the bitmap.
			*/
			// TODO offset could be randomized instead of last index
			int offset = last_index(size);
			new = ptr_to_offset_in_page(page, index, offset);
			bitmap_set(new->s.bitmap, offset);
			new->s.index = index;
		} else {
			/*
			  Page is managed with separate internal_pagelist.
			*/
			new = (struct internal_pagelist *)
				pagetable_new(&state->pagetables,
					      sizeof(struct internal_pagelist));
			if (!new) {
				munmap(page, PAGE_SIZE);
				goto oom;
			}
			memset(new->s.bitmap, 0, sizeof(new->s.bitmap));
			new->s.index = index;
		}

		new->s.page = page;
		get_random(&new->s.access_randomizer_state,
			   sizeof(new->s.access_randomizer_state));
		new->next = *pagetable;
		DPRINTF("new pagetable %p page %p rnd %lx\n", new, new->s.page,
			new->s.access_randomizer_state);
		// New page is inserted at head of list, retry.
		*pagetable = new;
	}

found:
	DPRINTF("returning %p\n", ret);
	return ret;
oom:
	return NULL;
}

/*
  Free a page table entry.
*/
static void pagetable_free(struct internal_pagelist **pagetable,
			   union pagelist *entry) {
	DPRINTF("*pagetable %p (from pagetable %p), entry %p\n", *pagetable, pagetable, entry);
	for (struct internal_pagelist *p = *pagetable, *prev = p; p;
	     prev = p, p = p->next) {
		DPRINTF("checking %p .page=%p bm=%lx\n", p, p->s.page, p->s.bitmap[0]);
		if (((unsigned long)p->s.page & PAGE_MASK) ==
		    ((unsigned long)entry & PAGE_MASK)) {
			// Calculate the number of the entry for its address
			// using the size class
			unsigned int bit = ((unsigned long)entry & ~PAGE_MASK) >>
				(p->s.index + MIN_ALLOC_BITS);
			DPRINTF("found match %p == %p, clearing bit %u "
				"(index %d)\n",
				entry, p->s.page, bit, p->s.index);
			bitmap_clear(p->s.bitmap, bit);

			size_t check_entries;
			if (pagetable == &state->pagetables)
				check_entries = last_index(sizeof(struct internal_pagelist));
			else
				/* The last entry can be also used,
				   it's not used for managing the
				   page, so add one */
				check_entries = last_index(1 << (p->s.index + MIN_ALLOC_BITS)) + 1;

			DPRINTF("check_entries %zu vs index %d\n", check_entries, p->s.index);
			if (bitmap_is_empty(p->s.bitmap, check_entries)) {
				DPRINTF("bitmap is empty at %p\n", p);
				unsigned long guard_size = get_guard_size(PAGE_SIZE);
				DPRINTF("unmap pagetable %p (guards %lu)\n",
					p->s.page, guard_size);
				/*
				  Grab next entry pointer before the
				  page is unmapped.
				*/
				struct internal_pagelist *next = p->next;
				int r = munmap((void *)((unsigned long)p->s.page -
							guard_size),
					       PAGE_SIZE + 2 * guard_size);
				if (r < 0) {
					perror("munmap");
					abort();
				}
				if (prev == p)
					*pagetable = next;
				else
					prev->next = next;
				if (pagetable != &state->pagetables)
					pagetable_free(&state->pagetables, (union pagelist *)p);
			} else
				DPRINTF("bitmap isn't empty at %p\n", p);
			return;
		}
	}
	fprintf(stderr, "pagetable_free: %p not found!\n", entry);
	abort();
}

static void is_yes(const char *str, bool *ret) {
	if (strcmp(str, "1") == 0 ||
	    strcmp(str, "y") == 0 ||
	    strcmp(str, "yes") == 0 ||
	    strcmp(str, "true") == 0) {
		*ret = true;
		DPRINTF("checking y/n for '%s' -> true\n", str);
	} else if (strcmp(str, "0") == 0 ||
		   strcmp(str, "n") == 0 ||
		   strcmp(str, "no") == 0 ||
		   strcmp(str, "false") == 0) {
		*ret = false;
		DPRINTF("checking y/n for '%s' -> false\n", str);
	}
}

// Macro because of sizeof(str)
#define CHECK_OPTION(line, str, ptr)					\
	if (strncmp(line, str, sizeof(str) - 1) == 0) 			\
		is_yes(&line[sizeof(str) - 1], ptr)

static void check_env(const char *name, bool *ret) {
	char *value = secure_getenv(name);
	DPRINTF("checking env %s: '%s'\n", name, value);
	if (value)
		is_yes(value, ret);
}

static void init_from_profile(const char *prefix) {
	int r;
	/* Flawfinder: ignore */
	char profile_path[PATH_MAX];
	int profile_file;
	/* Flawfinder: ignore */
	char profile_data[2048];
	r = snprintf(
		profile_path,
		sizeof(profile_path),
		"%s/libaslrmalloc/profiles/%s.profile",
		prefix,
		program_invocation_short_name
	);
	if (r < 0 || r > sizeof(profile_path))
		return;
	/* Flawfinder: ignore */
	profile_file = open(profile_path, O_RDONLY);
	if (profile_file == -1) {
		// Read default profile instead
		r = snprintf(
			     profile_path,
			     sizeof(profile_path),
			     "%s/libaslrmalloc/default.profile",
			     prefix
			     );
		if (r < 0 || r > sizeof(profile_path))
			return;
		/* Flawfinder: ignore */
		profile_file = open(profile_path, O_RDONLY);
		if (profile_file == -1)
			return;
	}

	/* Flawfinder: ignore */
	r = read(profile_file, profile_data, sizeof(profile_data));
	if (r == -1 || r == sizeof(profile_data)) {
		close(profile_file);
		return;
	}
	profile_data[r] = '\0';
	close(profile_file);

	char *saveptr = NULL;
	char *line = strtok_r(profile_data, "\n", &saveptr);
	if (NULL == line)
		return;
	do {
		DPRINTF("checking profile line %s\n", line);
		if (*line == '#')
			continue;
		else CHECK_OPTION(line, "debug=", &malloc_debug);
		else CHECK_OPTION(line, "passthrough=", &malloc_passthrough);
		else CHECK_OPTION(line, "stats=", &malloc_debug_stats);
		else CHECK_OPTION(line, "strict_malloc0=", &malloc_strict_malloc0);
		else CHECK_OPTION(line, "strict_posix_memalign_errno=",
				  &malloc_strict_posix_memalign_errno);
		else if (strncmp(line, "fill_junk=", sizeof("fill_junk=") - 1) == 0)
			malloc_fill_junk = line[sizeof("fill_junk=") - 1];

	} while ((line = strtok_r(NULL, "\n", &saveptr)));
}

/*
  Load a profile named `app.profile` using the name of the
  application. The profiles are loaded from directories
  `/usr/lib/libaslrmalloc/profiles` (distro),
  `/etc/libaslrmalloc/profiles` (local admin), and if the program
  isn't setuid or setgid, $XDG_CONFIG_HOME/libaslrmalloc/profiles (or
  $HOME/.config/libaslrmalloc/profiles).

  If an application specific profile doesn't exist, 'default.profile'
  is loaded instead from the directories, but dropping path component
  'profiles': `/usr/lib/libaslrmalloc/default.profile` and so forth.
*/
static void init_from_profiles(void) {
	init_from_profile(LIBDIR);
	init_from_profile(SYSCONFDIR);
	if (!getauxval(AT_SECURE) &&
	    geteuid() == getuid() && getegid() == getgid()) {
		/* Flawfinder: ignore */
		const char *xdg_config = getenv("XDG_CONFIG_HOME");
		if (xdg_config)
			init_from_profile(xdg_config);
		else {
			/* Flawfinder: ignore */
			const char *home = getenv("HOME");
			if (home) {
				/* Flawfinder: ignore */
				char home_config[PATH_MAX];
				snprintf(home_config, sizeof(home_config),
					 "%s/.config", home);
				init_from_profile(home_config);
			}
		}
	}
#ifdef PROFILE_DIR
	init_from_profile(PROFILE_DIR);
#endif
}

/*
  dlsym() calls calloc(), so let's use a temporary version.
*/
static void *temp_calloc(size_t nmemb, size_t size) {
	/* Flawfinder: ignore */
	static char buf[256];
	static int bufidx;
	void *ret = &buf[bufidx];
	bufidx += size;
	assert(bufidx < sizeof(buf));
	return ret;
}

/*
  Initialization of the global state.

  We need to allocate at least
  - global state
  - pagelist for the initial page
*/
static __attribute__((constructor)) void init(void) {
	/*
	  Despite using the ELF constructor, the library may be used
	  (perhaps by other libraries' constructors) earlier. Ignore
	  later calls.
	*/
	if (state)
		return;

	int saved_errno = errno;

	init_from_profiles();

	check_env("LIBASLRMALLOC_DEBUG", &malloc_debug);
	check_env("LIBASLRMALLOC_PASSTHROUGH", &malloc_passthrough);
	check_env("LIBASLRMALLOC_STATS", &malloc_debug_stats);
	check_env("LIBASLRMALLOC_STRICT_MALLOC0", &malloc_strict_malloc0);
	check_env("LIBASLRMALLOC_STRICT_POSIX_MEMALIGN_ERRNO",
		  &malloc_strict_posix_memalign_errno);

	char *junk = secure_getenv("LIBASLRMALLOC_FILL_JUNK");
	if (junk)
		malloc_fill_junk = *junk;

	if (malloc_passthrough) {
		libc_calloc = temp_calloc;
		libc_calloc = dlsym(RTLD_NEXT, "calloc");
		libc_malloc = dlsym(RTLD_NEXT, "malloc");
		libc_malloc_usable_size = dlsym(RTLD_NEXT, "malloc_usable_size");
		libc_free = dlsym(RTLD_NEXT, "free");
		libc_realloc = dlsym(RTLD_NEXT, "realloc");
		libc_reallocarray = dlsym(RTLD_NEXT, "reallocarray");
		libc_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
		libc_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
		libc_memalign = dlsym(RTLD_NEXT, "memalign");
		libc_valloc = dlsym(RTLD_NEXT, "valloc");
		libc_pvalloc = dlsym(RTLD_NEXT, "pvalloc");

		if (
			libc_malloc == NULL
			|| libc_malloc_usable_size == NULL
			|| libc_free == NULL
			|| libc_calloc == NULL
			|| libc_realloc == NULL
			|| libc_reallocarray == NULL
			|| libc_posix_memalign == NULL
			|| libc_aligned_alloc == NULL
			|| libc_memalign == NULL
			|| libc_valloc == NULL
			|| libc_pvalloc == NULL
		)
			abort();

		state = (void *) -1L;
		errno = saved_errno;
		return;
	}

	/*
	   Get number of virtual address bits with CPUID
	   instruction. There are lots of different values from 36 to
	   57 (https://en.wikipedia.org/wiki/X86).
	 */
	unsigned int eax, unused;
	int r = __get_cpuid(0x80000008, &eax, &unused, &unused, &unused);

	/*
	  Calculate a mask for requesting random addresses so that the
	  kernel should accept them.
	*/
	malloc_user_va_space_bits = 36;
	if (r == 1)
		malloc_user_va_space_bits = ((eax >> 8) & 0xff);
	malloc_user_va_space_bits--;
	malloc_random_address_mask = ((1UL << malloc_user_va_space_bits) - 1) &
		PAGE_MASK;

	// Also calculate number of random bytes needed for each address
	malloc_getrandom_bytes = (malloc_user_va_space_bits - PAGE_BITS + 7) / 8;

	/*
	  A temporary bitmap is used to store allocation of the first
	  page for global state and initial internal page tables. This
	  will be moved to the actual internal page table later.
	*/
	unsigned long temp_bitmap = 0;

	/*
	  Allocate a slab page for global state and initial internal
	  pagetables. The global state is an exception for slab use
	  because it occupies multiple slabs. It will never be freed,
	  so this is OK (unless the global state should be freed in
	  the rare case of all allocations get freed).
	*/
	void *pagetables = mmap_random(PAGE_SIZE, -1);
	if (pagetables == MAP_FAILED)
		abort();

	/*
	  Select random slabs for the state. Exclude last index, used
	  below for internal use.
	*/
	int pages_index = get_index(sizeof(struct internal_pagelist));
	unsigned int last_offset = last_index(sizeof(struct internal_pagelist));
	unsigned int num_slabs = align_up_size(sizeof(*state)) /
		align_up_size(sizeof(struct internal_pagelist));
	unsigned int offset = randomize_int(0, last_offset - 1 - num_slabs);
	state = ptr_to_offset_in_page(pagetables, pages_index, offset);

	// Mark slab allocation for global state in the bitmap.
	for (unsigned int i = offset; i < offset + num_slabs; i++)
		bitmap_set(&temp_bitmap, i);

	// Mark allocation for initial internal page tables in the bitmap.
	// TODO offset could be randomized instead of last index
	bitmap_set(&temp_bitmap, last_offset);
	state->pagetables = ptr_to_offset_in_page(pagetables, pages_index,
						  last_offset);
	state->pagetables->s.page = pagetables;
	state->pagetables->s.index = pages_index;
	get_random(&state->pagetables->s.access_randomizer_state,
		   sizeof(state->pagetables->s.access_randomizer_state));
	// Copy temporary bitmap
	state->pagetables->s.bitmap[0] = temp_bitmap;

	DPRINTF("%d VA space bits, mask %16.16lx, getrandom() bytes %d\n",
		malloc_user_va_space_bits, malloc_random_address_mask,
		malloc_getrandom_bytes);
	DPRINTF("main state at %p +%zu\n", state, sizeof(*state));
	pagetables_dump("initial");
	errno = saved_errno;
}

static __attribute__((destructor)) void fini(void) {
	if (!state) {
		DPRINTF("destructor called before constructor\n");
		return;
	}

	if (!malloc_debug || malloc_passthrough)
		return;

	if (malloc_debug_stats) {
		pagetables_dump("final");
		// Output as TSV
		fprintf(stderr, "Size\tCount\n");
		for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++)
			fprintf(stderr, "%d\t%ld\n", 1 << (i + MIN_ALLOC_BITS),
				state->small_count[i]);
		fprintf(stderr, "%d\t%ld\n", PAGE_SIZE, state->large_count);
	}
}

static void *aligned_malloc(size_t size, size_t alignment) {
	int ret_errno = errno;
	void *ret = NULL;

	if (!state)
		init();

	DPRINTF("aligned_malloc(%lu, %lu)\n", size, alignment);

	/*
	  The manual page says that malloc(0) may return NULL but
	  sadly some applications expect it to return accessible
	  memory and Glibc does that.
	*/
	if (size == 0) {
		if (malloc_strict_malloc0)
			goto finish;
		else
			size = 1;
	}

	if (size >= (1UL << malloc_user_va_space_bits) ||
	    alignment >= (1UL << malloc_user_va_space_bits)) {
		ret_errno = ENOMEM;
		goto finish;
	}

	// Get slab size class for the requested size.
	unsigned long extra_mask = ~(alignment - 1);
	unsigned int index = get_index(MAX(size, alignment));
	size_t real_size;
	void *alloc_start;

	pthread_mutex_lock(&malloc_lock);
	if (index == (unsigned int)-1) {
		// New large allocation
		real_size = PAGE_ALIGN_UP(size);

		union pagelist *new = pagetable_new(&state->pagetables,
						    sizeof(struct internal_pagelist));
		if (!new)
			goto oom;
		void *page = mmap_random(real_size, extra_mask);
		if (page == MAP_FAILED)
			goto oom;

		new->l.page = page;
		new->l.size = size;

		middle_table_insert(&state->large_pages, new, page,
				    malloc_user_va_space_bits,
				    MIDDLE_PAGE_TYPE_LARGE);
		middle_table_insert(&state->all_pages, new, page,
				    malloc_user_va_space_bits,
				    MIDDLE_PAGE_TYPE_LARGE);
		DPRINTF("new large page %p .page=%p .size=%lx\n", new,
			new->l.page, new->l.size);

		state->large_count++;
		/*
		  Randomize start of for example 5000 byte allocation
		  with 256 byte alignment
		*/
		unsigned int align_bits = __builtin_ctzl(extra_mask &
							 MIN_ALLOC_MASK);
		unsigned long page_offset = 0;
		if (align_bits < PAGE_BITS) {
			unsigned long slack = (real_size - size) >> align_bits;
			if (slack) {
				page_offset = randomize_int(0, slack)
					<< align_bits;
				DPRINTF("randomized %p with offset %lu "
					"(%lu positions, %d bits)\n",
					new->l.page, page_offset, slack,
					align_bits);
			}
		}
		alloc_start = new->l.page;
		ret = (void *)((unsigned long)new->l.page + page_offset);
	} else {
		// New small allocation
		real_size = 1 << (index + MIN_ALLOC_BITS);

		struct small_page_find_cb_data s = {
			.index = index,
			.real_size = real_size,
			.size = size,
			.extra_mask = extra_mask,
		};
		// Try to find a free entry in the free slabs
		if (!middle_table_iterate(state->small_pages[index],
					  small_page_find_cb, &s)) {
			// Not found, allocate a new page
			union pagelist *new = pagetable_new(&state->pagetables,
							    sizeof(struct internal_pagelist));
			if (!new)
				goto oom;

			void *page = mmap_random(PAGE_SIZE, extra_mask);
			if (page == MAP_FAILED)
				goto oom;

			new->s.page = page;
			new->s.index = index;
			/*
			  While the pages returned by mmap() will be
			  zeroed by the kernel, the page table entry
			  received may be an old recycled one, so
			  let's clear the bitmap.
			*/
			memset(new->s.bitmap, 0, sizeof(new->s.bitmap));

			get_random(&new->s.access_randomizer_state,
				   sizeof(new->s.access_randomizer_state));
			middle_table_insert(&state->small_pages[index], new, page,
					    malloc_user_va_space_bits,
					    MIDDLE_PAGE_TYPE_SMALL);
			middle_table_insert(&state->all_pages, new, page,
					    malloc_user_va_space_bits,
					    MIDDLE_PAGE_TYPE_SMALL);
			DPRINTF("new small pagetable at index %u %p .page=%p "
				".rnd=%lx\n",
				index, new, new->s.page,
				new->s.access_randomizer_state);
			state->small_count[index]++;
			small_page_find_cb(new, &s);
			pagetables_dump("post adding new page table");
		}
		alloc_start = s.alloc_start;
		ret = s.ret;
	}
	pthread_mutex_unlock(&malloc_lock);

	// Fill memory with junk
	if (malloc_fill_junk != '\0') {
		DPRINTF("fill junk %p +%lu\n", alloc_start, real_size);
		memset(alloc_start, malloc_fill_junk, real_size);
	}
	pagetables_dump("post malloc");
finish:
	DPRINTF("returning %p\n", ret);
	errno = ret_errno;
	return ret;
oom:
	pthread_mutex_unlock(&malloc_lock);
	errno = ENOMEM;
	return NULL;
}

/*
  See manual page for malloc().
*/
void *malloc(size_t size) {
	if (malloc_passthrough)
		return libc_malloc(size);

	return aligned_malloc(size, 1);
}

/*
  Glibc extension. See manual page for malloc_usable_size().
*/
size_t malloc_usable_size(void *ptr) {
	if (malloc_passthrough)
		return libc_malloc_usable_size(ptr);

	int saved_errno = errno;
	size_t ret = 0;

	if (!ptr)
		goto finish;

	if (!state)
		init();

	DPRINTF("malloc_usable_size(%p)\n", ptr);
	unsigned long address = (unsigned long)ptr;
	unsigned long page_address = address & PAGE_MASK;

	// Scan the slab pages if the page matches the pointer.
	pthread_mutex_lock(&malloc_lock);
	union pagelist **entry = middle_table_find(&state->all_pages, page_address,
						   malloc_user_va_space_bits);
	if (!entry) {
		// Not found, maybe a bug in the calling program?
		// TODO Optionally just ignore the error?
		fprintf(stderr, "malloc_usable_size: %p not found!\n", ptr);
		abort();
	}

	union pagelist *p = (union pagelist *)((unsigned long)*entry &
					       MIDDLE_PAGE_TYPE_MASK);
	// Recover randomization
	switch ((unsigned long)*entry & ~MIDDLE_PAGE_TYPE_MASK) {
	case MIDDLE_PAGE_TYPE_SMALL: {
		unsigned long offset = address & ((1 << (p->s.index +
							 MIN_ALLOC_BITS)) - 1);
		ret = (1 << (p->s.index + MIN_ALLOC_BITS)) - offset;
		break;
	}
	case MIDDLE_PAGE_TYPE_LARGE: {
		unsigned long offset = address & ~PAGE_MASK;
		ret = PAGE_ALIGN_UP(p->l.size) - offset;
		break;
	}
	case MIDDLE_PAGE_TYPE_MIDDLE:
		abort();
	}
	pthread_mutex_unlock(&malloc_lock);
finish:
	DPRINTF("returning %lx\n", ret);
	errno = saved_errno;
	return ret;
}

/*
  See manual page for free(). Glibc manual (3.2.5 Replacing malloc)
  warns that errno shall be preserved.
*/
void free(void *ptr) {
	if (malloc_passthrough)
		return libc_free(ptr);

	int saved_errno = errno;

	if (!ptr)
		goto finish;

	if (!state)
		init();

	DPRINTF("free(%p)\n", ptr);
	unsigned long address = (unsigned long)ptr;
	unsigned long page_address = address & PAGE_MASK;

	// Scan the slab pages if the page matches the pointer.
	pthread_mutex_lock(&malloc_lock);
	union pagelist **entry = middle_table_find(&state->all_pages, page_address,
						   malloc_user_va_space_bits);
	if (!entry) {
		// Not found, maybe a bug in the calling program?
		// TODO Optionally just ignore the error?
		fprintf(stderr, "free: %p not found!\n", ptr);
		abort();
	}

	union pagelist *p = (union pagelist *)((unsigned long)*entry
					       & MIDDLE_PAGE_TYPE_MASK);
	switch ((unsigned long)*entry & ~MIDDLE_PAGE_TYPE_MASK) {
	case MIDDLE_PAGE_TYPE_SMALL: {
		unsigned int bits = bitmap_bits((1 << (p->s.index + MIN_ALLOC_BITS)));
		bitmap_clear(p->s.bitmap, (address & ~PAGE_MASK) >>
			     (p->s.index + MIN_ALLOC_BITS));
		if (bitmap_is_empty(p->s.bitmap, bits)) {
			unsigned long guard_size =
				get_guard_size(PAGE_SIZE);
			// Immediately unmap pages
			DPRINTF("unmap small %p [%u] (guards %lu)\n",
				p->s.page, p->s.index, guard_size);
			int r = munmap((void *)((unsigned long)p->s.page -
						guard_size),
				       PAGE_SIZE + 2 * guard_size);
			if (r < 0) {
				perror("munmap");
				abort();
			}

			middle_table_delete(&state->small_pages[p->s.index],
					    page_address, malloc_user_va_space_bits);
			middle_table_delete(&state->all_pages, page_address,
					    malloc_user_va_space_bits);
			pagetable_free(&state->pagetables, p);
		} else if (malloc_fill_junk != '\0') {
			// Filter out randomization
			ptr = (void *)(address &
				       ~((1UL << (p->s.index + MIN_ALLOC_BITS))
					 - 1));
			// Immediately fill the freed memory
			// with junk
			DPRINTF("fill junk %p +%u\n", ptr,
				1 << (p->s.index + MIN_ALLOC_BITS));
			memset(ptr, malloc_fill_junk,
			       1 << (p->s.index + MIN_ALLOC_BITS));
		}
		break;
	}
	case MIDDLE_PAGE_TYPE_LARGE: {
		// Immediately unmap all freed memory
		unsigned long guard_size = get_guard_size(p->l.size);
		DPRINTF("unmap large %p +%lu + guard %lu\n", p->l.page,
			p->l.size, guard_size);
		int r = munmap((void *)((unsigned long)p->l.page - guard_size),
			       p->l.size + 2 * guard_size);
		if (r < 0) {
			perror("munmap");
			abort();
		}

		middle_table_delete(&state->large_pages, page_address,
				    malloc_user_va_space_bits);
		middle_table_delete(&state->all_pages, page_address,
				    malloc_user_va_space_bits);
		pagetable_free(&state->pagetables, p);
		break;
	}
	case MIDDLE_PAGE_TYPE_MIDDLE:
		abort();
	}
	pthread_mutex_unlock(&malloc_lock);
	pagetables_dump("post free");
finish:
	errno = saved_errno;
}

/*
  See manual page for calloc(). Locking is handled by malloc().
*/
void *calloc(size_t nmemb, size_t size) {
	if (malloc_passthrough)
		return libc_calloc(nmemb, size);

	int saved_errno = errno;

	/*
	  Handle overflow in the multiplication by using 128 bit
	  arithmetic.
	*/
	__uint128_t new_size = (__uint128_t)nmemb * (__uint128_t)size;
	if (new_size > (__uint128_t)(1ULL << malloc_user_va_space_bits)) {
		errno = ENOMEM;
		return NULL;
	}
	void *ptr = malloc((size_t)new_size);
	if (ptr) {
		memset(ptr, 0, (size_t)new_size);
		errno = saved_errno;
	}
	return ptr;
}

/*
  See manual page for calloc(). Locking is handled by
  malloc_usable_size(), malloc() and free().
*/
void *realloc(void *ptr, size_t new_size) {
	if (malloc_passthrough)
		return libc_realloc(ptr, new_size);

	int saved_errno = errno;

	if (!ptr)
		return malloc(new_size);
	if (new_size == 0) {
		free(ptr);
		errno = saved_errno;
		return NULL;
	}
	size_t old_size = malloc_usable_size(ptr);
	DPRINTF("realloc(%p, %lu) old_size %lu\n", ptr, new_size, old_size);
	// TODO introduce an internal version of malloc() which does
	// not touch memory. All of it will be copied or filled with
	// junk.
	void *ret = malloc(new_size);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}
	/* Flawfinder: ignore */
	memcpy(ret, ptr, MIN(old_size, new_size));

	if (new_size > old_size && malloc_fill_junk != '\0') {
		// Fill new part of memory with junk
		/* Flawfinder: ignore */
		DPRINTF("fill junk %p +%lu\n", &((char *)ret)[old_size],
			new_size - old_size);
		/* Flawfinder: ignore */
		memset(&((char *)ret)[old_size], malloc_fill_junk,
		       new_size - old_size);
	}
	free(ptr);
	DPRINTF("returning %p\n", ret);
	errno = saved_errno;
	return ret;
}

/*
  Glibc extension. See manual page for reallocarray(). Locking is
  handled by realloc().
*/
void *reallocarray(void *ptr, size_t nmemb, size_t size) {
	if (malloc_passthrough)
		return libc_reallocarray(ptr, nmemb, size);

	__uint128_t new_size = (__uint128_t)nmemb * (__uint128_t)size;
	if (new_size > (__uint128_t)(1ULL << malloc_user_va_space_bits)) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(ptr, (size_t)new_size);
}

/*
  See manual page for posix_memalign(). Locking is
  handled by aligned_malloc().
*/
int posix_memalign(void **memptr, size_t alignment, size_t size) {
	if (malloc_passthrough)
		return libc_posix_memalign(memptr, alignment, size);

	int saved_errno = errno;

	DPRINTF("posix_memalign(%p, %lx, %lx)\n", memptr, alignment, size);
	if ((alignment & (sizeof(void *) - 1)) != 0 || !powerof2(alignment)) {
		DPRINTF("returning EINVAL\n");
		return EINVAL;
	}

	void *ptr = aligned_malloc(size, alignment);
	if (ptr) {
		*memptr = ptr;
		DPRINTF("returning %p\n", ptr);
		errno = saved_errno;
		return 0;
	} else {
		int ret = errno;
		DPRINTF("returning error: %m\n");
		// Glibc does not save errno
		if (malloc_strict_posix_memalign_errno)
			errno = saved_errno;
		return ret;
	}
}

/*
  Glibc extension. See manual page for aligned_alloc(). Locking is
  handled by posix_memalign().
*/
void *aligned_alloc(size_t alignment, size_t size) {
	if (malloc_passthrough)
		return libc_aligned_alloc(alignment, size);

	DPRINTF("aligned_alloc(%lx, %lx)\n", alignment, size);
	void *ret = NULL;
	int r = posix_memalign(&ret, alignment, size);
	if (r != 0)
		errno = r;
	return ret;
}

/*
  Obsolete. See manual page for memalign(). Locking is
  handled by aligned_alloc().
*/
/* Flawfinder: ignore */
void *memalign(size_t alignment, size_t size) {
	if (malloc_passthrough)
		return libc_memalign(alignment, size);

	return aligned_alloc(alignment, size);
}

/*
  Obsolete. See manual page for valloc(). Locking is
  handled by aligned_alloc().
*/
void *valloc(size_t size) {
	if (malloc_passthrough)
		return libc_valloc(size);

	return aligned_alloc(PAGE_SIZE, size);
}

/*
  Obsolete. See manual page for pvalloc(). Locking is
  handled by aligned_alloc().
*/
void *pvalloc(size_t size) {
	if (malloc_passthrough)
		return libc_pvalloc(size);

	return aligned_alloc(PAGE_SIZE, size);
}

#endif // !LIBC

#if DEBUG
#ifndef ROUNDS1
// Warning: will allocate 2^ROUNDS1 of memory
#define ROUNDS1 10
#endif // ROUNDS1
#ifndef ROUNDS2
#define ROUNDS2 16
#endif // ROUNDS2
#ifndef ROUNDS3
#define ROUNDS3 129
#endif // ROUNDS3

static void check_align(void *ptr, size_t align) {
	assert(((unsigned long)ptr & (align - 1)) == 0);
}

int main(void) {
	for (int i = 0; i < ROUNDS1; i++) {
		void *ptrv[ROUNDS2];
		for (int j = 0; j < ROUNDS2; j++) {
			ptrv[j] = malloc(1UL << i);
			assert(ptrv[j]);
			check_align(ptrv[j], sizeof(void *));
			// Test that all memory is writable
			memset(ptrv[j], 0, 1UL << i);
			// Check that all pointers are unique
			for (int k = 0; k < j; k++)
				assert(ptrv[j] != ptrv[k]);
		}
#if DEBUG_2
		for (int j = 0; j < ROUNDS2; j++) {
			ptrv[j] = realloc(ptrv[j], (1UL << i) + 4096);
			// Test that all memory is writable
			assert(ptrv[j]);
			check_align(ptrv[j], sizeof(void *));
			memset(ptrv[j], 0, (1UL << i) + 4096);
			ptrv[j] = realloc(ptrv[j], (1UL << i));
			// Test that all memory is writable
			assert(ptrv[j]);
			check_align(ptrv[j], sizeof(void *));
			memset(ptrv[j], 0, 1UL << i);
			// Check that all pointers are unique
			for (int k = 0; k < j; k++)
				assert(ptrv[j] != ptrv[k]);
		}
#endif // DEBUG_2
		for (int j = 0; j < ROUNDS2; j++)
			free(ptrv[j]);
	}

	/*
	  Test a large enough number of largest of small allocations
	  (2048) to check that new pages can be allocated (and freed
	  later) for internal page table entries.
	*/
	void *ptrv[ROUNDS3];
	for (int j = 0; j < ROUNDS3; j++) {
		ptrv[j] = malloc(2048);
		assert(ptrv[j]);
		check_align(ptrv[j], sizeof(void *));
		// Test that memory is writable
		memset(ptrv[j], 0, 2048);
		// Check that all pointers are unique
		for (int k = 0; k < j; k++)
			assert(ptrv[j] != ptrv[k]);
	}
	for (int j = 0; j < ROUNDS3; j++)
		free(ptrv[j]);

	// Test that errno is saved throughout the several next tests.
	errno = EBADF;

	// free(NULL) is OK
	free(NULL);

	/*
	  The manual page says that malloc(0) may return NULL but
	  sadly some applications expect it to return accessible
	  memory and Glibc does that.
	*/
	void *ptr = malloc(0);
	free(ptr);

	ptr = malloc(1);
	assert(ptr);
	check_align(ptr, sizeof(void *));
	size_t usable_size = malloc_usable_size(ptr);
	assert(usable_size >= 1);
	/*
	  Can't test all usable size because of buffer overflow
	  detectors but we can test the initial size.
	*/
	memset(ptr, 0, 1);
	ptr = realloc(ptr, 0); // Equal to free()
	assert(ptr == NULL);
	free(ptr);

	/*
	  The manual page says that calloc(0) may return NULL but
	  sadly some applications expect it to return accessible
	  memory and Glibc does that.
	*/
	ptr = calloc(0, 0);
	free(ptr);

	ptr = calloc(4096, 1);
	assert(ptr);
	check_align(ptr, sizeof(void *));
	// Test that all memory is writable
	memset(ptr, 0, 4096);
	void *ptr2 = calloc(4096, 4);
	assert(ptr2);
	check_align(ptr2, sizeof(void *));
	// Test that all memory is writable
	memset(ptr2, 0, 4096 * 4);
	free(ptr);
	free(ptr2);

	/*
	  Test that errno was saved throughout the several previous
	  tests.
	*/
	assert(errno == EBADF);

	ptr = malloc(1);
	check_align(ptr, sizeof(void *));
	ptr = reallocarray(ptr, 2048, 1);
	check_align(ptr, sizeof(void *));
	free(ptr);

	// malloc_usable_size(NULL) should return 0
	usable_size = malloc_usable_size(NULL);
	assert(usable_size == 0);

	errno = EBADF;
	ptr = (void *)(unsigned long)1234;
	// Error expected: bad alignment
	int r = posix_memalign(&ptr, 3, 1);
	// Neither errno nor the pointer should be touched
	assert(errno == EBADF && r == EINVAL &&
	       ptr == (void *)(unsigned long)1234);

	errno = EBADF;
	// Error expected: bad alignment
	r = posix_memalign(&ptr, 48, 1);
	// Neither errno nor the pointer should be touched
	assert(errno == EBADF && r == EINVAL &&
	       ptr == (void *)(unsigned long)1234);

	errno = EBADF;
	r = posix_memalign(&ptr, 8192, 1);
	assert(errno == EBADF && r == 0);
	check_align(ptr, 8192);
	free(ptr);

	errno = EBADF;
	r = posix_memalign(&ptr, 256, 5000);
	assert(errno == EBADF && r == 0);
	check_align(ptr, 256);
	free(ptr);

	errno = EBADF;
	r = posix_memalign(&ptr, 32, 1600);
	assert(errno == EBADF && r == 0);
	check_align(ptr, 32);
	free(ptr);

	ptr = aligned_alloc(8192, 1);
	check_align(ptr, 8192);
	free(ptr);

	ptr = aligned_alloc(2048, 256);
	check_align(ptr, 2048);
	free(ptr);

	/* Flawfinder: ignore */
	ptr = memalign(8192, 1);
	check_align(ptr, 8192);
	free(ptr);

	size_t page_size = sysconf(_SC_PAGE_SIZE);
	ptr = valloc(1);
	check_align(ptr, page_size);
	free(ptr);

	ptr = pvalloc(1);
	check_align(ptr, page_size);
	free(ptr);

	errno = EBADF;
	// Test OOM
	ptr = malloc((size_t)1024 * 1024 * 1024 * 1024 * 1024);
	assert(errno == ENOMEM);

	errno = EBADF;
	// Test OOM
	ptr = realloc(NULL, (size_t)1024 * 1024 * 1024 * 1024 * 1024);
	assert(errno == ENOMEM);

	errno = EBADF;
	ptr = malloc(1);
	// Test OOM
	ptr2 = realloc(ptr, (size_t)1024 * 1024 * 1024 * 1024 * 1024);
	assert(errno == ENOMEM && ptr2 == NULL);

	errno = EBADF;
	ptr = malloc(1);
	// Test multiplication overflow
	ptr2 = reallocarray(ptr, INT_MAX, INT_MAX);
	assert(errno == ENOMEM && ptr2 == NULL);

	errno = EBADF;
	// Test multiplication overflow
	ptr = calloc(INT_MAX, INT_MAX);
	assert(errno == ENOMEM);

	ptr = (void *)(unsigned long)1234;
	// Test OOM
	r = posix_memalign(&ptr, 8192, (size_t)1024 * 1024 * 1024 * 1024 * 1024);
	/*
	  The manual page claims that errno would not be set, but
	  actually Glibc does that.
	*/
	assert(r == ENOMEM && ptr == (void *)(unsigned long)1234);

	errno = EBADF;
	// Test OOM
	ptr = aligned_alloc(8192, (size_t)1024 * 1024 * 1024 * 1024 * 1024);
	assert(errno == ENOMEM);

	errno = EBADF;
	// Test too large alignment
	ptr = aligned_alloc((size_t)1024 * 1024 * 1024 * 1024 * 1024, 8192);
	assert(errno == ENOMEM);

#if !LIBC
#ifdef PROFILE_DIR
#if EXPECT_PROFILE_CHANGE
	assert(malloc_debug == true);
	assert(malloc_fill_junk == 'X');
	assert(malloc_strict_malloc0 == true);
	assert(malloc_strict_posix_memalign_errno == true);
	assert(malloc_debug_stats == true);
#else // EXPECT_PROFILE_CHANGE
	assert(malloc_debug == false);
	assert(malloc_fill_junk == FILL_JUNK);
	assert(malloc_strict_malloc0 == false);
	assert(malloc_strict_posix_memalign_errno == false);
	assert(malloc_debug_stats == false);
#endif // EXPECT_PROFILE_CHANGE

#if EXPECT_PASSTHROUGH
	assert(malloc_passthrough == true);
#endif // EXPECT_PASSTHROUGH
#endif // PROFILE_DIR
#endif // !LIBC

	return 0;
}
#endif // DEBUG
