// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause
#define FILL_JUNK 'Z'
/*
 Compile for shared library
  gcc -o libaslrmalloc.so libaslrmalloc.c -fPIC -Wall -g -nostdlib -shared -O
 or as a test program
  gcc -o test libaslrmalloc.c -Wall -g -DDEBUG=1
 or to verify that libc malloc agrees with the test suite
  gcc -o test libaslrmalloc.c -Wall -g -DDEBUG=1 -DLIBC
*/
//#define DEBUG 1

#if !LIBC
#if DEBUG
#define malloc xmalloc
#define free xfree
#define calloc xcalloc
#define realloc xrealloc
#define DPRINTF(format, ...) fprintf(stderr, "%s: " format, __FUNCTION__, ##__VA_ARGS__)
#define DPRINTF_NOPREFIX(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
//#define DPRINTF(format, ...) do { char _buf[1024]; int _r = snprintf(_buf, sizeof(_buf), "%s: " format, __FUNCTION__, ##__VA_ARGS__); if (_r > 0) _r = write(2, _buf, _r); (void)_r; } while (0)
//#define DPRINTF_NOPREFIX(format, ...) do { char _buf[1024]; int _r = snprintf(_buf, sizeof(_buf), format, ##__VA_ARGS__); if (_r > 0) _r = write(2, _buf, _r); (void)_r; } while (0)
#define DPRINTF(format, ...) do {} while (0)
#define DPRINTF_NOPREFIX(format, ...) do {} while (0)
#endif
#endif

#include <assert.h>
#include <cpuid.h>
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/random.h>
#include <unistd.h>

#if !LIBC
// TODO assumes page size of 4096
#define PAGE_BITS 12
#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define PAGE_ALIGN_DOWN(size) ((size) & PAGE_MASK)
#define PAGE_ALIGN_UP(size) (((size) + (PAGE_SIZE - 1)) & PAGE_MASK)

// TODO assumes 64 bit longs
#define ULONG_BITS 6
#define ULONG_SIZE (1 << ULONG_BITS)
#define ULONG_MASK (~(ULONG_SIZE - 1))
#define ULONG_ALIGN_UP(size) (((size) + (ULONG_SIZE - 1)) & ULONG_MASK)

#define BITS_PER_BYTE 8

#define MIN_ALLOC_BITS 4
#define MIN_ALLOC_SIZE (1 << MIN_ALLOC_BITS)

#define MAX_SIZE_CLASSES (PAGE_BITS - MIN_ALLOC_BITS)

// Worst case: one bit for each smallest item (MIN_ALLOC_SIZE) per page
#define BITMAP_ULONGS (PAGE_SIZE / MIN_ALLOC_SIZE / ULONG_SIZE)

// TODO hash tables?
struct small_pagelist {
	struct small_pagelist *next;
	void *page;
	unsigned long bitmap[BITMAP_ULONGS];
};

struct large_pagelist {
	struct large_pagelist *next;
	void *page;
	size_t size;
};

struct malloc_state {
	// b16, b32, b64, b128, b256, b512, b1024, b2048;
	struct small_pagelist *pagetables;
	struct small_pagelist *small_pages[MAX_SIZE_CLASSES];
	struct large_pagelist *large_pages;
};

static struct malloc_state *state;
static pthread_mutex_t malloc_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long malloc_random_address_mask;
static int malloc_getrandom_bytes;
static int malloc_user_va_space_bits;

static void *mmap_random(size_t size) {
	for (;;) {
		unsigned long addr;
		ssize_t r = getrandom(&addr, malloc_getrandom_bytes, GRND_RANDOM);
		if (r < malloc_getrandom_bytes)
			continue;
		addr <<= PAGE_BITS;
		addr &= malloc_random_address_mask;
		void *ret = mmap((void *)addr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED_NOREPLACE | MAP_PRIVATE, -1, 0);
		if (ret == MAP_FAILED) {
			if (errno == EEXIST || errno == EINVAL)
				continue;
			else
				DPRINTF("mmap: %m");
		}
		DPRINTF("returning %p\n", ret);
		return ret;
	}
}

static unsigned int get_index(size_t size) {
	for (unsigned int index = MIN_ALLOC_BITS; index < PAGE_BITS; index++)
		if (size <= (1UL << index))
			return index - MIN_ALLOC_BITS;
	return -1;
}

static unsigned int last_index(size_t size) {
	for (unsigned int index = MIN_ALLOC_BITS; index < PAGE_BITS; index++)
		if (size <= (1UL << index))
			return (PAGE_SIZE / (1UL << index)) - 1;
	return -1;
}

static unsigned int align_up_size(size_t size) {
	for (unsigned int index = MIN_ALLOC_BITS; index < PAGE_BITS; index++)
		if (size <= (1UL << index))
			return 1UL << index;
	return PAGE_ALIGN_UP(size);
}

// Size of one bitmap structure in bits for one complete page
static unsigned int bitmap_bits(size_t size) {
	return PAGE_SIZE / align_up_size(size);
}

static void bitmap_set(unsigned long *bitmap, unsigned int bit) {
	bitmap[bit >> ULONG_BITS] |= 1UL << (bit & ~ULONG_MASK);
}

static void bitmap_clear(unsigned long *bitmap, unsigned int bit) {
	bitmap[bit >> ULONG_BITS] &= ~(1UL << (bit & ~ULONG_MASK));
}

// TODO free item could be found in random order instead of first
static int bitmap_find_first_clear(const unsigned long *bitmap, unsigned int bitmap_bits) {
	DPRINTF("bitmap_bits %u (%u words)\n", bitmap_bits, bitmap_bits >> ULONG_BITS);

	for (unsigned int b = 0; b < bitmap_bits; b += 1 << ULONG_BITS) {
		unsigned int i = b >> ULONG_BITS;
		unsigned long mask = (unsigned long)-1;

		if (bitmap_bits - b < ULONG_SIZE)
			mask = (1UL << (bitmap_bits - b)) - 1;
		unsigned long word = bitmap[i] & mask;

		DPRINTF("checking index %u word %lx mask %lx bits left %d\n", i, word, mask, bitmap_bits - b);
		if (word == 0) {
			DPRINTF("returning %u\n", b);
			return b;
		}
		if (word == ((unsigned long)-1 & mask))
			continue;

		int ret = b + __builtin_ctzl(~word);
		if (ret >= bitmap_bits)
			ret = -1;
		DPRINTF("counting bits returning %d\n", ret);
		return ret;
	}
	DPRINTF("returning -1\n");
	return -1;
}

static bool bitmap_is_empty(const unsigned long *bitmap, unsigned int bitmap_bits) {
	DPRINTF("bitmap_bits %u (%u words)\n", bitmap_bits, bitmap_bits >> ULONG_BITS);

	for (unsigned int b = 0; b < bitmap_bits; b += 1 << ULONG_BITS) {
		unsigned int i = b >> ULONG_BITS;
		unsigned long mask = (unsigned long)-1;

		if (bitmap_bits - b < ULONG_SIZE)
			mask = (1UL << (bitmap_bits - b)) - 1;
		unsigned long word = bitmap[i] & mask;

		DPRINTF("checking index %u word %lx mask %lx bits left %d\n", i, word, mask, bitmap_bits - b);
		if (word != 0) {
			DPRINTF("returning false\n");
			return false;
		}
	}
	DPRINTF("returning true\n");
	return true;
}

static void *ptr_to_offset_in_page(void *page, unsigned int size_index, int num) {
	assert(size_index <= MAX_SIZE_CLASSES);
	unsigned long offset = (1 << (size_index + MIN_ALLOC_BITS)) * num;
	unsigned long address = ((unsigned long)page) + offset;
	DPRINTF("offsetting page %p size index %u (0x%x) item number %d -> 0x%lx\n", page, size_index, 1 << (size_index + MIN_ALLOC_BITS), num, address);
	return (void *)address;
}

static void pagetables_dump(const char *label) {
#if DEBUG
	unsigned int count;
	struct small_pagelist *p;
	count = 0;
	for (p = state->pagetables, count = 0; p; p = p->next, count++) {
		DPRINTF("%s: pagetables (%p) [%u] .page=%p bm=", label, p, count, p->page);
		for (int i = 0; i < BITMAP_ULONGS; i++)
			DPRINTF_NOPREFIX("%lx ", p->bitmap[i]);
		DPRINTF_NOPREFIX("\n");
	}

	for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++) {
		count = 0;
		for (p = state->small_pages[i]; p; p = p->next, count++) {
			DPRINTF("%s: small_pages[%u] (%p) [%u] .page=%p bm=", label, i, p, count, p->page);
			for (int i = 0; i < BITMAP_ULONGS; i++)
				DPRINTF_NOPREFIX("%lx ", p->bitmap[i]);
			DPRINTF_NOPREFIX("\n");
		}
	}

	count = 0;
	for (struct large_pagelist *p = state->large_pages; p; p = p->next, count++)
		DPRINTF("%s: large_pages (%p) [%u] .page=%p .size=%lx\n", label, p, count, p->page, p->size);
#endif
}

static struct small_pagelist *pagetable_new(void) {
	struct small_pagelist *ret;

	unsigned int index = get_index(sizeof(*ret));
	for (;;) {
		for (struct small_pagelist *p = state->pagetables; p; p = p->next) {
			int offset = bitmap_find_first_clear(p->bitmap, bitmap_bits(sizeof(*ret)));

			if (offset >= 0) {
				ret = ptr_to_offset_in_page(p->page, index, offset);
				bitmap_set(p->bitmap, offset);
				goto found;
			}
		}

		void *page = mmap_random(PAGE_SIZE);
		if (page == MAP_FAILED)
			goto oom;

		// TODO offset could be randomized instead of last index
		int offset = last_index(sizeof(*ret));
		struct small_pagelist *new = ptr_to_offset_in_page(page, index, offset);
		new->page = page;
		bitmap_set(new->bitmap, offset);
		new->next = state->pagetables;
		DPRINTF("new pagetable %p page %p\n", new, new->page);
		state->pagetables = new;
	}

 found:
	DPRINTF("returning %p\n", ret);
	return ret;
 oom:
	return NULL;
}

static void pagetable_free(struct small_pagelist *entry) {
	int size_index = get_index(sizeof(struct small_pagelist));
	for (struct small_pagelist *p = state->pagetables, *prev = p; p; prev = p, p = p->next) {
		DPRINTF(".page=%p bm=%lx\n", p->page, p->bitmap[0]);
		if (((unsigned long)p->page & PAGE_MASK) == ((unsigned long)entry & PAGE_MASK)) {
			unsigned int bit = ((unsigned long)entry & ~PAGE_MASK) >> (size_index + MIN_ALLOC_BITS);
			DPRINTF("found match %p == %p, clearing bit %u (index %d)\n", entry, p->page, bit, size_index);
			bitmap_clear(p->bitmap, bit);

			// Check for emptiness excluding the last bit (entry used for managing the page itself)
			if (bitmap_is_empty(p->bitmap, last_index(sizeof(struct small_pagelist)))) {
				DPRINTF("unmap pagetable %p\n", p->page);
				// Because the page contains the entry
				// managing itself, grab next entry
				// pointer before the page is unmapped
				struct small_pagelist *next = p->next;
				int r = munmap(p->page, PAGE_SIZE);
				if (r < 0) {
					perror("munmap");
					abort();
				}
				if (prev == p)
					state->pagetables = next;
				else
					prev->next = next;
			}
			return;
		}
	}
	fprintf(stderr, "pagetable_free: %p not found!\n", entry);
	abort();
}

/*
  We need to allocate at least
  - global state
  - pagelist for the initial page
*/
static void init(void) {
	// Get number of virtual address bits. There are lots of different values from 36 to 57 (https://en.wikipedia.org/wiki/X86)
	unsigned int eax, unused;
	int r = __get_cpuid(0x80000008, &eax, &unused, &unused, &unused);
	malloc_user_va_space_bits = 36;
	if (r == 1)
		malloc_user_va_space_bits = ((eax >> 8) & 0xff) - 1;
	malloc_random_address_mask = ((1UL << malloc_user_va_space_bits) - 1) & PAGE_MASK;
	malloc_getrandom_bytes = (malloc_user_va_space_bits - PAGE_BITS + 7) / 8;
	DPRINTF("%d VA space bits, mask %16.16lx, getrandom() bytes %d\n", malloc_user_va_space_bits, malloc_random_address_mask,
		malloc_getrandom_bytes);

	void *pagetables;
	unsigned long temp_bitmap = 0;

	// Allocate for initial state (exception for slab use, occupying multiple slabs) and first pagetables
	pagetables = mmap_random(PAGE_SIZE);
	if (pagetables == MAP_FAILED)
		abort();

	// Mark allocation for global state
	int pages_index = get_index(sizeof(struct small_pagelist));
	// TODO offset could be randomized instead of 0
	int offset = 0;
	state = ptr_to_offset_in_page(pagetables, pages_index, offset);
	for (unsigned int i = offset; i < offset + align_up_size(sizeof(*state)) / align_up_size(sizeof(struct small_pagelist)); i++)
		bitmap_set(&temp_bitmap, i);

	// Mark allocation for page tables
	// TODO offset could be randomized instead of last index
	offset = last_index(sizeof(struct small_pagelist));
	bitmap_set(&temp_bitmap, offset);
	state->pagetables = ptr_to_offset_in_page(pagetables, pages_index, offset);
	state->pagetables->page = pagetables;
	// Copy temporary bitmap
	state->pagetables->bitmap[0] = temp_bitmap;
	pagetables_dump("initial");
}

void *malloc(size_t size)
{
	int ret_errno = errno;
	void *ret = NULL;

	if (!state)
		init();

	DPRINTF("malloc(%lu)\n", size);
	if (size == 0)
		goto finish;

	if (size > (1UL << malloc_user_va_space_bits)) {
		ret_errno = ENOMEM;
		goto finish;
	}

	unsigned int index = get_index(size);
	size_t real_size;
	if (index == (unsigned int)-1) {
		// New large allocation
		real_size = PAGE_ALIGN_UP(size);
		pthread_mutex_lock(&malloc_lock);
		struct large_pagelist *new = (struct large_pagelist *)pagetable_new();
		if (!new)
			goto oom;
		void *page = mmap_random(real_size);
		if (page == MAP_FAILED)
			goto oom;

		new->page = page;
		new->size = size;
		new->next = state->large_pages;
		DPRINTF("new large page %p .page=%p .size=%lx\n", new, new->page, new->size);
		state->large_pages = new;
		ret = new->page;
	} else {
		// New small allocation
		pagetables_dump("pre malloc");
		real_size = 1 << (index + MIN_ALLOC_BITS);

		pthread_mutex_lock(&malloc_lock);
		for (;;) {
			for (struct small_pagelist *p = state->small_pages[index]; p; p = p->next) {
				int offset = bitmap_find_first_clear(p->bitmap, bitmap_bits(size));

				if (offset >= 0) {
					DPRINTF("found offset %d ptr %p\n", offset, p->page);
					ret = ptr_to_offset_in_page(p->page, index, offset);
					bitmap_set(p->bitmap, offset);
					goto found;
				}
			}

			struct small_pagelist *new = pagetable_new();
			if (!new)
				goto oom;

			void *page = mmap_random(PAGE_SIZE);
			if (page == MAP_FAILED)
				goto oom;

			new->page = page;
			memset(new->bitmap, 0, sizeof(new->bitmap));
			new->next = state->small_pages[index];
			DPRINTF("new small pagetable at index %u %p .page=%p\n", index, new, new->page);
			state->small_pages[index] = new;
			pagetables_dump("post adding new page table");
		}
	}
 found:
	pthread_mutex_unlock(&malloc_lock);
#ifdef FILL_JUNK
	// Fill memory with junk
	DPRINTF("fill junk %p +%lu\n", ret, real_size);
	memset(ret, FILL_JUNK, real_size);
#endif
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

size_t malloc_usable_size(void *ptr) {
	int saved_errno = errno;
	size_t ret = 0;

	if (!state)
		init();

	if (!ptr)
		goto finish;

	DPRINTF("malloc_usable_size(%p)\n", ptr);
	pagetables_dump("malloc_usable_size");

	unsigned long address = (unsigned long)ptr & PAGE_MASK;
	for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++) {
		for (struct small_pagelist *p = state->small_pages[i]; p; p = p->next) {
			DPRINTF("pages[%u] .page=%p bm=%lx\n", i, p->page, p->bitmap[0]);
			if (((unsigned long)p->page & PAGE_MASK) == address) {
				ret = (1 << (i + MIN_ALLOC_BITS));
				goto finish;
			}
		}
	}

	DPRINTF("trying large list\n");

	for (struct large_pagelist *p = state->large_pages; p; p = p->next) {
		DPRINTF(".page=%p .size=%lx\n", p->page, p->size);
		if (((unsigned long)p->page & PAGE_MASK) == address) {
			DPRINTF("found\n");
			ret = PAGE_ALIGN_UP(p->size);
			goto finish;
		}
	}
	fprintf(stderr, "malloc_usable_size: %p not found!\n", ptr);
	abort();
 finish:
	DPRINTF("returning %lx\n", ret);
	errno = saved_errno;
	return ret;
}

void free(void *ptr)
{
	int saved_errno = errno;

	if (!state)
		init();

	if (!ptr)
		goto finish;

	DPRINTF("free(%p)\n", ptr);
	pagetables_dump("pre free");
	unsigned long address = (unsigned long)ptr;
	unsigned long page_address = address & PAGE_MASK;

	pthread_mutex_lock(&malloc_lock);
	for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++) {
		for (struct small_pagelist *p = state->small_pages[i], *prev = p; p; prev = p, p = p->next) {
			if (((unsigned long)p->page & PAGE_MASK) == page_address) {
				unsigned int bits = bitmap_bits(1 << (i + MIN_ALLOC_BITS));
				bitmap_clear(p->bitmap, (address & ~PAGE_MASK) >> (i + MIN_ALLOC_BITS));
				if (bitmap_is_empty(p->bitmap, bits)) {
					// Immediately unmap pages
					DPRINTF("unmap small %p\n", p->page);
					int r = munmap(p->page, PAGE_SIZE);
					if (r < 0) {
						perror("munmap");
						abort();
					}
					if (prev == p)
						state->small_pages[i] = p->next;
					else
						prev->next = p->next;
					pagetable_free(p);
				} else {
#ifdef FILL_JUNK
					// Immediately fill the freed memory with junk
					DPRINTF("free fill junk %p +%u\n", ptr, 1 << (i + MIN_ALLOC_BITS));
					memset(ptr, FILL_JUNK, 1 << (i + MIN_ALLOC_BITS));
#endif
				}
				goto found;
			}
		}
	}

	DPRINTF("trying large list\n");

	for (struct large_pagelist *p = state->large_pages, *prev = p; p; prev = p, p = p->next) {
		DPRINTF(".page=%p .size=%lx\n", p->page, p->size);
		if (((unsigned long)p->page & PAGE_MASK) == address) {
			// Immediately unmap all freed memory
			DPRINTF("unmap large %p +%lu\n", p->page, p->size);
			int r = munmap(p->page, p->size);
			if (r < 0) {
				perror("munmap");
				abort();
			}
			if (prev == p)
				state->large_pages = p->next;
			else
				prev->next = p->next;
			pagetable_free((struct small_pagelist *)p);
			goto found;
		}
	}
	fprintf(stderr, "free: %p not found!\n", ptr);
	abort();
 found:
	pthread_mutex_unlock(&malloc_lock);
	pagetables_dump("post free");
 finish:
	errno = saved_errno;
}

void *calloc(size_t nmemb, size_t size)
{
	int saved_errno = errno;

	if (!state)
		init();

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

void *realloc(void *ptr, size_t new_size)
{
	int saved_errno = errno;

	if (!state)
		init();

	if (!ptr)
		return malloc(new_size);
	if (new_size == 0) {
		free(ptr);
		errno = saved_errno;
		return NULL;
	}
	size_t old_size = malloc_usable_size(ptr);
	DPRINTF("realloc(%p, %lu) old_size %lu\n", ptr, new_size, old_size);
	void *ret = malloc(new_size);
	if (!ret) {
		errno = ENOMEM;
		return NULL;
	}
	memcpy(ret, ptr, MIN(old_size, new_size));
#ifdef FILL_JUNK
	// Fill new part of memory with junk
	if (new_size > old_size) {
		DPRINTF("fill junk %p +%lu\n", &((char *)ret)[old_size], new_size - old_size);
		memset(&((char *)ret)[old_size], FILL_JUNK, new_size - old_size);
	}
#endif
	free(ptr);
	DPRINTF("returning %p\n", ret);
	errno = saved_errno;
	return ret;
}

void *reallocarray(void *ptr, size_t nmemb, size_t size) {
	if (!state)
		init();

	__uint128_t new_size = (__uint128_t)nmemb * (__uint128_t)size;
	if (new_size > (__uint128_t)(1ULL << malloc_user_va_space_bits)) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(ptr, (size_t)new_size);
}

#endif

#if DEBUG
#ifndef ROUNDS1
#define ROUNDS1 10
#endif
#ifndef ROUNDS2
#define ROUNDS2 16
#endif
#ifndef ROUNDS3
#define ROUNDS3 129
#endif

int main(void) {
	for (int i = 0; i < ROUNDS1; i++) {
		void *ptrv[ROUNDS2];
		for (int j = 0; j < ROUNDS2; j++) {
			ptrv[j] = malloc(1UL << i);
			memset(ptrv[j], 0, 1UL << i);
		}
#if DEBUG_2
		for (int j = 0; j < ROUNDS2; j++) {
			ptrv[j] = realloc(ptrv[j], (1UL << i) + 4096);
			memset(ptrv[j], 0, (1UL << i) + 4096);
			ptrv[j] = realloc(ptrv[j], (1UL << i));
			memset(ptrv[j], 0, 1UL << i);
		}
#endif
		for (int j = 0; j < ROUNDS2; j++)
			free(ptrv[j]);
	}

	void *ptrv[ROUNDS3];
	for (int j = 0; j < ROUNDS3; j++) {
		ptrv[j] = malloc(2048);
		memset(ptrv[j], 0, 2048);
	}
	for (int j = 0; j < ROUNDS3; j++)
		free(ptrv[j]);

	errno = EBADF;
	free(NULL);

	void *ptr = malloc(0);
	free(ptr);

	ptr = malloc(1);
	size_t usable_size = malloc_usable_size(ptr);
	assert(usable_size >= 1);
	memset(ptr, 0, 1);
	ptr = realloc(ptr, 0); // Equal to free()
	assert(ptr == NULL);

	ptr = calloc(0, 0);
	free(ptr);

	ptr = calloc(4096, 1);
	memset(ptr, 0, 4096);
	void *ptr2 = calloc(4096, 4);
	memset(ptr2, 0, 4096 * 4);
	free(ptr);
	free(ptr2);
	assert(errno == EBADF);

	ptr = malloc(1);
	ptr = reallocarray(ptr, 2048, 1);
	free(ptr);

	usable_size = malloc_usable_size(NULL);
	assert(usable_size == 0);

	ptr = malloc((size_t)1024*1024*1024*1024*1024); // Test OOM
	assert(errno == ENOMEM);

	errno = EBADF;
	ptr = realloc(NULL, (size_t)1024*1024*1024*1024*1024); // Test OOM
	assert(errno == ENOMEM);

	errno = EBADF;
	ptr = malloc(1);
	ptr2 = realloc(ptr, (size_t)1024*1024*1024*1024*1024); // Test OOM
	assert(errno == ENOMEM && ptr2 == NULL);

	errno = EBADF;
	ptr = malloc(1);
	ptr2 = reallocarray(ptr, INT_MAX, INT_MAX);
	assert(errno == ENOMEM && ptr2 == NULL);

	errno = EBADF;
	ptr = calloc(INT_MAX, INT_MAX);
	assert(errno == ENOMEM);
	return 0;
}
#endif
