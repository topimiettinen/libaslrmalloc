// SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause
#define FILL_JUNK 'Z'
/*
 Compile for shared library
  gcc -o libaslrmalloc.so libaslrmalloc.c -fPIC -Wall -g -nostdlib -shared -O
 or as a test program
  gcc -o test libaslrmalloc.c -Wall -g -DDEBUG=1
*/
//#define DEBUG 1

#if DEBUG
#define malloc xmalloc
#define free xfree
#define calloc xcalloc
#define realloc xrealloc
#define DPRINTF(format, ...) fprintf(stderr, "%s: " format, __FUNCTION__, ##__VA_ARGS__)
#else
#define DPRINTF(...)
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
	unsigned int b = 0;

	for (; b < bitmap_bits; b += 1 << ULONG_BITS) {
		unsigned int i = b >> ULONG_BITS;
		DPRINTF("checking index %u word %lx bits left %d\n", i, bitmap[i], bitmap_bits - b);
		if (bitmap[i] == 0) {
			DPRINTF("returning %u\n", b);
			return b;
		}
		if (bitmap[i] == (unsigned long)-1)
			continue;

		int ret = b + __builtin_ctzl(~bitmap[i]);
		if (ret >= bitmap_bits - b)
			ret = -1;
		DPRINTF("counting bits returning %u\n", ret);
		return ret;
	}
	DPRINTF("returning -1\n");
	return -1;
}

static bool bitmap_is_empty(const unsigned long *bitmap, unsigned int bitmap_bits) {
	bitmap_bits = ULONG_ALIGN_UP(bitmap_bits);
	DPRINTF("bitmap_bits %u (%u words)\n", bitmap_bits, bitmap_bits >> ULONG_BITS);
	for (unsigned int i = 0; (i << ULONG_BITS) < bitmap_bits; i++) {
		DPRINTF("checking index %u word %lx\n", i, bitmap[i]);
		if (bitmap[i] != 0) {
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
	for (p = state->pagetables, count = 0; p; p = p->next, count++)
		DPRINTF("%s: pagetables (%p) [%u] .page=%p bm=%lx\n", label, p, count, p->page, p->bitmap[0]);

	for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++) {
		count = 0;
		for (p = state->small_pages[i]; p; p = p->next, count++)
			DPRINTF("%s: small_pages[%u] (%p) [%u] .page=%p bm=%lx\n", label, i, p, count, p->page, p->bitmap[0]);
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

		struct small_pagelist *new = mmap_random(PAGE_SIZE);
		if (new == MAP_FAILED)
			goto oom;
		new->page = new;

		DPRINTF("new pagetable %p page %p\n", new, new->page);
		new->next = state->pagetables;
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
	for (struct small_pagelist *p = state->pagetables; p; p = p->next) {
		DPRINTF(".page=%p bm=%lx\n", p->page, p->bitmap[0]);
		if (((unsigned long)p->page & PAGE_MASK) == ((unsigned long)entry & PAGE_MASK)) {
			unsigned int bit = ((unsigned long)entry & ~PAGE_MASK) >> (size_index + MIN_ALLOC_BITS);
			DPRINTF("found match %p == %p, clearing bit %u (index %d)\n", entry, p->page, bit, size_index);
			bitmap_clear(p->bitmap, bit);
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
	int first_free = bitmap_find_first_clear(&temp_bitmap, ULONG_BITS);
	bitmap_set(&temp_bitmap, first_free);
	state->pagetables = ptr_to_offset_in_page(pagetables, pages_index, first_free);
	state->pagetables->page = pagetables;
	// Copy temporary bitmap
	state->pagetables->bitmap[0] = temp_bitmap;
	pagetables_dump("initial");
}

void *malloc(size_t size)
{
	void *ret = NULL;

	if (!state)
		init();

	DPRINTF("malloc(%lu)\n", size);
	if (!size)
		return NULL;

	unsigned int index = get_index(size);
	size_t real_size;
	if (index == (unsigned int)-1) {
		// New large allocation
		real_size = PAGE_ALIGN_UP(size);
		pthread_mutex_lock(&malloc_lock);
		struct large_pagelist *new = (struct large_pagelist *)pagetable_new();
		if (!new)
			goto oom;
		new->page = mmap_random(real_size);
		if (new->page == MAP_FAILED)
			goto oom;

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
					DPRINTF("malloc: found offset %d ptr %p\n", offset, p->page);
					ret = ptr_to_offset_in_page(p->page, index, offset);
					bitmap_set(p->bitmap, offset);
					goto found;
				}
			}

			struct small_pagelist *new = pagetable_new();
			if (!new)
				goto oom;

			new->page = mmap_random(PAGE_SIZE);
			if (new->page == MAP_FAILED)
				goto oom;

			memset(new->bitmap, 0, sizeof(new->bitmap));
			DPRINTF("malloc: new small pagetable at index %u %p .page=%p\n", index, new, new->page);
			new->next = state->small_pages[index];
			state->small_pages[index] = new;
			pagetables_dump("post adding new page table");
		}
	}
 found:
	pthread_mutex_unlock(&malloc_lock);
#ifdef FILL_JUNK
	// Fill memory with junk
	DPRINTF("malloc fill junk %p +%lu\n", ret, real_size);
	memset(ret, FILL_JUNK, real_size);
#endif
	pagetables_dump("post malloc");
	DPRINTF("returning %p\n", ret);
	return ret;
 oom:
	pthread_mutex_unlock(&malloc_lock);
	errno = ENOMEM;
	return NULL;
}

size_t malloc_usable_size(void *ptr) {
	DPRINTF("pagetables .page=%p .bm=%lx\n", state->pagetables->page, state->pagetables->bitmap[0]);
	unsigned long address = (unsigned long)ptr & PAGE_MASK;
	for (unsigned int i = 0; i < MAX_SIZE_CLASSES; i++) {
		for (struct small_pagelist *p = state->small_pages[i]; p; p = p->next) {
			DPRINTF("pages[%u] .page=%p bm=%lx\n", i, p->page, p->bitmap[0]);
			if (((unsigned long)p->page & PAGE_MASK) == address)
				return (1 << (i + MIN_ALLOC_BITS));
		}
	}

	DPRINTF("trying large list\n");

	for (struct large_pagelist *p = state->large_pages; p; p = p->next) {
		DPRINTF(".page=%p .size=%lx\n", p->page, p->size);
		if (((unsigned long)p->page & PAGE_MASK) == address) {
			DPRINTF("found\n");
			return p->size;
		}
	}
	fprintf(stderr, "malloc_usable_size: %p not found!\n", ptr);
	abort();
}

void free(void *ptr)
{
	if (!ptr)
		return;

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
}

void *calloc(size_t nmemb, size_t size)
{
	__uint128_t new_size = (__uint128_t)nmemb * (__uint128_t)size;
	if (new_size == 0 || new_size > (__uint128_t)(1ULL << malloc_user_va_space_bits)) {
		errno = ENOMEM;
		return NULL;
	}
	void *ptr = malloc((size_t)new_size);
	if (ptr)
		memset(ptr, 0, (size_t)new_size);
	return ptr;
}

void *realloc(void *ptr, size_t new_size)
{
	if (!ptr)
		return malloc(new_size);
	if (new_size == 0) {
		free(ptr);
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
		DPRINTF("realloc fill junk %p +%lu\n", &((char *)ret)[old_size], new_size - old_size);
		memset(&((char *)ret)[old_size], FILL_JUNK, new_size - old_size);
	}
#endif
	free(ptr);
	DPRINTF("returning %p\n", ret);
	return ret;
}

#if DEBUG
#ifndef ROUNDS1
#define ROUNDS1 10
#endif
#ifndef ROUNDS2
#define ROUNDS2 16
#endif
int main(void) {
	init();

	for (int i = 0; i < ROUNDS1; i++) {
		void *ptr[ROUNDS2];
		for (int j = 0; j < ROUNDS2; j++)
			ptr[j] = malloc(1UL << i);
#if DEBUG_2
		for (int j = 0; j < ROUNDS2; j++)
			ptr[j] = realloc(ptr[j], (1UL << i) + 4096);
#endif
		for (int j = 0; j < ROUNDS2; j++)
			free(ptr[j]);
	}

	return 0;
}
#endif
