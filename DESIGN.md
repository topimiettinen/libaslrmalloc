# Design

## Security

The first and foremost goal of the library is to maximize address space layout randomization
([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)).
Other goals such as
- efficiency of memory use
- impacts to CPU page tables or caches
- kernel's ability to handle large number of VMAs
- performance of `malloc()`, `realloc()`, `free()` or other memory allocation functions
- usability on 32 bit systems due to heavy memory fragmentation
- portability

are really secondary. There are plenty of malloc libraries which only consider the efficiency, performance etc. issues
or retain heritage from small 32 bit systems, this isn't one of them. This library is for ASLR.

The goal is achieved by using small memory blocks and mapping them at random addresses.
Memory is also always unmapped immediately when possible in `realloc()` and `free()`,
so new allocations should be placed in newly randomized locations.
In contrast, many other malloc libraries keep the old allocations as caches.
Correctly written code should always expect that `realloc()` may move the memory and
the old memory may never be referenced after `realloc()` or `free()`.

## Specification

The purpose and operation of the allocation functions is described in detail in the manual pages:
- Linux/Glibc [malloc(3)](https://www.man7.org/linux/man-pages/man3/malloc.3.html), also describes `free()`, `calloc()`, `realloc()` and `reallocarray()`
- Linux/Glibc [malloc_usable_size(3)](https://www.man7.org/linux/man-pages/man3/malloc_usable_size.3.html)
- Linux/Glibc [posix_memalign(3)](https://www.man7.org/linux/man-pages/man3/posix_memalign.3.html), also describes `aligned_alloc()`
- Posix [malloc(3p)](https://www.man7.org/linux/man-pages/man3/malloc.3p.html), [free(3p)](https://www.man7.org/linux/man-pages/man3/free.3p.html),
[calloc(3p)](https://www.man7.org/linux/man-pages/man3/calloc.3p.html), [realloc(3p)](https://www.man7.org/linux/man-pages/man3/realloc.3p.html) and  [posix_memalign(3p)](https://www.man7.org/linux/man-pages/man3/posix_memalign.3p.html)

Glibc's [description](https://www.gnu.org/software/libc/manual/html_node/Replacing-malloc.html) how to replace the built-in allocator.

## Implementation
Small allocations are taken from slabs with sizes of 16, 32, 64, 128, 256, 512, 1024 or 2048 bytes.
All slabs in a page are same size. Slabs come from a single page, so slabs in different pages will not be in adjacent pages.
The slabs are not resized and multiple slabs can't be allocated together,
so if more memory is requested with `realloc()`, a new, larger slab is allocated.
A small bitmap in each page table entry is used to account allocations and deallocations for a slab page.
Entries are allocated from the bitmap in (weak) random order.

Large allocations starting from 2049 bytes are allocated and freed at page granularity.

The page tables are allocated from a dedicated slab pool.
This means that the page tables will not be adjacent to memory given to the callers of the library.
As an exception, the main state occupies several smaller slabs, since it will never be freed.

New memory is allocated with `mmap()` and the address of the new memory is randomized with `getrandom()`.
Flag `MAP_FIXED_NOREPLACE` is used to avoid mapping new memory over an existing memory mapping.
If the kernel rejects the address, `mmap()` is retried with a new random address.
In the 47 bit address space available on many 64 bit processors, this should happen very rarely.
Depending on alignment restrictions (minimum default 16 bytes), also the low bits are randomized when possible.

Using this library on 32 bit systems may be a bad idea.

`sbrk()`/`brk()` is not used at all. This function returns predictable addresses and it should never be used.

The library will also aggressively unmap any `free()`d memory or if that is not possible,
fill the memory with non-zero bytes (inspired by BSD `malloc()` implementations).
This also applies to old memory in `realloc()`.
Unmapping and filling can help find use-after-free ([CWE-416](https://cwe.mitre.org/data/definitions/416.html)) bugs.
Filling can be turned off at runtime.

The current implementation uses CPU page table like multi level
structures to access pages rapidly.
There are tables for each size class and also a global table for `free()`.
Each intermediate table contains a number of pointers to small or large
pagelist entries, or to further intermediate tables.
The table is indexed by bits of the address (like CPU page tables) and
the type of an entry is identified by low bits of the address.
Leaf entries can exist at any level.

The implementation is O(log N) for both allocating and `free()` for
large (4096 up) allocations but O(N) for allocation of small items.
Previous versions used a hash table (O(N) for `free()` for large
number of allocations, though O(1) for the first 512) or linked lists
(O(N) for any operation).

Some Glibc specific deviations (`malloc(0)`, `calloc(X, Y)` where X * Y == 0, `errno` handling of `posix_memalign()`) are configurable
to help portability to non-Glibc systems. For normal use, it's better to match Glibc in such cases.

### Previous implementations

[Wikipedia](https://en.wikipedia.org/wiki/C_dynamic_memory_allocation) covers several implementations.

- Glibc [Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals), [source](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=2ba1fee144f5742daa0fdc72088f73d4c3049ffe;hb=HEAD)
- Musl [mallocng](https://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/malloc.c)
- TCMalloc [Design](https://google.github.io/tcmalloc/design.html), [source](https://github.com/google/tcmalloc)
- Hardened malloc [source](https://github.com/GrapheneOS/hardened_malloc)
- OpenBSD malloc [man](https://man.openbsd.org/malloc), [source](https://cvsweb.openbsd.org/src/lib/libc/stdlib/malloc.c)

## TODO

Fix bugs.

Integration, packaging, CI etc.

For some loss of memory (which is secondary), further low bits of the start address could randomized always
(select larger slab size than requested, use extra space for randomization).

For x86-64, even the 16 bytes alignment could be made optional (are there any hard alignment restrictions? performance does not count).
Glibc uses 8 bytes alignment by default.

In case memory next to the allocation is filled with junk characters, `free()` should check that they are intact.

Also when memory slab is reused on allocation, the memory could be checked for writes after `free()` by the previous user.
Even all free blocks could be checked in the same page.

Randomization function for allocation of slabs by scrambling the bitmap is weak.
The goal is
that, given an address of an allocated memory block, it's impossible
to determine addresses of previous or future allocations in the same
slab page without knowing the secret (which is not in the same
page). This is also helped by having a separate state for each slab
page. Of course the number of entries in a page is always very
small.
  
Statistics of real usage patterns should be considered. If an application is not using a lot of small allocations,
the slab mechanism could be dropped and full pages would be always allocated, so each allocation would be truly separate from others.
This wastes memory but could be acceptable with some applications.

Global state could be randomized a bit by splitting it to page table slab sized smaller pieces and allocating them randomly.

The design should be very easy to extend to multithreaded allocator: each thread would get it's own global state pointer (as thread local storage)
and own global structure, so there would be no locking issues.
Freeing memory from a different thread would not be possible or very hard.

Debugging could be more robust in multithread environment and early library startup.

In case a huge alignment (bad for ASLR) is requested, hugepages could be used for `posix_memalign()` and `aligned_alloc()`.

Guard pages (`mprotect(,, PROT_NONE)`) are used before and after the allocated pages, to prevent other mappings getting too near.
Maybe the guard pages could be even larger than one page, for example fill the entire 2MB page table entry, especially for large allocations.
If they hold a small number of large items (as opposed to large number of small items), a small guard may not be enough.
That should only affect kernel's internal VMA structures, not CPU page tables.

On Intel CPUs, `pkey_mprotect()` could be used to protect internal structures with [pkeys](https://man7.org/linux/man-pages/man7/pkeys.7.html) (weakly).

Fully used slab pages could be kept in separate page table lists, so they wouldn't be consulted when looking for a free slab.

Internal page tables could also use multi level page table approach to speed up `pagetable_free()`.
