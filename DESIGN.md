# Design

## Security

The first and foremost goal of the library is to maximize address space layout randomization
([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)).
Other goals such as
- efficiency of memory use
- impacts to CPU page tables or caches
- kernel's ability to handle large number of VMAs
- performance of `malloc()`, `realloc()` or `free()`
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

## Implementation
Small allocations are taken from slabs with sizes of 16, 32, 64, 128, 256, 512, 1024 or 2048 bytes.
All slabs in a page are same size. Slabs come from a single page, so slabs in different pages will not be in adjacent pages.
The slabs are not resized and multiple slabs can't be allocated together,
so if more memory is requested with `realloc()`, a new, larger slab is allocated.
A small bitmap in each page table entry is used to account allocations and deallocations for a slab page.

Large allocations starting from 2049 bytes are allocated and freed at page granularity.

The page tables are allocated from a dedicated slab pool.
This means that the page tables will not be adjacent to memory given to the callers of the library.
As an exception, the main state occupies several smaller slabs, since it will never be freed.

New memory is allocated with `mmap()` and the address of the new memory is randomized with `getrandom()`.
Flag `MAP_FIXED_NOREPLACE` is used to avoid mapping new memory over an existing memory mapping.
If the kernel rejects the address, `mmap()` is retried with a new random address.
In the 47 bit address space available on 64 bit processors, this should happen very rarely.
Using this library on 32 bit systems may be a bad idea.

The library will also aggressively unmap any `free()`d memory or if that is not possible,
fill the memory with non-zero bytes (inspired by BSD `malloc()` implementations).
This also applies to old memory in `realloc()`.
Unmapping and filling can help find use-after-free ([CWE-416](https://cwe.mitre.org/data/definitions/416.html)) bugs.
Filling can be turned off at compile time.

## TODO

Fix bugs.

Integration, packaging, CI etc.

When more slabs or large pages are needed, linked lists are used to connect them to main structure.
This could be optimized to use hash tables (or modern tree structures) to speed up freeing memory without weakening ASLR.

Some opportunities to increase ASLR further are not yet utilized:
- randomize order of allocation of slabs by scrambling the bitmap bits instead of linear search from bit 0.
- randomize low bits of the start address if the allocation is smaller (by multiples of 16 bytes for alignment) than the slab or pages for large allocations.
For some loss of memory (which is secondary), this could be done always (select larger slab size than requested, use extra space for randomization).
- for x86-64, even the 16 byte alignment could be made optional (are there any hard alignment restrictions? performance does not count).

Statistics of real usage patterns should be considered. If an application is not using a lot of small allocations,
the slab mechanism could be dropped and full pages would be always allocated, so each allocation would be truly separate from others.
This wastes memory but could be acceptable with some applications.

Related to the above, the library could be made tunable to fit several different scenarios with different implementations.
The library could even try to find out the name of the application and automatically load different application profiles
(like profiles of [Firejail](https://github.com/netblue30/firejail)), or use for example a configuration file or an environment variable.

Global state could be randomized a bit by splitting it to page table slab sized smaller pieces and allocating them randomly.

The design should be very easy to extend to multithreaded allocator: each thread would get it's own global state pointer (as thread local storage)
and own global structure, so there would be no locking issues.
Freeing memory from a different thread would not be possible or very hard.
