# libaslrmalloc
[![Build CI](https://github.com/topimiettinen/libaslrmalloc/workflows/GitHub%20CI/badge.svg)](https://github.com/topimiettinen/libaslrmalloc/actions?query=workflow%3A%22GitHub+CI%22)
[![CodeQL](https://github.com/topimiettinen/libaslrmalloc/workflows/CodeQL/badge.svg)](https://github.com/topimiettinen/libaslrmalloc/actions?query=workflow%3ACodeQL)
[![Coverage Status](https://coveralls.io/repos/github/topimiettinen/libaslrmalloc/badge.svg?branch=master)](https://coveralls.io/github/topimiettinen/libaslrmalloc?branch=master)
[![lgtm alerts](https://img.shields.io/lgtm/alerts/g/topimiettinen/libaslrmalloc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/topimiettinen/libaslrmalloc/alerts/)
[![lgtm language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/topimiettinen/libaslrmalloc.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/topimiettinen/libaslrmalloc/context:cpp)

`libaslrmalloc` is a LD_PRELOADed library which replaces `malloc()` and other memory allocation functions from C library.
The main design goal is not performance or memory consumption but to increase address space
layout randomization ([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)), hence the name.
This is achieved by not trying to keep the pages together, forcing the kernel to map
pages at random addresses and unmapping old memory immediately when possible.

The amount of ALSR depends on processor type, size of allocation and possible user specified alignment (`posix_memalign()`).

Assuming a processor with 48 bits of virtual address space (47 is available to user applications) and no extra alignment restrictions:
Size | Lowest randomized bit | Total
---:|---:|---:
16 | 4 | 43
32 | 5 | 42
64 | 6 | 41
128 | 7 | 40
256 | 8 | 39
512 | 9 | 38
1024 | 10 | 37
2048 | 11 | 36
4096+ | 12 | 35

In addition, if the allocation is between the above sizes, the extra space is used to randomize the start address (within alignment restrictions).
For example, 1600 bytes fit in a slab of 2048 bytes. There's extra space of 2048 - 1600 = 448 bytes to randomize the start of the
allocation, but alignment needs to be taken care of as well.
For 16 bytes (default) alignment, 448 / 16 = 28 different random positions are possible, yielding fractional randomization of 4.8 bits.

`libaslrmalloc` has also the following features:
* drains kernel random bits pool
* fragments memory layout, consuming more memory in kernel page tables
* trashes caches, slowing down the system
* also buggy

Reading the [design document](/DESIGN.md) may present more complete view.

[![SPDX-License-Identifier: LGPL-2.1-or-later](https://img.shields.io/static/v1?label=SPDX-License-Identifier&message=LGPL-2.1-or-later&color=blue&logo=open-source-initiative&logoColor=white&logoWidth=10&style=flat-square)](LICENSES/LGPL-2.1-or-later)
[![SPDX-License-Identifier: BSD-3-Clause](https://img.shields.io/static/v1?label=SPDX-License-Identifier&message=BSD-3-Clause&color=blue&logo=open-source-initiative&logoColor=white&logoWidth=10&style=flat-square)](LICENSES/BSD-3-Clause)

`libaslrmalloc` is licensed with either [LGPL 2.1 (or later)](LICENSES/LGPL-2.1-or-later) or [BSD 3-clause](LICENSES/BSD-3-Clause) licenses.
Directory LICENCES contains the license texts.
SPDX License Identifiers can be found in source files.

## Build

```bash
$ sudo apt-get install build-essential meson
$ meson setup builddir/
$ meson compile -C builddir/ -v
```

## Install

```bash
$ dpkg-buildpackage --no-sign
$ sudo dpkg -i ../libaslrmalloc1_1-1_amd64.deb
```

## Usage

Set the environment variable `LD_PRELOAD` to the path to `libaslrmalloc` before starting the program.
Example: `LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libaslrmalloc.so.1 gedit`

Alternatively you can add `/usr/lib/x86_64-linux-gnu/libaslrmalloc.so.1` to `/etc/ld.so.preload`.
This activates `libaslrmalloc` for all programs on your system including SUID programs (for which `LD_PRELOAD` is ignored).
Only programs in containers such as flatpaks will not use `libaslrmalloc`.

### with systemd

Create a drop-in configuration and add

```
Environment=LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libaslrmalloc.so.1
```

### with Firejail

Create a .local and add

```
env LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libaslrmalloc.so.1
```

Note also that you can not use `LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libaslrmalloc.so.1 program`
if program is a symlink to firejail created by firecfg.

## Environment

`libaslrmalloc` understands the following environment variables:

- `LIBASLRMALLOC_DEBUG`: Enable debugging.
- `LIBASLRMALLOC_PASSTHROUGH`: Forward function calls to the libc implementations.
- `LIBASLRMALLOC_FILL_JUNK`: Can be used to change the fill character or to disable filling if set to an empty string.
- `LIBASLRMALLOC_STRICT_MALLOC0`: If set to 1, `malloc(0)` will return `NULL`.
- `LIBASLRMALLOC_STRICT_POSIX_MEMALIGN_ERRNO`: If set to 1, `posix_memalign()` will restore the old errno in case of an error.
- `LIBASLRMALLOC_STATS`: Enable stats.

Environment variables aren't used if secure execution is required (e.g. SUID programs).

## Profiles
`libaslrmalloc` automatically loads a profile in `/etc/libaslrmalloc/` named `app.profile` using the name of the application. 
The settings in the profile are same as with the environment variables but without the prefix and lowercase, for example:

```
debug
fill_junk=X
strict_malloc0
strict_posix_memalign_errno
stats
```

or

```
passthrough
```

## Examples

The example below disable kernel's ASLR to see the difference:
```bash
$ cat /proc/sys/kernel/randomize_va_space
0
```
Left: `vi` uses glibc `malloc()`, which typically uses heap only.
Right: `libaslrmalloc` has randomized the memory allocations over the address space and there's no heap. 
![image](https://user-images.githubusercontent.com/18518033/136421943-0bc63685-17b4-42af-8ae1-73618bbafd2a.png)

Show statistics on slab use in TSV format:
```bash
$ LIBASLRMALLOC_STATS=1 LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libaslrmalloc.so.1 gnome-system-monitor
Size    Count
16      154
32      482
64      329
128     1245
256     2146
512     6486
1024    3178
2048    1234
4096    2423
```
