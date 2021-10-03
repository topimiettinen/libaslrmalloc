# libaslrmalloc
[![Build CI](https://github.com/topimiettinen/libaslrmalloc/workflows/GitHub%20CI/badge.svg)](https://github.com/topimiettinen/libaslrmalloc/actions?query=workflow%3A%22GitHub+CI%22)
[![CodeQL](https://github.com/topimiettinen/libaslrmalloc/workflows/CodeQL/badge.svg)](https://github.com/topimiettinen/libaslrmalloc/actions?query=workflow%3ACodeQL)
[![Coverage Status](https://coveralls.io/repos/github/topimiettinen/libaslrmalloc/badge.svg?branch=master)](https://coveralls.io/github/topimiettinen/libaslrmalloc?branch=master)

`libaslrmalloc` is a LD_PRELOADed library which replaces `malloc()`,
`free()`, `realloc()`,`calloc()` and `malloc_usable_size()` from C library. The main design
goal is not performance or memory consumption but to increase address space
layout randomization ([ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization)), hence the name.
This is achieved by not trying to keep the pages together, forcing the kernel to map
pages at random addresses and unmapping old memory immediately when possible.

It has the following features:
* buggy
* drains kernel random bits pool
* fragments memory layout, consuming more memory in kernel page tables
* trashes caches, slowing down the system
* multithread unsafe
* also buggy

Reading the [design document](/DESIGN.md) may present more complete view.

[![SPDX-License-Identifier: LGPL-2.1-or-later](https://img.shields.io/static/v1?label=SPDX-License-Identifier&message=LGPL-2.1-or-later&color=blue&logo=open-source-initiative&logoColor=white&logoWidth=10&style=flat-square)](LICENSES/LGPL-2.1-or-later)
[![SPDX-License-Identifier: BSD-3-Clause](https://img.shields.io/static/v1?label=SPDX-License-Identifier&message=BSD-3-Clause&color=blue&logo=open-source-initiative&logoColor=white&logoWidth=10&style=flat-square)](LICENSES/BSD-3-Clause)

`libaslrmalloc` is licensed with either [LGPL 2.1 (or later)](LICENSES/LGPL-2.1-or-later) or [BSD 3-clause](LICENSES/BSD-3-Clause) licenses.
Directory LICENCES contains the license texts.
SPDX License Identifiers can be found in source files.

Examples:

The examples below disable kernel's ASLR to see the difference:
```bash
$ cat /proc/sys/kernel/randomize_va_space
0
```

Memory map with the library:
```bash
$ LD_PRELOAD=/home/topi/libaslrmalloc.so cat /proc/self/maps
f65d5630000-f65d5631000 rw-p 00000000 00:00 0 
10a32f846000-10a32f847000 rw-p 00000000 00:00 0 
148906208000-148906209000 rw-p 00000000 00:00 0 
1af26a917000-1af26a938000 rw-p 00000000 00:00 0 
22b4a36c0000-22b4a36c1000 rw-p 00000000 00:00 0 
31768fb98000-31768fb99000 rw-p 00000000 00:00 0 
3cbc9feed000-3cbc9feee000 rw-p 00000000 00:00 0 
555555554000-555555556000 r--p 00000000 fe:0c 1868624                    /usr/bin/cat
555555556000-55555555b000 r-xp 00002000 fe:0c 1868624                    /usr/bin/cat
55555555b000-55555555e000 r--p 00007000 fe:0c 1868624                    /usr/bin/cat
55555555e000-55555555f000 r--p 00009000 fe:0c 1868624                    /usr/bin/cat
55555555f000-555555560000 rw-p 0000a000 fe:0c 1868624                    /usr/bin/cat
5cc5dfb01000-5cc5dfb02000 rw-p 00000000 00:00 0 
6e6b82877000-6e6b82878000 rw-p 00000000 00:00 0 
7ffff786c000-7ffff7dcf000 r--p 00000000 fe:0c 2475246                    /usr/lib/locale/locale-archive
7ffff7dcf000-7ffff7dd2000 rw-p 00000000 00:00 0 
7ffff7dd2000-7ffff7df7000 r--p 00000000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7df7000-7ffff7f42000 r-xp 00025000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f42000-7ffff7f8c000 r--p 00170000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f8c000-7ffff7f8d000 ---p 001ba000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f8d000-7ffff7f90000 r--p 001ba000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f90000-7ffff7f93000 rw-p 001bd000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f93000-7ffff7f97000 rw-p 00000000 00:00 0 
7ffff7fc5000-7ffff7fc6000 r--p 00000000 fe:03 5657396                    /home/topi/libaslrmalloc.so
7ffff7fc6000-7ffff7fc7000 r-xp 00001000 fe:03 5657396                    /home/topi/libaslrmalloc.so
7ffff7fc7000-7ffff7fc8000 r--p 00002000 fe:03 5657396                    /home/topi/libaslrmalloc.so
7ffff7fc8000-7ffff7fc9000 r--p 00002000 fe:03 5657396                    /home/topi/libaslrmalloc.so
7ffff7fc9000-7ffff7fca000 rw-p 00003000 fe:03 5657396                    /home/topi/libaslrmalloc.so
7ffff7fca000-7ffff7fcc000 rw-p 00000000 00:00 0 
7ffff7fcc000-7ffff7fd0000 r--p 00000000 00:00 0                          [vvar]
7ffff7fd0000-7ffff7fd2000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fd2000-7ffff7fd3000 r--p 00000000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7fd3000-7ffff7ff3000 r-xp 00001000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ff3000-7ffff7ffb000 r--p 00021000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffc000-7ffff7ffd000 r--p 00029000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffd000-7ffff7ffe000 rw-p 0002a000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

Compare with glibc malloc() version:
```bash
$ cat /proc/self/maps
555555554000-555555556000 r--p 00000000 fe:0c 1868624                    /usr/bin/cat
555555556000-55555555b000 r-xp 00002000 fe:0c 1868624                    /usr/bin/cat
55555555b000-55555555e000 r--p 00007000 fe:0c 1868624                    /usr/bin/cat
55555555e000-55555555f000 r--p 00009000 fe:0c 1868624                    /usr/bin/cat
55555555f000-555555560000 rw-p 0000a000 fe:0c 1868624                    /usr/bin/cat
555555560000-555555581000 rw-p 00000000 00:00 0                          [heap]
7ffff7874000-7ffff7dd7000 r--p 00000000 fe:0c 2475246                    /usr/lib/locale/locale-archive
7ffff7dd7000-7ffff7dfc000 r--p 00000000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7dfc000-7ffff7f47000 r-xp 00025000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f47000-7ffff7f91000 r--p 00170000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f91000-7ffff7f92000 ---p 001ba000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f92000-7ffff7f95000 r--p 001ba000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f95000-7ffff7f98000 rw-p 001bd000 fe:0c 2402236                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7ffff7f98000-7ffff7f9e000 rw-p 00000000 00:00 0 
7ffff7faa000-7ffff7fcc000 rw-p 00000000 00:00 0 
7ffff7fcc000-7ffff7fd0000 r--p 00000000 00:00 0                          [vvar]
7ffff7fd0000-7ffff7fd2000 r-xp 00000000 00:00 0                          [vdso]
7ffff7fd2000-7ffff7fd3000 r--p 00000000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7fd3000-7ffff7ff3000 r-xp 00001000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ff3000-7ffff7ffb000 r--p 00021000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffc000-7ffff7ffd000 r--p 00029000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffd000-7ffff7ffe000 rw-p 0002a000 fe:0c 2400547                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

In reality `cat` does not use `malloc()` much.
