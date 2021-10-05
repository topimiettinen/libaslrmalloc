# SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

project('libaslrmalloc', 'c', license : ['LGPL-2.1-or-later', 'BSD-3-Clause'])

libaslrmalloc_version = '1'

libdir = get_option('prefix') / get_option('libdir')

threads = dependency('threads')
libaslrmalloc = shared_library('aslrmalloc', 'libaslrmalloc.c', dependencies: threads, version: libaslrmalloc_version, install: true, install_dir: libdir, c_args: '-fno-builtin')

test_1 = executable('test_1', 'libaslrmalloc.c', c_args: ['-DDEBUG', '-fno-builtin'])
test('test_1', test_1)

# Warning: test allocates 2^ROUNDS1 memory
test_2 = executable('test_2', 'libaslrmalloc.c', c_args: ['-DDEBUG', '-DDEBUG_2', '-DROUNDS1=10', '-DROUNDS2=16', '-fno-builtin'])
test('test_2', test_2)

cat = find_program('cat')
preload = environment({'LD_PRELOAD': libaslrmalloc.full_path()})
test('test_3', cat, args: '/proc/self/maps', env: preload)

test_4 = executable('test_4', 'libaslrmalloc.c', c_args: ['-DDEBUG', '-DLIBC', '-fno-builtin'])
test('test_4', test_4)

test_5 = executable('test_5', 'libaslrmalloc.c', c_args: ['-DDEBUG', '-DDEBUG_2', '-DROUNDS1=1', '-DROUNDS2=520', '-fno-builtin'])
test('test_5', test_5)
