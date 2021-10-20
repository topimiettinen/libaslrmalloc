# SPDX-License-Identifier: LGPL-2.1-or-later OR BSD-3-Clause

project('libaslrmalloc',
  'c',
  version: '1.0.0-alpha',
  meson_version: '>=0.52.1',
  license: ['LGPL-2.1-or-later', 'BSD-3-Clause'],
)

conf = configuration_data()
prefixdir = get_option('prefix')
libdir = prefixdir / 'lib'
sysconfdir = prefixdir / get_option('sysconfdir')
conf.set_quoted('LIBDIR', libdir)
conf.set_quoted('SYSCONFDIR', sysconfdir)
config_h = configure_file(
  output : 'config.h',
  configuration : conf)

add_project_arguments('-fno-builtin', language: 'c')
add_project_link_arguments('-ldl', language: 'c')

threads = dependency('threads')
libaslrmalloc = shared_library('aslrmalloc',
  'libaslrmalloc.c',
  dependencies: threads,
  version: meson.project_version().split('-').get(0),
  install: true,
)

#
# Tests
#

# Change this to project_source_root when we upgrade to meson 0.56 or higher
test_profile_dir = meson.source_root() / 'tests'
test_1 = executable('test_1',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DPROFILE_DIR="@0@"'.format(test_profile_dir), '-DEXPECT_PROFILE_CHANGE'],
)
test('test_1', test_1, env: [
  'LIBASLRMALLOC_DEBUG=1',
  'LIBASLRMALLOC_FILL_JUNK=X',
  'LIBASLRMALLOC_STATS=y',
  'LIBASLRMALLOC_STRICT_MALLOC0=yes',
  'LIBASLRMALLOC_STRICT_POSIX_MEMALIGN_ERRNO=true',
  ]
)
test('test_1_b', test_1, env: [
  'LIBASLRMALLOC_PASSTHROUGH=1',
  ]
)

# Warning: test allocates 2^ROUNDS1 memory
test_2 = executable('test_2',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DDEBUG_2', '-DROUNDS1=10', '-DROUNDS2=16'],
)
test('test_2', test_2, env: ['LIBASLRMALLOC_FILL_JUNK='])

cat = find_program('cat')
preload = environment({'LD_PRELOAD': libaslrmalloc.full_path()})
test('test_3', cat, args: '/proc/self/maps', env: preload)

test_4 = executable('test_4',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DLIBC'],
)
test('test_4', test_4)

test_5 = executable('test_5',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DDEBUG_2', '-DROUNDS1=1', '-DROUNDS2=520'],
)
test('test_5', test_5)

# Test zero sized profile
test_6 = executable('test_6',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DROUNDS1=1', '-DROUNDS2=1',
  '-DPROFILE_DIR="@0@"'.format(test_profile_dir)],
)
test('test_6', test_6)

# Test too large profile
test_7 = executable('test_7',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DROUNDS1=1', '-DROUNDS2=1',
  '-DPROFILE_DIR="@0@"'.format(test_profile_dir)],
)
test('test_7', test_7)

# Test passthrough profile
test_8 = executable('test_8',
  'libaslrmalloc.c',
  c_args: ['-DDEBUG', '-DROUNDS1=1', '-DROUNDS2=1', '-DEXPECT_PASSTHROUGH',
  '-DPROFILE_DIR="@0@"'.format(test_profile_dir)],
)
test('test_8', test_8, env: [
  'LIBASLRMALLOC_DEBUG=0',
  'LIBASLRMALLOC_STATS=n',
  'LIBASLRMALLOC_STRICT_MALLOC0=no',
  'LIBASLRMALLOC_STRICT_POSIX_MEMALIGN_ERRNO=false',
  ]
)
