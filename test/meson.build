tests = [
  'certs_manager_test.cpp',
]
incdir = ['.','../']

if get_option('oe-sdk').enabled()
  # Setup OE SYSROOT
  OECORE_TARGET_SYSROOT = run_command('sh', '-c', 'echo $OECORE_TARGET_SYSROOT').stdout().strip()
  if OECORE_TARGET_SYSROOT == ''
    error('Unable to get $OECORE_TARGET_SYSROOT, check your environment.')
  endif

  message('OE_SYSROOT: ' + OECORE_TARGET_SYSROOT)

  rpath = ':'.join([OECORE_TARGET_SYSROOT + '/lib', OECORE_TARGET_SYSROOT + '/usr/lib'])
  ld_so = run_command('sh', '-c', 'find ' + OECORE_TARGET_SYSROOT + '/lib/ld-*.so | sort -r -n | head -n1').stdout().strip()
  dynamic_linker = ['-Wl,-dynamic-linker,' + ld_so]

else
  dynamic_linker = []
endif

gtest      = dependency('gtest', main: true, disabler : true,required : get_option('tests'))
gmock      = dependency('gmock',required : get_option('tests'))
thread_dep = dependency('threads')

test('Test',executable('test-binary',tests,
  include_directories : incdir,
  link_with : libcertificate,
  link_args : dynamic_linker,
  build_rpath: get_option('oe-sdk').enabled() ? rpath : '',
  dependencies : [
    gtest,
    gmock,
    thread_dep
    ] + deps),
  timeout:40,
  is_parallel : false)
