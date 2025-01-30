gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
gmock_dep = dependency('gmock', disabler: true, required: false)
if not gtest_dep.found() or not gmock_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ]
        )
        gmock_dep = gtest_proj.dependency('gmock')
    else
        assert(
            not get_option('tests').allowed(),
            'Googletest is required if tests are enabled'
        )
    endif
endif

test(
    'test_argument',
    executable(
        'argument_test',
        'argument_test.cpp',
        include_directories: '..',
        dependencies: [
            gtest_dep,
            gmock_dep,
            cert_manager_dep,
        ],
    ),
)

test(
    'test_certs_manager',
    executable(
        'test-certs-manager',
        'certs_manager_test.cpp',
        include_directories: '..',
        dependencies: [
            gtest_dep,
            gmock_dep,
            cert_manager_dep,
        ],
    ),
    timeout: 500, # Takes about 1 minute to generate all the certs.
                  # considering valgrind enabled path setting up this 500 sec.
)

if get_option('ca-cert-extension').allowed()
    test(
        'test_ca_certs_manager',
        executable(
            'test-ca-certs-manager',
            'ca_certs_manager_test.cpp',
            include_directories: '..',
            dependencies: [
                gtest_dep,
                gmock_dep,
                bmc_vmi_ca_dep,
            ],
        ),
    )
endif
