project(
    'phosphor-certificate-manager',
    'cpp',
    default_options: [
        'buildtype=debugoptimized',
        'cpp_std=c++20',
        'warning_level=3',
        'werror=true',
    ],
    meson_version: '>=0.57.0',
)

cpp = meson.get_compiler('cpp')

sdbusplus_dep = dependency('sdbusplus')
sdeventplus_dep = dependency('sdeventplus')
phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
phosphor_logging_dep = dependency('phosphor-logging')

systemd_dep = dependency('systemd')
openssl_dep = dependency('openssl')

config_data = configuration_data()
config_data.set(
    'authority_limit',
     get_option('authority-limit')
)

configure_file(
    input: 'config.h.in',
    output: 'config.h',
    configuration: config_data
)

phosphor_certificate_deps = [
    openssl_dep,
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
    sdeventplus_dep,
]

cert_manager_lib = static_library(
    'phosphor-certificate-manager',
    [
        'argument.cpp',
        'certificate.cpp',
        'certs_manager.cpp',
        'csr.cpp',
        'watch.cpp',
    ],
    dependencies: phosphor_certificate_deps,
)

cert_manager_dep = declare_dependency(
    link_with: cert_manager_lib,
    dependencies: phosphor_certificate_deps
)

executable(
    'phosphor-certificate-manager',
    'mainapp.cpp',
    dependencies: cert_manager_dep,
    install: true,
)

if not get_option('ca-cert-extension').disabled()
  subdir('bmc-vmi-ca')
endif

subdir('dist')

if not get_option('tests').disabled()
    subdir('test')
endif

