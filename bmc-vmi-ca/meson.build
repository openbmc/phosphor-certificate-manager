bmc_vmi_ca_deps = [
    phosphor_dbus_interfaces_dep,
    phosphor_logging_dep,
    sdbusplus_dep,
]

bmc_vmi_ca_lib = static_library(
    'bmc_vmi_ca',
    ['ca_cert_entry.cpp', 'ca_certs_manager.cpp'],
    include_directories: '..',
    dependencies: bmc_vmi_ca_deps,
)

bmc_vmi_ca_dep = declare_dependency(
    link_with: bmc_vmi_ca_lib,
    dependencies: bmc_vmi_ca_deps,
)

executable(
    'bmc-vmi-ca',
    'mainapp.cpp',
    include_directories: '..',
    dependencies: bmc_vmi_ca_dep,
    install: true,
)
