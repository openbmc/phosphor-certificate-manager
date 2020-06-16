project('phosphor-certificate-manager',
        'cpp',
         version: '0.1',
         meson_version: '>=0.53.2',
         default_options: [ 'warning_level=3',
                            'werror=true',
                            'cpp_std=c++17' ])

########################################################################

# Project Links

project_pretty_name = 'phosphor-certificate-manager'
project_url = 'https://github.com/openbmc/' + project_pretty_name
project_issues_url = project_url + '/issues/new'

summary('Issue', project_issues_url, section : 'Report Issues')

#####################################################################

# Validate the c++ Standard

if get_option('cpp_std') != 'c++17'
    error('This project requires cpp std to be in c++17 mode')
endif

#########################################################################

# Get Compiler and default build type

compiler = meson.get_compiler('cpp')

#########################################################################

# Find the dependencies

cppfs           =   compiler.find_library('stdc++fs')
systemd         =   dependency ('systemd', version: '>=221')
sdbusplus       =   dependency ('sdbusplus')
ssl             =   dependency ('openssl')
sdeventplus     =   dependency ('sdeventplus')
logging         =   dependency ('phosphor-logging')
dbus            =   dependency ('phosphor-dbus-interfaces')
deps            =   [cppfs, systemd, sdbusplus, ssl, sdeventplus, logging, dbus]


if compiler.has_header('systemd/sd-bus.h')
    ### Nothing to do
else
    warning('Systemd Development Package Required')
endif

###########################################################################

# Set the compiler flags

add_project_arguments(

  compiler.get_supported_arguments([
    '-Wno-psabi',
    '-Wno-pedantic',
    '-Wno-missing-field-initializers',
    '-fpic',
    '-Wno-unused-result',
    ]),
    language : 'cpp')


add_project_link_arguments('-lstdc++fs', language : 'cpp')

############################################################################

# Get the config data and enable options

conf_data = configuration_data()

busname = get_option('BUSNAME')
conf_data.set_quoted('BUSNAME', busname)

objpath = get_option('OBJPATH')
conf_data.set_quoted('OBJPATH', objpath)

csr_file_name = get_option('CSR_FILE_NAME')
conf_data.set_quoted('CSR_FILE_NAME', csr_file_name)

authority_limit = get_option('AUTHORITY_CERTIFICATES_LIMIT')
conf_data.set('AUTHORITY_CERTIFICATES_LIMIT', authority_limit)

priv_key_file_name = get_option('PRIV_KEY_FILE_NAME')
conf_data.set_quoted('PRIV_KEY_FILE_NAME', priv_key_file_name)

rsa_priv_key_file_name = get_option('RSA_PRIV_KEY_FILE_NAME')
conf_data.set_quoted('RSA_PRIV_KEY_FILE_NAME', rsa_priv_key_file_name)

configure_file(output: 'config.h', configuration: conf_data)


############################################################################

# Gather sources for the target binaries

phosphor_certificate_manager_sources = [
                                        'argument.cpp',
                                        'certificate.cpp',
                                        'certs_manager.cpp',
                                        'csr.cpp',
                                        'watch.cpp',
                                       ]

libcertificate = static_library('libcertificate',
                                 phosphor_certificate_manager_sources,
                                 dependencies : deps)
############################################################################

# Build binaries

executable('phosphor-certificate-manager',
           'mainapp.cpp',
           link_with : libcertificate,
           dependencies : deps,
           install : true)

if get_option('tests').enabled()
    subdir('test')
endif
