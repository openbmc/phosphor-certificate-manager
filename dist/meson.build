systemd_system_unit_dir = systemd_dep.get_variable('systemdsystemunitdir')
busconfig_dir = get_option('datadir') / 'dbus-1' / 'system.d'
cert_manager_dir = get_option('datadir') / 'phosphor-certificate-manager'

certs = []
busconfig = []
service_files = ['phosphor-certificate-manager@.service']
systemd_alias = []

if not get_option('ca-cert-extension').disabled()
    busconfig += 'busconfig/bmc-vmi-ca.conf'
    service_files += 'bmc-vmi-ca-manager.service'
endif

if not get_option('config-bmcweb').disabled()
    busconfig += 'busconfig/phosphor-bmcweb-cert-config.conf'
    certs += 'env/bmcweb'
    systemd_alias += [
        [
            '../phosphor-certificate-manager@.service',
            'multi-user.target.wants/phosphor-certificate-manager@bmcweb.service',
        ],
    ]
endif

if not get_option('config-authority').disabled()
    busconfig += 'busconfig/phosphor-authority-cert-config.conf'
    certs += 'env/authority'
    systemd_alias += [
        [
            '../phosphor-certificate-manager@.service',
            'multi-user.target.wants/phosphor-certificate-manager@authority.service',
        ],
    ]
        
endif

install_data(service_files, install_dir: systemd_system_unit_dir)
install_data(busconfig, install_dir: busconfig_dir)
install_data(certs, install_dir: cert_manager_dir)

foreach service : systemd_alias
    # Meson 0.61 will support this:
    #install_symlink(
    #      service,
    #      install_dir: systemd_system_unit_dir,
    #      pointing_to: link,
    #  )
    meson.add_install_script(
        'sh',
        '-c',
        'mkdir -p $(dirname $DESTDIR/@0@/@1@)'.format(
            systemd_system_unit_dir,
            service[1],
        ),
    meson.add_install_script(
        'sh',
        '-c',
        'ln -s @0@ $DESTDIR/@1@/@2@'.format(
            service[0], systemd_system_unit_dir,
            service[1],
       ),
    )
endforeach
