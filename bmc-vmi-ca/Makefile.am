bin_PROGRAMS = \
	bmc-vmi-ca

noinst_HEADERS = \
	ca_cert_entry.hpp \
	ca_certs_manager.hpp

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	bmc-vmi-ca-manager.service
endif

bmc_vmi_ca_SOURCES = \
	mainapp.cpp \
	ca_cert_entry.cpp \
	ca_certs_manager.cpp

bmc_vmi_ca_LDFLAGS = \
	$(SDBUSPLUS_LIBS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	-lstdc++fs

bmc_vmi_ca_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS)
