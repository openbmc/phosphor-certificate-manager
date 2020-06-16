bin_PROGRAMS = \
	hypervisor-certificate-manager

noinst_HEADERS = \
	hypervisor_cert_entry.hpp \
	hypervisor_certs_manager.hpp

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	hypervisor-certificate-manager.service
endif

hypervisor_certificate_manager_SOURCES = \
	mainapp.cpp \
	hypervisor_cert_entry.cpp \
	hypervisor_certs_manager.cpp

hypervisor_certificate_manager_LDFLAGS = \
	$(SDBUSPLUS_LIBS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	-lstdc++fs

hypervisor_certificate_manager_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS)
