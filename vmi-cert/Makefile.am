bin_PROGRAMS = \
	vmi-certificate-manager

noinst_HEADERS = \
        vmi_cert_entry.hpp \
	vmi_certs_manager.hpp


vmi_certificate_manager_SOURCES = \
	mainapp.cpp \
        vmi_cert_entry.cpp \
	vmi_certs_manager.cpp

vmi_certificate_manager_LDFLAGS = \
	$(SDBUSPLUS_LIBS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	-lstdc++fs

vmi_certificate_manager_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS)
