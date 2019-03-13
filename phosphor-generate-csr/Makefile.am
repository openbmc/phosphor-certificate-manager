sbin_PROGRAMS = phosphor-generate-csr

noinst_HEADERS = generate_csr.hpp

phosphor_generate_csr_SOURCES = \
				main.cpp \
                generate_csr.cpp

phosphor_generate_csr_LDFLAGS = $(SDBUSPLUS_LIBS) \
                             $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                             $(PHOSPHOR_LOGGING_LIBS) \
                             $(OPENSSL_LIBS)

phosphor_generate_csr_CXXFLAGS = $(SYSTEMD_CFLAGS) \
                              $(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
                              $(PHOSPHOR_LOGGING_CFLAGS)
