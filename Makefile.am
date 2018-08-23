sbin_PROGRAMS =  phosphor_certificate_manager

phosphor_certificate_manager_SOURCES = \
				main.cpp  \
				argument.cpp

phosphor_certificate_manager_LDFLAGS = $(SDBUSPLUS_LIBS) \
                                 $(PHOSPHOR_DBUS_INTERFACES_LIBS)
phosphor_certificate_manager_CFLAGS =  $(SDBUSPLUS_CFLAGS) \
                                 $(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

@CODE_COVERAGE_RULES@

check_PROGRAMS =
XFAIL_TESTS =

TESTS = $(check_PROGRAMS)

clean-local: code-coverage-clean
dist-clean-local: code-coverage-dist-clean
