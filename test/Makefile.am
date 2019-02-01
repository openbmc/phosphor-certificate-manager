AM_CPPFLAGS = \
	-I$(top_srcdir)

AM_CFLAGS = \
	$(SDBUSPLUS_CFLAGS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS)

AM_CXXFLAGS =

AM_LDFLAGS = \
	-lstdc++fs \
	$(SDBUSPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(OPENSSL_LIBS) \
	$(GTEST_LIBS) -lgmock_main $(GMOCK_LIBS) \
	$(OESDK_TESTCASE_FLAGS)

check_PROGRAMS =

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# Build/add certs_manager_test to test suite
check_PROGRAMS += certs_manager_test
certs_manager_test_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_CPPFLAGS)
certs_manager_test_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)
certs_manager_test_SOURCES = certs_manager_test.cpp
certs_manager_test_LDADD = $(top_builddir)/certs_manager.o
certs_manager_test_LDADD += $(top_builddir)/certificate.o
