AM_CPPFLAGS = \
    -I$(top_srcdir) \
    $(PTHREAD_CPPFLAGS) \
    $(SDBUSPLUS_CPPFLAGS) \
    $(PHOSPHOR_DBUS_INTERFACES_CPPFLAGS)

AM_CFLAGS = \
    $(PTHREAD_CFLAGS) \
    $(SDBUSPLUS_CFLAGS) \
    $(PHOSPHOR_DBUS_INTERFACES_CFLAGS)

AM_CXXFLAGS = \
    $(PTHREAD_CXXFLAGS) \
    $(SDBUSPLUS_CXXFLAGS) \
    $(PHOSPHOR_DBUS_INTERFACES_CXXFLAGS)

AM_LDFLAGS = \
    -lstdc++fs \
    $(SDBUSPLUS_LIBS) \
    $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
    -lgtest -lgtest_main -lgmock $(PTHREAD_CFLAGS) $(OESDK_TESTCASE_FLAGS)

check_PROGRAMS =

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# Build/add certs_manager_test to test suite
check_PROGRAMS += certs_manager_test
certs_manager_test_CPPFLAGS = $(AM_CPPFLAGS) $(GTEST_CPPFLAGS) 
certs_manager_test_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS) $(OESDK_TESTCASE_FLAGS)
certs_manager_test_SOURCES = certs_manager_test.cpp
certs_manager_test_LDADD = $(top_builddir)/certs_manager.o
