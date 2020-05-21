# Ignore system headers
CODE_COVERAGE_IGNORE_PATTERN = '/include/*' '/usr/include/*' '$(includedir)/*'
export CODE_COVERAGE_IGNORE_PATTERN

CODE_COVERAGE_LCOV_SHOPTS = $(CODE_COVERAGE_LCOV_SHOPTS_DEFAULT)
# Use our configuration file for lcov
CODE_COVERAGE_LCOV_SHOPTS += --config-file $(abs_srcdir)/.lcovrc
export CODE_COVERAGE_LCOV_SHOPTS
#
CODE_COVERAGE_LCOV_OPTIONS = $(CODE_COVERAGE_LCOV_OPTIONS_DEFAULT)
# Use our configuration file for lcov
CODE_COVERAGE_LCOV_OPTIONS += --config-file $(abs_srcdir)/.lcovrc
export CODE_COVERAGE_LCOV_OPTIONS

CODE_COVERAGE_LCOV_RMOPTS = $(CODE_COVERAGE_LCOV_RMOPTS_DEFAULT)
# Use our configuration file for lcov
CODE_COVERAGE_LCOV_RMOPTS += --config-file $(abs_srcdir)/.lcovrc
export CODE_COVERAGE_LCOV_RMOPTS

CODE_COVERAGE_GENHTML_OPTIONS = $(CODE_COVERAGE_GENHTML_OPTIONS_DEFAULT)
# Use our configuration file for genhtml
CODE_COVERAGE_GENHTML_OPTIONS += --config-file $(abs_srcdir)/.lcovrc
# Don't generate the absolute path for each file in the HTML output
CODE_COVERAGE_GENHTML_OPTIONS += --prefix $(abs_srcdir) --prefix $(abs_builddir)
export CODE_COVERAGE_GENHTML_OPTIONS

if AUTOCONF_CODE_COVERAGE_2019_01_06
include $(top_srcdir)/aminclude_static.am
clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean
else
@CODE_COVERAGE_RULES@
endif

AM_LIBS = $(CODE_COVERAGE_LIBS)
AM_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS) -UNDEBUG $(GTEST_CPPFLAGS)
AM_CFLAGS = $(CODE_COVERAGE_CFLAGS)
AM_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
AM_LDFLAGS = $(GMOCK_LIBS) -lgmock_main \
	$(GTEST_LIBS) $(OESDK_TESTCASE_FLAGS) $(PTHREAD_LIBS)

AM_DEFAULT_SOURCE_EXT = .cpp

# Build these headers, don't install them
noinst_HEADERS = \
	certs_manager.hpp \
	argument.hpp \
	certificate.hpp \
	csr.hpp \
	watch.hpp

bin_PROGRAMS = \
	phosphor-certificate-manager

phosphor_certificate_manager_SOURCES = \
	mainapp.cpp \
	certs_manager.cpp \
	argument.cpp \
	certificate.cpp \
	csr.cpp \
	watch.cpp

phosphor_certificate_manager_LDFLAGS = \
	$(SDBUSPLUS_LIBS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_LIBS) \
	$(PHOSPHOR_LOGGING_LIBS) \
	$(OPENSSL_LIBS) \
	-lstdc++fs

phosphor_certificate_manager_CXXFLAGS = \
	$(SYSTEMD_CFLAGS) \
	$(SDEVENTPLUS_LIBS) \
	$(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
	$(PHOSPHOR_LOGGING_CFLAGS)

SUBDIRS = test

check_PROGRAMS =
XFAIL_TESTS =

TESTS = $(check_PROGRAMS)
