# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-certificate-manager], [1.0], [https://github.com/openbmc/phosphor-certificate-manager/issues])
AC_LANG([C++])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for library functions
LT_INIT # Required for systemd linking

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

# For libtools
LT_INIT

AC_ARG_VAR(BUSNAME, [The Dbus busname to own])
AS_IF([test "x$BUSNAME" == "x"], [BUSNAME="xyz.openbmc_project.Certs.Manager"])
AC_DEFINE_UNQUOTED([BUSNAME], ["$BUSNAME"], [The Dbus busname to own])
AC_ARG_VAR(OBJPATH, [The certificate manager Dbus root])
AS_IF([test "x$OBJPATH" == "x"], [OBJPATH="/xyz/openbmc_project/certs"])
AC_DEFINE_UNQUOTED([OBJPATH], ["$OBJPATH"], [The certificate manager Dbus root])

# Create configured output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
