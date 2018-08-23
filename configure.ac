# Initialization
AC_PREREQ([2.69])
AC_INIT([phosphor-led-sysfs], [1.0], [https://github.com/openbmc/phosphor-led-sysfs/issues])
AC_LANG([C++])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror foreign dist-xz])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
PKG_CHECK_MODULES([SYSTEMD], [libsystemd >= 221])

# Checks for typedefs, structures, and compiler characteristics.
AX_CXX_COMPILE_STDCXX_14([noext])
AX_APPEND_COMPILE_FLAGS([-Wall -Werror], [CXXFLAGS])

# For libtools
LT_INIT

# Checks for header files.
PKG_CHECK_MODULES([SDBUSPLUS], [sdbusplus],, [AC_MSG_ERROR([Could not find sdbusplus...openbmc/sdbusplus package required])])
PKG_CHECK_MODULES([PHOSPHOR_DBUS_INTERFACES], [phosphor-dbus-interfaces],, [AC_MSG_ERROR([Could not find phosphor-dbus-interfaces...openbmc/phosphor-dbus-interfaces package required])])

# Check/set gtest specific functions.
AX_PTHREAD([GTEST_CPPFLAGS="-DGTEST_HAS_PTHREAD=1"],[GTEST_CPPFLAGS="-DGTEST_HAS_PTHREAD=0"])
AC_SUBST(GTEST_CPPFLAGS)

AX_CODE_COVERAGE

AC_ARG_VAR(BUSNAME, [The Dbus busname to own])
AS_IF([test "x$BUSNAME" == "x"], [BUSNAME="xyz.openbmc_project.LED.Controller"])
AC_DEFINE_UNQUOTED([BUSNAME], ["$BUSNAME"], [The Dbus busname to own])
AC_ARG_VAR(OBJPATH, [The physical LED controller Dbus root])
AS_IF([test "x$OBJPATH" == "x"], [OBJPATH="/xyz/openbmc_project/led/physical"])
AC_DEFINE_UNQUOTED([OBJPATH], ["$OBJPATH"], [The physical LED controller Dbus root])

# Platform device path for led subsystem.
AC_ARG_VAR(DEVPATH, [Physical led device path])
AS_IF([test "x$DEVPATH" == "x"], [DEVPATH="/sys/class/leds/"])
AC_DEFINE_UNQUOTED([DEVPATH], ["$DEVPATH"], [Physical led device path])

# Create configured output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
