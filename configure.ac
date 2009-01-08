# +------------------------------------------------------------------+
# | madwimax: configure.in                                           |
# +------------------------------------------------------------------+

# madwimax version number is defined here and *only* here
AC_INIT(madwimax, 0.0.2, [http://code.google.com/p/madwimax/issues/list])
echo "MadWimax version ${PACKAGE_VERSION}"
AC_CANONICAL_SYSTEM
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Use "./configure --enable-maintainer-mode" to keep Makefile.in and Makefile
# in sync after SVN updates.
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_VPRINTF
AC_FUNC_WAIT3
AC_CHECK_FUNCS([gettimeofday memset socket strerror])

# Check for libusb-1.0
PKG_CHECK_MODULES([libusb1], libusb-1.0,,exit)
CFLAGS="$CFLAGS $libusb1_CFLAGS"
LDFLAGS="$LDFLAGS $libusb1_LIBS"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
