dnl +------------------------------------------------------------------+
dnl | madwimax: configure.in                                           |
dnl +------------------------------------------------------------------+

dnl madwimax version number is defined here and *only* here
AC_INIT(madwimax, 0.0.2, [http://code.google.com/p/madwimax/issues/list])
echo "MadWimax version ${PACKAGE_VERSION}"
AC_CANONICAL_SYSTEM
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

dnl Use "./configure --enable-maintainer-mode" to keep Makefile.in and Makefile
dnl in sync after SVN updates.
AM_MAINTAINER_MODE

AC_PROG_CC

AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strerror])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_C_CONST
AC_FUNC_VPRINTF
AC_HEADER_STDC
AC_HEADER_TIME
AC_PROG_GCC_TRADITIONAL

dnl Check for libusb-1.0
PKG_CHECK_MODULES([libusb1], libusb-1.0,,exit)
CFLAGS="$CFLAGS $libusb1_CFLAGS"
LDFLAGS="$LDFLAGS $libusb1_LIBS"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
