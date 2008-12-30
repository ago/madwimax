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

dnl Check for libusb-1.0
PKG_CHECK_MODULES([libusb1], libusb-1.0,,exit)
CFLAGS="$CFLAGS $libusb1_CFLAGS"
LDFLAGS="$LDFLAGS $libusb1_LIBS"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
