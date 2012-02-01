AC_INIT(src/udp.c)
PACKAGE=udp_filter
VERSION=0.1.0
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AC_PROG_CC_C99
AC_CHECK_LIB(geoip, GeoIP_num_countries)
AC_CONFIG_FILES(Makefile)
AC_CHECK_HEADERS([GeoIP.h],[udp_filter_found_int_headers=yes; break;])
AC_OUTPUT
