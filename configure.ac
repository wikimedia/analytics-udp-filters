PACKAGE=udp-filter
VERSION=0.2.4
EMAIL=dvanliere@wikimedia.org

AC_INIT([udp-filter],[0.2.2],[dvanliere@wikimedia.org])
AC_CONFIG_SRCDIR([src/udp-filter.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

AC_PROG_MAKE_SET

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

#Checks for header files

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stddef.h stdlib.h string.h sys/socket.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_RESTRICT
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset regcomp strchr strdup strstr])

AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([ctype.h])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([regex.h])
AC_CHECK_HEADERS([libcidr.h])
AC_CHECK_HEADERS([GeoIP.h])
AC_CHECK_HEADERS([GeoIPCity.h])



##########################################################################
# debug compilation support
##########################################################################
 
AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])
 
if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    AM_CXXFLAGS="$AM_CXXFLAGS -g -Wall -pedantic -Werror -Wno-uninitialized -O0"
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CXXFLAGS="$AM_CXXFLAGS -O3 -Wall"
fi
 
##########################################################################


AC_SUBST([AM_CXXFLAGS])


AC_PROG_CC_C99
AC_CHECK_LIB(geoip, GeoIP_num_countries)
#AC_CHECK_HEADERS([GeoIPCity.h],[GeoIP.h],[udp_filter_found_int_headers=yes; break;])


AC_CONFIG_FILES(Makefile)

AC_OUTPUT
