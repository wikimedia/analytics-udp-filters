PACKAGE=udp-filters
VERSION=DEBIANIZE_REPLACES_THIS_VERSION
EMAIL=dvanliere@wikimedia.org

AC_INIT([udp-filters],[DEBIANIZE_REPLACES_THIS_VERSION],[dvanliere@wikimedia.org])
AC_CONFIG_SRCDIR([src/udp-filter.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

AC_PROG_MAKE_SET


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

AC_PATH_PROG(HELP2MAN, help2man, false // No help2man //)

##########################################################################
# debug compilation support
##########################################################################

AC_ARG_ENABLE(debug,
 [  --enable-debug ],
 [ debugit=yes
 ])

if test x"$debugit" = x"yes"; then
    AM_CXXFLAGS="$AM_CPPFLAGS -g -Wall -pedantic -Werror -Wno-uninitialized -O0"
else
    AM_CXXFLAGS="$AM_CPPFLAGS -O3 -Wall"
fi
 
##########################################################################


AC_SUBST([AM_CXXFLAGS])


AC_PROG_CC_C99
AC_CHECK_LIB(geoip, GeoIP_num_countries)
#AC_CHECK_HEADERS([GeoIPCity.h],[GeoIP.h],[udp_filter_found_int_headers=yes; break;])


AC_CONFIG_FILES(Makefile)

AC_OUTPUT
