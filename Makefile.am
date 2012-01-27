bin_PROGRAMS = udp_filter
udp_filter_SOURCES = src/udp.c
AM_CPPFLAGS = $(GEOIP_CFLAGS) -g
udp_filter_LDADD = $(GEOIP_LIBS) $(DEPS_LIBS) -lGeoIP

#If you know a way how to automatically detect a library, then please contact me or submit a patch. 