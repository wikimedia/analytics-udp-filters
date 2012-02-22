bin_PROGRAMS = udp-filter
udp_filter_SOURCES = src/udp-filter.c src/udp-filter.h src/countries.c src/countries.h
AM_CPPFLAGS = $(GEOIP_CFLAGS) -g
udp_filter_LDADD = $(GEOIP_LIBS) $(DEPS_LIBS) -lGeoIP

#If you know a way how to automatically detect a library, then please contact me or submit a patch. 
