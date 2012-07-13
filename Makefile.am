bin_PROGRAMS = udp-filter
udp_filter_SOURCES = src/udp-filter.c src/udp-filter.h src/countries.c src/countries.h
if DEBUG
	AM_CFLAGS = -g3 -O0 -Wall -pedantic
	AM_CXXFLAGS = -g3 -O0 -Wall -pedantic
else
	AM_CLFAGS = -O3
	AM_CXXFLAGS = -O3
endif

AM_CPPFLAGS = $(GEOIP_CFLAGS)
udp_filter_LDADD = $(GEOIP_LIBS) $(DEPS_LIBS) -lGeoIP -lcidr

#If you know a way how to automatically detect a library, then please contact me or submit a patch. 
