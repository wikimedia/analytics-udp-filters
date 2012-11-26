CFLAGS=
AM_CPPFLAGS=
AM_CFLAGS=$(AM_CXXFLAGS)

bin_PROGRAMS = udp-filter udp-filter-static


udp_filter_SOURCES = src/udp-filter.c       \
                     src/udp-filter.h       \
                     src/countries.c        \
                     src/countries.h        \
                     src/collector-output.c \
                     src/collector-output.h \
                     src/geo.h              \
                     src/geo.c              \
                     src/anonymize.h        \
                     src/anonymize.c        \
                     src/match.h            \
                     src/match.c            \
                     src/utils.h            \
                     src/utils.c


AM_CPPFLAGS = $(GEOIP_CFLAGS)

udp_filter_LDADD = 	  $(GEOIP_LIBS) $(DEPS_LIBS) -lGeoIP -lcidr -lanon


udp_filter_static_SOURCES = $(udp_filter_SOURCES)
udp_filter_static_LDADD   = $(udp_filter_LDADD) -lcrypto -lz -ldl -lssl
udp_filter_static_LDFLAGS = -static

#If you know a way how to automatically detect a library, then please contact me or submit a patch. 

man: udp-filter$(EXEEXT)
	-$(HELP2MAN) --section=1 --no-info --opt-include=docs/help2man.include --output=docs/udp-filter.1 ./udp-filter

install-man: man
	mkdir -p $(mandir)/man1
	install -c docs/udp-filter.1 $(mandir)/man1

install-data-am: install-man

uninstall: uninstall-am
	rm -rf $(docdir) $(mandir)/man1/udp-filter.1*
