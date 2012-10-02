/*
    Copyright (C) 2012  <Diederik van Liere / Wikimedia Foundation>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "geo.h"
#include "udp-filter.h"
char unknown_geography[] = "XX";


int geo_check(const char *country_code, char *countries[], int countries_count, int _verbose_flag) {
	if (!country_code){
		return 0;
	}
	int i;
	for (i = 0; i < countries_count; ++i) {
		if (_verbose_flag){
			fprintf(stderr, "Comparing: %s <--> %s\n", country_code, countries[i]);
		}
		if (strcmp(country_code, countries[i]) == 0) {
			return 1;
		}
	}
	return 0;
}



char *geo_lookup(GeoIP *gi, char *ipaddr, int bird) {
	/*
	 * Lookup the country_code by ip address, we can
	 * extend this in the future with more granular data
	 * such as region,city or even zipcode.
	 */
	static char area[MAX_BUF_LENGTH];

	// set the charset to UTF8
	GeoIP_set_charset(gi, GEOIP_CHARSET_UTF8);

	switch(bird){
		case COUNTRY: {
			const char *country= GeoIP_country_code_by_addr(gi, ipaddr);
			if (country==NULL){
				strncpy(area, unknown_geography, MAX_BUF_LENGTH);
			} else {
				strncpy(area, country, MAX_BUF_LENGTH);
			}

		}
		break;

		case REGION:{
			GeoIPRegion *gir;
			gir=GeoIP_region_by_addr(gi,ipaddr);
			if(gir == NULL || strlen(gir->region)==0){
				strncpy(area, unknown_geography, MAX_BUF_LENGTH);
			} else {
				strncpy(area, gir->region, MAX_BUF_LENGTH);
			}

			if(gir != NULL) {
				GeoIPRegion_delete(gir);
			}
			break;
		}

		case CITY:{
			GeoIPRecord *grecord;
			char *city;
			int mustFreeCity = 0;
			grecord = GeoIP_record_by_addr(gi, ipaddr);
			if (grecord !=NULL){
				if (grecord->city == NULL){
					strncpy(area, unknown_geography, MAX_BUF_LENGTH);
				} else {
					int len = strlen(grecord->city);
					city = strdup(grecord->city);
					mustFreeCity = 1;
					strncpy(area,city, MAX_BUF_LENGTH);
					replace_space_with_underscore(area, len);
				}
				if (mustFreeCity) {
					free(city);
				}
				GeoIPRecord_delete(grecord);
			} else {
				strncpy(area, unknown_geography, MAX_BUF_LENGTH);
			}
			break;
		}

		case LAT_LON: {
			GeoIPRecord *grecord;
			grecord = GeoIP_record_by_addr(gi, ipaddr);
			if (grecord!=NULL){
				snprintf(area, MAX_BUF_LENGTH, "%f,%f", grecord->latitude, grecord->longitude);
				GeoIPRecord_delete(grecord);
			} else {
				strncpy(area, unknown_geography, MAX_BUF_LENGTH);
			}
			break;
		}

		case EVERYTHING: {
			GeoIPRecord *grecord;
			char *country = unknown_geography, *region = unknown_geography, *city = unknown_geography;
			int mustFreeCity = 0;
			float lat = 0.0, lon = 0.0;
			grecord = GeoIP_record_by_addr(gi, ipaddr);
			if (grecord != NULL) {
				if (grecord->city != NULL) {
					city = strdup(grecord->city);
					mustFreeCity = 1;
				}
				replace_space_with_underscore(city, strlen(city));

				if (grecord->region != NULL) {
					region = grecord->region;
				}
				if (grecord->country_code != NULL) {
					country = grecord->country_code;
				}
				lat = grecord->latitude;
				lon = grecord->longitude;
			}
			snprintf(area, MAX_BUF_LENGTH, "%s|%s|%s|%f,%f", country, region, city, lat, lon);

			if (grecord != NULL) {
				GeoIPRecord_delete(grecord);
			}

			if (mustFreeCity) {
				free(city);
			}
			break;
		}

		default:
			break;
	}
	return area;
}
