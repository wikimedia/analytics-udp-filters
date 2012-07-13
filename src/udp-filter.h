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

#include <regex.h>
#include <libcidr.h>

typedef enum ScreenType{
	NO_FILTER          = 0,    // no filtering, write all hits to a file
	DOMAIN_FILTER      = 1,    // filter on domain
	PATH_FILTER        = 2,    // filter on path
	IP_FILTER          = 3,    // filter on ip address or ip range
	GEO_FILTER         = 4,    // filter on geographic area
	HTTP_STATUS_FILTER = 5,    // filter on http response status codes
} ScreenType;

typedef enum IpMatchType {
	SIMPLE,   // exact ip address matching
	RANGE,    // match ip address by looking at range(s).
}IpMatchType;

typedef enum SearchType{
	STRING,   //exact (case-sensitive) substring matching, default value
	REGEX,    //regular expression matching.
}SearchType;



/*
 * These are bit operable values.
 * Examples:
 *   recode = (GEO | ANONYMIZE);
 *     (recode & GEO) == true # need to geocode.
 *     (recode & ANONYMIZE) == true # need to anonymize.
 *  recode = GEO;
 *     (recode & GEO) == true # need to geocode.
 *     (recode & ANONYMIZE) == false # do not need to anonymize.
 * etc.
 */
typedef enum RecodeType{
	NO        = 0,        // No recoding of a field, default value.
	GEO       = 1,        // this flag indicates whether the IP address should be geocoded.
	ANONYMIZE = 2,        // current IP adddress should be replaced with 0.0.0.0
}RecodeType;

typedef enum BirdType{
	COUNTRY,   // Quite obvious, geocoding at the country level.
	REGION,    // This is country-specific, usually it's a province or state.
	CITY,      // Geocoding at the city, this should be used with the necessary precautions.
	LAT_LON,   // Geocode to longitude latitude
	EVERYTHING, // All of the above
}BirdType;

typedef struct {
	char *address;
	long address_long;
	long lbound;
	long ubound;
} Ip;

typedef struct{
	union domain{
		char *string;
		regex_t *regex;
	} domain;

	union path{
		char *string;
		regex_t *regex;
	} path;
	
	union http_status{
		char *string;
		regex_t *regex;
	} http_status;
	
	int searchtype;

	CIDR *cidr_block;
} Filter;


//PROTOTYPES
int match_path(char *url, Filter *filters, int num_path_filters);

int match_domain(char *url, Filter *filters, int num_domain_filters);

regex_t * init_regex(char *token);

long convert_ip_to_long(char *ip_address, int initialization);
