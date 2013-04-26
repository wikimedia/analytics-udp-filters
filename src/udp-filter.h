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

#ifndef __UDP_FILTER_H
#define __UDP_FILTER_H

#include <regex.h>
#include <stdint.h>
#include <libcidr.h>

#include <libanon.h>


typedef enum ScreenType{       // by default, enums start at 0, increment by 1
	NO_FILTER,             // no filtering, write all hits to a file
	DOMAIN_FILTER,         // filter on domain
	PATH_FILTER,           // filter on path
	IP_FILTER,             // filter on ip address or ip range
	GEO_FILTER,            // filter on geographic area
	HTTP_STATUS_FILTER,    // filter on http response status codes
	REFERER_FILTER,        // filter on referer url
	MAX_FILTER             // number of filters (not a valid value)
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

	union referer{
		char *string;
		regex_t *regex;
	} referer;
	
	int searchtype;

	CIDR *cidr_block;
} Filter;






regex_t * init_regex(char *token);

char *anonymize_ip_address(char *ip);
int   determine_ai_family(char *ip, void *raw_address);
void  init_anon_ip(uint8_t *anon_key_salt);

/*
 * Example of maximum length IP addr + geocoded everything string:
 *   ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190|US:San Sebasti?n De Los Ballesteros:0.000000:0.000000
 * This is 100 chars.  Set MAX_BUF_LENGTH to 128 to be safe.
 */
#define MAX_BUF_LENGTH 128

char *extract_domain(char *url);
char *extract_status(char *http_status_field);


#endif
