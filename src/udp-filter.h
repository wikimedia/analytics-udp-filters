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


typedef enum ScreenType{
	NO_FILTER  =0,          // no filtering, write all hits to a file
	DOMAIN_FILTER =1,       // filter on domain
	PATH_FILTER =2,         // filter on path
	IP_FILTER  =3,          // filter on ip address or ip range
	GEO_FILTER =4,          // filter on geographic area
} ScreenType;

typedef enum IpMatchType {
	SIMPLE,   // exact ip address matching
	RANGE,    // match ip address by looking at range(s).
}IpMatchType;

typedef enum SearchType{
	STRING,   //exact (case-sensitive) substring matching, default value
	REGEX,    //regular expression matching.
}SearchType;

typedef enum RecodeType{
	NO,        // No recoding of a field, default value.
	GEO,       // this flag indicates whether the ip address should be geocoded.
	ANONYMIZE, // current ip adddress should be replaced with 0.0.0.0
}RecodeType;

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
	int searchtype;
	Ip ip;
} Filter;


//PROTOTYPES
int match_path(char *url, Filter *filters, int num_path_filters);

int match_domain(char *url, Filter *filters, int num_domain_filters);

regex_t * init_regex(char *token);

long convert_ip_to_long(char *ip_address, int initialization);
