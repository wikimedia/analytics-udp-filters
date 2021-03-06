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

#ifdef _GNU_SOURCE
#define FPUTS fputs_unlocked
#else
#define FPUTS fputs
#endif

// the version is set by the debianize script, don't worry about it
char *VERSION="0.3.23";

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <regex.h>
#include <stddef.h>
#include <signal.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include <libcidr.h>

#include <GeoIP.h>
#include <GeoIPCity.h>
#include "countries.h"
#include "udp-filter.h"
// #include "collector-output.h"
#include "geo.h"
#include "anonymize.h"
#include "match.h"
#include "utils.h"

#ifndef GeoIP_cleanup
#define GeoIP_cleanup
#endif

/*
 * Enter this in GDB for debugging
 * run -a -d GeoIP.dat -u wiki,waka -v < example.log
 */

// various useful constants
enum {
	MAX_FIELD_CNT = 32,
	LINE_BUF_SIZE = 65534
};

bool params[ MAX_FILTER ];

bool verbose_flag = false;       // whether we should output detailed debug messages


// Default paths to GeoIP databases.
const char *maxmind_dir     = "/usr/share/GeoIP";
const char *db_country_path = "/usr/share/GeoIP/GeoIP.dat";
const char *db_city_path    = "/usr/share/GeoIP/GeoIPCity.dat";
const char *db_region_path  = "/usr/share/GeoIP/GeoIPRegion.dat";


const int maximum_field_count = 32;  // maximum number of fields ever allowed in a log line.


/*
 * This is the expected input format, both in length and in sequence:
 *
 * 1. Hostname of the squid
 * 2. Sequence number
 * 3. The current time in ISO 8601 format (plus milliseconds), according to the squid server's clock.
 * 4. Request service time in ms
 * 5. Client IP
 * 6. Squid request status, HTTP status code
 * 7. Reply size including HTTP headers
 * 8. Request method (GET/POST etc)
 * 9. URL
 * 10. Squid hierarchy status, peer IP
 * 11. MIME content type
 * 12. Referer header
 * 13. X-Forwarded-For header
 * 14. User-Agent header
 * 15. Accept-Language header
 * 16. X-CS header

Sample line, with the client IP address replaced with 1.2.3.4 to protect the innocent:
sq18.wikimedia.org 1715898 1169499304.066 0 1.2.3.4 TCP_MEM_HIT/200 13208 GET http://en.wikipedia.org/wiki/Main_Page NONE/- text/html - - Mozilla/4.0%20(compatible;%20MSIE%206.0;%20Windows%20NT%205.1;%20.NET%20CLR%201.1.4322) en-US -|-|-

 */

void die(){
	exit(EXIT_FAILURE);
}


regex_t *init_regex(char *token) {
	/*
	 * This function tries to compile a string into a regex_t type
	 */
	regex_t *re = (regex_t *) malloc(sizeof(regex_t));
	if (re == NULL){
		fprintf(stderr, "REGEX: Could not allocate memory. This should never happen.\n");
		exit(EXIT_FAILURE);
	}
	int errcode = regcomp(re, token, REG_EXTENDED|REG_NOSUB);
	if (errcode!=0) {
		char error_message[MAX_ERROR_MSG];
		regerror (errcode, re, error_message, MAX_ERROR_MSG);
		fprintf(stderr, "When compiling %s to a regular expression, we encountered the following error:\n%s", token, error_message);
		exit(EXIT_FAILURE);
	}
	return re;
}

void init_countries(char *countries[], char *country_input, int num_countries, const char delimiter) {
	/*
	 * This function initializes an array of pointers that will contain the
	 * country codes that we need to filtered (i.e. included in the log file)
	 * We also validate whether the entered country code is a valid country
	 * code according to the ISO 3166-1 standard.
	 */
	if (num_countries == 0){
		return;
	}
	char *input = strdup(country_input);
	int i=0;

	char *startToken = input;
	for(i=0; i<num_countries; i++) {
		char *endToken;
		endToken = strchr(startToken, delimiter);
		if (endToken) {
			*endToken = '\0';
		}
		int result = verify_country_code(startToken);
		if (result){
			countries[i] = strdup(startToken);
			if (verbose_flag){
				fprintf(stderr,"%d:%s\n", i, startToken);
			}
		} else {
			fprintf(stderr, "%s is not a valid ISO 3166-1 country code.\n", startToken);
			exit(EXIT_FAILURE);
		}
		startToken = endToken + 1;
	}
	if (i>num_countries){
		fprintf(stderr, "Catching out of bounds error while initializing countries array.\n");
		exit(EXIT_FAILURE);
	}
	free(input);
}



void init_ip_addresses(Filter *filters, char *ipaddress_input, const char delimiter){
	int i=0;

	char *input = strdup(ipaddress_input);
	char *startToken = input;
	char *endToken;

	for (;;) {
		endToken = strchr(startToken, delimiter);
		if (endToken) {
			*endToken = '\0';
		}

		// convert this IP address or CIDR range into a libcidr CIDR object.
		filters[i].cidr_block = cidr_from_str(startToken);

		if (filters[i].cidr_block == NULL) {
            perror("Could not initialize cidr filter");
			exit(EXIT_FAILURE);
		}

		// if we didnt' find an endToken delimeter, then
		// this is the end of the -i filter input.
		// break out of loop now.
		if (!endToken) {
			break;
		}
		i++;
		startToken = endToken + 1;
	}
	free(input);
}


// TODO.  DRY the following 3 functions. 
// It's silly to have so much similar logic copy/pasted here.


void init_paths(Filter *filters, char *path_input, const char delimiter) {
	/* path_input is a string *excluding* the full qualified domain name
	 * path_input can be comma delimited, so we first need to determine the
	 * different parts and then depending on whether the regex_flag is activated
	 * we need to compile the string or else we just store it right away.
	 */
	int i=0;
	int error=0;

	char *input = strdup(path_input);
	char *startToken = input;
	for (;;){
		char *endToken;
		endToken = strchr(startToken, delimiter);
		if (endToken) {
			*endToken = '\0';
		}

		switch(search) {
			case STRING: {
				size_t s = strlen(startToken) + 1;
				filters[i].path.string= malloc(sizeof(char)*s);
				if (filters[i].path.string==NULL) {
					error=1;
					break;
				}
				strcpy(filters[i].path.string, startToken);
				filters[i].searchtype = PATH_FILTER;
				break;
			}

			case REGEX:{
				filters[i].path.regex =malloc(sizeof(regex_t));
				if (filters[i].path.regex==NULL) {
					error=1;
					break;
				}
				filters[i].path.regex = init_regex(startToken);
				filters[i].searchtype = PATH_FILTER;
				break;
			}
		}
		if (!endToken) {
			break;
		}
		i++;
		startToken = endToken + 1;
	}

	if (error==1){
		fprintf(stderr, "PATH: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}
	free(input);
}

void init_domains(Filter *filters, char *domain_input, const char delimiter){
	/*
	 * domain_input is a comma separated list of Wikipedia
	 * (parts of) domain names. Valid examples include:
	 * - en.wikipedia
	 * - en.m.wikipedia
	 * - wikipedia.org
	 * - commons,wikimediafoundation
	 */
	int i=0;
	int error=0;

	char *input = strdup(domain_input);
	char *startToken = input;
	for (;;){

		char *endToken;
		endToken = strchr(startToken, delimiter);
		if (endToken) {
			*endToken='\0';
		}

		switch(search){
			case STRING: {
				size_t s = strlen(startToken) + 1;
				filters[i].domain.string= malloc(sizeof(char)*s);
				if(filters[i].domain.string==NULL) {
					error=1;
					break;
				}
				strcpy(filters[i].domain.string,startToken);
				filters[i].searchtype = DOMAIN_FILTER;
				break;

			}
			case REGEX:{
				filters[i].domain.regex= malloc(sizeof(regex_t));
				if (filters[i].domain.regex==NULL){
					error=1;
					break;
				}
				filters[i].domain.regex = init_regex(startToken);
				filters[i].searchtype = DOMAIN_FILTER;
				break;
			}
		}
		if (!endToken){
			break;
		}
		i++;
		startToken = endToken + 1;

	}
	if (error==1){
		fprintf(stderr, "DOMAIN: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}
	free(input);
}


void init_http_status(Filter *filters, char *http_status_input, const char delimiter){
	/*
	 * http_status_input is a comma separated list of http response status codes
	 * - 200
	 * - 400
	 * - 404
	 * - 501
	 */
	int i=0;
	int error=0;

	char *input = strdup(http_status_input);
	char *startToken = input;
	for (;;){

		char *endToken;
		endToken = strchr(startToken, delimiter);
		if (endToken) {
			*endToken='\0';
		}

		switch(search){
			case STRING: {
				size_t s = strlen(startToken) + 1;
				filters[i].http_status.string= malloc(sizeof(char)*s);
				if(filters[i].http_status.string==NULL) {
					error=1;
					break;
				}
				strcpy(filters[i].http_status.string,startToken);
				filters[i].searchtype = HTTP_STATUS_FILTER;
				break;

			}
			case REGEX:{
				filters[i].http_status.regex= malloc(sizeof(regex_t));
				if (filters[i].http_status.regex==NULL){
					error=1;
					break;
				}
				filters[i].http_status.regex = init_regex(startToken);
				filters[i].searchtype = HTTP_STATUS_FILTER;
				break;
			}
		}
		if (!endToken){
			break;
		}
		i++;
		startToken = endToken + 1;

	}
	if (error==1){
		fprintf(stderr, "HTTP_STATUS: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}
	free(input);
}


int init_bird_level(char *bird){
	int result;
	if (bird){
		if(strcmp(bird,"country")==0) {
			result = COUNTRY;
		} else if (strcmp(bird,"region")==0) {
			result = REGION;
		} else if (strcmp(bird,"city")==0) {
			result = CITY;
		} else if (strcmp(bird, "latlon")==0){
			result = LAT_LON;
		} else if (strcmp(bird, "everything")==0){
			result = EVERYTHING;
		} else {
			fprintf(stderr, "%s is not a valid option for geocoding. <country>, <region>, <city> or <latlon> (without the <> are valid choices).\n", bird);
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "When you enter -g please also enter a valid -b switch.\n");
		exit(EXIT_FAILURE);
	}
	return result;
}

char *extract_domain(char *url) {
	if (url==NULL){
		return NULL;
	}
	char *domainEnd;
	char *domainStart = strstr(url, "//");
	if (domainStart !=NULL){
		domainEnd = strstr(domainStart + 2, "/");
	} else{
		return NULL;
	}
	if(domainEnd ==NULL){
		return NULL;
	}

	static char buffer[65536];
	int domainLength = (domainEnd - domainStart)-2;
	memcpy(buffer, domainStart+2, domainLength);
	buffer[domainLength] = '\0';
	return buffer;
}

char *extract_status(char *http_status_field) {
	if (http_status_field==NULL){
		return NULL;
	}
	// if there is a / in the field, then
	// return a pointer pointing to the string
	// starting immediately after the /.
	char *http_status = strstr(http_status_field, "/") + 1;
	if (http_status != NULL){
		// return the string starting after the /
		return http_status;
	}
	else
	{
		// else assume the status field in the line
		// is just a http response status
		return http_status_field;
	}
}



/*
 * Uses getaddrinfo() to determine if ip_address
 * is IPv4 or IPv6.
 * Returns -1 if getaddrinfo() fails.
 * Else returns ai_family, or AF_UNSPEC if
 * ai_family is not AF_INET or AF_INET6
 *
 * raw_address should point to a non null buffer
 * big enough to hold a raw IPv6 address.
 * The raw address will be copied into raw_address
 * from the result struct returned by getaddrinfo.
 * raw_address will then be a pointer to either
 * a struct in_addr or a struct in6_addr.
 */
int determine_ai_family(char *ip, void *raw_address) {
	int ai_family;

	struct addrinfo hint, *res = NULL;
	memset(&hint, '\0', sizeof hint);

	// Flags to tell getaddrinfo() that
	// we don't yet know the IP version,
	// and that we don't want to do any
	// DNS lookups.
	hint.ai_family          = PF_UNSPEC;
	hint.ai_flags           = AI_NUMERICHOST;

	// Call getaddrinfo to determine IPv4 vs IPv6.
	// If getaddrinfo returns non-zero, then this
	// is an error.  Return -1 and set raw_address to NULL;
	if (getaddrinfo(ip, NULL, &hint, &res)) {
		raw_address = NULL;
		return -1;
	}

	if (res->ai_family == AF_INET) {
		ai_family   = res->ai_family;
		// copy the IPv4 address into raw_address
		memcpy(raw_address, &((struct sockaddr_in *)res->ai_addr)->sin_addr, sizeof(struct in_addr));
	}
	else if (res->ai_family == AF_INET6) {
		ai_family = res->ai_family;
		// copy the IPv6 address into raw_address;
		memcpy(raw_address, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
	}
	// else we can't figure out the address type.
	// return AF_UNSPEC and set raw_address to NULL;
	else {
		ai_family   = AF_UNSPEC;
		raw_address = NULL;
	}

	freeaddrinfo(res);
	return ai_family;
}




void replace_ip_addr(char *fields[], char* area, int should_anonymize_ip) {
	/*
	 * The purpose of this function is to replace the original ip address from
	 * line (where line is the original input as read from STDIN with
	 * either an anonymous ip address (0.0.0.0) or the country code as
	 * generated by geocode_lookup.
	 * This assumes that the client IP address is currently at fields[4].
	 * area is a geocoded string to be appended to the IP address.  If it
	 * is null, nothing will be appended.
	 * If should_anonymize_ip is true, the IP address will be replaced with anonoymous_ip.
	 *
	 * fields is by reference, so fields[4] will be replaced with the resulting string.
	 */

	if (should_anonymize_ip) {
		fields[4] = anonymize_ip_address(fields[4]);
	}

	if (area != NULL)
	{
		// temporary variable in which to store new field with geocode string.
		static char new_field[MAX_BUF_LENGTH];
		snprintf(new_field, MAX_BUF_LENGTH, "%s|%s", fields[4], area);
		// set fields[4] to the new string.
		fields[4] = new_field;
	}
}

void free_memory(Filter *filters, char *path_input, char *domain_input, int num_filters, GeoIP* gi, char *countries[], int num_countries_filters) {
	int i;
	if(gi){
		GeoIP_delete(gi);
	}

	if (countries){
		for(i=0;i<num_countries_filters;i++){
			free(countries[i]);
		}
	}

	for(i=0;i<num_filters; i++){
		if (filters[i].searchtype == DOMAIN_FILTER){
			switch (search){
				case STRING:
					if (domain_input){
						free(filters[i].domain.string);
					}
					break;

				case REGEX:
					if (domain_input){
						regfree(filters[i].domain.regex);
					}
					break;

				default:
					break;
				}
		} else if (filters[i].searchtype == PATH_FILTER){
			switch (search){
				case STRING:
					if(path_input){
						free(filters[i].path.string);
					}
					break;

				case REGEX:
					if(path_input){
						regfree(filters[i].path.regex);
					}
					break;

				default:
					break;
			}
		}
	}
}

void parse(char *country_input,
	   char *path_input,
	   char *domain_input,
	   char *ipaddress_input,
	   char *http_status_input,
	   char *referer_input,
	   char *bird,
	   char *db_path,
	   int minimum_field_count) {

	// GENERIC VARIABLES
	char *fields[MAX_FIELD_CNT];       // number of fields we expect in a single line
	int num_filters             = 0;   // total number of filters we detect from the command line
	int num_domain_filters      = 0;   // total number of domain filters
	int num_path_filters        = 0;   // total number of path filters
	int num_ipaddress_filters   = 0;   // total number of ipaddress filter
	int num_countries_filters   = 0;   // total number countries we want to restrict the filtering
	int num_http_status_filters = 0;   // total number of http status we want to restrict the filtering.
	int num_referer_filters     = 0;
	int required_hits           = 0;
	int bird_int                = 0;
	int i;

	int field_count_this_line=0;  // number of fields found in the current line

	char line[ LINE_BUF_SIZE ];
	char *ipaddr;
	char *url;
	char *http_status;
	char *referer;


	// DETERMINE NUMBER OF FILTERS
	if(params[DOMAIN_FILTER]){
		num_domain_filters = determine_num_obs(domain_input,comma_delimiter);
		required_hits+=1;
	}
	if(params[PATH_FILTER]){
		num_path_filters = determine_num_obs(path_input,comma_delimiter);
		required_hits+=1;
	}
	if(params[IP_FILTER]){
		num_ipaddress_filters = determine_num_obs(ipaddress_input, comma_delimiter);
		required_hits+=1;
	}
	if(params[GEO_FILTER]){
		if(country_input != NULL && strlen(country_input) >1){
			num_countries_filters = determine_num_obs(country_input, comma_delimiter);
			required_hits+=1;
		}
	}
	if(params[REFERER_FILTER]){
		num_referer_filters = determine_num_obs(referer_input, comma_delimiter);
		required_hits+=1;
	}
	if(params[HTTP_STATUS_FILTER]){
		if(http_status_input != NULL && strlen(http_status_input) >1){
			num_http_status_filters = determine_num_obs(http_status_input, comma_delimiter);
			required_hits+=1;
		}
	}

	num_filters = num_path_filters + num_domain_filters + num_ipaddress_filters
		+ num_countries_filters + num_http_status_filters + num_referer_filters;
	Filter filters[num_filters];

	// GEO_FILTER INITIALIZATION
	GeoIP *gi = NULL;    // initialize to suppress compiler warning
	char *countries[num_countries_filters];
	char *area;

	// FILTER INITIALIZATION
	if(params[DOMAIN_FILTER]){
		init_domains(filters, domain_input, comma_delimiter);
	} else {
		domain_input=NULL;
	}

	if(params[PATH_FILTER]){
		init_paths(filters, path_input, comma_delimiter);
	} else {
		path_input = NULL;
	}

	if(params[IP_FILTER]){
		init_ip_addresses(filters, ipaddress_input, comma_delimiter);
	} else {
		ipaddress_input = NULL;
	}

	if (params[REFERER_FILTER]){
		init_domains(filters, referer_input, comma_delimiter);
	} else {
		referer_input = NULL;
	}

	if( ! (params[GEO_FILTER] || (recode & GEO)) ) {
		country_input = NULL;
	} else {
		init_countries(countries, country_input, num_countries_filters, comma_delimiter);
		bird_int = init_bird_level(bird);
		/*
		 *  Before changing the type of cache, have a look at this benchmark:
		 *  http://www.maxmind.com/app/benchmark
		 *  and choose wisely.
		 */
		switch(bird_int){
		case COUNTRY:
			if(db_path!=NULL){
				db_country_path=db_path;
			}
			gi = GeoIP_open(db_country_path, GEOIP_MEMORY_CACHE);
			break;

		case REGION:
			if(db_path!=NULL){
				db_region_path=db_path;
			}
			gi = GeoIP_open(db_region_path, GEOIP_MEMORY_CACHE);
			break;

		case CITY:
			if(db_path!=NULL){
				db_city_path=db_path;
			}
			gi = GeoIP_open(db_city_path, GEOIP_MEMORY_CACHE);
			break;

		case LAT_LON:
			if(db_path!=NULL){
				db_city_path=db_path;
			}
			gi = GeoIP_open(db_city_path, GEOIP_MEMORY_CACHE);
			break;

		case EVERYTHING:
			if(db_path!=NULL){
				db_city_path=db_path;
			}
			gi = GeoIP_open(db_city_path, GEOIP_MEMORY_CACHE);
			break;
		}

		if (gi == NULL) {
			fprintf(stderr, "Error opening MaxMind Geo database.\n");
			fprintf(stderr, "Path used for country database:%s\n", db_country_path);
			fprintf(stderr, "Path used for region database:%s\n", db_region_path);
			fprintf(stderr, "Path used for city database:%s\n", db_city_path);
			exit(EXIT_FAILURE);
		} else {
			if(verbose_flag){
				char *db_info =GeoIP_database_info(gi);
				unsigned char db_edition = GeoIP_database_edition(gi);
				GeoIPDBTypes geodbtype = (GeoIPDBTypes)db_info;
				fprintf(stderr,"Maxmind database: %i; version: %i\n", db_edition, geodbtype);
			}
		}
	}

	if(params[HTTP_STATUS_FILTER]){
		init_http_status(filters, http_status_input, comma_delimiter);
	} else {
		http_status_input = NULL;
	}


	if (verbose_flag){
		fprintf(stderr, "num_path_filters:%d\tnum_domain_filters:%d"
			"\tnum_http_status_filters:%d\tip_address_count:%d"
			"\tcountries_count:%d\treferer_count:%d\n",
			num_path_filters, num_domain_filters, num_http_status_filters,
			num_ipaddress_filters, num_countries_filters, num_referer_filters);
	}


	// Now that we have initilaized all the filters,
	// do the actual filtering and conversion of the
	// incoming data.
	while ( true ) {
		int found =0;
		area = NULL;

		char *r;
		r=fgets(line, LINE_BUF_SIZE, stdin);
		if(!r) {
			break;
		}

		i = 0;
		char *p;
		do {
			fields[i] = r;
			//strsep(&r, ws_delimiter);
			p = strchr( r, *ws_delimiter );
			i++;
                        if ( NULL == p )
                                break;
                        *p = 0;
                        r = p + 1;
		} while (i < MAX_FIELD_CNT);

		if (i < minimum_field_count || i == MAX_FIELD_CNT){
			continue;    // ignore line since field count is outside expected range
		}


		// we found i fields in this line.
		field_count_this_line = i;

		ipaddr        = fields[4];
		http_status   = fields[5];
		url           = fields[8];
		referer       = fields[11];
		//ua            = fields[13]; // necessary for bot detection


		if (url != NULL) {

			if (params[DOMAIN_FILTER]){
				found += match_domain(url, filters, num_domain_filters,verbose_flag);
			}

			if (params[PATH_FILTER]){
				found += match_path(url, filters, num_path_filters,verbose_flag);
			}

			if (params[HTTP_STATUS_FILTER]){
				found += match_http_status(http_status, filters, num_http_status_filters,verbose_flag);
			}

			if (params[IP_FILTER]){
				found += match_ip_address(ipaddr, filters, num_ipaddress_filters,verbose_flag);
			}

			if (params[REFERER_FILTER]){
				found += match_domain(referer, filters, num_referer_filters,verbose_flag);
			}

			if (params[GEO_FILTER]){
				area = geo_lookup(gi, ipaddr, bird_int);
				found += geo_check(area, countries, num_countries_filters,verbose_flag);
				if (verbose_flag){
					fprintf(stderr, "IP address: %s was geocoded as: %s\n", ipaddr, area);
				}
			}
		}

		// required_hits will equal the number of filters
		// given.  These include ip, domain, path, status,
		// and country filtering.  If no filters were given,
		// then found will be 0 AND require_hits will be 0,
		// allowing the line to pass through.
		if (found >= required_hits) {
			// if we need to replace the IP addr
			// because recode is GEO or ANONYMIZE or both
			if (recode)
			{
				// geocode if we haven't already geocoded and
				// we'll be needing the geocoded string when
				// replacing the IP.
				if (area == NULL && (recode & GEO)) {
					area = geo_lookup(gi, ipaddr, bird_int);
				}

				// replace the ip address in fields.
				// if area is not null, it will be appended
				// to the ip address.  If (recode & ANONYMIZE) is
				// true, then the IP will be replaced.
				replace_ip_addr(fields, area, (recode & ANONYMIZE));
			}

			// print output to stdout
			for (i=0;i<field_count_this_line;++i){
				if (i!=0){
					FPUTS(ws_delimiter, stdout);
				}
				FPUTS(fields[i], stdout);
			}

		}

		if (verbose_flag) {
			fprintf(stderr, "ipaddr: '%s', url: '%s, status: %s'\n", ipaddr, url, http_status);
		}

	}
	free_memory(filters, path_input, domain_input,num_filters, gi, countries, num_countries_filters);
}


void version() {
	char *version = VERSION;
	printf("udp-filter %s\n", version);
	printf("\n");
	printf("Wikimedia's generic webserver access log filtering system.\n");
	printf("This new filter system replaces the old collection of udp2log filters written in C.\n");
	printf("It is customizable and can be configured using the command line.\n");
	printf("\n");
	printf("Copyright (C) 2012 Wikimedia Foundation, Inc.\n");
	printf("This is free software; see the source copying conditions. There is NO\n");
	printf("warrant; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
	printf("\n");
	printf("Written by Diederik van Liere (dvanliere@wikimedia.org).\n");
	printf("           Andrew Otto (aotto@wikimedia.org).\n");
}

void usage() {
	version();

	printf("Usage: udp-filter [OPTION] ...\n");
	printf("  udp-filter reads from stdin and writes to stdout by default.");
	printf("\n");
	printf("Options:\n");
	printf("  -p paths, --path=paths                    Path portions of the request URI to match.  Comma separated.\n");
	printf("\n");
	printf("  -d domains, --domain=domain               Parts of domain names to match.  Comma separated.\n");
	printf("\n");
	printf("  -r referers, --referers=domain            Parts of the referer domain to match. Comma separated.\n");
	printf("\n");
	printf("  -i addresses, --ip=addresses              IP address(es) to match.  Comma seperated.  Accepts IPv4\n");
	printf("                                            and IPv6 addresses and CIDR ranges.\n");
	printf("\n");
	printf("  -c countries, --country-list=countries    Filter for countries.  This should be a comma separated\n");
	printf("                                            list of country codes. Valid country codes are the\n");
	printf("                                            ISO 3166 country codes (see http://www.maxmind.com/app/iso3166).\n");
	printf("\n");
	printf("  -s status, --http-status=status           Filter for HTTP response status code(s).\n");
	printf("\n");
	printf("  -r pattern, --regex=pattern               The parameters -p, -u and -s are interpreted as regular\n");
	printf("                                            expressions. Regular expression searching is probably \n");
	printf("                                            slower so substring matching is recommended.\n");
	printf("\n");
	printf("  -g, --geocode                             Turns on geocoding of IP addresses.\n");
	printf("                                            Must also specify --bird.\n");
	printf("\n");
	printf("  -b bird, --bird=bird                      Mandatory when specifying --geocode.  Valid choices are\n");
	printf("                                            <country>, <region>, <city>, <latlon> and <everything>.\n");
	printf("\n");
	printf("  -a, --anonymize[=salt-key]                Turns on IP addresses anonymization.  If salt-key is given, then\n");
	printf("                                            libanon will be used to do prefix preserviing anonymization.\n");
	printf("                                            salt-key may be 'random' a string at least 32 characters long.\n");
	printf("                                            If 'random' is given, then a random salt-key will be chosen.\n");
	printf("\n");
	printf("  -n count, --min-field-count=count         Minimum number of fields that a log line contains.\n");
	printf("                                            Default is 14.  If a line has fewer than this number of\n");
	printf("                                            fields,the line will be discarded.\n");
	printf("\n");
	printf("  -m path, --maxmind=path                   Alternative path to MaxMind database.  Default %s.\n", maxmind_dir);
	printf("\n");
	printf("  -F delimiter, --field-delimiter=delimter  Sets the delimiter used to separate fields.  '\\t' will be translated to a\n");
	printf("                                            tab character.   Default: ' ' (space).\n");
	printf("\n");
	printf("  -v, --verbose                             Output detailed debug information to stderr, not recommended\n");
	printf("                                            in production.\n");
	printf("  -h, --help                                Show this help message.\n");
	printf("  -V, --version                             Show version info.\n\n");
}

int main(int argc, char **argv){
	char *country_input      = NULL;
	char *path_input         = NULL;
	char *domain_input       = NULL;
	char *ipaddress_input    = NULL;
	char *referer_input      = NULL;
	char *http_status_input  = NULL;
	char *db_path            = NULL;
	char *bird               = NULL;
	bool bird_param_supplied  = false;

	// Expected minimum number of fields in a line.
	// There can be no fewer than this, but no more than
	// MAX_FIELD_CNT space separated fields in a long line.
	// Anything outside of this range will be discarded.
	//
	int minimum_field_count = 14;

	static struct option long_options[] = {
			{"anonymize"        , optional_argument , NULL , 'a'} ,
			{"bird"             , required_argument , NULL , 'b'} ,
			{"country_list"     , required_argument , NULL , 'c'} ,
			{"domain"           , required_argument , NULL , 'd'} ,
			{"geocode"          , no_argument       , NULL , 'g'} ,
			{"help"             , no_argument       , NULL , 'h'} ,
			{"ip"               , required_argument , NULL , 'i'} ,
			{"http-status"      , required_argument , NULL , 's'} ,
			{"maxmind"          , required_argument , NULL , 'm'} ,
			{"min-field-count"  , required_argument , NULL , 'n'} ,
			{"path"             , required_argument , NULL , 'p'} ,
			{"regex"            , no_argument       , NULL , 'r'} ,
			{"referer"          , required_argument , NULL , 'f'} ,
			{"field-delimiter"  , required_argument , NULL , 'F'} ,
			{"verbose"          , no_argument       , NULL , 'v'} ,
			{"version"          , no_argument       , NULL , 'V'} ,
			{0                  , 0                 , 0    , 0 }
	};

	signal(SIGINT,die);

	int c;

	while((c = getopt_long(argc, argv, "a::b:c:d:f:m:n:s:ghi:rF:p:vV", long_options, NULL)) != -1) {
		// b,c,d,f,i,m,n,s,p have mandatory arguments
		switch(c)
		{
		case 'a':
			/* Indicate whether we should anonymize the log, default is false */
			recode |= ANONYMIZE;

			// if optarg is NULL, then we will not be using
			// libanon.  No need to initialize the anon ip objects
			if (optarg != NULL) {
				// if 'random', then use a random
				// anon salt key by passing NULL to init_anon_ip().
				if (strcmp(optarg, "random") == 0) {
					init_anon_ip(NULL);
				}
				// Ok, we've been given a salt key.
				// make sure it is long enough.
				else if (strlen(optarg) < 32) {
					fprintf(stderr, "salt-key argument to --anonymize '%s' must be at least 32 characters long.\n", optarg);
					exit(EXIT_FAILURE);
				}
				// great, initialized the anon ip objects.
				else {
					init_anon_ip((uint8_t *)optarg);
				}
			}
			break;

		case 'b':
			bird_param_supplied = true;
			bird = optarg;
			break;

		case 'c':
			/* Optional list of countries to restrict logging */
			country_input = optarg;
			params[GEO_FILTER] = true;
			break;

		case 'd':
			/* -d is set. This specifies the project: en.wikipedia, commons.
			 * it should be a part of the domain name
			 */
			params[DOMAIN_FILTER] = true;
			domain_input = optarg;
			search=STRING;
			break;

		case 'f':
			/* -f is set. This specificies to filter on the referrer string.
			*/
			params[REFERER_FILTER] = true;
			referer_input = optarg;
			search=STRING;
			break;

		case 'F':
			/* -F is set. This changes the field delimiter.
			*/
			// special case for '\t'.  If '\t' was passed,
			// then use "\t" as a string to get a real tab character.
			if (strcmp(optarg, "\\t") == 0) {
				optarg = "\t";
			}
			ws_delimiter = optarg;
			break;

		case 'g':
			/* Indicate whether we should do geocode, default is false */
			recode |= GEO;
			//params[GEO_FILTER] = true;
			break;

		case 'h':
			/* Show help to user */
			version();
			usage();
			exit(EXIT_SUCCESS);
			break;

		case 'i':
			/* Enable filtering by ip-address or ip-range */
			params[IP_FILTER] = true;
			ipaddress_input = optarg;
			break;

		case 'm':
			/* Optional alternative path to database. */
			db_path = optarg;
			break;

		case 'n':
			minimum_field_count = atoi(optarg);
			break;

		case 's':
			/* Enable filtering by HTTP response status code */
			params[HTTP_STATUS_FILTER] = true;
			http_status_input = optarg;
			break;
		case 'r':
			/* indicate whether we should treat the search string as a regular
			 * expression or not, default is false
			 */
			search=REGEX;
			break;

		case 'p':
			/* -p is set. Store the url that needs to be matched. */
			params[PATH_FILTER] = true;
			path_input = optarg;
			search=STRING;
			break;

		case 'v':
			/* Turn verbose on */
			verbose_flag = true;
			break;

		case 'V':
			/* Show version information to user */
			version();
			exit(EXIT_SUCCESS);
			break;

		default:
			exit(EXIT_FAILURE);
		}
	}

	// minimum_field_count cannot be greater than MAX_FIELD_CNT
	if (minimum_field_count > MAX_FIELD_CNT)
	{
		fprintf(stderr,"min-field-count (%i) cannot be greater than %i.\n", minimum_field_count, MAX_FIELD_CNT);
		version();
		usage();
		exit(EXIT_FAILURE);
	}

	if ( !bird_param_supplied && params[GEO_FILTER]){
		fprintf(stderr,"You supplied the -g parameter without specifying the -b parameter.\n");
		exit(EXIT_FAILURE);
	}

	if (argc==1) {
		/* There were no options given at all */
		usage();
		exit(EXIT_FAILURE);
	} else {
		parse(country_input,
		      path_input,
		      domain_input,
		      ipaddress_input,
		      http_status_input,
		      referer_input,
		      bird,
		      db_path,
		      minimum_field_count);
		return EXIT_SUCCESS;
	}
	return 0;
}
