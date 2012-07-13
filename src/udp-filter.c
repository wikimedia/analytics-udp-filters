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

#define MAX_ERROR_MSG 0x1000
#define VERSION_NUMBER 0.2.4
#define VERSION_STRING_HELPER(X) #X
#define VERSION_STRING(X) VERSION_STRING_HELPER(X)


#include <stdio.h>
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

#ifndef GeoIP_cleanup
#define GeoIP_cleanup
#endif

/*
 * Enter this in GDB for debugging
 * run -a -d GeoIP.dat -u wiki,waka -v < example.log
 */

char anonymous_ip[] = "0.0.0.0";
char unknown_geography[] = "XX";
const char comma_delimiter =',';
const char ws_delimiter[] = " ";
const char fs_delimiter = '/';
const char us_delimiter = '-';
const int num_predefined_filters = (HTTP_STATUS_FILTER - NO_FILTER) +1;
int verbose_flag = 0;       // this flag indicates whether we should output detailed debug messages, default is off.

// Default paths to GeoIP databases.
char *db_country_path = "/usr/share/GeoIP/GeoIP.dat";
char *db_city_path    = "/usr/share/GeoIP/GeoIPCity.dat";
char *db_region_path  = "/usr/share/GeoIP/GeoIPRegion.dat";

SearchType search = STRING;
RecodeType recode = NO;
IpMatchType ipmatch = SIMPLE;

int params[6];   // Increase this when you add a new filter to ScreenType enum.

const int maximum_field_count = 32;  // maximum number of fields ever allowed in a log line.

/*
 * Example of maximum length IP addr + geocoded everything string:
 *   ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190|US:San Sebasti?n De Los Ballesteros:0.000000:0.000000
 * This is 100 chars.  Set MAX_BUF_LENGTH to 128 to be safe.
 */
#define MAX_BUF_LENGTH 128

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
 * 16. x-wap-profile|Profile|wap-profile header(s)

Sample line, with the client IP address replaced with 1.2.3.4 to protect the innocent:
sq18.wikimedia.org 1715898 1169499304.066 0 1.2.3.4 TCP_MEM_HIT/200 13208 GET http://en.wikipedia.org/wiki/Main_Page NONE/- text/html - - Mozilla/4.0%20(compatible;%20MSIE%206.0;%20Windows%20NT%205.1;%20.NET%20CLR%201.1.4322) en-US -|-|-

 */

void die(){
	exit(EXIT_FAILURE);
}

int determine_num_obs(char *raw_input, const char delimiter) {
	/*
	 * Determine the number of comma-separated filter parameters are entered
	 * on the command line. This function is applied to both the path_input and
	 * domain_input parameters.
	 */
	int size=0;
	int j=0;
	if (raw_input!=NULL){
		while(raw_input[j] !='\0') {
			if (raw_input[j] == delimiter) {
				size++;
			}
			j++;
		}
		size++;// the number of obs. is the number of comma_delimiters plus 1
	}
	return size;
}

void replace_space_with_underscore(char *string, int len){
	int i;
	for (i=0;i<len; i++){
		if(string[i]== ' ') {
			string[i] = '_';
		}
	}
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


/**
 * Returns true if ip_address belongs to an IP address range in filters.
 * 
 * char   *ip_address  - IP address string, either IPv4 or IPv6.
 * Filter *filters     - Array of filters on which to match.
 * int     num_filters - number of filters in filters array.
 * returns int 1 if ip_address is at least one of the provided IP filters, 0 if not.
 */
int match_ip_address(char *ip_address, Filter *filters, int num_filters){
	int i;

	// convert the ip_address to a libcidr CIDR object
	CIDR *cidr_ip = cidr_from_str(ip_address);

	// start with matched == false.
	int matched = 0;

	// Loop through each filter.  
	// If the filter has a cidr_block,
	// then check to see if ip_address
	// is in that block.
	for (i=0; i < num_filters; i++) {
		if (filters[i].cidr_block == NULL) {
			continue;
		}

		// result will be 0 if the cidr_ip is in the cidr_block, -1 if not.
		int result = cidr_contains(filters[i].cidr_block, cidr_ip);

		if (verbose_flag == 1) {
			fprintf(stderr, "Filtering IP address %s in block %s: %s\n", cidr_to_str(cidr_ip, CIDR_NOFLAGS), cidr_to_str(filters[i].cidr_block, CIDR_NOFLAGS), result == 0 ? "yes" : "no");
		}

		// If result was 0, then this filter's cidr_block
		// contains the ip_address.  Set matched to true
		// and break out of the filter search loop.
		if (result == 0) {
			matched = 1;
			break;
		}
	}

	// free up the libcidr ip address from the 
	// input line and return matched.
	cidr_free(cidr_ip);
	return matched;
}

int match_path(char *url, Filter *filters, int num_path_filters){
	if (num_path_filters > 0) {
		/*
		 * this for loop checks if the url contains the path from the command
		 * line.If it finds a match then return 1 else return 0.
		 */
		int i;
		int path_found = 0;
		regmatch_t pmatch[1];
		char* path = strtok(url, ws_delimiter);

		if (path!=NULL){
			for (i = 0; i < num_path_filters; i++) {
				switch (search){
				case STRING:
					if (strstr(path, filters[i].path.string)!=NULL){
						path_found =1;
					}
					if (verbose_flag){
						fprintf(stderr, "%s<-->%s\t%d\n", path, filters[i].path.string, path_found);
					}
					break;

				case REGEX:
				{
					int result = regexec(filters[i].path.regex, path, 0, pmatch, 0);
					if (result ==0) {
						path_found = 1;
					}
					if (verbose_flag){
						if (result>0) {
							char errbuf[MAX_ERROR_MSG];
							regerror(result, filters[i].path.regex, errbuf, MAX_ERROR_MSG);
							fprintf(stderr, "Encountered error while regex matching: %s\n", errbuf);
						} else {
							fprintf(stderr, "%s<-->%p\t%d\n", path, &filters[i].path.regex, path_found);
						}
					}
					if (verbose_flag){
						if (result>0) {
							char errbuf[MAX_ERROR_MSG];
							regerror(result, filters[i].path.regex, errbuf, MAX_ERROR_MSG);
							fprintf(stderr, "Encountered error while regex matching: %s\n", errbuf);
						} else {
							fprintf(stderr, "%s<-->%p\t%d\n", path, &filters[i].path.regex, path_found);
						}
					}
				}
				break;

				default:
					break;
				}
			}
			return path_found;
		}
	}
	return 0;
}

int match_domain(char *url, Filter *filters, int num_domain_filters){
	/*
	 * Check whether a given URL matches the filter criteria
	 * @param t URL
	 * @param filters Array of Filters containg either string or regular
	 * expressions to macth
	 * @return 1 if the URL matches, 0 otherwise
	 */
	char* domain;
	int j;
	regmatch_t pmatch[1];

	if (num_domain_filters > 0){
		/* this for-loop checks if the url contains the domain string
		 * if it does return 1 if there is no additional filtering, or
		 * else break to next loop.
		 */
		domain =extract_domain(url);
		if (domain !=NULL){
			for (j=0; j<num_domain_filters; ++j){
				switch(search){
					case STRING:
						if (strstr(domain, filters[j].domain.string) != NULL) {
							return 1;
						}
						break;

					case REGEX: {
						int result = regexec(filters[j].domain.regex, domain, 0, pmatch, 0);
						if (result ==0) {
							return 1;
						}
						if (result >0){
							if (verbose_flag){
								char errbuf[100];
								regerror(result, filters[j].domain.regex, errbuf, 100);
								fprintf(stderr, "Encountered error while regex matching: %s\n", errbuf);
							}
						}
					}
					break;

					default:
						break;
					}
				}
			}
		}
	return 0;
}

int match_http_status(char *http_status_field, Filter *filters, int num_http_status_filters){
	/*
	 * Check whether a given http response status code matches the filter criteria
	 * @param t http_status field
	 * @param filters Array of Filters containg either string or regular
	 * expressions to macth
	 * @return 1 if the http status matches, 0 otherwise
	 */
	char* http_status;
	int j;
	regmatch_t pmatch[1];

	if (num_http_status_filters > 0){
		/* this for-loop checks if the url contains the domain string
		 * if it does return 1 if there is no additional filtering, or
		 * else break to next loop.
		 */
		http_status = extract_status(http_status_field);
		if (http_status !=NULL){
			for (j=0; j<num_http_status_filters; ++j){
				switch(search){
					case STRING:
						if (strstr(http_status, filters[j].http_status.string) != NULL) {
							return 1;
						}
						break;

					case REGEX: {
						int result = regexec(filters[j].http_status.regex, http_status, 0, pmatch, 0);
						if (result ==0) {
							return 1;
						}
						if (result >0){
							if (verbose_flag){
								char errbuf[100];
								regerror(result, filters[j].http_status.regex, errbuf, 100);
								fprintf(stderr, "Encountered error while regex matching: %s\n", errbuf);
							}
						}
					}
					break;

					default:
						break;
					}
				}
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

int geo_check(const char *country_code, char *countries[], int countries_count) {
	if (!country_code){
		return 0;
	}
	int i;
	for (i = 0; i < countries_count; ++i) {
		if (verbose_flag){
			fprintf(stderr, "Comparing: %s <--> %s\n", country_code, countries[i]);
		}
		if (strcmp(country_code, countries[i]) == 0) {
			return 1;
		}
	}
	return 0;
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
	 * fields is by reference, so fields[4] will be replaced with the resulting string.
	 */
	
	if (should_anonymize_ip) {
		fields[4] = anonymous_ip;
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

void parse(char *country_input, char *path_input, char *domain_input, char *ipaddress_input, char *http_status_input, char *bird, char *db_path, int minimum_field_count) {
	// GENERIC VARIABLES
	char *fields[maximum_field_count];	// the number of fields we expect in a single line
	int num_filters =0;			// the total number of filters we detect from the command line
	int num_domain_filters =0;  // the total number of domain filters
	int num_path_filters =0 ;   // the total number of path filters
	int num_ipaddress_filters=0;// the total number of ipaddress filter
	int num_countries_filters=0;// the total number countries we want to restrict the filtering
	int num_http_status_filters=0; // the total number of http status we want to restrict the filtering.  
	int required_hits =0;
	int bird_int = 0;
	int i;
	int j;
	int n;
	
	int field_count_this_line=0;  // number of fields found in the current line

	char line[65534];
	char *ipaddr;
	char *url;
	char *http_status;

	// DETERMINE NUMBER OF FILTERS
	for(n=0; n<num_predefined_filters; n++){
		switch (n) {
		case 0: // NO_FILTER
			if(params[n] ==1){
				required_hits+=1;
			}
			break;

		case 1: // DOMAIN_FILTER
			if(params[n] ==1){
				num_domain_filters = determine_num_obs(domain_input,comma_delimiter);
				required_hits+=1;
			}
			break;

		case 2: // PATH_FILTER
			if(params[n] ==1){
				num_path_filters = determine_num_obs(path_input,comma_delimiter);
				required_hits+=1;
			}
			break;

		case 3: //IP_FILTER
			if(params[n] ==1){
				num_ipaddress_filters = determine_num_obs(ipaddress_input, comma_delimiter);
				required_hits+=1;
			}
			break;

		case 4: // GEO_FILTER
			if(params[n] ==1){
				if(country_input != NULL && strlen(country_input) >1){
					num_countries_filters = determine_num_obs(country_input, comma_delimiter);
					required_hits+=1;
				}
			}
			break;
		case 5: // HTTP_STATUS_FILTER
			if(params[n] ==1){
				if(http_status_input != NULL && strlen(http_status_input) >1){
					num_http_status_filters = determine_num_obs(http_status_input, comma_delimiter);
					required_hits+=1;
				}
			}		
			break;
		}
	}

	num_filters = num_path_filters+num_domain_filters+num_ipaddress_filters+num_countries_filters+num_http_status_filters;
	Filter filters[num_filters];

	// GEO_FILTER INITIALIZATION
	GeoIP *gi;
	char *countries[num_countries_filters];
	char *area;

	// FILTER INITIALIZATION
	for(n=0; n<num_predefined_filters; n++){
		switch (n) {
		case 0: // NO_FILTER
			if(params[n] ==1){
			}
			break;

		case 1: // DOMAIN_FILTER
			if(params[n] ==1){
				init_domains(filters, domain_input,comma_delimiter);
			} else {
				domain_input=NULL;
			}
			break;

		case 2: // PATH_FILTER
			if(params[n] ==1){
				init_paths(filters, path_input, comma_delimiter);
			} else {
				path_input = NULL;
			}
			break;

		case 3: //IP_FILTER
			if(params[n] ==1){
				init_ip_addresses(filters, ipaddress_input, comma_delimiter);
			} else {
				ipaddress_input = NULL;
			}
			break;

		case 4: // GEO_FILTER
			if(params[n] ==1 || (recode & GEO)) {
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
			} else {
				country_input =NULL;
			}
			break;
		case 5: // HTTP_STATUS_FILTER
			if(params[n] ==1){
				init_http_status(filters, http_status_input, comma_delimiter);
			} else {
				http_status_input = NULL;
			}
			break;
		}
	}

	if (verbose_flag){
		fprintf(stderr, "num_path_filters:%d\tnum_domain_filters:%d\tnum_http_status_filters:%d\tip_address_count:%d\tcountries_count:%d\n",\
			num_path_filters,num_domain_filters,num_http_status_filters,num_ipaddress_filters,num_countries_filters);
	}


	// Now that we have initilaized all the filters,
	// do the actual filtering and conversion of the 
	// incoming data.
	while (!feof(stdin)) {
		int found =0;
		area = NULL;
		//re-initialize the fields array.
		for (j = 0; j < maximum_field_count; j++) {
			fields[j] = NULL;
		}

		char *r;
		r=fgets(line, 65534, stdin);
		if(!r) {
			break;
		}

		i = 0;
		do {
			fields[i] = r;
			strsep(&r, ws_delimiter);
			i++;
		} while (r != NULL && i < maximum_field_count);

		if (i < minimum_field_count || r != NULL){
			/* line contains less than minimum_field_count fields. ignore this line.
			 */
			continue;
		}
		
		// we found i fields in this line.
		field_count_this_line = i;

		ipaddr      = fields[4];
		http_status = fields[5];
		url         = fields[8];

		if (url != NULL) {
			if (params[NO_FILTER] == 1){
				found =1;
			}

			if (params[DOMAIN_FILTER] == 1){
				found += match_domain(url, filters, num_domain_filters);
			}

			if (params[PATH_FILTER] == 1){
				found += match_path(url, filters, num_path_filters);
			}
			
			if (params[HTTP_STATUS_FILTER] == 1){
				found += match_http_status(http_status, filters, num_http_status_filters);
			}

			if (params[IP_FILTER] == 1){
				found += match_ip_address(ipaddr, filters, num_ipaddress_filters);
			}

			if (params[GEO_FILTER] == 1){
				area = geo_lookup(gi, ipaddr, bird_int);
				found += geo_check(area, countries, num_countries_filters);
				if (verbose_flag){
					fprintf(stderr, "IP address: %s was geocoded as: %s\n", ipaddr, area);
				}
			}
		}


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
				// true, then the IP will be replaced with 0.0.0.0
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
	char *version = VERSION_STRING(VERSION_NUMBER);
	printf("udp-filter %s\n", version);
	printf("Copyright (C) 2012 Wikimedia Foundation, Inc.\n");
	printf("This is free software; see the source copying conditions. There is NO\n");
	printf("warrant; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
	printf("\n");
	printf("Written by Diederik van Liere (dvanliere@wikimedia.org).\n");
}

void usage() {
	printf("Wikimedia's generic UDP filtering system.\n");
	printf("This new filter system replaces the old collection of filters written in C. It is highly customizable and can be fully configured using the command line.\n");
	printf("\n");
	printf("\nUsage: udp-filter [OPTION] ...\n\n");
	printf("Options:\n");
	printf("  Either --path or --domain are mandatory (you can use them both, the other command line parameters are optional.\n");
	printf("  -p or --path:               the string or multiple strings separated by a comma that indicate what you want to match.\n");
	printf("  -d or --domain:             the part of the domain name that you want to match. For example, 'en.m.' would match all English mobile Wikimedia projects.\n");
	printf("\n");
	printf("  -g or --geocode:            flag to indicate geocode the log, by default turned off.\n");
	printf("  -b or --bird:               parameter that is mandatory when specifying -g or --geocode. Valid choices are <country>, <region>, <city>, <latlon> and <everything>.\n");
	printf("  -a or --anonymize:          flag to indicate anonymize the log, by default turned off.\n");
	printf("  -i or --ip:                 flag to indicate ip-filter the log, by default turned off. You can supply comma separated ip addresses, or comma-separated ip-ranges.\n");
	printf("\n");
	printf("  -n or --min-field-count:    specify the number of fields that a log line contains. Default is 14.\n");
	printf("  -m or --maxmind:            specify alternative path to MaxMind database.\n");
	printf("    Current path to region database: %s\n", db_region_path);
	printf("    Current path to city database: %s\n", db_city_path);
	printf("\n");
	printf("  -c or --country-list:       limit the log to particular countries, this should be a comma separated list of country codes. Valid country codes are the ISO 3166 country codes (see http://www.maxmind.com/app/iso3166). \n");
	printf("  -s or --http-status:        match only lines with these HTTP response status code(s).\n");
	printf("  -r or --regex:              the parameters -p, -u and -s are interpreted as regular expressions. Regular expression searching is probably slower so substring matching is recommended.\n");
	printf("  -f or --force:              do not match on either domain, path, or ip address, basically turn filtering off. Can be useful when filtering for specific country.");
	printf("\n");
	printf("  -v or --verbose:            output detailed debug information to stderr, not recommended in production.\n");
	printf("  -h or --help:               show this menu with all command line options.\n");
	printf("  -V or --version             show version info.\n");
}

int main(int argc, char **argv){
	char *country_input = NULL;
	char *path_input = NULL;
	char *domain_input = NULL;
	char *ipaddress_input = NULL;
	char *http_status_input = NULL;
	char *db_path = NULL;
	char *bird = NULL;
	int geo_param_supplied = -1;
	int required_args = 0;
	
	// Expected minimum number of fields in a line.
	// There  can be no fewer than this, but no more than
	// maximum_field_count space separated fields in a long line.
	// Anything outside of this range will be discarded.
	int minimum_field_count = 14;

	static struct option long_options[] = {
			{"anonymize", no_argument, NULL, 'a'},
			{"bird", required_argument, NULL, 'b'},
			{"country_list", required_argument, NULL, 'c'},
			{"domain", required_argument, NULL, 'd'},
			{"force", no_argument, NULL, 'f'},
			{"geocode", no_argument, NULL, 'g'},
			{"help", no_argument, NULL, 'h'},
			{"ip", required_argument, NULL, 'i'},
			{"http-status", required_argument, NULL, 's'},
			{"maxmind", required_argument, NULL, 'm'},
			{"min-field-count", required_argument, NULL, 'n'},
			{"path", required_argument, NULL, 'p'},
			{"regex", no_argument, NULL, 'r'},
			{"verbose", no_argument, NULL, 'v'},
			{0, 0, 0, 0}
	};

	signal(SIGINT,die);

	int c;

	while((c = getopt_long(argc, argv, "ab:c:d:m:n:s:fghi:rp:vV", long_options, NULL)) != -1) {
		// c,d,m,i,p have mandatory arguments
		switch(c)
		{
		case 'a':
			/* Indicate whether we should anonymize the log, default is false */
			recode = (recode | ANONYMIZE);
			break;

		case 'b':
			geo_param_supplied =0;
			bird = optarg;
			break;

		case 'c':
			/* Optional list of countries to restrict logging */
			country_input = optarg;
			params[GEO_FILTER] = 1;
			required_args++;
			break;

		case 'd':
			/* -d is set. This specifies the project: en.wikipedia, commons.
			 * it should be a part of the domain name
			 */
			params[DOMAIN_FILTER] = 1;
			domain_input = optarg;
			required_args++;
			search=STRING;
			break;

		case 'm':
			/* Optional alternative path to database. */
			db_path = optarg;
			break;

		case 'n':
			minimum_field_count = atoi(optarg);
			break;

		case 'f':
			/* Do not perform any matching */
			params[NO_FILTER] = 1;
			required_args++;
			break;

		case 'g':
			/* Indicate whether we should do geocode, default is false */
			recode = (recode | GEO);
			//params[GEO_FILTER] = 1;
			break;

		case 'h':
			/* Show help to user */
			version();
			usage();
			exit(EXIT_SUCCESS);
			break;

		case 'i':
			/* Enable filtering by ip-address or ip-range */
			params[IP_FILTER] =1;
			ipaddress_input = optarg;
			required_args++;
			break;

		case 's':
			/* Enable filtering by HTTP response status code */
			params[HTTP_STATUS_FILTER] = 1;
			http_status_input = optarg;
			required_args++;
			break;
		case 'r':
			/* indicate whether we should treat the search string as a regular
			 * expression or not, default is false
			 */
			search=REGEX;
			break;

		case 'p':
			/* -p is set. Store the url that needs to be matched. */
			params[PATH_FILTER]= 1;
			path_input = optarg;
			required_args++;
			search=STRING;
			break;

		case 'v':
			/* Turn verbose on */
			verbose_flag = 1;
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
	
	// minimum_field_count cannot be greater than maximum_field_count
	if (minimum_field_count > maximum_field_count)
	{
		fprintf(stderr,"min-field-count (%i) cannot be greater than %i.\n", minimum_field_count, maximum_field_count);
		version();
		usage();
		exit(EXIT_FAILURE);
	}
	
	if (geo_param_supplied==-1 && params[GEO_FILTER] ==1){
		fprintf(stderr,"You supplied the -g parameter without specifying the -b parameter.\n");
		exit(EXIT_FAILURE);
	}
	
	if (required_args>=1){
		parse(country_input, path_input, domain_input, ipaddress_input, http_status_input, bird, db_path, minimum_field_count);
	} else{
		usage();
	}
	return EXIT_SUCCESS;
}
