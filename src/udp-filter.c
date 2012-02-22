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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <regex.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


#include <GeoIP.h>
#include <GeoIPCity.h>
#include "countries.h"
#include "udp-filter.h"

/*
 * Enter this in GDB for debugging
 * run -a -d GeoIP.dat -u wiki,waka -v < example.log
 */

char anonymous_ip[] = "0.0.0.0";
char unknown_geography[] = "XX";
const char comma_delimiter[] =",";
const char ws_delimiter[] = " ";
const char fs_delimiter[] = "/";
const char us_delimiter[] = "_";
const int num_fields =14;
const int unknown_geography_length =2;
const int num_predefined_filters = (GEO_FILTER - NO_FILTER) +1;
int verbose_flag = 0;       // this flag indicates whether we should output detailed debug messages, default is off.

char *db_country_path = "/var/log/squid/filters/GeoIPLibs/GeoIP.dat";
char *db_city_path = "/var/log/squid/filters/GeoIPLibs/GeoIPCity.dat";
char *db_region_path = "/var/log/squid/filters/GeoIPLibs/GeoIPRegion.dat";

SearchType search = STRING;
RecodeType recode = NO;
IpMatchType ipmatch = SIMPLE;

int params[5];   // Increase this when you add a new filter to ScreenType enum.

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

Sample line, with the client IP address replaced with 1.2.3.4 to protect the innocent:
sq18.wikimedia.org 1715898 1169499304.066 0 1.2.3.4 TCP_MEM_HIT/200 13208 GET http://en.wikipedia.org/wiki/Main_Page NONE/- text/html - - Mozilla/4.0%20(compatible;%20MSIE%206.0;%20Windows%20NT%205.1;%20.NET%20CLR%201.1.4322)

 */

int determine_num_obs(char *raw_input, char delimiter) {
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

regex_t * init_regex(char *token) {
	/*
	 * This function tries to compile a string into a regex_t type
	 *
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

void init_countries(char *countries[], char *country_input, int num_countries) {
	/*
	 * This function initializes an array of pointers that will contain the
	 * country codes that we need to filtered (i.e. included in the log file)
	 * We also validate whether the entered country code is a valid country
	 * code according to the ISO 3166-1 standard.
	 */
	if (num_countries == 0){
		return;
	}
	char *country_input_dup = strdup(country_input);
	if (country_input_dup != NULL) {
		char *country_token = strtok(country_input_dup, comma_delimiter);
		int i=0;
		while (country_token != NULL) {
			int result = verify_country_code(country_token);
			if (result){
				countries[i] = strdup(country_token);
			} else {
				fprintf(stderr, "%s is not a valid ISO 3166-1 country code.\n", country_token);
				exit(EXIT_FAILURE);
			}
			i++;
			country_token = strtok(NULL, comma_delimiter);
			if (i>num_countries){
				fprintf(stderr, "Catching out of bounds error while initializing countries array.\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	free(country_input_dup);
}

long convert_ip_to_long(char *ip_address, int initialization){
	/*
	 * Given an IP (4 or 6) address return the long value.
	 */
	struct addrinfo *addr;
	char *ip_address_dup = strdup(ip_address);
	int result = getaddrinfo(ip_address_dup, NULL,NULL, &addr);
	if (result==0){
		long ip_long = -1;
		switch (addr->ai_family){
		case AF_INET: {
			struct sockaddr_in *ipv4 = malloc(sizeof(struct sockaddr_in));
			memset(ipv4, 0, sizeof(struct sockaddr_in));
			memcpy(ipv4, (struct sockaddr_in *)addr->ai_addr, sizeof(struct sockaddr_in));
			ip_long = ntohl(ipv4->sin_addr.s_addr);
			free(ipv4);
			break;
		}
		case AF_INET6:{
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
			/* we cannot convert an ip6 address to a long, an ip6 address is stored
			 *  as an array of sixteen 8-bit elements, that together make up a
			 *  single 128-bit IPv6 address. (ipv6->sin6_addr.__u6_addr;)
			 *  Implementation is not finished.
			 *  TODO: Add byte-by-byte comparison
			 */
			fprintf(stderr,"IP6 address filtering is not yet implemented.\n");
			free(ipv6);
			break;
		}

		default: {
			break;
		}
		}
		if (verbose_flag==1){
			fprintf(stderr,"ip-address: %s\t ip-address long value:%ld\n", ip_address_dup, ip_long);
		}
		freeaddrinfo(addr);
		free(ip_address_dup);
		return ip_long;
	} else{
		if (initialization==1){
			const char *error = gai_strerror(result);
			fprintf(stderr, "Could not convert ip address: %s. Exact cause: %s\n", ip_address_dup, error);
			/* we are encountering the error while initializing the filter, this
			 *  is most likely due to faulty user input.
			 */
			exit(EXIT_FAILURE);
		} else{
			// we are encountering the error while parsing a logline, just
			// ignore it and go to the next line
			freeaddrinfo(addr);
			free(ip_address_dup);
			return -1;
		}
	}
}

void init_ip_addresses(Filter *filters, char *ipaddress_input){
	int i=0;
	int initialization=1;
	char *ipaddress_input_dup = strdup(ipaddress_input);
	ipaddress_input_dup = strtok(ipaddress_input, comma_delimiter);
	if(strstr(ipaddress_input_dup, "-") == NULL) {
		// we are not dealing with ip-ranges but just with individual ip adress(es).
		while (ipaddress_input_dup!=NULL) {
			filters[i].ip.address_long= convert_ip_to_long(ipaddress_input_dup, initialization);
			i++;
			ipaddress_input_dup = strtok(NULL, comma_delimiter);
		}
	} else {
		ipmatch = RANGE;
		// we are dealing with ip-ranges.
		char * hyphenPos = strstr(ipaddress_input, "-");
		*hyphenPos = '\0';
		filters[i].ip.lbound = convert_ip_to_long(ipaddress_input_dup, initialization);
		filters[i].ip.ubound = convert_ip_to_long(hyphenPos + 1, initialization);
	}
}


void init_paths(Filter *filters, char *path_input) {
	/* path_input is a string *excluding* the full qualified domain name
	 * path_input can be comma delimited, so we first need to determine the
	 * different parts and then depending on whether the regex_flag is activated
	 * we need to compile the string or else we just store it right away.
	 */
	char *url_token;
	int i=0;
	int error=0;

	url_token = strtok(path_input,comma_delimiter);
	while (url_token != NULL) {
		switch(search) {
		case STRING:{
			size_t s = strlen(url_token) + 1;
			filters[i].path.string= malloc(sizeof(char)*s);
			if (filters[i].path.string==NULL) {
				error=1;
				break;
			}
			strcpy(filters[i].path.string, url_token);
			filters[i].searchtype = PATH_FILTER;
			break;
		}
		case REGEX:{
			filters[i].path.regex =malloc(sizeof(regex_t));
			if (filters[i].path.regex==NULL) {
				error=1;
				break;
			}
			filters[i].path.regex = init_regex(url_token);
			filters[i].searchtype = PATH_FILTER;
			break;
		}
		}
		i++;
		url_token = strtok(NULL,comma_delimiter);
	}

	if (error==1){
		fprintf(stderr, "PATH: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}

}

void init_domains(Filter *filters, char *domain_input){
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
	char *domain_token;
	domain_token = strtok(domain_input, comma_delimiter);

	while (domain_token !=NULL){
		switch(search){
		case STRING: {
			size_t s = strlen(domain_token) + 1;
			filters[i].domain.string= malloc(sizeof(char)*s);
			if(filters[i].domain.string==NULL) {
				error=1;
				break;
			}
			strcpy(filters[i].domain.string,domain_token);
			filters[i].searchtype = DOMAIN_FILTER;
			break;

		}
		case REGEX:{
			filters[i].domain.regex= malloc(sizeof(regex_t));
			if (filters[i].domain.regex==NULL){
				error=1;
				break;
			}
			filters[i].domain.regex = init_regex(domain_token);
			filters[i].searchtype = DOMAIN_FILTER;
			break;
		}
		}
		i++;
		domain_token=strtok(NULL, comma_delimiter);
	}
	if (error==1){
		fprintf(stderr, "DOMAIN: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}
}

int init_bird_level(char *bird){
	int result;
	if(strcmp(bird,"country")==0) {
		result = COUNTRY;
	} else if (strcmp(bird,"region")==0) {
		result = REGION;
	} else if (strcmp(bird,"city")==0) {
		result = CITY;
	} else if (strcmp(bird, "lonlat")==0){
		result = LON_LAT;
	} else {
		fprintf(stderr, "%s is not a valid option for geocoding. <country>, <region>, <city> or <lonlat> (without the <> are valid choices).\n", bird);
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

int match_ip_address(char *ip_address,Filter *filters, int num_filters){
	int i=0;
	long ip_address_long = convert_ip_to_long(ip_address, 0);
	if (ip_address_long==-1){
		// this happens when there was an error converting the ip_address to a long.
		// treat as a non-match.
		return 0;
	}
	switch (ipmatch) {
	case SIMPLE:
		for(i=0;i<num_filters;i++){
			if (ip_address_long == filters[i].ip.address_long){
				return 1;
			}
		}
		return 0;
		break;

	case RANGE:
		for(i=0;i<num_filters;i++){
			if (verbose_flag == 1){
				fprintf(stderr, "ip address long:%ld\tlower-bound:%ld\tupper-bound:%ld\n", ip_address_long, filters[i].ip.lbound,filters[i].ip.ubound);
			}
			if (ip_address_long >= filters[i].ip.lbound) {
				if(ip_address_long <= filters[i].ip.ubound){
					return 1;
				}
			}
		}
		return 0;
		break;
	}
	return 0;
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
			for (i = 0; i < num_path_filters; ++i) {
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

				case REGEX:
				{
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


char *geo_lookup(GeoIP *gi, char *ipaddr, int bird) {
	/*
	 * Lookup the country_code by ip address, we can
	 * extend this in the future with more granular data
	 * such as region,city or even zipcode.
	 */
	int max_buf_length= 100;
	char *area = malloc(max_buf_length);

	switch(bird){
		case COUNTRY: {
			const char *country= GeoIP_country_code_by_addr(gi, ipaddr);
			if (country==NULL){
				strcpy(area, unknown_geography);
			} else {
				strcpy(area, country);
			}

			}
			break;

		case REGION:{
			GeoIPRegion *gir;
			gir=GeoIP_region_by_addr(gi,ipaddr);
			if(strlen(gir->region)==0){
				area= unknown_geography;
			} else {
				area=gir->region;
			}

			GeoIPRegion_delete(gir);
			}
			break;

		case CITY:{
			GeoIPRecord *grecord;
			grecord = GeoIP_record_by_addr(gi, ipaddr);
			if (grecord !=NULL){
				if (grecord->city == NULL){
					strcpy(area, unknown_geography);
				} else {
					int len = strlen(grecord->city);
					strcpy(area,grecord->city);
					replace_space_with_underscore(area, len);
				}
				GeoIPRecord_delete(grecord);
			} else {
				area = malloc(unknown_geography_length*sizeof(char));
				strcpy(area, unknown_geography);
			}
			break;
		}

		case LON_LAT: {
			GeoIPRecord *grecord;
			grecord = GeoIP_record_by_addr(gi, ipaddr);
			if (grecord!=NULL){
				int length = 0;
				length += snprintf(area+length, max_buf_length, "%f", grecord->longitude);
				length += snprintf(area+length, max_buf_length, "%s", ":");
				length += snprintf(area+length, max_buf_length, "%f", grecord->latitude);
			} else {
				area = unknown_geography;
			}
		}
		break;

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

void replace_ip_addr(char *fields[], char* area){
	/*
	 * The purpose of this function is to replace the original ip address from
	 * line (where line is the original input as read from STDIN with
	 * either an anonymous ip address (0.0.0.0) or the country code as
	 * generated by geocode_lookup.
	 * The returning value is a line with the replaced ip address.
	 */
	switch (recode){
	case GEO:
		fields[4]= area;
		break;

	case ANONYMIZE:
		fields[4] = anonymous_ip;
		break;

	case NO:
		break;
	}
}

void free_memory(Filter *filters, char *path_input, char *domain_input, int num_filters) {
	int i;
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
			}
			break;
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
			}
			break;
		}
	}
}

void parse(char *country_input, char *path_input, char *domain_input, char *ipaddress_input, char *bird, char *db_path) {
	// GENERIC VARIABLES
	char *fields[num_fields];	//the number of fields we expect in a single line
	int num_filters =0;
	int num_domain_filters =0;
	int num_path_filters =0 ;
	int num_ipaddress_filters=0;
	int num_countries_filters=0;
	int required_hits =0;
	int bird_int = 0;
	int i;
	int j;
	int n;

	char line[65534];
	char *ipaddr;
	char *url;

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
				num_domain_filters  = determine_num_obs(domain_input,comma_delimiter[0]);
				required_hits+=1;
			}
			break;

		case 2: // PATH_FILTER
			if(params[n] ==1){
				num_path_filters = determine_num_obs(path_input,comma_delimiter[0]);
				required_hits+=1;
			}
			break;

		case 3: //IP_FILTER
			if(params[n] ==1){
				num_ipaddress_filters = determine_num_obs(ipaddress_input, comma_delimiter[0]);
				required_hits+=1;
			}
			break;

		case 4: // GEO_FILTER
			if(params[n] ==1){
				if(country_input != NULL && strlen(country_input) >1){
					num_countries_filters= determine_num_obs(country_input, comma_delimiter[0]);
					required_hits+=1;
				}
			}
			break;
		}
	}

	num_filters = num_path_filters+num_domain_filters+num_ipaddress_filters+num_countries_filters;
	Filter filters[num_filters];


	// GEO_FILTER INITIALIZATION
	GeoIP *gi;
	char* countries[num_countries_filters];
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
				init_domains(filters, domain_input);
			}
			break;

		case 2: // PATH_FILTER
			if(params[n] ==1){
				init_paths(filters, path_input);
			}
			break;

		case 3: //IP_FILTER
			if(params[n] ==1){
				init_ip_addresses(filters, ipaddress_input);
			}
			break;

		case 4: // GEO_FILTER
			if(params[n] ==1){
				init_countries(countries, country_input, num_countries_filters);
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

				case LON_LAT:
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
			break;
		}
	}

	if (verbose_flag){
		fprintf(stderr, "num_path_filters:%d\tnum_domain_filters:%d\t ip_address_count:%d\tcountries_count:%d\n",\
				num_path_filters,num_domain_filters,num_ipaddress_filters,num_countries_filters);
	}


	while (!feof(stdin)) {
		int found =0;
		//re-initialize the fields array.
		for (j = 0; j < num_fields; j++) {
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
		} while (r != NULL && i < num_fields);

		if (i<num_fields){
			/* line contained fewer than 14 fields, ignore this field.
			 *  this check should be stricter, it should basically ignore any
			 *  line with != 14 fields, however there are too many known issues
			 *  with the current logging infrastructure that we know for a fact
			 *  that we will run into longer lines. Longer lines should not cause
			 *  any problems as we are only looking at fields 4 and 8.
			 */
			continue;
		}

		ipaddr = fields[4];
		url = fields[8];

		if (url != NULL) {
			for (n=0; n<num_predefined_filters;n++){
				switch(n){
				case 0: //NO_FILTER:
					if (params[n] == 1){
						found =1;
					}
					break;

				case 1: //DOMAIN_FILTER:
					if (params[n] == 1){
						found += match_domain(url, filters, num_domain_filters);
					}
					break;

				case 2: //PATH_FILTER:
					if (params[n] == 1){
						found += match_path(url, filters, num_path_filters);
					}
					break;

				case 3: //IP_FILTER:
					if (params[n] == 1){
						found += match_ip_address(ipaddr, filters, num_ipaddress_filters);
					}
					break;

				case 4: //GEO_FILTER:
					if (params[n] == 1){
						area = geo_lookup(gi, ipaddr, bird_int);
						found += geo_check(area, countries, num_countries_filters);
						if (verbose_flag){
							fprintf(stderr, "IP address: %s was geocoded as: %s\n", ipaddr, area);
						}
					}
					break;
				}
			}
		}

		if (found >= required_hits) {
			switch(recode) {
			case NO:
				break;

			case ANONYMIZE:
				//Apply the anonymization
				replace_ip_addr(fields, NULL);
				break;

			case GEO:
				// Apply the geocoding
				if (area == NULL){
					area = geo_lookup(gi, ipaddr, bird_int);
				}
				replace_ip_addr(fields, area);
				break;
			}
			// print output to stdout
			for (i=0;i<num_fields;++i){
				if (i!=0){
					FPUTS(ws_delimiter, stdout);
				}
				FPUTS(fields[i], stdout);
			}
		}

		if (verbose_flag) {
			fprintf(stderr, "ipaddr: '%s', url: '%s'\n", ipaddr, url);
		}

	}
	free_memory(filters, path_input, domain_input,num_filters);
}


void usage() {
	printf("Wikimedia's generic UDP filtering system.\n");
	printf("Version 0.2 // Written by Diederik van Liere.\n");
	printf("\n");
	printf("Either --path or --domain are mandatory (you can use them both, the other command line parameters are optional:\n");
	printf("-p or --path:         the string or multiple strings separated by a comma that indicate what you want to match.\n");
	printf("-d or --domain:       the part of the domain name that you want to match. For example, 'en.m.' would match all English mobile Wikimedia projects.\n");
	printf("\n");
	printf("-g or --geocode:      flag to indicate geocode the log, by default turned off.\n");
	printf("-b or --bird:         parameter that is mandatory when specifying -g or --geocode. Valid choices are <country>, <region>, <city> and <lonlat>.\n");
	printf("-a or --anonymize:    flag to indicate anonymize the log, by default turned off.\n");
	printf("-i or --ip:           flag to indicate ip-filter the log, by default turned off. You can supply comma separated ip adresses, or comma-separated ip-ranges.\n");
	printf("\n");
	printf("-m or --maxmind:     specify alternative path to MaxMind database.\n");
	printf("Current path to region database: %s\n", db_region_path);
	printf("Current path to city database: %s\n", db_city_path);
	printf("\n");
	printf("-c or --country_list: limit the log to particular countries, this should be a comma separated list of country codes. Valid country codes are the ISO 3166 country codes (see http://www.maxmind.com/app/iso3166). \n");
	printf("-r or --regex:        the parameters -p and -u are interpreted as regular expressions. Regular expression searching is probably slower so substring matching is recommended.\n");
	printf("-f or --force:        do not match on either domain, path, or ip address, basically turn filtering off. Can be useful when filtering for specific country.");
	printf("\n");
	printf("-v or --verbose:      output detailed debug information to stderr, not recommended in production.\n");
	printf("-h or --help:         show this menu with all command line options.\n");
}

int main(int argc, char **argv){
	char *country_input = NULL;
	char *path_input = NULL;
	char *domain_input = NULL;
	char *ipaddress_input = NULL;
	char *db_path = NULL;
	char *bird = NULL;
	int geo_param_supplied = -1;
	int required_args = 0;

	static struct option long_options[] = {
			{"path", required_argument, NULL, 'p'},
			{"domain", required_argument, NULL, 'd'},
			{"geocode", no_argument, NULL, 'g'},
			{"anonymize", no_argument, NULL, 'a'},
			{"maxmind", required_argument, NULL, 'm'},
			{"country_list", required_argument, NULL, 'c'},
			{"regex", no_argument, NULL, 'r'},
			{"verbose", no_argument, NULL, 'v'},
			{"help", no_argument, NULL, 'h'},
			{"force", no_argument, NULL, 'f'},
			{"ip", required_argument, NULL, 'i'},
			{"bird", required_argument, NULL, 'b'},
			{0, 0, 0, 0}
	};

	int c;

	while((c = getopt_long(argc, argv, "ab:c:d:m:fghi:rp:v", long_options, NULL)) != -1) {
		// c,d,m,i,p have mandatory arguments
		switch(c)
		{
		case 'a':
			/* Indicate whether we should anonymize the log, default is false */
			recode = ANONYMIZE;
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

		case 'f':
			/* Do not perform any matching */
			params[NO_FILTER] = 1;
			required_args++;
			break;

		case 'g':
			/* Indicate whether we should do geocode, default is false */
			recode = GEO;
			params[GEO_FILTER] = 1;
			break;

		case 'h':
			/* Show help to user */
			usage();
			break;

		case 'i':
			/* Enable filternig by ip-address or ip-range */
			params[IP_FILTER] =1;
			ipaddress_input = optarg;
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

		default:
			exit(EXIT_FAILURE);
		}
	}
	if (geo_param_supplied==-1 && params[GEO_FILTER] ==1){
		fprintf(stderr,"You supplied the -g parameter without specifying the -b parameter.\n");
		exit(EXIT_FAILURE);
	}
	if (required_args>=1){
		parse(country_input, path_input, domain_input, ipaddress_input, bird, db_path);
	} else{
		usage();
	}
	return EXIT_SUCCESS;
}
