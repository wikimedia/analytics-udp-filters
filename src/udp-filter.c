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
#include <regex.h>
#include <arpa/inet.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "countries.c"

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


/*
 * Enter this in GDB for debugging
 * run -a -d GeoIP.dat -u wiki,waka -v < example.log
 */

typedef enum ScreenType{
	NO_FILTER  =1,          // no filtering, write all hits to a file
	URL_FILTER =2,          // filter on either domain or path (or both), default value
	IP_FILTER  =4,          // filter on ip address or ip range
	GEO_FILTER =8,          // filter on geographic area
	URL_IP_FILTER = 6,      // filter on both domain / path and ip address(es)
	URL_GEO_FILTER = 10,    // filter on both domain / path and geographic area
	IP_GEO_FILTER = 12,     // filter on ip address(es) and geographic area
	IP_GEO_URL_FILTER = 14, // filter all: domain / path, ip adress(es) and geographic area
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
} RecodeType;

typedef struct {
	char *address;
	unsigned long address_long;
	unsigned long lbound;
	unsigned long ubound;
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
	Ip ip;
	char **countries;
} Filter;

char anonymous_ip[] = "0.0.0.0";
char unknown_geography[] = "XX";
const char comma_delimiter[] =",";	//comma_delimiter has to be a comma (,)
const char ws_delimiter[] = " ";
const char fs_delimiter[] = "/";
const int num_fields =14;

int required_args = 0;
int countries_count =0;
int num_path_filters =0;
int num_domain_filters =0;
int num_ipaddress_filters=0;

char *country_input;
char *url_input;
char *domain_input;
char *ipaddress_input;
char *db_path = "/var/log/squid/filters/GeoIPLibs/GeoIP.dat";


SearchType Search = STRING;
RecodeType Recode = NO;
ScreenType Screen = 0;
IpMatchType IpMatch = SIMPLE;

int verbose_flag = 0;       // this flag indicates whether we should output detailed debug messages.

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

int determine_max_array(int a[], int num_elements) {
	/*
	 * Give an array, return the max value of the array.
	 */
	int i, max=-1;
	for (i=0; i<num_elements; i++) {
		if (a[i]>max) {
			max=a[i];
		}
	}
	return(max);
}

regex_t * init_regex(char *token) {
	/*
	 * This function tries to compile a string into a regex_t type
	 *
	 */
	regex_t *re = (regex_t *) malloc(sizeof(regex_t));
	if (re == NULL){
		fprintf(stderr, "REGEX: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}
	int errcode = regcomp(re, token, REG_EXTENDED|REG_NOSUB);
	if (errcode!=0) {
		char error_message[MAX_ERROR_MSG];
		regerror (errcode, re, error_message, MAX_ERROR_MSG);
		/* report error */
		fprintf(stderr, "When compiling %s to a regular expression, we encountered the following error:\n%s", token, error_message);
		exit(EXIT_FAILURE);
	}
	return re;
}

void init_countries(char *countries[]) {
	/*
	 * This function initializes an array of pointers that will contain the
	 * country codes that we need to filtered (i.e. included in the log file)
	 * We also validate whether the entered country code is a valid country
	 * code according to the ISO 3166-1 standard.
	 */
	// fill the array with country_codes
	if (country_input != NULL) {
		char *country_token = strdup(strtok(country_input, comma_delimiter));
		int i=0;
		while (country_token != NULL) {
			int result = verify_country_code(country_token);
			if (result){
				countries[i] = country_token;
			} else {
				fprintf(stderr, "%s is not a valid ISO 3166-1 country code.\n", country_token);
				exit(EXIT_FAILURE);
			}
			i++;
			country_token = strtok(NULL, comma_delimiter);
		}
	}
}

long convert_ip_to_decimal(char *ip_address){
	/*
	 * Given an IP4 address, this can be generalized to IP6, return the decimal value.
	 */
	struct in_addr addr;
	inet_pton(AF_INET, ip_address, &addr);
	if(&addr.s_addr!=NULL){
		return addr.s_addr;
	} else {
		fprintf(stderr, "Could not convert ip address\n");
		return -1;
	}
}

void init_ip_addresses(Filter *filters){
	int i=0;
	char *ipaddress_input_dup = strdup(strtok(ipaddress_input, comma_delimiter));
	if(strstr(ipaddress_input, "-") ==NULL){
		// we are not dealing with ip-ranges but just with individual ip adress(es).
		while (ipaddress_input_dup!=NULL) {
			filters[i].ip.address_long=  convert_ip_to_decimal(ipaddress_input_dup);
			i++;
			ipaddress_input_dup = strtok(NULL, comma_delimiter);
		}
	} else {
		IpMatch = RANGE;
		// we are dealing with ip-ranges.
		int j=0;
		char *ip_address_end;
		char *ip_address = strdup(strtok_r(ipaddress_input_dup, "-", &ip_address_end));
		while (ip_address!=NULL){
			if (j%2==0){
				filters[i].ip.lbound = convert_ip_to_decimal(ip_address); //inet_addr(ip_address);
			} else {
				filters[i].ip.ubound = convert_ip_to_decimal(ip_address);
			}
			j++;
			ip_address = strtok_r(NULL, "-", &ip_address_end);
		}
	}
}


void init_paths(Filter *filters) {
	/* url_input is a string *excluding* the full qualified domain name
	 * url_input can be comma delimited, so we first need to determine the
	 * different parts and then depending on whether the regex_flag is activated
	 * we need to compile the string or else we just store it right away.
	 */
	char *url_token;
	int i=0;
	int error=0;

	num_path_filters = determine_num_obs(url_input, comma_delimiter[0]);
	url_token = strtok(url_input,comma_delimiter);
	printf("%s", url_token);
	while (url_token != NULL) {
		switch(Search) {
		case STRING:
			filters[i].path.string =malloc(sizeof(url_token));
			if (filters[i].path.string==NULL) {
				error=1;
				break;
			}
			filters[i].path.string = url_token;
			break;

		case REGEX:
			filters[i].path.regex =malloc(sizeof(regex_t));
			if (filters[i].path.regex==NULL) {
				error=1;
				break;
			}
			filters[i].path.regex = init_regex(url_token);
			break;
		}
		i++;
		url_token = strtok(NULL,comma_delimiter);
	}

	if (error==1){
		fprintf(stderr, "PATH: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}

}

void init_domains(Filter *filters){
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
	num_domain_filters = determine_num_obs(domain_input, comma_delimiter[0]);
	domain_token = strtok(domain_input, comma_delimiter);

	while (domain_token !=NULL){
		switch(Search){
		case STRING:
			filters[i].domain.string= malloc(sizeof(domain_token));
			if(filters[i].domain.string==NULL) {
				error=1;
				break;
			}
			filters[i].domain.string  = domain_token;
			break;

		case REGEX:
			filters[i].domain.regex= malloc(sizeof(regex_t));
			if (filters[i].domain.regex==NULL){
				error=1;
				break;
			}
			filters[i].domain.regex = init_regex(domain_token);
			break;
		}
		i++;
		domain_token=strtok(NULL, comma_delimiter);
	}
	if (error==1){
		fprintf(stderr, "DOMAIN: Could not allocate memory. This should never happen");
		exit(EXIT_FAILURE);
	}
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
	unsigned long ip_address_long = inet_addr(ip_address);
	switch (IpMatch) {
		case SIMPLE:
			for(i=0;i<num_filters;i++){
				if (ip_address_long == filters[i].ip.address_long){
					return 1;
				}
			}
			return 0;
			break;

		case RANGE:
			printf("ACTUAL:%ld\tLBOUND:%ld\tUBOUND:%ld\n", ip_address_long, filters[i].ip.lbound,filters[i].ip.ubound);
			for(i=0;i<num_filters;i++){
				printf("CHECKING: %i\n", i);
				if (ip_address_long > filters[i].ip.lbound) {
					if(ip_address_long < filters[i].ip.ubound){
						return 1;
					}
				}
			}
			return 0;
			break;
		}
	return 0;
}

int match_url(char *url, Filter *filters){
	/*
	 *
	 * Check whether a given URL matches the filter criteria
	 * @param t URL
	 * @param urls Array of URL substrings to match
	 * @param domains Array of domain substrings or regular expressions
	 *  to match
	 * @return 1 if the URL matches, 0 otherwise
	 *
	 * There are three possible ways to match a filter
	 * 1: Both domain name(s) and filter(s) are defined,
	 * found=1 when *both* criteria are satisfied. This
	 * allows for targeted filtering.
	 *
	 * 2: Only a domain name is defined, found=1 when
	 * the domain name matches. This allows for project
	 * level filtering.
	 *
	 * 3: Only a filter is defined, found=1 when the filter
	 * matches. This allows for filtering for particular
	 * pages across different projects.
	 *
	 * Option 2 will generate the most hits, then option 3
	 * and finally option 1.
	 *
	 */
	int found_domain = 0;
	char* domain;
	int j;
	regmatch_t pmatch[1]; // regex specific variable

	if (num_domain_filters > 0){
		/* this for-loop checks if the url contains the domain string
		 * if it does return 1 if there is no additional filtering, or
		 * else break to next loop.
		 */
		domain =extract_domain(url);
		if (domain !=NULL){
			for (j=0; j<num_domain_filters; ++j){
				switch(Search){
				case STRING:
					if (strstr(domain, filters[j].domain.string) != NULL) {
						found_domain = 1;
					}
					break;
				case REGEX:
					if (regexec(filters[j].domain.regex, domain, 0, pmatch, 0) == 0) {
						found_domain = 1;
					}
					break;
				}
				if (found_domain == 1){
					if (num_path_filters ==0) {
						// No filters have been defined just domain matching.
						return 1;
					} else {
						break;
					}
				}
			}
		}
	}

	if (num_path_filters > 0) {
		/*
		 * this for loop checks if the url contains the path from the command
		 * line.If it finds a match then return 1 else return 0.
		 */
		int i;
		int path_found = 0;
		char* path = strtok(url, ws_delimiter);

		if (path!=NULL){
			for (i = 0; i < num_path_filters; ++i) {
				switch (Search){
					case STRING:
						if (strstr(path, filters[i].path.string)!=NULL){
							path_found =1;
						}
						if (verbose_flag){
							fprintf(stderr, "%s<-->%s\t%d\n", path, filters[i].path.string, path_found);
						}
						break;


					case REGEX:
						if (regexec(filters[i].path.regex, path, 0, pmatch, 0) == 0) {
							path_found =1;
						}

						if (verbose_flag){
							fprintf(stderr, "%s<-->%p\t%d\n", path, &filters[i].path.regex, path_found);
						}
						break;
				}

			}
			return path_found;
		}
	}
	return 0;
}


const char *geo_lookup(GeoIP *gi, char *ipaddr) {
	/*
	 * Lookup the country_code by ip address, we can
	 * extend this in the future with more granular data
	 * such as region,city or even zipcode.
	 */
	const char *country_code= GeoIP_country_code_by_addr(gi, ipaddr);
	return country_code;
}

int geo_check(const char *country_code, char *countries[]) {
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

void replace_ip_addr(char *fields[], const char* country_code){
	/*
	 * The purpose of this function is to replace the original ip address from
	 * line (where line is the original input as read from STDIN with
	 * either an anonymous ip address (0.0.0.0) or the country code as
	 * generated by geocode_lookup.
	 * The returning value is a line with the replaced ip address.
	 */
	switch (Recode){
	case GEO:
		if (country_code != NULL){
			static char cc[10];
			if (strlen(country_code) < sizeof(cc)) {
				strcpy(cc, country_code);
			} else {
				strcpy(cc, unknown_geography);
			}
			fields[4] = cc;
		} else {
			fields[4] = unknown_geography;
		}
		break;

	case ANONYMIZE:
		fields[4] = anonymous_ip;
		break;

	case NO:
		break;
	}
}

void free_memory(Filter *filters, int num_filters) {
	int i;
	for(i=0;i<num_filters; i++){
		if (Screen == URL_FILTER){
			switch (Search){
			case STRING:
				free(filters[i].domain.string);
				free(filters[i].path.string);
				break;

			case REGEX:
				free(filters[i].domain.regex);
				free(filters[i].path.regex);
				break;
			}
			break;
		}

	}
}

void parse() {
	// GENERIC VARIABLES
	char *fields[num_fields];	//the number of fields we expect in a single line
	int num_filters;

	int i;
	int j;

	char line[65534];
	char *ipaddr;
	char *url;
	char *valid_url_start = "http";

	// URL_FILTER INITIALIZATION
	int num_filters_arr[3] = {};
	num_filters_arr[0] = determine_num_obs(url_input,comma_delimiter[0]);
	num_filters_arr[1] = determine_num_obs(domain_input,comma_delimiter[0]);
	num_filters_arr[2] = determine_num_obs(ipaddress_input, comma_delimiter[0]);
	num_filters = determine_max_array(num_filters_arr, 3);
	Filter filters[num_filters];

	if (verbose_flag){
		fprintf(stderr, "num_path_filters:%d\tnum_domain_filters:%d\tcountries_count:%d\t ip_address_count:%d\n", num_filters_arr[0], num_filters_arr[1], countries_count, num_filters_arr[2]);
	}

	if (Screen == URL_FILTER){
		init_paths(filters);
		init_domains(filters);
	}

	// GEO_FILTER INITIALIZATION
	GeoIP *gi;
	countries_count= determine_num_obs(country_input, comma_delimiter[0]);
	char* countries[countries_count];
	const char *country_code;

	if (Screen == GEO_FILTER || Recode == GEO) {
		init_countries(countries);
		/*
		 *  Before changing the type of cache, have a look at this benchmark:
		 *  http://www.maxmind.com/app/benchmark
		 *  and choose wisely.
		 */
		gi = GeoIP_open(db_path, GEOIP_MEMORY_CACHE);
		if (gi == NULL) {
			fprintf(stderr, "Error opening MaxMind Geo database.\n");
			fprintf(stderr, "Path used:%s\n", db_path);
			exit(1);
		}
	}

	// IP_FILTER INITIALIZATION
	if (Screen == IP_FILTER){
			init_ip_addresses(filters);
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
			//line contained fewer than 14 fields, ignore this field.
			continue;
		}

		ipaddr = fields[4];
		url = fields[8];

		if (url != NULL) {
			switch(Screen){
			case NO_FILTER:
				found=1;
				break;

			case IP_FILTER: case URL_IP_FILTER:
				found = match_ip_address(ipaddr, filters, num_filters);
				break;

			case URL_FILTER:
				//make sure we are dealing with a url that starts with http
				if (strncmp(url, valid_url_start, 4) == 0) {
					found = match_url(url, filters);
				}
				break;

			case GEO_FILTER : case URL_GEO_FILTER: case IP_GEO_FILTER: case IP_GEO_URL_FILTER:
				country_code = geo_lookup(gi, ipaddr);
				found = geo_check(country_code, countries);
				if (verbose_flag){
					fprintf(stderr, "Geocode result: %s\n", country_code);
				}
				break;
			}
		}

		if (found > 0){
			switch(Recode) {
				case NO:
					break;

				case ANONYMIZE:
					//Apply the anonymization
					replace_ip_addr(fields, NULL);
					break;

				case GEO:
					// Apply the geocoding
					if (country_code == NULL){
						country_code = geo_lookup(gi, ipaddr);
					}
					replace_ip_addr(fields, country_code);
					break;
			}

			// print output to stdout
			for (i=0;i<num_fields;++i){
				if (i!=0){
					fputs(ws_delimiter, stdout);
				}
				fputs(fields[i], stdout);
			}

		}

		if (verbose_flag) {
			fprintf(stderr, "ipaddr: '%s', url: '%s'\n", ipaddr, url);
		}

	}
	free_memory(filters, num_filters);
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
	printf("-a or --anonymize:    flag to indicate anonymize the log, by default turned off.\n");
	printf("-i or --ip:           flag to indicate ip-filter the log, by default turned off. You can supply comma separated ip adresses, or comma-separated ip-ranges.\n");
	printf("\n");
	printf("-m or --maxmind:     specify alternative path to MaxMind database.\n");
	printf("Current path to database: %s\n", db_path);
	printf("\n");
	printf("-c or --country_list: limit the log to particular countries, this should be a comma separated list of country codes. Valid country codes are the ISO 3166 country codes (see http://www.maxmind.com/app/iso3166). \n");
	printf("-r or --regex:        the parameters -p and -u are interpreted as regular expressions. Regular expression searching is probably slower so substring matching is recommended.\n");
	printf("-f or --force:        do not match on either domain, path, or ip address, basically turn filtering off. Can be useful when filtering for specific country.");
	printf("\n");
	printf("-v or --verbose:      output detailed debug information to stderr, not recommended in production.\n");
	printf("-h or --help:         show this menu with all command line options.\n");
}

int main(int argc, char **argv){
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
			{0, 0, 0, 0}
	};

	int c;

	while((c = getopt_long(argc, argv, "ac:d:m:fghi:rp:v", long_options, NULL)) != -1) {
		// c,d,m,i,p have mandatory arguments
		switch(c)
		{
		case 'a':
			Recode = ANONYMIZE;
			/* Indicate whether we should anonymize the log, default is false */
			break;

		case 'c':
			country_input = optarg;
			Screen +=GEO_FILTER;
			/* Optional list of countries to restrict logging */
			break;

		case 'd':
			Screen += URL_FILTER;
			domain_input = optarg;
			required_args++;
			/* -d is set. This specifies the project: en.wikipedia, commons.
			 * it should be a part of the domain name
			 */
			break;

		case 'm':
			db_path = optarg;
			/* Optional alternative path to database. */
			break;

		case 'f':
			Screen = NO_FILTER;
			break;

		case 'g':
			Recode = GEO;
			/* Indicate whether we should do geocode, default is false */
			break;

		case 'h':
			usage();
			break;

		case 'i':
			Screen += IP_FILTER;
			ipaddress_input = optarg;
			required_args++;
			break;

		case 'r':
			/* indicate whether we should treat the search string as a regular
			 * expression or not, default is false
			 */
			Search=REGEX;
			break;

		case 'p':
			/* -p is set. Store the url that needs to be matched. */
			Screen = URL_FILTER;
			url_input = optarg;
			required_args++;
			break;

		case 'v':
			/* Turn verbose on */
			verbose_flag = 1;
			break;

		default:
			exit(-1);
		}
	}
	if (required_args>=1 || Screen==NO_FILTER){
		parse();
	} else{
		usage();
	}
	return 0;
}

