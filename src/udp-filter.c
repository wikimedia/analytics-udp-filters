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
#include <GeoIP.h>
#include <GeoIPCity.h>
#include "countries.c"
#include "radix-tree.c"

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

typedef struct{
	char *domain_str;
	regex_t *domain_re;
	char *path_str;
	regex_t *path_re;
	char *ip;
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
int filter_count =0;
int domain_count =0;
int ipaddress_count=0;

char *country_input;
char *url_input;
char *domain_input;
char *ipaddress_input;
char *db_path = "/var/log/squid/filters/GeoIPLibs/GeoIP.dat";


int regex_flag = 0;

/*
 * this flag indicates whether we do regex matching
 * or substring matching (substring matching is the default.
 */
int no_filter_flag =0;      // this flag indicates that we are not filtering at *all* everything gets matched. Use carefully!
int verbose_flag = 0;       // this flag indicates whether we should output detailed debug messages.
int limit_country_flag = 0;	// this flag indicates whether we should restrict the log to certain countries.
int geocode_flag =0;		// this flag indicates whether the ip address should be geocoded.
int anonymize_flag =0;      // this flag indicates whether the ip address should be anonymized.
int ip_address_flag = 0;
/*
 * this flag indicates whether to anonymize the ip address,
 * current ip adddress should be replaced with 0.0.0.0
 */


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

int determine_num_obs(char *raw_input) {
	/*
	 * Determine the number of comma-separated filter parameters are entered
	 * on the command line. This function is applied to both the path_input and
	 * domain_input parameters.
	 */
	int size=0;
	int j=0;
	if (raw_input!=NULL){
		while(raw_input[j] !='\0') {
			if (raw_input[j] == comma_delimiter[0]) {
				size++;
			}
			j++;
		}
		size++;// the number of obs. is the number of comma_delimiters plus 1
	}
	return size;
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

char** init_countries() {
	/*
	 * This function initializes an array of pointers that will contain the
	 * country codes that we need to filtered (i.e. included in the log file)
	 * We also validate whether the entered country code is a valid country
	 * code according to the ISO 3166-1 standard.
	 */
	countries_count= determine_num_obs(country_input);
	char **countries = malloc(sizeof(char *) *countries_count);
	if (limit_country_flag==1) {
		// fill the array with country_codes
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
	return countries;
}

void init_ip_addresses(struct radix_tree_root *tree){
	ipaddress_count = determine_num_obs(ipaddress_input);
	int result;
	if (ip_address_flag==1){
		char *ip_token = strdup(strtok(ipaddress_input, comma_delimiter));
		int i=0;
		while (ip_token!=NULL) {
			result = radix_tree_insert(tree, i, ip_token);
			if (result!=0){
				fprintf(stderr, "Could not create radix-tree.\n");
				exit(EXIT_FAILURE);
			}
		}
	}
}

void init_urls(Filter *filters) {
	/* url_input is a string *excluding* the full qualified domain name
	 * url_input can be comma delimited, so we first need to determine the
	 * different parts and then depending on whether the regex_flag is activated
	 * we need to compile the string or else we just store it right away.
	 */
	char *url_token;
	int i=0;
	int error=0;

	filter_count = determine_num_obs(url_input);
	url_token = strtok(url_input,comma_delimiter);
	while (url_token != NULL) {
		if (regex_flag == 0){
			filters[i].path_str =malloc(sizeof(url_token));
			if (filters[i].path_str) {
				error=1;
				break;
			}
			filters[i].path_str = url_token;
		} else {
			filters[i].path_re =malloc(sizeof(regex_t));
			if (filters[i].path_re==NULL) {
				error=1;
				break;
			}
			filters[i].path_re = init_regex(url_token);
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

	domain_count = determine_num_obs(domain_input);
	domain_token = strtok(domain_input, comma_delimiter);

	while (domain_token !=NULL){
		if (regex_flag == 0){
			filters[i].domain_str= malloc(sizeof(domain_token));
			if(filters[i].domain_str==NULL) {
				error=1;
				break;
			}
			filters[i].domain_str  = domain_token;
		}else {
			filters[i].domain_re= malloc(sizeof(regex_t));
			if (filters[i].domain_re==NULL){
				error=1;
				break;
			}
			filters[i].domain_re = init_regex(domain_token);
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

int match_ip_address(char *ip, char *ip_filters[]){
	int result=0;
	while (ip!=NULL){

		ip++;
	}

	return result;
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
	if (no_filter_flag ==1){
		return 1;
	}

	int found_domain = 0;
	char* domain;
	int j;
	regmatch_t pmatch[1]; // regex specific variable

	if (domain_count > 0){
		/* this for-loop checks if the url contains the domain string
		 * if it does return 1 if there is no additional filtering, or
		 * else break to next loop.
		 */
		domain =extract_domain(url);
		if (domain !=NULL){
			for (j=0; j<domain_count; ++j){
				if (regex_flag == 0){
					if (strstr(domain, filters[j].path_str) != NULL) {
						found_domain = 1;
					}
				} else {
					printf("%s\t%p\n", domain, filters[j].domain_re);
					if (regexec(filters[j].domain_re, domain, 0, pmatch, 0) == 0) {
						found_domain = 1;
					}
				}
				if (found_domain != 0){
					if (filter_count ==0) {
						// No filters have been defined just domain matching.
						return 1;
					} else {
						break;
					}
				}
			}
		}
	}

	if (filter_count > 0) {
		/*
		 * this for loop checks if the url contains the path from the command
		 * line.If it finds a match then return 1 else return 0.
		 */
		int i;
		int path_found = 0;
		char* path = strtok(url, ws_delimiter);

		if (path!=NULL){
			for (i = 0; i < filter_count; ++i) {
				if (regex_flag ==0) {
					if (strstr(path, filters[i].path_str)!=NULL){
						path_found =1;
					}
				} else {
					if (regexec(filters[i].path_re, path, 0, pmatch, 0) == 0) {
						path_found =1;
					}
				}

				if (verbose_flag){
					if (regex_flag ==0){
						fprintf(stderr, "%s<-->%s\t%d\n", path, filters[i].path_str, path_found);
					} else {
						fprintf(stderr, "%s<-->%p\t%d\n", path, &filters[i].path_re, path_found);
					}
				}
				return path_found;
			}
		}
		return 0;
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
	if (geocode_flag){
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
	} else if (anonymize_flag) {
		fields[4] = anonymous_ip;
	}
}

void parse() {
	int country_check;
	int num_filters;
	int num_paths = determine_num_obs(url_input);
	int num_domains = determine_num_obs(domain_input);

	int i;
	int j;

	char line[65534];
	char *ipaddr;
	char *url;
	char *valid_url_start = "http";


	//RADIX_TREE_INIT();
	struct radix_tree_root tree = RADIX_TREE_INIT();
	//INIT_RADIX_TREE(tree);
	init_ip_addresses(&tree);


	GeoIP *gi;

	char *fields[num_fields];
	char** countries = init_countries();


	if (num_paths>num_domains){
		num_filters= num_paths;
	} else if (num_paths < num_domains){
		num_filters= num_domains;
	} else {
		num_filters = num_domains;
	}


	Filter filters[num_filters];
	init_urls(filters);
	init_domains(filters);

	if (verbose_flag){
		fprintf(stderr, "filter_count:%d\tdomain_count:%d\tcountries_count:%d\n", filter_count, domain_count, countries_count);
	}

	if (geocode_flag){
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
			//make sure we are dealing with a url that starts with http
			if (strncmp(url, valid_url_start, 4) == 0) {
				found = match_url(url, filters);
			}
		}

		if (found > 0){
			if (geocode_flag==1 || limit_country_flag ==1) {
				if (ipaddr !=NULL) {
					const char *country_code = geo_lookup(gi, ipaddr);
					if (verbose_flag){
						fprintf(stderr, "Geocode result: %s\n", country_code);
					}

					if (limit_country_flag==1) {
						// check if the country associated with the ip address
						// is in the whitelist set of countries
						country_check = geo_check(country_code, countries);
						if (country_check == 0){
							continue;
						}
					}
					if (geocode_flag ==1 ){
						// Apply the geocoding
						replace_ip_addr(fields, country_code);
					}
				}
			}
			else if (anonymize_flag==1){
				// Apply the anonymization
				replace_ip_addr(fields, NULL);
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
	//free(domains);
	free(countries);
	//free(urls);
}


void usage() {
	printf("Wikimedia's generic UDP filtering system.\n");
	printf("Version 0.2 // Written by Diederik van Liere.\n");
	printf("\n");
	printf("Either --url or --project are mandatory (you can use them both, the other command line parameters are optional:\n");
	printf("-u or --url:          the string or multiple strings separated by a comma that indicate what you want to match.\n");
	printf("-p or --project:      the part of the domain name that you want to match. For example, 'en.m.' would match all English mobile Wikimedia projects.\n");
	printf("\n");
	printf("-g or --geocode:      flag to indicate geocode the log, by default turned off.\n");
	printf("-a or --anonymize:    flag to indicate anonymize the log, by default turned off\n");
	printf("-i or --ip:           flag to indicate anonymize the log, by default turned off\n");
	printf("\n");
	printf("-d or --database:     specify alternative path to MaxMind database.\n");
	printf("Current path to database: %s\n", db_path);
	printf("\n");
	printf("-c or --country_list: limit the log to particular countries, this should be a comma separated list of country codes. Valid country codes are the ISO 3166 country codes (see http://www.maxmind.com/app/iso3166). \n");
	printf("-r or --regex:        the parameters -p and -u are interpreted as regular expressions. Regular expression searching is probably slower so substring matching is recommended.\n");
	printf("-f or --force:        do not match on either domain or url part, basically turn filtering off. Can be useful when filtering for specific country.");
	printf("\n");
	printf("-v or --verbose:      output detailed debug information to stderr, not recommended in production.\n");
	printf("-h or --help:         show this menu with all command line options.\n");
}

int main(int argc, char **argv){
	static struct option long_options[] = {
			{"url", required_argument, NULL, 'u'},
			{"project", required_argument, NULL, 'p'},
			{"geocode", no_argument, NULL, 'g'},
			{"anonymize", no_argument, NULL, 'a'},
			{"database", required_argument, NULL, 'd'},
			{"country_list", required_argument, NULL, 'c'},
			{"regex", no_argument, NULL, 'r'},
			{"verbose", no_argument, NULL, 'v'},
			{"help", no_argument, NULL, 'h'},
			{"force", no_argument, NULL, 'f'},
			{"ip", required_argument, NULL, 'i'},
			{0, 0, 0, 0}
	};

	int c;

	while((c = getopt_long(argc, argv, "u:p:gad:c:vhrfi:", long_options, NULL)) != -1) {
		// we accept -u, -p, -d and -c have mandatory arguments
		switch(c)
		{
		case 'a':
			anonymize_flag = 1;
			/* Indicate whether we should anonymize the log, default is false */
			break;

		case 'c':
			country_input = optarg;
			limit_country_flag = 1;
			/* Optional list of countries to restrict logging */
			break;

		case 'd':
			db_path = optarg;
			/* Optional alternative path to database. */
			break;

		case 'f':
			no_filter_flag =1;
			break;

		case 'g':
			geocode_flag = 1;
			/* Indicate whether we should do geocode, default is false */
			break;

		case 'h':
			usage();
			break;

		case 'i':
			ip_address_flag = 1;
			ipaddress_input = optarg;
			break;

		case 'p':
			domain_input = optarg;
			required_args++;
			/* -p is set. This specifies the project: en.wikipedia, commons.
			 * it should be a part of the domain name
			 */
			break;

		case 'r':
			regex_flag =1;
			/* indicate whether we should treat the search string as a regular expression or not, default is false */
			break;

		case 'u':
			url_input = optarg;
			required_args++;
			/* -u is set. Store the url that needs to be matched. */
			break;

		case 'v':
			verbose_flag = 1;
			/* Turn verbose on */
			break;

		default:
			exit(-1);
		}
	}
	if (required_args>=1 || no_filter_flag==1){
		parse();
	} else{
		usage();
	}
	return 0;
}

