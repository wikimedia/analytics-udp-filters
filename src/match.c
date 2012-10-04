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
#include "match.h"

/*
 * Delimiters
 *
 */


const char comma_delimiter = ',';
const char ws_delimiter[]  = " ";
const char fs_delimiter    = '/';
const char us_delimiter    = '-';

SearchType  search  = STRING;
RecodeType  recode  = NO;
IpMatchType ipmatch = SIMPLE;

/*
 * Specific types of filtering
 *
 */


/**
 * Returns true if ip_address belongs to an IP address range in filters.
 *
 * char   *ip_address  - IP address string, either IPv4 or IPv6.
 * Filter *filters     - Array of filters on which to match.
 * int     num_filters - number of filters in filters array.
 * returns int 1 if ip_address is at least one of the provided IP filters, 0 if not.
 */
int match_ip_address(char *ip_address, Filter *filters, int num_filters,int _verbose_flag){
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

		if (_verbose_flag == 1) {
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

int match_path(char *url, Filter *filters, int num_path_filters,int _verbose_flag){
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
					if (_verbose_flag){
						fprintf(stderr, "%s<-->%s\t%d\n", path, filters[i].path.string, path_found);
					}
					break;

				case REGEX:
				{
					int result = regexec(filters[i].path.regex, path, 0, pmatch, 0);
					if (result ==0) {
						path_found = 1;
					}
					if (_verbose_flag){
						if (result>0) {
							char errbuf[MAX_ERROR_MSG];
							regerror(result, filters[i].path.regex, errbuf, MAX_ERROR_MSG);
							fprintf(stderr, "Encountered error while regex matching: %s\n", errbuf);
						} else {
							fprintf(stderr, "%s<-->%p\t%d\n", path, (void *)&filters[i].path.regex, path_found);
						}
					}
					if (_verbose_flag){
						if (result>0) {
							char errbuf[MAX_ERROR_MSG];
							regerror(result, filters[i].path.regex, errbuf, MAX_ERROR_MSG);
							fprintf(stderr, "Encountered error while regex matching: %s\n", errbuf);
						} else {
							fprintf(stderr, "%s<-->%p\t%d\n", path, (void *)&filters[i].path.regex, path_found);
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

int match_domain(char *url, Filter *filters, int num_domain_filters,int _verbose_flag){
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
							if (_verbose_flag){
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

int match_http_status(char *http_status_field, Filter *filters, int num_http_status_filters,int _verbose_flag){
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
							if (_verbose_flag){
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


