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


#include <stdlib.h>
#include <check.h>
#include "../src/udp-filter.h"
#include "../src/countries.h"

char *url_str = "http://www.wikipedia.org/wiki/Main_Page";
char *path_str = "Manual";
char *domain_str = "wiki";


START_TEST (test_string_matching){
	Filter filters[1];

	int result;
	int num_path_filters =1;
	int num_domain_filters =1;

	filters[1].path.string = path_str;
	filters[1].domain.string = domain_str;
	filters[1].searchtype = STRING;

	result = match_path(url_str, filters, num_path_filters);
	fail_unless(result==1);
	result = match_domain(url_str, filters, num_domain_filters);
	fail_unless(result==1);
}
END_TEST


START_TEST (test_regex_matching){
	Filter filters[1];

	int result;
	int num_path_filters =1;
	int num_domain_filters =1;
	regex_t *path_re = init_regex(path_str);
	regex_t *domain_re = init_regex(domain_str);

	fail_unless(path_re==NULL);
	fail_unless(domain_re==NULL);

	filters[1].path.regex =path_re;
	filters[1].domain.regex =domain_re;
	filters[1].searchtype = REGEX;

	result = match_path(url_str, filters, num_path_filters);
	fail_unless(result==1);
	result = match_domain(url_str, filters, num_domain_filters);
	fail_unless(result==1);
}
END_TEST

START_TEST (ip_address_filtering){
	char *ip_address = "127.0.0.1";
	int initialization = 0;
	long ip_value =  convert_ip_to_long(ip_address, initialization);
	fail_unless(ip_value == 2130706433);

}
END_TEST

Suite * udp_filter_suite(void) {
	Suite *s = suite_create("udp-filter test suite");
	/* Core test case */
	TCase *tc_core = tcase_create ("Core");
	tcase_add_test (tc_core, test_string_matching);
	tcase_add_test (tc_core, test_regex_matching);
	tcase_add_test (tc_core, ip_address_filtering);
	suite_add_tcase (s, tc_core);
	return s;
}

int main(void){
	int number_failed;
	Suite *s = udp_filter_suite();
	SRunner *sr = srunner_create (s);
	srunner_run_all (sr, CK_NORMAL);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
