#ifndef __COLLECTOR_OUTPUT_H
#define __COLLECTOR_OUTPUT_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


enum {
  // passed checks for internal traffic rules switch
  RETVAL_MATCH_INTERNAL_VALID                   = 1,

  // no url present
  RETVAL_MATCH_INTERNAL_NO_URL                  = 2,

  // Ip was in a range not allowed
  RETVAL_MATCH_INTERNAL_IP_REJECTED             = 4,

  // title field present but project field empty
  RETVAL_MATCH_INTERNAL_PROJECT_EMPTY_REJECTED  = 8,

  // title field present but language field empty
  RETVAL_MATCH_INTERNAL_LANGUAGE_EMPTY_REJECTED = 16,

  // project does not have a title and it was not of
  // exceptions:
  //   
  //   * planet.wikimedia
  //   * wikimediafoundation
  //   * blog.wikimedia
  //    
  RETVAL_MATCH_INTERNAL_SPECIAL_UNRECOGNIZED    = 32
};
/*
 * Collector output specific data structure
 */
typedef struct {
		char *ip;
		char *size;
		char *language;
		char *project;
		char *title;
		char *suffix;
} info;

/*
 * Internal traffic rules specific data structure
 * Url broken down to match internal traffic rules
 *
 */

typedef struct {
  bool has_dir;
  bool has_title;
  char dir[2000];
  char title[7000];
  char host_parts[30][200];
  int  n_host_parts;
} url_s ;

void internal_traffic_explode_url(char *url,url_s *u);
bool internal_traffic_ip_check(char *ip);
bool internal_traffic_fill_suffix_language(info *i);
int match_internal_traffic_rules(char *url,char *ip,url_s *u,info *in);
bool internal_traffic_detect_bot(const char *user_agent);
void internal_traffic_print_for_collector(info *i,char *ua,int _bot_flag);

#endif
