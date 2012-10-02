#ifndef __INTERNAL_TRAFFIC_H
#define __INTERNAL_TRAFFIC_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>


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
bool match_internal_traffic_rules(char *url,char *ip,url_s *u,info *in);
bool internal_traffic_detect_bot(const char *user_agent);
void internal_traffic_print_for_collector(info *i,char *ua,int _bot_flag);

#endif
