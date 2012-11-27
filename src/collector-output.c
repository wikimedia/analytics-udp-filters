#include "collector-output.h"

/**
  * internal_traffic_explode_url breaks the url down into hostname parts (splits on dot)
  * and extracts the title of an article (the string after /wiki/)
  *
  * This is used in conjunction with match_internal_traffic_rules
  *
  */


void internal_traffic_explode_url(char *url,url_s *u) {
  u->has_dir       = false;
  u->has_title     = false;
  u->n_host_parts  = 0;

  if(       strncmp(url,"http://" ,7) == 0) {
    url+=7;
  } else if(strncmp(url,"https://",8) == 0) {
    url+=8;
  } else {
    return;
  };


  char *hostname_iter = url;
  size_t len_part;
  size_t len_until_params = strcspn(hostname_iter,"?#");
  *(url+len_until_params) = '\0'; // ignore any params in the url


  bool end_url      = false;
  bool found_dir    = false;

  /* this part will split the domain name into fragments into u.hostname_parts */
  while(!found_dir && !end_url && (len_part = strcspn(hostname_iter,"./"))) {
    /* do different things depending on separator that was found */
    switch(*(hostname_iter+len_part)) {
      case '/':
        // copy last domain name part where it belongs
        strncpy(u->host_parts[u->n_host_parts++],hostname_iter,len_part);
        u->host_parts[u->n_host_parts][len_part+1] = '\0';//strncpy does not do string endings
        hostname_iter += len_part;
        found_dir = true;
      case 0  :
        end_url   = true;
        break;
      default:
        strncpy(u->host_parts[u->n_host_parts++],hostname_iter,len_part);
        u->host_parts[u->n_host_parts][len_part+1] = '\0';//strncpy does not do string endings
        hostname_iter += len_part+1; // jump over separator
    };
  };

  /* if a '/' is found that means a directory follows, also check if there are any trailing characters after it */
  if(found_dir && *(hostname_iter+1)) {
    u->has_dir = true;
    strcpy(u->dir,hostname_iter);
    if(strncmp(u->dir,"/wiki/",6)==0) {
      u->has_title = true;

      strcpy(u->title,u->dir+6);
    };
  };

  return;
}




bool internal_traffic_ip_check(char *ip) {
  char *internal_traffic_dupes[] = {
    "208.80.152.",
    "208.80.153.",
    "208.80.154.",
    "208.80.155.",
    "91.198.174.",
    NULL
  };
  char **prefix=internal_traffic_dupes;
  for (;*prefix;prefix++) {
    if(!strncmp(*prefix,ip,strlen(*prefix))) {
      return false;
    };
  }
  return true;
}


/**
  * sets suffix for the project
  * also has branches for each project and specific code which decides
  * depending on other attributes of struct info if the project will
  * be filtered out or not
  *
  *
  */

bool internal_traffic_fill_suffix_language(info *i) {
  char *wikimedia_whitelist[] = {
    "commons",
    "meta",
    "incubator",
    "species",
    "strategy",
    "outreach",
    "planet",
    "blog",
    NULL
  };

  /* safety check, do we have a project in there or is it
   * empty ? 
   */
  if(!i->project) {
    strcpy(i->project,"N/A");
    strcpy(i->suffix ,"N/A");
    return false;
  };

  if(        !strcmp(i->project,"wikipedia")) {
    i->suffix = "";
  } else if( !strcmp(i->project,"wikimedia")) {
    i->suffix = ".m";
    char **p=wikimedia_whitelist;
    for(;*p;p++) {
      if(!strcmp(*p,i->language)) {
        return true;
      };
    };
    return false;
  } else if( !strcmp(i->project,"wikidata")) {
    i->suffix = ".wd";
  } else if( !strcmp(i->project,"wikivoyage")) {
    i->suffix = ".wo";
  } else if( !strcmp(i->project,"wiktionary")) {
    i->suffix = ".d";
  } else if( !strcmp(i->project,"wikinews")) {
    i->suffix = ".n";
  } else if( !strcmp(i->project,"wikibooks")) {
    i->suffix = ".b";
  } else if( !strcmp(i->project,"wikisource")) {
    i->suffix = ".s";
  } else if( !strcmp(i->project,"mediawiki")) {
    i->suffix = ".w";
  } else if( !strcmp(i->project,"wikiversity")) {
    i->suffix = ".v";
  } else if( !strcmp(i->project,"wikiquote")) {
    i->suffix = ".q";
  } else if( !strcmp(i->project,"m.wikipedia")) {
    i->suffix = ".mw";
  } else if( !strcmp(i->project,"wikimediafoundation")) {
    i->suffix = ".f";
  } else {
  };
  return true;
}



/**
  *
  * match_internal_traffic_rules does the following:
  *
  * 1) breaks down the url into relevant data using internal_traffic_explode_url
  * 2) filters based on specific wikimedia sites:
  *             *.planet.wikimedia.org
  *             blog.wikimedia.org
  *             wikimediafoundation.org
  * 
  *    it also sets specific attributes for these, like title, depending on which of these
  *    websites appear in the url
  * 3) returns true/false depending on whether the line will be discarded or not
  * 4) adds data in info* in , this will later be used to print the output in internal_traffic_print_for_collector
  *    if the switch( -o ) for collector output is present on the commandline
  * 
  *
  * Params: url, ip   are used as input
  * Params: u  , in   are used as output
  *
  */



int match_internal_traffic_rules(char *url,char *ip,url_s *u,info *in) {
  int retval = 0;

  if (!url) {
    retval |= RETVAL_MATCH_INTERNAL_NO_URL;
    return retval;
  };


  if(!internal_traffic_ip_check(ip)) {
    retval |= RETVAL_MATCH_INTERNAL_IP_REJECTED;
  };

  internal_traffic_explode_url(url,u);

  /** this branch is for urls with /wiki/ inside them 
    * that means that the url is a url to a mediawiki website
    */
  if(u->has_title) {
    in->title = u->title;

    in->project  = u->host_parts[u->n_host_parts-2];
    in->language = u->host_parts[0];

    if(strcmp(u->host_parts[0],"m") ==0) {
      in->project = "m.wikipedia";
      retval |= RETVAL_MATCH_INTERNAL_VALID;
    } else if(strcmp(in->language,"wikimediafoundation")==0) {
      // special case, this is not a mediawiki
      in->project  = in->language;
      in->language =  "blog";
      retval |= RETVAL_MATCH_INTERNAL_VALID;
    } else if (strcmp(in->project,"wikivoyage")==0) {
      retval |= RETVAL_MATCH_INTERNAL_VALID;
    } else {

      if(strlen(in->project) == 0) {
        retval |= RETVAL_MATCH_INTERNAL_PROJECT_EMPTY_REJECTED;
      };
      
      if( strlen(in->language) == 0) {
        retval |= RETVAL_MATCH_INTERNAL_LANGUAGE_EMPTY_REJECTED;
      };

    };

  } else {
    /* this branch is for special cases */
    in->project  = u->host_parts[u->n_host_parts-2];
    in->language = u->host_parts[0];


    if(
      // for *.planet.wikimedia.org
      strcmp(u->host_parts[1],"planet"   )==0 &&
      strcmp(u->host_parts[2],"wikimedia")==0
    ) {
      in->language = u->host_parts[1];
      strcpy(u->title,"main");
      in->title = u->title;
      retval |= RETVAL_MATCH_INTERNAL_VALID;
      // for blog.wikimedia.org
    } else if(strcmp(u->host_parts[1],"wikimedia")==0 && strcmp(u->host_parts[0],"blog")==0 ) {
      strcpy(u->title,"main");
      //getting title of blog post
      int len_dir = strlen(u->dir);
      if(u->dir[len_dir-1] == '/') {
        u->dir[len_dir-1] = '\0';
        len_dir--;
      };
      char *title=u->dir + len_dir;
      while(*--title != '/');
      in->title = title+1;
      retval |= RETVAL_MATCH_INTERNAL_VALID;
      //for wikimediafoundation.org
    } else if(strcmp(in->project,"wikimediafoundation")==0) {
      strcpy(u->title,"main");
      in->title = u->title;
      retval |= RETVAL_MATCH_INTERNAL_VALID;
    };

    retval |= RETVAL_MATCH_INTERNAL_SPECIAL_UNRECOGNIZED;
  };

  return retval;
}

bool internal_traffic_detect_bot(const char *user_agent) {
        
	char *crawlers[5];
	crawlers[0] = "bot";
	crawlers[1] = "spider";
	crawlers[2] = "crawler";
	crawlers[3] = "http";
	crawlers[4] = NULL;
	/*
	 * If user agent contains either 'bot', 'spider', 'crawler' or 'http'
	 * then we classify this request as a bot request, else it is a regular
	 * request.
	 */
	if(user_agent){
		int i=0;
		char *result;
		for (;;){
			if (crawlers[i]) {
				result = strstr(user_agent, (char *)crawlers[i]);
				if (result){
					return true;
				}
			} else {
				break;
			}
			i++;
		}
	}
	return false;
}

void internal_traffic_print_for_collector(info *i,char *ua, int _bot_flag) {
  if (_bot_flag && internal_traffic_detect_bot(ua)) {
    printf("1 %s%s_bot 1 %s %s\n",i->language, i->suffix, i->size, i->title);
  } else {
    printf("1 %s%s 1 %s %s\n",i->language, i->suffix, i->size, i->title);
  };
}
