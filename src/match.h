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

#ifndef __MATCH_H
#define __MATCH_H
#include "udp-filter.h"
#include <stdlib.h>
#include <stdio.h>
#include <libcidr.h>
#include <string.h>

int match_ip_address(char *ip_address, Filter *filters, int num_filters,int _verbose_flag);
int match_path(char *url, Filter *filters, int num_path_filters,int _verbose_flag);
int match_domain(char *url, Filter *filters, int num_domain_filters,int _verbose_flag);
int match_http_status(char *http_status_field, Filter *filters, int num_http_status_filters,int _verbose_flag);

extern const char comma_delimiter;
extern const char fs_delimiter   ;
extern const char us_delimiter   ;
extern char *ws_delimiter        ;

extern SearchType  search ;
extern RecodeType  recode ;
extern IpMatchType ipmatch;
#define MAX_ERROR_MSG 0x1000


#endif
