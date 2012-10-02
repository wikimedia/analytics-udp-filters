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

#ifndef __GEO_H
#define __GEO_H
#include <GeoIP.h>
#include <GeoIPCity.h>


char *geo_lookup(GeoIP *gi, char *ipaddr, int bird);
int geo_check(const char *country_code, char *countries[], int countries_count, int _verbose_flag);

#endif
