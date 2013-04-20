#include <stdio.h>
#include "utils.h"

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


void replace_space_with_underscore(char *string, int len){
        int i;
        for (i=0;i<len; i++){
                if(string[i]== ' ') {
                        string[i] = '_';
                }
        }
}



int determine_num_obs(char *raw_input, const char delimiter) {
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

