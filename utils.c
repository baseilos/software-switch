/**
 * Copyright (C) 2011, Jozef Lang
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *
 * File:     utils.c
 * Revision: $Rev: 4 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-03-05 17:19:28 +0100 (Sat, 05 Mar 2011) $
 *
 * Various useful utility functions
 */

#include "utils.h"

#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>


void flushStream(FILE * stream) {
	if (stream == NULL)
		return;

	char c;
	while ((c = getc(stream)) != EOF && c != '\n')
		;
}

int readCommand(char * command, unsigned int length) {	

	// Read command from stdin
	if (command == NULL || fgets(command, sizeof(char) * length, stdin) == NULL)
		return 0;

	// Trim trailing '\n'
	int i = 0;
	while (i < length && command[i] != '\n')
		i++;
	if (i < length)
		command[i] = '\0';

	return i;
}

void formatMACAddress(u_char * address,  char * output) {

	if (address == NULL || output == NULL) {
		return;
	}

	sprintf(output, "%.2x%.2x.%.2x%.2x.%.2x%.2x", 
		(u_int) address[0], 
	        (u_int) address[1],
	        (u_int) address[2],
	        (u_int) address[3],
	        (u_int) address[4],
	        (u_int) address[5]
	);

}

int isBroadcast(u_char * address) {

	char frmt[20];

	if (address == NULL)
		return 0;

	formatMACAddress(address, frmt);
	if (strcmp(frmt, "ff.ff.ff.ff.ff.ff") == 0)
		return 1;
	
	return 0;
}

