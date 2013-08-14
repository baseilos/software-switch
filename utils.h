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
 * File:     utils.h
 * Revision: $Rev: 4 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-03-05 17:19:28 +0100 (Sat, 05 Mar 2011) $
 *
 * Various useful utility functions
 */

#ifndef _UTILS_
#define _UTILS_

#include <stdio.h>
#include <string.h>
#include <pcap.h>

#ifdef _DEBUG_ 
	#define DEBUG_TEST 1
#else
	#define DEBUG_TEST 0
#endif

#define debug_print(fmt, ...) \
	do { if (DEBUG_TEST) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, __VA_ARGS__); } while(0)

#define error_print(fmt, ...) \
	do { fprintf(stderr, "ERROR: " fmt, __VA_ARGS__); } while(0)

#define user_print(fmt, ...) \
	do { fprintf(stdout, "" fmt, __VA_ARGS__); } while(0) 

#define error_message(buffer,msg) \
	strcpy(buffer, msg)

void flushStream(FILE * stream);
int readCommand(char * command, unsigned int length);
void formatMACAddress(u_char * address, char * output);
int isBroadcast(u_char * address);

#endif

