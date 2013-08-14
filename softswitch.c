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
 * File:     softswitch.c
 * Revision: $Rev: 14 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-30 17:32:58 +0200 (Sat, 30 Apr 2011) $
 *
 * Main application file. 
 */

#include "switchcore.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

int main(int argc, char * argv[]) {

	char command[SWITCH_COMMAND_MAX_LENGTH];
	int readCommandLength;
	struct switch_dev device;

	// Prepare device
	device.started &= 0;
	device.if_count &= 0;
	device.ifs = NULL;
	device.mac_table = NULL;
	device.swtch_thread = 0;
	pthread_mutex_init(&device.mutex, NULL);

	// Start switch automatically
	fireSwitchCommand(&device, "start");

	// Input reading loop
	while (1) {
		fprintf(stdout, SWITCH_PROMPT);
		readCommandLength = readCommand(command, SWITCH_COMMAND_MAX_LENGTH);
		if (readCommandLength > 0)
			if (fireSwitchCommand(&device,command) == 0) // 0 - Do not continue
				break;
		if (readCommandLength >= SWITCH_COMMAND_MAX_LENGTH)
			flushStream(stdin);
	}

	// Destroy mutex
	pthread_mutex_destroy(&device.mutex);

	return EXIT_SUCCESS;
}

