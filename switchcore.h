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
 * File:     switchcore.h
 * Revision: $Rev: 13 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-30 02:42:02 +0200 (Sat, 30 Apr 2011) $
 *
 * Core switch functions and constants. 
 */

#ifndef _SWITCHCORE_
#define _SWITCHCORE_

#include "switchbuffer.h"
#include "mactable.h"

#include <pcap.h>
#include <pthread.h>
#include <net/ethernet.h>

#define SWITCH_COMMAND_MAX_LENGTH 10
#define SWITCH_MACTABLE_TIMEOUT 180

#define SWITCH_PROMPT "switch> "

struct switch_if_stats { // Switch interface stats
	long receivedFrames;
	long receivedBytes;
	long sentFrames;
	long sentBytes;
	long droppedFrames;
	long droppedBytes;
	pthread_mutex_t mutex;
};

struct switch_if { // Switch interface
	unsigned int opened:1;
	char * name;
	pcap_t * handler;
	u_char macAddress[ETHER_ADDR_LEN];
	pthread_t listening_thread;
	pthread_t sending_thread;
	struct switch_if_stats stats;
	struct switch_buffer * receiveBuffer;
	struct switch_buffer * sendBuffer;
	pthread_mutex_t mutex;
	struct switch_if * next;
};

struct switch_dev { // Switch device
	unsigned int started:1;
	unsigned int if_count;
	struct switch_if * ifs;
	pthread_mutex_t mutex;
	pthread_t swtch_thread;
	pthread_t swtch_mactable_maintain_thread;
	struct switch_mactable * mac_table;
};

int fireSwitchCommand(struct switch_dev * device, char * command);

#endif

