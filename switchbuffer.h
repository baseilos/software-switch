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
 * File:     switchbuffer.h
 * Revision: $Rev: 18 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-30 18:10:08 +0200 (Sat, 30 Apr 2011) $
 *
 * Buffers implementation
 */

#ifndef _SWITCHBUFFER_
#define _SWITCHBUFFER_

#include "switchcore.h"

#include <pcap.h>
#include <pthread.h>

#define SWITCH_BUFFER_MAX_SIZE 100
#define SWITCH_BUFFER_PACKET_DATA_SIZE BUFSIZ // Same as pcap_next buffer

struct switch_buffer_item {
	struct switch_if * receiverIf;
	unsigned int size;
	u_char * packetData;
};

struct switch_buffer {
	struct switch_buffer_item * items;
	unsigned int size;
	unsigned int start;
	unsigned int end;
	pthread_mutex_t mutex;
};

void initSwitchBuffer(struct switch_buffer ** buffer, unsigned int size); 
void freeSwitchBuffer(struct switch_buffer ** buffer);
int switchBufferQueue(struct switch_buffer * buffer, struct switch_if * receiverIf, const u_char * packetData, const int packetLength);
const struct switch_buffer_item * switchBufferDequeue(struct switch_buffer * buffer);

#endif

