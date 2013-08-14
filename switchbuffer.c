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
 * File:     switchbuffer.c
 * Revision: $Rev: 12 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-28 23:05:05 +0200 (Thu, 28 Apr 2011) $
 *
 * Buffers implementation
 */

#include "switchbuffer.h"
#include "utils.h"
#include "switchcore.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>

/**************************************************************/

void initSwitchBuffer(struct switch_buffer ** buffer, unsigned int size);
void freeSwitchBuffer(struct switch_buffer ** buffer);
int switchBufferQueue(struct switch_buffer * buffer, struct switch_if * receiverIf, const u_char * packetData, const int packetLength);
const struct switch_buffer_item * switchBufferDequeue(struct switch_buffer * buffer);

/**************************************************************/

void initSwitchBuffer(struct switch_buffer ** buffer, unsigned int size) {
	debug_print("%s\n", "START");
	
	// Firstly try to free buffer
	if (buffer != NULL && *buffer != NULL)
		debug_print("%s\n", "Buffer already initialized -> freeing");
		freeSwitchBuffer(buffer);

	// Limit buffer size
	if (size > SWITCH_BUFFER_MAX_SIZE)
		size = SWITCH_BUFFER_MAX_SIZE;

	// Alloc buffer memory
	(*buffer) = (struct switch_buffer *) malloc(sizeof(struct switch_buffer));
	if (*buffer == NULL) {
		debug_print("%s\n", "Error initializing buffer");
		return;
	}

	// Reset counters & pointers
	(*buffer)->size = size;
	(*buffer)->start = 0;
	(*buffer)->end = 0;

	// Init MUTEX
	pthread_mutex_init(&(*buffer)->mutex, NULL);

	// Alloc buffer items
	(*buffer)->items = (struct switch_buffer_item *) malloc(sizeof(struct switch_buffer_item) * (*buffer)->size);
	if ((*buffer)->items == NULL) {
		debug_print("%s\n", "Error initializing buffer items");
		// Free buffer
		free((void *) *buffer);
		*buffer = NULL;
		return;
	}

	// Alloc packet data
	for (int i = 0; i < (*buffer)->size; i++) {
	(*buffer)->items[i].packetData = (u_char *) malloc(sizeof(u_char) * SWITCH_BUFFER_PACKET_DATA_SIZE);
		 if ((*buffer)->items[i].packetData == NULL) {
			debug_print("%s\n", "Error initializing buffer packet data");
			freeSwitchBuffer(buffer);
			return;
		}
	 }

	debug_print("%s\n", "END");
}

void freeSwitchBuffer(struct switch_buffer ** buffer) {
	debug_print("%s\n","START");

	if (buffer == NULL || *buffer == NULL)
		return;

	pthread_mutex_destroy(&(*buffer)->mutex);
	for (int i = 0; i < (*buffer)->size; i++) {
		if ((*buffer)->items[i].packetData != NULL)
			free((void *) (*buffer)->items[i].packetData);
	}
	free((void *) (*buffer)->items);
	free((void *) *buffer);
	*buffer = NULL;

	debug_print("%s\n","END");
}


int switchBufferQueue(struct switch_buffer * buffer, struct switch_if * receiverIf,const u_char * packetData, const int packetLength) {	

	if (buffer == NULL) {
		debug_print("%s\n", "Cannot queue to unitialized buffer");
		return 0;
	}

	pthread_mutex_lock(&buffer->mutex);
	if (buffer->start == (buffer->end + 1) % buffer->size) {
	/*	debug_print("Buffer(%d) full: start: %d, end: %d, %d == %d\n",
				buffer->size, 
				buffer->start, 
				buffer->end, 
				(buffer->start-1) % buffer->size,
				buffer->end);*/
		pthread_mutex_unlock(&buffer->mutex);
		return 0; // Not added
	}

	
	// Add to queue
	buffer->items[buffer->end].receiverIf = receiverIf;
	buffer->items[buffer->end].size = packetLength;

	//TODO: Memcpy or packet reference counter?
	//buffer->items[buffer->end].packetData = packetData;
	memcpy(buffer->items[buffer->end].packetData, packetData,sizeof(char) * packetLength);
	buffer->end = (buffer->end + 1) % buffer->size;

	pthread_mutex_unlock(&buffer->mutex);
	
	return 1; // Added
}

const struct switch_buffer_item * switchBufferDequeue(struct switch_buffer * buffer) {

	if (buffer == NULL) {
		debug_print("%s\n", "Cannot dequeue to unitialized buffer");
		return NULL;
	}

	pthread_mutex_lock(&buffer->mutex);

	struct switch_buffer_item * retItem = NULL;

	if (buffer->start == buffer->end) {
		pthread_mutex_unlock(&buffer->mutex);
	        return NULL; // No data
	}
	
	retItem =  &buffer->items[buffer->start]; // Data returned
	buffer->start = (buffer->start + 1) % buffer->size; // Dequeue

	pthread_mutex_unlock(&buffer->mutex);

	return retItem;
}

