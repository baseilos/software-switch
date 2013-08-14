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
 * File:     mactable.c
 * Revision: $Rev: 13 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-30 02:42:02 +0200 (Sat, 30 Apr 2011) $
 *
 * MAC table implementation
 */

#include "mactable.h"
#include "switchcore.h"
#include "utils.h"

#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <net/ethernet.h>

/********************************************************************/

struct switch_mactable * initMACTable(const unsigned int timeOutLimit);
void destroyMACTable(struct switch_mactable * table);
struct switch_if * getMACTableRecord(struct switch_mactable * table, void * macAddress);
int insertMACTableRecord(struct switch_mactable * table, void * macAddress, struct switch_if * iface);
void deleteMACTableRecord(struct switch_mactable * table, void * macAddress);
void maintainMACTable(struct switch_mactable * table);
struct switch_mactable_item * initMACTableItem(void * macAddress, struct switch_if * iface);
unsigned int MACTableHashFunction(void * macAddress);
int MACAddressEqual(void * addr1, void * addr2);
void deleteMACTableItem(struct switch_mactable_item * item);
void printMACTable(struct switch_mactable * table);

/*******************************************************************/

struct switch_mactable * initMACTable(const unsigned int timeOutLimit) {

	debug_print("%s\n", "START");

	struct switch_mactable * table = (struct switch_mactable *) malloc(sizeof(struct switch_mactable));
	if (table == NULL) {
		debug_print("%s\n", "Error initializing MAC Table");
		return NULL;
	}

	// Mutex
 	if (pthread_mutex_init(&table->mutex, NULL) != 0) {
		debug_print("%s\n", "Error initializing mutex");
		destroyMACTable(table);
		return NULL;
	}

	table->timeOutLimit = timeOutLimit;

	// Init hashmap
	table->map = hashMapInit(MACTABLE_HASHMAP_SIZE, MACTableHashFunction, MACAddressEqual);
	if (table->map == NULL) {
		debug_print("%s\n", "Error initializing hashmap");
		destroyMACTable(table);
	}

	debug_print("%s\n", "END");
	return table;
}


void destroyMACTable(struct switch_mactable * table) {
	
	debug_print("%s\n", "START");

	if (table == NULL) {
		debug_print("%s\n", "MAC Table already uninitialized");
		return;
	}

	// Mutex
	pthread_mutex_destroy(&table->mutex);

	// Destroy HashMap
	hashMapDestroy(table->map);
	table = NULL;

	debug_print("%s\n", "END");
}


struct switch_if * getMACTableRecord(struct switch_mactable * table, void * macAddress) {

	struct switch_mactable_item * value = NULL;

	if (table == NULL || macAddress == NULL) 
		return NULL;


	pthread_mutex_lock(&table->mutex);
	value = (struct switch_mactable_item *) hashMapGetValue(table->map, macAddress);
	pthread_mutex_unlock(&table->mutex);
	
	/* If time_added < 0, record is marked to removal */
	if (value != NULL && value->time_added < 0)
		value = NULL;

	return (value == NULL) ? NULL : value->if_handler;
}

int insertMACTableRecord(struct switch_mactable * table, void * macAddress, struct switch_if * iface) {

	struct switch_mactable_item * item;

	//debug_print("%s\n","START");

	if (table == NULL || macAddress == NULL || iface == NULL) 
		return -1;

	pthread_mutex_lock(&table->mutex);
	item = (struct switch_mactable_item *) hashMapGetValue(table->map, macAddress);
	if (item != NULL) {
		/* If already exists, update addedDate tu actual date */
		item->time_added = time(NULL);
		pthread_mutex_unlock(&table->mutex);
		//debug_print("%s\n", "Item already present - updating");
		return 1;
	} else {
		/* Add new macTable item */
		item = initMACTableItem(macAddress, iface);
		if (item == NULL) {
			debug_print("%s\n", "Error inserting new MAC Table item");
			pthread_mutex_unlock(&table->mutex);
			return -1;
		}
		// Add to hashMap
		if (hashMapInsertValue(table->map, macAddress, item) < 0) {
			debug_print("%s\n", "Error inserting to HASHMAP");
			pthread_mutex_unlock(&table->mutex);
			return -1;
		}

	}

	pthread_mutex_unlock(&table->mutex);
	//debug_print("%s\n", "New item inserted");

	//debug_print("%s\n","END");

	return 1;

}

void deleteMACTableRecord(struct switch_mactable * table, void * macAddress) {
	
	struct switch_mactable_item * item;

	debug_print("%s\n", "START");

	if (table == NULL || macAddress == NULL) {
		debug_print("%s\n", "Invalid params");
	}

	pthread_mutex_lock(&table->mutex);
	item = (struct switch_mactable_item *) hashMapGetValue(table->map, macAddress);

	if (item != NULL) {
		hashMapDeleteValue(table->map, macAddress);
		deleteMACTableItem(item);
	}

	pthread_mutex_unlock(&table->mutex);

	debug_print("%s\n", "END");

}

void maintainMACTable(struct switch_mactable * table) {

	
	struct hashMap_item_list * list;
	time_t currTime = time(NULL);

	if (table == NULL) {
		debug_print("%s\n", "Invalid params");
		return;
	}

	pthread_mutex_lock(&table->mutex);
	list = hashMap2List(table->map);

	for (int i = 0; i < table->map->itemCount; i++) {
		struct switch_mactable_item * item = (struct switch_mactable_item *) (list + i)->value;
		if (item == NULL)
			continue;
		if (item->time_added < 0 || ((unsigned int) (currTime - item->time_added)) > table->timeOutLimit) {
			// Erase old record
			hashMapDeleteValue(table->map, (void *) item->macAddress);
			deleteMACTableItem(item);
		}
	}

	hashMapDestroyList(list);
	pthread_mutex_unlock(&table->mutex);
}


struct switch_mactable_item * initMACTableItem(void * macAddress, struct switch_if * iface) {

	struct switch_mactable_item * item = NULL;	

	if (macAddress == NULL || iface == NULL) 
		return NULL;

	item = (struct switch_mactable_item *) malloc(sizeof(struct switch_mactable_item));
	if (item == NULL) {
		debug_print("%s\n","Error initializing new MACTable item");
		return NULL;
	}

	// Set values
	item->macAddress = malloc(sizeof(u_char) * 6);
	if (item->macAddress == NULL) {
		debug_print("%s\n", "Error initalizing MACAdrress field in MAC Table init");
		free((void *) item);
		return NULL;
	}
	memcpy(item->macAddress, macAddress, sizeof(u_char) * ETHER_ADDR_LEN);

	item->if_handler = iface;
	item->time_added = time(NULL);

	return item;

}


unsigned int MACTableHashFunction(void * macAddress) {

	u_char * addr = (u_char *) macAddress;

	if (macAddress == NULL)
		return 0;

	unsigned int hash = 0;

	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		hash ^= (u_int) addr[i];
	}
	
	return hash;
}


int MACAddressEqual(void * addr1, void * addr2) {

	u_char * ad1 = (u_char *) addr1;
	u_char * ad2 = (u_char *) addr2;

	if (addr1 == NULL || addr2 == NULL)
		return 0;

	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		if (ad1[i] != ad2[i])
			return 0;
	}
		
	return 1;
}


void deleteMACTableItem(struct switch_mactable_item * item) {

	if (item == NULL)
		return;
		
	free((void *) item->macAddress);
	free((void *) item);
}

void printMACTable(struct switch_mactable * table) {

	struct hashMap_item_list * list = NULL;
	struct switch_mactable_item * item = NULL;
	time_t currentTime;
	char macAddressString[15];

	debug_print("%s\n","START");

	user_print("\nMAC address\tPort\tAge%s","\n");

	if (table == NULL) {
		debug_print("%s\n","MAC table not initialized");
		return;
	}

	// Load items from HashMap
	
	pthread_mutex_lock(&table->mutex);
	list = hashMap2List(table->map);
	if (list == NULL) {
		debug_print("%s\n", "Hash map itemList not initialized");
		return;
	}

	// Print out each item
	currentTime = time(NULL);
	for (int i = 0; i < table->map->itemCount; i++) {
		item = (struct switch_mactable_item *) (list + i)->value;
		if (item == NULL)
			continue;
		formatMACAddress((u_char *) item->macAddress, macAddressString);
		user_print("%s\t%s\t%ld\n", macAddressString, item->if_handler->name, (long int) currentTime - item->time_added);
	}	
	
	pthread_mutex_unlock(&table->mutex);

	hashMapDestroyList(list);

	debug_print("%s\n","END");

}

