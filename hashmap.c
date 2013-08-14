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
 * File:     hashmap.c
 * Revision: $Rev: 13 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-30 02:42:02 +0200 (Sat, 30 Apr 2011) $
 *
 * HashMap implementation
 */

#include "hashmap.h"
#include "utils.h"
#include "mactable.h"

#include <stdlib.h>
#include <pcap.h>

/**********************************************************/

struct hashMap * hashMapInit (const unsigned int mapSize, unsigned int(*hashFunction)(void *), int(*keyEqual)(void *, void *));
void hashMapDestroy(struct hashMap * map);
int hashMapInsertValue(struct hashMap * map, void * key, void * value);
void hashMapDeleteValue(struct hashMap * map, void * key);
void * hashMapGetValue(struct hashMap * map, void * key);
struct hashMap_item_list * hashMap2List(struct hashMap * map);
void hashMapDestroyList(struct hashMap_item_list * list);

/*********************************************************/

struct hashMap * hashMapInit (const unsigned int mapSize, unsigned int(*hashFunction)(void *), int(*keyEqual)(void *, void *)) {

	debug_print("%s\n", "START");

	struct hashMap * map = NULL;

	if (mapSize <= 0) {
		debug_print("%s\n", "Invalid hashMap size");
		return NULL;
	}

	map = (struct hashMap *) malloc(sizeof(struct hashMap));
	if (map == NULL) {
		debug_print("%s\n", "Error initializing hashMap structure");
		return NULL;
	}

	map->mapSize = mapSize;
	map->hashFunction = hashFunction;
	map->keyEqual = keyEqual;

	// Items initalizing
	map->data = (struct hashMap_item *) malloc(sizeof(struct hashMap_item) * map->mapSize);
	if (map->data == NULL) {
		debug_print("%s\n", "Error initializing hashMap items structure");
		free((void *) map);
		return NULL;
	}
	map->itemCount = 0;

	// Clearing slots */
	for (int i = 0; i < map->mapSize; i++) { 
		(map->data + i)->value = NULL;
		//(map->data + i)->key = NULL;
		(map->data + i)->occupied  = 0;
		(map->data + i)->next = NULL;
	}

	// Mutex
	if ( pthread_mutex_init(&map->mutex, NULL) != 0) {
		debug_print("%s\n", "Error initializing hashMap mutex");
		hashMapDestroy(map);
		return NULL;
	}

	debug_print("%s\n", "END");

	return map;

}

void hashMapDestroy(struct hashMap * map) {
	
	debug_print("%s\n", "START");

	if (map == NULL) {
		debug_print("%s\n", "HashMap already uninitialized");	
		return;
	}

	pthread_mutex_destroy(&map->mutex);

	for (int i = 0; i < map->mapSize; i++) {
		/* Free linear list */
		struct hashMap_item * curr = (map->data + i)->next;
		struct hashMap_item * prev = NULL;
		while (curr != NULL) {
			prev = curr;
			curr = curr->next;
			if (prev != NULL) {
				deleteMACTableItem((struct switch_mactable_item *) prev->value);
				free(prev);
			}
		}
	}
	free(map->data);
	map->data = NULL;
	
	if (map != NULL)
		free((void *) map);

	debug_print("%s\n", "END");

}

int hashMapInsertValue(struct hashMap * map, void * key, void * value) {
	
	//debug_print("%s\n", "START");

	int hashValue;

	if (map == NULL || key == NULL || value == NULL) {
		debug_print("%s\n", "Invalid params");
		return -1;
	}

	// Lock mutex
	pthread_mutex_lock(&map->mutex);

	hashValue = map->hashFunction(key) % map->mapSize;

	// Insert into HashMap 
	// 1. Check first line items
	if ((map->data + hashValue)->occupied == 0) {
	    (map->data + hashValue)->value = value;
		memcpy((map->data + hashValue)->key, key, sizeof(u_char) * 6);
		(map->data + hashValue)->occupied = 1;
		map->itemCount++;
		pthread_mutex_unlock(&map->mutex);
		//debug_print("%s\n", "Item inserted - first variant");
		return hashValue;
	}

	// 2. Add data to linear list 
	struct hashMap_item * item = (struct hashMap_item *) malloc(sizeof(struct hashMap_item));
	if (item == NULL) {
		debug_print("%s\n", "Error initializing new item");
		pthread_mutex_unlock(&map->mutex);
		return -1;
	}
	item->value = value;
	memcpy(item->key,key, sizeof(u_char) * 6);
	item->occupied = 1;
	item->next = NULL;

	struct hashMap_item * itm = map->data + hashValue;
	while (itm->next != NULL)
		itm = itm->next;
	itm->next = item;

	map->itemCount++;

	pthread_mutex_unlock(&map->mutex);
	//debug_print("%s\n", "Item inserted - second variant");
	//debug_print("%s\n", "END");

	return hashValue;

}

void hashMapDeleteValue(struct hashMap * map, void * key) {

	debug_print("%s\n", "START");

	int hashValue;
	struct hashMap_item * item;

	if (map == NULL || key == NULL) {
		debug_print("%s\n", "Invalid params");
		return;
	}

	pthread_mutex_lock(&map->mutex);

	hashValue = map->hashFunction(key) % map->mapSize;

	item = map->data + hashValue;
	while (item != NULL) {
		if (map->keyEqual(item->key, key) == 1)
			break;
		item = item->next;
	}

	// Nothing to delete
	if (item == NULL) {
		pthread_mutex_unlock(&map->mutex);
		return;
	}

	// Deleting first record?, if yes, only dealloc value & set occupied to 0
	if (item == (map->data + hashValue)) {
		(map->data + hashValue)->occupied = 0;
		//deleteMACTableItem((struct switch_mactable_item *) item->value);
	} else {
		/* Free item */
		struct hashMap_item * itm = map->data + hashValue;
		while (itm != NULL && itm->next != item)
			itm = itm->next;
		if (itm == NULL) {
			pthread_mutex_unlock(&map->mutex);
			return;
		}
		itm->next = NULL;
		//deleteMACTableItem((struct switch_mactable_item *) item->value);
		free((void *) item);
	}

	map->itemCount--;
	pthread_mutex_unlock(&map->mutex);
	return;

	debug_print("%s\n", "END");

}

void * hashMapGetValue(struct hashMap * map, void * key) {
	
	//debug_print("%s\n", "START");

	int hashValue;

	if (map == NULL || key == NULL) {
		debug_print("%s\n", "Invalid params");
		return NULL;
	}

	hashValue = map->hashFunction(key) % map->mapSize;

	// Find value
	struct hashMap_item * itm = map->data + hashValue;
	while (itm != NULL) {
		if (itm->occupied == 1 && map->keyEqual(itm->key, key) == 1)
			break;
		itm = itm->next;
	}

	//debug_print("%s\n", "END");

	return (itm == NULL) ? NULL : itm->value;

}


struct hashMap_item_list * hashMap2List(struct hashMap * map) {
	
	struct hashMap_item_list * itemList; 
	struct hashMap_item * item;

	//debug_print("%s\n", "START");

	if (map == NULL) {
		debug_print("%s\n", "Error, map unitialized");
		return NULL;
	}

	pthread_mutex_lock(&map->mutex);
	itemList = (struct hashMap_item_list *) malloc(sizeof(struct hashMap_item_list) * map->itemCount);
	if (itemList == NULL) {
		debug_print("%s\n", "Error initalizing itemList");
		return NULL;
	}

	/* Create list */
	int copied = 0;
	for (int i = 0; i < map->mapSize; i++) {
		item = (map->data + i);
		while (item != NULL) {
			if (item->value != NULL && item->occupied == 1) {
				(itemList + copied++)->value = item->value;
			}
			item = item->next;
		}
	}

	pthread_mutex_unlock(&map->mutex);
	//debug_print("%s\n", "END");

	return itemList;
}

void hashMapDestroyList(struct hashMap_item_list * list) {

	debug_print("%s\n", "START");
	
	if (list == NULL) {
		debug_print("%s\n", "Error, map unitialized");
		return;
	}

	free((void *) list);

	debug_print("%s\n", "END");

}

