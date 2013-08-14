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
 * File:     hashmap.h
 * Revision: $Rev: 12 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-28 23:05:05 +0200 (Thu, 28 Apr 2011) $
 *
 * HashMap implementation
 */

#ifndef _HASH_MAP_
#define _HASH_MAP_

#include <pthread.h>
#include <pcap.h>

struct hashMap_item {
	void * value;
	u_char key[6];
	unsigned int occupied;
	struct hashMap_item * next;
	struct hashMap_item * last;
};

struct hashMap {
	struct hashMap_item * data;
	unsigned int mapSize;
	unsigned int itemCount;
	unsigned int (*hashFunction)(void *);
	int (*keyEqual) (void *, void *);
	pthread_mutex_t mutex;
};

struct hashMap_item_list {
	void * value;
};

struct hashMap * hashMapInit (const unsigned int mapSize, unsigned int(*hashFunction)(void *), int(*keyEqual)(void *, void *));
void hashMapDestroy(struct hashMap * map);
int hashMapInsertValue(struct hashMap * map, void * key, void * value);
void hashMapDeleteValue(struct hashMap * map, void * key);
void * hashMapGetValue(struct hashMap * map, void * key);
struct hashMap_item_list * hashMap2List(struct hashMap * map);
void hashMapDestroyList(struct hashMap_item_list * list);

#endif

