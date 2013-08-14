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
 * File:     mactable.h
 * Revision: $Rev: 11 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-27 23:14:32 +0200 (Wed, 27 Apr 2011) $
 *
 * MAC table implementation
 */

#ifndef _MACTABLE_
#define _MACTABLE_

#include "switchcore.h"
#include "hashmap.h"

#include <pthread.h>
#include <time.h>

#define MACTABLE_HASHMAP_SIZE 20

struct switch_mactable_item { // MAC Table item
	void * macAddress;
	struct switch_if * if_handler;
	time_t time_added;
};

struct switch_mactable { // MAC Table
	struct hashMap * map;
	unsigned int timeOutLimit; 
	pthread_mutex_t mutex;
};

struct switch_mactable * initMACTable(const unsigned int timeOutLimit);
void destroyMACTable(struct switch_mactable * table);
struct switch_if * getMACTableRecord(struct switch_mactable * table, void * macAddress);
int insertMACTableRecord(struct switch_mactable * table, void * macAddress, struct switch_if * iface);
void deleteMACTableRecord(struct switch_mactable * table, void * macAddress);
void maintainMACTable(struct switch_mactable * table);
void deleteMACTableItem(struct switch_mactable_item * item);
void printMACTable(struct switch_mactable * table);

#endif

