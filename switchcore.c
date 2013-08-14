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
 * File:     switchcore.c
 * Revision: $Rev: 18 $
 * Author:   $Author: lang.jozef@gmail.com $
 * Date:     $Date: 2011-04-30 18:10:08 +0200 (Sat, 30 Apr 2011) $
 *
 * Core switch functions and constants. 
 */

#include "switchcore.h"
#include "utils.h"
#include "mactable.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <signal.h>
#include <libnet.h>

#define SWITCH_COMMANDS_COUNT 6
char * switchCommands[] = {"start", "quit", "cam", "stat", "help", "const"};
enum e_switchCommand {
				E_SWITCH_COMMAND_NONE = -2,
				E_SWITCH_COMMAND_INVALID = -1,
				E_SWITCH_COMMAND_START = 0,
				E_SWITCH_COMMAND_QUIT,
				E_SWITCH_COMMAND_MAC,
				E_SWITCH_COMMAND_STATS,
				E_SWITCH_COMMAND_HELP,
				E_SWITCH_COMMAND_CONST};

/********************************************************************/

void printHelp();
void printStats(struct switch_dev * device);
void printCAM(struct switch_dev * device);
void printConstants();
enum e_switchCommand getSwitchCommand(char * command);
int fireSwitchCommand(struct switch_dev * device, char * command);
unsigned int getSwitchState(struct switch_dev * dev);
void setSwitchState(struct switch_dev * dev, const unsigned int state);
int switchStartup(struct switch_dev * swtch);
void switchShutdown(struct switch_dev * swtch);
int loadSwitchIfs(struct switch_if ** iterface, char * errorMsg);
int getSwitchOpenedIfsCount(struct switch_dev * dev);
void resetSwitchIfStats(struct switch_if * ifs);
void openSwitchIf(struct switch_if * iface, char * errorMsg);
int openSwitchIfs(struct switch_if * ifaces, char * errorMsg);
void closeSwitchIf(struct switch_if * iface, char * errorMsg);
void * switchIfListeningThread(void * iface);
void * switchIfSendingThread(void * iface);
unsigned int isSwitchIfOpened(struct switch_if * iface);
void setSwitchIfState(struct switch_if * iface, int isOpened);
void incSwitchIfStats(struct switch_if * iface, long * counter, const int amount);
void getSwitchifStats(struct switch_if * iface, long * counter, long * value);
int startSwitching(struct switch_dev * dev, char * errorMsg);
void * switchMACTableMaintainThread(void * dev);
void * switchSwitchingThread(void * dev);
void sendBroadcast(struct switch_dev * dev, const struct switch_buffer_item * item);
void sendUnicast(struct switch_if * iface, const struct switch_buffer_item * item);

/*******************************************************************/

void printHelp() {
	user_print("\n%s\n","softswitch Copyright (C) 2011 Jozef Lang\n");
	user_print("%s\n","Available commands");
	user_print("%s\n","==================");
	//user_print("%s\n","start  - start switching");	
	user_print("%s\n","cam    - show MAC table");
	user_print("%s\n","stat  - show stats");
	user_print("%s\n","help   - show help");
	user_print("%s\n","const  - show switch constants");
	user_print("%s\n","quit   - quit application\n");
}

void printStats(struct switch_dev * device) {
	if (device == NULL || device->started == 0) {
		user_print("%s\n","Switch is not running");
		return;
	}

	user_print("\nIface\tSent-B\tSent-frm\tRecv-B\tRecv-frm\n%s","");
	for (struct switch_if * iface = device->ifs; iface != NULL; iface = iface->next) {
		user_print("%-6s\t%-6ld\t%-8ld\t%-6ld\t%-8ld\n",
					   			iface->name, 
								(iface->stats).sentBytes, 
								(iface->stats).sentFrames,
								(iface->stats).receivedBytes, 
								(iface->stats).receivedFrames);
	}
	user_print("%s\n","");
}

void printCAM(struct switch_dev * device) {
	
	if (device == NULL || device->started == 0) {
		user_print("%s\n","Switch is not running");
		return;
	}

	printMACTable(device->mac_table);

	user_print("%s\n","");
}

void printConstants() {

	user_print("%s\n","");
	user_print("Maximal PCAP packet size: %d bytes\n", BUFSIZ);
	user_print("Buffers size: %d items\n", SWITCH_BUFFER_MAX_SIZE);
	user_print("MAC table timeout: %d seconds\n", SWITCH_MACTABLE_TIMEOUT);
	user_print("%s\n","");
}

enum e_switchCommand getSwitchCommand(char * command) {

	if (command == NULL || strcmp(command, "") == 0)
		return E_SWITCH_COMMAND_NONE;

	// Find appropiate switch command
	for (int i = 0; i < SWITCH_COMMANDS_COUNT; i++) {
	  	if (strcmp(command, switchCommands[i]) == 0)
			return (enum e_switchCommand) i;
  	}

	// Invalid command
	return E_SWITCH_COMMAND_INVALID;
}

int fireSwitchCommand(struct switch_dev * device, char * command) {

	switch(getSwitchCommand(command)) {
		case E_SWITCH_COMMAND_START:
			switchStartup(device);
			if (getSwitchState(device) == 1) {
				user_print("Switch started, %d/%d interfaces opened\n", getSwitchOpenedIfsCount(device), device->if_count);
			}
			break;
		case E_SWITCH_COMMAND_QUIT:
			switchShutdown(device);
			user_print("%s\n","Bye.");
			return 0; // Exit program
			break;
		case E_SWITCH_COMMAND_MAC:
			printCAM(device);
			break;
		case E_SWITCH_COMMAND_STATS:
			printStats(device);
			break;
		case E_SWITCH_COMMAND_HELP:
			printHelp();
			break;
		case E_SWITCH_COMMAND_CONST:
			printConstants();
			break;
		case E_SWITCH_COMMAND_INVALID:
			error_print("%s\n","Invalid command! Try 'help'");
			break;
		default: 
			return 1;
			break;
	}
	return 1; // Continue
}

unsigned int getSwitchState(struct switch_dev * dev) {
	if (dev == NULL)
		return 0;

	unsigned int ret;
	pthread_mutex_lock(&dev->mutex);
	ret = dev->started > 0 ? 1 : 0;
	pthread_mutex_unlock(&dev->mutex);
	return ret;
}

void setSwitchState(struct switch_dev * dev, const unsigned int state) {
	if (dev == NULL)
		return;

	pthread_mutex_lock(&dev->mutex);
	dev->started = state > 0 ? 1 : 0;
	pthread_mutex_unlock(&dev->mutex);
}

int switchStartup(struct switch_dev * swtch) {
	
	debug_print("%s\n","START");

	if (getSwitchState(swtch) == 1) {
		debug_print("%s\n", "Device already started");
		user_print("%s\n", "Device already started");
		return 1;
	}

	// Mark swtch as running
	setSwitchState(swtch, 1);

	char errorMsg[255];
	int wasError = 0;

	if (swtch == NULL) {
		debug_print("%s\n", "Param 'swtch' is NULL");
		error_message(errorMsg,"Fatal error");
		wasError = 1;
	} 

	// 1. Load interfaces
	if (wasError == 0) {
		swtch->if_count = loadSwitchIfs(&swtch->ifs, errorMsg);
		if (swtch->if_count == -1) {
			swtch->if_count = 0;
			debug_print("%s: %s\n", "loadSwitchIntefaces", errorMsg);
			wasError = 1;	
		}
	}

	// 2. Init MAC Table
	if (wasError == 0) {
		swtch->mac_table = initMACTable(SWITCH_MACTABLE_TIMEOUT);
		if (swtch->mac_table == NULL) {
			debug_print("%s: %s\n", "InitMACTable", errorMsg);
			wasError = 1;	
		}
	}

	// 3. Open interfaces & start listening / sending threads
	if (wasError == 0) {
		openSwitchIfs(swtch->ifs, errorMsg);
	}

	// 4. Start switching
	if (wasError == 0) {
		if(startSwitching(swtch, errorMsg) == 0) {
			debug_print("Unable to start switching: %s\n", errorMsg);
			wasError = 1;
		}
	}

	if (wasError != 0) {
		// Switch shutdown
		error_print("%s: %s\n", "Switch startup error",errorMsg);
		switchShutdown(swtch);
	}

	debug_print("%s\n","END");
	return !wasError;

}

void switchShutdown(struct switch_dev * swtch) {

	debug_print("%s\n","START");
	
	if (swtch == NULL) {
		debug_print("%s\n","Param 'swtch' is NULL");
	}

	// 1. Stop switching and mactable maintain thread
	setSwitchState(swtch, 0); 
	if (swtch->swtch_thread != 0) {
		int rc = pthread_join(swtch->swtch_thread, NULL);
		if (rc) {
			debug_print("Error joing switching thread%s\n","");	
		}
	}
	if (swtch->swtch_mactable_maintain_thread != 0) {
		int rc = pthread_join(swtch->swtch_mactable_maintain_thread, NULL);
		if (rc) {
			debug_print("Error joining MAC table maintain thread%s\n", "");
		}
	}
	

	// 2. Close & dealloc all ifs
	struct switch_if * shutIf;
	char errorMsg[255];
	while (swtch->ifs != NULL) {
		shutIf = swtch->ifs;
		swtch->ifs = swtch->ifs->next;
		
		// Close iface
		closeSwitchIf(shutIf, errorMsg);
		
		// Dealloc name
		free((void *) shutIf->name);
		shutIf->name = NULL;

		// Destroy mutexes
		pthread_mutex_destroy(&shutIf->mutex);
		pthread_mutex_destroy(&shutIf->stats.mutex);

		// Dealloc ifs
		free((void *) shutIf);
	}

	// 3. Dealoc MAC TABLE
	destroyMACTable(swtch->mac_table);
	
	// 4. Reset counters
	swtch->if_count &= 0;
	
	user_print("%s\n", "Switch stoped, interfaces closed");
	debug_print("%s\n","END");

}

int loadSwitchIfs(struct switch_if ** interface, char * errorMsg) {
	
	debug_print("%s\n", "START");

	char errBuff[PCAP_ERRBUF_SIZE];
	pcap_if_t * devList = NULL;
	pcap_t * handler = NULL;

	if (pcap_findalldevs(&devList, errBuff) == -1) {
		debug_print("%s\n", errBuff);
	}

	if (devList == NULL) {
		error_message(errorMsg,"No suitable devices found!");
		return -1; // Error
	}

	// Construct interface list
	int ifsCount = 0;
	int wasError = 0;
	for (pcap_if_t * dev = devList; dev->next != NULL; dev = dev->next) {
		// Skip device called "any"
		if (strcmp(dev->name,"any") == 0)
			continue;

		// Skip non ethernet devices
		handler = pcap_open_live(dev->name, BUFSIZ, 1, -1, errBuff);
		if (pcap_datalink(handler) != DLT_EN10MB) {
			debug_print("Interface %s is not ethernet device, skipping\n", dev->name);
			pcap_close(handler);
			continue;
		}
		pcap_close(handler);

		debug_print("%s: %s\n","Device found", dev->name);

		// Malloc 
		struct switch_if * newIf = (struct switch_if *) malloc(sizeof(struct switch_if));
		if (newIf == NULL) {
			wasError = 1; // Error
			debug_print("%s\n", "newIf malloc error!");
		} else {
			// Set values
			newIf->handler = NULL;
			newIf->next = NULL;
			newIf->receiveBuffer = NULL;
			newIf->sendBuffer = NULL;
			newIf->listening_thread = 0;
			newIf->sending_thread = 0;
			// Init MUTEXes
			pthread_mutex_init(&newIf->mutex,NULL);
			pthread_mutex_init(&newIf->stats.mutex,NULL);
			resetSwitchIfStats(newIf);
			newIf->name = (char *) malloc(sizeof(char) * (strlen(dev->name) + 1));
			if (newIf->name == NULL) {
				wasError = 1; // Error
				free((void *) newIf);
				debug_print("%s\n","newIf name malloc error");
			}
			strcpy(newIf->name, dev->name);

			// Get interface MAC Address
			libnet_t * libSession = NULL;
			char libErrBuff[LIBNET_ERRBUF_SIZE];
			struct libnet_ether_addr * hwAddr;

			libSession = libnet_init(LIBNET_LINK, newIf->name, libErrBuff);
			if (libSession == NULL) {
				wasError = 1; // Error
				debug_print("Error initializing libnet session: %s\n", libErrBuff);
			}

			hwAddr = libnet_get_hwaddr(libSession);
			memcpy(newIf->macAddress, hwAddr->ether_addr_octet, sizeof(u_char) * ETHER_ADDR_LEN);

			libnet_destroy(libSession);

			setSwitchIfState(newIf, 0);
		}

		if (wasError) {
			struct switch_if * freeIf;
			debug_print("%s\n","On error deallocating START");
			while (*interface != NULL) {
				freeIf = *interface;
				*interface = (*interface)->next;
				free((void *) freeIf);
			}
			*interface = NULL;
			debug_print("%s\n","On error deallocating END");
			return -1; // Error
		}

		// Add dev to interface list
		if (*interface == NULL) {
			*interface = newIf; 
		} else {
			struct switch_if * switch_if_cur = *interface;
			while (switch_if_cur->next != NULL)
					switch_if_cur = switch_if_cur->next;
			switch_if_cur->next = newIf;
		}
	ifsCount++;
	}

	pcap_freealldevs(devList);

	debug_print("%s\n","END");
	return ifsCount;
}

int getSwitchOpenedIfsCount(struct switch_dev * device) {
	int count = 0;
	for (struct switch_if * ifs = device->ifs; ifs != NULL; ifs = ifs->next) {
			if (isSwitchIfOpened(ifs) == 1)
				count++;
	}
	return count;
}

void resetSwitchIfStats(struct switch_if * ifs) {
	if (ifs == NULL) {
		debug_print("%s\n", "Param 'ifs' IS NULL");
		return;
	}

	pthread_mutex_lock(&ifs->stats.mutex);
	(ifs->stats).receivedFrames = 0;
	(ifs->stats).receivedBytes = 0;
	(ifs->stats).sentFrames = 0;
	(ifs->stats).sentBytes = 0;
	(ifs->stats).droppedFrames = 0;
	(ifs->stats).droppedBytes = 0;
	pthread_mutex_unlock(&ifs->stats.mutex);
}

void openSwitchIf(struct switch_if * iface, char * errorMsg) {

	debug_print("%s\n","START");
	
	if (iface == NULL) {
		debug_print("%s\n","Param 'iface' is NULL");
		error_message(errorMsg, "No interface to open");
		return;
	}
	debug_print("START opening iface: %s\n", iface->name);

	if (isSwitchIfOpened(iface) == 1) {
		debug_print("%s\n", "Iface already opened");
		return;
	}

	char error[PCAP_ERRBUF_SIZE];	
	iface->handler = pcap_open_live(iface->name, BUFSIZ, 1, -1, error);
	if (iface->handler == NULL) {
		debug_print("Unable to open: %s: %s\n",iface->name, error);
		sprintf(errorMsg, "Unable to open: %s\n", iface->name);
		return;
	}

	// Set direction & filter 
	pcap_setdirection(iface->handler, PCAP_D_IN);

	// Init switch buffers
	initSwitchBuffer(&iface->receiveBuffer, SWITCH_BUFFER_MAX_SIZE);
	initSwitchBuffer(&iface->sendBuffer, SWITCH_BUFFER_MAX_SIZE);

	// Set iface as OPEN
	setSwitchIfState(iface, 1);

	// Run worker threads
	int resCode;
	resCode = pthread_create(&iface->listening_thread, PTHREAD_CREATE_JOINABLE, switchIfListeningThread, (void *) iface);
	if (resCode) {
		setSwitchIfState(iface, 0);
		debug_print("Unable to start listening thread for iface: %s\n", iface->name);
		sprintf(errorMsg,"Unable to start listening thread for interface: %s\n", iface->name);
		return;
	 } else {
		debug_print("Listening thread for iface: %s started\n",iface->name); 
	 }

	resCode = pthread_create(&iface->sending_thread, PTHREAD_CREATE_JOINABLE, switchIfSendingThread, (void *) iface);
	if (resCode) {
		setSwitchIfState(iface, 0);
		debug_print("Unable to start sending thread for iface: %s\n", iface->name);
		sprintf(errorMsg,"Unable to start sending thread for interface: %s\n", iface->name);
		return;
	} else {
		debug_print("Sending thread for iface: %s started\n", iface->name);		
	}
	if (isSwitchIfOpened(iface) == 0 && iface->handler != NULL) {
		pcap_close(iface->handler);
		iface->handler = NULL;
	}

	debug_print("END opening iface: %s\n", iface->name);

	debug_print("%s\n","END");
}

int openSwitchIfs(struct switch_if * ifaces, char * errorMsg) {
	debug_print("%s\n","START");

	if (ifaces == NULL) {
		debug_print("%s\n","Param 'ifaces' is NULL");
		error_message(errorMsg,"No interfaces to open");
		return 0;
	}

	int ifsOpened = 0;
	for(struct switch_if * openIf = ifaces; openIf != NULL; openIf = openIf->next) {
		openSwitchIf(openIf, errorMsg);
		if (isSwitchIfOpened(openIf) == 1)
				ifsOpened++;
	}	

	debug_print("%s\n","END");
	return ifsOpened;
}

void closeSwitchIf(struct switch_if * iface, char * errorMsg) {

	debug_print("%s\n","START");
	
	if (iface == NULL) {
		debug_print("%s\n","Param 'iface' is NULL");
		error_message(errorMsg, "No interface to close");
		return;
	}
	
	debug_print("START stoping iface: %s\n", iface->name);

	setSwitchIfState(iface, 0); // Stop infinite listening & sending loop

	// Wait for listening & sending threads to finnish
	int rc;
	if (iface->listening_thread != 0) {
		rc = pthread_join(iface->listening_thread, NULL);
		if (rc) {
			debug_print("Error joing listening thread of iface %s\n", iface->name);
		}	
	}
	if (iface->sending_thread != 0) {
		rc = pthread_join(iface->sending_thread, NULL);
		if (rc) {
			debug_print("Error joing sending thread of iface %s\n", iface->name);
		}		
	}

	// Free buffers
	freeSwitchBuffer(&iface->receiveBuffer);
	freeSwitchBuffer(&iface->sendBuffer);

	// Close pcap handler
	if (iface->handler != NULL) {
		pcap_close(iface->handler);
		iface->handler = NULL;
	}	

	debug_print("END stoping iface: %s\n", iface->name);
	
	debug_print("%s\n","END");
}

void * switchIfListeningThread(void * iface) {
	
	struct pcap_pkthdr header;
	struct switch_if * ifc = (struct switch_if *) iface;
	int packetLength;
	struct ether_header * frameHdr;
	char addr1[20], addr2[20];

	while (isSwitchIfOpened(ifc) == 1) {
		// Read packet
		const u_char * packet = pcap_next(ifc->handler, &header);
		if (packet == NULL)
			continue;

		// Skip own packets
		frameHdr = (struct ether_header *) packet;
		formatMACAddress(frameHdr->ether_dhost, addr1);
		formatMACAddress(ifc->macAddress, addr2);
		if (strcmp(addr1, addr2) == 0)
			continue;

		packetLength = header.caplen; //TODO: What to use caplen or cap?

		//Add packet to receive buffer
		if (switchBufferQueue(ifc->receiveBuffer, ifc, packet, packetLength) == 0) { // Not Added
			// Increment dropped counters
			incSwitchIfStats(ifc, &ifc->stats.droppedFrames, 1);
			incSwitchIfStats(ifc, &ifc->stats.droppedBytes, packetLength);
		} else { // Added
			// Increment receive counters
			incSwitchIfStats(ifc, &ifc->stats.receivedFrames, 1);
			incSwitchIfStats(ifc, &ifc->stats.receivedBytes, packetLength);
		}
	}

	// If iface still opened, close
	if (isSwitchIfOpened(iface) == 1) 
		setSwitchIfState(iface, 0);
	debug_print("Thread :: Stopping listening thread of iface: %s\n",ifc->name);
	pthread_exit(NULL);
}

void * switchIfSendingThread(void * iface) {
	
	//Reading Loop from iface send buffer	
	struct switch_if * ifc = (struct switch_if *) iface;

       	while (isSwitchIfOpened(ifc) == 1) {	
		while (1) {
			const struct switch_buffer_item * item = switchBufferDequeue(ifc->sendBuffer);
			if (item == NULL) 
				break; // Nothing to send

			// Send	 
			// TODO: Examine packetData, whether it contains also ether hdr
			 if (pcap_sendpacket(ifc->handler, item->packetData, item->size) == 0) {
				// Increment counters
				incSwitchIfStats(ifc, &ifc->stats.sentFrames, 1);
				incSwitchIfStats(ifc, &ifc->stats.sentBytes, item->size);
			} 
		}

	}

	// If iface still opened, close
	if (isSwitchIfOpened(iface) == 1) 
		setSwitchIfState(iface, 0);

	debug_print("Thread :: Stopping sending thread of iface: %s\n",((struct switch_if *) iface)->name);
	pthread_exit(NULL);
}

unsigned int isSwitchIfOpened(struct switch_if * iface) {
	int isOpened;

	pthread_mutex_lock(&iface->mutex);
	isOpened = iface->opened;
	pthread_mutex_unlock(&iface->mutex);

	return isOpened;	
}

void setSwitchIfState(struct switch_if * iface, int isOpened) {	
	if (iface == NULL)
		return;
	char * ifName = ((struct switch_if *) iface)->name;
	debug_print("Setting iface %s status to %d\n", ifName == NULL ? "N/A" : ifName, isOpened);

	pthread_mutex_lock(&iface->mutex);
	iface->opened = isOpened > 0 ? 1 : 0;
	pthread_mutex_unlock(&iface->mutex);
}

void incSwitchIfStats(struct switch_if * iface, long * counter, const int amount) {
	if (amount == 0 || iface == NULL || counter == NULL)
		return;

	pthread_mutex_lock(&iface->stats.mutex);
	*counter += amount;
	pthread_mutex_unlock(&iface->stats.mutex);
}

int startSwitching(struct switch_dev * dev, char * errorMsg) {
	debug_print("%s\n","START");

	if (dev == NULL) {
		sprintf(errorMsg,"Unable to start switching: %s\n", errorMsg);
		return 0; // Not started
	}

	// Start switch thread
	int resCode;
	resCode = pthread_create(&dev->swtch_thread, PTHREAD_CREATE_JOINABLE, switchSwitchingThread, (void *) dev);
	if (resCode) {
		sprintf(errorMsg,"Unable to start switching thread");
		return 0;
	 } else {
		debug_print("Switching thread started%s\n",""); 
	 }

	// Start MAC Table maintain thread
	resCode = pthread_create(&dev->swtch_mactable_maintain_thread, PTHREAD_CREATE_JOINABLE, switchMACTableMaintainThread, (void *) dev);
	if (resCode) {
		sprintf(errorMsg, "Unable to start MAC table maintain thread");
		return 0;
	} else {
		debug_print("MAC table maintain thread started %s\n", "");
	}
	
	debug_print("%s\n","END");
	return 1; // Started
}

void * switchMACTableMaintainThread(void * dev) {

	struct switch_dev * device = (struct switch_dev *) dev;

	// While is switch running
	while (getSwitchState(device) == 1) {
		// Maintain
		maintainMACTable(device->mac_table);
		sleep(1);
	}


	pthread_exit(NULL);
}

void * switchSwitchingThread(void * dev) {

	struct switch_dev * device = (struct switch_dev *) dev;
	struct ether_header * frameHdr;
	struct switch_if * outIf = NULL;

	// Read ifaces receive buffers, while switch is running
	while (getSwitchState(device) == 1) {
		// Loop over all available ifaces
		for (struct switch_if * iface = device->ifs; iface != NULL; iface = iface->next) {
			if (isSwitchIfOpened(iface) == 1) { // Only opened
				const struct switch_buffer_item * item = switchBufferDequeue(iface->receiveBuffer);
				if (item != NULL) { // There is an item to send
					frameHdr = (struct ether_header *) item->packetData;
					if (isBroadcast(frameHdr->ether_dhost) == 1) {
						/* Send broadcast */
						sendBroadcast(device, item);
					} else {
						/* 1. Check for port change */
						outIf = getMACTableRecord(device->mac_table, frameHdr->ether_shost);
						if (outIf != NULL && outIf != item->receiverIf) {
							// Delete old record & insert new
							deleteMACTableRecord(device->mac_table, frameHdr->ether_shost);
				 			insertMACTableRecord(device->mac_table, frameHdr->ether_shost, item->receiverIf);		
							debug_print("%s\n", "Port change");
						} else {
							// Insert new record
				 			insertMACTableRecord(device->mac_table, frameHdr->ether_shost, item->receiverIf);		
						}
						/* 2. Find out iface */
						outIf = getMACTableRecord(device->mac_table, frameHdr->ether_dhost);
						if (outIf == NULL) {
							// Not known yet, send broadcast
							sendBroadcast(device, item);
						} else {
							// Send unicast
							sendUnicast(outIf, item);
						}
					}
				}
			}
		}	
	}

	debug_print("%s\n", "Thread :: Stopping switch switching thread");
	pthread_exit(NULL);
}

void sendBroadcast(struct switch_dev * dev, const struct switch_buffer_item * item) {
	if (dev == NULL || item == NULL)
		return;
 
	for (struct switch_if * iface = dev->ifs; iface != NULL; iface = iface->next) {
		if (iface == item->receiverIf) // Skip 
			continue;
		if (isSwitchIfOpened(iface) == 1) { // If Opened
			// Add to sending buffer
			switchBufferQueue(iface->sendBuffer, NULL, item->packetData, item->size);
		}
	}
}

void sendUnicast(struct switch_if * iface, const struct switch_buffer_item * item) {
	if (iface == NULL || item == NULL || iface == item->receiverIf)
		return;

	if (isSwitchIfOpened(iface) == 1) {
		switchBufferQueue(iface->sendBuffer, NULL, item->packetData, item->size);
	}
}

