# Makefile 
# Author: Jozef Lang

PROJ = switch
CC = gcc
CFLAGS = -std=c99 -D_GNU_SOURCE -Wall -pedantic
CFLAGS_DEBUG = $(CFLAGS) -ggdb -D_DEBUG_
LIBS = -lpcap -lpthread -lnet

main: release

debug:
	$(CC) -o $(PROJ) *.c *.h $(CFLAGS_DEBUG) $(LIBS)

release: 
	$(CC) -o $(PROJ) *.c *.h $(CFLAGS) $(LIBS)

clean:
	rm -f $(PROJ)
