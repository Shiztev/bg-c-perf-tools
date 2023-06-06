# Makefile for opensnoop.c
# Author: Ross Zwisler
# Author: Stevie Alvarez

# include trace libs
INCLUDES = -I/usr/local/include/tracefs
INCLUDES += -I/usr/local/include/traceevent

LIBS = -ltracefs

CFLAGS ?= -g -Wall #-Wextra

opensnoop: opensnoop.c
	gcc -o opensnoop opensnoop.c $(INCLUDES) $(LIBS) $(CFLAGS)

clean:
	rm opensnoop

.PHONY: clean