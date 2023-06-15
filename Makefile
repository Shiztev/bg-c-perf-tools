# Makefile for opensnoop.c
# Author: Ross Zwisler
# Author: Stevie Alvarez

#
# Definitions
#
CC = gcc
CFLAGS ?= -g -Wall -Wextra -pedantic

# include trace libs
INCLUDES = -I/usr/local/include/tracefs
INCLUDES += -I/usr/local/include/traceevent

LTFS = -ltracefs
LTE = -ltraceevent
LIBS = $(LTFS) $(LTE)
FTFLAGS = $(LIBS) $(INCLUDES)

#
# Targets
#

all: opensnoop

opensnoop: src/opensnoop.c
	gcc -o opensnoop src/opensnoop.c $(FTFLAGS) $(CFLAGS)

cleanup: src/cleanup.c
	gcc -o cleanup src/cleanup.c $(INCLUDES) $(LTFS) $(CFLAGS)

#
# Clean up
#

clean:
	rm opensnoop
	rm cleanup

.PHONY: clean
