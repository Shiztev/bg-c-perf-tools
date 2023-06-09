# Makefile for opensnoop.c
# Author: Ross Zwisler
# Author: Stevie Alvarez

# include trace libs
INCLUDES = -I/usr/local/include/tracefs
INCLUDES += -I/usr/local/include/traceevent

LTFS = -ltracefs
LTE = -ltraceevent
LIBS = $(LTFS) $(LTE)

CFLAGS ?= -g -Wall #-Wextra

opensnoop: opensnoop.c
	gcc -o opensnoop opensnoop.c $(INCLUDES) $(LIBS) $(CFLAGS)

cleanup: cleanup.c
	gcc -o cleanup cleanup.c $(INCLUDES) $(LTFS) $(CFLAGS)

clean:
	rm opensnoop
	rm cleanup

.PHONY: clean
