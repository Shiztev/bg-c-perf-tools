# Makefile for pflat.c
# Author: Ross Zwisler
# Author: Stevie Alvarez

# include trace libs
INCLUDES = -I/usr/local/include/tracefs
INCLUDES += -I/usr/local/include/traceevent

LIBS = -ltracefs

CFLAGS ?= -g -Wall #-Wextra

pflat: pflat.c
	gcc -o pflat pflat.c $(INCLUDES) $(LIBS) $(CFLAGS)

clean:
	rm pflat

.PHONY: clean