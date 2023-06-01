# Makefile for funccount.c
# Author: Ross Zwisler
# Author: Stevie Alvarez

# include trace libs
INCLUDES = -I/usr/local/include/tracefs
INCLUDES += -I/usr/local/include/traceevent

LIBS = -ltracefs

CFLAGS ?= -g -Wall #-Wextra

funccount: funccount.c
	gcc -o funccount funccount.c $(INCLUDES) $(LIBS) $(CFLAGS)

clean:
	rm funccount

.PHONY: clean