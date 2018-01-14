# Example makefile for CPE 464
#

CC = gcc
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  ping_spoof-$(EXEC_SUFFIX)

ping_spoof-$(EXEC_SUFFIX): ping_spoof.c
	$(CC) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o $@ ping_spoof.c checksum.c smartalloc.c -lpcap

handin: README
	handin bellardo p1 README smartalloc.c smartalloc.h checksum.c checksum.h ping_spoof.c Makefile

clean:
	-rm -rf ping_spoof-* ping_spoof-*.dSYM
