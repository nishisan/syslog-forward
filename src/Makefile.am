AM_CFLAGS = 
AM_LDFLAGS = -lpcap 
ACLOCAL_AMFLAGS = -I m4 -Ilib

bin_PROGRAMS = syslog-forward 

syslog_forward_SOURCES = server.c configuration.c 


#include_HEADERS = common/default.h common/configuration.h
LDADD = -L../lib/libconfig -lconfig
INCLUDES = -I$(top_builddir)/lib/libconfig

