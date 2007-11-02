# Makefile for Azzurra Proxy Monitor

include ../Makefile.inc

# LWRESLIBS =  /usr/local/lib/liblwres.a
# DNSLIBS =    /usr/local/lib/libdns.a
# ISCLIBS =    /usr/local/lib/libisc.a

# LIBS =       ${LWRESLIBS} ${DNSLIBS} ${ISCLIBS} -lnsl

SRCS = cidr.c config.c firedns.c http.c irc.c log.c main.c match.c misc.c negcache.c regions.c scan.c
OBJS = cidr.o config.o firedns.o http.o irc.o log.o main.o match.o misc.o negcache.o regions.o scan.o

build: $(PROGRAM)

########

$(PROGRAM): $(SRCS) $(OBJS)
	@touch $@
	$(CC) $(LFLAGS) $(OBJS) -o $@ ${LIBS}

cidr.o:		../inc/cidr.h
config.o:	../inc/config.h ../inc/irc.h ../inc/log.h ../inc/misc.h
firedns.o:	../inc/setup.h ../inc/irc.h ../inc/log.h ../inc/scan.h ../inc/options.h ../inc/config.h ../inc/firedns.h
http.o:		../inc/http.h
irc.o:		../inc/setup.h ../inc/config.h ../inc/irc.h ../inc/log.h ../inc/main.h ../inc/misc.h ../inc/negcache.h ../inc/options.h ../inc/scan.h
log.o:		../inc/config.h ../inc/irc.h
main.o:		../inc/config.h ../inc/irc.h ../inc/log.h ../inc/negcache.h ../inc/scan.h
negcache.o:	../inc/config.h ../inc/log.h ../inc/negcache.h
regions.o:	../inc/regions.h ../inc/cidr.h ../inc/log.h
scan.o:		../inc/setup.h ../inc/config.h ../inc/irc.h ../inc/log.h ../inc/misc.h ../inc/negcache.h ../inc/options.h ../inc/scan.h
