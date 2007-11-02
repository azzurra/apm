#************************************************************************
#*   IRC - Internet Relay Chat, Makefile
#*   Copyright (C) 1990, Jarkko Oikarinen
#*
#*   This program is free software; you can redistribute it and/or modify
#*   it under the terms of the GNU General Public License as published by
#*   the Free Software Foundation; either version 1, or (at your option)
#*   any later version.
#*
#*   This program is distributed in the hope that it will be useful,
#*   but WITHOUT ANY WARRANTY; without even the implied warranty of
#*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#*   GNU General Public License for more details.
#*
#*   You should have received a copy of the GNU General Public License
#*   along with this program; if not, write to the Free Software
#*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#*/

RM=/bin/rm

# Compile flags
CFLAGS= -pipe -Wall -O3 -g3
# linker flags.
LDFLAGS=

SHELL=/bin/sh
SUBDIRS=src

MAKE=make 'CFLAGS=${CFLAGS}' 'LDFLAGS=${LDFLAGS}'

all:	build

build:
	-@if [ ! -f inc/setup.h ] ; then \
		echo "Hmm... doesn't look like you've run configure... doing so now."; \
		sh configure; \
	fi
	@for i in $(SUBDIRS); do \
		echo "Building $$i";\
		cd $$i;\
		${MAKE} build; cd ..;\
	done
	@echo "All done!"

clean:
	@${RM} -f apm
	@cd src; ${RM} -f *.o apm; cd ..
	-@if [ -f inc/setup.h ] ; then \
	echo "To really restart installation, make distclean" ; \
	fi

distclean:
	@${RM} -f Makefile.inc configure.log apm inc/setup.h src/*.o src/apm
