/*
 * Azzurra Proxy Monitor - main.c
 * Copyright (C) 2007 Azzurra IRC Network <devel@azzurra.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Based on:
 *	Blitzed Open Proxy Monitor is copyright (C) 2002 Erik Fears
 *
 */

/* $Id$ */


#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "../inc/setup.h"

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "../inc/config.h"
#include "../inc/irc.h"
#include "../inc/log.h"
#include "../inc/negcache.h"
#include "../inc/options.h"
#include "../inc/firedns.h"
#include "../inc/http.h"
#include "../inc/scan.h"


/* TS of when we were started. */
time_t START_TIME;

/* Configuration files. */
char *CONFFILE = "./apm.conf";
char *EXCEPTIONSFILE = "./exceptions.conf";
char *SCANCHECKFILE = "./scanchk.conf";
char *PROTOCOLSFILE = "./protocols.conf";
char *REGIONSFILE = "./regions.conf";

static char *PIDFILE = "./apm.pid";

/* Alarm stuff. */
static int ALARMED;
static struct sigaction ALARMACTION;
static struct sigaction INTACTION;

/* Remove our PID file. Done at exit. */
static __inline__ void remove_pidfile(void) {

	remove(PIDFILE);
}

static void do_signal(int signum) {

	switch (signum) {

		case SIGALRM:
			ALARMED = 1;
			alarm(1);
			break;

		case SIGINT:
			log_event(0, "MAIN -> Caught SIGINT, exiting.");
			fprintf(stderr, "\nCaught SIGINT, exiting.\n");
			exit(EXIT_SUCCESS);
			break;
	}
}

int main(int argc, char **argv) {

	int pid;

	#ifdef HAVE_SYS_RESOURCE_H
	struct rlimit rlim; /* Resource limits. */

	/* Set corefilesize to maximum. */
	if (!getrlimit(RLIMIT_CORE, &rlim)) {

		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}
	#endif

	/* Were we run with a path? */
	if (strchr(argv[0], '/')) {

		char *ptr;

		ptr = strrchr(argv[0], '/');

		*ptr = '\0';

		chdir(argv[0]);
	}

	fprintf(stderr, "\nAzzurra Proxy Monitor starting...");

	/* Fork off. */
	if ((pid = fork()) < 0) {

		log_event(0, "MAIN -> Error in fork(). Aborting.");
		fprintf(stderr, "\nError in fork(). Aborting.\n");
		exit(EXIT_FAILURE);
	}
	else if (pid != 0) {

		FILE *pidout;

		/* Create our pid file. */
		pidout = fopen(PIDFILE, "w");
		fprintf(pidout, "%d\n", pid);
		fclose(pidout);

		/* Started! Wee! */
		fprintf(stderr, "\nRunning in background (pid: %d)\n\n", pid);

		_exit(EXIT_SUCCESS);
	}

	/* Get us in our own process group. */
	if (setpgid(0, 0) < 0) {

		log_event(0, "MAIN -> Error in setpgid(). Aborting.");
		fprintf(stderr, "\nError in setpgid(). Aborting.\n");
		exit(EXIT_FAILURE);
	}

	/* Remove our pid file at exit. */
	atexit(remove_pidfile);

	/* Reset file mode. */
	umask(002);

	/* Close file descriptors. */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	log_open();
	parse_init();

	log_event(0, "MAIN -> APM Started");

	START_TIME = time(NULL);

	/* Setup alarm & int handlers. */
	ALARMACTION.sa_handler = &(do_signal);
	ALARMACTION.sa_flags = SA_RESTART;
	INTACTION.sa_handler = &(do_signal);

	sigaction(SIGALRM, &ALARMACTION, 0);
	sigaction(SIGINT, &INTACTION, 0);

	/* Ignore SIGPIPE. */
	signal(SIGPIPE, SIG_IGN);

	alarm(1);

	while (1) {

		irc_cycle();
		scan_cycle();
		firedns_cycle();
		http_cycle();

		if (ALARMED) {

			irc_timer();
			scan_timer();
			http_timer();
			ALARMED = 0;

			negcache_clear();
		}
	}

	if (!CONF_DEBUG)
		log_close();

	parse_terminate();

	return 0;
}
