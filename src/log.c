/*
 * Azzurra Proxy Monitor - log.c
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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "../inc/config.h"
#include "../inc/irc.h"

static FILE *logfile;

void log_open(void) {

	logfile = fopen("./apm.log", "a");

	if (!logfile) {

		fprintf(stderr, "\nCannot open log file [apm.log]. Aborting.\n");
		exit(EXIT_FAILURE);
	}
}

void log_close(void) {

	fclose(logfile);
}

void log_event(const int level, const char *fmt, ...) {

	char buffer[4096];
	char timebuf[64];
	va_list arglist;
	time_t present;
	struct tm *tm_present;

	if (logfile == NULL)
		return;

	if (CONF_DEBUG < level)
		return;

	time(&present);
	tm_present = gmtime(&present);
	strftime(timebuf, sizeof(timebuf), "%b %d %H:%M:%S %Y", tm_present);

	va_start(arglist, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, arglist);
	va_end(arglist);

	fprintf(logfile, "[%s] %s\n", timebuf, buffer);
	fflush(logfile);
}

void log_snoop(const char *fmt, ...) {

	if (!SYNCHED)
		return;

	if (fmt) {

		char log_buffer[1024];
		va_list	args;

		log_buffer[0] = '\0';
		va_start(args, fmt);
		vsnprintf(log_buffer, sizeof(log_buffer), fmt, args);
		va_end(args);

		irc_send("PRIVMSG #apm :%s", log_buffer);
	}
}
