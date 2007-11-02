/*
 * Azzurra Proxy Monitor - misc.c
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
#include <string.h>
#include <time.h>

#include "../inc/misc.h"


/*
 * Split a time_t into an English-language explanation of how
 * much time it represents, e.g. "2 hours 45 minutes 8 seconds"
 */
char *dissect_time(time_t timeframe) {

	static char buf[64];
	unsigned int years, weeks, days, hours, minutes, seconds;

	years = weeks = days = hours = minutes = seconds = 0;

	while (timeframe >= 60 * 60 * 24 * 365) {

		timeframe -= 60 * 60 * 24 * 365;
		years++;
	}

	while (timeframe >= 60 * 60 * 24 * 7) {

		timeframe -= 60 * 60 * 24 * 7;
		weeks++;
	}

	while (timeframe >= 60 * 60 * 24) {

		timeframe -= 60 * 60 * 24;
		days++;
	}

	while (timeframe >= 60 * 60) {

		timeframe -= 60 * 60;
		hours++;
	}

	while (timeframe >= 60) {

		timeframe -= 60;
		minutes++;
	}

	seconds = timeframe;

	if (years)
		snprintf(buf, sizeof(buf), "%d year%s, %d week%s, %d day%s, %02d:%02d:%02d",
			years, years == 1 ? "" : "s", weeks, weeks == 1 ? "" : "s", days, days == 1 ? "" : "s",
			hours, minutes, seconds);

	else if (weeks)
		snprintf(buf, sizeof(buf), "%d week%s, %d day%s, %02d:%02d:%02d", weeks,
			weeks == 1 ? "" : "s", days, days == 1 ? "" : "s", hours, minutes, seconds);

	else if (days)
		snprintf(buf, sizeof(buf), "%d day%s, %02d:%02d:%02d",
			days, days == 1 ? "" : "s", hours, minutes, seconds);

	else if (hours) {

		if (minutes || seconds)
			snprintf(buf, sizeof(buf), "%d hour%s, %d minute%s, %d second%s", hours,
				hours == 1 ? "" : "s", minutes, minutes == 1 ? "" : "s", seconds, seconds == 1 ? "" : "s");

		else
			snprintf(buf, sizeof(buf), "%d hour%s", hours, hours == 1 ? "" : "s");

	}
	else if (minutes)
		snprintf(buf, sizeof(buf), "%d minute%s, %d second%s",
			minutes, minutes == 1 ? "" : "s", seconds, seconds == 1 ? "" : "s");

	else
		snprintf(buf, sizeof(buf), "%d second%s", seconds, seconds == 1 ? "" : "s");

	return(buf);
}

/*
 * Strip leading/tailing characters from null terminated str and return a
 * pointer to the new string.
 */

char *clean(char *str) {

	size_t i, len;

	int lastnon = 0;		/* Position of last non space. */
	int firstnon = 0;		/* Position of first non space. */

	len = strlen(str);

	/* Dont need to deal with 1 character */ 
	if (len <= 1)
		return str;

	for (i = 0; i < len; i++) {

		if (firstnon == 0 && str[i] != ' ')
			firstnon = i;

		if (str[i] != ' ')
			lastnon = i;
	}

	/* Null terminate before the trailing spaces. */ 
	str[lastnon + 1] = 0;
	
	/* Return pointer to point after leading spaces. */
	return (str + (firstnon - 1));
}

char *char2ascii(char *string) {

	static char buffer[4096];
	unsigned int bufIdx = 0;
	char *ptr = string;

	while (*ptr) {

		if (*ptr == '\\') {

			switch (*(ptr + 1)) {

				case 'r':	buffer[bufIdx++] = '\r';	break;
				case 't':	buffer[bufIdx++] = '\t';	break;
				default:	buffer[bufIdx++] = '\n';	break;
			}

			++ptr;
		}
		else
			buffer[bufIdx++] = *ptr;

		++ptr;

		if (bufIdx > (sizeof(buffer) - 20))
			break;
	}

	buffer[bufIdx] = '\0';
	return buffer;
}

char *ascii2char(const char *string, size_t len) {

	static char buffer[4096];
	unsigned int idx, bufIdx = 0;

	for (idx = 0; idx < len; ++idx) {

		if (string[idx] == '\r') {

			buffer[bufIdx++] = '\\';
			buffer[bufIdx++] = 'r';
		}
		else if (string[idx] == '\n') {

			buffer[bufIdx++] = '\\';
			buffer[bufIdx++] = 'n';
		}
		else if (string[idx] == '\t') {

			buffer[bufIdx++] = '\\';
			buffer[bufIdx++] = 't';
		}
		else if (string[idx] < 32) {

			int ascii = string[idx];

			buffer[bufIdx++] = '\\';

			if (ascii > 9) {

				buffer[bufIdx++] = (ascii % 10) + 48;
				ascii -= (ascii % 10) * 10;
			}

			buffer[bufIdx++] = ascii + 48;
		}
		else
			buffer[bufIdx++] = string[idx];

		if (bufIdx > (sizeof(buffer) - 20))
			break;
	}

	buffer[bufIdx] = '\0';
	return buffer;
}

char *ascii2int(const char *string, size_t len) {

	static char buffer[4096];
	unsigned int idx, bufIdx = 0;

	memset(buffer, 0, sizeof(buffer));

	for (idx = 0; idx < len; ++idx) {

		if (string[idx] == '\r') {

			buffer[bufIdx++] = '\\';
			buffer[bufIdx++] = 'r';
		}
		else if (string[idx] == '\n') {

			buffer[bufIdx++] = '\\';
			buffer[bufIdx++] = 'n';
		}
		else if (string[idx] == '\t') {

			buffer[bufIdx++] = '\\';
			buffer[bufIdx++] = 't';
		}
		else if (string[idx] < 32) {

			int ascii = string[idx];

			buffer[bufIdx++] = '\\';

			if (ascii > 9) {

				buffer[bufIdx++] = (ascii % 10) + 48;
				ascii -= (ascii % 10) * 10;
			}

			buffer[bufIdx++] = ascii + 48;
		}
		else
			buffer[bufIdx++] = string[idx];

		buffer[bufIdx++] = ' ';
		buffer[bufIdx++] = '(';

		snprintf(buffer + bufIdx, sizeof(buffer) - bufIdx, "%3d", (unsigned int)string[idx]);

		bufIdx += 3;

		buffer[bufIdx++] = ')';
		buffer[bufIdx++] = ' ';

		if (bufIdx > (sizeof(buffer) - 20))
			break;
	}

	buffer[bufIdx] = '\0';
	return buffer;
}

unsigned long int aton(const char *host) {

	unsigned long int res;
	unsigned char *bytes = (unsigned char *) &res;
	long int quad;
	char *endptr;


	if (!host)
		return INADDR_NONE;

	/* Quad #1. */
	quad = strtol(host, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr == '\0') || (*endptr != '.'))
		return INADDR_NONE;

	bytes[0] = (unsigned char) quad;

	/* Quad #2. */
	quad = strtol(endptr + 1, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr == '\0') || (*endptr != '.'))
		return INADDR_NONE;

	bytes[1] = (unsigned char) quad;

	/* Quad #3. */
	quad = strtol(endptr + 1, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr == '\0') || (*endptr != '.'))
		return INADDR_NONE;

	bytes[2] = (unsigned char) quad;

	/* Quad #4. */
	quad = strtol(endptr + 1, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr != '\0'))
		return INADDR_NONE;

	bytes[3] = (unsigned char) quad;

	return res;
}

/*********************************************************
 * str_tokenize()                                        *
 *                                                       *
 * string     : source string                            *
 * token      : target buffer                            *
 * token_len  : buffer size                              *
 * delimiters : delimiters set                           *
 *********************************************************/

char *str_tokenize(const char *string, char *token, size_t token_len, char delimiter) {

	char *lim;

	if ((string == NULL) || (string[0] == '\0'))
		return NULL;

	lim = token + token_len - 1;

	while (*string && (token < lim)) {

		if (*string == delimiter) {

			*token = 0;
			return (char *) (string + 1);
		}

		*token++ = *string++;
	}

	*token = 0;

	return (char *)string;
}
