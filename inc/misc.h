/*
 * Azzurra Proxy Monitor - misc.h
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

#ifndef APM_MISC_H
#define APM_MISC_H

/* Solaris fix. */
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) 0xFFFFFFFF)
#endif

#define	str_equals(string1, string2)					(strcmp((string1), (string2)) == 0)
#define	str_equals_nocase(string1, string2)				(strcasecmp((string1), (string2)) == 0)
#define	str_equals_partial(string1, string2, len)		(strncasecmp((string1), (string2), (len)) == 0)
#define	str_not_equals(string1, string2)				(strcmp((string1), (string2)) != 0)
#define	str_not_equals_nocase(string1, string2)			(strcasecmp((string1), (string2)) != 0)
#define	str_not_equals_partial(string1, string2, len)	(strncasecmp((string1), (string2), (len)) != 0)

#define IS_NULL(x)										((x) == NULL)
#define IS_NOT_NULL(x)									((x) != NULL)

#define getlen(value) (((value) > 99) ? 3 : (((value) > 9) ? 2 : 1))

extern char *dissect_time(time_t timeframe);
extern char *clean(char *str);
extern char *char2ascii(char *string);
extern char *ascii2char(const char *string, size_t len);
extern char *ascii2int(const char *string, size_t len);
extern unsigned long int aton(const char *host);
extern char *str_tokenize(const char *string, char *token, size_t token_len, char delimiter);

#endif
