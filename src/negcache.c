/*
 * Azzurra Proxy Monitor - negcache.c
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../inc/setup.h"

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include "../inc/config.h"
#include "../inc/log.h"
#include "../inc/negcache.h"

static Cache *CacheList = NULL;

int check_cache(const unsigned long ip) {

	Cache *c;

	if (ip) {

		c = CacheList;

		while (c != NULL) {

			if (c->ip == ip)
				return 1;

			c = c->next;
		}
	}

	return 0;
}

/* Prepare an ASCII string representing an IPv4 address for inserting into our negative cache. */
int negcache_insert(const char *ipstr) {

	struct sockaddr_in ip;
	Cache *c;

	if (!inet_pton(AF_INET, ipstr, &(ip.sin_addr))) {

		log_snoop("Invalid IPv4 address '%s'", ipstr);
		return 0;
	}

	c = (Cache *) calloc(1, sizeof(Cache));

	if (!c)
		return 0;

	c->ip = ip.sin_addr.s_addr;
	c->seen = time(NULL);
	c->next = CacheList;
	CacheList = c;

	return 1;
}

void negcache_clear() {

	Cache *cache, *swap, *cachePrev = NULL;
	time_t expire = time(NULL) - 3600;

	cache = CacheList;

	while (cache != NULL) {

		if (cache->seen < expire) {

			if (cachePrev != NULL)
				cachePrev->next = cache->next;
			else
				CacheList = cache->next;

			swap = cache->next;

			free(cache);
			cache = swap;
		}
		else {

			cachePrev = cache;
			cache = cache->next;
		}
	}
}
