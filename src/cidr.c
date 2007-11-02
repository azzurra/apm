/*
 * Azzurra Proxy Monitor - cidr.c
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


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include <string.h>
#include <stdlib.h>

#include "../inc/cidr.h"


/*********************************************************
 * Public code                                           *
 *********************************************************/

unsigned int cidr_to_netmask(const unsigned int cidr) {

	return (cidr == 0) ? 0 : (0xFFFFFFFF - (1 << (32 - cidr)) + 1);
}


unsigned int cidr_from_netmask(const unsigned int mask)  {

	int tmp = 0;

	while (!(mask & (1 << tmp)) && (tmp < 32))
		++tmp;

	return (32 - tmp);
}


int cidr_match(const CIDR_IP *cidr, const unsigned long ip) {

	return cidr ? ((ip & cidr->mask) == cidr->ip) : 0;
}


int cidr_ip_fill(const char *source_ip, CIDR_IP *cidr) {

	char			ip[64];
	char			*ptr, *slash_ptr;
	short int		numCount, dotCount;
	int				lastIsDot, slashFound, cidr_size;
	unsigned long	net_address, host_address;

	
	if (!cidr || !source_ip || !*source_ip)
		return 0;

	strncpy(ip, source_ip, sizeof(ip));

	dotCount = numCount = 0;
	lastIsDot = slashFound = 0;

	for (slash_ptr = NULL, ptr = ip; *ptr; ++ptr) {

		switch (*ptr) {

			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				++numCount;
				lastIsDot = 0;
				break;

			case '.':
				if (lastIsDot || // ".." ?
					slashFound)  // "1.2.3.4/*.*"
					return 0;

				++dotCount;
				lastIsDot = 1;
				break;

			case '/':
				if (slashFound || // "*//*"
					lastIsDot) // "*./*"
					return 0;

				slash_ptr = ptr;
				slashFound = 1;
				lastIsDot = 0;
				break;

			default:
				return 0;
		}
	}

	if ((dotCount != 3) || !numCount)
		return 0;

	if (slashFound && slash_ptr) {

		char *err;

		*slash_ptr = '\0';
		++slash_ptr;

		cidr_size = strtol(slash_ptr, &err, 10);

		if ((*err != '\0') || cidr_size < 0 || cidr_size > 32)
			return 0;
	}
	else
		return 0;

	if ((host_address = inet_addr(ip)) == INADDR_NONE)
		return 0;

	net_address = htonl(cidr_to_netmask(cidr_size));
	host_address &= net_address;

	cidr->ip = host_address;
	cidr->mask = net_address;

	return 1;
}


