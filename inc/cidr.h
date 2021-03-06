/*
 * Azzurra Proxy Monitor - cidr.h
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

#ifndef APM_CIDR_H
#define APM_CIDR_H

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*********************************************************
 * Data types                                            *
 *********************************************************/

struct _CIDR_IP {

	unsigned int ip;
	unsigned int mask;
};

typedef struct _CIDR_IP	CIDR_IP;


/*********************************************************
 * Public code                                           *
 *********************************************************/

unsigned int cidr_to_netmask(unsigned int cidr);
unsigned int cidr_from_netmask(unsigned int mask);

int cidr_match(const CIDR_IP *cidr, unsigned long int ip);

int cidr_ip_fill(const char *source_ip, CIDR_IP *cidr);

#endif	/* APM_CIDR_H */
