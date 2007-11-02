/*
 * Azzurra Proxy Monitor - firedns.h
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
 *	FireDNS is copyright (C) 2002 Ian Gulliver
 *
 */

/* $Id */

#ifndef APM_FIREDNS_H
#define APM_FIREDNS_H

/* Maximum number of nameservers used. */
#define FDNS_MAX			8

/* Number of seconds to wait for a reply. */
#define FDNS_TIMEOUT		5

/* Error codes. */
#define FDNS_ERR_NONE		0
#define FDNS_ERR_FORMAT		1
#define FDNS_ERR_SERVFAIL	2
#define FDNS_ERR_NXDOMAIN 	3
#define FDNS_ERR_NOIMPT		4
#define FDNS_ERR_REFUSED	5

/* Local error codes */
#define FDNS_ERR_TIMEOUT	6
#define FDNS_ERR_PAYLOAD	7
#define FDNS_ERR_QR			8
#define FDNS_ERR_OPCODE		9
#define FDNS_ERR_NOANSWER	10
#define FDNS_ERR_QLEN		11
#define FDNS_ERR_ALEN		12
#define FDNS_ERR_RRLEN		13


typedef struct _Zone Zone;
struct _Zone {

	char *name;
	int idx;

	struct sockaddr_in sockaddr;
	char *host;
	char *url;
	char *message;
};

typedef struct _fdns_result fdns_result;
struct _fdns_result {

	char	nick[31];				/* Nick used on IRC, or nick of who requested it. */
	char	username[11];			/* Username used on IRC (NULL if requested). */
	char	host[128];				/* Host used on IRC. */

	short	requested;				/* Was it requested? */
	short	equals;					/* IP == host */

	char	ip[16];					/* Original IP. */
	unsigned short int port;		/* Port (if any). */

	Zone	*zone;				/* Index of blacklist zone. */

	int		error;
	int		count;
	char	text[8][1024];
};

#define FlagSet(v, f)       (((v) & (f)) != 0)
#define FlagUnset(v, f)     (((v) & (f)) == 0)

extern Zone *ZoneArray[4];

extern void firedns_init(void);
extern void firedns_cycle(void);
extern void do_nslist(char *nick);

extern void dnsbl_check(const char *ip, const char *nick, const char *username, const char *host, int equals);

#endif /* APM_FIREDNS_H */
