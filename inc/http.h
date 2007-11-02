/*
 * Azzurra Proxy Monitor - http.h
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

#ifndef APM_HTTP_H
#define APM_HTTP_H

/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct http_struct_ http_struct;
struct http_struct_ {

	http_struct *next;

	char ip[16];					/* Address of remote host (IP) */
	char nick[31];

	Zone *zone;

	int fd;							/* File descriptor of socket */
	struct sockaddr_in sockaddr;	/* holds information about remote host for socket() */
	time_t create_time;				/* Creation time, for timeout */
	short state;					/* Status of this connection */
	size_t bytes_read;				/* Number of bytes received */

	int requested;

	char *url;
	char response[65536];			/* Buffered data */
};


extern void http_send_request(const fdns_result *res);
extern void http_cycle(void);
extern void http_timer(void);
extern void do_httpqueue(char *nick, int nolist);
extern void http_remove_connections(const struct sockaddr_in saddr);

#endif 
