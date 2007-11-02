/*
 * Azzurra Proxy Monitor - scan.h
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

#ifndef APM_SCAN_H
#define APM_SCAN_H

#define STATE_UNESTABLISHED		1
#define STATE_WELCOME			2
#define STATE_HANDSHAKE			3
#define STATE_HANDSHAKE_SENT	4
#define STATE_ESTABLISHED		5
#define STATE_SENT				6
#define STATE_CLOSED			7
#define STATE_POSITIVE			8

typedef struct scan_protocol_ scan_protocol;
typedef struct scan_struct_ scan_struct;
typedef int (*scan_function) (scan_struct *);

struct scan_protocol_ {

	scan_protocol *next;

	char *name;						/* Plaintext name of what we're scanning */
	char type;						/* Protocol used */
	unsigned short port;			/* Port to scan protocol on */

	char *welcome_string;

	char *handshake_write_string;	/* String to send to initiate the handshake, if needed (i.e. Socks 5). */
	char *handshake_check_string;	/* String to check for to validate the handshake. */
	size_t handshake_write_string_len;

	scan_function write_handler;	/* Function to handle specific protocol. */
	char *write_string;				/* String to send for this protocol if no handler is given. */
	size_t write_string_len;

	scan_function check_handler;	/* Function to handle the received data. */
	char *check_string;				/* String to check the received data against if no handler is given. */

	char *reason;

	unsigned long int stat_num;
	unsigned long int stat_numopen;
};

struct scan_struct_ {

	scan_struct *next;

	char *addr;						/* Address of remote host (IP) */
	char *irc_addr;					/* Hostname of user on IRC (for kline) */ 
	short equals;					/* addr is the same as irc_addr (i.e. this is an IP) */

	char *irc_nick;					/* Nickname of user on IRC (for logging) */
	char *irc_user;					/* Username of user on IRC (for logging) */
	short requested;				/* Is this a request? */
	short positive;					/* Was this host found to be positive? Needed by negcache. */

	char *data;						/* Buffered data */

	int fd;							/* File descriptor of socket */
	struct sockaddr_in sockaddr;	/* holds information about remote host for socket() */
	time_t create_time;				/* Creation time, for timeout */
	short state;					/* Status of scan */
	size_t bytes_read;				/* Number of bytes received */
	scan_protocol *protocol;		/* Pointer to protocol type */

	Zone *zone;
};

extern void protocols_load(char *filename);
extern int protocols_add(char *string);
extern int protocols_remove(char *string);
extern void protocols_stats(void);
extern void scan_init(void);
extern void scan_rehash(void);
extern void scan_connect(char *addr, char *irc_addr, char *irc_nick, char *irc_user, int equals);
extern void scan_cycle(void);
extern void scan_timer(void);
extern void do_manual_check(char *nick, char *host, int port, char *write_handler, char *check_handler);
extern void do_queue(char *nick, int nolist);
extern int scan_http_result(const http_struct *conn, const int port, const char *type);
extern char *scan_get_method(void);

#endif 
