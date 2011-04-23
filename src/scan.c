/*
 * Azzurra Proxy Monitor - scan.c
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

#include "../inc/setup.h"

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <sys/resource.h>

#include "../inc/config.h"
#include "../inc/irc.h"
#include "../inc/log.h"
#include "../inc/match.h"
#include "../inc/misc.h"
#include "../inc/negcache.h"
#include "../inc/options.h"
#include "../inc/regions.h"
#include "../inc/firedns.h"
#include "../inc/http.h"
#include "../inc/scan.h"

#if defined(FORCE_SELECT) && defined(HAVE_SYS_SELECT_H)
# define USING_SELECT
#elif defined(FORCE_POLL) && defined(HAVE_SYS_POLL_H)
# include <sys/poll.h>	// For Poll
# define USING_POLL
#elif defined(FORCE_EPOLL) && defined(HAVE_SYS_EPOLL_H)
# include <sys/epoll.h>	// For EPoll
# define USING_EPOLL
#elif defined(FORCE_KQUEUE) && defined(HAVE_SYS_EVENT_H)
# include <sys/event.h>	// For KQueue
# define USING_KQUEUE
#else
# if defined(HAVE_SYS_EVENT_H)
#  include <sys/event.h>	// For KQueue
#  define USING_KQUEUE
# elif defined(HAVE_SYS_EPOLL_H)
#  include <sys/epoll.h>	// For EPoll
#  define USING_EPOLL
# elif defined(HAVE_SYS_POLL_H)
#  include <sys/poll.h>	// For Poll
#  define USING_POLL
# elif defined(HAVE_SYS_SELECT_H)
#  define USING_SELECT
# else
#  error "No valid method found."
# endif
#endif

static void scan_establish(scan_struct *conn);
static void scan_check(void);
static void scan_readready(scan_struct *conn);
static void scan_read(scan_struct *conn);
static void scan_writeready(scan_struct *conn);
static void scan_add(scan_struct *newconn);
static void scan_del(scan_struct *delconn);
static int scan_http_connect(scan_struct *conn);
static int scan_http_post(scan_struct *conn);
static int scan_http_put(scan_struct *conn);
static int scan_ircd(scan_struct *conn);
static int scan_socks4(scan_struct *conn);
static int scan_socks5(scan_struct *conn);
static int scan_cisco(scan_struct *conn);
static int scan_write_string(scan_struct *conn);
static int scan_check_http(scan_struct *conn);
static int scan_check_httpd(scan_struct *conn);
static int scan_check_ircd(scan_struct *conn);
static int scan_check_socks4(scan_struct *conn);
static int scan_check_socks5(scan_struct *conn);
static int scan_check_wingate(scan_struct *conn);
static int scan_check_cisco(scan_struct *conn);
static int scan_check_string(scan_struct *conn);
static int protocol_find(const char type, const int port, const scan_function write_handler, const scan_function check_handler,
	const char *write_string, const char *check_string, const char *handshake_write_string, const char *handshake_check_string);
static char get_state(const scan_struct *conn);

#ifdef USING_KQUEUE
int kqfd = -1;
#endif

#ifdef USING_EPOLL
int epfd = -1;
#endif

/* Linked list head for protocols. */
scan_protocol *SCAN_PROTOCOLS = NULL;

/* Linked list head for connections. */
static scan_struct *CONNECTIONS = NULL;

/* For local bind() */
static struct sockaddr_in SCAN_LOCAL;

#define SCANBUFFER 512
#define SCANBUFFERSIZE SCANBUFFER + 1

/* Stuff to send to check for open ports. */
static char SOCKS4BUF[9];
static char SOCKS5BUF[10];
static char HTTPCONNBUF[512];
static size_t HTTPCONNBUFLEN;
static char HTTPPOSTBUF[512];
static size_t HTTPPOSTBUFLEN;
static char HTTPPUTBUF[512];
static size_t HTTPPUTBUFLEN;
static char CISCOWELCOMEBUF[512];

int protocols_add(char *string) {

	scan_protocol *protocol;
	int port;
	char *ptr;

	if (!string)
		return 0;

	/* Allocate the new protocol struct. */
	protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));


	/* Protocol type. */
	ptr = strtok(string, ":");

	if (!ptr || (ptr[1] != '\0'))
		return 0;

	protocol->type = ptr[0];


	/* Protocol name. */
	ptr = strtok(NULL, ":");

	if (!ptr || (strlen(ptr) > 30))
		return 0;

	protocol->name = strdup(ptr);


	/* Protocol port. */
	ptr = strtok(NULL, ":");

	if (!ptr || ((port = atoi(ptr)) <= 0) || (port > 65535))
		return 0;

	protocol->port = port;


	/* Protocol handshake string. */
	ptr = strtok(NULL, ":");

	if (!ptr)
		return 0;

	else if (str_not_equals_nocase(ptr, "NULL")) {

		protocol->handshake_write_string = strdup(char2ascii(ptr));
		protocol->handshake_write_string_len = strlen(protocol->handshake_write_string);
	}

	/* Protocol validation string. */
	ptr = strtok(NULL, ":");

	if (!ptr)
		return 0;

	else if (str_not_equals_nocase(ptr, "NULL"))
		protocol->handshake_check_string = strdup(char2ascii(ptr));


	/* Protocol write method or string. */
	ptr = strtok(NULL, ":");

	if (!ptr)
		return 0;

	else if (!strcmp(ptr, "CONNECT"))
		protocol->write_handler = &(scan_http_connect);

	else if (!strcmp(ptr, "POST"))
		protocol->write_handler = &(scan_http_post);

	else if (!strcmp(ptr, "PUT"))
		protocol->write_handler = &(scan_http_put);

	else if (!strcmp(ptr, "IRCD"))
		protocol->write_handler = &(scan_ircd);

	else if (!strcmp(ptr, "SOCKS4"))
		protocol->write_handler = &(scan_socks4);

	else if (!strcmp(ptr, "SOCKS5")) {

		protocol->write_handler = &(scan_socks5);
		protocol->handshake_write_string = strdup("\5\1\0");
		protocol->handshake_write_string_len = strlen(protocol->handshake_write_string);
	}
	else if (str_equals_nocase(ptr, "CISCO"))
		protocol->write_handler = &(scan_cisco);

	else if (!strcmp(ptr, "WINGATE"))
		protocol->write_handler = NULL;

	else if (strcmp(ptr, "NULL")) {

		protocol->write_string = strdup(char2ascii(ptr));
		protocol->write_string_len = strlen(protocol->write_string);
		protocol->write_handler = &(scan_write_string);
	}

	/* Protocol read method or string. */
	ptr = strtok(NULL, "");

	if (!ptr)
		return 0;

	else if (!strcmp(ptr, "HTTPD"))
		protocol->check_handler = &(scan_check_httpd);

	else if (!strcmp(ptr, "HTTP"))
		protocol->check_handler = &(scan_check_http);

	else if (!strcmp(ptr, "POST") || !strcmp(ptr, "PUT") || !strcmp(ptr, "IRCD"))
		protocol->check_handler = &(scan_check_ircd);

	else if (!strcmp(ptr, "SOCKS4"))
		protocol->check_handler = &(scan_check_socks4);

	else if (!strcmp(ptr, "SOCKS5")) {

		protocol->handshake_check_string = strdup("\5\0");
		protocol->check_handler = &(scan_check_socks5);
	}
	else if (str_equals_nocase(ptr, "CISCO")) {

		protocol->handshake_check_string = strdup(CISCOWELCOMEBUF);
		protocol->check_handler = &(scan_check_cisco);
	}
	else if (!strcmp(ptr, "WINGATE"))
		protocol->check_handler = &(scan_check_wingate);

	else {

		protocol->check_string = strdup(char2ascii(ptr));
		protocol->check_handler = &(scan_check_string);
	}

	/* Now link the new protocol to the protocols list. */
	protocol->next = SCAN_PROTOCOLS;

	SCAN_PROTOCOLS = protocol;

	return 1;
}

static int protocol_find(const char type, const int port, const scan_function write_handler, const scan_function check_handler,
	const char *write_string, const char *check_string, const char *handshake_write_string, const char *handshake_check_string) {

	scan_protocol *protocol;

	protocol = SCAN_PROTOCOLS;

	while (protocol) {

		if ((protocol->type == type) &&
			(protocol->port == port) &&
			(protocol->write_handler == write_handler) &&
			(protocol->check_handler == check_handler) &&
			(protocol->write_string ? (write_string && !strcmp(protocol->write_string, write_string)) : (write_string == NULL)) &&
			(protocol->check_string ? (check_string && !strcmp(protocol->check_string, check_string)) : (write_string == NULL)) &&
			(protocol->handshake_write_string ? (handshake_write_string && !strcmp(protocol->handshake_write_string, handshake_write_string)) : (handshake_write_string == NULL)) &&
			(protocol->handshake_check_string ? (handshake_check_string && !strcmp(protocol->handshake_check_string, handshake_check_string)) : (handshake_check_string == NULL)))
			return 1;

		protocol = protocol->next;
	}

	return 0;
}

int protocols_remove(char *string) {

	int port, result = 0;
	char type;
	char *ptr, *name = NULL;
	scan_function write_handler = NULL, check_handler = NULL;
	char *handshake_write_string = NULL, *handshake_check_string = NULL;
	char *write_string = NULL, *check_string = NULL;
	scan_protocol *protocol, *prev = NULL;

	if (!string)
		return result;

	/* Protocol type. */
	ptr = strtok(string, ":");

	if (!ptr || (ptr[1] != '\0'))
		goto free;

	type = ptr[0];


	/* Protocol name. */
	ptr = strtok(NULL, ":");

	if (!ptr || (strlen(ptr) > 30))
		goto free;

	name = strdup(ptr);


	/* Protocol port. */
	ptr = strtok(NULL, ":");

	if (!ptr || ((port = atoi(ptr)) <= 0) || (port > 65535))
		goto free;


	/* Protocol handshake string. */
	ptr = strtok(NULL, ":");

	if (!ptr)
		goto free;

	else if (strcmp(ptr, "NULL"))
		handshake_write_string = strdup(char2ascii(ptr));


	/* Protocol handshake check string. */
	ptr = strtok(NULL, ":");

	if (!ptr)
		goto free;

	else if (strcmp(ptr, "NULL"))
		handshake_check_string = strdup(char2ascii(ptr));


	/* Protocol write method or string. */
	ptr = strtok(NULL, ":");

	if (!ptr)
		goto free;

	else if (!strcmp(ptr, "CONNECT"))
		write_handler = &(scan_http_connect);

	else if (!strcmp(ptr, "POST"))
		write_handler = &(scan_http_post);

	else if (!strcmp(ptr, "PUT"))
		write_handler = &(scan_http_put);

	else if (!strcmp(ptr, "IRCD"))
		write_handler = &(scan_ircd);

	else if (!strcmp(ptr, "SOCKS4"))
		write_handler = &(scan_socks4);

	else if (!strcmp(ptr, "SOCKS5")) {

		write_handler = &(scan_socks5);
		handshake_write_string = strdup("\5\1\0");
	}
	else if (!strcmp(ptr, "CISCO"))
		write_handler = &(scan_cisco);

	else if (!strcmp(ptr, "WINGATE"))
		write_handler = NULL;

	else if (strcmp(ptr, "NULL")) {

		write_string = strdup(char2ascii(ptr));
		write_handler = &(scan_write_string);
	}


	/* Protocol read method or string. */
	ptr = strtok(NULL, "");

	if (!ptr)
		goto free;

	else if (!strcmp(ptr, "HTTPD"))
		check_handler = &(scan_check_httpd);

	else if (!strcmp(ptr, "HTTP"))
		check_handler = &(scan_check_http);

	else if (!strcmp(ptr, "POST") || !strcmp(ptr, "PUT") || !strcmp(ptr, "IRCD"))
		check_handler = &(scan_check_ircd);

	else if (!strcmp(ptr, "SOCKS4"))
		check_handler = &(scan_check_socks4);

	else if (!strcmp(ptr, "SOCKS5")) {

		handshake_check_string = strdup("\5\0");
		check_handler = &(scan_check_socks5);
	}
	else if (!strcmp(ptr, "CISCO")) {

		handshake_check_string = strdup(CISCOWELCOMEBUF);
		check_handler = &(scan_check_cisco);
	}
	else if (!strcmp(ptr, "WINGATE"))
		check_handler = &(scan_check_wingate);

	else {

		check_string = strdup(char2ascii(ptr));
		check_handler = &(scan_check_string);
	}


	protocol = SCAN_PROTOCOLS;

	while (protocol) {

		if ((protocol->type == type) && (protocol->port == port) && !strcasecmp(protocol->name, name) &&
			(protocol->write_handler == write_handler) && (protocol->check_handler == check_handler) &&
			(protocol->write_string ? (write_string && !strcmp(protocol->write_string, write_string)) : (write_string == NULL)) &&
			(protocol->check_string ? (check_string && !strcmp(protocol->check_string, check_string)) : (write_string == NULL)) &&
			(protocol->handshake_write_string ? (handshake_write_string && !strcmp(protocol->handshake_write_string, handshake_write_string)) : (handshake_write_string == NULL)) &&
			(protocol->handshake_check_string ? (handshake_check_string && !strcmp(protocol->handshake_check_string, handshake_check_string)) : (handshake_check_string == NULL))) {

			/* Found it, remove. */
			if (prev)
				prev->next = protocol->next;
			else
				SCAN_PROTOCOLS = protocol->next;

			if (protocol->name)
				free(protocol->name);

			if (protocol->handshake_write_string)
				free(protocol->handshake_write_string);

			if (protocol->handshake_check_string)
				free(protocol->handshake_check_string);

			if (protocol->write_string)
				free(protocol->write_string);

			if (protocol->check_string)
				free(protocol->check_string);

			free(protocol);
			result = 1;
			goto free;
		}

		prev = protocol;
		protocol = protocol->next;
	}

free:
	if (name)
		free(name);

	if (handshake_write_string)
		free(handshake_write_string);

	if (handshake_check_string)
		free(handshake_check_string);

	if (write_string)
		free(write_string);

	if (check_string)
		free(check_string);

	return result;
}

static void protocols_clear(void) {

	scan_protocol *protocol, *next;

	protocol = SCAN_PROTOCOLS;

	while (protocol) {

		next = protocol->next;

		if (protocol->name)
			free(protocol->name);

		if (protocol->handshake_write_string)
			free(protocol->handshake_write_string);

		if (protocol->handshake_check_string)
			free(protocol->handshake_check_string);

		if (protocol->write_string)
			free(protocol->write_string);

		if (protocol->check_string)
			free(protocol->check_string);

		free(protocol);
		protocol = next;
	}

	SCAN_PROTOCOLS = NULL;
}

void protocols_load(char *filename) {

	/* 1k buffer for reading the file. */
	char line[1024];
	size_t len;
	FILE *in;

	log_event(0, "CONFIG -> Reading protocols file...");

	if (!(in = fopen(filename, "r"))) {

		log_event(0, "CONFIG -> No exceptions file found.");
		return;
	}

	/* Initialize the list. */
	protocols_clear();

	/* Initialize the string list. */
	free_list(CONF_PROTOCOLS);
	CONF_PROTOCOLS = NULL;

	/* Read data from file and fill the new list. */
	while (fgets(line, sizeof(line), in)) {

		len = strlen(line);

		if (line[len - 1] == '\n') {

			if (line[len - 2] == '\r')
				line[len - 2] = '\0';
			else
				line[len - 1] = '\0';
		}

		if (line[0] == '\0')
			continue;

		/* Strip leading and trailing spaces. */
		clean(line);

		/* Add it to the list. */
		if (add_to_list(&CONF_PROTOCOLS, line)) {

			log_event(0, "CONFIG -> Added scan protocol: %s", line);

			if (!protocols_add(line)) {

				log_event(0, "CONFIG -> Error loading scan protocol: %s", line);
				fprintf(stderr, "\nInvalid protocols file detected. Aborting.\n");
				exit(EXIT_FAILURE);
			}
		}
		else
			log_event(0, "WARNING: Duplicate protocol found: %s", line);
	}

	fclose(in);
}

void scan_init(void) {

	unsigned long int ip;
	struct rlimit rlim;

	if (CONF_FDLIMIT == 0) {

		if (!getrlimit(RLIMIT_NOFILE, &rlim))
			CONF_FDLIMIT = rlim.rlim_cur;
	}

	/* Set corefilesize to maximum. */
	if (!getrlimit(RLIMIT_CORE, &rlim)) {

		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}

	ip = inet_addr(CONF_SERVER);
	ip = htonl(ip);

	/* Fill in the Socks 4 buffer. */
	SOCKS4BUF[0] = 4;
	SOCKS4BUF[1] = 1;
	SOCKS4BUF[2] = ((CONF_PORT >> 8) & 0xFF);
	SOCKS4BUF[3] = (CONF_PORT & 0xFF);
	SOCKS4BUF[4] = (ip >> 24) & 0xFF;
	SOCKS4BUF[5] = (ip >> 16) & 0xFF;
	SOCKS4BUF[6] = (ip >> 8) & 0xFF;
	SOCKS4BUF[7] = ip & 0xFF;
	SOCKS4BUF[8] = 0;

	/* Fill in the Socks 5 buffer. */
	SOCKS5BUF[0] = 5;
	SOCKS5BUF[1] = 1;
	SOCKS5BUF[2] = 0;
	SOCKS5BUF[3] = 1;
	SOCKS5BUF[4] = (ip >> 24) & 0xFF;
	SOCKS5BUF[5] = (ip >> 16) & 0xFF;
	SOCKS5BUF[6] = (ip >> 8) & 0xFF;
	SOCKS5BUF[7] = ip & 0xFF;
	SOCKS5BUF[8] = ((CONF_PORT >> 8) & 0xFF);
	SOCKS5BUF[9] = (CONF_PORT & 0xFF);

	/* Fill in the Cisco Welcome buffer. */
	CISCOWELCOMEBUF[0] = -1;
	CISCOWELCOMEBUF[1] = -5;
	CISCOWELCOMEBUF[2] = 1;
	CISCOWELCOMEBUF[3] = -1;
	CISCOWELCOMEBUF[4] = -5;
	CISCOWELCOMEBUF[5] = 3;
	CISCOWELCOMEBUF[6] = -1;
	CISCOWELCOMEBUF[7] = -3;
	CISCOWELCOMEBUF[8] = 24;
	CISCOWELCOMEBUF[9] = -1;
	CISCOWELCOMEBUF[10] = -3;
	CISCOWELCOMEBUF[11] = 31;
	strncpy(CISCOWELCOMEBUF + 12, "*User Access Verification\r\n\r\nPassword: ", 42);

	/* Fill in the HTTP CONNECT buffer. */
	snprintf(HTTPCONNBUF, 512, "CONNECT %s:%u HTTP/1.0\r\n\r\n", CONF_SERVER, CONF_PORT);
	HTTPCONNBUFLEN = strlen(HTTPCONNBUF);

	/* Fill in the HTTP POST buffer. */
	snprintf(HTTPPOSTBUF, 512, "POST http://%s:%u/ HTTP/1.0\r\n"
								   "Content-type: text/plain\r\n"
								   "Content-length: 5\r\n\r\n"
								   "quit\r\n\r\n", CONF_SERVER, CONF_PORT);
	HTTPPOSTBUFLEN = strlen(HTTPPOSTBUF);

	/* Fill in the HTTP PUT buffer. */
	snprintf(HTTPPUTBUF, 512, "PUT http://%s:%u/ HTTP/1.0\r\n"
								   "Content-type: text/plain\r\n"
								   "Content-length: 5\r\n\r\n"
								   "quit\r\n\r\n", CONF_SERVER, CONF_PORT);
	HTTPPUTBUFLEN = strlen(HTTPPUTBUF);

	/* For local bind() */
	if (CONF_BINDSCAN) {

		memset(&SCAN_LOCAL, 0, sizeof(struct sockaddr_in));

		if (!inet_aton(CONF_BINDSCAN, &(SCAN_LOCAL.sin_addr))) {

			log_event(0, "SCAN -> Bind scan IP [%s] is invalid.", CONF_BINDSCAN);
			fprintf(stderr, "\nBind scan IP [%s] is invalid.\n", CONF_BINDSCAN);
			exit(EXIT_FAILURE);
		}

		SCAN_LOCAL.sin_family = AF_INET;
		SCAN_LOCAL.sin_port = 0;
	}

	#ifdef USING_KQUEUE
	kqfd = kqueue();

	if (kqfd < 0) {

		log_event(0, "SCAN -> Failed to initialize kqueue (error %d)", errno);
		exit(EXIT_FAILURE);
	}
	#endif

	#ifdef USING_EPOLL
	epfd = epoll_create(CONF_FDLIMIT);

	if (epfd < 0) {

		log_event(0, "SCAN -> Failed to initialize epoll (error %d)", errno);
		exit(EXIT_FAILURE);
	}
	#endif
}


/*********************************************************
 * We received a +c notice from the remote server.       *
 * scan_connect() is called with the connecting IP,      *
 * where we will begin to establish the proxy testing.   *
 *********************************************************/

void scan_connect(char *addr, char *irc_addr, char *irc_nick, char *irc_user, int equals) {

	scan_struct *newconn;
	scan_protocol *protocol = SCAN_PROTOCOLS;
	struct sockaddr_in sockaddr;


	sockaddr.sin_addr.s_addr = inet_addr(addr);

	for (newconn = CONNECTIONS; newconn; newconn = newconn->next) {

		if (newconn->sockaddr.sin_addr.s_addr == sockaddr.sin_addr.s_addr) {

			/* This host is already being scanned. */
			return;
		}
	}

	/* Loop through the protocols creating a separate connection struct for each port/protocol. */

	while (protocol) {

		newconn = (scan_struct *) calloc(1, sizeof(scan_struct));

		newconn->addr = strdup(addr);

		if (!equals)
			newconn->irc_addr = strdup(irc_addr);

		newconn->equals = equals;

		newconn->irc_nick = strdup(irc_nick);
		newconn->irc_user = strdup(irc_user);

		/* Give struct a link to information about the protocol it will be handling. */
		newconn->protocol = protocol;

		/* Fill in sockaddr with information about remote host. */
		newconn->sockaddr.sin_family = AF_INET;
		newconn->sockaddr.sin_port = htons(protocol->port); 
		newconn->sockaddr.sin_addr.s_addr = sockaddr.sin_addr.s_addr;

		/* Queue connection. */
		newconn->state = STATE_UNESTABLISHED;

		/* Add struct to list of connections. */
		scan_add(newconn);

		/* If we have available FD's, override queue. */
		if (FD_USE < CONF_FDLIMIT)
			scan_establish(newconn);
		else
			log_event(7, "SCAN -> File Descriptor limit (%d) reached, queuing scan for %s", CONF_FDLIMIT, addr);

		protocol = protocol->next;
	}

	if (CONF_DNSBL && !regions_match(addr, irc_addr, 0))
		dnsbl_check(addr, irc_nick, irc_user, irc_addr, equals);
}


/*********************************************************
 * Get FD for new socket, bind to interface and          *
 * connect() (non blocking), then set conn to            *
 * ESTABLISHED for write check, or SENT for direct read  *
 * check (listen without sending data).                  *
 *********************************************************/

static void scan_establish(scan_struct *conn) {

	/* Request file descriptor for socket. */
	conn->fd = socket(PF_INET, SOCK_STREAM, 0);

	/* Increase global FD Use counter. */
	++FD_USE;

	if (CONF_DEBUG > 0) {

		if (conn->requested > 0) {

			switch (conn->protocol->type) {

				case 'C':
				case 'P':
				case 'U':
					if (conn->equals)
						log_event(7, "SCAN -> [Socket %d] Connecting to %s on port %u [%s/%c] [Requested by %s]", conn->fd,
							conn->addr, conn->protocol->port, conn->protocol->name, conn->protocol->type, conn->irc_nick);
					else
						log_event(7, "SCAN -> [Socket %d] Connecting to %s [%s] on port %u [%s/%c] [Requested by %s]", conn->fd,
							conn->irc_addr, conn->addr, conn->protocol->port, conn->protocol->name, conn->protocol->type, conn->irc_nick);
					break;

				default:
					if (conn->equals)
						log_event(7, "SCAN -> [Socket %d] Connecting to %s on port %u [%s] [Requested by %s]", conn->fd,
							conn->addr, conn->protocol->port, conn->protocol->name, conn->irc_nick);
					else
						log_event(7, "SCAN -> [Socket %d] Connecting to %s [%s] on port %u [%s] [Requested by %s]", conn->fd,
							conn->irc_addr, conn->addr, conn->protocol->port, conn->protocol->name, conn->irc_nick);
					break;
			}
		}
		else {

			switch (conn->protocol->type) {

				case 'C':
				case 'P':
				case 'U':
					if (conn->equals)
						log_event(7, "SCAN -> [Socket %d] Connecting to %s on port %u [%s/%c]",
							conn->fd, conn->addr, conn->protocol->port, conn->protocol->name, conn->protocol->type);
					else
						log_event(7, "SCAN -> [Socket %d] Connecting to %s [%s] on port %u [%s/%c]",
							conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, conn->protocol->name, conn->protocol->type);
					break;

				default:
					if (conn->equals)
						log_event(7, "SCAN -> [Socket %d] Connecting to %s on port %u [%s]",
							conn->fd, conn->addr, conn->protocol->port, conn->protocol->name);
					else
						log_event(7, "SCAN -> [Socket %d] Connecting to %s [%s] on port %u [%s]",
							conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, conn->protocol->name);
					break;
			}
		}
	}

	/* If error, mark connection for close. */
	if (conn->fd == -1) {

		log_snoop("SCAN -> Error allocating file descriptor.");
		conn->state = STATE_CLOSED;
		return;
	}

	/* Bind to specific interface designated in conf file. */
	if (CONF_BINDSCAN) {

		if (bind(conn->fd, (struct sockaddr *)&SCAN_LOCAL, sizeof(struct sockaddr_in)) == -1) {

			switch (errno) {

				case EACCES:
					log_event(7, "SCAN -> Error binding to scan IP [%s]: No access.", CONF_BINDSCAN);
					fprintf(stderr, "\nError binding to scan IP [%s]: No access.\n", CONF_BINDSCAN);
					break;

				case EADDRNOTAVAIL:
					log_event(7, "SCAN -> Error binding to scan IP [%s]: Address not available.", CONF_BINDSCAN);
					fprintf(stderr, "\nError binding to scan IP [%s]: Address not available.\n", CONF_BINDSCAN);
					break;

				default:
					log_event(7, "SCAN -> Error %d binding to scan IP [%s]: %s", errno, CONF_BINDSCAN, strerror(errno));
					fprintf(stderr, "\nError %d binding to scan IP [%s]: %s\n", errno, CONF_BINDSCAN, strerror(errno));
					break;
			}

			exit(EXIT_FAILURE);
		}
	}

	/* Log create time of connection for timeouts. */
	time(&(conn->create_time));

	/* Flag conn established (for write). */
	if (conn->protocol->handshake_write_string)
		conn->state = STATE_HANDSHAKE;			// This protocol needs a handshake

	else if (conn->protocol->handshake_check_string)
		conn->state = STATE_HANDSHAKE_SENT;

	else if (conn->protocol->write_handler)
		conn->state = STATE_ESTABLISHED;		// This is a normal send/receive protocol

	else
		conn->state = STATE_SENT;				// This protocol only connects and reads

	/* Set socket non blocking. */
	fcntl(conn->fd, F_SETFL, O_NONBLOCK);

	/* Connect! */
	if ((connect(conn->fd, (struct sockaddr *) &(conn->sockaddr), sizeof(conn->sockaddr)) == -1) && (errno != EINPROGRESS)) {

		if (conn->equals)
			log_event(7, "SCAN -> [Socket %d] Connection refused on %s on port %u [Error %d: %s]",
				conn->fd, conn->addr, conn->protocol->port, errno, strerror(errno));
		else
			log_event(7, "SCAN -> [Socket %d] Connection refused on %s [%s] on port %u [Error %d: %s]",
				conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, errno, strerror(errno));

		scan_del(conn);
		return;
	}

	/* Allocate memory for the scan buffer. */
	conn->data = (char *) malloc(SCANBUFFERSIZE * sizeof(char));
}


/*********************************************************
 * Pass one cycle to the proxy scanner so it can do      *
 * necessary functions like testing for sockets to be    *
 * written to and read from.                             *
 *********************************************************/

void scan_cycle(void) {

	if (CONNECTIONS)
		scan_check();
}


/*********************************************************
 * Test for sockets to be written/read to.               *
 *********************************************************/

static void scan_check(void) {

	scan_struct *ss;
	int ready;

#if defined(USING_KQUEUE)
	struct kevent kev, klist[EVENT_CHUNK];
	struct timespec tspec = { 0, 0 };
	int idx = 0;
#elif defined(USING_EPOLL)
	struct epoll_event ev, evlist[EVENT_CHUNK];
	int idx = 0;
#elif defined(USING_POLL)
	static struct pollfd ufds[EVENT_CHUNK];
	int size = 0, idx;
#else
	fd_set w_fdset;
	fd_set r_fdset;
	struct timeval scan_timeout;
	int highfd = 0;
#endif

#ifdef USING_KQUEUE
	for (ss = CONNECTIONS; ss; ss = ss->next) {

		if ((ss->state != STATE_HANDSHAKE) && (ss->state != STATE_HANDSHAKE_SENT) &&
			(ss->state != STATE_ESTABLISHED) && (ss->state != STATE_SENT))
			continue;

		++idx;

		switch (ss->state) {

			case STATE_HANDSHAKE:
				/* We need to send a handshake. */
				// Fall...
			case STATE_ESTABLISHED:
				/* Add this event to the event queue. */
				EV_SET(&kev, ss->fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, &tspec);

				if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0) {

					log_event(8, "SCAN -> [Socket %d (%c)] Failed kevent() for %s on port %u",
						ss->fd, get_state(ss), ss->addr, ss->protocol->port);

					break;
				}

				log_event(8, "SCAN -> [Socket %d (%c)] KQueuing %s on port %u (OUT)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
				break;

			case STATE_HANDSHAKE_SENT:
				/* Handshake was sent, we now need to read the response. */
				// Fall...
			case STATE_SENT:
				/* Add this event to the event queue. */
				EV_SET(&kev, ss->fd, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, &tspec);

				if (kevent(kqfd, &kev, 1, NULL, 0, NULL) < 0) {

					log_event(8, "SCAN -> [Socket %d (%c)] Failed kevent() for %s on port %u",
						ss->fd, get_state(ss), ss->addr, ss->protocol->port);

					return;
				}

				log_event(8, "SCAN -> [Socket %d (%c)] KQueuing %s on port %u (IN)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
				break;

			default:
				log_event(8, "SCAN -> [Socket %d (%c)] KQueuing %s on port %u (?)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
		}

		if (idx >= EVENT_CHUNK)
			break;
	}

#elif defined(USING_EPOLL)
	for (ss = CONNECTIONS; ss; ss = ss->next) {

		if ((ss->state != STATE_HANDSHAKE) && (ss->state != STATE_HANDSHAKE_SENT) &&
			(ss->state != STATE_ESTABLISHED) && (ss->state != STATE_SENT))
			continue;

		++idx;

		switch (ss->state) {

			case STATE_HANDSHAKE:
				/* We need to send a handshake. */
				// Fall...
			case STATE_ESTABLISHED:
				/* Check for NO BLOCK ON WRITE. */
				ev.events = EPOLLOUT;
				ev.data.fd = ss->fd;

				if (epoll_ctl(epfd, EPOLL_CTL_ADD, ss->fd, &ev) < 0) {

					log_event(8, "SCAN -> [Socket %d (%c)] Failed epoll_ctl(ADD/OUT) for %s on port %u",
						ss->fd, get_state(ss), ss->addr, ss->protocol->port);

					break;
				}

				log_event(8, "SCAN -> [Socket %d (%c)] EPolling %s on port %u (OUT)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
				break;

			case STATE_HANDSHAKE_SENT:
				/* Handshake was sent, we now need to read the response. */
				// Fall...
			case STATE_SENT:
				/* Check for data to be read. */
				ev.events = EPOLLIN | EPOLLHUP | EPOLLERR;
				ev.data.fd = ss->fd;

				if (epoll_ctl(epfd, EPOLL_CTL_ADD, ss->fd, &ev) < 0) {

					log_event(8, "SCAN -> [Socket %d (%c)] Failed epoll_ctl(ADD/IN) for %s on port %u",
						ss->fd, get_state(ss), ss->addr, ss->protocol->port);

					return;
				}

				log_event(8, "SCAN -> [Socket %d (%c)] EPolling %s on port %u (IN)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
				break;

			default:
				log_event(8, "SCAN -> [Socket %d (%c)] EPolling %s on port %u (?)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
		}

		if (idx >= EVENT_CHUNK)
			break;
	}

#elif defined(USING_POLL)
	for (ss = CONNECTIONS; ss; ss = ss->next) {

		if ((ss->state != STATE_HANDSHAKE) && (ss->state != STATE_HANDSHAKE_SENT) &&
			(ss->state != STATE_ESTABLISHED) && (ss->state != STATE_SENT))
			continue;

		ufds[size].events = 0;
		ufds[size].revents = 0;
		ufds[size].fd = ss->fd;

		/* Check for HUNG UP. */
		ufds[size].events |= POLLHUP;

		/* Check for INVALID FD */
		ufds[size].events |= POLLNVAL;

		switch (ss->state) {

			case STATE_HANDSHAKE:
				/* We need to send a handshake. */
				// Fall...
			case STATE_ESTABLISHED:
				/* Check for NO BLOCK ON WRITE. */
				ufds[size].events |= POLLOUT;

				log_event(8, "SCAN -> [Socket %d (%c)] Polling %s on port %u (OUT)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
				break;

			case STATE_HANDSHAKE_SENT:
				/* Handshake was sent, we now need to read the response. */
				// Fall...
			case STATE_SENT:
				/* Check for data to be read. */
				ufds[size].events |= POLLIN;

				log_event(8, "SCAN -> [Socket %d (%c)] Polling %s on port %u (IN)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
				break;

			default:
				log_event(8, "SCAN -> [Socket %d (%c)] Polling %s on port %u (?)",
					ss->fd, get_state(ss), ss->addr, ss->protocol->port);
		}

		if (++size >= EVENT_CHUNK)
			break;
	}

#else /* select() */
	FD_ZERO(&w_fdset);
	FD_ZERO(&r_fdset);

	/* Add connections to appropriate sets. */
	for (ss = CONNECTIONS; ss; ss = ss->next) {

		if ((ss->state == STATE_HANDSHAKE) || (ss->state == STATE_ESTABLISHED)) {

			if (ss->fd > highfd)
				highfd = ss->fd;

			FD_SET(ss->fd, &w_fdset);
		}
		else if ((ss->state == STATE_HANDSHAKE_SENT) || (ss->state == STATE_SENT)) {

			if (ss->fd > highfd)
				highfd = ss->fd;

			FD_SET(ss->fd, &r_fdset);
		}
	}

	/* No timeout. */
	scan_timeout.tv_sec = 0;
	scan_timeout.tv_usec = 0;

#endif

#if defined(USING_KQUEUE)
	ready = kevent(kqfd, 0, 0, klist, EVENT_CHUNK, &tspec);
#elif defined(USING_EPOLL)
	ready = epoll_wait(epfd, evlist, EVENT_CHUNK, 0);
#elif defined(USING_POLL)
	ready = poll(ufds, size, 0);
#else /* select() */
	ready = select((highfd + 1), &r_fdset, &w_fdset, 0, &scan_timeout);
#endif

	switch (ready) {

		case -1:	/* Error in select/poll. */
		case 0:		/* Nothing to do. */
			return;

		default:
			/* Pass pointer to connection to handler. */

#if defined(USING_KQUEUE)
			for (ss = CONNECTIONS; ss; ss = ss->next) {

				for (idx = 0; idx < ready; ++idx) {

					if (klist[idx].ident == ss->fd) {

						if ((ss->state == STATE_CLOSED) || (ss->state == STATE_POSITIVE)) {

							log_event(8, "SCAN -> [Socket %d (%c)] Skipped %s on port %u [Closed/Positive]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							break;
						}

						if (FlagSet(klist[idx].flags, EV_ERROR)) {

							/* Negotiation failed (read returned false). Discard the connection as a closed proxy. */

							if (ss->bytes_read) {

								if (ss->equals)
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s on port %u [Read: %s]",
										ss->fd, ss->addr, ss->protocol->port, ascii2char(ss->data, ss->bytes_read));
								else
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s [%s] on port %u [Read: %s]",
										ss->fd, ss->irc_addr, ss->addr, ss->protocol->port, ascii2char(ss->data, ss->bytes_read));
							}
							else {

								if (ss->equals)
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s on port %u",
										ss->fd, ss->addr, ss->protocol->port);
								else
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s [%s] on port %u",
										ss->fd, ss->irc_addr, ss->addr, ss->protocol->port);
							}

							ss->state = STATE_CLOSED;
							break;
						}

						switch (klist[idx].filter) {

							case EVFILT_READ:
								log_event(8, "SCAN -> [Socket %d (%c)] KQueued %s on port %u [READ]",
									ss->fd, get_state(ss), ss->addr, ss->protocol->port);

								scan_readready(ss);
								break;

							case EVFILT_WRITE:
								log_event(8, "SCAN -> [Socket %d (%c)] KQueued %s on port %u [WRITE]",
									ss->fd, get_state(ss), ss->addr, ss->protocol->port);

								scan_writeready(ss);
								break;

							default:
								log_event(8, "SCAN -> [Socket %d (%c)] KQueued %s on port %u [Unknown value: %d]",
									ss->fd, get_state(ss), ss->addr, ss->protocol->port, klist[idx].filter);

								break;
						}

						break;
					}
				}
			}

#elif defined(USING_EPOLL)
			for (ss = CONNECTIONS; ss; ss = ss->next) {

				for (idx = 0; idx < ready; ++idx) {

					if (evlist[idx].data.fd == ss->fd) {

						if ((ss->state == STATE_CLOSED) || (ss->state == STATE_POSITIVE)) {

							log_event(8, "SCAN -> [Socket %d (%c)] Skipped %s on port %u [Closed/Positive]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							break;
						}

						log_event(8, "SCAN -> [Socket %d (%c)] EPolled %s on port %u [%d]",
							ss->fd, get_state(ss), ss->addr, ss->protocol->port, evlist[idx].events);

						if (FlagSet(evlist[idx].events, EPOLLHUP) ||
							FlagSet(evlist[idx].events, EPOLLERR)) {

							/* Negotiation failed (read returned false). Discard the connection as a closed proxy. */

							if (ss->bytes_read) {

								if (ss->equals)
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s on port %u [Read: %s]",
										ss->fd, ss->addr, ss->protocol->port, ascii2char(ss->data, ss->bytes_read));
								else
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s [%s] on port %u [Read: %s]",
										ss->fd, ss->irc_addr, ss->addr, ss->protocol->port, ascii2char(ss->data, ss->bytes_read));
							}
							else {

								if (ss->equals)
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s on port %u",
										ss->fd, ss->addr, ss->protocol->port);
								else
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s [%s] on port %u",
										ss->fd, ss->irc_addr, ss->addr, ss->protocol->port);
							}

							ss->state = STATE_CLOSED;
							break;
						}

						if (FlagSet(evlist[idx].events, EPOLLIN)) {

							log_event(8, "SCAN -> [Socket %d (%c)] EPolled %s on port %u [EPOLLIN]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							scan_readready(ss);
						}

						if (FlagSet(evlist[idx].events, EPOLLOUT)) {

							log_event(8, "SCAN -> [Socket %d (%c)] EPolled %s on port %u [EPOLLOUT]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							scan_writeready(ss);
						}

						break;
					}
				}
			}

#elif defined(USING_POLL)
			for (ss = CONNECTIONS; ss; ss = ss->next) {

				for (idx = 0; idx < size; ++idx) {

					if (ufds[idx].fd == ss->fd) {

						if ((ss->state == STATE_CLOSED) || (ss->state == STATE_POSITIVE)) {

							log_event(8, "SCAN -> [Socket %d (%c)] Skipped %s on port %u [Closed/Positive]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							break;
						}

						log_event(8, "SCAN -> [Socket %d (%c)] Polled %s on port %u [%d]",
							ss->fd, get_state(ss), ss->addr, ss->protocol->port, ufds[idx].revents);

						if (FlagSet(ufds[idx].revents, POLLHUP) ||
							FlagSet(ufds[idx].revents, POLLERR)) {

							/* Negotiation failed (read returned false). Discard the connection as a closed proxy. */

							if (ss->bytes_read) {

								if (ss->equals)
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s on port %u [Read: %s]",
										ss->fd, ss->addr, ss->protocol->port, ascii2char(ss->data, ss->bytes_read));
								else
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s [%s] on port %u [Read: %s]",
										ss->fd, ss->irc_addr, ss->addr, ss->protocol->port, ascii2char(ss->data, ss->bytes_read));
							}
							else {

								if (ss->equals)
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s on port %u",
										ss->fd, ss->addr, ss->protocol->port);
								else
									log_event(7, "SCAN -> [Socket %d] Negotiation failed for %s [%s] on port %u",
										ss->fd, ss->irc_addr, ss->addr, ss->protocol->port);
							}

							ss->state = STATE_CLOSED;
							break;
						}

						if (FlagSet(ufds[idx].revents, POLLIN)) {

							log_event(8, "SCAN -> [Socket %d (%c)] Polled %s on port %u [POLLIN]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							scan_readready(ss);
						}

						if (FlagSet(ufds[idx].revents, POLLOUT)) {

							log_event(8, "SCAN -> [Socket %d (%c)] Polled %s on port %u [POLLOUT]",
								ss->fd, get_state(ss), ss->addr, ss->protocol->port);

							scan_writeready(ss);
						}

						break;
					}
				}
			}
#else

			for (ss = CONNECTIONS; ss; ss = ss->next) {

				if ((ss->state == STATE_HANDSHAKE) || (ss->state == STATE_ESTABLISHED)) {

					if (FD_ISSET(ss->fd, &w_fdset))
						scan_writeready(ss);
				}
				else if ((ss->state == STATE_HANDSHAKE_SENT) || (ss->state == STATE_SENT)) {

					if (FD_ISSET(ss->fd, &r_fdset))
						scan_readready(ss);
				}
			}
#endif
	}
}


/*********************************************************
 * Poll or select returned back that this connection is  *
 * ready for read. Get the data, and pass it to the      *
 * protocol check handler.                               *
 *********************************************************/

static void scan_readready(scan_struct *conn) {

	int len;
	static char dump[1025];

	memset(conn->data, 0, sizeof(conn->data));
	conn->bytes_read = 0;

	errno = 0;

	len = recv(conn->fd, conn->data, SCANBUFFER, 0);

	log_event(8, "SCAN -> [Socket %d (%c)] Read %d bytes from %s on port %u [errno: %d (%s)]",
		conn->fd, get_state(conn), len, conn->addr, conn->protocol->port, errno, strerror(errno));

	switch (len) {

		case -1:	/* Error, or socket was closed. */
			conn->state = STATE_CLOSED;
			/* Fall... */
		case 0:		/* No data read from socket. */
			return;

		case SCANBUFFER:
			/* Get rid of whatever was left on the socket. */
			while (recv(conn->fd, dump, 1024, 0) > 0)
				;

			/* Fall... */

		default:
			conn->bytes_read = len;

			log_event(8, "DEBUG -> [Socket %d] Read: %s", conn->fd, ascii2int(conn->data, conn->bytes_read));

			scan_read(conn);
			return;
	}
}


/*********************************************************
 * Now actually check what we read from the socket       *
 * against the protocol's check handler.                 *
 *********************************************************/

static void scan_read(scan_struct *conn) {

	if (conn->state == STATE_HANDSHAKE_SENT) {

		if (match(conn->protocol->handshake_check_string, conn->data)) {

			if (conn->equals)
				log_event(7, "SCAN -> [Socket %d] Handshake validated by %s on port %u",
					conn->fd, conn->addr, conn->protocol->port);
			else
				log_event(7, "SCAN -> [Socket %d] Handshake validated by %s [%s] on port %u",
					conn->fd, conn->irc_addr, conn->addr, conn->protocol->port);

			conn->state = STATE_ESTABLISHED;
		}
		else {

			if (conn->equals)
				log_event(7, "SCAN -> [Socket %d] Invalid handshake by %s on port %u: %s",
					conn->fd, conn->addr, conn->protocol->port, ascii2char(conn->data, conn->bytes_read));
			else
				log_event(7, "SCAN -> [Socket %d] Invalid handshake by %s [%s] on port %u: %s",
					conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char(conn->data, conn->bytes_read));

			conn->state = STATE_CLOSED;
		}

		return;
	}

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Checking data from %s on port %u: %s",
			conn->fd, conn->addr, conn->protocol->port, ascii2char(conn->data, conn->bytes_read));
	else
		log_event(7, "SCAN -> [Socket %d] Checking data from %s [%s] on port %u: %s",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char(conn->data, conn->bytes_read));

	if ((*conn->protocol->check_handler)(conn)) {

		scan_struct *ss;

		/* Mark it positive. */
		conn->state = STATE_POSITIVE;

		/* Report it. */
		irc_kline(conn->addr, conn->irc_addr, conn->protocol->port, conn->sockaddr.sin_addr.s_addr, conn->protocol->type);

		/* Log it. */
		log_event(0, "OPEN %s -> %s (%s@%s) [%u/%c]", conn->protocol->name, conn->irc_nick, conn->irc_user,
			(conn->equals) ? conn->addr : conn->irc_addr, conn->protocol->port, conn->protocol->type);

		switch (conn->protocol->type) {

			case 'C':
			case 'P':
			case 'U':
				switch (conn->requested) {

					case 3:
					case 2:
					case 1:
						log_snoop("Open %s on port %u [%c] found on \2%s\2 [Requested by %s]",
							conn->protocol->name, conn->protocol->port, conn->protocol->type, conn->addr, conn->irc_nick);
						break;

					case 0:
						log_snoop("Open %s on port %u [%c] found on \2%s\2 [%s]",
							conn->protocol->name, conn->protocol->port, conn->protocol->type, conn->irc_nick, conn->addr);
						break;

					default:
						log_snoop("Open %s on port %u [%c] found on \2%s\2 [Reported by %s]",
							conn->protocol->name, conn->protocol->port, conn->protocol->type, conn->addr, IS_NULL(conn->zone) ? "NULL" : conn->zone->name);
						break;
				}

				break;

			default:
				switch (conn->requested) {

					case 3:
					case 2:
					case 1:
						log_snoop("Open %s on port %u found on \2%s\2 [Requested by %s]",
							conn->protocol->name, conn->protocol->port, conn->addr, conn->irc_nick);
						break;

					case 0:
						log_snoop("Open %s on port %u found on \2%s\2 [%s]",
							conn->protocol->name, conn->protocol->port, conn->irc_nick, conn->addr);
						break;

					default:
						log_snoop("Open %s on port %u found on \2%s\2 [Reported by %s]",
							conn->protocol->name, conn->protocol->port, conn->addr, IS_NULL(conn->zone) ? "NULL" : conn->zone->name);
						break;
				}

				break;
		}

		/* Should we stop scanning this host now that we know it's positive? */
		for (ss = CONNECTIONS; ss; ss = ss->next) {

			if (ss->sockaddr.sin_addr.s_addr == conn->sockaddr.sin_addr.s_addr) {

				ss->positive = 1;

				/* Flag only if it's a normal connection, or if it comes from a DNSBL report. */
				if ((ss->requested == 0) || (ss->requested >= 10))
					ss->state = STATE_POSITIVE;
			}
		}

		/* Stop sending http requests to DNSBLs. */
		http_remove_connections(conn->sockaddr);

		/* Increase number of open (insecure) proxies of this type. */
		++(conn->protocol->stat_numopen);
	}
	else
		conn->state = STATE_CLOSED;
}


/*********************************************************
 * Poll or select returned back that this connect is     *
 * ready for write. Pass it to the protocol's write      *
 * handler and have it send the appropriate data.        *
 *********************************************************/

static void scan_writeready(scan_struct *conn) {

	/* Send handshake, if any. */
	if (conn->state == STATE_HANDSHAKE) {

		if (send(conn->fd, conn->protocol->handshake_write_string, conn->protocol->handshake_write_string_len, 0) == -1) {

			log_event(7, "SCAN -> [Socket %d (%c)] Failed sending handshake to %s on port %u [errno: %d (%s)]",
				conn->fd, get_state(conn), conn->addr, conn->protocol->port, errno, strerror(errno));

			conn->state = STATE_CLOSED;
		}
		else {

			if (conn->equals)
				log_event(7, "SCAN -> [Socket %d] Sent handshake to %s on port %u",
					conn->fd, conn->addr, conn->protocol->port);
			else
				log_event(7, "SCAN -> [Socket %d] Sent handshake to %s [%s] on port %u",
					conn->fd, conn->irc_addr, conn->addr, conn->protocol->port);

			conn->state = STATE_HANDSHAKE_SENT;
		}

		return;
	}

	if ((*conn->protocol->write_handler)(conn)) {

		/* If write returns true, flag STATE_SENT. */
		conn->state = STATE_SENT;

		/* Increase number of attempted negotiations of this type. */
		++(conn->protocol->stat_num);
	}
	else
		conn->state = STATE_CLOSED;
}


/*********************************************************
 * Link struct to connection list.                       *
 *********************************************************/

static void scan_add(scan_struct *newconn) {

	scan_struct *ss;

	if (newconn->equals)
		log_event(7, "SCAN -> Adding to scan list: %s on port %u", newconn->addr, newconn->protocol->port);
	else
		log_event(7, "SCAN -> Adding to scan list: %s [%s] on port %u", newconn->irc_addr, newconn->addr, newconn->protocol->port);

	/* Only item in list. */

	if (!CONNECTIONS) {

		newconn->next = NULL;
		CONNECTIONS = newconn;
	}
	else {

		/* Link to end of list. */
		for (ss = CONNECTIONS; ss; ss = ss->next) {

			if (!ss->next) {

				newconn->next = NULL;
				ss->next = newconn;
				break;
			}
		}
	}
}


/*********************************************************
 * Unlink struct from connection list and free its       *
 * memory. Delete the protocol if we created it          *
 * manually.                                             *
 *********************************************************/

static void scan_del(scan_struct *delconn) {

	scan_struct *ss;
	scan_struct *lastss = NULL;

	if (delconn->equals)
		log_event(7, "SCAN -> [Socket %d] Removing from scan list: %s on port %u",
			delconn->fd, delconn->addr, delconn->protocol->port);
	else
		log_event(7, "SCAN -> [Socket %d] Removing from scan list: %s [%s] on port %u",
			delconn->fd, delconn->irc_addr, delconn->addr, delconn->protocol->port);

	if (delconn->fd > 0) 
		close(delconn->fd);

	/* 1 file descriptor freed up for use. */
	if (delconn->fd)
		--FD_USE;

	/* We now have to check if there are any other scans for the same address
	   in progress. If not then the last scan just failed and we can add this
	   to our negative cache. */

	if (delconn->positive != 1) {

		for (ss = CONNECTIONS; ss; ss = ss->next) {

			if (ss == delconn)
				continue;

			if ((ss->sockaddr.sin_addr.s_addr == delconn->sockaddr.sin_addr.s_addr) &&
				(ss->requested == delconn->requested))
				break;
		}

		if (ss == NULL) {

			/* There are no scans left for this host. Act accordingly. */
			switch (delconn->requested) {

				case 3:
					log_snoop("Host \2%s\2 is negative on port %u [%s] [Requested by %s]", (delconn->equals) ? delconn->addr : delconn->irc_addr, delconn->protocol->port, delconn->protocol->name, delconn->irc_nick);
					break;

				case 2:
					log_snoop("Host \2%s\2 is negative on port %u [Requested by %s]", (delconn->equals) ? delconn->addr : delconn->irc_addr, delconn->protocol->port, delconn->irc_nick);
					break;

				case 1:
					log_snoop("Host \2%s\2 is negative [Requested by %s]", (delconn->equals) ? delconn->addr : delconn->irc_addr, delconn->irc_nick);
					/* Fall... */

				case 0:
					negcache_insert(delconn->addr);
					break;

				default:
					if (IS_NULL(delconn->zone))
						log_snoop("Host \2%s\2 used by %s is a \2false positive\2 and has no zone!", (delconn->equals) ? delconn->addr : delconn->irc_addr, delconn->irc_nick);
					else
						log_snoop("[%s] IP \2%s\2 used by \2%s\2 is a \2false positive\2 [Details: http://%s%s%s ]", delconn->zone->name, (delconn->equals) ? delconn->addr : delconn->irc_addr, delconn->irc_nick, delconn->zone->host, delconn->zone->url, delconn->addr);
							break;
			}
		}
	}

	for (ss = CONNECTIONS; ss; ss = ss->next) {

		if (ss == delconn) {

			/* Link around deleted node */
			if (lastss == NULL)
				CONNECTIONS = ss->next;
			else
				lastss->next = ss->next;

			free(ss->addr);

			if (ss->irc_addr)
				free(ss->irc_addr);

			free(ss->irc_nick);

			if (ss->irc_user)
				free(ss->irc_user);

			/* If it's established, free the scan buffer. */
			if (ss->data)
				free(ss->data);

			/* If we created the protocol on the fly, we need to free it now. */
			if (ss->requested >= 2) {

				if (ss->protocol->name)
					free(ss->protocol->name);

				if (ss->protocol->handshake_write_string)
					free(ss->protocol->handshake_write_string);

				if (ss->protocol->handshake_check_string)
					free(ss->protocol->handshake_check_string);

				if (ss->protocol->write_string)
					free(ss->protocol->write_string);

				if (ss->protocol->check_string)
					free(ss->protocol->check_string);

				free(ss->protocol);
			}

			free(ss);
			break;
		}

		lastss = ss;
	}
}


/*********************************************************
 * Alarm signaled, loop through connections and remove   *
 * any we don't need anymore. Also check if we have any  *
 * unestablished connections we can start now.           *
 *********************************************************/

void scan_timer() {

	scan_struct *ss, *next;
	time_t present;

	time(&present);

	for (ss = CONNECTIONS; ss;) {

		if (ss->state == STATE_UNESTABLISHED) { 

			if (FD_USE < CONF_FDLIMIT) {

				scan_establish(ss);

				log_event(7, "SCAN -> File descriptor free, continuing queued scan on %s", ss->addr);
			}
			else {

				ss = ss->next;

				/* Continue to avoid timeout checks on an unestablished connection. */
				continue;
			}
		}

		if ((ss->state == STATE_CLOSED) || (ss->state == STATE_POSITIVE) ||
			((present - ss->create_time) >= CONF_TIMEOUT)) {

			next = ss->next;
			scan_del(ss);
			ss = next;
			continue;
		}

		ss = ss->next;
	}
}

static int scan_socks4(scan_struct *conn) {

	if (send(conn->fd, SOCKS4BUF, 9, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent Socks 4 request to %s on port %u",
			conn->fd, conn->addr, conn->protocol->port);
	else
		log_event(7, "SCAN -> [Socket %d] Sent Socks 4 request to %s [%s] on port %u",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port);

	return 1;
}

static int scan_socks5(scan_struct *conn) {

	if (send(conn->fd, SOCKS5BUF, 10, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent Socks 5 request to %s on port %u",
			conn->fd, conn->addr, conn->protocol->port);
	else
		log_event(7, "SCAN -> [Socket %d] Sent Socks 5 request to %s [%s] on port %u",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port);

	return 1;
}

static int scan_http_connect(scan_struct *conn) {

	if (send(conn->fd, HTTPCONNBUF, HTTPCONNBUFLEN, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent to %s on port %u: %s",
			conn->fd, conn->addr, conn->protocol->port, ascii2char(HTTPCONNBUF, HTTPCONNBUFLEN));
	else
		log_event(7, "SCAN -> [Socket %d] Sent to %s [%s] on port %u: %s",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char(HTTPCONNBUF, HTTPCONNBUFLEN));

	return 1;
}

static int scan_http_post(scan_struct *conn) {

	if (send(conn->fd, HTTPPOSTBUF, HTTPPOSTBUFLEN, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent to %s on port %u: %s",
			conn->fd, conn->addr, conn->protocol->port, ascii2char(HTTPPOSTBUF, HTTPPOSTBUFLEN));
	else
		log_event(7, "SCAN -> [Socket %d] Sent to %s [%s] on port %u: %s",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char(HTTPPOSTBUF, HTTPPOSTBUFLEN));

	return 1;
}

static int scan_http_put(scan_struct *conn) {

	if (send(conn->fd, HTTPPUTBUF, HTTPPUTBUFLEN, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent to %s on port %u: %s",
			conn->fd, conn->addr, conn->protocol->port, ascii2char(HTTPPUTBUF, HTTPPUTBUFLEN));
	else
		log_event(7, "SCAN -> [Socket %d] Sent to %s [%s] on port %u: %s",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char(HTTPPUTBUF, HTTPPUTBUFLEN));

	return 1;
}

static int scan_ircd(scan_struct *conn) {

	if (send(conn->fd, "QUIT\r\n", 6, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent to %s on port %u: %s",
			conn->fd, conn->addr, conn->protocol->port, ascii2char("QUIT\r\n", 6));
	else
		log_event(7, "SCAN -> [Socket %d] Sent to %s [%s] on port %u: %s",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char("QUIT\r\n", 6));

	return 1;
}

static int scan_cisco(scan_struct *conn) {

	if (send(conn->fd, "cisco\r\n", 7, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent Cisco request to %s on port %u",
			conn->fd, conn->addr, conn->protocol->port);
	else
		log_event(7, "SCAN -> [Socket %d] Sent Cisco request to %s [%s] on port %u",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port);

	return 1;
}

static int scan_write_string(scan_struct *conn) {

	if (send(conn->fd, conn->protocol->write_string, conn->protocol->write_string_len, 0) == -1)
		return 0;

	if (conn->equals)
		log_event(7, "SCAN -> [Socket %d] Sent to %s on port %u: %s",
			conn->fd, conn->addr, conn->protocol->port, ascii2char(conn->protocol->write_string, conn->protocol->write_string_len));
	else
		log_event(7, "SCAN -> [Socket %d] Sent to %s [%s] on port %u: %s",
			conn->fd, conn->irc_addr, conn->addr, conn->protocol->port, ascii2char(conn->protocol->write_string, conn->protocol->write_string_len));

	return 1;
}

static int scan_check_string(scan_struct *conn) {

	return match(conn->protocol->check_string, conn->data);
}

static int scan_check_http(scan_struct *conn) {

	return match("HTTP/?.? 200*", conn->data);
}

static int scan_check_httpd(scan_struct *conn) {

	string_list *list;

	if (BLOCK_SPEEDTOUCH && match("*HTTP/?.? 401*WWW-Authenticate: Basic realm=?SpeedTouch (*-*-*-*-*-*)*", conn->data))
		return 1;

	if (!match("*HTTP/?.? 200*", conn->data))
		return 0;

	for (list = ((string_list *) CONF_SCANCHECK); list; list = list->next) {

		if (match(list->text, conn->data)) {

			if (CONF_DEBUG > 3) {

				if (conn->equals)
					log_snoop("SCAN -> false positive on %s on port %u [%s/%c]",
						conn->addr, conn->protocol->port, conn->protocol->name, conn->protocol->type);
				else
					log_snoop("SCAN -> false positive on %s [%s] on port %u [%s/%c]",
						conn->irc_addr, conn->addr, conn->protocol->port, conn->protocol->name, conn->protocol->type);
			}

			return 0;
		}
	}

	return 1;
}

static int scan_check_ircd(scan_struct *conn) {

	return (match("ERROR :Closing Link*", conn->data) || match(":*.azzurra.org NOTICE *", conn->data));
}

static int scan_check_wingate(scan_struct *conn) {

	return (match("*>\r\n", conn->data) || match("Too many*", conn->data));
}

static int scan_check_socks4(scan_struct *conn) {

	return (conn->data[1] == 90);
}

static int scan_check_socks5(scan_struct *conn) {

	return ((conn->data[0] == 5) && (conn->data[1] == 0));
}

static int scan_check_cisco(scan_struct *conn) {

	return (match("\r\n*>", conn->data));
}

/* Manually check a host for proxies. */
void do_manual_check(char *nick, char *host, int port, char *write_string, char *check_string) {

	char *ip;
	struct hostent *he;
	scan_protocol *protocol = SCAN_PROTOCOLS;
	scan_struct *newconn;
	int equals;

	if (!(he = gethostbyname(host))) {

		switch (h_errno) {

			case HOST_NOT_FOUND:
				log_snoop("Host '%s' is unknown.", host);
				return;

			case NO_ADDRESS:
				log_snoop("The specified name '%s' exists, but has no address.", host);
				return;

			case NO_RECOVERY:
				log_snoop("An unrecoverable error occured whilst resolving '%s'.", host);
				return;

			case TRY_AGAIN:
				log_snoop("A temporary nameserver error occurred.");
				return;

			default:
				log_snoop("Error %d [%s] resolving %s", h_errno, hstrerror(h_errno), host);
				return;
		}
	}

	ip = inet_ntoa(*((struct in_addr *) he->h_addr));

	equals = !strcmp(ip, host);

	if (port > 0) {

		if (write_string) {

			/* We only want to scan one port with one method. */

			newconn = (scan_struct *) calloc(1, sizeof(scan_struct));

			newconn->addr = strdup(ip);

			if (!equals)
				newconn->irc_addr = strdup(host);

			newconn->equals = equals;

			newconn->irc_nick = strdup(nick);

			newconn->requested = 3;

			/* Create a new protocol and fill it. */
			protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

			if (!strcasecmp(write_string, "CONNECT")) {

				protocol->name = strdup("HTTP Proxy");
				protocol->type = 'C';

				protocol->write_handler = &(scan_http_connect);

				if ((check_string == NULL) || !strcasecmp(check_string, "HTTPD"))
					protocol->check_handler = &(scan_check_httpd);

				else if (!strcasecmp(check_string, "HTTP"))
					protocol->check_handler = &(scan_check_http);

				else {

					protocol->check_string = strdup(char2ascii(check_string));
					protocol->check_handler = &(scan_check_string);
				}
			}
			else if (!strcasecmp(write_string, "POST")) {

				protocol->name = strdup("HTTP Proxy");
				protocol->type = 'P';

				protocol->write_handler = &(scan_http_post);

				if ((check_string == NULL) || !strcasecmp(check_string, "POST"))
					protocol->check_handler = &(scan_check_ircd);

				else {

					protocol->check_string = strdup(char2ascii(check_string));
					protocol->check_handler = &(scan_check_string);
				}
			}
			else if (!strcasecmp(write_string, "PUT")) {

				protocol->name = strdup("HTTP Proxy");
				protocol->type = 'U';

				protocol->write_handler = &(scan_http_put);

				if ((check_string == NULL) || !strcasecmp(check_string, "PUT"))
					protocol->check_handler = &(scan_check_ircd);

				else {

					protocol->check_string = strdup(char2ascii(check_string));
					protocol->check_handler = &(scan_check_string);
				}
			}
			else if (!strcasecmp(write_string, "IRCD")) {

				protocol->name = strdup("IRC Backdoor");
				protocol->type = 'I';

				protocol->write_handler = &(scan_ircd);

				if ((check_string == NULL) || !strcasecmp(check_string, "IRCD"))
					protocol->check_handler = &(scan_check_ircd);

				else {

					protocol->check_string = strdup(char2ascii(check_string));
					protocol->check_handler = &(scan_check_string);
				}
			}
			else if (!strcasecmp(write_string, "SOCKS4")) {

				protocol->name = strdup("Socks 4");
				protocol->type = '4';

				protocol->write_handler = &(scan_socks4);
				protocol->check_handler = &(scan_check_socks4);
			}
			else if (!strcasecmp(write_string, "SOCKS5")) {

				protocol->name = strdup("Socks 5");
				protocol->type = '5';

				protocol->handshake_write_string = strdup("\5\1\0");
				protocol->handshake_check_string = strdup("\5\0");
				protocol->handshake_write_string_len = strlen(protocol->handshake_write_string);

				protocol->write_handler = &(scan_socks5);
				protocol->check_handler = &(scan_check_socks5);
			}
			else if (!strcasecmp(write_string, "WINGATE")) {

				protocol->name = strdup("Wingate");
				protocol->type = 'W';

				if ((check_string == NULL) || !strcasecmp(check_string, "WINGATE"))
					protocol->check_handler = &(scan_check_wingate);

				else {

					protocol->check_string = strdup(char2ascii(check_string));
					protocol->check_handler = &(scan_check_string);
				}
			}
			else {

				protocol->name = strdup("Manual string");
				protocol->type = 'M';

				if (strcasecmp(write_string, "NULL")) {

					protocol->write_string = strdup(char2ascii(write_string));
					protocol->write_string_len = strlen(protocol->write_string);
					protocol->write_handler = &(scan_write_string);
				}

				if ((check_string == NULL) || !strcasecmp(check_string, "HTTPD"))
					protocol->check_handler = &(scan_check_httpd);

				else if (!strcasecmp(check_string, "HTTP"))
					protocol->check_handler = &(scan_check_http);

				else if (!strcasecmp(check_string, "POST") || !strcasecmp(check_string, "PUT"))
					protocol->check_handler = &(scan_check_ircd);

				else if (!strcasecmp(check_string, "IRCD"))
					protocol->check_handler = &(scan_check_ircd);

				else if (!strcasecmp(check_string, "WINGATE"))
					protocol->check_handler = &(scan_check_wingate);

				else {

					protocol->check_string = strdup(char2ascii(check_string));
					protocol->check_handler = &(scan_check_string);
				}
			}

			/* Set the port. */
			protocol->port = port;

			/* Give struct a link to information about the protocol it will be handling. */
			newconn->protocol = protocol;

			/* Fill in sockaddr with information about remote host. */
			newconn->sockaddr.sin_family = AF_INET;
			newconn->sockaddr.sin_port = htons(protocol->port);
			newconn->sockaddr.sin_addr.s_addr = inet_addr(ip);

			/* Queue connection. */
			newconn->state = STATE_UNESTABLISHED;

			/* Log this request. */
			if (equals)
				log_snoop("Scanning %s on port %u [Protocol: %s] [Requested by %s]", ip, port, protocol->name, nick);
			else
				log_snoop("Scanning %s [%s] on port %u [Protocol: %s] [Requested by %s]", host, ip, port, protocol->name, nick);

			/* Add struct to list of connections. */
			scan_add(newconn);

			/* If we have available FD's, override queue. */
			if (FD_USE < CONF_FDLIMIT)
				scan_establish(newconn);
			else
				log_event(7, "SCAN -> File Descriptor limit (%d) reached, queuing scan for %s", CONF_FDLIMIT, newconn->addr);
		}
		else {

			/* No method specified. Create a new instance for each protocol with the specified port. */
			int idx;

			/* Log this request. */
			if (equals)
				log_snoop("Scanning %s on port %u [Requested by %s]", ip, port, nick);
			else
				log_snoop("Scanning %s [%s] on port %u [Requested by %s]", host, ip, port, nick);

			for (idx = 0; idx < 7; ++idx) {

				newconn = (scan_struct *) calloc(1, sizeof(scan_struct));

				newconn->addr = strdup(ip);

				if (!equals)
					newconn->irc_addr = strdup(host);

				newconn->equals = equals;

				newconn->irc_nick = strdup(nick);

				newconn->requested = 2;

				/* Create a new protocol and fill it. */
				protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

				switch (idx) {

					case 0:	/* Socks 4 */
						protocol->name = strdup("Socks 4");
						protocol->type = '4';

						protocol->write_handler = &(scan_socks4);
						protocol->check_handler = &(scan_check_socks4);
						break;

					case 1:	/* Socks 5 */
						protocol->name = strdup("Socks 5");
						protocol->type = '5';

						protocol->handshake_write_string = strdup("\5\1\0");
						protocol->handshake_check_string = strdup("\5\0");
						protocol->handshake_write_string_len = strlen(protocol->handshake_write_string);

						protocol->write_handler = &(scan_socks5);
						protocol->check_handler = &(scan_check_socks5);
						break;

					case 2:	/* HTTP Proxy, CONNECT method */
						protocol->name = strdup("HTTP Proxy");
						protocol->type = 'C';

						protocol->write_handler = &(scan_http_connect);
						protocol->check_handler = &(scan_check_httpd);
						break;

					case 3:	/* HTTP Proxy, POST method */
						protocol->name = strdup("HTTP Proxy");
						protocol->type = 'P';

						protocol->write_handler = &(scan_http_post);
						protocol->check_handler = &(scan_check_ircd);
						break;

					case 4:	/* HTTP Proxy, PUT method */
						protocol->name = strdup("HTTP Proxy");
						protocol->type = 'U';

						protocol->write_handler = &(scan_http_put);
						protocol->check_handler = &(scan_check_ircd);
						break;

					case 5:	/* IRC Backdoor */
						protocol->name = strdup("IRC Backdoor");
						protocol->type = 'I';

						protocol->write_handler = &(scan_ircd);
						protocol->check_handler = &(scan_check_ircd);
						break;

					case 6:	/* Wingate */
						protocol->name = strdup("Wingate");
						protocol->type = 'W';

						protocol->check_handler = &(scan_check_wingate);
						break;
				}

				/* Set the port. */
				protocol->port = port;

				/* Give struct a link to information about the protocol it will be handling. */
				newconn->protocol = protocol;

				/* Fill in sockaddr with information about remote host. */
				newconn->sockaddr.sin_family = AF_INET;
				newconn->sockaddr.sin_port = htons(protocol->port);
				newconn->sockaddr.sin_addr.s_addr = inet_addr(ip);

				/* Queue connection. */
				newconn->state = STATE_UNESTABLISHED;

				/* Add struct to list of connections. */
				scan_add(newconn);

				/* If we have available FD's, override queue. */
				if (FD_USE < CONF_FDLIMIT)
					scan_establish(newconn);
				else
					log_event(7, "SCAN -> File Descriptor limit (%d) reached, queuing scan for %s", CONF_FDLIMIT, newconn->addr);
			}
		}
	}
	else {

		/* No port specified, fire up the normal protocols only. */

		/* Log this request. */
		if (equals)
			log_snoop("Scanning %s [Requested by %s]", ip, nick);
		else
			log_snoop("Scanning %s [%s] [Requested by %s]", host, ip, nick);

		if (CONF_DNSBL)
			dnsbl_check(ip, nick, NULL, host, equals);

		while (protocol) {

			newconn = (scan_struct *) calloc(1, sizeof(scan_struct));

			newconn->addr = strdup(ip);

			if (!equals)
				newconn->irc_addr = strdup(host);

			newconn->equals = equals;

			newconn->irc_nick = strdup(nick);

			newconn->requested = 1;

			/* Give struct a link to information about the protocol it will be handling. */
			newconn->protocol = protocol;

			/* Fill in sockaddr with information about remote host. */
			newconn->sockaddr.sin_family = AF_INET;
			newconn->sockaddr.sin_port = htons(protocol->port);
			newconn->sockaddr.sin_addr.s_addr = inet_addr(ip);

			/* Queue connection. */
			newconn->state = STATE_UNESTABLISHED;

			/* Add struct to list of connections. */
			scan_add(newconn);

			/* If we have available FD's, override queue. */
			if (FD_USE < CONF_FDLIMIT)
				scan_establish(newconn);
			else
				log_event(7, "SCAN -> File Descriptor limit (%d) reached, queuing scan for %s", CONF_FDLIMIT, newconn->addr);

			protocol = protocol->next;
		}
	}
}

void do_queue(char *nick, int nolist) {

	scan_struct *ss;
	int count;

	if (!CONNECTIONS) {

		log_snoop("Queue is empty.");
		return;
	}

	for (ss = CONNECTIONS, count = 0; ss; ss = ss->next) {

		++count;

		if (!nolist && (count <= 20)) {

			switch (ss->state) {

				case STATE_UNESTABLISHED:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Waiting]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Waiting]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;

				case STATE_HANDSHAKE:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Handshaking]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Handshaking]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;

				case STATE_HANDSHAKE_SENT:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Validating]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Validating]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;

				case STATE_ESTABLISHED:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Established]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Established]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;

				case STATE_SENT:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Sent]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Sent]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;

				case STATE_CLOSED:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Closed]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Closed]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;

				case STATE_POSITIVE:
					if (ss->equals)
						log_snoop("%d) %s on port %d [Positive]", count, ss->addr, ss->protocol->port);
					else
						log_snoop("%d) %s [%s] on port %d [Positive]", count, ss->irc_addr, ss->addr, ss->protocol->port);
					break;
			}
		}
	}

	if (nolist || (count > 20))
		log_snoop("Total hosts on queue: %d", count);
}

void protocols_stats(void) {

	scan_protocol *protocol = SCAN_PROTOCOLS;

	while (protocol) {

		log_snoop("Found %u %s (%d / %c), %u open.",
			protocol->stat_num, protocol->name, protocol->port, protocol->type, protocol->stat_numopen);

		protocol = protocol->next;
	}
}

int scan_http_result(const http_struct *conn, const int port, const char *type) {

	scan_protocol *protocol;
	scan_struct *newconn;
	int idx, count = 0;

	for (idx = 0; idx < 6; ++idx) {

		protocol = NULL;

		switch (idx) {

			default:
			case 0:	/* Socks 4 */
				if (str_equals_nocase(type, "SOCKS") || str_equals_nocase(type, "SOCKS4")) {

					if (protocol_find('4', port, &(scan_socks4), &(scan_check_socks4), NULL, NULL, NULL, NULL))
						continue;

					/* Create a new protocol and fill it. */
					protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

					protocol->name = strdup("Socks 4");
					protocol->type = '4';

					protocol->write_handler = &(scan_socks4);
					protocol->check_handler = &(scan_check_socks4);
					break;
				}

				continue;

			case 1:	/* Socks 5 */
				if (str_equals_nocase(type, "SOCKS") || str_equals_nocase(type, "SOCKS5")) {

					if (protocol_find('5', port, &(scan_socks5), &(scan_check_socks5), NULL, NULL, "\5\1\0", "\5\0"))
						continue;

					/* Create a new protocol and fill it. */
					protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

					protocol->name = strdup("Socks 5");
					protocol->type = '5';

					protocol->handshake_write_string = strdup("\5\1\0");
					protocol->handshake_check_string = strdup("\5\0");
					protocol->handshake_write_string_len = strlen(protocol->handshake_write_string);

					protocol->write_handler = &(scan_socks5);
					protocol->check_handler = &(scan_check_socks5);
					break;
				}

				continue;

			case 2:	/* HTTP Proxy, CONNECT method */
				if (str_equals_nocase(type, "HTTP") || str_equals_nocase(type, "HTTP-CONNECT")) {

					if (protocol_find('C', port, &(scan_http_connect), &(scan_check_httpd), NULL, NULL, NULL, NULL) ||
						protocol_find('C', port, &(scan_http_connect), &(scan_check_http), NULL, NULL, NULL, NULL))
						continue;

					/* Create a new protocol and fill it. */
					protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

					protocol->name = strdup("HTTP Proxy");
					protocol->type = 'C';

					protocol->write_handler = &(scan_http_connect);
					protocol->check_handler = &(scan_check_httpd);
					break;
				}

				continue;

			case 3:	/* HTTP Proxy, POST method */
				if (str_equals_nocase(type, "HTTPPOST") ||
					str_equals_nocase(type, "HTTP POST") || str_equals_nocase(type, "HTTP-POST")) {

					if (protocol_find('P', port, &(scan_http_post), &(scan_check_ircd), NULL, NULL, NULL, NULL))
						continue;

					/* Create a new protocol and fill it. */
					protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

					protocol->name = strdup("HTTP Proxy");
					protocol->type = 'P';

					protocol->write_handler = &(scan_http_post);
					protocol->check_handler = &(scan_check_ircd);
					break;
				}

				continue;

			case 4:	/* HTTP Proxy, PUT method */
				if (str_equals_nocase(type, "HTTP PUT") || str_equals_nocase(type, "HTTP-PUT")) {

					if (protocol_find('U', port, &(scan_http_put), &(scan_check_ircd), NULL, NULL, NULL, NULL))
						continue;

					/* Create a new protocol and fill it. */
					protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

					protocol->name = strdup("HTTP Proxy");
					protocol->type = 'U';

					protocol->write_handler = &(scan_http_put);
					protocol->check_handler = &(scan_check_ircd);
					break;
				}

				continue;

			case 5:	/* Wingate */
				if (str_equals_nocase(type, "WINGATE")) {

					if (protocol_find('W', port, NULL, &(scan_check_wingate), NULL, NULL, NULL, NULL))
						continue;

					/* Create a new protocol and fill it. */
					protocol = (scan_protocol *) calloc(1, sizeof(scan_protocol));

					protocol->name = strdup("Wingate");
					protocol->type = 'W';

					protocol->check_handler = &(scan_check_wingate);
					break;
				}

				continue;
		}

		if (IS_NULL(protocol)) {

			log_snoop("Unsupported type for IP %s on port %d: %s", conn->ip, port, type);
			continue;
		}

		/* Set the port. */
		protocol->port = port;

		/* Create the new connection and fill it. */
		newconn = (scan_struct *) calloc(1, sizeof(scan_struct));

		newconn->addr = strdup(conn->ip);

		newconn->irc_nick = strdup(conn->nick);

		newconn->equals = 1;

		newconn->requested = (10 + conn->zone->idx);

		newconn->zone = conn->zone;

		/* Give struct a link to information about the protocol it will be handling. */
		newconn->protocol = protocol;

		/* Fill in sockaddr with information about remote host. */
		newconn->sockaddr.sin_family = AF_INET;
		newconn->sockaddr.sin_port = htons(protocol->port);
		newconn->sockaddr.sin_addr.s_addr = inet_addr(conn->ip);

		/* Queue connection. */
		newconn->state = STATE_UNESTABLISHED;

		/* Add struct to list of connections. */
		scan_add(newconn);

		++count;

		/* If we have available FD's, override queue. */
		if (FD_USE < CONF_FDLIMIT)
			scan_establish(newconn);
		else
			log_event(7, "SCAN -> File Descriptor limit (%d) reached, queuing scan for %s", CONF_FDLIMIT, newconn->addr);
	}

	return count;
}

static char get_state(const scan_struct *conn) {

	if (IS_NULL(conn))
		return '!';

	switch (conn->state) {

		case STATE_UNESTABLISHED:	return 'U';
		case STATE_WELCOME:			return 'W';
		case STATE_HANDSHAKE:		return 'H';
		case STATE_HANDSHAKE_SENT:	return 'T';
		case STATE_ESTABLISHED:		return 'E';
		case STATE_SENT:			return 'S';
		case STATE_CLOSED:			return 'C';
		case STATE_POSITIVE:		return 'P';
	}

	return '?';
}

char *scan_get_method(void) {

#ifdef USING_KQUEUE
	return "KQueue";
#elif defined(USING_EPOLL)
	return "EPoll";
#elif defined(USING_POLL)
	return "Poll";
#else
	return "Select";
#endif
}
