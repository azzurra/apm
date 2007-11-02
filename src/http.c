/*
 * Azzurra Proxy Monitor - http.c
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

#if defined(HAVE_SYS_POLL_H) && !defined(FORCE_SELECT)
# include <sys/poll.h>
#endif

#include "../inc/config.h"
#include "../inc/irc.h"
#include "../inc/log.h"
#include "../inc/match.h"
#include "../inc/misc.h"
#include "../inc/options.h"
#include "../inc/firedns.h"
#include "../inc/http.h"
#include "../inc/scan.h"


static void http_establish(http_struct *conn);
static void http_check(void);
static void http_readready(http_struct *conn);
static void http_writeready(http_struct *conn);
static void http_conn_add(http_struct *newconn);
static void http_conn_del(http_struct *delconn);
static void http_request_parse(http_struct *conn);

/* Linked list head for connections. */
static http_struct *HTTPREQUESTS = NULL;


/*********************************************************
 * We received a +c notice from the remote server.       *
 * http_connect() is called with the connecting IP,      *
 * where we will begin to establish the proxy testing.   *
 *********************************************************/

void http_send_request(const fdns_result *res) {

	http_struct *newconn;

	log_event(6, "HTTP -> Sending request to %s for IP %s", res->zone->name, res->ip);

	newconn = (http_struct *) calloc(1, sizeof(http_struct));

	strncpy(newconn->ip, res->ip, sizeof(newconn->ip));
	strncpy(newconn->nick, res->nick, sizeof(newconn->nick));

	newconn->zone = res->zone;

	if (res->requested)
		newconn->requested = res->requested;

	/* Queue connection. */
	newconn->state = STATE_UNESTABLISHED;

	/* Add struct to list of connections. */
	http_conn_add(newconn);

	/* If we have available FD's, override queue. */
	if (FD_USE < CONF_FDLIMIT)
		http_establish(newconn);
	else
		log_event(6, "HTTP -> File Descriptor limit (%d) reached, queuing request for IP %s on %s", CONF_FDLIMIT, res->ip, res->zone->name);
}


/*********************************************************
 * Get FD for new socket, bind to interface and          *
 * connect() (non blocking), then set conn to            *
 * ESTABLISHED for write check, or SENT for direct read  *
 * check (listen without sending data).                  *
 *********************************************************/

static void http_establish(http_struct *conn) {

	/* Request file descriptor for socket. */
	conn->fd = socket(PF_INET, SOCK_STREAM, 0);

	/* Increase global FD Use counter. */
	++FD_USE;

	log_event(6, "HTTP -> [Socket %d] Requesting info for IP %s to %s", conn->fd, conn->ip, conn->zone->name);

	/* If error, mark connection for close. */
	if (conn->fd == -1) {

		log_snoop("HTTP -> Error allocating file descriptor.");
		conn->state = STATE_CLOSED;
		return;
	}

	/* Log create time of connection for timeouts. */
	time(&(conn->create_time));

	/* Flag conn established (for write). */
	conn->state = STATE_ESTABLISHED;

	/* Set socket non blocking. */
	fcntl(conn->fd, F_SETFL, O_NONBLOCK);

	/* Connect! */
	if ((connect(conn->fd, (struct sockaddr *) &(conn->zone->sockaddr), sizeof(conn->zone->sockaddr)) == -1) && (errno != EINPROGRESS)) {

		log_event(6, "HTTP -> [Socket %d] Connection refused by %s for IP %s [Error %d: %s]",
			conn->fd, conn->zone->name, conn->ip, errno, strerror(errno));

		http_conn_del(conn);
	}
}


/*********************************************************
 * Pass one cycle to the proxy scanner so it can do      *
 * necessary functions like testing for sockets to be    *
 * written to and read from.                             *
 *********************************************************/

void http_cycle(void) {

	if (HTTPREQUESTS)
		http_check();
}


/*********************************************************
 * Test for sockets to be written/read to.               *
 *********************************************************/

static void http_check(void) {

	http_struct *conn;

#if defined(HAVE_SYS_POLL_H) && !defined(FORCE_SELECT)
	static struct pollfd ufds[EVENT_CHUNK];
	unsigned long size, i;
#else /* select() */
	fd_set w_fdset;
	fd_set r_fdset;
	struct timeval http_timeout;
	int highfd = 0;
#endif /* HAVE_SYS_POLL_H */

#if defined(HAVE_SYS_POLL_H) && !defined(FORCE_SELECT)

	size = i = 0;

	/* Get size of list we're interested in. */
	for (conn = HTTPREQUESTS; conn; conn = conn->next) {

		if ((conn->state == STATE_ESTABLISHED) || (conn->state == STATE_SENT))
			++size;
	}

	/* Setup each element now. */
	for (conn = HTTPREQUESTS; conn; conn = conn->next) {

		if ((conn->state != STATE_ESTABLISHED) && (conn->state != STATE_SENT))
			continue;

		ufds[i].events = 0;
		ufds[i].revents = 0;
		ufds[i].fd = conn->fd;

		/* Check for HUNG UP. */
		ufds[i].events |= POLLHUP;

		/* Check for INVALID FD */
		ufds[i].events |= POLLNVAL;

		switch (conn->state) {

			case STATE_ESTABLISHED:
				/* Check for NO BLOCK ON WRITE. */
				ufds[i].events |= POLLOUT;
				break;

			case STATE_SENT:
				/* Check for data to be read. */
				ufds[i].events |= POLLIN;
				break;
		}

		if (++i >= EVENT_CHUNK)
			break;
	}

#else /* select() */
	FD_ZERO(&w_fdset);
	FD_ZERO(&r_fdset);

	/* Add connections to appropriate sets. */

	for (conn = HTTPREQUESTS; conn; conn = conn->next) {

		if (conn->state == STATE_ESTABLISHED) {

			if (conn->fd > highfd)
				highfd = conn->fd;

			FD_SET(conn->fd, &w_fdset);
		}
		else if (conn->state == STATE_SENT) {

			if (conn->fd > highfd)
				highfd = conn->fd;

			FD_SET(conn->fd, &r_fdset);
		}
	}

	/* No timeout. */
	http_timeout.tv_sec = 0;
	http_timeout.tv_usec= 0;

#endif /* HAVE_SYS_POLL_H */

#if defined(HAVE_SYS_POLL_H) && !defined(FORCE_SELECT)
	switch (poll(ufds, size, 0)) {
#else /* select() */
	switch (select((highfd + 1), &r_fdset, &w_fdset, 0, &http_timeout)) {
#endif /* HAVE_SYS_POLL_H */

		case -1:	/* Error in select/poll. */
		case 0:		/* Nothing to do. */
			return;

		default:
			/* Pass pointer to connection to handler. */

#if defined(HAVE_SYS_POLL_H) && !defined(FORCE_SELECT)

			for (conn = HTTPREQUESTS; conn; conn = conn->next) {

				for (i = 0; i < size; ++i) {

					if ((ufds[i].fd == conn->fd) && (conn->state != STATE_CLOSED) && (conn->state != STATE_POSITIVE)) {

						if (ufds[i].revents & POLLIN)
							http_readready(conn);

						if (ufds[i].revents & POLLOUT)
							http_writeready(conn);

						if (ufds[i].revents & POLLHUP) {

							/* Negotiation failed (read returned false). Discard the connection as a closed proxy. */

							log_event(6, "HTTP -> [Socket %d] Negotiation failed on %s for IP %s [Read: %s]",
								conn->fd, conn->zone->name, conn->ip, (conn->bytes_read > 0) ? ascii2char(conn->response, conn->bytes_read) : "Nothing");

							conn->state = STATE_CLOSED;
						}

						break;
					}
				}
			}
#else

			for (conn = HTTPREQUESTS; conn; conn = conn->next) {

				if (conn->state == STATE_ESTABLISHED) {

					if (FD_ISSET(conn->fd, &w_fdset))
						http_writeready(conn);
				}
				else if (conn->state == STATE_SENT) {

					if (FD_ISSET(conn->fd, &r_fdset))
						http_readready(conn);
				}
			}
#endif /* HAVE_SYS_POLL_H */
	}
}


/*********************************************************
 * Poll or select returned back that this connection is  *
 * ready for read. Get the data, and pass it to the      *
 * protocol check handler.                               *
 *********************************************************/

static void http_readready(http_struct *conn) {

	int len;

	memset(conn->response, 0, sizeof(conn->response));
	conn->bytes_read = 0;

	len = recv(conn->fd, conn->response, sizeof(conn->response), MSG_WAITALL);

	switch (len) {

		case -1:	/* Error, or socket was closed. */
		case 0:		/* No data read from socket. */
			return;

		default:
			if (len >= sizeof(conn->response)) {

				char dump[1024];

				log_event(6, "HTTP -> [Socket %d] Read more than %d bytes, discarding the rest", conn->fd, sizeof(conn->response));

				/* Get rid of whatever was left on the socket. */
				while (recv(conn->fd, dump, sizeof(dump), MSG_WAITALL) > 0)
					;
			}

			conn->bytes_read = len;

			log_event(6, "HTTP -> [Socket %d] Reading data from %s for IP %s: %s",
				conn->fd, conn->zone->name, conn->ip, ascii2char(conn->response, conn->bytes_read));

			http_request_parse(conn);

			conn->state = STATE_CLOSED;
			return;
	}
}

static void http_request_parse(http_struct *conn) {

	char *err, *ptr;
	char token[32];
	long int port = 0;
	int found = 0;


	switch (conn->zone->idx) {

		case 0:
			ptr = strstr(conn->response, "<td class=\"protohead\">Protocol</td>");

			if ((ptr == NULL) || ((conn->bytes_read - (ptr - conn->response)) < 48)) {

				log_snoop("Error parsing OPM http reply for IP %s: data not found", conn->ip);
				return;
			}

			ptr += 48;

			while (1) {

				ptr = str_tokenize(ptr, token, sizeof(token), '<');

				if ((ptr == NULL) || (token[0] == '\0')) {

					log_snoop("Error parsing OPM http reply for IP %s: port not found", conn->ip);
					return;
				}

				if (!strcasecmp(token, "Evidence")) {

					if (found == 0) {

						if (conn->requested == 1)
							log_snoop("[%s] IP \2%s\2 is positive on known ports only [Details: http://%s%s%s ] [Requested by %s]", conn->zone->name, conn->ip, conn->zone->host, conn->zone->url, conn->ip, conn->nick);
						else
							log_snoop("[%s] IP \2%s\2 used by \2%s\2 is positive on known ports only [Details: http://%s%s%s ]", conn->zone->name, conn->ip, conn->nick, conn->zone->host, conn->zone->url, conn->ip);
					}

					return;
				}

				port = strtol(token, &err, 10);

				if ((port <= 0) || (port > 65535) || (*err != '\0')) {

					log_snoop("Error parsing OPM http reply for IP %s: invalid port (%s)", conn->ip, token);
					return;
				}

				if ((conn->bytes_read - (ptr - conn->response)) < 8) {

					log_snoop("Error parsing OPM http reply for IP %s: invalid protocol data", conn->ip);
					return;
				}

				ptr = str_tokenize(ptr + 8, token, sizeof(token), '<');

				if ((ptr == NULL) || (token[0] == '\0')) {

					log_snoop("Error parsing OPM http reply for IP %s: protocol not found", conn->ip);
					return;
				}

				if ((conn->bytes_read - (ptr - conn->response)) < 17) {

					log_snoop("Error parsing OPM http reply for IP %s: invalid end data", conn->ip);
					return;
				}

				ptr += 17;

				found += scan_http_result(conn, port, token);
			}
			break;

		case 1: {	/* DSBL */

			http_struct *newconn;
			size_t len;

			ptr = strstr(conn->response, "<h1>DSBL: Message Detail</h1>");

			if (IS_NOT_NULL(ptr)) {

				char protocol[32];

				memset(protocol, 0, sizeof(protocol));

				ptr = strstr(conn->response, "<b>Transport:</b>");

				if (IS_NOT_NULL(ptr)) {

					ptr = str_tokenize(ptr + 18, protocol, sizeof(protocol), '\n');

					if ((ptr == NULL) || (protocol[0] == '\0')) {

						log_snoop("Error parsing DSBL http reply for IP %s: invalid transport (%s)", conn->ip, protocol);
						return;
					}
				}

				ptr = strstr(conn->response, "<b>Input Port:</b>");

				if (IS_NOT_NULL(ptr)) {

					ptr = str_tokenize(ptr + 19, token, sizeof(token), '\n');

					if ((ptr == NULL) || (token[0] == '\0')) {

						log_snoop("Error parsing DSBL http reply for IP %s: invalid port (%s)", conn->ip, token);
						return;
					}

					port = strtol(token, &err, 10);

					if ((port < 0) || (port > 65535) || (*err != '\0')) {

						log_snoop("Error parsing DSBL http reply for IP %s: invalid port (%s)", conn->ip, token);
						return;
					}
				}

				if ((port == 0) || (protocol[0] == '\0')) {

					ptr = strstr(conn->response, "Port ");

					if ((ptr == NULL) || ((conn->bytes_read - (ptr - conn->response)) < 30)) {

						log_snoop("Error parsing DSBL http reply for IP %s: invalid data", conn->ip);
						return;
					}

					ptr = str_tokenize(ptr + 5, token, sizeof(token), ',');

					if ((ptr == NULL) || (token[0] == '\0')) {

						log_snoop("Error parsing DSBL http reply for IP %s: port not found", conn->ip);
						return;
					}

					port = strtol(token, &err, 10);

					if ((port < 0) || (port > 65535) || (*err != '\0')) {

						log_snoop("Error parsing DSBL http reply for IP %s: invalid port (%s)", conn->ip, token);
						return;
					}

					ptr = str_tokenize(ptr + 1, protocol, sizeof(protocol), ',');

					if ((ptr == NULL) || (protocol[0] == '\0')) {

						log_snoop("Error parsing DSBL http reply for IP %s: protocol not found", conn->ip);
						return;
					}
				}
				log_snoop("Discovered Port: \2%i\2",port);
				if (port == 21)
				{
					log_snoop("Found anonymous FTP server, skip check");
					return;
				}
				log_snoop("I'm checking for open proxies");


				if ((!scan_http_result(conn, port, protocol)) && (!scan_http_result(conn, port, "SOCKS")) && (!scan_http_result( conn, port, "HTTPPOST")) && (!scan_http_result( conn, port, "HTTP"))) {

					if (conn->requested == 1)
						log_snoop("[%s] IP \2%s\2 is positive on known ports only [Details: http://%s%s%s ] [Requested by %s]", conn->zone->name, conn->ip, conn->zone->host, conn->zone->url, conn->ip, conn->nick);
					else
						log_snoop("[%s] IP \2%s\2 used by \2%s\2 is positive on known ports only [Details: http://%s%s%s ]", conn->zone->name, conn->ip, conn->nick, conn->zone->host, conn->zone->url, conn->ip);
				}

				return;
			}

			ptr = strstr(conn->response, "<h2>Messages from this host</h2>");

			if ((ptr == NULL) || ((conn->bytes_read - (ptr - conn->response)) < 10)) {

				log_snoop("Error parsing DSBL http reply for IP %s: data not found", conn->ip);
				return;
			}

			ptr += 32;

			while (1) {

				ptr = strstr(ptr, "UTC");

				if (IS_NULL(ptr))
					break;

				if ((conn->bytes_read - (ptr - conn->response)) < 50) {

					log_snoop("Error parsing DSBL http reply for IP %s: invalid message", conn->ip);
					return;
				}

				ptr = str_tokenize(ptr + 13, token, sizeof(token), '"');

				if ((ptr == NULL) || (token[0] == '\0')) {

					log_snoop("Error parsing DSBL http reply for IP %s: message url not found", conn->ip);
					return;
				}

				/* Message parsed and written into 'token'. Continue, as we want the last one. */
			}

			log_event(6, "HTTP -> Sending request to %s for IP %s", conn->zone->name, conn->ip);

			newconn = (http_struct *) calloc(1, sizeof(http_struct));

			strncpy(newconn->ip, conn->ip, sizeof(newconn->ip));

			len = strlen(token);

			newconn->url = malloc(len + 2);

			newconn->url[0] = '/';
			memcpy(newconn->url + 1, token, len);
			newconn->url[len + 1] = '\0';

			strncpy(newconn->nick, conn->nick, sizeof(newconn->nick));

			newconn->zone = conn->zone;

			if (conn->requested)
				newconn->requested = conn->requested;

			/* Queue connection. */
			newconn->state = STATE_UNESTABLISHED;

			/* Add struct to list of connections. */
			http_conn_add(newconn);

			/* If we have available FD's, override queue. */
			if (FD_USE < CONF_FDLIMIT)
				http_establish(newconn);
			else
				log_event(6, "HTTP -> File Descriptor limit (%d) reached, queuing request for IP %s on %s", CONF_FDLIMIT, conn->ip, conn->zone->name);

			break;
		}

		case 2: {	/* SORBS */

			char *endtag, *protocol;
			int skip;

			ptr = conn->response;

			while (1) {

				ptr = strstr(ptr, "Address and Port:");

				if (IS_NULL(ptr)) {

					if (found == 0) {

						if (conn->requested == 1)
							log_snoop("[%s] IP \2%s\2 is positive on known ports only [Details: http://%s%s%s ] [Requested by %s]", conn->zone->name, conn->ip, conn->zone->host, conn->zone->url, conn->ip, conn->nick);
						else
							log_snoop("[%s] IP \2%s\2 used by \2%s\2 is positive on known ports only [Details: http://%s%s%s ]", conn->zone->name, conn->ip, conn->nick, conn->zone->host, conn->zone->url, conn->ip);
					}

					return;
				}

				if ((conn->bytes_read - (ptr - conn->response)) < 46) {

					log_snoop("Error parsing SORBS http reply for IP %s: invalid data", conn->ip);
					return;
				}

				ptr = str_tokenize(ptr + 30 + strlen(conn->ip), token, sizeof(token), '<');

				if (IS_NULL(ptr) || (token[0] == '\0')) {

					log_snoop("Error parsing SORBS http reply for IP %s: port not found", conn->ip);
					return;
				}

				port = strtol(token, &err, 10);

				if ((port < 0) || (port > 65535) || (*err != '\0')) {

					log_snoop("Error parsing SORBS http reply for IP %s: invalid port (%s)", conn->ip, token);
					return;
				}

				endtag = strstr(ptr, "<!--/#result-->");

				protocol = strstr(ptr, "Confirmed open ");
				skip = 15;

				if (IS_NULL(protocol) || (protocol > endtag)) {

					protocol = strstr(ptr, "Unconfirmed misc ");
					skip = 17;
				}

				if (IS_NULL(protocol) || (protocol > endtag)) {

					protocol = strstr(ptr, "[Dynablock]");

					if (IS_NOT_NULL(protocol) && (protocol < endtag)) {

						ptr = endtag;
						continue;
					}
				}

				if (IS_NULL(protocol) || (protocol > endtag)) {

					log_snoop("Error parsing SORBS http reply for IP %s: protocol not found", conn->ip);
					return;
				}

				protocol += skip;

				if (str_equals_partial(protocol, "SOCKS v4", 8) ||
					str_equals_partial(protocol, "socks4", 6))
					found += scan_http_result(conn, port, "SOCKS4");

				else if (str_equals_partial(protocol, "SOCKS v5", 8) ||
					str_equals_partial(protocol, "socks5", 6))
					found += scan_http_result(conn, port, "SOCKS5");

				else if (str_equals_partial(protocol, "HTTP CONNECT", 12) ||
					str_equals_partial(protocol, "http-connect", 12) ||
					str_equals_partial(protocol, "wingate proxy", 13) ||
					str_equals_partial(protocol, "open proxy", 10))
					found += scan_http_result(conn, port, "HTTP");

				else
					log_snoop("Error parsing SORBS http reply for IP %s: unknown protocol", conn->ip);

				ptr = endtag;
			}
		}

		case 3: {	/* NJABL */

			char *protocol;
			size_t ipLen;


			ptr = strstr(conn->response, "<pre>");

			if ((ptr == NULL) || ((conn->bytes_read - (ptr - conn->response)) < 17)) {

				log_snoop("Error parsing NJABL http reply for IP %s: data not found", conn->ip);
				return;
			}

			ptr += 17;
			ipLen = strlen(conn->ip);

			while (1) {

				if (str_not_equals_partial(ptr + 3, conn->ip, ipLen)) {

					log_snoop("Error parsing NJABL http reply for IP %s: IP mismatch", conn->ip);
					return;
				}

				ptr += (3 + ipLen + 5);

				protocol = NULL;

				switch (ptr[0]) {

					case 'h':
						switch (ptr[1]) {

							case 'c':	protocol = "HTTP";		break;
							case 'u':	protocol = "HTTP PUT";	break;
							case 'o':	protocol = "HTTPPOST";	break;
						}
						break;

					case 's':
						switch (ptr[1]) {

							case '4':	protocol = "SOCKS4";	break;
							case '5':	protocol = "SOCKS5";	break;
						}
						break;

					case 'w':
						if (ptr[1] == 'g')
							protocol = "WINGATE";
						break;
				}

				if (IS_NOT_NULL(protocol)) {

					ptr = str_tokenize(ptr + 3, token, sizeof(token), ':');

					if ((ptr == NULL) || (token[0] == '\0')) {

						log_snoop("Error parsing NJABL http reply for IP %s: port not found", conn->ip);
						return;
					}

					port = strtol(token, &err, 10);

					if ((port <= 0) || (port > 65535) || (*err != '\0')) {

						log_snoop("Error parsing NJABL http reply for IP %s: invalid port (%s)", conn->ip, token);
						return;
					}

					found += scan_http_result(conn, port, protocol);
				}

				ptr = strstr(ptr, " open");

				if (IS_NULL(ptr)) {

					log_snoop("Error parsing NJABL http reply for IP %s: EOF not found", conn->ip);
					return;
				}

				if (str_equals_partial(ptr + 6, "<BR>", 4)) {

					if (found == 0) {

						if (conn->requested == 1)
							log_snoop("[%s] IP \2%s\2 is positive on known ports only [Details: http://%s%s%s ] [Requested by %s]", conn->zone->name, conn->ip, conn->zone->host, conn->zone->url, conn->ip, conn->nick);
						else
							log_snoop("[%s] IP \2%s\2 used by \2%s\2 is positive on known ports only [Details: http://%s%s%s ]", conn->zone->name, conn->ip, conn->nick, conn->zone->host, conn->zone->url, conn->ip);
					}

					return;
				}

				ptr += 6;
			}
			break;
		}
	}
}


/*********************************************************
 * Poll or select returned back that this connect is     *
 * ready for write. Pass it to the protocol's write      *
 * handler and have it send the appropriate data.        *
 *********************************************************/

static void http_writeready(http_struct *conn) {

	char buffer[512];

	if (conn->url)
		snprintf(buffer, sizeof(buffer), "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n",
			conn->url, conn->zone->host);
	else
		snprintf(buffer, sizeof(buffer), "GET %s%s HTTP/1.0\r\nHost: %s\r\n\r\n",
			conn->zone->url, conn->ip, conn->zone->host);

	if (send(conn->fd, buffer, strlen(buffer), 0) == -1) {

		log_event(6, "HTTP -> [Socket %d] Failed to send request to %s for IP %s [Error %d: %s]", conn->fd, conn->zone->name, conn->ip, errno, strerror(errno));
		conn->state = STATE_CLOSED;
		return;
	}

	log_event(6, "HTTP -> [Socket %d] Sent request to %s for IP %s: %s", conn->fd, conn->zone->name, conn->ip, ascii2char(buffer, strlen(buffer)));

	/* If write returns true, flag STATE_SENT. */
	conn->state = STATE_SENT;
}


/*********************************************************
 * Link struct to connection list.                       *
 *********************************************************/

static void http_conn_add(http_struct *newconn) {

	http_struct *conn;

	log_event(6, "HTTP -> Adding IP %s to http requests for %s", newconn->ip, newconn->zone->name);

	/* Only item in list. */

	if (!HTTPREQUESTS) {

		newconn->next = NULL;
		HTTPREQUESTS = newconn;
	}
	else {

		/* Link to end of list. */
		for (conn = HTTPREQUESTS; conn; conn = conn->next) {

			if (!conn->next) {

				newconn->next = NULL;
				conn->next = newconn;
				return;
			}
		}
	}
}


/*********************************************************
 * Unlink struct from connection list and free its       *
 * memory. Delete the protocol if we created it          *
 * manually.                                             *
 *********************************************************/

static void http_conn_del(http_struct *delconn) {

	http_struct *conn;
	http_struct *lastconn = NULL;

	log_event(6, "HTTP -> [Socket %d] Removing IP %s from http requests", delconn->fd, delconn->ip);

	if (delconn->fd > 0) 
		close(delconn->fd);

	/* 1 file descriptor freed up for use. */
	if (delconn->fd)
		--FD_USE;

	for (conn = HTTPREQUESTS; conn; conn = conn->next) {

		if (conn == delconn) {

			/* Link around deleted node */
			if (lastconn == NULL)
				HTTPREQUESTS = conn->next;
			else
				lastconn->next = conn->next;

			if (conn->url)
				free(conn->url);

			free(conn);
			break;
		}

		lastconn = conn;
	}
}


/*********************************************************
 * Alarm signaled, loop through connections and remove   *
 * any we don't need anymore. Also check if we have any  *
 * unestablished connections we can start now.           *
 *********************************************************/

void http_timer() {

	http_struct *conn, *next;
	time_t present;

	time(&present);

	for (conn = HTTPREQUESTS; conn; ) {

		if (conn->state == STATE_UNESTABLISHED) { 

			if (FD_USE < CONF_FDLIMIT) {

				http_establish(conn);

				log_event(6, "HTTP -> File descriptor free, continuing queued request for IP %s", conn->ip);
			}
			else {

				conn = conn->next;

				/* Continue to avoid timeout checks on an unestablished connection. */
				continue;
			}
		}

		if ((conn->state == STATE_CLOSED) || (conn->state == STATE_POSITIVE) ||
			((present - conn->create_time) >= CONF_TIMEOUT)) {

			next = conn->next;
			http_conn_del(conn);
			conn = next;
			continue;
		}

		conn = conn->next;
	}
}

void do_httpqueue(char *nick, int nolist) {

	if (!HTTPREQUESTS)
		log_snoop("HTTP queue is empty.");

	else {

		http_struct *conn;
		int count = 0;

		for (conn = HTTPREQUESTS; conn; conn = conn->next) {

			++count;

			if (!nolist) {

				switch (conn->state) {

					case STATE_UNESTABLISHED:
						log_snoop("%d) %s [Waiting]", count, conn->ip);
						break;

					case STATE_HANDSHAKE:
						log_snoop("%d) %s [Handshaking]", count, conn->ip);
						break;

					case STATE_HANDSHAKE_SENT:
						log_snoop("%d) %s [Validating]", count, conn->ip);
						break;

					case STATE_ESTABLISHED:
						log_snoop("%d) %s [Established]", count, conn->ip);
						break;

					case STATE_SENT:
						log_snoop("%d) %s [Sent]", count, conn->ip);
						break;

					case STATE_CLOSED:
						log_snoop("%d) %s [Closed]", count, conn->ip);
						break;

					case STATE_POSITIVE:
						log_snoop("%d) %s [Positive]", count, conn->ip);
						break;
				}
			}
		}

		if (nolist)
			log_snoop("Total hosts on queue: %d", count);
	}
}

void http_remove_connections(const struct sockaddr_in saddr) {

	http_struct *conn;

	for (conn = HTTPREQUESTS; conn; conn = conn->next) {

		if (conn->sockaddr.sin_addr.s_addr == saddr.sin_addr.s_addr)
			conn->state = STATE_POSITIVE;
	}
}

