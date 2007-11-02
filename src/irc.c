/*
 * Azzurra Proxy Monitor - irc.c
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
#include <stdarg.h>

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

#include "../inc/config.h"
#include "../inc/irc.h"
#include "../inc/log.h"
#include "../inc/main.h"
#include "../inc/match.h"
#include "../inc/misc.h"
#include "../inc/negcache.h"
#include "../inc/options.h"
#include "../inc/firedns.h"
#include "../inc/http.h"
#include "../inc/scan.h"
#include "../inc/regions.h"

#define getrandom(min, max) ((rand() % (unsigned long)(((max)+1) - (min))) + (min))
#define IRCBUFSIZE	513

static void irc_init(void);
static void irc_connect(void);
static void irc_reconnect(void);
static void irc_read(void);
static void irc_parse(void);

static char what[] = "@(#)APM (Azzurra Proxy Monitor) v1.2.6.alpha10 Azzurra IRC Network";

static char IRC_RAW[IRCBUFSIZE];		/* Buffer to read data into */
static int IRC_RAW_LEN;					/* Position of IRC_RAW */
static char *argv[24];

static int IRC_FD = -1;					/* File descriptor for IRC client */
static struct sockaddr_in IRC_SVR;		/* Sock Address Struct for IRC server */
static fd_set IRC_READ_FDSET;			/* fd_set for IRC (read) data for select() */

static struct timeval IRC_TIMEOUT;		/* timeval struct for select() timeout */
static time_t IRC_NICKSERV_LAST;		/* Last notice from NickServ */
static time_t IRC_LAST;					/* Last full line of data from irc server */
static unsigned int TOTAL_CONNECTS;
static int CYBCOP_ONLINE;
static int FORCE_KLINE;

time_t IRC_TS = 0;				/* Connection TS */
int BLOCK_SPEEDTOUCH = 0;
int SYNCHED = 0;

/* Keep track of numbers of open FD's, for use with FDLIMIT. */
unsigned int FD_USE = 0;

/* Give one cycle to the IRC client, which will allow it to poll for data and handle
   that data if need be. */

void irc_cycle(void) {	

	if (IRC_FD <= 0) {

		if ((IRC_TS != 0) && ((time(NULL) - IRC_TS) < 180)) {

			alarm(0);
			sleep(180);
		}

		/* No socket open. */
		config_load(CONFFILE);			/* Reload config. */

		if (!strcmp(CONF_SERVER, "127.0.0.1")) {

			fprintf(stderr, "\nPlease use the server's IP and not 127.0.0.1\nfor the SERVER setting in the conf file.\n");
			exit(EXIT_FAILURE);
		}

		irc_init();						/* Resolve remote host. */
		irc_connect();					/* Connect to remote host. */
		scan_init();					/* Initialize scan buffers. */
		firedns_init();					/* Initialize firedns buffers. */

		exception_load(EXCEPTIONSFILE);	/* Reload exceptions. */
		scancheck_load(SCANCHECKFILE);	/* Reload scan checks. */
		protocols_load(PROTOCOLSFILE);	/* Reload scan protocols. */

		regions_load(REGIONSFILE);		/* Reload regions. */

		IRC_TS = time(NULL);
	}

	IRC_TIMEOUT.tv_sec = 0;

	/* Block .05 seconds to avoid excessive CPU use on select(). */
	IRC_TIMEOUT.tv_usec = 50000;

	FD_ZERO(&IRC_READ_FDSET);

	FD_SET(IRC_FD, &IRC_READ_FDSET);

	switch (select((IRC_FD + 1), &IRC_READ_FDSET, 0, 0, &IRC_TIMEOUT)) {

		case -1:
		case 0:
			return;

		default:

			/* Check if IRC data is available. */
			if (FD_ISSET(IRC_FD, &IRC_READ_FDSET))
				irc_read();

			break;
	}
}

void parse_init(void) {

	int argc;

	for (argc = 0; argc < 24; ++argc)
		argv[argc] = (char *) calloc(1, IRCBUFSIZE);
}

void parse_terminate(void) {

	int argc;

	for (argc = 0; argc < 24; ++argc)
		free(argv[argc]);
}

/* Allocate socket file descriptor for connection, and resolve remote host. */
static void irc_init(void) {

	struct hostent *he;
	struct sockaddr_in IRC_LOCAL;

	if (IRC_FD)
		close(IRC_FD);

	memset(&IRC_SVR, 0, sizeof(IRC_SVR));

	/* Resolve IRC host. */
	if (!(he = gethostbyname(CONF_SERVER))) {

		switch (h_errno) {

			case HOST_NOT_FOUND:
				log_event(0, "IRC -> Error resolving server host [%s]: host is unknown", CONF_SERVER);
				fprintf(stderr, "\nError resolving server host [%s]: host is unknown.\n", CONF_SERVER);
				break;

			case NO_ADDRESS:
				log_event(0, "IRC -> Error resolving server host [%s]: no IP for that host.", CONF_SERVER);
				fprintf(stderr, "\nError resolving server host [%s]: no IP for that host.\n", CONF_SERVER);
				break;

			case NO_RECOVERY:
				log_event(0, "IRC -> Error resolving server host [%s]: unrecoverable error.", CONF_SERVER);
				fprintf(stderr, "\nError resolving server host [%s]: unrecoverable error.\n", CONF_SERVER);
				break;

			case TRY_AGAIN:
				log_event(0, "IRC -> Error resolving server host [%s]: authoritative name server error.", CONF_SERVER);
				fprintf(stderr, "\nError resolving server host [%s]: authoritative name server error.\n", CONF_SERVER);
				break;

			default:
				log_event(0, "IRC -> Error %d resolving server host [%s]: %s", CONF_SERVER);
				fprintf(stderr, "\nError %d resolving server host [%s]: %s\n", h_errno, CONF_SERVER, hstrerror(h_errno));
				break;
		}

		exit(EXIT_FAILURE);
	}

	IRC_SVR.sin_family = AF_INET;
	IRC_SVR.sin_port = htons(CONF_PORT);
	memcpy((char *)&(IRC_SVR.sin_addr), he->h_addr, he->h_length);

	if (IRC_SVR.sin_addr.s_addr == INADDR_NONE) {

		log_event(0, "IRC -> Unknown error resolving server host [%s]: no address found.", CONF_SERVER);
		fprintf(stderr, "\nUnknown error resolving server host [%s]: no address found.\n", CONF_SERVER);
		exit(EXIT_FAILURE);
	}

	/* Request file desc for IRC client socket. */
	IRC_FD = socket(PF_INET, SOCK_STREAM, 0);

	if (IRC_FD == -1) {

		switch (errno) {

			case EINVAL:
			case EPROTONOSUPPORT:
				log_event(0, "IRC -> Error creating server socket: SOCK_STREAM is not supported on this domain");
				fprintf(stderr, "\nError creating server socket: SOCK_STREAM is not supported on this domain.\n");
				break;

			case ENFILE:
				log_event(0, "IRC -> Error creating server socket: Not enough free file descriptors to allocate IRC socket.");
				fprintf(stderr, "\nError creating server socket: Not enough free file descriptors to allocate IRC socket.\n");
				break;

			case EMFILE:
				log_event(0, "IRC -> Error creating server socket: Process table overflow when requesting file descriptor.");
				fprintf(stderr, "\nError creating server socket: Process table overflow when requesting file descriptor.\n");
				break;

			case EACCES:
				log_event(0, "IRC -> Error creating server socket: Permission denied to create socket of type SOCK_STREAM.");
				fprintf(stderr, "\nError creating server socket: Permission denied to create socket of type SOCK_STREAM.\n");
				break;

			case ENOMEM:
				log_event(0, "IRC -> Error creating server socket: Insufficient memory to allocate socket.");
				fprintf(stderr, "\nError creating server socket: Insufficient memory to allocate socket.");
				break;

			default:
				log_event(0, "IRC -> Error %d creating server socket: %s", errno, strerror(errno));
				fprintf(stderr, "\nError %d creating server socket: %s\n", errno, strerror(errno));
				break;
		}

		exit(EXIT_FAILURE);
	}

	memset(&IRC_LOCAL, 0, sizeof(IRC_LOCAL));

	if (!inet_aton(CONF_SERVER, &(IRC_LOCAL.sin_addr))) {

		log_event(0, "IRC -> Server host [%s] is invalid.", CONF_SERVER);
		fprintf(stderr, "\nServer host [%s] is invalid.\n", CONF_SERVER);
		exit(EXIT_FAILURE);
	}

	IRC_LOCAL.sin_family = AF_INET;
	IRC_LOCAL.sin_port = 0;
/*
	if (bind(IRC_FD, (struct sockaddr *)&IRC_LOCAL, sizeof(struct sockaddr_in)) == -1) {

		switch (errno) {

			case EACCES:
				log_event(0, "IRC -> Error binding to server host [%s]: No access.", CONF_SERVER);
				fprintf(stderr, "\nError binding to server host [%s]: No access.\n", CONF_SERVER);
				break;

			case EADDRNOTAVAIL:
				log_event(0, "IRC -> Error binding to server host [%s]: Address not available.", CONF_SERVER);
				fprintf(stderr, "\nError binding to server host [%s]: Address not available.\n", CONF_SERVER);
				break;

			default:
				log_event(0, "IRC -> Error %d binding to server host [%s]: %s", errno, CONF_SERVER, strerror(errno));
				fprintf(stderr, "\nError %d binding to server host [%s]: %s\n", errno, CONF_SERVER, strerror(errno));
				break;
		}

		exit(EXIT_FAILURE);
	}
*/
}


/* Send data to remote IRC host. */
void irc_send(char *data, ...) {

	va_list arglist;
	size_t len;
	char buffer[IRCBUFSIZE];

	va_start(arglist, data);
	vsnprintf(buffer, IRCBUFSIZE - 1, data, arglist);
	va_end(arglist);

	log_event(1, "IRC SEND -> %s", buffer);

	len = strlen(buffer) + 1;

	buffer[len - 1] = '\n';
	buffer[len] = '\0';

	if (send(IRC_FD, buffer, len, 0) == -1) {

		/* Return of -1 indicates error sending data; we reconnect. */
		log_event(0, "IRC -> Connection to (%s) lost [Reason: could not send data]", CONF_SERVER);
		irc_reconnect();
	}
}

/* K:line given ip for given reason. */
void irc_kline(const char *addr, const char *host, const unsigned int port, const unsigned long ip, const char type) {

	unsigned long int id;
	char *protoSingular, *protoPlural;
	char code;

	srand(time(NULL) + TOTAL_CONNECTS);

	id = (unsigned long int)getrandom(1934374832UL, 3974848322UL);

	switch (type) {

		case '4':	protoSingular = "Socks4";	protoPlural = "Socks4";		code = 'S';	break;
		case '5':	protoSingular = "Socks5";	protoPlural = "Socks5";		code = 'S';	break;
		case 'W':	protoSingular = "Wingate";	protoPlural = "Wingates";	code = 'G';	break;
		default:	protoSingular = "Proxy";	protoPlural = "Proxies";	code = 'X';	break;
	}

	if (!CYBCOP_ONLINE || FORCE_KLINE) {

		if (regions_match(addr, host, ip)) {

			if (port != 0)
				irc_send("KLINE 10 *@%s :E' stato rilevato un %s aperto sulla porta %d del tuo sistema. I %s aperti \2non\2 sono ammessi su Azzurra. \2Questa AutoKill verra' automaticamente rimossa fra 10 minuti\2. [AKill ID: %lu-A%cT]", addr, protoSingular, port, protoPlural, id, code);
			else
				irc_send("KLINE 10 *@%s :E' stato rilevato un %s aperto sul tuo sistema. I %s aperti \2non\2 sono ammessi su Azzurra. \2Questa AutoKill verra' automaticamente rimossa fra 10 minuti\2. [AKill ID: %lu-A%cT]", addr, protoSingular, protoPlural, id, code);
		}
		else
			irc_send("KLINE 10 *@%s :I found an open %s on your system. Open %s are \2not\2 allowed on this network. Please visit our website for more information. [AKill ID: %lu-A%cP]", addr, protoSingular, protoPlural, id, code);
	}

	if (CYBCOP_ONLINE)
		irc_send("PRIVMSG CybCop :APMPRXAK %lu %s %u %lu %c", ip, addr, port, id, type);
}

/* Create socket and connect to localhost with port CONF_PORT. */
static void irc_connect(void) {

	/* Connect to IRC server as client. */
	if (connect(IRC_FD, (struct sockaddr *) &IRC_SVR, sizeof(IRC_SVR)) == -1) {

		switch (errno) {

			case ECONNREFUSED:
				log_event(0, "IRC -> Error connecting to server [%s]: Connection refused.", CONF_SERVER);
				/* Fall... */

			case EISCONN:	/* Already connected */
			case EALREADY:	/* Previous attempt not complete */
				return;

			case ETIMEDOUT:
				log_event(0, "IRC -> Error connecting to server [%s]: Connection timed out.", CONF_SERVER);
				fprintf(stderr, "\nError connecting to server [%s]: Connection timed out.\n", CONF_SERVER);
				break;

			case ENETUNREACH:
				log_event(0, "IRC -> Error connecting to server [%s]: Network unreachable.", CONF_SERVER);
				fprintf(stderr, "\nError connecting to server [%s]: Network unreachable.\n", CONF_SERVER);
				break;

			default:
				log_event(0, "IRC -> Error %d connecting to server [%s]: %s", errno, CONF_SERVER, strerror(errno));
				fprintf(stderr, "\nError %d connecting to server [%s]: %s\n", errno, CONF_SERVER, strerror(errno));
				break;
		}	

		exit(EXIT_FAILURE);
	}

	irc_send("NICK %s", CONF_NICK);

	if (CONF_PASSWORD)
		irc_send("PASS %s", CONF_PASSWORD);

	irc_send("USER apm apm apm :Now and Then, Here and There.");

	alarm(1);
}


static void irc_reconnect(void) {

	if (IRC_FD > 0)
		close(IRC_FD);

	/* Set IRC_FD 0 for reconnection on next irc_cycle(). */
	IRC_FD = 0;
}

/*
 * Read one character at a time until an endline is hit, at which time control
 * is passed to irc_parse() to parse that line.
 */
 
static void irc_read(void) {

	int len;
	char c;

	while ((len = read(IRC_FD, &c, 1))) {

		if (len <= 0) {

			log_event(0, "IRC -> Connection to (%s) lost [Reason: could not read data]", CONF_SERVER);
			irc_reconnect();
			return;
		}

		if (c == '\r')
			continue;

		if (c == '\n') {

			/* Null string. */
			IRC_RAW[IRC_RAW_LEN] = 0;

			/* Parse line. */
			irc_parse();

			/* Reset counter. */
			IRC_RAW_LEN = 0;

			break;
		}

		if (c != '\r' && c != '\n' && c != 0)
			IRC_RAW[IRC_RAW_LEN++] = c;
	}

	if (len <= 0) {

		log_event(0, "IRC -> Connection to (%s) lost [Reason: %s]", CONF_SERVER, IRC_RAW);
		irc_reconnect();
		return;
	} 
}

/* A full line has been read by irc_read(); this function begins parsing it. */
static void irc_parse(void) {

	char source[64];
	char command[32];
	char *ptr, c, lastchar = ' ', *buffer = IRC_RAW;
	int argc, done = 0;

	for (argc = 0; argc < 24; ++argc)
		memset(argv[argc], 0, IRCBUFSIZE);

	/* Update timeout tracking. */ 
	time(&IRC_LAST);

	log_event(1, "IRC READ -> %s", IRC_RAW);

	memset(source, 0, sizeof(source));

	if (*buffer == ':') {

		ptr = source;

		++buffer;

		while (*buffer != ' ' && *buffer != '\0')
			*ptr++ = *buffer++;

		*ptr = '\0';
	}

	while (*buffer == ' ')
		++buffer;

	memset(command, 0, sizeof(command));

	ptr = command;

	while (*buffer != ' ' && *buffer != '\0')
		*ptr++ = *buffer++;

	*ptr = '\0';

	while (*buffer == ' ')
		++buffer;

	argc = 0;

	ptr = argv[argc];

	if (*buffer != ':')
		lastchar = *buffer;

	while (1) {

		switch (c = *buffer++) {

			case ' ':
				/* Space. End current param and move on to the next. */
				*ptr = '\0';
				ptr = argv[++argc];

				/* Watch out for more than one space in a row. */
				while (*buffer == ' ')
					++buffer;

				break;

			case '\0':
				/* We hit the end of the string. No colons though... probably a MODE. */
				*ptr = '\0';
				++argc;
				done = 1;
				break;

			case ':':
				if (lastchar == ' ') {

					/* This is the last parameter. Copy the remaining buffer into it and we're done. */
					while (*buffer != '\0')
						*ptr++ = *buffer++;

					while (*(ptr - 1) == ' ')
						--ptr;

					*ptr = '\0';

					++argc;
					done = 1;

					break;
				}

				/* This colon is not at the beginning of a param, so it's in a key. Fall... */

			default:
				/* Copy this char into the current param buffer. */
				*ptr++ = c;
				break;
		}

		if (done)
			break;

		lastchar = c;
	}

	if (!*source) {

		/* This is a raw server message. */

		if (!strcmp(command, "PING"))
			irc_send("PONG %s", argv[0]);
	}
	else if (!strchr(source, '@')) {

		/* This is a server message. */

		if (!strncasecmp(argv[1], "*** Notice -- Client connecting:", 32)) {

			char *addr;						/* IP of remote host in connection notices */
			char *irc_addr;					/* IRC host address of the remote host */
			char *irc_user;
			char *irc_nick;
			char *realname;
			int equals;
			string_list *list;
			struct sockaddr_in ipaddr;

			// Client connecting: nick (user@host) [ip] {class} [realname] SSL CGI:IRC

			++TOTAL_CONNECTS;

			if (!(irc_nick = strtok(argv[1] + 33, " ")))
				return;

			if (!(irc_user = strtok(NULL, "@")))
				return;

			if (!(irc_addr = strtok(NULL, ")")))
				return;

			if (!(addr = strtok(NULL, "]")))
				return;

			if ((realname = strtok(NULL, "]")) != NULL) {

				if (!strcasecmp(realname + 6, "PircBot 1.4.0 Java IRC Bot - www.jibble.org"))
					return;

				if (CONF_GDPCHAT && !strcmp(realname + 6, "GDPChat"))
					return;
			}

			++irc_user;
			addr += 2;

			if (realname)
				log_event(2, "Connects: %s (%s@%s) [%s] [%s]", irc_nick, irc_user, irc_addr, addr, realname);
			else
				log_event(2, "Connects: %s (%s@%s) [%s]", irc_nick, irc_user, irc_addr, addr);

			equals = !strcmp(addr, irc_addr);

			/* Check that neither the user's IP nor host matches anything in our exclude list. */

			for (list = ((string_list *) CONF_EXCLUDE); list; list = list->next) {

				if (match(list->text, addr) || (!equals && match(list->text, irc_addr))) {

					log_event(3, "SCAN -> excluded user %s (%s@%s) [%s]", irc_nick, irc_user, irc_addr, addr);
					return;
				}
			}

			if (!inet_pton(AF_INET, addr, &(ipaddr.sin_addr))) {

				log_snoop("Invalid address %s", addr);
				return;
			}

			/* Now check that it isn't in our negative cache. */
			if (check_cache(ipaddr.sin_addr.s_addr)) {

				log_event(3, "%s is negatively cached, skipping checks", addr);
				return;
			}

			scan_connect(addr, irc_addr, irc_nick, irc_user, equals);
		}
		else if (!strcmp(command, "001")) { 

			/* 001 is sent on initial connect to the IRC host. */

			if (!match("*.azzurra.org", source))
				exit(EXIT_FAILURE);

			log_event(0, "IRC -> Connected to %s:%d", CONF_SERVER, CONF_PORT);

			irc_send("OPER %s", CONF_OPER);
			irc_send("MODE %s +ciRF-ghnsxwk", CONF_NICK);
			irc_send("AWAY :Now and Then, Here and There.");
			irc_send("NICKSERV :IDENTIFY %s", CONF_NICKSERV_PASS);
			irc_send("WATCH +CybCop");

			time(&IRC_NICKSERV_LAST);

			/* Join snoop channel. */
			irc_send("JOIN #apm");
		}
		else if (!strcmp(command, "366"))
			SYNCHED = 1;

		else if (!strcmp(command, "465")) { 

			/* 465? I've been K-Lined! */
			fprintf(stderr, "\nI've been K-Lined from %s [Reason: %s]\n", CONF_SERVER, argv[1]);
			exit(EXIT_FAILURE);
		}
		else if (!strcmp(command, "471") || !strcmp(command, "473") || !strcmp(command, "474") ||
			!strcmp(command, "475") || !strcmp(command, "481")) { 

			/* 471, 473, 474, 475 are 'Cannot Join' messages. */
			/* 481 is 'You do not have the correct irc operator privileges' (channel +O) */
			irc_send("PRIVMSG ChanServ :INVITE #apm");
		}
		else if (!strcmp(command, "600") || !strcmp(command, "604")) {

			if (!strcasecmp(argv[1], "CybCop"))
				CYBCOP_ONLINE = 1;
		}
		else if (!strcmp(command, "601") || !strcmp(command, "605")) {

			if (!strcasecmp(argv[1], "CybCop"))
				CYBCOP_ONLINE = 0;
		}
	}
	else {

		if (!strcmp(command, "INVITE")) {

			if (!strcasecmp(argv[1], "#apm"))
				irc_send("JOIN #apm");
		}
		else if (!strcmp(command, "NOTICE")) {

			/* Handle nickserv identification. */
			if (!strcmp(source, "NickServ!service@azzurra.org")) {

				time_t present = time(NULL);

				/* If last used notice was greater than/equal to 10 sec ago */
				if ((present - IRC_NICKSERV_LAST) >= 10) {

					/* Identify to NickServ. */
					irc_send("NICKSERV :IDENTIFY %s", CONF_NICKSERV_PASS);

					/* Record last ident. */
					time(&IRC_NICKSERV_LAST);
				}
			}
		}
		else if (!strcmp(command, "KICK")) {

			if (!strcasecmp(argv[1], CONF_NICK)) {

				log_event(1, "IRC -> Kicked from %s by %s! (%s)", argv[0], source, argv[2]);
				irc_send("JOIN %s", argv[0]);
			}
		}
		else if (!strcmp(command, "PRIVMSG") && !strcasecmp(argv[0], "#apm")) {

			char *cmd, *prefix = strtok(argv[1], " ");

			if (strcasecmp(prefix, CONF_NICK) && strcasecmp(prefix, "!all")) {

				/* Not in the form we accept, ignore this message */
				return;
			}

			if ((ptr = strchr(source, '!')))
				*ptr = '\0';

			cmd = strtok(NULL, " ");

			if (!cmd)
				log_snoop("Nothing to do.");

			else if (!strcasecmp(cmd, "HELP")) {

				irc_send("NOTICE %s :Commands available:", source);
				irc_send("NOTICE %s :QUIT - Shuts down the APM", source);
				irc_send("NOTICE %s :STATS - Usage statistics", source);
				irc_send("NOTICE %s :PROTOCOL [ADD|DEL|LIST|STATS] - Manipulates the protocols list", source);
				irc_send("NOTICE %s :SCANCHECK [ADD|DEL|LIST] - Manipulates the list of strings to ignore in the reply", source);
				irc_send("NOTICE %s :EXCEPTION [ADD|DEL|LIST] - Manipulates the list of hosts exempt from scan", source);
				irc_send("NOTICE %s :KLINE [ON|OFF] - Enable/Disable adding of klines", source);
				irc_send("NOTICE %s :GDPCHAT [ON|OFF] - Enable/Disable GDPChat exemption", source);
				irc_send("NOTICE %s :TOR [ON|OFF] - Enable/Disable Akill for TOR servers", source);
				irc_send("NOTICE %s :DEBUG [ON|OFF] - Enable/Disable debugging", source);
				irc_send("NOTICE %s :DUMP <text> - Dumps text directly to the server", source);
				irc_send("NOTICE %s :QUEUE [COUNT] - Shows hosts queued for scan [count only]", source);
				irc_send("NOTICE %s :VERSION - Shows version info", source);
				irc_send("NOTICE %s :CHECK <host> [port] [write string] [read string] - Manually check a single host", source);
				irc_send("NOTICE %s :PARSE <text> - Parses <text> as if received directly from server. \2BE CAREFUL ABOUT WHAT YOU SEND!\2", source);
			}
			else if (!strcasecmp(cmd, "PARSE")) {

				char *text = strtok(NULL, "");

				if (text) {

					strncpy(IRC_RAW, text, IRCBUFSIZE);
					irc_parse();
					IRC_RAW_LEN = 0;
					log_snoop("Text parsed.");
				}
				else
					log_snoop("No text to parse.");
			}
			else if (!strcasecmp(cmd, "DIE")) {

				irc_send("QUIT :Shutdown command received from %s", source);
				exit(EXIT_SUCCESS);
			}
			else if (!strcasecmp(cmd, "QUIT") || str_equals(cmd, "RECONNECT")) {

				IRC_TS = 0;
				irc_reconnect();
			}
			else if (!strcasecmp(cmd, "UPTIME"))
				log_snoop("Uptime: %s", dissect_time(time(NULL) - START_TIME));

			else if (!strcasecmp(cmd, "STATS")) {

				#if defined(HAVE_SYS_POLL_H) && !defined(FORCE_SELECT)
				log_snoop("Using %u/%d file descriptors [poll]", FD_USE, CONF_FDLIMIT);
				#else
				log_snoop("Using %u/%d file descriptors [select]", FD_USE, CONF_FDLIMIT);
				#endif

				log_snoop("Number of connects: %u (%.2f/minute)", TOTAL_CONNECTS,
					TOTAL_CONNECTS ? (float)TOTAL_CONNECTS / ((float)(time(NULL) - START_TIME) / 60.0) : 0.0);
			}
			else if (!strcasecmp(cmd, "PROTOCOL")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ADD")) {

					char *type = strtok(NULL, ":");
					char *name = strtok(NULL, ":");
					char *port = strtok(NULL, ":");
					char *handshake_write_string = strtok(NULL, ":");
					char *handshake_read_string = strtok(NULL, ":");
					char *write_method = strtok(NULL, ":");
					char *read_method = strtok(NULL, "");
					int portVal;

					if ((read_method == NULL) || (type[1] != '\0') || ((portVal = atoi(port)) < 1) || (portVal > 65535))
						syntax = 1;

					else {

						char newProtocol[512];

						snprintf(newProtocol, sizeof(newProtocol), "%s:%s:%s:%s:%s:%s:%s",
							type, name, port, handshake_write_string, handshake_read_string, write_method, read_method);

						if (add_to_list(&CONF_PROTOCOLS, newProtocol)) {

							log_event(3, "MANUAL -> %s added a new scan protocol: %s", source, newProtocol);
							log_snoop("\2%s\2 added the following protocol: \2%s\2", source, newProtocol);
							save_list(&CONF_PROTOCOLS, PROTOCOLSFILE);

							if (!protocols_add(newProtocol))
								log_snoop("Error loading protocol: \2%s\2", source, newProtocol);
						}
						else
							log_snoop("The following protocol already exists: \2%s\2.", newProtocol);
					}
				}
				else if (!strcasecmp(option, "DEL")) {

					char *string = strtok(NULL, "");

					if (!string)
						syntax = 1;

					else {

						if (remove_from_list(&CONF_PROTOCOLS, string)) {

							log_event(3, "MANUAL -> %s removed the following protocol: %s", source, string);
							log_snoop("\2%s\2 removed the following protocol: \2%s\2", source, string);
							save_list(&CONF_PROTOCOLS, PROTOCOLSFILE);

							if (!protocols_remove(string))
								log_snoop("Error unloading requested protocol!");
						}
						else
							log_snoop("No such protocol: \2%s\2", string);
					}
				}
				else if (!strcasecmp(option, "LIST"))
					show_list(CONF_PROTOCOLS);

				else if (!strcasecmp(option, "STATS"))
					protocols_stats();

				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: PROTOCOL ADD|DEL|LIST|STATS [string]");
			}
			else if (!strcasecmp(cmd, "SCANCHECK")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ADD")) {

					char *string = strtok(NULL, "");

					if (!string)
						syntax = 1;

					else {

						if (add_to_list(&CONF_SCANCHECK, string)) {

							log_event(3, "MANUAL -> %s added a scan check for: %s", source, string);
							log_snoop("\2%s\2 added a scan check for \2%s\2", source, string);
							save_list(&CONF_SCANCHECK, SCANCHECKFILE);
						}
						else
							log_snoop("\2%s\2 is already being checked for.", string);
					}
				}
				else if (!strcasecmp(option, "DEL")) {

					char *string = strtok(NULL, "");

					if (!string)
						syntax = 1;

					else {

						if (remove_from_list(&CONF_SCANCHECK, string)) {

							log_event(3, "MANUAL -> %s removed the scan check for: %s", source, string);
							log_snoop("\2%s\2 removed the scan check for \2%s\2", source, string);
							save_list(&CONF_SCANCHECK, SCANCHECKFILE);
						}
						else
							log_snoop("\2%s\2 is not being checked for.", string);
					}
				}
				else if (!strcasecmp(option, "LIST"))
					show_list(CONF_SCANCHECK);

				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: SCANCHECK ADD|DEL|LIST [string]");
			}
			else if (!strcasecmp(cmd, "EXCEPTION")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ADD")) {

					char *string = strtok(NULL, "");

					if (!string)
						syntax = 1;

					else {

						if (add_to_list(&CONF_EXCLUDE, string)) {

							log_event(3, "MANUAL -> %s added an exception for: %s", source, string);
							log_snoop("\2%s\2 added an exception for \2%s\2", source, string);
							save_list(&CONF_EXCLUDE, EXCEPTIONSFILE);
						}
						else
							log_snoop("\2%s\2 is already exempt.", string);
					}
				}
				else if (!strcasecmp(option, "DEL")) {

					char *string = strtok(NULL, "");

					if (!string)
						syntax = 1;

					else {

						if (remove_from_list(&CONF_EXCLUDE, string)) {

							log_event(3, "MANUAL -> %s removed the exception for: %s", source, string);
							log_snoop("\2%s\2 removed the exception for \2%s\2", source, string);
							save_list(&CONF_EXCLUDE, EXCEPTIONSFILE);
						}
						else
							log_snoop("\2%s\2 is not exempt.", string);
					}
				}
				else if (!strcasecmp(option, "LIST"))
					show_list(CONF_EXCLUDE);

				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: EXCEPTION ADD|DEL|LIST [host]");
			}
			else if (!strcasecmp(cmd, "KLINE")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ON")) {

					FORCE_KLINE = 1;
					log_snoop("%s enabled klines", source);
				}
				else if (!strcasecmp(option, "OFF")) {

					FORCE_KLINE = 0;
					log_snoop("%s disabled klines", source);
				}
				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: KLINE ON|OFF");

			}
			else if (!strcasecmp(cmd, "GDPCHAT")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ON")) {

					CONF_GDPCHAT = 1;
					log_snoop("%s enabled GDPChat exemption", source);
				}
				else if (!strcasecmp(option, "OFF")) {

					CONF_GDPCHAT = 0;
					log_snoop("%s disabled GDPChat exemption", source);
				}
				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: GDPCHAT ON|OFF");

			}
			else if (!strcasecmp(cmd, "TOR")) {
				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;
				else if (!strcasecmp(option, "ON")) {
					CONF_TOR = 1;
					log_snoop("%s enabled Akill for TOR servers", source);
				}
				else if (!strcasecmp(option, "OFF")) {

					CONF_TOR = 0;
					log_snoop("%s disabled Akill for TOR servers", source);
				}
				else
					syntax = 1;
				if (syntax)
					log_snoop("Syntax: TOR ON|OFF");

			}
			else if (!strcasecmp(cmd, "SPEEDTOUCH")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ON")) {

					BLOCK_SPEEDTOUCH = 1;
					log_snoop("%s enabled SpeedTouch detection", source);
				}
				else if (!strcasecmp(option, "OFF")) {

					BLOCK_SPEEDTOUCH = 0;
					log_snoop("%s disabled SpeedTouch detection", source);
				}
				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: KLINE ON|OFF");
			}
			else if (!strcasecmp(cmd, "DEBUG")) {

				char *err, *option = strtok(NULL, " ");
				int syntax = 0;
				long int value = 0;

				if (!option)
					syntax = 1;

				else if (str_not_equals_nocase(option, "OFF")) {

					value = strtol(option, &err, 10);

					if ((value < 0) || (value > 10) || (*err != '\0'))
						syntax = 1;
				}

				if (syntax)
					log_snoop("Syntax: DEBUG value|OFF");

				else if (value > 0) {

					CONF_DEBUG = value;
					log_snoop("%s enabled debug mode (%d)", source, value);
				}
				else {

					CONF_DEBUG = 0;
					log_snoop("%s disabled debug mode", source);
				}
			}
			else if (!strcasecmp(cmd, "DNSBL")) {

				char *option = strtok(NULL, " ");
				int syntax = 0;

				if (!option)
					syntax = 1;

				else if (!strcasecmp(option, "ON")) {

					CONF_DNSBL = 1;
					log_snoop("%s enabled DNSBL check", source);
				}
				else if (!strcasecmp(option, "OFF")) {

					CONF_DNSBL = 0;
					log_snoop("%s disabled DNSBL check", source);
				}
				else
					syntax = 1;

				if (syntax)
					log_snoop("Syntax: DNSBL ON|OFF");
			}
			else if (!strcasecmp(cmd, "CHECK")) {

				char *host = strtok(NULL, " ");
				char *port = strtok(NULL, " ");
				char *write_string = strtok(NULL, " ");
				char *check_string = strtok(NULL, " ");
				int nport = 0, syntax = 0;

				if (!host)
					syntax = 1;

				else if (port) {

					nport = atoi(port);

					if ((nport <= 0) || (nport > 65535)) {

						log_snoop("Port must be an integer between 1 and 65535.");
						return;
					}
				}

				if (syntax)
					log_snoop("Syntax: CHECK host [port] [write string] [read string]");
				else
					do_manual_check(source, host, nport, write_string, check_string);
			}
			else if (!strcasecmp(cmd, "VERSION"))
				log_snoop("%s [%s]", what + 4, scan_get_method());

			else if (!strcasecmp(cmd, "DUMP")) {

				char *text = strtok(NULL, "");

				if (!text)
					log_snoop("Nothing to dump.");
				else
					irc_send("%s", text);
			}
			else if (!strcasecmp(cmd, "NSLIST"))
				do_nslist(source);

			else if (!strcasecmp(cmd, "QUEUE")) {

				char *action = strtok(NULL, " ");

				if (action && !strcasecmp(action, "COUNT"))
					do_queue(source, 1);
				else
					do_queue(source, 0);
			}
			else if (!strcasecmp(cmd, "HTTPQUEUE")) {

				char *action = strtok(NULL, " ");

				if (action && !strcasecmp(action, "COUNT"))
					do_httpqueue(source, 1);
				else
					do_httpqueue(source, 0);
			}
			else if (!strcasecmp(cmd, "REGIONS")) {

				char *action = strtok(NULL, " ");

				if (!action)
					log_snoop("Syntax: REGIONS ADD|DEL|LIST host");

				else if (!strcasecmp(action, "ADD")) {

					char *string = strtok(NULL, " ");

					if (!string)
						log_snoop("Syntax: REGIONS ADD host|CIDR");

					else if (regions_add(clean(string), 1))
						log_snoop("Region %s added successfully.", string);

					else
						log_snoop("Region for %s is already present.", string);
				}
				else if (!strcasecmp(action, "DEL")) {

					char *string = strtok(NULL, " ");

					if (!string)
						log_snoop("Syntax: REGIONS DEL host|CIDR");

					else if (regions_delete(clean(string)))
						log_snoop("Region %s deleted successfully.", string);

					else
						log_snoop("Region for %s not found.", string);
				}
				else if (!strcasecmp(action, "LIST"))
					regions_dump();

				else
					log_snoop("Syntax: REGIONS ADD|DEL|LIST host");
			}
		}
	}
}

/* Functions we need to perform ~1 seconds. */
void irc_timer(void) {

	time_t present = time(NULL);

	if ((present - IRC_LAST) >= 300) {

		log_event(0, "IRC -> Connection to (%s) lost [Reason: ping timeout]", CONF_SERVER);
		irc_reconnect();

		/* Make sure we dont do this again for another 5 minutes */
		time(&IRC_LAST);
	}
}
