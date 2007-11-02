/*
 * Azzurra Proxy Monitor - firedns.c
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

/* $Id$ */


#include "../inc/setup.h"

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include "../inc/firedns.h"
#include "../inc/config.h"
#include "../inc/options.h"
#include "../inc/irc.h"
#include "../inc/log.h"
#include "../inc/http.h"
#include "../inc/scan.h"
#include "../inc/misc.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

/* DNS query. */
typedef struct _fdns_struct fdns_struct;
struct _fdns_struct {

	fdns_struct	*next;

	unsigned char id[2];			/* Random number. */

	int		fd;						/* File descriptor returned from sockets. */
	time_t	start;					/* TS of query start. */

	char	nick[31];				/* Nick used on IRC, or nick of who requested it. */
	char	username[11];			/* Username used on IRC (NULL if requested). */
	char	host[128];				/* Host used on IRC. */

	short	requested;				/* Was it requested? */
	short	equals;					/* IP == host */

	char	ip[16];					/* Original IP. */
	Zone	*zone;				/* Index of blacklist zone. */

	char	payload[512];			/* Name to lookup. */
	int		payloadLen;
};

struct s_rr_middle {

	unsigned short type;			/* Two bytes, holding the type of this query.
									       Values:  1 - A (host address)
										            2 - NS (Authoritative NS)
												    3 - MD (Mail Destination), obsolete
												    4 - MF (Mail Forwarder), obsolete
												    5 - CNAME (Aliases)
												    6 - SOA (Start of a zone of Authority)
												    7 - MB (Mail Box), experimental
												    8 - MG (Mail Group), experimental
												    9 - MR (Mail Rename), experimental
												   10 - NULL (a NULL RR), experimental
												   11 - WKS (Well Known Service)
												   12 - PTR (domain name pointer)
												   13 - HINFO (host information)
												   14 - MINFO (mail box info)
												   15 - MX (Mail eXchange)
												   16 - TXT (text strings)
									*/

	unsigned short rrclass;			/* Two bytes, holding the class of this query.
									       Values: 1 - IN (the Internet)
										           2 - CS (CSNET), obsolete
												   3 - CH (CHAOS)
												   4 - HS (Hesiod)
									*/
	unsigned int ttl;				/* Four bytes, holding the record TTL. */
	unsigned short rdlength;		/* Two bytes, holding the length of the following RDATA field. */
};

/* DNS query header. */
typedef struct _fdns_header fdns_header;
struct _fdns_header {

	unsigned char id[2];			/* Two bytes, holding message ID. */
	unsigned char flags1;			/* One byte.
									   Bit 0 is QR, specifies whether this is a query or a response.
									       Values: 0 if it's a query, 1 if it's a response.
									   Bits 1 to 4 are the OPCODE, specify the kind of query.
									       Values: 0 - Standard query (QUERY)
										           1 - Inverse query (IQUERY)
												   2 - Server status request (STATUS)
												   3-15 are reserved for future use
									   Bit 5 is AA (Authoritative Answer), valid in responses only.
									     Specifies whether the responding NS is an authority for the
										 domain in the request section.
									   Bit 6 is TC (TrunCation), specifies that this message was
									     truncated due to length greater than that permitted.
									   Bit 7 is RD (Recursion Desired), copied into the response.
									     Requests the NS to pursue the query recursively.
									*/

	unsigned char flags2;			/* One byte.
									   Bit 0 is RA (Recursion Available), it's set in a response,
									     and denotes whether recursion is available or not.
									   Bits 1 to 3 are Z (Reserved) and must always be 0.
									   Bits 4 to 7 are RCODE (Response Code).
									       Values: 0 - No error condition
										           1 - Query format error
												   2 - Server failure
												   3 - Name error (the name does not exist). Valid
												       only for responses from an authoritative NS.
												   4 - Not implemented
												   5 - Refused
												   6-15 are reserved for future use
									*/

	unsigned short qdcount;		/* Holds the number of entries in the question section. */
	unsigned short ancount;		/* Holds the number of RRs in the answer section. */
	unsigned short nscount;		/* Holds the number of NS RRs in the authority records section. */
	unsigned short arcount;		/* Holds the number of RRs in the additional records section. */

	/* DNS question. */
	unsigned char payload[1024];
};

typedef struct _ns_struct ns_struct;
struct _ns_struct {

	ns_struct		*next;

	char			*name;
	struct in_addr	addr;
};


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of nameservers. */
static ns_struct *NAMESERVERS;

/* Actual count of nameservers. */
static int NSCount;

/* List of DNS queries. */
static fdns_struct *CONNECTIONS = NULL;

/* List of DNSBL zones. */
Zone *ZoneArray[4];


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static int firedns_doquery(fdns_struct *fdns);
static fdns_result *firedns_getresult(fdns_struct *fdns);
static void firedns_record_add(fdns_struct *fdns);
static void firedns_record_remove(fdns_struct *delfdns);
static void dnsbl_result(const fdns_result *res);
static char *firedns_strerror(int error);
static int validate_result(const fdns_result *res);


/*********************************************************
 * Initialization routine                                *
 *********************************************************/

void firedns_init(void) {

	FILE			*f;
	struct in_addr	addr;
	char			buffer[1024];
	char			*name, *filename;
	int				idx;


	srand((unsigned int) time(NULL));

	/* Initialize DNSBL Zones. */

	for (idx = 0; idx < 7; ++idx) {

		ZoneArray[idx] = (Zone *)calloc(1, sizeof(Zone));

		ZoneArray[idx]->idx = idx;

		switch (idx) {

			case 0:
				ZoneArray[idx]->name = "OPM";
				ZoneArray[idx]->sockaddr.sin_family = AF_INET;
				ZoneArray[idx]->sockaddr.sin_port = htons(80);
				ZoneArray[idx]->sockaddr.sin_addr.s_addr = inet_addr("82.195.234.2");
				ZoneArray[idx]->host = "opm.blitzed.org";
				ZoneArray[idx]->url = "/details?ip=";
				break;

			case 1:
				ZoneArray[idx]->name = "DSBL";
				ZoneArray[idx]->sockaddr.sin_family = AF_INET;
				ZoneArray[idx]->sockaddr.sin_port = htons(80);
				ZoneArray[idx]->sockaddr.sin_addr.s_addr = inet_addr("205.231.29.240");
				ZoneArray[idx]->host = "dsbl.org";
				ZoneArray[idx]->url = "/listing?";
				break;

			case 2:
				ZoneArray[idx]->name = "TOR";
				ZoneArray[idx]->sockaddr.sin_family = AF_INET;
				ZoneArray[idx]->sockaddr.sin_port = htons(80);
				ZoneArray[idx]->sockaddr.sin_addr.s_addr = inet_addr("205.231.29.24");
				ZoneArray[idx]->host = "www.sectoor.de";
				ZoneArray[idx]->url = "/tor.php?ip=";
				break;

			case 3:
				ZoneArray[idx]->name = "NJABL";
				ZoneArray[idx]->sockaddr.sin_family = AF_INET;
				ZoneArray[idx]->sockaddr.sin_port = htons(80);
				ZoneArray[idx]->sockaddr.sin_addr.s_addr = inet_addr("209.208.0.104");
				ZoneArray[idx]->host = "njabl.org";
				ZoneArray[idx]->url = "/cgi-bin/lookup.cgi?query=";
				break;
		}
	}

	/* Read etc/firedns.conf if we've got it, otherwise parse /etc/resolv.conf */

	if (!(f = fopen("./firedns.conf", "r"))) {

		if (!(f = fopen("/etc/resolv.conf", "r"))) {

			log_event(0, "FIREDNS -> Error opening config files.");
			fprintf(stderr, "\nError opening firedns config files. Aborting.\n");
			return;
		}

		filename = "/etc/resolv.conf";

		while (fgets(buffer, 1024, f) != NULL) {

			name = strtok(buffer, "\n\r");

			if ((name != NULL) && !strncmp(name, "nameserver", 10)) {

				name += 10;

				while ((*name == ' ') || (*name == '\t'))
					++name;

				if (inet_aton(name, &addr)) {

					ns_struct *ns;

					ns = (ns_struct *) calloc(1, sizeof(ns_struct));

					ns->name = strdup(name);
					memcpy(&(ns->addr), &addr, sizeof(struct in_addr));

					ns->next = NAMESERVERS;
					NAMESERVERS = ns;

					log_event(0, "FIREDNS -> Added nameserver %s", name);
					++NSCount;
				}

				if (NSCount >= FDNS_MAX)
					break;
			}
		}
	}
	else {

		filename = "firedns.conf";

		while (fgets(buffer, 1024, f) != NULL) {

			buffer[strspn(buffer, "0123456789.")] = '\0';

			if (inet_pton(AF_INET, buffer, (char *)&addr)) {

				ns_struct *ns;

				ns = (ns_struct *) calloc(1, sizeof(ns_struct));

				ns->name = strdup(buffer);
				memcpy(&(ns->addr), &addr, sizeof(struct in_addr));

				ns->next = NAMESERVERS;
				NAMESERVERS = ns;

				log_event(0, "FIREDNS -> Added nameserver %s", buffer);
				++NSCount;
			}

			if (NSCount >= FDNS_MAX)
				break;
		}
	}

	fclose(f);

	if (NSCount == 0) {

		log_event(0, "FIREDNS -> No nameservers found in %s", filename);
		fprintf(stderr, "\nNo nameservers found in %s. Aborting.\n", filename);
		exit(EXIT_FAILURE);
	}
}

static int firedns_request(const char *ip, const char *nick, const char *username, const char *host, int equals,
						   Zone *zone, const char *payload, const int payloadLen) {

	fdns_struct *fdns;
	int			fd;


	/* Create new connection object. */
	fdns = calloc(1, sizeof(fdns_struct));

	/* Fill it. */
	fdns->id[0] = rand() % 255;
	fdns->id[1] = rand() % 255;

	fdns->fd = -1;

	fdns->equals = equals;

	strncpy(fdns->ip, ip, sizeof(fdns->ip));
	strncpy(fdns->nick, nick, sizeof(fdns->nick));

	memcpy(fdns->payload, payload, payloadLen);
	fdns->payloadLen = payloadLen;

	if (!fdns->equals)
		strncpy(fdns->host, host, sizeof(fdns->host));

	if (!username)
		fdns->requested = 1;
	else
		strncpy(fdns->username, username, sizeof(fdns->username));

	fdns->zone = zone;

	/* Done filling, do something with it. */

	if (FD_USE >= CONF_FDLIMIT) {

		log_event(4, "DNSBL -> File Descriptor limit (%d) reached, queuing query for %s", CONF_FDLIMIT, ip);

		/* Reached fd limit, add to queue. */
		firedns_record_add(fdns);

		return 0;
	}

	/* We have fds to spare, jump queue and start the query. */
	fd = firedns_doquery(fdns);

	if (fd == -1) {

		free(fdns);
		return -1;
	}

	firedns_record_add(fdns);
	return fd;
}

static int firedns_doquery(fdns_struct *fdns) {

	int					dataSent = 0;
	struct sockaddr_in	addr;
	fdns_header			header;
	ns_struct			*ns;


	/* Set up the query header. */

	/* Set the header ID, the same as the fdns record that generated it. */
	memcpy(header.id, fdns->id, 2);

	/* Set header flags. */
	/* We want to set QR to 0 (query), OPCODE to 0 (standard query), AA to 0 (response only),
	   TC to 0 (response only), and RD to 1 (we want recursion). The result is 1 bin, or 0x01 hex. */
	header.flags1 = 0x01;

	/* We want to set RA to 0 (response only), Z to 0 (reserved) and RCODE to 0 (response only).
	   All zero's. */
	header.flags2 = 0;

	header.qdcount = htons(1);	/* This is a single query. */
	header.ancount = htons(0);	/* This is valid in responses only. */
	header.nscount = htons(0);	/* This is valid in responses only. */
	header.arcount = htons(0);	/* This is valid in responses only. */

	/* Done with the header, set up the question packet next. */

	/* Everything up to the first \0 is the name. */
	memcpy(header.payload, fdns->payload, fdns->payloadLen);

	/* TYPE and CLASS are supposed to follow... hmm. */

	/* Our query is ready, send it out now. */

	/* Try to create ipv4 socket. */
	if ((fdns->fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {

		log_snoop("FIREDNS -> Out of sockets when checking for %s", fdns->ip);
		return -1;
	}

	/* Try to set it non-blocking. */
	if (fcntl(fdns->fd, F_SETFL, O_NONBLOCK) != 0) {

		log_snoop("FIREDNS -> Error setting socket nonblock when checking for %s", fdns->ip);

		close(fdns->fd);
		fdns->fd = -1;

		return -1;
	}

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = 0;
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(fdns->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {

		log_snoop("FIREDNS -> Error binding socket when checking for %s", fdns->ip);

		close(fdns->fd);
		fdns->fd = -1;

		return -1;
	}

	ns = NAMESERVERS;

	while (ns != NULL) {

		memset(&addr, 0, sizeof(addr));

		memcpy(&addr.sin_addr, &(ns->addr), sizeof(addr.sin_addr));

		addr.sin_family = AF_INET;
		addr.sin_port = htons(53);		/* DNS port */

		/* Note: total size of the header without the payload is 12 bytes. */
		if (sendto(fdns->fd, &header, fdns->payloadLen + 12, 0, (struct sockaddr *) &addr, sizeof(addr)) > 0)
			dataSent = 1;

		ns = ns->next;
	}

	if (!dataSent) {

		log_snoop("FIREDNS -> Error sending request to nameservers when checking for %s", fdns->ip);

		close(fdns->fd);
		fdns->fd = -1;

		return -1;
	}

	time(&fdns->start);
	++FD_USE;

	return fdns->fd;
}

static fdns_result *firedns_getresult(fdns_struct *fdns) {

	static fdns_result	result;
	fdns_header			header;
	int					bytes, payloadLen, payloadIdx = 0, questionIdx = 0, answerIdx = 0;
	struct s_rr_middle	*rr = NULL, rrbacking;
	char				*src, *dst;


	/* Fill result first. */
	memset(&result, 0, sizeof(result));

	strncpy(result.ip, fdns->ip, sizeof(result.ip));

	result.zone = fdns->zone;

	strncpy(result.nick, fdns->nick, sizeof(result.nick));

	if (fdns->requested)
		result.requested = 1;
	else
		strncpy(result.username, fdns->username, sizeof(result.username));

	if (fdns->equals)
		result.equals = 1;
	else
		strncpy(result.host, fdns->host, sizeof(result.host));

	/* Now read the DNS server reply to our query. */
	payloadLen = recv(fdns->fd, &header, sizeof(fdns_header), 0);

	if (payloadLen == -1) {

		result.error = FDNS_ERR_PAYLOAD;
		return &result;
	}

	/* We read less than the minimum required to fill a header. Error out. */
	if (payloadLen < 12)
		return &result;

	/* ID mismatch: we keep the connection, as this could be an answer to a previous lookup. */
	if ((fdns->id[0] != header.id[0]) || (fdns->id[1] != header.id[1]))
		return NULL;

	/* Make sure this is a response and not a query (i.e. QR is set to 1).
	   QR is the first bit, and 0x80 hex = 0x10000000 bin. */
	if ((header.flags1 & 0x80) == 0) {

		result.error = FDNS_ERR_QR;
		return &result;
	}

	/* Also make sure that the OPCODE values in the first bit are empty, as they must match the
	   ones we sent (empty). OPCODE has bits 2 to 5, and 0x78 hex = 0x01111000 bin. */
	if ((header.flags1 & 0x78) != 0) {

		result.error = FDNS_ERR_OPCODE;
		return &result;
	}

	/* Now check the response code. A value of 0 indicates success, so anything else is an error.
	   RCODE has bits 4 to 7, and 0x0F hex = 0x00001111 bin. */
	if ((header.flags2 & 0x0F) != 0) {

		result.error = (header.flags2 & 0x0F);
		return &result;
	}

	/* Count the number of answers. If there isn't at least one, we may as well stop here. */
	header.qdcount = ntohs(header.qdcount);
	header.ancount = ntohs(header.ancount);
	header.nscount = ntohs(header.nscount);
	header.arcount = ntohs(header.arcount);

	if (header.ancount < 1) {

		result.error = FDNS_ERR_NOANSWER;
		return &result;
	}

	/* Skip the first 12 bytes (the header). */
	payloadLen -= 12;

	/* Skip the question block, it's the same as the one we sent... well, it should anyway. */
	while (questionIdx < header.qdcount) {

		/* We need to read every answer. The first field is always the NAME one,
		   but we do not need it, so we get rid of it with the following loop. */

		if (payloadIdx >= payloadLen) {

			result.error = FDNS_ERR_QLEN;
			return &result;
		}

		if (header.payload[payloadIdx] > 63) {

			/* This is a pointer (two bytes). CLASS (two bytes) and TYPE (two bytes) follow. */
			payloadIdx += 6;

			/* That's all for this question, get on to the next. */
			++questionIdx;
		}
		else {

			/* This is a label. */
			if (header.payload[payloadIdx] == 0) {

				/* We reached the root label. Skip it (1 byte), CLASS and TYPE. */
				payloadIdx += 5;


				/* That's all for this question, get on to the next. */
				++questionIdx;
			}
			else {

				/* This is a normal label. Skip the length (1 byte) and the whole label name. */
				payloadIdx += (1 + header.payload[payloadIdx]);

				/* More labels follow, continue looping. */
			}
		}
	}

	/* 'payloadIdx' should now point to the beginning of the first response. */

	while (answerIdx < header.ancount) {

		/* We need to read every answer. The first field is always the NAME one,
		   but we do not need it, so we get rid of it with the following loop. */

		while (payloadIdx < payloadLen) {

			if (header.payload[payloadIdx] > 63) {

				/* This is a pointer (2 bytes). Skip it and we're done. */
				payloadIdx += 2;
				break;
			}
			else {

				/* This is a label. */
				if (header.payload[payloadIdx] == 0) {

					/* This is the root label (1 byte). Skip it and we're done. */
					++payloadIdx;
					break;
				}
				else {

					/* This is a normal label. Skip the length (1 byte) and the whole label name. */
					payloadIdx += (1 + header.payload[payloadIdx]);
				}
			}
		}

		/* If we skipped so much there's not enough data for a RR left, error out. */
		if ((payloadLen - payloadIdx) < 10) {

			result.error = FDNS_ERR_ALEN;
			return &result;
		}

		/* Proceed to read RDATA stuff: TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes),
		   and RDLENGTH (2 bytes). 10 bytes total. */

		rr = (struct s_rr_middle *)&header.payload[payloadIdx];
		src = (char *) rr;
		dst = (char *) &rrbacking;

		for (bytes = sizeof(rrbacking); bytes; bytes--)
			*dst++ = *src++;

		rr = &rrbacking;

		/* We've read 10 bytes, update the pointer. */
		payloadIdx += 10;

		/* DNS data is in network byte order. Convert it. */
		rr->rdlength = ntohs(rr->rdlength);

		/* We want an Internet class answer (type 1). */
		if (ntohs(rr->rrclass) != 1) {

			/* This answer is not though, so skip it and whatever follows. */
			++answerIdx;
			payloadIdx += rr->rdlength;
			continue;
		}

		/* We also want a host address answer (type 1), so make sure this is a suitable one. */
		if (ntohs(rr->type) != 1) {

			/* It isn't, skip it and whatever follows. */
			++answerIdx;
			payloadIdx += rr->rdlength;
			continue;
		}

		/* If we haven't found a valid answer RR, error out. */
		if (!rr || (answerIdx == header.ancount))
			return &result;

		/* Also make sure the data we're going to need made it in the buffer. */
		if ((payloadIdx + rr->rdlength) > payloadLen)
			return &result;

		if (rr->rdlength > 1023) {

			result.error = FDNS_ERR_RRLEN;
			return &result;
		}

		memcpy(result.text[result.count], &header.payload[payloadIdx], rr->rdlength);
		result.text[result.count][rr->rdlength] = '\0';

		++result.count;

		++answerIdx;
		payloadIdx += rr->rdlength;
	}

	/* Why are we here? */
	return &result;
}

void firedns_cycle(void) {

	static struct pollfd	ufds[EVENT_CHUNK];
	fdns_struct				*fdns, *next;
	fdns_result				*res, result;
	unsigned int			size, i;
	time_t					NOW;


	if (!CONNECTIONS)
		return;

	time(&NOW);
	size = 0;

	for (fdns = CONNECTIONS; fdns; fdns = next) {

		next = fdns->next;

		if (size >= CONF_FDLIMIT)
			break;

		if (fdns->fd < 0)
			continue;

		if ((fdns->fd > 0) && ((fdns->start + FDNS_TIMEOUT) < NOW)) {

			/* Timed out - remove from list */

			/* Fill result first. */
			memset(&result, 0, sizeof(result));

			strncpy(result.ip, fdns->ip, sizeof(result.ip));

			result.zone = fdns->zone;

			strncpy(result.nick, fdns->nick, sizeof(result.nick));

			if (fdns->requested)
				result.requested = 1;
			else
				strncpy(result.username, fdns->username, sizeof(result.username));

			if (fdns->equals)
				result.equals = 1;
			else
				strncpy(result.host, fdns->host, sizeof(result.host));

			result.error = FDNS_ERR_TIMEOUT;

			log_event(4, "FIREDNS -> Entry for %s has timed out, removing", fdns->ip);

			firedns_record_remove(fdns);

			/* Report result (negative). */
			dnsbl_result(&result);
			continue;
		}

		ufds[size].events = 0;
		ufds[size].revents = 0;
		ufds[size].fd = fdns->fd;
		ufds[size].events = POLLIN;

		if (++size >= EVENT_CHUNK)
			break;
	}

	switch (poll(ufds, size, 0)) {

		case -1:
		case 0:
			return;
	}

	for (fdns = CONNECTIONS; fdns; fdns = next) {

		next = fdns->next;

		if (fdns->fd > 0) {

			for (i = 0; i < size; ++i) {

				if ((ufds[i].revents & POLLIN) && (ufds[i].fd == fdns->fd)) {

					res = firedns_getresult(fdns);

					log_event(4, "FIREDNS -> Got result for %s", fdns->ip);

					if (res != NULL)
						dnsbl_result(res);
					else
						log_snoop("FIREDNS -> Result for %s is NULL", fdns->ip);

					log_event(4, "FIREDNS -> Removing entry for %s (got result)", fdns->ip);

					firedns_record_remove(fdns);
					break;
				}
			}
		}
		else if (FD_USE < CONF_FDLIMIT)
			firedns_doquery(fdns);
	}
}

static void firedns_record_add(fdns_struct *fdns) {

	log_event(4, "DNSBL -> Adding to firedns list: %s [%s]", fdns->ip, fdns->zone->name);

	/* Only item in list. */

	if (!CONNECTIONS) {

		fdns->next = NULL;
		CONNECTIONS = fdns;
	}
	else {

		fdns_struct *list;

		/* Link to end of list. */
		for (list = CONNECTIONS; list; list = list->next) {

			if (!list->next) {

				fdns->next = NULL;
				list->next = fdns;
				break;
			}
		}
	}
}

static void firedns_record_remove(fdns_struct *delfdns) {

	fdns_struct *fdns;
	fdns_struct *lastfdns = NULL;

	log_event(4, "DNSBL -> [Socket %d] Removing from fdns list: %s", delfdns->fd, delfdns->ip);

	if (delfdns->fd > 0) {

		close(delfdns->fd);

		/* 1 file descriptor freed up for use. */
		--FD_USE;
	}

	for (fdns = CONNECTIONS; fdns; fdns = fdns->next) {

		if (fdns == delfdns) {

			/* Link around deleted node */
			if (lastfdns == NULL)
				CONNECTIONS = fdns->next;
			else
				lastfdns->next = fdns->next;

			free(fdns);
			break;
		}

		lastfdns = fdns;
	}
}

static char *firedns_strerror(int error) {

	switch (error) {

		case FDNS_ERR_NONE:
			return "None";

		case FDNS_ERR_FORMAT:
			return "Format error";

		case FDNS_ERR_SERVFAIL:
			return "Server failure";

		case FDNS_ERR_NXDOMAIN:
			return "Name error";

		case FDNS_ERR_NOIMPT:
			return "Not implemented";

		case FDNS_ERR_REFUSED:
			return "Refused";

		case FDNS_ERR_TIMEOUT:
			return "Timed out";

		case FDNS_ERR_PAYLOAD:
			return "Payload error";

		case FDNS_ERR_QR:
			return "Flag error (QR)";

		case FDNS_ERR_OPCODE:
			return "Flag error (OPCODE)";

		case FDNS_ERR_NOANSWER:
			return "No answer found";

		case FDNS_ERR_QLEN:
			return "Question length error";

		case FDNS_ERR_ALEN:
			return "Answer length error";

		case FDNS_ERR_RRLEN:
			return "RR length error";
	}

	return "Unknown error";
}

void dnsbl_check(const char *ip, const char *nick, const char *username, const char *host, int equals) {

	struct in_addr	addr;
	unsigned char	A, B, C, D;
	char			payload[512];
	int				idx, payloadLen;


	if (!inet_aton(ip, &addr)) {

		log_snoop("DNSBL -> Invalid address '%s', ignoring.", ip);
		return;
	}

	D = (unsigned char) (addr.s_addr >> 24) & 0xFF;
	C = (unsigned char) (addr.s_addr >> 16) & 0xFF;
	B = (unsigned char) (addr.s_addr >>  8) & 0xFF;
	A = (unsigned char) (addr.s_addr      ) & 0xFF;

	for (idx = 0; idx < 3; ++idx) {

		switch (idx) {

			default:
			case 0:
				// D.C.B.A.opm.blitzed.org
				snprintf(payload, sizeof(payload), "%c%d%c%d%c%d%c%d%copm%cblitzed%corg%c%c%c%c%c",
					getlen(D), D, getlen(C), C, getlen(B), B, getlen(A), A, 3, 7, 3, 0, 0, 1, 0, 1);

				payloadLen = (getlen(D) + getlen(C) + getlen(B) + getlen(A) + 25);
				break;

			case 1:
				// D.C.B.A.list.dsbl.org
				snprintf(payload, sizeof(payload), "%c%d%c%d%c%d%c%d%clist%cdsbl%corg%c%c%c%c%c",
					getlen(D), D, getlen(C), C, getlen(B), B, getlen(A), A, 4, 4, 3, 0, 0, 1, 0, 1);

				payloadLen = (getlen(D) + getlen(C) + getlen(B) + getlen(A) + 23);
				break;

			case 2:
				// D.C.B.A.tor.dnsbl.sectoor.de tor.ahbl.org
				snprintf(payload, sizeof(payload), "%c%d%c%d%c%d%c%d%ctor%cahbl%corg%c%c%c%c%c",
					getlen(D), D, getlen(C), C, getlen(B), B, getlen(A), A, 3, 4, 3, 0, 0, 1, 0, 1);

				payloadLen = (getlen(D) + getlen(C) + getlen(B) + getlen(A) + 23);
				break;

			//case 3:
				// D.C.B.A.dnsbl.njabl.org
			//	snprintf(payload, sizeof(payload), "%c%d%c%d%c%d%c%d%cdnsbl%cnjabl%corg%c%c%c%c%c",
			//		getlen(D), D, getlen(C), C, getlen(B), B, getlen(A), A, 5, 5, 3, 0, 0, 1, 0, 1);

			//	payloadLen = (getlen(D) + getlen(C) + getlen(B) + getlen(A) + 25);
			//	break;
		}

		if (firedns_request(ip, nick, username, host, equals, ZoneArray[idx], payload, payloadLen) == -1)
			log_snoop("[%s] Error sending DNS lookup for %s: %s", ZoneArray[idx]->name, ip, strerror(errno));
	}
}

static void dnsbl_result(const fdns_result *res) {

	if (CONF_DEBUG >= 4) {

		int resultIdx, bufIdx = 0;
		char buffer[512];

		memset(buffer, 0, sizeof(buffer));

		for (resultIdx = 0; resultIdx < res->count; ++resultIdx) {

			if (buffer[0] != '\0') {

				buffer[bufIdx++] = ',';
				buffer[bufIdx++] = ' ';
			}

			snprintf(buffer + bufIdx, sizeof(buffer) - bufIdx, "%d.%d.%d.%d", 
				(unsigned char)res->text[resultIdx][0], (unsigned char)res->text[resultIdx][1],
				(unsigned char)res->text[resultIdx][2], (unsigned char)res->text[resultIdx][3]);

			bufIdx += getlen((unsigned char)res->text[resultIdx][0]);
			bufIdx += getlen((unsigned char)res->text[resultIdx][1]);
			bufIdx += getlen((unsigned char)res->text[resultIdx][2]);
			bufIdx += getlen((unsigned char)res->text[resultIdx][3]);
			bufIdx += 3;
		}

		log_event(4, "DNSBL -> [%s] Lookup result for %s: %s (total: %d) (error: %d)",
			res->zone->name, res->ip, buffer, res->count, res->error);
	}

	/* Everything is OK */
	if ((res->error == FDNS_ERR_NXDOMAIN) && (res->count == 0))
		return;

	if (res->error != FDNS_ERR_NONE) {

		log_event(4, "[%s] Lookup error %d on IP %s: %s", res->zone->name, res->error, res->ip, firedns_strerror(res->error));
		return;
	}

	/* Successfully resolved. Make sure the result is valid for us. */

	switch (validate_result(res)) {

		case 0:
			log_event(4, "[%s] skipped IP \2%s\2", res->zone->name, res->ip);
			return;

		case 1:
			if (res->requested) {

				if (res->zone->host)
					log_snoop("[%s] IP \2%s\2 is positive  [Details: http://%s%s%s ] [Requested by %s]", res->zone->name, res->ip, res->zone->host, res->zone->url, res->ip, res->nick);
				else
					log_snoop("[%s] IP \2%s\2 is positive [Requested by %s]", res->zone->name, res->ip, res->nick);
			}
			else {

				if (res->zone->host)
					log_snoop("[%s] IP \2%s\2 used by \2%s\2 (%s@%s) is positive [Details: http://%s%s%s ]", res->zone->name, res->ip, res->nick, res->username, res->equals ? res->ip : res->host, res->zone->host, res->zone->url, res->ip);
				else
					log_snoop("[%s] IP \2%s\2 used by \2%s\2 (%s@%s) is positive", res->zone->name, res->ip, res->nick, res->username, res->equals ? res->ip : res->host);
			}
			return;

		default:
			return;
	}
}

static int validate_result(const fdns_result *res) {

	unsigned long irc_addr;

	switch (res->zone->idx) {

		case 0:		/* OPM */
			//http_send_request(res);
			return 1;

		case 1:		/* DSBL */
			//log_snoop("Requested: \2%s\2", res->requested);
			http_send_request(res);
			return 1;

		case 2:		/* SORBS */
			/*for (idx = 0; idx < res->count; ++idx) {

				if (((unsigned char)res->text[idx][3] >= 2) && ((unsigned char)res->text[idx][3] <= 4)) {

					http_send_request(res);
					return 2;
				}
			}*/
			irc_addr = inet_addr(res->ip);
			if (CONF_TOR)
			{
				
				irc_kline(res->ip, res->ip , 0 , irc_addr , '0' );
				log_snoop("Akill added for IP \2%s\2", res->ip);
			}
			return 1;

		case 3:		/* NJABL */
			/*for (idx = 0; idx < res->count; ++idx) {

				if ((unsigned char)res->text[idx][3] == 9) {

					http_send_request(res);
					return 2;
				}
			} */

			return 1;
	}

	return 0;
}

void do_nslist(char *nick) {

	ns_struct *ns;
	int idx;

	if (!NAMESERVERS)
		log_snoop("Name servers list is empty.");

	for (ns = NAMESERVERS, idx = 0; ns; ns = ns->next)
		log_snoop("%d) %s", ++idx, ns->name);
}
