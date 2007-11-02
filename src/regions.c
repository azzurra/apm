/*
 * Azzurra Proxy Monitor - regions.c
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../inc/cidr.h"
#include "../inc/main.h"
#include "../inc/log.h"
#include "../inc/misc.h"
#include "../inc/match.h"
#include "../inc/regions.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef	struct _Region	Region;
struct _Region {

	Region			*next;

	unsigned int	type;

	CIDR_IP			cidr;
	char			*hostmask;
};


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	REGION_TYPE_UNKNOWN		0
#define	REGION_TYPE_CIDR		1
#define	REGION_TYPE_HOST		2
#define	REGION_TYPE_WILD		3


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static void regions_clear(void);


/*********************************************************
 * Local data                                            *
 *********************************************************/

static Region *RegionList = NULL;


/*********************************************************
 * Public code                                           *
 *********************************************************/

void regions_load(const char *filename) {

	char line[1024];
	size_t len;
	FILE *in;

	if (!(in = fopen(filename, "r")))
		return;

	/* Initialize the list. */
	regions_clear();

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
		if (!regions_add(line, 0))
			log_event(0, "WARNING: Duplicate region found: %s", line);
	}

	fclose(in);
}

void regions_save(void) {

	FILE	*file;
	Region	*region;

	if (!(file = fopen(REGIONSFILE, "w"))) {

		log_event(0, "CONFIG -> Error opening file: %s", REGIONSFILE);
		fprintf(stderr, "\nError opening file: %s\n", REGIONSFILE);
		exit(EXIT_FAILURE);
	}

	region = RegionList;

	while (region) {

		fputs(region->hostmask, file);
		fputc('\n', file);

		region = region->next;
	}

	fclose(file);
}


int regions_add(const char *line, int save) {

	CIDR_IP cidr;
	int type = REGION_TYPE_UNKNOWN;
	Region *region;


	log_event(0, "CONFIG -> Adding region: %s", line);

	region = RegionList;

	if (cidr_ip_fill(line, &cidr)) {

		while (region) {

			if ((region->type == REGION_TYPE_CIDR) && (region->cidr.ip == cidr.ip) && (region->cidr.mask == cidr.mask))
				return 0;

			region = region->next;
		}

		type = REGION_TYPE_CIDR;
	}
	else {

		while (region) {

			if (((region->type == REGION_TYPE_HOST) || (region->type == REGION_TYPE_WILD)) && !strcmp(region->hostmask, line))
				return 0;

			region = region->next;
		}

		type = (strchr(line, '*') || strchr(line, '?')) ? REGION_TYPE_WILD : REGION_TYPE_HOST;
	}

	region = calloc(1, sizeof(Region));

	region->type = type;
	region->hostmask = strdup(line);

	if (type == REGION_TYPE_CIDR)
		region->cidr = cidr;

	region->next = RegionList;
	RegionList = region;

	if (save)
		regions_save();

	return 1;
}

int regions_delete(const char *line) {

	Region *region, *prev = NULL;


	region = RegionList;

	while (region) {

		if (!strcmp(region->hostmask, line)) {

			if (prev)
				prev->next = region->next;
			else
				RegionList = region->next;

			free(region->hostmask);
			free(region);

			regions_save();
			return 1;
		}

		prev = region;
		region = region->next;
	}

	return 0;
}

int regions_match(const char *addr, const char *host, const unsigned long int sourceIP) {

	Region				*region;
	unsigned long int	ip;


	if (sourceIP != 0)
		ip = sourceIP;
	else
		ip = aton(addr);

	region = RegionList;

	while (region) {

		if ((region->type == REGION_TYPE_CIDR) && cidr_match(&(region->cidr), ip))
			return 1;

		if (host && (region->type == REGION_TYPE_HOST) && !strcasecmp(region->hostmask, host))
			return 1;

		if (host && (region->type == REGION_TYPE_WILD) && match(region->hostmask, host))
			return 1;

		region = region->next;
	}

	return 0;
}

static void regions_clear(void) {

	Region *region, *next;

	region = RegionList;

	while (region) {

		next = region->next;

		free(region->hostmask);
		free(region);

		region = next;
	}

	RegionList = NULL;
}

void regions_dump(void) {

	Region *region = RegionList;
	int count = 0;

	while (region) {

		log_snoop("Entry %d: %s [%s]", ++count, region->hostmask, ((region->type == REGION_TYPE_CIDR) ? "CIDR" : ((region->type == REGION_TYPE_HOST) ? "HOST" : "WILD")));

		region = region->next;
	}
}
