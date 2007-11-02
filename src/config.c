/*
 * Azzurra Proxy Monitor - config.c
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
#include "../inc/misc.h"

static void config_checkreq(void);
static void add_to_config(const char *key, const char *val);

/* Global Configuration Variables */

char *CONF_PASSWORD;
char *CONF_NICK;
char *CONF_SERVER;
char *CONF_OPER;
char *CONF_BINDSCAN;
char *CONF_NICKSERV_PASS;
string_list *CONF_EXCLUDE;
string_list *CONF_SCANCHECK;
string_list *CONF_PROTOCOLS;

unsigned int CONF_PORT;
unsigned int CONF_FDLIMIT;
unsigned int CONF_TIMEOUT;
unsigned int CONF_DEBUG;
unsigned int CONF_DNSBL;
unsigned int CONF_GDPCHAT;
unsigned int CONF_TOR ;

/* Configuration Hash , Hashes Config Params to their Function Handlers*/
/*      NAME,                  TYPE,	REQ,REQMET, PTR TO VAR        */
config_hash hash[] = {
       {"PORT",                TYPE_INT   , 1,0,    &CONF_PORT               },
       {"PASSWORD",            TYPE_STRING, 0,0,    &CONF_PASSWORD           },
       {"NICK",                TYPE_STRING, 1,0,    &CONF_NICK               },
       {"SERVER",              TYPE_STRING, 0,0,    &CONF_SERVER             },
       {"OPER",                TYPE_STRING, 1,0,    &CONF_OPER               },
       {"BINDSCAN",            TYPE_STRING, 0,0,    &CONF_BINDSCAN           },
       {"FDLIMIT",             TYPE_INT   , 0,0,    &CONF_FDLIMIT            },
       {"NICKSERV_PASS",       TYPE_STRING, 0,0,    &CONF_NICKSERV_PASS      },
       {"TIMEOUT",             TYPE_INT   , 1,0,    &CONF_TIMEOUT            },
       {"DEBUG",               TYPE_INT   , 0,0,    &CONF_DEBUG              },
       {"DNSBL",               TYPE_INT   , 0,0,    &CONF_DNSBL              },
       {"GDPCHAT",             TYPE_INT   , 0,0,    &CONF_GDPCHAT            },
       {"TOR",		       TYPE_INT   , 0,0,    &CONF_TOR            },
       {0,                     0,           0,0,    0                        }
};

/* Parse File */
void config_load(char *filename) {

	/* 1k buffer for reading the file. */
	char line[1024];
	size_t i;
	char *key, *args;
	FILE *in;

	log_event(0, "CONFIG -> Reading configuration file...");

	if (!(in = fopen(filename, "r"))) {

		log_event(0, "CONFIG -> No config file found, aborting.");
		fprintf(stderr, "\nNo config file found, aborting.\n");
		exit(EXIT_FAILURE);
	}

	/* Clear anything we have already. */
	for (i = 0; i < (sizeof(hash) / sizeof(config_hash) - 1); i++) {

		switch (hash[i].type) { 

			case TYPE_STRING:
				if (( *(char**) hash[i].var))
					free(*(char**)hash[i].var);

				*(char**)hash[i].var = 0;
				break;

			case TYPE_INT:
				*(int *) hash[i].var = 0;
				break;
		}

		hash[i].reqmet = 0;
	}
	CONF_TOR = 1;
	while (fgets(line, sizeof(line), in)) {

		if (line[0] == '#')
			continue;

		key = strtok(line, " ");
		args = strtok(NULL, "\n");

		if (!args)
			continue;

		/* Strip leading and trailing spaces. */
		args = clean(args);
		add_to_config(key, args);
	}

	fclose(in);

	/* Check required parameters. */
	config_checkreq();
}

static void config_checkreq() {

	size_t i;
	int errfnd = 0;

	for (i = 0; i < (sizeof(hash) / sizeof(config_hash) - 1); i++) {

		if (hash[i].req && !hash[i].reqmet) {

			log_event(0, "CONFIG -> Parameter [%s] required but not defined in config.", hash[i].key);
			errfnd++;
		}
		else if (hash[i].reqmet) {

			switch (hash[i].type) {

			case TYPE_STRING:
				log_event(0, "CONFIG -> Set [%s]: %s", hash[i].key, *(char**) hash[i].var);
				break;

			case TYPE_INT:
				log_event(0, "CONFIG -> Set [%s]: %d", hash[i].key, *(int *) hash[i].var);
				break;
			}
		}
	}

	if (errfnd) {

		log_event(0, "CONFIG -> %d parameters missing from config file, aborting.", errfnd);
		fprintf(stderr, "\n%d parameters missing from config file, aborting.\n", errfnd);
		exit(EXIT_FAILURE);
	}
}

static void add_to_config(const char *key, const char *val) {

	size_t i;

	for (i = 0; i < (sizeof(hash) / sizeof(config_hash)) - 1; i++) {

		if (!strcasecmp(key, hash[i].key)) {

			switch (hash[i].type) {

				case TYPE_STRING: 
					*(char**) hash[i].var = strdup(val);
					break;

				case TYPE_INT:
					*(int *) hash[i].var = atoi(val);
					break;
			}

			hash[i].reqmet = 1;
		}
	}
}

void exception_load(char *filename) {

	/* 1k buffer for reading the file. */
	char line[1024];
	char *host;
	FILE *in;

	log_event(0, "CONFIG -> Reading exceptions file...");

	if (!(in = fopen(filename, "r"))) {

		log_event(0, "CONFIG -> No exceptions file found.");
		return;
	}

	/* Initialize the list. */
	free_list(CONF_EXCLUDE);
	CONF_EXCLUDE = NULL;

	while (fgets(line, sizeof(line), in)) {

		host = strtok(line, " \r\n");

		/* Strip leading and trailing spaces. */
		host = clean(host);

		if (add_to_list(&CONF_EXCLUDE, host))
			log_event(0, "CONFIG -> Added exception for: %s", host);
	}

	fclose(in);
}

void scancheck_load(char *filename) {

	/* 1k buffer for reading the file. */
	char line[1024];
	char *string;
	FILE *in;

	log_event(0, "CONFIG -> Reading scancheck file...");

	if (!(in = fopen(filename, "r"))) {

		log_event(0, "CONFIG -> No http scan checks file found.");
		return;
	}

	/* Initialize the list. */
	free_list(CONF_SCANCHECK);
	CONF_SCANCHECK = NULL;

	while (fgets(line, sizeof(line), in)) {

		string = strtok(line, " \r\n");

		/* Strip leading and trailing spaces. */
		string = clean(string);

		if (add_to_list(&CONF_SCANCHECK, string))
			log_event(0, "CONFIG -> Added scan check for: %s", string);
	}

	fclose(in);
}

int add_to_list(string_list **list, const char *item) {

	string_list *entry = *list;

	while (entry != NULL) {

		if (!strcasecmp(entry->text, item))
			return 0;

		entry = entry->next;
	}

	log_event(5, "Adding '%s' to string_list", item);

	entry = (string_list *) malloc(sizeof(*list));

	entry->text = strdup(item);

	entry->next = *list;
	*list = entry;
	return 1;
}

int remove_from_list(string_list **list, const char *item) {

	string_list *p, *prev = NULL;

	p = *list;

	log_event(5, "Removing '%s' from string_list", item);

	while (p != NULL) {

		if (!strcasecmp(p->text, item)) {

			if (prev != NULL)
				prev->next = p->next;
			else
				*list = p->next;

			free(p->text);
			free(p);
			return 1;
		}

		prev = p;
		p = p->next;
	}

	return 0;
}


void show_list(string_list *list) {

	string_list *p = list;
	int idx = 0;

	while (p != NULL) {

		irc_send("PRIVMSG #apm :%d) %s", ++idx, p->text);
		p = p->next;
	}

	if (idx == 0)
		irc_send("PRIVMSG #apm :The list is empty.");
}


void free_list(string_list *list) {

	string_list *t, *nextlist;

	if (!list)
		return;

	for (t = list->next; t; ) {

		nextlist = t->next;
		free(t->text);
		free(t);
		t = nextlist;
	}
} 

void save_list(string_list **list, char *filename) {

	FILE *file;
	string_list *p;

	log_event(5, "CONFIG -> Saving exception list...");

	if (*list == NULL) {

		char buf[256];

		log_event(5, "CONFIG -> No exceptions, removing %s", filename);

		snprintf(buf, sizeof(buf), "rm -rf %s", filename);

		system(buf);
		return;
	}

	if (!(file = fopen(filename, "w"))) {

		log_event(5, "CONFIG -> Error opening file: %s", filename);
		fprintf(stderr, "\nError opening file: %s\n", filename);
		exit(EXIT_FAILURE);
	}

	p = *list;

	while (p != NULL) {

		fputs(p->text, file);
		fputc('\n', file);

		p = p->next;
	}

	fclose(file);

	log_event(5, "CONFIG -> Exception list saved...");
}
