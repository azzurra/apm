/*
 * Azzurra Proxy Monitor - config.h
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

/* $Id */

#ifndef APM_CONFIG_H
#define APM_CONFIG_H

typedef struct config_hash config_hash;

#define TYPE_STRING		1
#define TYPE_INT		2
#define TYPE_LIST		3

struct config_hash {

	char *key;
	int type;
	int req;		/* Item is required */
	int reqmet;		/* Req met */
	void *var;
};

typedef struct string_list string_list;

struct string_list {

	string_list *next;
	char *text;
};

extern char *CONF_PASSWORD;
extern char *CONF_NICK;
extern char *CONF_SERVER;
extern char *CONF_OPER;
extern char *CONF_BINDSCAN;
extern char *CONF_NICKSERV_PASS;
extern string_list *CONF_EXCLUDE;
extern string_list *CONF_SCANCHECK;
extern string_list *CONF_PROTOCOLS;

extern unsigned int CONF_PORT;
extern unsigned int CONF_FDLIMIT;
extern unsigned int CONF_TIMEOUT;
extern unsigned int CONF_DEBUG;
extern unsigned int CONF_DNSBL;
extern unsigned int CONF_GDPCHAT;
extern unsigned int CONF_TOR ;

extern void config_load(char *filename);
extern void exception_load(char *filename);
extern void scancheck_load(char *filename);

extern int add_to_list(string_list **list, const char *item);
extern int remove_from_list(string_list **list, const char *item);
extern void show_list(string_list *list);
extern void free_list(string_list *list);
extern void save_list(string_list **list, char *filename);

#endif
