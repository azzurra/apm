/*
 * Azzurra Proxy Monitor - regions.h
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

#ifndef SRV_REGIONS_H
#define SRV_REGIONS_H


extern int regions_match(const char *addr, const char *host, const unsigned long int sourceIP);
extern int regions_add(const char *line, int save);
extern int regions_delete(const char *line);
extern void regions_save(void);
extern void regions_load(const char *filename);
extern void regions_dump(void);

#endif /* SRV_REGIONS_H */
