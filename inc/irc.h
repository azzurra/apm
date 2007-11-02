/*
 * Azzurra Proxy Monitor - irc.h
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

#ifndef APM_IRC_H
#define APM_IRC_H

extern void parse_init(void);
extern void parse_terminate(void);
extern void irc_send(char *data, ...);
extern void irc_kline(const char *addr, const char *host, const unsigned int port, const unsigned long ip, const char type);
extern void irc_cycle(void);
extern void irc_timer(void);

extern time_t IRC_TS;
extern int BLOCK_SPEEDTOUCH;
extern int SYNCHED;
extern unsigned int FD_USE;

#endif
