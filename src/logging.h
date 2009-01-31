/*
 * This is a proof-of-concept driver for Samsung SWC-U200 wimax dongle.
 * Copyright (C) 2008 Alexander Gordeev <lasaine@lvk.cs.msu.su>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef _LOGGING_H
#define _LOGGING_H

/* get printable madwimax version */
const char* get_madwimax_version();

/* set wmlog level to the desired value */
void set_wmlog_level(int level);

/* increase wmlog level by 1 */
void inc_wmlog_level();

/* print wmlog message. */
void wmlog_msg(int level, const char *fmt, ...);

/* dump message msg and len bytes from buf in hexadecimal and ASCII. */
void wmlog_dumphexasc(int level, const char *msg, const void *buf, int len);

/* print usage information */
void usage(const char *prog);

/* print version */
void version();

#endif /* _LOGGING_H */

