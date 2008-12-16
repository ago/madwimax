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

#ifndef _WIMAX_H
#define _WIMAX_H

struct wimax_dev_status {
	int info_updated;
	char chip_info[0x40];
	char firmware_info[0x40];
	unsigned char mac[6];
	int network_found;
	short rssi;
	float cinr;
	unsigned char bsid[6];
	unsigned short txpwr;
	unsigned int freq;
	int state;
};

/* print debug message. */
void debug_msg(int level, const char *fmt, ...);

/* dump message msg and len bytes from buf in hexadecimal and ASCII. */
void debug_dumphexasc(int level, const char *msg, const void *buf, int len);

#endif // _WIMAX_H

