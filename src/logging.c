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

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

/* the reason we define MADWIMAX_VERSION as a static string, rather than a
	macro, is to make dependency tracking easier (only logging.o depends
	on madwimax_version.h), and also to prevent all sources from
	having to be recompiled each time the version changes (they only
	need to be re-linked). */
#include "madwimax_version.h"

const char* get_madwimax_version()
{
	return MADWIMAX_VERSION_MACRO;
}

static int wimax_debug_level = 0;

/* set debug level to the desired value */
void set_debug_level(int level)
{
	wimax_debug_level = level;
}

/* increase debug level by 1 */
void inc_debug_level()
{
	wimax_debug_level++;
}

/* print debug message. */
void debug_msg(int level, const char *fmt, ...)
{
	va_list va;

	if (level > wimax_debug_level) return;

	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}

/* If a character is not printable, return a dot. */
#define toprint(x) (isprint((unsigned int)x) ? (x) : '.')

/* dump message msg and len bytes from buf in hexadecimal and ASCII. */
void debug_dumphexasc(int level, const char *msg, const void *buf, int len)
{
	int i;

	if (level > wimax_debug_level) return;

	printf("%s\n", msg);
	for (i = 0; i < len; i+=16) {
		int j;
		char hex[49];
		char ascii[17];
		memset(hex, ' ', 48);
		for(j = i; j < i + 16 && j < len; j++) {
			sprintf(hex + ((j - i) * 3), " %02x", ((unsigned char*)buf)[j]);
			ascii[j - i] = toprint(((unsigned char*)buf)[j]);
		}
		hex[(j - i) * 3] = ' ';
		hex[48] = 0;
		ascii[j - i] = 0;
		printf("  %08x:%s    %s\n", i, hex, ascii);
	}
}

void usage(char *progname)
{
	printf("Usage: %s [options]\n", progname);
	printf("Options:\n");
	printf("  -v, --verbose               increase the debugging level\n");
	printf("  -q, --quiet                 don't print on the console\n");
	printf("  -d, --daemonize             daemonize after startup\n");
	printf("  -o, --diode-off             turn off the diode (diode is on by default)\n");
	printf("  -f, --detach-dvd            detach pseudo-DVD kernel driver on startup\n");
	printf("      --device vid:pid        specify the USB device by VID:PID\n");
	printf("      --exact-device bus/dev  specify the exact USB bus/device (use with care!)\n");
	printf("  -V, --version               print the version number\n");
	printf("  -h, --help                  display this help\n");
}

void version()
{
	printf("%s %s\n", PACKAGE_NAME, MADWIMAX_VERSION_MACRO);
}

