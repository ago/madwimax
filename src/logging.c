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
#include <syslog.h>

#include "config.h"
#include "logging.h"

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

static int wimax_log_level = 0;

/* set wmlog level to the desired value */
void set_wmlog_level(int level)
{
	wimax_log_level = level;
}

/* increase wmlog level by 1 */
void inc_wmlog_level()
{
	wimax_log_level++;
}

/* log to stderr */
static void wmlog_stderr(const char *fmt, va_list va)
{
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
}

/* log to syslog */
static void wmlog_syslog(const char *fmt, va_list va)
{
	vsyslog(LOG_INFO, fmt, va);
}

typedef void (*wmlogger_func)(const char *fmt, va_list va);

static wmlogger_func loggers[2] = {[WMLOGGER_STDERR] = wmlog_stderr, [WMLOGGER_SYSLOG] = wmlog_syslog};
static wmlogger_func selected_logger = wmlog_stderr;

/* set logger to stderr or syslog */
void set_wmlogger(const char *progname, int logger)
{
	selected_logger = loggers[logger];
	if (logger == WMLOGGER_SYSLOG) {
		openlog(progname, LOG_PID, LOG_DAEMON);
	} else {
		closelog();
	}
}

/* print wmlog message. */
void wmlog_msg(int level, const char *fmt, ...)
{
	va_list va;

	if (level > wimax_log_level) return;

	va_start(va, fmt);
	selected_logger(fmt, va);
	va_end(va);
}

/* print wmlog message. */
static inline void wmlog_msg_priv(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	selected_logger(fmt, va);
	va_end(va);
}

/* If a character is not printable, return a dot. */
#define toprint(x) (isprint((unsigned int)x) ? (x) : '.')

/* dump message and len bytes from buf in hexadecimal and ASCII. */
void wmlog_dumphexasc(int level, const void *buf, int len, const char *fmt, ...)
{
	int i;
	va_list va;

	if (level > wimax_log_level) return;

	va_start(va, fmt);
	selected_logger(fmt, va);
	va_end(va);

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
		wmlog_msg_priv("  %08x:%s    %s", i, hex, ascii);
	}
}

void usage(const char *progname)
{
	printf("Usage: %s [options]\n", progname);
	printf("Options:\n");
	printf("  -v, --verbose               increase the log level\n");
	printf("  -q, --quiet                 switch off logging\n");
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

