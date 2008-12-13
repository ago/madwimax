/*
 * Proof-of-concept driver for Samsung SWC-U200 wimax dongle.
 * This file contains binary protocol realization.
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

#include <stdio.h>
#include <string.h>

#include "protocol.h"

static int process_C_response(const unsigned char *buf, int len)
{
}

static int process_D_response(const unsigned char *buf, int len)
{
}

static int process_E_response(const unsigned char *buf, int len)
{
}

static int process_P_response(const unsigned char *buf, int len)
{
}

int process_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	int check_len;

	if(len < 4) {
		printf("short read\n");
		return -1;
	}

	if(buf[0] != 0x57) {
		printf("bad header\n");
		return -1;
	}

	check_len = 4 + buf[2] + (buf[3] << 8);
	if(buf[1] == 0x43 || buf[1] == 0x44) {
		check_len += 2;
	}

	if(check_len != len) {
		printf("bad length: %02x instead of %02x\n", check_len, len);
		return -1;
	}

	switch (buf[1]) {
		case 0x43:
			process_C_response(buf, len);
			break;
		case 0x44:
			process_D_response(buf, len);
			break;
		case 0x45:
			process_E_response(buf, len);
			break;
		case 0x50:
			process_P_response(buf, len);
			break;
		default:
			printf("bad response type: %02x\n", buf[1]);
			return -1;
	}
}

static void fill_C_req(unsigned char *buf, int len)
{
	len -= 6;
	buf[0x00] = 0x57;
	buf[0x01] = 0x43;
	buf[0x02] = len & 0xff;
	buf[0x03] = (len >> 8) & 0xff;
	memset(buf + 6, 0, 12);
}

static void fill_normal_C_req(unsigned char *buf, int len, unsigned short type_a, unsigned short type_b, unsigned short param_len, unsigned char *param)
{
	fill_C_req(buf, len);
	buf[0x04] = 0x15;
	buf[0x05] = 0x00;
	buf[0x12] = 0x15;
	buf[0x13] = 0x00;
	buf[0x14] = type_a >> 8;
	buf[0x15] = type_a & 0xff;
	buf[0x16] = type_b >> 8;
	buf[0x17] = type_b & 0xff;
	buf[0x18] = param_len >> 8;
	buf[0x19] = param_len & 0xff;
	memcpy(buf + 0x1a, param, param_len);
}

int fill_string_info_req(unsigned char *buf, int len)
{
	fill_normal_C_req(buf, 0x1a, 8, 1, 0, NULL);
	return 0x1a;
}

