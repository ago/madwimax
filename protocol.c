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

#include <string.h>

#include "protocol.h"

static int process_normal_C_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	short type_a = (buf[0x14] << 8) + buf[0x15];
	short type_b = (buf[0x16] << 8) + buf[0x17];
	short param_len = (buf[0x18] << 8) + buf[0x19];

	if (type_a == 0x8 && type_b == 0x2) {
		if (param_len != 0x80) {
			debug_msg(0, "bad param_len\n");
			return -1;
		}
		memcpy(dev->chip, buf + 0x1a, 0x40);
		memcpy(dev->firmware, buf + 0x5a, 0x40);
		dev->info_updated |= WDS_CHIP | WDS_FIRMWARE;
		return 0;
	}
	if (type_a == 0x3 && type_b == 0x2) {
		if (param_len != 0x6) {
			debug_msg(0, "bad param_len\n");
			return -1;
		}
		memcpy(dev->mac, buf + 0x1a, 0x6);
		dev->info_updated |= WDS_MAC;
		return 0;
	}
	if (type_a == 0x1 && type_b == 0x2) {
		if (param_len != 0x2) {
			debug_msg(0, "bad param_len\n");
			return -1;
		}
		dev->net_found = (buf[0x1a] << 8) + buf[0x1b];
		dev->info_updated |= WDS_NET_FOUND;
		return 0;
	}
	if (type_a == 0x1 && type_b == 0x3) {
		if (param_len != 0x4) {
			debug_msg(0, "bad param_len\n");
			return -1;
		}
		dev->net_found = 0;
		dev->info_updated |= WDS_NET_FOUND;
		return 0;
	}
	if (type_a == 0x1 && type_b == 0xa) {
		if (param_len != 0x16) {
			debug_msg(0, "bad param_len\n");
			return -1;
		}
		dev->rssi = (buf[0x1a] << 8) + buf[0x1b];
		dev->cinr = (float)((short)((buf[0x1c] << 8) + buf[0x1d])) / 8;
		memcpy(dev->bsid, buf + 0x1e, 0x6);
		dev->txpwr = (buf[0x26] << 8) + buf[0x27];
		dev->freq = (buf[0x28] << 24) + (buf[0x29] << 16) + (buf[0x2a] << 8) + buf[0x2b];
		dev->info_updated |= WDS_RSSI | WDS_CINR | WDS_BSID | WDS_TXPWR | WDS_FREQ;
		return 0;
	}
	if (type_a == 0x1 && type_b == 0xc) {
		if (param_len != 0x2) {
			debug_msg(0, "bad param_len\n");
			return -1;
		}
		dev->state = (buf[0x1a] << 8) + buf[0x1b];
		dev->info_updated |= WDS_STATE;
		return 0;
	}

	dev->info_updated |= WDS_OTHER;

	return 0;
}

static int process_debug_C_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	return 0;
}

static int process_C_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	if (buf[0x12] != 0x15) {
		debug_msg(0, "bad format\n");
		return -1;
	}

	switch (buf[0x13]) {
		case 0x00:
			return process_normal_C_response(dev, buf, len);
		case 0x02:
			return process_debug_C_response(dev, buf, len);
		case 0x04:
			break;
		default:
			debug_msg(0, "bad format\n");
			return -1;
	}

	return 0;
}

static int process_D_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	write_netif(buf + 0x06, len - 0x06);
	return 0;
}

static int process_E_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	return 0;
}

static int process_P_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	return 0;
}

int process_response(struct wimax_dev_status *dev, const unsigned char *buf, int len)
{
	int check_len;

	if(len < 4) {
		debug_msg(0, "short read\n");
		return -1;
	}

	if(buf[0] != 0x57) {
		debug_msg(0, "bad header\n");
		return -1;
	}

	check_len = 4 + buf[2] + (buf[3] << 8);
	if(buf[1] == 0x43 || buf[1] == 0x44) {
		check_len += 2;
	}

	if(check_len != len) {
		debug_msg(0, "bad length: %02x instead of %02x\n", check_len, len);
		return -1;
	}

	switch (buf[1]) {
		case 0x43:
			return process_C_response(dev, buf, len);
		case 0x44:
			return process_D_response(dev, buf, len);
		case 0x45:
			return process_E_response(dev, buf, len);
		case 0x50:
			return process_P_response(dev, buf, len);
		default:
			debug_msg(0, "bad response type: %02x\n", buf[1]);
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

static int fill_normal_C_req(unsigned char *buf, unsigned short type_a, unsigned short type_b, unsigned short param_len, unsigned char *param)
{
	int len = 0x1a + param_len;
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
	return len;
}

int fill_string_info_req(unsigned char *buf, int len)
{
	return fill_normal_C_req(buf, 0x8, 0x1, 0x0, NULL);
}

int fill_diode_control_cmd(unsigned char *buf, int len, int turn_on)
{
	unsigned char param[0x2] = {0x0, turn_on ? 0x1 : 0x0};
	return fill_normal_C_req(buf, 0x30, 0x1, sizeof(param), param);
}

int fill_mac_req(unsigned char *buf, int len)
{
	return fill_normal_C_req(buf, 0x3, 0x1, 0x0, NULL);
}

int fill_auth_policy_req(unsigned char *buf, int len)
{
	return fill_normal_C_req(buf, 0x20, 0x8, 0x0, NULL);
}

int fill_auth_method_req(unsigned char *buf, int len)
{
	return fill_normal_C_req(buf, 0x20, 0xc, 0x0, NULL);
}

int fill_auth_set_cmd(unsigned char *buf, int len)
{
	unsigned char param[0xd] = {0x00, 0x10, 0x00, 0x09, 0x40, 0x79, 0x6f, 0x74, 0x61, 0x2e, 0x72, 0x75, 0x00};
	return fill_normal_C_req(buf, 0x20, 0x20, sizeof(param), param);
}

int fill_find_network_req(unsigned char *buf, int len, unsigned short level)
{
	unsigned char param[0x2] = {level >> 8, level & 0xff};
	return fill_normal_C_req(buf, 0x1, 0x1, sizeof(param), param);
}

int fill_connection_params1_req(unsigned char *buf, int len)
{
	unsigned char param[0x2] = {0xff, 0xff};
	return fill_normal_C_req(buf, 0x1, 0x9, sizeof(param), param);
}

int fill_connection_params2_req(unsigned char *buf, int len)
{
	unsigned char param[0x2] = {0x00, 0x00};
	return fill_normal_C_req(buf, 0x1, 0x9, sizeof(param), param);
}

int fill_state_req(unsigned char *buf, int len)
{
	return fill_normal_C_req(buf, 0x1, 0xb, 0x0, NULL);
}

int fill_network_list_req(unsigned char *buf, int len)
{
	unsigned char param[0x2] = {0x00, 0x00};
	return fill_normal_C_req(buf, 0x24, 0x1, sizeof(param), param);
}


int get_D_header_len()
{
	return 6;
}

int fill_outgoing_packet_header(unsigned char *buf, int len, int body_len)
{
	buf[0x00] = 0x57;
	buf[0x01] = 0x44;
	buf[0x02] = body_len & 0xff;
	buf[0x03] = (body_len >> 8) & 0xff;
	return body_len + 6;
}

