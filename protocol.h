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

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include "wimax.h"

int process_response(struct wimax_dev_status *dev, const unsigned char *buf, int len);

int fill_string_info_req(unsigned char *buf, int len);

int fill_init1_req(unsigned char *buf, int len);

int fill_mac_req(unsigned char *buf, int len);

int fill_init2_req(unsigned char *buf, int len);

int fill_init3_req(unsigned char *buf, int len);

int fill_authorization_data_req(unsigned char *buf, int len);

int fill_find_network_req(unsigned char *buf, int len, unsigned short level);

int fill_connection_params1_req(unsigned char *buf, int len);

int fill_connection_params2_req(unsigned char *buf, int len);

int fill_state_req(unsigned char *buf, int len);

#endif // _PROTOCOL_H

