/*
 * This is a reverse-engineered driver for mobile WiMAX (802.16e) devices
 * based on Samsung CMC-730 chip.
 * Copyright (C) 2008-2009 Alexander Gordeev <lasaine@lvk.cs.msu.su>
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
 */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "devconfig.h"
#include "logging.h"

int load_config(unsigned char *mac, char *ifname, struct device_config *cfg)
{
	char macbuf[18];
	lua_State *L = lua_open();	/* open Lua */
	luaL_openlibs(L);		/* open libs */

	wmlog_msg(1, "Loading config...");

	snprintf(macbuf, sizeof(macbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	lua_pushstring(L, macbuf);
	lua_setglobal(L, "mac");

	lua_pushstring(L, ifname);
	lua_setglobal(L, "ifname");

	if (luaL_loadfile(L, SYSCONFDIR "/config.lua") || lua_pcall(L, 0, 0, 0)) {
		wmlog_msg(0, "cannot run configuration file: %s", lua_tostring(L, -1));
		return 1;
	}

	lua_getglobal(L, "diode_on");
	lua_getglobal(L, "realm");

	if (lua_isnumber(L, -2)) {
		cfg->diode_on = (int) lua_tonumber(L, -2);
		wmlog_msg(2, "cfg->diode_on = %d", cfg->diode_on);
	} else
		wmlog_msg(2, "cfg->diode_on = nil");

	if (lua_isstring(L, -1)) {
		cfg->realm = strdup(lua_tostring(L, -1));
		wmlog_msg(2, "cfg->realm = %s", cfg->realm);
	} else
		wmlog_msg(2, "cfg->realm = nil");

	lua_close(L);
	return 0;
}

