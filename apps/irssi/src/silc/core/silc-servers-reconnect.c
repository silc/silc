/*
 silc-servers-reconnect.c : irssi

    Copyright (C) 2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"

#include "silc-servers.h"

static void sig_server_reconnect_save_status(SILC_SERVER_CONNECT_REC *conn,
					     SILC_SERVER_REC *server)
{
	if (!IS_SILC_SERVER_CONNECT(conn) || !IS_SILC_SERVER(server))
		return;

	g_free_not_null(conn->channels);
	conn->channels = silc_server_get_channels(server);
}

static void sig_server_connect_copy(SERVER_CONNECT_REC **dest,
				    SILC_SERVER_CONNECT_REC *src)
{
	SILC_SERVER_CONNECT_REC *rec;

	g_return_if_fail(dest != NULL);
	if (!IS_SILC_SERVER_CONNECT(src))
		return;

	rec = g_new0(SILC_SERVER_CONNECT_REC, 1);
	rec->chat_type = SILC_PROTOCOL;
	*dest = (SERVER_CONNECT_REC *) rec;
}

void silc_servers_reconnect_init(void)
{
	signal_add("server reconnect save status", (SIGNAL_FUNC) sig_server_reconnect_save_status);
	signal_add("server connect copy", (SIGNAL_FUNC) sig_server_connect_copy);
}

void silc_servers_reconnect_deinit(void)
{
	signal_remove("server reconnect save status", (SIGNAL_FUNC) sig_server_reconnect_save_status);
	signal_remove("server connect copy", (SIGNAL_FUNC) sig_server_connect_copy);
}
