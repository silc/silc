/*

  server_util.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVER_UTIL_H
#define SERVER_UTIL_H

/* This function is used to remove all client entries by the server `entry'.
   This is called when the connection is lost to the server. In this case
   we must invalidate all the client entries owned by the server `entry'. 
   If the `server_signoff' is TRUE then the SERVER_SIGNOFF notify is
   distributed to our local clients. */
bool silc_server_remove_clients_by_server(SilcServer server, 
					  SilcServerEntry entry,
					  bool server_signoff);

/* Updates the clients that are originated from the `from' to be originated
   from the `to'. If the `resolve_real_server' is TRUE then this will
   attempt to figure out which clients really are originated from the
   `from' and which are originated from a server that we have connection
   to, when we've acting as backup router. If it is FALSE the `to' will
   be the new source. This function also removes the clients that are
   *really* originated from `from' if `remove_from' is TRUE. These are
   clients that the `from' owns, and not just clients that are behind
   the `from'. */
void silc_server_update_clients_by_server(SilcServer server, 
					  SilcServerEntry from,
					  SilcServerEntry to,
					  bool resolve_real_server,
					  bool remove_from);

/* Updates servers that are from `from' to be originated from `to'.  This
   will also update the server's connection to `to's connection. */
void silc_server_update_servers_by_server(SilcServer server, 
					  SilcServerEntry from,
					  SilcServerEntry to);

/* Removes channels that are from `from. */
void silc_server_remove_channels_by_server(SilcServer server, 
					   SilcServerEntry from);

/* Updates channels that are from `from' to be originated from `to'.  */
void silc_server_update_channels_by_server(SilcServer server, 
					   SilcServerEntry from,
					   SilcServerEntry to);

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */
bool silc_server_channel_has_global(SilcChannelEntry channel);

/* Checks whether given channel has locally connected users.  If it does this
   returns TRUE and FALSE if there is not one locally connected client. */
bool silc_server_channel_has_local(SilcChannelEntry channel);

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */
bool silc_server_client_on_channel(SilcClientEntry client,
				   SilcChannelEntry channel);

/* Checks string for bad characters and returns TRUE if they are found. */
bool silc_server_name_bad_chars(const char *name, uint32 name_len);

/* Modifies the `nick' if it includes bad characters and returns new
   allocated nickname that does not include bad characters. */
char *silc_server_name_modify_bad(const char *name, uint32 name_len);

#endif /* SERVER_UTIL_H */
