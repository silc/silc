/*

  server_util.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

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
   the `from'. If `from' is NULL then all non-local clients are switched
   to `to'. */
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

/* Toggles the enabled/disabled status of local server connections.  Packets
   can be sent to the servers when `toggle_enabled' is TRUE and will be
   dropped if `toggle_enabled' is FALSE, after this function is called. */
void silc_server_local_servers_toggle_enabled(SilcServer server,
					      bool toggle_enabled);

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

/* This function removes the channel and all users on the channel, unless
   the channel is permanent.  In this case the channel is disabled but all
   users are removed from the channel.  Returns TRUE if the channel is
   destroyed totally, and FALSE if it is permanent and remains. */
bool silc_server_channel_delete(SilcServer server,
				SilcChannelEntry channel);

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */
bool silc_server_client_on_channel(SilcClientEntry client,
				   SilcChannelEntry channel,
				   SilcChannelClientEntry *chl);

/* Checks string for bad characters and returns TRUE if they are found. */
bool silc_server_name_bad_chars(const char *name, SilcUInt32 name_len);

/* Modifies the `nick' if it includes bad characters and returns new
   allocated nickname that does not include bad characters. */
char *silc_server_name_modify_bad(const char *name, SilcUInt32 name_len);

/* Find number of sockets by IP address indicated by `ip'. Returns 0 if
   socket connections with the IP address does not exist. */
SilcUInt32 silc_server_num_sockets_by_ip(SilcServer server, const char *ip,
					 SilcSocketType type);

/* Find number of sockets by IP address indicated by remote host, indicated
   by `ip' or `hostname', `port', and `type'.  Returns 0 if socket connections
   does not exist. If `ip' is provided then `hostname' is ignored. */
SilcUInt32 silc_server_num_sockets_by_remote(SilcServer server, 
					     const char *ip,
					     const char *hostname,
					     SilcUInt16 port,
					     SilcSocketType type);

/* Finds locally cached public key by the public key received in the SKE. 
   If we have it locally cached then we trust it and will use it in the
   authentication protocol.  Returns the locally cached public key or NULL
   if we do not find the public key.  */
SilcPublicKey silc_server_find_public_key(SilcServer server, 
					  SilcHashTable local_public_keys,
					  SilcPublicKey remote_public_key);

/* This returns the first public key from the table of public keys.  This
   is used only in cases where single public key exists in the table and
   we want to get a pointer to it.  For public key tables that has multiple
   keys in it the silc_server_find_public_key must be used. */
SilcPublicKey silc_server_get_public_key(SilcServer server,
					 SilcHashTable local_public_keys);

/* Check whether the connection `sock' is allowed to connect to us.  This
   checks for example whether there is too much connections for this host,
   and required version for the host etc. */
bool silc_server_connection_allowed(SilcServer server, 
				    SilcSocketConnection sock,
				    SilcSocketType type,
				    SilcServerConfigConnParams *global,
				    SilcServerConfigConnParams *params,
				    SilcSKE ske);

/* Checks that client has rights to add or remove channel modes. If any
   of the checks fails FALSE is returned. */
bool silc_server_check_cmode_rights(SilcServer server,
				    SilcChannelEntry channel,
				    SilcChannelClientEntry client,
				    SilcUInt32 mode);

/* Check that the client has rights to change its user mode.  Returns
   FALSE if setting some mode is not allowed. */
bool silc_server_check_umode_rights(SilcServer server,
				    SilcClientEntry client,
				    SilcUInt32 mode);

/* This function is used to send the notify packets and motd to the
   incoming client connection. */
void silc_server_send_connect_notifys(SilcServer server,
				      SilcSocketConnection sock,
				      SilcClientEntry client);

/* Kill the client indicated by `remote_client' sending KILLED notify
   to the client, to all channels client has joined and to primary
   router if needed.  The killed client is also removed from all channels. */
void silc_server_kill_client(SilcServer server,
			     SilcClientEntry remote_client,
			     const char *comment,
			     void *killer_id,
			     SilcIdType killer_id_type);

/* This function checks whether the `client' nickname is being watched
   by someone, and notifies the watcher of the notify change of notify
   type indicated by `notify'. */
bool silc_server_check_watcher_list(SilcServer server,
				    SilcClientEntry client,
				    const char *new_nick,
				    SilcNotifyType notify);

/* Remove the `client' from watcher list. After calling this the `client'
   is not watching any nicknames. */
bool silc_server_del_from_watcher_list(SilcServer server,
				       SilcClientEntry client);

/* Force the client indicated by `chl' to change the channel user mode
   on channel indicated by `channel' to `forced_mode'. */
bool silc_server_force_cumode_change(SilcServer server,
				     SilcSocketConnection sock,
				     SilcChannelEntry channel,
				     SilcChannelClientEntry chl,
				     SilcUInt32 forced_mode);

/* Find active socket connection by the IP address and port indicated by
   `ip' and `port', and socket connection type of `type'. */
SilcSocketConnection
silc_server_find_socket_by_host(SilcServer server,
				SilcSocketType type,
				const char *ip, SilcUInt16 port);

#endif /* SERVER_UTIL_H */
