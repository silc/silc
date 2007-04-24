/*

  server_util.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005, 2007 Pekka Riikonen

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

/* This function removes all client entries that are originated from
   `router' and are owned by `entry'.  `router' and `entry' can be same
   too.  If `server_signoff' is TRUE then SERVER_SIGNOFF notify is
   distributed to our local clients. */
SilcBool silc_server_remove_clients_by_server(SilcServer server,
					  SilcServerEntry router,
					  SilcServerEntry entry,
					  SilcBool server_signoff);

/* Updates the clients that are originated from the `from' to be originated
   from the `to'. If the `resolve_real_server' is TRUE then this will
   attempt to figure out which clients really are originated from the
   `from' and which are originated from a server that we have connection
   to, when we've acting as backup router. If it is FALSE the `to' will
   be the new source.  If `from' is NULL then all clients (except locally
   connected) are updated `to'. */
void silc_server_update_clients_by_server(SilcServer server,
					  SilcServerEntry from,
					  SilcServerEntry to,
					  SilcBool resolve_real_server);

/* Updates servers that are from `from' to be originated from `to'.  This
   will also update the server's connection to `to's connection. */
void silc_server_update_servers_by_server(SilcServer server,
					  SilcServerEntry from,
					  SilcServerEntry to);

/* Toggles the enabled/disabled status of local server connections.  Packets
   can be sent to the servers when `toggle_enabled' is TRUE and will be
   dropped if `toggle_enabled' is FALSE, after this function is called. */
void silc_server_local_servers_toggle_enabled(SilcServer server,
					      SilcBool toggle_enabled);

/* Removes servers that are originated from the `from'.  The server
   entry is deleted in this function.  If `remove_clients' is TRUE then
   all clients originated from the server are removed too, and server
   signoff is sent.  Note that this does not remove the `from'.  This
   also does not remove locally connected servers. */
void silc_server_remove_servers_by_server(SilcServer server,
					  SilcServerEntry from,
					  SilcBool remove_clients);

/* Removes channels that are from `from. */
void silc_server_remove_channels_by_server(SilcServer server,
					   SilcServerEntry from);

/* Updates channels that are from `from' to be originated from `to'.  */
void silc_server_update_channels_by_server(SilcServer server,
					   SilcServerEntry from,
					   SilcServerEntry to);

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */
SilcBool silc_server_channel_has_global(SilcChannelEntry channel);

/* Checks whether given channel has locally connected users.  If it does this
   returns TRUE and FALSE if there is not one locally connected client. */
SilcBool silc_server_channel_has_local(SilcChannelEntry channel);

/* This function removes the channel and all users on the channel, unless
   the channel is permanent.  In this case the channel is disabled but all
   users are removed from the channel.  Returns TRUE if the channel is
   destroyed totally, and FALSE if it is permanent and remains. */
SilcBool silc_server_channel_delete(SilcServer server,
				    SilcChannelEntry channel);

/* Returns TRUE if the given client is on the channel.  FALSE if not.
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from
   `client' which is faster than checking the user list from `channel'. */
SilcBool silc_server_client_on_channel(SilcClientEntry client,
				       SilcChannelEntry channel,
				       SilcChannelClientEntry *chl);

/* Find number of sockets by IP address indicated by `ip'. Returns 0 if
   socket connections with the IP address does not exist. */
SilcUInt32 silc_server_num_sockets_by_ip(SilcServer server, const char *ip,
					 SilcConnectionType type);

/* Find number of sockets by IP address indicated by remote host, indicated
   by `ip' or `hostname', `port', and `type'.  Returns 0 if socket connections
   does not exist. If `ip' is provided then `hostname' is ignored. */
SilcUInt32 silc_server_num_sockets_by_remote(SilcServer server,
					     const char *ip,
					     const char *hostname,
					     SilcUInt16 port);

/* Get public key by key usage and key context. */
SilcPublicKey silc_server_get_public_key(SilcServer server,
					 SilcSKRKeyUsage usage,
					 void *key_context);

/* Find public key by client for identification purposes.  Finds keys
   with SILC_SKR_USAGE_IDENTIFICATION. */
SilcBool silc_server_get_public_key_by_client(SilcServer server,
					      SilcClientEntry client,
					      SilcPublicKey *public_key);

/* Check whether the connection `sock' is allowed to connect to us.  This
   checks for example whether there is too much connections for this host,
   and required version for the host etc. */
SilcBool silc_server_connection_allowed(SilcServer server,
					SilcPacketStream sock,
					SilcConnectionType type,
					SilcServerConfigConnParams *global,
					SilcServerConfigConnParams *params,
					SilcSKE ske);

/* Checks that client has rights to add or remove channel modes. If any
   of the checks fails FALSE is returned. */
SilcBool silc_server_check_cmode_rights(SilcServer server,
					SilcChannelEntry channel,
					SilcChannelClientEntry client,
					SilcUInt32 mode);

/* Check that the client has rights to change its user mode.  Returns
   FALSE if setting some mode is not allowed. */
SilcBool silc_server_check_umode_rights(SilcServer server,
				    SilcClientEntry client,
				    SilcUInt32 mode);

/* This function is used to send the notify packets and motd to the
   incoming client connection. */
void silc_server_send_connect_notifys(SilcServer server,
				      SilcPacketStream sock,
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
SilcBool silc_server_check_watcher_list(SilcServer server,
				    SilcClientEntry client,
				    const char *new_nick,
				    SilcNotifyType notify);

/* Remove the `client' from watcher list. After calling this the `client'
   is not watching any nicknames. */
SilcBool silc_server_del_from_watcher_list(SilcServer server,
				       SilcClientEntry client);

/* Force the client indicated by `chl' to change the channel user mode
   on channel indicated by `channel' to `forced_mode'. */
SilcBool silc_server_force_cumode_change(SilcServer server,
				     SilcPacketStream sock,
				     SilcChannelEntry channel,
				     SilcChannelClientEntry chl,
				     SilcUInt32 forced_mode);

/* Find active socket connection by the IP address and port indicated by
   `ip' and `port', and socket connection type of `type'. */
SilcPacketStream
silc_server_find_socket_by_host(SilcServer server,
				SilcConnectionType type,
				const char *ip, SilcUInt16 port);

/* This function can be used to match the invite and ban lists. */
SilcBool silc_server_inviteban_match(SilcServer server, SilcHashTable list,
				 SilcUInt8 type, void *check);

/* Process invite or ban information */
SilcBool silc_server_inviteban_process(SilcServer server, SilcHashTable list,
				   SilcUInt8 action, SilcArgumentPayload args);

/* Destructor for invite or ban list entrys */
void silc_server_inviteban_destruct(void *key, void *context,
				    void *user_context);

/* Creates connections according to configuration. */
void silc_server_create_connections(SilcServer server);


/* Processes a channel public key, either adds or removes it. */
SilcStatus
silc_server_process_channel_pk(SilcServer server,
			       SilcChannelEntry channel,
			       SilcUInt32 type, const unsigned char *pk,
			       SilcUInt32 pk_len);

/* Returns the channel public keys as Argument List payload. */
SilcBuffer silc_server_get_channel_pk_list(SilcServer server,
					   SilcChannelEntry channel,
					   SilcBool announce,
					   SilcBool delete);

/* Sets the channel public keys into channel from the list of public keys. */
SilcStatus silc_server_set_channel_pk_list(SilcServer server,
					   SilcPacketStream sender,
					   SilcChannelEntry channel,
					   const unsigned char *pklist,
					   SilcUInt32 pklist_len);

/* Verifies the Authentication Payload `auth' with one of the public keys
   on the `channel' public key list. */
SilcBool silc_server_verify_channel_auth(SilcServer server,
				     SilcChannelEntry channel,
				     SilcClientID *client_id,
				     const unsigned char *auth,
				     SilcUInt32 auth_len);

#endif /* SERVER_UTIL_H */
