/*

  server_entry.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVER_ENTRY_H
#define SERVER_ENTRY_H

void silc_server_destructor_client(SilcIDCache cache,
				   const SilcIDCacheEntry entry,
				   void *destructor_context,
				   void *app_context);
void silc_server_destructor_server(SilcIDCache cache,
				   const SilcIDCacheEntry entry,
				   void *destructor_context,
				   void *app_context);
void silc_server_destructor_channel(SilcIDCache cache,
				    const SilcIDCacheEntry entry,
				    void *destructor_context,
				    void *app_context);

SilcServerEntry silc_server_add_server(SilcServer server,
				       const char *server_name,
				       SilcServerType server_type,
				       SilcServerID *id,
				       SilcPacketStream origin);
SilcBool silc_server_del_server(SilcServer server, SilcServerEntry entry);
SilcServerEntry
silc_server_find_server_by_id(SilcServer server,
			      SilcServerID *id,
			      SilcBool registered,
			      SilcIDCacheEntry *ret_entry);
SilcServerEntry
silc_server_find_server_by_name(SilcServer server, char *name,
				SilcBool registered,
				SilcIDCacheEntry *ret_entry);
SilcServerEntry
silc_server_find_server_by_conn(SilcServer server, char *hostname,
				int port, SilcBool registered,
				SilcIDCacheEntry *ret_entry);
SilcServerEntry
silc_server_replace_server_id(SilcServer server, SilcServerID *old_id,
			      SilcServerID *new_id);
SilcClientEntry silc_server_add_client(SilcServer server,
				       const char *nickname,
				       const char *username,
				       const char *userinfo,
				       SilcClientID *id,
				       SilcUInt32 mode,
				       SilcPacketStream origin);
SilcBool silc_server_del_client(SilcServer server, SilcClientEntry entry);
SilcBool silc_server_find_clients(SilcServer server, char *nickname,
				  SilcList *list);
SilcClientEntry silc_server_find_client_by_id(SilcServer server,
					      SilcClientID *id,
					      SilcBool registered,
					      SilcIDCacheEntry *ret_entry);
SilcClientEntry
silc_server_replace_client_id(SilcServer server, SilcClientID *old_id,
			      SilcClientID *new_id, const char *nickname);
SilcChannelEntry silc_server_add_channel(SilcServer server,
					 const char *channel_name,
					 SilcUInt32 mode,
					 SilcChannelID *id,
					 SilcPacketStream origin,
					 SilcCipher channel_key,
					 SilcHmac hmac);
SilcBool silc_server_del_channel(SilcServer server, SilcChannelEntry entry);
SilcChannelEntry silc_server_find_channel_by_name(SilcServer server,
						  const char *name,
						  SilcIDCacheEntry *ret_entry);
SilcChannelEntry silc_server_find_channel_by_id(SilcServer server,
						SilcChannelID *id,
						SilcIDCacheEntry *ret_entry);
SilcChannelEntry silc_server_replace_channel_id(SilcServer server,
						SilcChannelID *old_id,
						SilcChannelID *new_id);
SilcBool silc_server_get_channels(SilcServer server,
				  SilcChannelID *channel_id,
				  SilcList *list);

#endif /* SERVER_ENTRY_H */
