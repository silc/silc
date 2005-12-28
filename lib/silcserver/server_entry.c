/*

  server_entry.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

/************************ Static utility functions **************************/

/* Foreach callbcak to free all users from the channel when deleting a
   channel entry. */

static void silc_server_del_channel_foreach(void *key, void *context,
					    void *user_context)
{
  SilcChannelClientEntry chl = (SilcChannelClientEntry)context;

  SILC_LOG_DEBUG(("Removing client %s from channel %s",
		  chl->client->nickname ? chl->client->nickname :
		  (unsigned char *)"", chl->channel->channel_name));

  /* Remove the context from the client's channel hash table as that
     table and channel's user_list hash table share this same context. */
  silc_hash_table_del(chl->client->channels, chl->channel);
  silc_free(chl);
}


/****************************** Server entry ********************************/

void silc_server_destructor_server(SilcIDCache cache,
				   const SilcIDCacheEntry entry,
				   void *destructor_context,
				   void *app_context)
{

}

/* Adds new server entry to server */

SilcServerEntry silc_server_add_server(SilcServer server,
				       const char *server_name,
				       SilcServerType server_type,
				       SilcServerID *id,
				       SilcPacketStream origin)
{
  SilcServerEntry entry;
  char *server_namec = NULL;

  if (!id || !origin)
    return NULL;

  entry = silc_calloc(1, sizeof(*entry));
  if (!entry)
    return NULL;

  SILC_LOG_DEBUG(("Adding server entry %p %s", entry,
		  silc_id_render(id, SILC_ID_SERVER)));

  /* Normalize name.  This is cached, original is in server context.  */
  if (server_name) {
    server_namec = silc_identifier_check(server_name, strlen(server_name),
					 SILC_STRING_UTF8, 256, NULL);
    if (!server_namec) {
      silc_free(entry);
      return NULL;
    }

    entry->server_name = strdup(server_name);
    if (!server->server_name) {
      silc_free(server_namec);
      silc_free(entry);
      return NULL;
    }
  }

  entry->server_type = server_type;
  entry->id = *id;
  entry->stream = origin;

  /* Add to cache */
  if (!silc_idcache_add(server->servers, server_namec, &entry->id,
			entry)) {
    silc_free(server_namec);
    silc_free(entry->server_name);
    silc_free(entry);
    return NULL;
  }

  /* Take reference of the packet stream */
  silc_packet_stream_ref(origin);

  return entry;
}

/* Delete server entry */

SilcBool silc_server_del_server(SilcServer server, SilcServerEntry entry)
{
  SILC_LOG_DEBUG(("Deleting server %s id %s", entry->server_name ?
		  entry->server_name : "??", &entry->id ?
		  silc_id_render(&entry->id, SILC_ID_SERVER) : "??"));

  /* Delete */
  if (!silc_idcache_del_by_context(server->servers, entry, NULL)) {
    SILC_LOG_ERROR(("Unknown server %s, could not delete from cache",
		    &entry->id ? silc_id_render(&entry->id, SILC_ID_SERVER) :
		    "??"));
    return FALSE;
  }

  return TRUE;
}

/* Find server by Server ID */

SilcServerEntry
silc_server_find_server_by_id(SilcServer server,
			      SilcServerID *id,
			      SilcBool registered,
			      SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry entry;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Find Server ID (%s)",
		  silc_id_render(id, SILC_ID_SERVER)));

  if (!silc_idcache_find_by_id_one(server->servers, (void *)id,
				   &id_cache))
    return NULL;

  entry = id_cache->context;

  if (entry && registered && !(entry->data.registered))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return entry;
}

/* Find server by name.  The 'name' must be normalized already. */

SilcServerEntry
silc_server_find_server_by_name(SilcServer server, char *name,
				SilcBool registered,
				SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry entry;

  SILC_LOG_DEBUG(("Find server by name `%s'", name));

  if (!silc_idcache_find_by_name_one(server->servers, name, &id_cache))
    return NULL;

  entry = id_cache->context;

  if (entry && registered && !(entry->data.registered))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return entry;
}

/* Find server by connection parameters, hostname and port */

SilcServerEntry
silc_server_find_server_by_conn(SilcServer server, char *hostname,
				int port, SilcBool registered,
				SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;
  SilcStream stream;
  SilcList list;
  const char *h;
  SilcUInt16 p;

  SILC_LOG_DEBUG(("Server by hostname %s and port %d", hostname, port));

  if (!silc_idcache_get_all(server->servers, &list))
    return NULL;

  while ((id_cache = silc_list_get(list)) != SILC_LIST_END) {
    entry = id_cache->context;
    stream = silc_packet_stream_get_stream(entry->stream);

    if (entry && registered && !(entry->data.registered))
      continue;

    if (silc_socket_stream_get_info(stream, NULL, &h, NULL, &p)) {
      if (silc_utf8_strcasecmp(hostname, h) && p == port)
	break;
    }
  }
  if (!id_cache)
    entry = NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return entry;
}

/* Replaces old Server ID with new one */

SilcServerEntry
silc_server_replace_server_id(SilcServer server, SilcServerID *old_id,
			      SilcServerID *new_id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry entry;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Server ID %s",
		  silc_id_render(old_id, SILC_ID_SERVER)));
  SILC_LOG_DEBUG(("New Server ID %s",
		  silc_id_render(new_id, SILC_ID_SERVER)));

  if (!silc_idcache_find_by_id_one(server->servers, (void *)old_id,
				   &id_cache))
    return NULL;

  entry = id_cache->context;
  entry->id = *new_id;

  if (!silc_idcache_update(server->servers, id_cache, old_id, &entry->id,
			   NULL, NULL)) {
    SILC_LOG_ERROR(("Error updating Server ID"));
    return NULL;
  }

  SILC_LOG_DEBUG(("Replaced"));

  return entry;
}


/****************************** Client entry ********************************/

void silc_server_destructor_client(SilcIDCache cache,
				   const SilcIDCacheEntry entry,
				   void *destructor_context,
				   void *app_context)
{

}

/* Adds new client to server */

SilcClientEntry silc_server_add_client(SilcServer server,
				       const char *nickname,
				       const char *username,
				       const char *userinfo,
				       SilcClientID *id,
				       SilcUInt32 mode,
				       SilcPacketStream origin)
{
  SilcClientEntry client;
  char *nicknamec = NULL;
  char u[128], h[256];
  int ret;

  if (!id || !origin || !nickname || !username)
    return NULL;

  client = silc_calloc(1, sizeof(*client));
  if (!client)
    return NULL;

  SILC_LOG_DEBUG(("Adding client entry %p", client));

  /* Normalize name.  This is cached, original is in client context.  */
  nicknamec = silc_identifier_check(nickname, strlen(nickname),
				    SILC_STRING_UTF8, 128, NULL);
  if (!nicknamec)
    goto err;

  /* Check username */
  ret = silc_parse_userfqdn(username, u, sizeof(u), h, sizeof(h));
  if (!ret)
    goto err;
  if (!silc_identifier_verify(u, strlen(u), SILC_STRING_UTF8, 128))
    goto err;
  if (ret == 2 &&
      !silc_identifier_verify(h, strlen(h), SILC_STRING_UTF8, 256))
    goto err;

  client->nickname = strdup(nickname);
  if (!client->nickname)
    goto err;

  client->username = strdup(username);
  if (!client->username)
    goto err;

  client->userinfo = userinfo ? strdup(userinfo) : NULL;
  if (!client->userinfo)
    goto err;

  client->id = *id;
  client->mode = mode;
  client->stream = origin;

  client->channels = silc_hash_table_alloc(0, silc_hash_ptr, NULL,
					   NULL, NULL, NULL, NULL, TRUE);
  if (!client->channels)
    goto err;

  if (!silc_idcache_add(server->clients, nicknamec, (void *)&client->id,
			(void *)client))
    goto err;

  /* Take reference of the packet stream */
  silc_packet_stream_ref(origin);

  return client;

 err:
  if (client->channels)
    silc_hash_table_free(client->channels);
  silc_free(client->nickname);
  silc_free(client->username);
  silc_free(client->userinfo);
  silc_free(client);
  silc_free(nicknamec);
  return NULL;
}

/* Delete client entry */

SilcBool silc_server_del_client(SilcServer server, SilcClientEntry entry)
{
  SILC_LOG_DEBUG(("Deleting client %s id %s", entry->nickname ?
		  entry->nickname : (unsigned char *)"??", &entry->id ?
		  silc_id_render(&entry->id, SILC_ID_CLIENT) : "??"));

  /* Delete */
  if (!silc_idcache_del_by_context(server->clients, entry, NULL)) {
    SILC_LOG_ERROR(("Unknown client %s, could not delete from cache",
		    &entry->id ? silc_id_render(&entry->id, SILC_ID_CLIENT) :
		    "??"));
    return FALSE;
  }

  return TRUE;
}

/* Finds all clients matching the nickanem `nickname'.  Returns list of
   SilcIDCacheEntry entries.  The `nickname' must be normalized. */

SilcBool silc_server_find_clients(SilcServer server, char *nickname,
				  SilcList *list)
{
  SilcClientID client_id;
  unsigned char hash[16];

  SILC_LOG_DEBUG(("Find clients named %s", nickname));

  /* Find using Client ID hash, as Client ID is based on the nickname,
     we can find clients quickly using the hash of the nickname. */
  memset(&client_id, 0, sizeof(client_id));
  silc_hash_make(server->md5hash, nickname, strlen(nickname), hash);
  memcpy(client_id.hash, hash, CLIENTID_HASH_LEN);

  if (!silc_idcache_find_by_id(server->clients, &client_id, list))
    return FALSE;

  SILC_LOG_DEBUG(("Found %d clients", silc_list_count(*list)));

  return TRUE;
}

/* Finds client by Client ID */

SilcClientEntry silc_server_find_client_by_id(SilcServer server,
					      SilcClientID *id,
					      SilcBool registered,
					      SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Client ID (%s)", silc_id_render(id, SILC_ID_CLIENT)));

  if (!silc_idcache_find_by_id_one(server->clients, (void *)id, &id_cache))
    return NULL;

  client = id_cache->context;

  if (client && registered && !(client->data.registered))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return client;
}

/* Replaces old Client ID with new one */

SilcClientEntry
silc_server_replace_client_id(SilcServer server, SilcClientID *old_id,
			      SilcClientID *new_id, const char *nickname)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry entry;
  char *name, *nicknamec = NULL;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Client ID %s",
		  silc_id_render(old_id, SILC_ID_SERVER)));
  SILC_LOG_DEBUG(("New Client ID %s",
		  silc_id_render(new_id, SILC_ID_SERVER)));

  /* Normalize name. This is cached, original is in client context.  */
  if (nickname) {
    nicknamec = silc_identifier_check(nickname, strlen(nickname),
				      SILC_STRING_UTF8, 128, NULL);
    if (!nicknamec)
      return NULL;
  }

  if (!silc_idcache_find_by_id_one(server->clients, (void *)old_id,
				   &id_cache))
    return NULL;

  entry = id_cache->context;
  entry->id = *new_id;

  name = id_cache->name;
  if (!silc_idcache_update(server->clients, id_cache, old_id, &entry->id,
			   name, nicknamec)) {
    SILC_LOG_ERROR(("Error updating Client ID"));
    return NULL;
  }
  if (nicknamec)
    silc_free(name);

  /* Check if anyone is watching old nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, entry, nickname,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

  silc_free(entry->nickname);
  entry->nickname = nickname ? strdup(nickname) : NULL;

  /* Check if anyone is watching new nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, entry, nickname,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

  SILC_LOG_DEBUG(("Replaced"));

  return entry;
}


/****************************** Channel entry *******************************/

void silc_server_destructor_channel(SilcIDCache cache,
				    const SilcIDCacheEntry entry,
				    void *destructor_context,
				    void *app_context)
{

}

/* Add new channel */

SilcChannelEntry silc_server_add_channel(SilcServer server,
					 const char *channel_name,
					 SilcUInt32 mode,
					 SilcChannelID *id,
					 SilcPacketStream origin,
					 SilcCipher channel_key,
					 SilcHmac hmac)
{
  SilcChannelEntry channel;
  char *channel_namec = NULL;

  if (!id || !channel_key || !hmac)
    return NULL;

  channel = silc_calloc(1, sizeof(*channel));
  if (!channel)
    return NULL;

  SILC_LOG_DEBUG(("Adding new channel %s %p", channel_name, channel));

  /* Normalize name.  This is cached, original is in client context.  */
  if (channel_name) {
    channel_namec = silc_channel_name_check(channel_name, strlen(channel_name),
					    SILC_STRING_UTF8, 256, NULL);
    if (!channel_namec) {
      silc_free(channel);
      return NULL;
    }
  }

  channel->channel_name = channel_name ? strdup(channel_name) : NULL;
  if (!channel) {
      silc_free(channel);
      silc_free(channel_namec);
      return NULL;
  }

  channel->mode = mode;
  channel->id = *id;
  channel->channel_key = channel_key;
  channel->hmac = hmac;
  channel->router = origin;

  channel->user_list = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL,
					     NULL, NULL, NULL, TRUE);
  if (!channel->user_list) {
    silc_cipher_free(channel->channel_key);
    silc_hmac_free(channel->hmac);
    silc_free(channel->channel_name);
    silc_free(channel);
    silc_free(channel_namec);
    return NULL;
  }

  if (!silc_idcache_add(server->channels, channel_namec,
			(void *)&channel->id, (void *)channel)) {
    silc_cipher_free(channel->channel_key);
    silc_hmac_free(channel->hmac);
    silc_free(channel->channel_name);
    silc_hash_table_free(channel->user_list);
    silc_free(channel);
    silc_free(channel_namec);
    return NULL;
  }

  /* Take reference of the packet stream */
  silc_packet_stream_ref(origin);

  return channel;
}

/* Free channel entry.  This free's everything. */

SilcBool silc_server_del_channel(SilcServer server, SilcChannelEntry entry)
{
  SILC_LOG_DEBUG(("Deleting channel %s", entry->channel_name));

  /* Remove from cache */
  if (!silc_idcache_del_by_context(server->channels, entry, NULL)) {
    SILC_LOG_DEBUG(("Unknown channel %s, did not delete",
		    entry->channel_name));
    return FALSE;
  }

  return TRUE;
}

/* Finds channel by channel name.  Channel names are unique and they
   are not case-sensitive.  The 'name' must be normalized already. */

SilcChannelEntry silc_server_find_channel_by_name(SilcServer server,
						  const char *name,
						  SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;

  SILC_LOG_DEBUG(("Channel by name %s", name));

  if (!silc_idcache_find_by_name_one(server->channels, (char *)name,
				     &id_cache))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return id_cache->context;
}

/* Finds channel by Channel ID. */

SilcChannelEntry silc_server_find_channel_by_id(SilcServer server,
						SilcChannelID *id,
						SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Channel ID (%s)", silc_id_render(id, SILC_ID_CHANNEL)));

  if (!silc_idcache_find_by_id_one(server->channels, (void *)id, &id_cache))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return id_cache->context;
}

/* Replaces old Channel ID with new one. This is done when router forces
   normal server to change Channel ID. */

SilcChannelEntry silc_server_replace_channel_id(SilcServer server,
						SilcChannelID *old_id,
						SilcChannelID *new_id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry entry;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Channel ID %s",
		  silc_id_render(old_id, SILC_ID_CHANNEL)));
  SILC_LOG_DEBUG(("New Channel ID %s",
		  silc_id_render(new_id, SILC_ID_CHANNEL)));

  if (!silc_idcache_find_by_id_one(server->channels, (void *)old_id,
				   &id_cache))
    return NULL;

  entry = id_cache->context;
  entry->id = *new_id;

  if (!silc_idcache_update(server->channels, id_cache, old_id, &entry->id,
			   NULL, NULL)) {
    SILC_LOG_ERROR(("Error updating Channel ID"));
    return NULL;
  }

  SILC_LOG_DEBUG(("Replaced"));

  return entry;
}

/* Returns channels from the ID list.  If the `channel_id' is NULL then
   all channels are returned.  Returns list of SilcIDCacheEntry entries. */

SilcBool silc_server_get_channels(SilcServer server,
				  SilcChannelID *channel_id,
				  SilcList *list)
{
  SILC_LOG_DEBUG(("Start"));

  if (!channel_id) {
    if (!silc_idcache_get_all(server->channels, list))
      return FALSE;
  } else {
    if (!silc_idcache_find_by_id(server->channels, channel_id, list))
      return FALSE;
  }

  return TRUE;
}
