/*

  idlist.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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

#include "serverincludes.h"
#include "idlist.h"

/******************************************************************************

                          Server entry functions

******************************************************************************/

/* Add new server entry. This adds the new server entry to ID cache and
   returns the allocated entry object or NULL on error. This is called
   when new server connects to us. We also add ourselves to cache with
   this function. */

SilcServerEntry 
silc_idlist_add_server(SilcIDList id_list, 
		       char *server_name, int server_type,
		       SilcServerID *id, SilcServerEntry router,
		       SilcCipher send_key, SilcCipher receive_key,
		       SilcPKCS pkcs, SilcHmac hmac, 
		       SilcPublicKey public_key, void *connection)
{
  SilcServerEntry server;

  SILC_LOG_DEBUG(("Adding new server entry"));

  server = silc_calloc(1, sizeof(*server));
  server->server_name = server_name;
  server->server_type = server_type;
  server->id = id;
  server->router = router;
  server->send_key = send_key;
  server->receive_key = receive_key;
  server->pkcs = pkcs;
  server->hmac = hmac;
  server->public_key = public_key;
  server->connection = connection;

  if (!silc_idcache_add(id_list->servers, server->server_name, SILC_ID_SERVER,
			(void *)server->id, (void *)server, TRUE)) {
    silc_free(server);
    return NULL;
  }

  return server;
}

/* Finds server by Server ID */

SilcServerEntry
silc_idlist_find_server_by_id(SilcIDList id_list, SilcServerID *id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Finding server by ID"));

  if (!silc_idcache_find_by_id_one(id_list->servers, (void *)id, 
				   SILC_ID_SERVER, &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;

  return server;
}

/* Replaces old Server ID with new one */ 

SilcServerEntry
silc_idlist_replace_server_id(SilcIDList id_list, SilcServerID *old_id,
			      SilcServerID *new_id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Server ID"));

  if (!silc_idcache_find_by_id_one(id_list->servers, (void *)old_id, 
				   SILC_ID_SERVER, &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;
  silc_free(server->id);
  server->id = new_id;
  id_cache->id = (void *)new_id;

  return server;
}

/******************************************************************************

                          Client entry functions

******************************************************************************/

/* Add new client entry. This adds the client entry to ID cache system
   and returns the allocated client entry or NULL on error.  This is
   called when new client connection is accepted to the server. */

SilcClientEntry
silc_idlist_add_client(SilcIDList id_list, char *nickname, char *username,
		       char *userinfo, SilcClientID *id, 
		       SilcServerEntry router,
		       SilcCipher send_key, SilcCipher receive_key,
		       SilcPKCS pkcs, SilcHmac hmac, 
		       SilcPublicKey public_key, void *connection)
{
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Adding new client entry"));

  client = silc_calloc(1, sizeof(*client));
  client->nickname = nickname;
  client->username = username;
  client->userinfo = userinfo;
  client->id = id;
  client->router = router;
  client->send_key = send_key;
  client->receive_key = receive_key;
  client->pkcs = pkcs;
  client->hmac = hmac;
  client->public_key = public_key;
  client->connection = connection;
  silc_list_init(client->channels, struct SilcChannelClientEntryStruct, 
		 client_list);

  if (!silc_idcache_add(id_list->clients, client->nickname, SILC_ID_CLIENT,
			(void *)client->id, (void *)client, TRUE)) {
    silc_free(client);
    return NULL;
  }

  return client;
}

/* Free client entry. This free's everything and removes the entry
   from ID cache. */

void silc_idlist_del_client(SilcIDList id_list, SilcClientEntry entry)
{
  if (entry) {
    /* Remove from cache */
    if (entry->id)
      silc_idcache_del_by_id(id_list->clients, SILC_ID_CLIENT, 
			     (void *)entry->id);

    /* Free data */
    if (entry->nickname)
      silc_free(entry->nickname);
    if (entry->username)
      silc_free(entry->username);
    if (entry->userinfo)
      silc_free(entry->userinfo);
    if (entry->id)
      silc_free(entry->id);
    if (entry->send_key)
      silc_cipher_free(entry->send_key);
    if (entry->receive_key)
      silc_cipher_free(entry->receive_key);
    if (entry->pkcs)
      silc_pkcs_free(entry->pkcs);
    if (entry->public_key)
      silc_pkcs_public_key_free(entry->public_key);
    if (entry->hmac)
      silc_hmac_free(entry->hmac);
  }
}

/* Returns all clients matching requested nickname. Number of clients is
   returned to `clients_count'. Caller must free the returned table. */

SilcClientEntry *
silc_idlist_get_clients_by_nickname(SilcIDList id_list, char *nickname,
				    char *server, unsigned int *clients_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry *clients;
  int i;

  if (!silc_idcache_find_by_data(id_list->clients, nickname, &list))
    return NULL;

  clients = silc_calloc(silc_idcache_list_count(list), sizeof(*clients));

  i = 0;
  silc_idcache_list_first(list, &id_cache);
  clients[i++] = (SilcClientEntry)id_cache->context;

  while (silc_idcache_list_next(list, &id_cache))
    clients[i++] = (SilcClientEntry)id_cache->context;
  
  silc_idcache_list_free(list);
  
  if (clients_count)
    *clients_count = i;

  return clients;
}

/* Finds client entry by nickname. */

SilcClientEntry
silc_idlist_find_client_by_nickname(SilcIDList id_list, char *nickname,
				    char *server)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;

  SILC_LOG_DEBUG(("Finding client by nickname"));

  if (server) {
    if (!silc_idcache_find_by_data(id_list->clients, nickname, &list))
      return NULL;

#if 0
    while (silc_idcache_list_next(list, &id_cache)) {
      client = (SilcClientEntry)id_cache->context;

      if (!strcmp(server, XXX, strlen(server)))
	break;

      client = NULL;
    }
#endif

   silc_idcache_list_free(list);

   if (!client)
     return NULL;
  } else {
    if (!silc_idcache_find_by_data_one(id_list->clients, nickname, &id_cache))
      return NULL;

    client = (SilcClientEntry)id_cache->context;
  }

  return client;
}

/* Finds client by nickname hash. */

SilcClientEntry
silc_idlist_find_client_by_hash(SilcIDList id_list, char *nickname,
				SilcHash md5hash)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  unsigned char hash[32];

  SILC_LOG_DEBUG(("Finding client by hash"));

  silc_hash_make(md5hash, nickname, strlen(nickname), hash);

  if (!silc_idcache_find_by_id(id_list->clients, SILC_ID_CACHE_ANY, 
			       SILC_ID_CLIENT, &list))
    return NULL;

  if (!silc_idcache_list_first(list, &id_cache)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  while (id_cache) {
    client = (SilcClientEntry)id_cache->context;
    
    if (client && !SILC_ID_COMPARE_HASH(client->id, hash))
      break;

    id_cache = NULL;
    client = NULL;

    if (!silc_idcache_list_next(list, &id_cache))
      break;
  }
  
  silc_idcache_list_free(list);

  return client;
}

/* Finds client by Client ID */

SilcClientEntry
silc_idlist_find_client_by_id(SilcIDList id_list, SilcClientID *id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Finding client by ID"));

  if (!silc_idcache_find_by_id_one(id_list->clients, (void *)id, 
				   SILC_ID_CLIENT, &id_cache))
    return NULL;

  client = (SilcClientEntry)id_cache->context;

  return client;
}

/* Replaces old Client ID with new one */

SilcClientEntry
silc_idlist_replace_client_id(SilcIDList id_list, SilcClientID *old_id,
			      SilcClientID *new_id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Client ID"));

  if (!silc_idcache_find_by_id_one(id_list->clients, (void *)old_id, 
				   SILC_ID_CLIENT, &id_cache))
    return NULL;

  client = (SilcClientEntry)id_cache->context;
  silc_free(client->id);
  client->id = new_id;
  id_cache->id = (void *)new_id;

  return client;
}


/******************************************************************************

                          Channel entry functions

******************************************************************************/

/* Add new channel entry. This add the new channel entry to the ID cache
   system and returns the allocated entry or NULL on error. */

SilcChannelEntry
silc_idlist_add_channel(SilcIDList id_list, char *channel_name, int mode,
			SilcChannelID *id, SilcServerEntry router,
			SilcCipher channel_key)
{
  SilcChannelEntry channel;

  channel = silc_calloc(1, sizeof(*channel));
  channel->channel_name = channel_name;
  channel->mode = mode;
  channel->id = id;
  channel->router = router;
  channel->channel_key = channel_key;
  silc_list_init(channel->user_list, struct SilcChannelClientEntryStruct, 
		 channel_list);

  if (!silc_idcache_add(id_list->channels, channel->channel_name, 
			SILC_ID_CHANNEL, (void *)channel->id, 
			(void *)channel, TRUE)) {
    silc_free(channel);
    return NULL;
  }

  return channel;
}

/* Free channel entry.  This free's everything. */

void silc_idlist_del_channel(SilcIDList id_list, SilcChannelEntry entry)
{
  if (entry) {
    SilcChannelClientEntry chl;

    /* Remove from cache */
    if (entry->id)
      silc_idcache_del_by_id(id_list->channels, SILC_ID_CHANNEL, 
			     (void *)entry->id);

    /* Free data */
    if (entry->channel_name)
      silc_free(entry->channel_name);
    if (entry->id)
      silc_free(entry->id);
    if (entry->topic)
      silc_free(entry->topic);
    if (entry->channel_key)
      silc_cipher_free(entry->channel_key);
    if (entry->key) {
      memset(entry->key, 0, entry->key_len / 8);
      silc_free(entry->key);
    }
    memset(entry->iv, 0, sizeof(entry->iv));
    
    silc_list_start(entry->user_list);
    while ((chl = silc_list_get(entry->user_list)) != SILC_LIST_END) {
      silc_list_del(entry->user_list, chl);
      silc_free(chl);
    }
  }
}

/* Finds channel by channel name. Channel names are unique and they
   are not case-sensitive. */

SilcChannelEntry
silc_idlist_find_channel_by_name(SilcIDList id_list, char *name)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("Finding channel by name"));

  if (!silc_idcache_find_by_data_loose(id_list->channels, name, &list))
    return NULL;
  
  if (!silc_idcache_list_first(list, &id_cache)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  channel = (SilcChannelEntry)id_cache->context;

  silc_idcache_list_free(list);

  return channel;
}

/* Finds channel by Channel ID. */

SilcChannelEntry
silc_idlist_find_channel_by_id(SilcIDList id_list, SilcChannelID *id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Finding channel by ID"));

  if (!silc_idcache_find_by_id_one(id_list->channels, (void *)id, 
				   SILC_ID_CHANNEL, &id_cache))
    return NULL;

  channel = (SilcChannelEntry)id_cache->context;

  return channel;
}
