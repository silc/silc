/*

  idlist.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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

                             Common functions

******************************************************************************/

/* This function is used to add keys and stuff to common ID entry data
   structure. */

void silc_idlist_add_data(void *entry, SilcIDListData idata)
{
  SilcIDListData data = (SilcIDListData)entry;
  data->send_key = idata->send_key;
  data->receive_key = idata->receive_key;
  data->hmac = idata->hmac;
  data->hmac_key = idata->hmac_key;
  data->hmac_key_len = idata->hmac_key_len;
  data->pkcs = idata->pkcs;
  data->public_key = idata->public_key;
  data->last_receive = idata->last_receive;
  data->last_sent = idata->last_sent;
  data->registered = idata->registered;
}

/* Free's all data in the common ID entry data structure. */

void silc_idlist_del_data(void *entry)
{
  SilcIDListData idata = (SilcIDListData)entry;
  if (idata->send_key)
    silc_cipher_free(idata->send_key);
  if (idata->receive_key)
    silc_cipher_free(idata->receive_key);
  if (idata->hmac)
    silc_hmac_free(idata->hmac);
  if (idata->hmac_key) {
    memset(idata->hmac_key, 0, idata->hmac_key_len);
    silc_free(idata->hmac_key);
  }
  if (idata->pkcs)
    silc_pkcs_free(idata->pkcs);
  if (idata->public_key)
    silc_pkcs_public_key_free(idata->public_key);
}

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
		       void *connection)
{
  SilcServerEntry server;

  SILC_LOG_DEBUG(("Adding new server entry"));

  server = silc_calloc(1, sizeof(*server));
  server->server_name = server_name;
  server->server_type = server_type;
  server->id = id;
  server->router = router;
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
silc_idlist_find_server_by_id(SilcIDList id_list, SilcServerID *id,
			      SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Server ID (%s)",
		  silc_id_render(id, SILC_ID_SERVER)));

  if (!silc_idcache_find_by_id_one(id_list->servers, (void *)id, 
				   SILC_ID_SERVER, &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

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

/* Removes and free's server entry from ID list */

void silc_idlist_del_server(SilcIDList id_list, SilcServerEntry entry)
{
  if (entry) {
    /* Remove from cache */
    if (entry->id)
      silc_idcache_del_by_id(id_list->servers, SILC_ID_SERVER, 
			     (void *)entry->id);

    /* Free data */
    if (entry->server_name)
      silc_free(entry->server_name);
    if (entry->id)
      silc_free(entry->id);
  }
}

/******************************************************************************

                          Client entry functions

******************************************************************************/

/* Add new client entry. This adds the client entry to ID cache system
   and returns the allocated client entry or NULL on error.  This is
   called when new client connection is accepted to the server. If The
   `router' is provided then the all server routines assume that the client
   is not directly connected local client but it has router set and is
   remote.  If this is the case then `connection' must be NULL.  If, on the
   other hand, the `connection' is provided then the client is assumed
   to be directly connected local client and `router' must be NULL. */

SilcClientEntry
silc_idlist_add_client(SilcIDList id_list, unsigned char *nickname, 
		       char *username, char *userinfo, SilcClientID *id, 
		       SilcServerEntry router, void *connection)
{
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Adding new client entry"));

  client = silc_calloc(1, sizeof(*client));
  client->nickname = nickname;
  client->username = username;
  client->userinfo = userinfo;
  client->id = id;
  client->router = router;
  client->connection = connection;
  silc_list_init(client->channels, struct SilcChannelClientEntryStruct, 
		 client_list);

  if (!silc_idcache_add(id_list->clients, nickname, SILC_ID_CLIENT,
			(void *)client->id, (void *)client, TRUE)) {
    silc_free(client);
    return NULL;
  }

  return client;
}

/* Free client entry. This free's everything and removes the entry
   from ID cache. Call silc_idlist_del_data before calling this one. */

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

/* Returns all clients matching requested nickname. Number of clients is
   returned to `clients_count'. Caller must free the returned table. */

SilcClientEntry *
silc_idlist_get_clients_by_hash(SilcIDList id_list, char *nickname,
				SilcHash md5hash,
				unsigned int *clients_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry *clients;
  unsigned char hash[32];
  int i;

  silc_hash_make(md5hash, nickname, strlen(nickname), hash);

  if (!silc_idcache_find_by_data(id_list->clients, hash, &list))
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
				    char *server, SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;

  SILC_LOG_DEBUG(("Client by nickname"));

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

    if (ret_entry)
      *ret_entry = id_cache;
  }

  SILC_LOG_DEBUG(("Found"));

  return client;
}

/* Finds client by nickname hash. */

SilcClientEntry
silc_idlist_find_client_by_hash(SilcIDList id_list, char *nickname,
				SilcHash md5hash, SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  unsigned char hash[32];

  SILC_LOG_DEBUG(("Client by hash"));

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

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return client;
}

/* Finds client by Client ID */

SilcClientEntry
silc_idlist_find_client_by_id(SilcIDList id_list, SilcClientID *id,
			      SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Client ID (%s)", 
		  silc_id_render(id, SILC_ID_CLIENT)));

  if (!silc_idcache_find_by_id_one(id_list->clients, (void *)id, 
				   SILC_ID_CLIENT, &id_cache))
    return NULL;

  client = (SilcClientEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

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

  /* If the old ID Cache data was the hash value of the old Client ID
     replace it with the hash of new Client ID */
  if (id_cache->data && !SILC_ID_COMPARE_HASH(old_id, id_cache->data)) {
    silc_free(id_cache->data);
    id_cache->data = silc_calloc(sizeof(new_id->hash), sizeof(unsigned char));
    memcpy(id_cache->data, new_id->hash, sizeof(new_id->hash));
    silc_idcache_sort_by_data(id_list->clients);
  }

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

int silc_idlist_del_channel(SilcIDList id_list, SilcChannelEntry entry)
{
  if (entry) {
    SilcChannelClientEntry chl;

    /* Remove from cache */
    if (entry->id)
      if (!silc_idcache_del_by_id(id_list->channels, SILC_ID_CHANNEL, 
				  (void *)entry->id))
	return FALSE;

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

  return TRUE;
}

/* Finds channel by channel name. Channel names are unique and they
   are not case-sensitive. */

SilcChannelEntry
silc_idlist_find_channel_by_name(SilcIDList id_list, char *name,
				 SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("Channel by name"));

  if (!silc_idcache_find_by_data_loose(id_list->channels, name, &list))
    return NULL;
  
  if (!silc_idcache_list_first(list, &id_cache)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  channel = (SilcChannelEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

  silc_idcache_list_free(list);

  SILC_LOG_DEBUG(("Found"));

  return channel;
}

/* Finds channel by Channel ID. */

SilcChannelEntry
silc_idlist_find_channel_by_id(SilcIDList id_list, SilcChannelID *id,
			       SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Channel ID (%s)",
		  silc_id_render(id, SILC_ID_CHANNEL)));

  if (!silc_idcache_find_by_id_one(id_list->channels, (void *)id, 
				   SILC_ID_CHANNEL, &id_cache))
    return NULL;

  channel = (SilcChannelEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return channel;
}
