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
  data->rekey = idata->rekey;
  data->hash = idata->hash;
  data->hmac_send = idata->hmac_send;
  data->hmac_receive = idata->hmac_receive;
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
  if (idata->rekey) {
    if (idata->rekey->send_enc_key) {
      memset(idata->rekey->send_enc_key, 0, idata->rekey->enc_key_len);
      silc_free(idata->rekey->send_enc_key);
    }
    silc_free(idata->rekey);
  }
  if (idata->hmac_send)		/* Same as idata->hmac_receive */
    silc_hmac_free(idata->hmac_send);
  if (idata->public_key)
    silc_pkcs_public_key_free(idata->public_key);
}

/* Purges ID cache */

SILC_TASK_CALLBACK_GLOBAL(silc_idlist_purge)
{
  SilcIDListPurge i = (SilcIDListPurge)context;

  SILC_LOG_DEBUG(("Start"));

  silc_idcache_purge(i->cache);
  silc_schedule_task_add(i->schedule, 0, 
			 silc_idlist_purge,
			 (void *)i, 600, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
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

  if (!silc_idcache_add(id_list->servers, server->server_name, 
			(void *)server->id, (void *)server, FALSE)) {
    silc_free(server);
    return NULL;
  }

  return server;
}

/* Finds server by Server ID */

SilcServerEntry
silc_idlist_find_server_by_id(SilcIDList id_list, SilcServerID *id,
			      bool registered, SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Server ID (%s)",
		  silc_id_render(id, SILC_ID_SERVER)));

  if (!silc_idcache_find_by_id_one(id_list->servers, (void *)id, 
				   &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

  if (server && registered && !server->data.registered)
    return NULL;

  SILC_LOG_DEBUG(("Found"));

  return server;
}

/* Find server by name */

SilcServerEntry
silc_idlist_find_server_by_name(SilcIDList id_list, char *name,
				bool registered, SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server;

  SILC_LOG_DEBUG(("Server by name `%s'", name));

  if (!silc_idcache_find_by_name_one(id_list->servers, name, &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;
  
  if (ret_entry)
    *ret_entry = id_cache;

  if (server && registered && !server->data.registered)
    return NULL;

  SILC_LOG_DEBUG(("Found"));

  return server;
}

/* Find server by connection parameters, hostname and port */

SilcServerEntry
silc_idlist_find_server_by_conn(SilcIDList id_list, char *hostname,
				int port, bool registered,
				SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server = NULL;
  SilcSocketConnection sock;
 
  SILC_LOG_DEBUG(("Server by hostname %s and port %d", hostname, port));

  if (!silc_idcache_get_all(id_list->servers, &list))
    return NULL;

  if (!silc_idcache_list_first(list, &id_cache)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  while (id_cache) {
    server = (SilcServerEntry)id_cache->context;
    sock = (SilcSocketConnection)server->connection;
    
    if (sock && ((sock->hostname && !strcasecmp(sock->hostname, hostname)) ||
		 (sock->ip && !strcasecmp(sock->ip, hostname)))
	&& sock->port == port)
      break;

    id_cache = NULL;
    server = NULL;

    if (!silc_idcache_list_next(list, &id_cache))
      break;
  }
  
  silc_idcache_list_free(list);

  if (ret_entry)
    *ret_entry = id_cache;

  if (server && registered && !server->data.registered)
    return NULL;

  SILC_LOG_DEBUG(("Found"));

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
				   &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;

  /* Remove the old entry and add a new one */

  silc_idcache_del_by_id(id_list->servers, (void *)server->id);

  silc_free(server->id);
  server->id = new_id;

  silc_idcache_add(id_list->servers, server->server_name, server->id, 
		   server, FALSE);

  SILC_LOG_DEBUG(("Found"));

  return server;
}

/* Removes and free's server entry from ID list */

int silc_idlist_del_server(SilcIDList id_list, SilcServerEntry entry)
{
  SILC_LOG_DEBUG(("Start"));

  if (entry) {
    /* Remove from cache */
    if (entry->id)
      if (!silc_idcache_del_by_id(id_list->servers, (void *)entry->id))
	return FALSE;

    /* Free data */
    if (entry->server_name)
      silc_free(entry->server_name);
    if (entry->id)
      silc_free(entry->id);

    memset(entry, 'F', sizeof(*entry));
    silc_free(entry);
    return TRUE;
  }

  return FALSE;
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
silc_idlist_add_client(SilcIDList id_list, char *nickname, char *username, 
		       char *userinfo, SilcClientID *id, 
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
  client->channels = silc_hash_table_alloc(3, silc_hash_ptr, NULL,
					   NULL, NULL, NULL, NULL, TRUE);

  if (!silc_idcache_add(id_list->clients, nickname, (void *)client->id, 
			(void *)client, FALSE)) {
    silc_hash_table_free(client->channels);
    silc_free(client);
    return NULL;
  }

  return client;
}

/* Free client entry. This free's everything and removes the entry
   from ID cache. Call silc_idlist_del_data before calling this one. */

int silc_idlist_del_client(SilcIDList id_list, SilcClientEntry entry)
{
  SILC_LOG_DEBUG(("Start"));

  if (entry) {
    /* Remove from cache */
    if (entry->id)
      if (!silc_idcache_del_by_context(id_list->clients, entry))
	return FALSE;

    /* Free data */
    if (entry->nickname)
      silc_free(entry->nickname);
    if (entry->username)
      silc_free(entry->username);
    if (entry->userinfo)
      silc_free(entry->userinfo);
    if (entry->id)
      silc_free(entry->id);

    memset(entry, 'F', sizeof(*entry));
    silc_free(entry);

    return TRUE;
  }

  return FALSE;
}

/* Returns all clients matching requested nickname. Number of clients is
   returned to `clients_count'. Caller must free the returned table. */

int silc_idlist_get_clients_by_nickname(SilcIDList id_list, char *nickname,
					char *server, 
					SilcClientEntry **clients,
					uint32 *clients_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  int i;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_find_by_name(id_list->clients, nickname, &list))
    return FALSE;

  *clients = silc_realloc(*clients, 
			  (silc_idcache_list_count(list) + *clients_count) * 
			  sizeof(**clients));

  i = 0;
  silc_idcache_list_first(list, &id_cache);
  (*clients)[i++] = (SilcClientEntry)id_cache->context;

  while (silc_idcache_list_next(list, &id_cache))
    (*clients)[i++] = (SilcClientEntry)id_cache->context;
  
  silc_idcache_list_free(list);
  
  *clients_count += i;

  SILC_LOG_DEBUG(("Found %d clients", *clients_count));

  return TRUE;
}

/* Returns all clients matching requested nickname hash. Number of clients
   is returned to `clients_count'. Caller must free the returned table. */

int silc_idlist_get_clients_by_hash(SilcIDList id_list, char *nickname,
				    SilcHash md5hash,
				    SilcClientEntry **clients,
				    uint32 *clients_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  unsigned char hash[32];
  int i;
  SilcClientID client_id;

  SILC_LOG_DEBUG(("Start"));

  silc_hash_make(md5hash, nickname, strlen(nickname), hash);

  /* As the Client ID is hashed in the ID cache by hashing only the hash
     from the Client ID, we can do a lookup with only the hash not the
     other parts of the ID and get all the clients with that hash, ie.
     with that nickname, as the hash is from the nickname. */
  memset(&client_id, 0, sizeof(client_id));
  memcpy(&client_id.hash, hash, sizeof(client_id.hash));
  if (!silc_idcache_find_by_id(id_list->clients, &client_id, &list))
    return FALSE;

  *clients = silc_realloc(*clients, 
			  (silc_idcache_list_count(list) + *clients_count) * 
			  sizeof(**clients));

  i = 0;
  silc_idcache_list_first(list, &id_cache);
  (*clients)[i++] = (SilcClientEntry)id_cache->context;

  while (silc_idcache_list_next(list, &id_cache))
    (*clients)[i++] = (SilcClientEntry)id_cache->context;
  
  silc_idcache_list_free(list);
  
  *clients_count += i;

  SILC_LOG_DEBUG(("Found %d clients", *clients_count));

  return TRUE;
}

/* Finds client by Client ID */

SilcClientEntry
silc_idlist_find_client_by_id(SilcIDList id_list, SilcClientID *id,
			      bool registered, SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client;

  if (!id)
    return NULL;

  SILC_LOG_DEBUG(("Client ID (%s)", 
		  silc_id_render(id, SILC_ID_CLIENT)));

  /* Do extended search since the normal ID comparison function for
     Client ID's compares only the hash from the Client ID and not the
     entire ID. The silc_hash_client_id_compare compares the entire
     Client ID as we want to find one specific Client ID. */
  if (!silc_idcache_find_by_id_one_ext(id_list->clients, (void *)id, 
				       NULL, NULL, 
				       silc_hash_client_id_compare, NULL,
				       &id_cache))
    return NULL;

  client = (SilcClientEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

  if (client && registered && !client->data.registered)
    return NULL;

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

  /* Do extended search since the normal ID comparison function for
     Client ID's compares only the hash from the Client ID and not the
     entire ID. The silc_hash_client_id_compare compares the entire
     Client ID as we want to find one specific Client ID. */
  if (!silc_idcache_find_by_id_one_ext(id_list->clients, (void *)old_id, 
				       NULL, NULL, 
				       silc_hash_client_id_compare, NULL,
				       &id_cache))
    return NULL;

  client = (SilcClientEntry)id_cache->context;

  /* Remove the old entry and add a new one */

  silc_idcache_del_by_context(id_list->clients, client);

  silc_free(client->id);
  client->id = new_id;

  silc_idcache_add(id_list->clients, client->nickname, client->id, 
		   client, FALSE);

  SILC_LOG_DEBUG(("Replaced"));

  return client;
}

/* Client cache entry destructor that is called when the cache is purged. */

void silc_idlist_client_destructor(SilcIDCache cache,
				   SilcIDCacheEntry entry)
{
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  client = (SilcClientEntry)entry->context;
  if (client) {
    if (client->nickname)
      silc_free(client->nickname);
    if (client->username)
      silc_free(client->username);
    if (client->userinfo)
      silc_free(client->userinfo);
    if (client->id)
      silc_free(client->id);

    memset(client, 'F', sizeof(*client));
    silc_free(client);
  }
}

/******************************************************************************

                          Channel entry functions

******************************************************************************/

/* Add new channel entry. This add the new channel entry to the ID cache
   system and returns the allocated entry or NULL on error. */

SilcChannelEntry
silc_idlist_add_channel(SilcIDList id_list, char *channel_name, int mode,
			SilcChannelID *id, SilcServerEntry router,
			SilcCipher channel_key, SilcHmac hmac)
{
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("Adding new channel entry"));

  channel = silc_calloc(1, sizeof(*channel));
  channel->channel_name = channel_name;
  channel->mode = mode;
  channel->id = id;
  channel->router = router;
  channel->channel_key = channel_key;
  channel->hmac = hmac;
  if (!channel->hmac)
    if (!silc_hmac_alloc("hmac-sha1-96", NULL, &channel->hmac)) {
      silc_free(channel);
      return NULL;
    }

  channel->user_list = silc_hash_table_alloc(3, silc_hash_ptr, NULL, NULL,
					     NULL, NULL, NULL, TRUE);

  if (!silc_idcache_add(id_list->channels, channel->channel_name, 
			(void *)channel->id, (void *)channel, FALSE)) {
    silc_hmac_free(channel->hmac);
    silc_hash_table_free(channel->user_list);
    silc_free(channel);
    return NULL;
  }

  return channel;
}

/* Foreach callbcak to free all users from the channel when deleting a
   channel entry. */

static void silc_idlist_del_channel_foreach(void *key, void *context,
					    void *user_context)
{
  SilcChannelClientEntry chl = (SilcChannelClientEntry)context;

  /* Remove the context from the client's channel hash table as that
     table and channel's user_list hash table share this same context. */
  silc_hash_table_del(chl->client->channels, chl->channel);
  silc_free(chl);
}

/* Free channel entry.  This free's everything. */

int silc_idlist_del_channel(SilcIDList id_list, SilcChannelEntry entry)
{
  SILC_LOG_DEBUG(("Start"));

  if (entry) {
    /* Remove from cache */
    if (entry->id)
      if (!silc_idcache_del_by_id(id_list->channels, (void *)entry->id))
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
    if (entry->cipher)
      silc_free(entry->cipher);
    if (entry->hmac_name)
      silc_free(entry->hmac_name);
    if (entry->rekey)
      silc_free(entry->rekey);

    /* Free all client entrys from the users list. The silc_hash_table_free
       will free all the entries so they are not freed at the foreach 
       callback. */
    silc_hash_table_foreach(entry->user_list, silc_idlist_del_channel_foreach,
			    NULL);
    silc_hash_table_free(entry->user_list);

    memset(entry, 'F', sizeof(*entry));
    silc_free(entry);
    return TRUE;
  }

  return FALSE;
}

/* Finds channel by channel name. Channel names are unique and they
   are not case-sensitive. */

SilcChannelEntry
silc_idlist_find_channel_by_name(SilcIDList id_list, char *name,
				 SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;

  SILC_LOG_DEBUG(("Channel by name"));

  if (!silc_idcache_find_by_name_one(id_list->channels, name, &id_cache))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return id_cache->context;
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

  if (!silc_idcache_find_by_id_one(id_list->channels, (void *)id, &id_cache))
    return NULL;

  channel = (SilcChannelEntry)id_cache->context;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return channel;
}

/* Replaces old Channel ID with new one. This is done when router forces
   normal server to change Channel ID. */

SilcChannelEntry
silc_idlist_replace_channel_id(SilcIDList id_list, SilcChannelID *old_id,
			       SilcChannelID *new_id)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Channel ID"));

  if (!silc_idcache_find_by_id_one(id_list->channels, (void *)old_id, 
				   &id_cache))
    return NULL;

  channel = (SilcChannelEntry)id_cache->context;

  /* Remove the old entry and add a new one */

  silc_idcache_del_by_id(id_list->channels, (void *)channel->id);

  silc_free(channel->id);
  channel->id = new_id;

  silc_idcache_add(id_list->channels, channel->channel_name, channel->id, 
		   channel, FALSE);

  SILC_LOG_DEBUG(("Replaced"));

  return channel;
}

/* Returns channels from the ID list. If the `channel_id' is NULL then
   all channels are returned. */

SilcChannelEntry *
silc_idlist_get_channels(SilcIDList id_list, SilcChannelID *channel_id,
			 uint32 *channels_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry *channels = NULL;
  int i = 0;

  SILC_LOG_DEBUG(("Start"));

  if (!channel_id) {
    if (!silc_idcache_get_all(id_list->channels, &list))
      return NULL;

    channels = silc_calloc(silc_idcache_list_count(list), sizeof(*channels));
    
    i = 0;
    silc_idcache_list_first(list, &id_cache);
    channels[i++] = (SilcChannelEntry)id_cache->context;
    
    while (silc_idcache_list_next(list, &id_cache))
      channels[i++] = (SilcChannelEntry)id_cache->context;
    
    silc_idcache_list_free(list);
  } else {
    if (!silc_idcache_find_by_id_one(id_list->channels, channel_id, &id_cache))
      return NULL;

    i = 1;
    channels = silc_calloc(1, sizeof(*channels));
    channels[0] = (SilcChannelEntry)id_cache->context;
  }

  if (channels_count)
    *channels_count = i;

  return channels;
}
