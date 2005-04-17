/*

  idlist.c

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

#include "serverincludes.h"
#include "idlist.h"
#include "server_internal.h"

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
  data->hmac_send = idata->hmac_send;
  data->hmac_receive = idata->hmac_receive;
  data->psn_send = idata->psn_send;
  data->psn_receive = idata->psn_receive;
  data->hash = idata->hash;
  data->public_key = idata->public_key;
  memcpy(data->fingerprint, idata->fingerprint, sizeof(data->fingerprint));
  data->rekey = idata->rekey;
  data->last_receive = idata->last_receive;
  data->last_sent = idata->last_sent;
  data->status = idata->status;

  data->created = time(0);	/* Update creation time */
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
  if (idata->hmac_send)
    silc_hmac_free(idata->hmac_send);
  if (idata->hmac_receive)
    silc_hmac_free(idata->hmac_receive);
  if (idata->hash)
    silc_hash_free(idata->hash);
  if (idata->public_key)
    silc_pkcs_public_key_free(idata->public_key);

  idata->send_key = NULL;
  idata->receive_key = NULL;
  idata->rekey = NULL;
  idata->hmac_send = NULL;
  idata->hmac_receive = NULL;
  idata->hash = NULL;
  idata->public_key = NULL;
}

/* Purges ID cache */

SILC_TASK_CALLBACK_GLOBAL(silc_idlist_purge)
{
  SilcServer server = app_context;
  SilcIDListPurge i = (SilcIDListPurge)context;

  SILC_LOG_DEBUG(("Purging cache"));

  silc_idcache_purge(i->cache);
  silc_schedule_task_add(server->schedule, 0, silc_idlist_purge,
			 (void *)i, i->timeout, 0,
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
  char *server_namec = NULL;

  SILC_LOG_DEBUG(("Adding new server entry"));

  /* Normalize name.  This is cached, original is in server context.  */
  if (server_name) {
    server_namec = silc_identifier_check(server_name, strlen(server_name),
					 SILC_STRING_UTF8, 256, NULL);
    if (!server_namec)
      return NULL;
  }

  server = silc_calloc(1, sizeof(*server));
  server->server_name = server_name;
  server->server_type = server_type;
  server->id = id;
  server->router = router;
  server->connection = connection;

  if (!silc_idcache_add(id_list->servers, server_namec,
			(void *)server->id, (void *)server, 0, NULL)) {
    silc_free(server);
    silc_free(server_namec);
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

  if (server && registered &&
      !(server->data.status & SILC_IDLIST_STATUS_REGISTERED))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return server;
}

/* Find server by name.  The 'name' must be normalized already. */

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

  if (server && registered &&
      !(server->data.status & SILC_IDLIST_STATUS_REGISTERED))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

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
	&& server->id->port == SILC_SWAB_16(port))
      break;

    id_cache = NULL;
    server = NULL;

    if (!silc_idcache_list_next(list, &id_cache))
      break;
  }

  silc_idcache_list_free(list);

  if (server && registered &&
      !(server->data.status & SILC_IDLIST_STATUS_REGISTERED))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

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
  char *name;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Server ID"));

  if (!silc_idcache_find_by_id_one(id_list->servers, (void *)old_id,
				   &id_cache))
    return NULL;

  server = (SilcServerEntry)id_cache->context;
  name = strdup(id_cache->name);

  /* Remove the old entry and add a new one */

  silc_idcache_del_by_id(id_list->servers, (void *)server->id);

  silc_free(server->id);
  server->id = new_id;

  silc_idcache_add(id_list->servers, name, server->id, server, 0, NULL);

  SILC_LOG_DEBUG(("Found"));

  return server;
}

/* Removes and free's server entry from ID list */

int silc_idlist_del_server(SilcIDList id_list, SilcServerEntry entry)
{
  if (entry) {
    /* Remove from cache */
    if (!silc_idcache_del_by_context(id_list->servers, entry)) {
      SILC_LOG_DEBUG(("Unknown server, did not delete"));
      return FALSE;
    }

    SILC_LOG_DEBUG(("Deleting server %s id %s", entry->server_name ?
		    entry->server_name : "",
		    entry->id ?
		    silc_id_render(entry->id, SILC_ID_SERVER) : ""));

    /* Free data */
    silc_free(entry->server_name);
    silc_free(entry->id);
    silc_free(entry->server_info);

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
		       SilcServerEntry router, void *connection,
		       int expire)
{
  SilcClientEntry client;
  char *nicknamec = NULL;

  SILC_LOG_DEBUG(("Adding new client entry"));

  /* Normalize name.  This is cached, original is in client context.  */
  if (nickname) {
    nicknamec = silc_identifier_check(nickname, strlen(nickname),
				      SILC_STRING_UTF8, 128, NULL);
    if (!nicknamec)
      return NULL;
  }

  /* Check username. */
  if (username) {
    char *u = NULL, *h = NULL;
    silc_parse_userfqdn(username, &u, &h);
    if (!u)
      return NULL;
    if (!silc_identifier_verify(u, strlen(u), SILC_STRING_UTF8, 128)) {
      silc_free(u);
      silc_free(h);
      return NULL;
    }
    if (h && !silc_identifier_verify(h, strlen(h), SILC_STRING_UTF8, 256)) {
      silc_free(u);
      silc_free(h);
      return NULL;
    }
  }

  client = silc_calloc(1, sizeof(*client));
  client->nickname = nickname;
  client->username = username ? strdup(username) : NULL;
  client->userinfo = userinfo;
  client->id = id;
  client->router = router;
  client->connection = connection;
  client->channels = silc_hash_table_alloc(3, silc_hash_ptr, NULL,
					   NULL, NULL, NULL, NULL, TRUE);

  if (!silc_idcache_add(id_list->clients, nicknamec, (void *)client->id,
			(void *)client, expire, NULL)) {
    silc_hash_table_free(client->channels);
    silc_free(client);
    silc_free(nicknamec);
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
    /* Remove from cache. Destructor callback deletes stuff. */
    if (!silc_idcache_del_by_context(id_list->clients, entry)) {
      SILC_LOG_DEBUG(("Unknown client, did not delete"));
      return FALSE;
    }

    assert(!silc_hash_table_count(entry->channels));

    silc_free(entry->nickname);
    silc_free(entry->servername);
    silc_free(entry->username);
    silc_free(entry->userinfo);
    silc_free(entry->id);
    silc_free(entry->attrs);
    silc_hash_table_free(entry->channels);

    memset(entry, 'F', sizeof(*entry));
    silc_free(entry);

    return TRUE;
  }

  return FALSE;
}

/* ID Cache destructor */

void silc_idlist_client_destructor(SilcIDCache cache,
				   SilcIDCacheEntry entry)
{
  SilcClientEntry client;

  client = (SilcClientEntry)entry->context;
  if (client) {
    assert(!silc_hash_table_count(client->channels));
    silc_free(client->nickname);
    silc_free(client->servername);
    silc_free(client->username);
    silc_free(client->userinfo);
    silc_free(client->id);
    silc_free(client->attrs);
    silc_hash_table_free(client->channels);

    memset(client, 'A', sizeof(*client));
    silc_free(client);
  }
}

/* Returns all clients matching requested nickname. Number of clients is
   returned to `clients_count'. Caller must free the returned table.
   The 'nickname' must be normalized already. */

int silc_idlist_get_clients_by_nickname(SilcIDList id_list, char *nickname,
					char *server,
					SilcClientEntry **clients,
					SilcUInt32 *clients_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_find_by_name(id_list->clients, nickname, &list))
    return FALSE;

  *clients = silc_realloc(*clients,
			  (silc_idcache_list_count(list) + *clients_count) *
			  sizeof(**clients));

  silc_idcache_list_first(list, &id_cache);
  (*clients)[(*clients_count)++] = (SilcClientEntry)id_cache->context;

  while (silc_idcache_list_next(list, &id_cache))
    (*clients)[(*clients_count)++] = (SilcClientEntry)id_cache->context;
  silc_idcache_list_free(list);

  SILC_LOG_DEBUG(("Found total %d clients", *clients_count));

  return TRUE;
}

/* Returns all clients matching requested nickname hash. Number of clients
   is returned to `clients_count'. Caller must free the returned table.
   The 'nickname' must be normalized already. */

int silc_idlist_get_clients_by_hash(SilcIDList id_list, char *nickname,
				    SilcHash md5hash,
				    SilcClientEntry **clients,
				    SilcUInt32 *clients_count)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  unsigned char hash[32];
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

  silc_idcache_list_first(list, &id_cache);
  (*clients)[(*clients_count)++] = (SilcClientEntry)id_cache->context;

  while (silc_idcache_list_next(list, &id_cache))
    (*clients)[(*clients_count)++] = (SilcClientEntry)id_cache->context;

  silc_idcache_list_free(list);

  SILC_LOG_DEBUG(("Found total %d clients", *clients_count));

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

  if (client && registered &&
      !(client->data.status & SILC_IDLIST_STATUS_REGISTERED))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  return client;
}

/* Replaces old Client ID with new one */

SilcClientEntry
silc_idlist_replace_client_id(SilcServer server,
			      SilcIDList id_list, SilcClientID *old_id,
			      SilcClientID *new_id, const char *nickname)
{
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client;
  char *nicknamec = NULL;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Client ID"));

  /* Normalize name. This is cached, original is in client context.  */
  if (nickname) {
    nicknamec = silc_identifier_check(nickname, strlen(nickname),
				      SILC_STRING_UTF8, 128, NULL);
    if (!nicknamec)
      return NULL;
  }

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

  if (!silc_idcache_del_by_context(id_list->clients, client))
    return NULL;

  /* Check if anyone is watching old nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, nickname,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

  silc_free(client->id);
  silc_free(client->nickname);
  client->id = new_id;
  client->nickname = nickname ? strdup(nickname) : NULL;

  /* Check if anyone is watching new nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, nickname,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

  if (!silc_idcache_add(id_list->clients, nicknamec, client->id,
			client, 0, NULL))
    return NULL;

  SILC_LOG_DEBUG(("Replaced"));

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
			SilcCipher channel_key, SilcHmac hmac,
			int expire)
{
  SilcChannelEntry channel;
  char *channel_namec = NULL;

  SILC_LOG_DEBUG(("Adding new channel %s", channel_name));

  /* Normalize name.  This is cached, original is in client context.  */
  if (channel_name) {
    channel_namec = silc_channel_name_check(channel_name, strlen(channel_name),
					    SILC_STRING_UTF8, 256, NULL);
    if (!channel_namec)
      return NULL;
  }

  channel = silc_calloc(1, sizeof(*channel));
  channel->channel_name = channel_name;
  channel->mode = mode;
  channel->id = id;
  channel->router = router;
  channel->channel_key = channel_key;
  channel->hmac = hmac;
  channel->created = channel->updated = time(0);
  if (!channel->hmac)
    if (!silc_hmac_alloc(SILC_DEFAULT_HMAC, NULL, &channel->hmac)) {
      silc_free(channel);
      return NULL;
    }

  channel->user_list = silc_hash_table_alloc(3, silc_hash_ptr, NULL, NULL,
					     NULL, NULL, NULL, TRUE);

  if (!silc_idcache_add(id_list->channels, channel_namec,
			(void *)channel->id, (void *)channel, expire, NULL)) {
    silc_hmac_free(channel->hmac);
    silc_hash_table_free(channel->user_list);
    silc_free(channel);
    silc_free(channel_namec);
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

  SILC_LOG_DEBUG(("Removing client %s from channel %s",
		  chl->client->nickname ? chl->client->nickname :
		  (unsigned char *)"", chl->channel->channel_name));

  /* Remove the context from the client's channel hash table as that
     table and channel's user_list hash table share this same context. */
  silc_hash_table_del(chl->client->channels, chl->channel);
  silc_free(chl);
}

/* Free channel entry.  This free's everything. */

int silc_idlist_del_channel(SilcIDList id_list, SilcChannelEntry entry)
{
  if (entry) {
    /* Remove from cache */
    if (!silc_idcache_del_by_context(id_list->channels, entry)) {
      SILC_LOG_DEBUG(("Unknown channel, did not delete"));
      return FALSE;
    }

    SILC_LOG_DEBUG(("Deleting channel %s", entry->channel_name));

    /* Free all client entrys from the users list. The silc_hash_table_free
       will free all the entries so they are not freed at the foreach
       callback. */
    silc_hash_table_foreach(entry->user_list, silc_idlist_del_channel_foreach,
			    NULL);
    silc_hash_table_free(entry->user_list);

    /* Free data */
    silc_free(entry->channel_name);
    silc_free(entry->id);
    silc_free(entry->topic);

    if (entry->invite_list)
      silc_hash_table_free(entry->invite_list);
    if (entry->ban_list)
      silc_hash_table_free(entry->ban_list);

    if (entry->channel_key)
      silc_cipher_free(entry->channel_key);
    if (entry->key) {
      memset(entry->key, 0, entry->key_len / 8);
      silc_free(entry->key);
    }
    silc_free(entry->cipher);
    if (entry->hmac)
      silc_hmac_free(entry->hmac);
    silc_free(entry->hmac_name);
    silc_free(entry->rekey);
    if (entry->founder_key)
      silc_pkcs_public_key_free(entry->founder_key);
    if (entry->channel_pubkeys)
      silc_hash_table_free(entry->channel_pubkeys);

    memset(entry, 'F', sizeof(*entry));
    silc_free(entry);
    return TRUE;
  }

  return FALSE;
}

/* Finds channel by channel name. Channel names are unique and they
   are not case-sensitive.  The 'name' must be normalized already. */

SilcChannelEntry
silc_idlist_find_channel_by_name(SilcIDList id_list, char *name,
				 SilcIDCacheEntry *ret_entry)
{
  SilcIDCacheEntry id_cache = NULL;

  SILC_LOG_DEBUG(("Channel by name %s", name));

  if (!silc_idcache_find_by_name_one(id_list->channels, name, &id_cache))
    return NULL;

  if (ret_entry)
    *ret_entry = id_cache;

  SILC_LOG_DEBUG(("Found"));

  /* Touch channel */
  ((SilcChannelEntry)id_cache->context)->updated = time(NULL);

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

  /* Touch channel */
  channel->updated = time(NULL);

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
  char *name;

  if (!old_id || !new_id)
    return NULL;

  SILC_LOG_DEBUG(("Replacing Channel ID"));

  if (!silc_idcache_find_by_id_one(id_list->channels, (void *)old_id,
				   &id_cache))
    return NULL;

  channel = (SilcChannelEntry)id_cache->context;
  name = strdup(id_cache->name);

  /* Remove the old entry and add a new one */

  silc_idcache_del_by_id(id_list->channels, (void *)channel->id);

  silc_free(channel->id);
  channel->id = new_id;

  silc_idcache_add(id_list->channels, name, channel->id, channel, 0, NULL);

  SILC_LOG_DEBUG(("Replaced"));

  /* Touch channel */
  channel->updated = time(NULL);

  return channel;
}

/* Returns channels from the ID list. If the `channel_id' is NULL then
   all channels are returned. */

SilcChannelEntry *
silc_idlist_get_channels(SilcIDList id_list, SilcChannelID *channel_id,
			 SilcUInt32 *channels_count)
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
