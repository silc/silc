/*

  idlist.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

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

#include "clientlibincludes.h"

typedef struct {
  SilcClientCommandContext cmd;
  SilcGetClientCallback completion;
  char *nickname;
  char *server;
  void *context;
  int found;
} *GetClientInternal;

SILC_CLIENT_CMD_FUNC(get_client_callback)
{
  GetClientInternal i = (GetClientInternal)context;
  SilcClientEntry *clients;
  unsigned int clients_count;

  /* Get the clients */
  clients = silc_client_get_clients_local(i->cmd->client, i->cmd->conn,
					  i->nickname, i->server,
					  &clients_count);
  if (clients) {
    i->completion(i->cmd->client, i->cmd->conn, clients, 
		  clients_count, i->context);
    i->found = TRUE;
    silc_free(clients);
  }
}

static void silc_client_get_client_destructor(void *context)
{
  GetClientInternal i = (GetClientInternal)context;

  if (i->found == FALSE)
    i->completion(i->cmd->client, i->cmd->conn, NULL, 0, i->context);

  silc_client_command_free(i->cmd);
  if (i->nickname)
    silc_free(i->nickname);
  if (i->server)
    silc_free(i->server);
  silc_free(i);
}

/* Finds client entry or entries by the `nickname' and `server'. The 
   completion callback will be called when the client entries has been found.

   Note: this function is always asynchronous and resolves the client
   information from the server. Thus, if you already know the client
   information then use the silc_client_get_client_by_id function to
   get the client entry since this function may be very slow and should
   be used only to initially get the client entries. */

void silc_client_get_clients(SilcClient client,
			     SilcClientConnection conn,
			     char *nickname,
			     char *server,
			     SilcGetClientCallback completion,
			     void *context)
{
  char ident[512];
  SilcClientCommandContext ctx;
  GetClientInternal i = silc_calloc(1, sizeof(*i));
      
  /* No ID found. Do query from the server. The query is done by 
     sending simple IDENTIFY command to the server. */
  ctx = silc_client_command_alloc();
  ctx->client = client;
  ctx->conn = conn;
  ctx->command = silc_client_command_find("IDENTIFY");
  memset(ident, 0, sizeof(ident));
  snprintf(ident, sizeof(ident), "IDENTIFY %s", nickname);
  silc_parse_command_line(ident, &ctx->argv, &ctx->argv_lens, 
			  &ctx->argv_types, &ctx->argc, 2);
  ctx->command->cb(ctx);
      
  i->cmd = ctx;
  i->nickname = nickname ? strdup(nickname) : NULL;
  i->server = server ? strdup(server) : NULL;
  i->completion = completion;
  i->context = context;

  /* Add pending callback */
  silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
			      ++conn->cmd_ident, 
			      silc_client_get_client_destructor,
			      silc_client_command_get_client_callback, 
			      (void *)i);
}

/* Same as above function but does not resolve anything from the server.
   This checks local cache and returns all clients from the cache. */

SilcClientEntry *silc_client_get_clients_local(SilcClient client,
					       SilcClientConnection conn,
					       char *nickname,
					       char *server,
					       unsigned int *clients_count)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list = NULL;
  SilcClientEntry entry, *clients;
  int i = 0;

  /* Find ID from cache */
  if (!silc_idcache_find_by_data_loose(conn->client_cache, nickname, &list))
    return NULL;

  if (!silc_idcache_list_count(list)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  clients = silc_calloc(silc_idcache_list_count(list), sizeof(*clients));
  *clients_count = silc_idcache_list_count(list);

  if (!server) {
    /* Take all without any further checking */
    silc_idcache_list_first(list, &id_cache);
    while (id_cache) {
      clients[i++] = id_cache->context;
      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
  } else {
    /* Check multiple cache entries for match */
    silc_idcache_list_first(list, &id_cache);
    while (id_cache) {
      entry = (SilcClientEntry)id_cache->context;
      
      if (entry->server && 
	  strncasecmp(server, entry->server, strlen(server))) {
	if (!silc_idcache_list_next(list, &id_cache)) {
	  break;
	} else {
	  continue;
	}
      }
      
      clients[i++] = id_cache->context;
      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
  }

  if (list)
    silc_idcache_list_free(list);

  return clients;
}

/* The old style function to find client entry. This is used by the
   library internally. If `query' is TRUE then the client information is
   requested by the server. The pending command callback must be set
   by the caller. */

SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       char *nickname,
				       char *server,
				       unsigned int num,
				       int query)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list = NULL;
  SilcClientEntry entry = NULL;

  /* Find ID from cache */
  if (!silc_idcache_find_by_data_loose(conn->client_cache, nickname, &list)) {
  identify:

    if (query) {
      char ident[512];
      SilcClientCommandContext ctx;
      
      SILC_LOG_DEBUG(("Requesting Client ID from server"));
      
      /* No ID found. Do query from the server. The query is done by 
	 sending simple IDENTIFY command to the server. */
      ctx = silc_client_command_alloc();
      ctx->client = client;
      ctx->conn = conn;
      ctx->command = silc_client_command_find("IDENTIFY");
      memset(ident, 0, sizeof(ident));
      snprintf(ident, sizeof(ident), "IDENTIFY %s", nickname);
      silc_parse_command_line(ident, &ctx->argv, &ctx->argv_lens, 
			      &ctx->argv_types, &ctx->argc, 2);
      ctx->command->cb(ctx);
      
      if (list)
	silc_idcache_list_free(list);

      return NULL;
    }
    return NULL;
  }

  if (!server && !num) {
    /* Take first found cache entry */
    if (!silc_idcache_list_first(list, &id_cache))
      goto identify;

    entry = (SilcClientEntry)id_cache->context;
  } else {
    /* Check multiple cache entries for match */
    silc_idcache_list_first(list, &id_cache);
    entry = (SilcClientEntry)id_cache->context;
    
    while (entry) {
      if (server && entry->server && 
	  !strncasecmp(server, entry->server, strlen(server)))
	break;
      
      if (num && entry->num == num)
	break;

      if (!silc_idcache_list_next(list, &id_cache)) {
	entry = NULL;
	break;
      }

      entry = (SilcClientEntry)id_cache->context;
    }

    /* If match weren't found, request it */
    if (!entry)
      goto identify;
  }

  if (list)
    silc_idcache_list_free(list);

  return entry;
}

/* Finds entry for client by the client's ID. Returns the entry or NULL
   if the entry was not found. */

SilcClientEntry silc_client_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id)
{
  SilcIDCacheEntry id_cache;

  SILC_LOG_DEBUG(("Finding client by ID (%s)", 
		  silc_id_render(client_id, SILC_ID_CLIENT)));

  /* Find ID from cache */
  if (!silc_idcache_find_by_id_one(conn->client_cache, client_id, 
				   SILC_ID_CLIENT, &id_cache))
    return NULL;

  SILC_LOG_DEBUG(("Found"));

  return (SilcClientEntry)id_cache->context;
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcClientID *client_id;
  SilcGetClientCallback completion;
  void *context;
  int found;
} *GetClientByIDInternal;

SILC_CLIENT_CMD_FUNC(get_client_by_id_callback)
{
  GetClientByIDInternal i = (GetClientByIDInternal)context;
  SilcClientEntry entry;

  /* Get the client */
  entry = silc_client_get_client_by_id(i->client, i->conn,
				       i->client_id);
  if (entry) {
    i->completion(i->client, i->conn, &entry, 1, i->context);
    i->found = TRUE;
  }
}

static void silc_client_get_client_by_id_destructor(void *context)
{
  GetClientByIDInternal i = (GetClientByIDInternal)context;

  if (i->found == FALSE)
    i->completion(i->client, i->conn, NULL, 0, i->context);

  if (i->client_id)
    silc_free(i->client_id);
  silc_free(i);
}

/* Same as above but will always resolve the information from the server.
   Use this only if you know that you don't have the entry and the only
   thing you know about the client is its ID. */

void silc_client_get_client_by_id_resolve(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientID *client_id,
					  SilcGetClientCallback completion,
					  void *context)
{
  SilcBuffer idp;
  GetClientByIDInternal i = silc_calloc(1, sizeof(*i));

  idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
  silc_client_send_command(client, conn, SILC_COMMAND_WHOIS, 
			   ++conn->cmd_ident,
			   1, 3, idp->data, idp->len);
  silc_buffer_free(idp);

  i->client = client;
  i->conn = conn;
  i->client_id = silc_id_dup(client_id, SILC_ID_CLIENT);
  i->completion = completion;
  i->context = context;
      
  /* Add pending callback */
  silc_client_command_pending(conn, SILC_COMMAND_WHOIS, 
			      ++conn->cmd_ident, 
			      silc_client_get_client_by_id_destructor,
			      silc_client_command_get_client_by_id_callback, 
			      (void *)i);
}

/* Finds entry for channel by the channel name. Returns the entry or NULL
   if the entry was not found. It is found only if the client is joined
   to the channel. */

SilcChannelEntry silc_client_get_channel(SilcClient client,
					 SilcClientConnection conn,
					 char *channel)
{
  SilcIDCacheEntry id_cache;
  SilcChannelEntry entry;

  if (!silc_idcache_find_by_data_one(conn->channel_cache, channel, &id_cache))
    return NULL;

  entry = (SilcChannelEntry)id_cache->context;

  return entry;
}
