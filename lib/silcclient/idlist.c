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

/* Finds client entry from cache by nickname. If the entry is not found
   from the cache this function queries it from the server. If `server'
   and `num' are defined as well thisk checks the match from multiple
   cache entries thus providing support for multiple same nickname
   handling. This also ignores case-sensitivity. */

SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       char *nickname,
				       char *server,
				       unsigned int num)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list = NULL;
  SilcClientEntry entry = NULL;

  /* Find ID from cache */
  if (!silc_idcache_find_by_data_loose(conn->client_cache, nickname, &list)) {
    SilcClientCommandContext ctx;
    char ident[512];
    
  identify:

    SILC_LOG_DEBUG(("Requesting Client ID from server"));

    /* No ID found. Do query from the server. The query is done by 
       sending simple IDENTIFY command to the server. */
    ctx = silc_calloc(1, sizeof(*ctx));
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

/* Finds client entry from cache by Client ID. If the entry is not found
   from the cache this function can query it from the server. */

SilcClientEntry silc_idlist_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id,
					     int query)
{
  SilcIDCacheEntry id_cache;

  SILC_LOG_DEBUG(("Finding client by ID (%s)", 
		  silc_id_render(client_id, SILC_ID_CLIENT)));

  /* Find ID from cache */
  if (!silc_idcache_find_by_id_one(conn->client_cache, client_id, 
				   SILC_ID_CLIENT, &id_cache)) {
    if (!query) {
      return NULL;
    } else {
      SilcBuffer idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
      silc_client_send_command(client, conn, SILC_COMMAND_WHOIS, 1,
			       3, idp->data, idp->len);
      return NULL;
    }
  }

  return (SilcClientEntry)id_cache->context;
}

/* Finds channel entry from ID cache by channel name. */

SilcChannelEntry silc_idlist_get_channel(SilcClient client,
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
