/*

  server_util.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

/* Removes the client from channels and possibly removes the channels
   as well.  After removing those channels that exist, their channel
   keys are regnerated. This is called only by the function
   silc_server_remove_clients_by_server. */

static void silc_server_remove_clients_channels(SilcServer server, 
						SilcSocketConnection sock,
						SilcClientEntry client,
						SilcHashTable channels)
{
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer clidp;

  SILC_LOG_DEBUG(("Start"));

  if (!client || !client->id)
    return;

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    /* Remove channel from client's channel list */
    silc_hash_table_del(client->channels, channel);

    /* Remove channel if there is no users anymore */
    if (server->server_type == SILC_ROUTER &&
	silc_hash_table_count(channel->user_list) < 2) {

      if (silc_hash_table_find(channels, channel, NULL, NULL))
	silc_hash_table_del(channels, channel);

      if (channel->rekey)
	silc_schedule_task_del_by_context(server->schedule, channel->rekey);

      if (!silc_idlist_del_channel(server->local_list, channel))
	silc_idlist_del_channel(server->global_list, channel);
      server->stat.my_channels--;
      continue;
    }

    /* Remove client from channel's client list */
    silc_hash_table_del(channel->user_list, chl->client);

    /* If there is no global users on the channel anymore mark the channel
       as local channel. Do not check if the removed client is local client. */
    if (server->server_type != SILC_ROUTER && channel->global_users && 
	chl->client->router && !silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    silc_free(chl);
    server->stat.my_chanclients--;

    /* If there is not at least one local user on the channel then we don't
       need the channel entry anymore, we can remove it safely. */
    if (server->server_type != SILC_ROUTER &&
	!silc_server_channel_has_local(channel)) {

      if (silc_hash_table_find(channels, channel, NULL, NULL))
	silc_hash_table_del(channels, channel);

      if (channel->rekey)
	silc_schedule_task_del_by_context(server->schedule, channel->rekey);

      if (channel->founder_key) {
	/* The founder auth data exists, do not remove the channel entry */
	SilcChannelClientEntry chl2;
	SilcHashTableList htl2;

	channel->id = NULL;

	silc_hash_table_list(channel->user_list, &htl2);
	while (silc_hash_table_get(&htl2, NULL, (void *)&chl2)) {
	  silc_hash_table_del(chl2->client->channels, channel);
	  silc_hash_table_del(channel->user_list, chl2->client);
	  silc_free(chl2);
	}
	continue;
      }

      /* Remove the channel entry */
      if (!silc_idlist_del_channel(server->local_list, channel))
	silc_idlist_del_channel(server->global_list, channel);
      server->stat.my_channels--;
      continue;
    }

    /* Add the channel to the the channels list to regenerate the 
       channel key */
    if (!silc_hash_table_find(channels, channel, NULL, NULL))
      silc_hash_table_add(channels, channel, channel);
  }

  silc_buffer_free(clidp);
}

/* This function is used to remove all client entries by the server `entry'.
   This is called when the connection is lost to the server. In this case
   we must invalidate all the client entries owned by the server `entry'. 
   If the `server_signoff' is TRUE then the SERVER_SIGNOFF notify is
   distributed to our local clients. */

bool silc_server_remove_clients_by_server(SilcServer server, 
					  SilcServerEntry entry,
					  bool server_signoff)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  SilcBuffer idp;
  SilcClientEntry *clients = NULL;
  uint32 clients_c = 0;
  unsigned char **argv = NULL;
  uint32 *argv_lens = NULL, *argv_types = NULL, argc = 0;
  SilcHashTableList htl;
  SilcChannelEntry channel;
  SilcHashTable channels;
  int i;

  SILC_LOG_DEBUG(("Start"));

  /* Allocate the hash table that holds the channels that require
     channel key re-generation after we've removed this server's clients
     from the channels. */
  channels = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL, NULL,
				   NULL, NULL, TRUE);

  if (server_signoff) {
    idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
    argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
    argv_lens = silc_realloc(argv_lens,  sizeof(*argv_lens) * (argc + 1));
    argv_types = silc_realloc(argv_types, sizeof(*argv_types) * (argc + 1));
    argv[argc] = silc_calloc(idp->len, sizeof(*argv[0]));
    memcpy(argv[argc], idp->data, idp->len);
    argv_lens[argc] = idp->len;
    argv_types[argc] = argc + 1;
    argc++;
    silc_buffer_free(idp);
  }

  if (silc_idcache_get_all(server->local_list->clients, &list)) {

    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (client->router != entry) {
	  if (server_signoff && client->connection) {
	    clients = silc_realloc(clients, 
				   sizeof(*clients) * (clients_c + 1));
	    clients[clients_c] = client;
	    clients_c++;
	  }

	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (server_signoff) {
	  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
	  argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
	  argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) *
				   (argc + 1));
	  argv_types = silc_realloc(argv_types, sizeof(*argv_types) *
				    (argc + 1));
	  argv[argc] = silc_calloc(idp->len, sizeof(*argv[0]));
	  memcpy(argv[argc], idp->data, idp->len);
	  argv_lens[argc] = idp->len;
	  argv_types[argc] = argc + 1;
	  argc++;
	  silc_buffer_free(idp);
	}

	/* Remove the client entry */
	silc_server_remove_clients_channels(server, NULL, client, channels);
	silc_idlist_del_client(server->local_list, client);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
  
  if (silc_idcache_get_all(server->global_list->clients, &list)) {

    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}
	
	if (client->router != entry) {
	  if (server_signoff && client->connection) {
	    clients = silc_realloc(clients, 
				   sizeof(*clients) * (clients_c + 1));
	    clients[clients_c] = client;
	    clients_c++;
	  }

	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (server_signoff) {
	  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
	  argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
	  argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) *
				   (argc + 1));
	  argv_types = silc_realloc(argv_types, sizeof(*argv_types) *
				    (argc + 1));
	  argv[argc] = silc_calloc(idp->len, sizeof(*argv[0]));
	  memcpy(argv[argc], idp->data, idp->len);
	  argv_lens[argc] = idp->len;
	  argv_types[argc] = argc + 1;
	  argc++;
	  silc_buffer_free(idp);
	}

	/* Remove the client entry */
	silc_server_remove_clients_channels(server, NULL, client, channels);
	silc_idlist_del_client(server->global_list, client);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  /* Send the SERVER_SIGNOFF notify */
  if (server_signoff) {
    SilcBuffer args;

    /* Send SERVER_SIGNOFF notify to our primary router */
    if (!server->standalone && server->router &&
	server->router != entry) {
      args = silc_argument_payload_encode(1, argv, argv_lens,
					  argv_types);
      silc_server_send_notify_args(server, 
				   server->router->connection,
				   server->server_type == SILC_SERVER ? 
				   FALSE : TRUE, 
				   SILC_NOTIFY_TYPE_SERVER_SIGNOFF,
				   argc, args);
      silc_buffer_free(args);
    }

    args = silc_argument_payload_encode(argc, argv, argv_lens,
					argv_types);
    /* Send to local clients */
    for (i = 0; i < clients_c; i++) {
      silc_server_send_notify_args(server, clients[i]->connection,
				   FALSE, SILC_NOTIFY_TYPE_SERVER_SIGNOFF,
				   argc, args);
    }

    silc_free(clients);
    silc_buffer_free(args);
    for (i = 0; i < argc; i++)
      silc_free(argv[i]);
    silc_free(argv);
    silc_free(argv_lens);
    silc_free(argv_types);
  }

  /* We must now re-generate the channel key for all channels that had
     this server's client(s) on the channel. As they left the channel we
     must re-generate the channel key. */
  silc_hash_table_list(channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&channel)) {
    if (!silc_server_create_channel_key(server, channel, 0))
      return FALSE;

    /* Do not send the channel key if private channel key mode is set */
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY)
      continue;

    silc_server_send_channel_key(server, NULL, channel, 
				 server->server_type == SILC_ROUTER ? 
				 FALSE : !server->standalone);
  }
  silc_hash_table_free(channels);

  return TRUE;
}

static SilcServerEntry
silc_server_update_clients_by_real_server(SilcServer server,
					  SilcClientEntry client)
{
  SilcServerEntry server_entry;
  SilcIDCacheEntry id_cache = NULL;
  SilcIDCacheList list;

  if (!silc_idcache_get_all(server->local_list->servers, &list))
    return NULL;

  if (silc_idcache_list_first(list, &id_cache)) {
    while (id_cache) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (SILC_ID_COMPARE(server_entry->id, client->id, 
			  client->id->ip.data_len)) {
	SILC_LOG_DEBUG(("Found"));
	silc_idcache_list_free(list);
	return server_entry;
      }

      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
  }

  silc_idcache_list_free(list);

  return NULL;
}

/* Updates the clients that are originated from the `from' to be originated
   from the `to'. If the `resolve_real_server' is TRUE then this will
   attempt to figure out which clients really are originated from the
   `from' and which are originated from a server that we have connection
   to, when we've acting as backup router. If it is FALSE the `to' will
   be the new source. This function also removes the clients that are
   *really* originated from `from' if `remove_from' is TRUE. These are
   clients that the `from' owns, and not just clients that are behind
   the `from'. */

void silc_server_update_clients_by_server(SilcServer server, 
					  SilcServerEntry from,
					  SilcServerEntry to,
					  bool resolve_real_server,
					  bool remove_from)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (silc_idcache_get_all(server->local_list->clients, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (client->router == from) {
	  /* Skip clients that are *really* owned by the `from' */
	  if (SILC_ID_COMPARE(from->id, client->id, 
			      client->id->ip.data_len)) {
	    SILC_LOG_DEBUG(("Found really owned client, skip it"));
	    if (!silc_idcache_list_next(list, &id_cache))
	      break;
	    else
	      continue;
	  }

	  if (resolve_real_server) {
	    client->router = 
	      silc_server_update_clients_by_real_server(server, client);
	    if (!client->router)
	      client->router = to;
	  } else {
	    client->router = to;
	  }
	}

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  if (silc_idcache_get_all(server->global_list->clients, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (client->router == from) {
	  /* Skip clients that are *really* owned by the `from' */
	  if (SILC_ID_COMPARE(from->id, client->id, 
			      client->id->ip.data_len)) {
	    SILC_LOG_DEBUG(("Found really owned client, skip it"));
	    if (!silc_idcache_list_next(list, &id_cache))
	      break;
	    else
	      continue;
	  }

	  if (resolve_real_server) {
	    client->router = 
	      silc_server_update_clients_by_real_server(server, client);
	    if (!client->router)
	      client->router = to;
	  } else {
	    client->router = to;
	  }
	}

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  if (remove_from)
    /* Now remove the clients that are still marked as orignated from the
       `from'. These are the clients that really was owned by the `from' and
       not just exist behind the `from'. */
    silc_server_remove_clients_by_server(server, from, TRUE);
}

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */

bool silc_server_channel_has_global(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    if (chl->client->router)
      return TRUE;
  }

  return FALSE;
}

/* Checks whether given channel has locally connected users.  If it does this
   returns TRUE and FALSE if there is not one locally connected client. */

bool silc_server_channel_has_local(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    if (!chl->client->router)
      return TRUE;
  }

  return FALSE;
}

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */

bool silc_server_client_on_channel(SilcClientEntry client,
				   SilcChannelEntry channel)
{
  if (!client || !channel)
    return FALSE;

  if (silc_hash_table_find(client->channels, channel, NULL, NULL))
    return TRUE;

  return FALSE;
}
