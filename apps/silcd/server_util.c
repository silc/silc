/*

  server_util.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

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

extern char *server_version;

/* Removes the client from channels and possibly removes the channels
   as well.  After removing those channels that exist, their channel
   keys are regnerated. This is called only by the function
   silc_server_remove_clients_by_server. */

static void
silc_server_remove_clients_channels(SilcServer server,
				    SilcServerEntry server_entry,
				    SilcHashTable clients,
				    SilcClientEntry client,
				    SilcHashTable channels)
{
  SilcChannelEntry channel;
  SilcChannelClientEntry chl, chl2;
  SilcHashTableList htl, htl2;

  if (!client)
    return;

  SILC_LOG_DEBUG(("Remove client from all channels"));

  if (silc_hash_table_find(clients, client, NULL, NULL))
    silc_hash_table_del(clients, client);

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
    channel = chl->channel;

    /* Remove channel if this is last client leaving the channel, unless
       the channel is permanent. */
    if (server->server_type == SILC_ROUTER &&
	silc_hash_table_count(channel->user_list) < 2) {
      if (silc_hash_table_find(channels, channel, NULL, NULL))
	silc_hash_table_del(channels, channel);
      silc_schedule_task_del_by_context(server->schedule, channel->rekey);
      silc_server_channel_delete(server, channel);
      continue;
    }

    silc_hash_table_del(client->channels, channel);
    silc_hash_table_del(channel->user_list, chl->client);
    channel->user_count--;

    /* If there is no global users on the channel anymore mark the channel
       as local channel. Do not check if the removed client is local client. */
    if (server->server_type != SILC_ROUTER && channel->global_users && 
	chl->client->router && !silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    silc_free(chl);

    /* Update statistics */
    if (SILC_IS_LOCAL(client))
      server->stat.my_chanclients--;
    if (server->server_type == SILC_ROUTER) {
      server->stat.cell_chanclients--;
      server->stat.chanclients--;
    }

    /* If there is not at least one local user on the channel then we don't
       need the channel entry anymore, we can remove it safely, unless the
       channel is permanent channel */
    if (server->server_type != SILC_ROUTER &&
	!silc_server_channel_has_local(channel)) {
      if (silc_hash_table_find(channels, channel, NULL, NULL))
	silc_hash_table_del(channels, channel);
      silc_schedule_task_del_by_context(server->schedule, channel->rekey);
      silc_server_channel_delete(server, channel);
      continue;
    }

    /* Mark other local clients to the table of clients whom will receive
       the SERVER_SIGNOFF notify. */
    silc_hash_table_list(channel->user_list, &htl2);
    while (silc_hash_table_get(&htl2, NULL, (void **)&chl2)) {
      SilcClientEntry c = chl2->client;
      if (!c)
	continue;

      /* Add client to table, if it's not from the signoff server */
      if (c->router != server_entry &&
	  !silc_hash_table_find(clients, c, NULL, NULL))
	silc_hash_table_add(clients, c, c);
    }
    silc_hash_table_list_reset(&htl2);

    /* Add the channel to the the channels list to regenerate the 
       channel key */
    if (!silc_hash_table_find(channels, channel, NULL, NULL))
      silc_hash_table_add(channels, channel, channel);
  }
  silc_hash_table_list_reset(&htl);
}

/* This function removes all client entries that are originated from
   `router' and are owned by `entry'.  `router' and `entry' can be same
   too.  If `server_signoff' is TRUE then SERVER_SIGNOFF notify is 
   distributed to our local clients. */

bool silc_server_remove_clients_by_server(SilcServer server,
					  SilcServerEntry router,
					  SilcServerEntry entry,
					  bool server_signoff)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  SilcBuffer idp;
  unsigned char **argv = NULL;
  SilcUInt32 *argv_lens = NULL, *argv_types = NULL, argc = 0;
  SilcHashTableList htl;
  SilcChannelEntry channel;
  SilcHashTable channels, clients;
  int i;

  if (!(entry->data.status & SILC_IDLIST_STATUS_REGISTERED))
    return FALSE;

  SILC_LOG_DEBUG(("Removing clients by %s",
		  entry->server_name ? entry->server_name : "server"));

  if (!router)
    router = entry;

  /* Allocate the hash table that holds the channels that require
     channel key re-generation after we've removed this server's clients
     from the channels. */
  channels = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL, NULL,
				   NULL, NULL, TRUE);
  clients = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL, NULL,
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

	/* If client is not registered, is not originated from `router'
	   or is not owned by `entry', skip it. */
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	    client->router != router ||
	    !SILC_ID_COMPARE(client->id, entry->id, client->id->ip.data_len)) {
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

	/* Update statistics */
	server->stat.clients--;
	if (server->stat.cell_clients)
	  server->stat.cell_clients--;
	SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
	SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

	silc_server_remove_clients_channels(server, entry, clients,
					    client, channels);
	silc_server_del_from_watcher_list(server, client);

	/* Remove the client entry */
	if (!server_signoff) {
	  client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
	  id_cache->expire = SILC_ID_CACHE_EXPIRE_DEF;
	} else {
	  silc_idlist_del_client(server->local_list, client);
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

	/* If client is not registered, is not originated from `router'
	   or is not owned by `entry', skip it. */
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	    client->router != router ||
	    !SILC_ID_COMPARE(client->id, entry->id, client->id->ip.data_len)) {
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

	/* Update statistics */
	server->stat.clients--;
	if (server->stat.cell_clients)
	  server->stat.cell_clients--;
	SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
	SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

	silc_server_remove_clients_channels(server, entry, clients,
					    client, channels);
	silc_server_del_from_watcher_list(server, client);

	/* Remove the client entry */
	if (!server_signoff) {
	  client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
	  id_cache->expire = SILC_ID_CACHE_EXPIRE_DEF;
	} else {
	  silc_idlist_del_client(server->global_list, client);
	}

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  /* Send the SERVER_SIGNOFF notify */
  if (server_signoff) {
    SilcBuffer args, not;

    SILC_LOG_DEBUG(("Sending SERVER_SIGNOFF for %s with %d clients",
		    silc_id_render(entry->id, SILC_ID_SERVER), argc - 1));

    /* Send SERVER_SIGNOFF notify to our primary router */
    if (server->router != entry) {
      args = silc_argument_payload_encode(1, argv, argv_lens,
					  argv_types);
      silc_server_send_notify_args(server, SILC_PRIMARY_ROUTE(server),
				   SILC_BROADCAST(server),
				   SILC_NOTIFY_TYPE_SERVER_SIGNOFF,
				   argc, args);
      silc_buffer_free(args);
    }

    /* Send to local clients. We also send the list of client ID's that
       is to be removed for those servers that would like to use that list. */
    args = silc_argument_payload_encode(argc, argv, argv_lens,
					argv_types);
    not = silc_notify_payload_encode_args(SILC_NOTIFY_TYPE_SERVER_SIGNOFF, 
					  argc, args);
    silc_server_packet_send_clients(server, clients,
				    SILC_PACKET_NOTIFY, 0, FALSE,
				    not->data, not->len, FALSE);

    silc_buffer_free(args);
    silc_buffer_free(not);
    for (i = 0; i < argc; i++)
      silc_free(argv[i]);
    silc_free(argv);
    silc_free(argv_lens);
    silc_free(argv_types);
    silc_hash_table_free(clients);
  }

  /* We must now re-generate the channel key for all channels that had
     this server's client(s) on the channel. As they left the channel we
     must re-generate the channel key. */
  silc_hash_table_list(channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&channel)) {
    if (!silc_server_create_channel_key(server, channel, 0)) {
      silc_hash_table_list_reset(&htl);
      silc_hash_table_free(channels);
      return FALSE;
    }

    /* Do not send the channel key if private channel key mode is set */
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY)
      continue;

    silc_server_send_channel_key(server, NULL, channel, 
				 server->server_type == SILC_ROUTER ? 
				 FALSE : !server->standalone);
  }
  silc_hash_table_list_reset(&htl);
  silc_hash_table_free(channels);

  return TRUE;
}

static SilcServerEntry
silc_server_update_clients_by_real_server(SilcServer server,
					  SilcServerEntry from,
					  SilcClientEntry client,
					  bool local,
					  SilcIDCacheEntry client_cache)
{
  SilcServerEntry server_entry;
  SilcIDCacheEntry id_cache = NULL;
  SilcIDCacheList list;

  if (!silc_idcache_get_all(server->local_list->servers, &list))
    return NULL;

  if (silc_idcache_list_first(list, &id_cache)) {
    while (id_cache) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (server_entry != from &&
	  SILC_ID_COMPARE(server_entry->id, client->id, 
			  client->id->ip.data_len)) {
	SILC_LOG_DEBUG(("Found (local) %s",
			silc_id_render(server_entry->id, SILC_ID_SERVER)));

	if (!server_entry->data.send_key && server_entry->router) {
	  SILC_LOG_DEBUG(("Server not locally connected, use its router"));
	  /* If the client is not marked as local then move it to local list
	     since the server is local. */
	  if (!local) {
	    SILC_LOG_DEBUG(("Moving client to local list"));
	    silc_idcache_add(server->local_list->clients, client_cache->name,
			     client_cache->id, client_cache->context,
			     client_cache->expire, NULL);
	    silc_idcache_del_by_context(server->global_list->clients, client);
	  }
	  server_entry = server_entry->router;
	} else {
	  /* If the client is not marked as local then move it to local list
	     since the server is local. */
	  if (server_entry->server_type != SILC_BACKUP_ROUTER && !local) {
	    SILC_LOG_DEBUG(("Moving client to local list"));
	    silc_idcache_add(server->local_list->clients, client_cache->name,
			     client_cache->id, client_cache->context,
			     client_cache->expire, NULL);
	    silc_idcache_del_by_context(server->global_list->clients, client);
	  }
	}

	silc_idcache_list_free(list);
	return server_entry;
      }

      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
  }

  silc_idcache_list_free(list);

  if (!silc_idcache_get_all(server->global_list->servers, &list))
    return NULL;

  if (silc_idcache_list_first(list, &id_cache)) {
    while (id_cache) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (server_entry != from &&
	  SILC_ID_COMPARE(server_entry->id, client->id, 
			  client->id->ip.data_len)) {
	SILC_LOG_DEBUG(("Found (global) %s",
			silc_id_render(server_entry->id, SILC_ID_SERVER)));

	if (!server_entry->data.send_key && server_entry->router) {
	  SILC_LOG_DEBUG(("Server not locally connected, use its router"));
	  /* If the client is marked as local then move it to global list
	     since the server is global. */
	  if (local) {
	    SILC_LOG_DEBUG(("Moving client to global list"));
	    silc_idcache_add(server->global_list->clients, client_cache->name,
			     client_cache->id, client_cache->context,
			     client_cache->expire, NULL);
	    silc_idcache_del_by_context(server->local_list->clients, client);
	  }
	  server_entry = server_entry->router;
	} else {
	  /* If the client is marked as local then move it to global list
	     since the server is global. */
	  if (server_entry->server_type != SILC_BACKUP_ROUTER && local) {
	    SILC_LOG_DEBUG(("Moving client to global list"));
	    silc_idcache_add(server->global_list->clients, client_cache->name,
			     client_cache->id, client_cache->context,
			     client_cache->expire, NULL);
	    silc_idcache_del_by_context(server->local_list->clients, client);
	  }
	}

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
   the `from'. If `from' is NULL then all non-local clients are switched
   to `to'. */

void silc_server_update_clients_by_server(SilcServer server, 
					  SilcServerEntry from,
					  SilcServerEntry to,
					  bool resolve_real_server,
					  bool remove_from)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  bool local;

  if (from)
    SILC_LOG_DEBUG(("Updating %s", silc_id_render(from->id,
						  SILC_ID_SERVER)));
  if (to)
    SILC_LOG_DEBUG(("to %s", silc_id_render(to->id,
					    SILC_ID_SERVER)));

  local = FALSE;
  if (silc_idcache_get_all(server->global_list->clients, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;

	/* If entry is disabled skip it.  If entry is local to us, do not
	   switch it to anyone else, it is ours so skip it. */
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	    SILC_IS_LOCAL(client)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	SILC_LOG_DEBUG(("Client (global) %s", 
			silc_id_render(client->id, SILC_ID_CLIENT)));
	if (client->router)
	  SILC_LOG_DEBUG(("Client->router (global) %s", 
			  silc_id_render(client->router->id, SILC_ID_SERVER)));

	if (from) {
	  if (client->router == from) {
	    /* Skip clients that are *really* owned by the `from' */
	    if (remove_from && SILC_ID_COMPARE(from->id, client->id, 
					       client->id->ip.data_len)) {
	      SILC_LOG_DEBUG(("Found really owned client, skip it"));
	      if (!silc_idcache_list_next(list, &id_cache))
		break;
	      else
		continue;
	    }

	    if (resolve_real_server) {
	      client->router = 
		silc_server_update_clients_by_real_server(server, from, client,
							  local, id_cache);
	      if (!client->router) {
		if (server->server_type == SILC_ROUTER)
		  client->router = from;
		else
		  client->router = to;
	      }
	    } else {
	      client->router = to;
	    }
	  }
	} else {
	  /* All are changed */
	  client->router = to;
	}

	if (client->router)
	  SILC_LOG_DEBUG(("Client changed to %s", 
			  silc_id_render(client->router->id, SILC_ID_CLIENT)));

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  local = TRUE;
  if (silc_idcache_get_all(server->local_list->clients, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;

	/* If entry is disabled skip it.  If entry is local to us, do not
	   switch it to anyone else, it is ours so skip it. */
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	    SILC_IS_LOCAL(client)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	SILC_LOG_DEBUG(("Client (local) %s", 
			silc_id_render(client->id, SILC_ID_CLIENT)));
	if (client->router)
	  SILC_LOG_DEBUG(("Client->router (local) %s", 
			  silc_id_render(client->router->id, SILC_ID_SERVER)));

	if (from) {
	  if (client->router == from) {
	    /* Skip clients that are *really* owned by the `from' */
	    if (remove_from && SILC_ID_COMPARE(from->id, client->id, 
					       client->id->ip.data_len)) {
	      SILC_LOG_DEBUG(("Found really owned client, skip it"));
	      if (!silc_idcache_list_next(list, &id_cache))
		break;
	      else
		continue;
	    }

	    if (resolve_real_server) {
	      client->router = 
		silc_server_update_clients_by_real_server(server, from, client,
							  local, id_cache);
	      if (!client->router)
		client->router = from;
	    } else {
	      client->router = to;
	    }
	  }
	} else {
	  /* All are changed */
	  client->router = to;
	}

	if (client->router)
	  SILC_LOG_DEBUG(("Client changed to %s", 
			  silc_id_render(client->router->id, SILC_ID_CLIENT)));

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
    silc_server_remove_clients_by_server(server, from, from, TRUE);
}

/* Updates servers that are from `from' to be originated from `to'.  This
   will also update the server's connection to `to's connection. */

void silc_server_update_servers_by_server(SilcServer server, 
					  SilcServerEntry from,
					  SilcServerEntry to)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server_entry = NULL;

  SILC_LOG_DEBUG(("Updating servers"));

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;

	/* If entry is local to us, do not switch it to any anyone else,
	   it is ours. */
	if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	    server_entry == from) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	/* If we are standalone router, any server that is not directly
	   connected to cannot exist anymore.  If we are not standalone
	   we update it correctly. */
	if (server->server_type == SILC_ROUTER && server->standalone) {
	  silc_server_backup_del(server, server_entry);
	  silc_server_backup_replaced_del(server, server_entry);
	  silc_idlist_del_data(server_entry);
	  silc_idlist_del_server(server->local_list, server_entry);
	  server->stat.servers--;
	  server->stat.cell_servers--;
	} else {
	  /* XXX if we are not standalone, do a check from local config
	     whether this server is in our cell, but not connected to
	     us (in which case we must remove it). */

	  if (server_entry->router == from) {
	    SILC_LOG_DEBUG(("Updating server (local) %s",
			    server_entry->server_name ? 
			    server_entry->server_name : ""));
	    server_entry->router = to;
	    server_entry->connection = to->connection;
	  }
	}

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;

	/* If entry is local to us, do not switch it to anyone else,
	   it is ours. */
	if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	    server_entry == from) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	/* If we are standalone router, any server that is not directly
	   connected to cannot exist anymore.  If we are not standalone
	   we update it correctly. */
	if (server->server_type == SILC_ROUTER && server->standalone) {
	  silc_server_backup_del(server, server_entry);
	  silc_server_backup_replaced_del(server, server_entry);
	  silc_idlist_del_data(server_entry);
	  silc_idlist_del_server(server->global_list, server_entry);
	  server->stat.servers--;
	  server->stat.cell_servers--;
	} else {
	  /* XXX if we are not standalone, do a check from local config
	     whether this server is in our cell, but not connected to
	     us (in which case we must remove it). */

	  if (server_entry->router == from) {
	    SILC_LOG_DEBUG(("Updating server (global) %s",
			    server_entry->server_name ? 
			    server_entry->server_name : ""));
	    server_entry->router = to;
	    server_entry->connection = to->connection;
	  }
	}

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
}


/* Toggles the enabled/disabled status of local server connections.  Packets
   can be sent to the servers when `toggle_enabled' is TRUE and will be
   dropped if `toggle_enabled' is FALSE, after this function is called. */

void silc_server_local_servers_toggle_enabled(SilcServer server,
					      bool toggle_enabled)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server_entry = NULL;

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;
	if (!SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (toggle_enabled)
	  server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
	else
	  server_entry->data.status |= SILC_IDLIST_STATUS_DISABLED;

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;
	if (!SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	if (toggle_enabled)
	  server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
	else
	  server_entry->data.status |= SILC_IDLIST_STATUS_DISABLED;

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
}

/* Removes servers that are originated from the `from'.  The server
   entry is deleted in this function.  If `remove_clients' is TRUE then
   all clients originated from the server are removed too, and server
   signoff is sent.  Note that this does not remove the `from'.  This
   also does not remove locally connected servers. */

void silc_server_remove_servers_by_server(SilcServer server,
					  SilcServerEntry from,
					  bool remove_clients)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server_entry = NULL;

  SILC_LOG_DEBUG(("Removing servers by %s",
		  from->server_name ? from->server_name : "server"));

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;
	if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	  server_entry->router != from || server_entry == from) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	/* Remove clients owned by this server */
	if (remove_clients)
	  silc_server_remove_clients_by_server(server, from, server_entry,
					       TRUE);

	/* Remove the server */
	silc_idlist_del_server(server->local_list, server_entry);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }

  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	server_entry = (SilcServerEntry)id_cache->context;
	if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	  server_entry->router != from || server_entry == from) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  else
	    continue;
	}

	/* Remove clients owned by this server */
	if (remove_clients)
	  silc_server_remove_clients_by_server(server, from, server_entry,
					       TRUE);

	/* Remove the server */
	silc_idlist_del_server(server->global_list, server_entry);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
}

/* Removes channels that are from `from. */

void silc_server_remove_channels_by_server(SilcServer server, 
					   SilcServerEntry from)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel = NULL;

  SILC_LOG_DEBUG(("Removing channels by server"));

  if (silc_idcache_get_all(server->global_list->channels, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	channel = (SilcChannelEntry)id_cache->context;
	if (channel->router == from)
	  silc_idlist_del_channel(server->global_list, channel);
	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
}

/* Updates channels that are from `from' to be originated from `to'.  */

void silc_server_update_channels_by_server(SilcServer server, 
					   SilcServerEntry from,
					   SilcServerEntry to)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel = NULL;

  SILC_LOG_DEBUG(("Updating channels by server"));

  if (silc_idcache_get_all(server->global_list->channels, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	channel = (SilcChannelEntry)id_cache->context;
	if (channel->router == from)
	  channel->router = to;
	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }
    silc_idcache_list_free(list);
  }
}

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */

bool silc_server_channel_has_global(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
    if (chl->client->router) {
      silc_hash_table_list_reset(&htl);
      return TRUE;
    }
  }
  silc_hash_table_list_reset(&htl);

  return FALSE;
}

/* Checks whether given channel has locally connected users.  If it does this
   returns TRUE and FALSE if there is not one locally connected client. */

bool silc_server_channel_has_local(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
    if (!chl->client->router) {
      silc_hash_table_list_reset(&htl);
      return TRUE;
    }
  }
  silc_hash_table_list_reset(&htl);

  return FALSE;
}

/* This function removes the channel and all users on the channel, unless
   the channel is permanent.  In this case the channel is disabled but all
   users are removed from the channel.  Returns TRUE if the channel is
   destroyed totally, and FALSE if it is permanent and remains. */

bool silc_server_channel_delete(SilcServer server,
				SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  bool delchan = !(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH);

  if (delchan) {
    SILC_LOG_DEBUG(("Deleting %s channel", channel->channel_name));

    /* Update statistics */
    if (server->server_type == SILC_ROUTER)
      server->stat.chanclients -= channel->user_count;

    /* Totally delete the channel and all users on the channel. The
       users are deleted automatically in silc_idlist_del_channel. */
    silc_schedule_task_del_by_context(server->schedule, channel->rekey);
    if (silc_idlist_del_channel(server->local_list, channel)) {
      server->stat.my_channels--;
      if (server->server_type == SILC_ROUTER) {
	server->stat.channels--;
	server->stat.cell_channels--;
      }
    } else {
      if (silc_idlist_del_channel(server->global_list, channel))
	if (server->server_type == SILC_ROUTER)
	  server->stat.channels--;
    }

    return FALSE;
  }

  /* Channel is permanent, do not remove it, remove only users */
  channel->disabled = TRUE;
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    silc_hash_table_del(chl->client->channels, channel);
    silc_hash_table_del(channel->user_list, chl->client);
    channel->user_count--;

    /* Update statistics */
    if (SILC_IS_LOCAL(chl->client))
      server->stat.my_chanclients--;
    if (server->server_type == SILC_ROUTER) {
      server->stat.cell_chanclients--;
      server->stat.chanclients--;
    }

    silc_free(chl);
  }
  silc_hash_table_list_reset(&htl);

  SILC_LOG_DEBUG(("Channel %s remains", channel->channel_name));

  return TRUE;
}

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */

bool silc_server_client_on_channel(SilcClientEntry client,
				   SilcChannelEntry channel,
				   SilcChannelClientEntry *chl)
{
  if (!client || !channel)
    return FALSE;

  return silc_hash_table_find(client->channels, channel, NULL, 
			      (void **)chl);
}

/* Checks string for bad characters and returns TRUE if they are found. */

bool silc_server_name_bad_chars(const char *name, SilcUInt32 name_len)
{
  int i;

  for (i = 0; i < name_len; i++) {
    if (!isascii(name[i]))
      return TRUE;
    if (name[i] <= 32) return TRUE;
    if (name[i] == ' ') return TRUE;
    if (name[i] == '*') return TRUE;
    if (name[i] == '?') return TRUE;
    if (name[i] == ',') return TRUE;
  }

  return FALSE;
}

/* Modifies the `name' if it includes bad characters and returns new
   allocated name that does not include bad characters. */

char *silc_server_name_modify_bad(const char *name, SilcUInt32 name_len)
{
  int i;
  char *newname = strdup(name);

  for (i = 0; i < name_len; i++) {
    if (!isascii(newname[i])) newname[i] = '_';
    if (newname[i] <= 32) newname[i] = '_';
    if (newname[i] == ' ') newname[i] = '_';
    if (newname[i] == '*') newname[i] = '_';
    if (newname[i] == '?') newname[i] = '_';
    if (newname[i] == ',') newname[i] = '_';
  }

  return newname;
}

/* Find number of sockets by IP address indicated by `ip'. Returns 0 if
   socket connections with the IP address does not exist. */

SilcUInt32 silc_server_num_sockets_by_ip(SilcServer server, const char *ip,
					 SilcSocketType type)
{
  int i, count;

  for (i = 0, count = 0; i < server->config->param.connections_max; i++) {
    if (server->sockets[i] && !strcmp(server->sockets[i]->ip, ip) &&
	server->sockets[i]->type == type)
      count++;
  }

  return count;
}

/* Find number of sockets by IP address indicated by remote host, indicatd
   by `ip' or `hostname', `port', and `type'.  Returns 0 if socket connections
   does not exist. If `ip' is provided then `hostname' is ignored. */

SilcUInt32 silc_server_num_sockets_by_remote(SilcServer server, 
					     const char *ip,
					     const char *hostname,
					     SilcUInt16 port,
					     SilcSocketType type)
{
  int i, count;

  if (!ip && !hostname)
    return 0;

  for (i = 0, count = 0; i < server->config->param.connections_max; i++) {
    if (server->sockets[i] && 
	((ip && !strcmp(server->sockets[i]->ip, ip)) ||
	 (hostname && !strcmp(server->sockets[i]->hostname, hostname))) &&
	server->sockets[i]->port == port &&
	server->sockets[i]->type == type)
      count++;
  }

  return count;
}

/* Finds locally cached public key by the public key received in the SKE. 
   If we have it locally cached then we trust it and will use it in the
   authentication protocol.  Returns the locally cached public key or NULL
   if we do not find the public key.  */

SilcPublicKey silc_server_find_public_key(SilcServer server, 
					  SilcHashTable local_public_keys,
					  SilcPublicKey remote_public_key)
{
  SilcPublicKey cached_key;

  SILC_LOG_DEBUG(("Find remote public key (%d keys in local cache)",
		  silc_hash_table_count(local_public_keys)));

  if (!silc_hash_table_find_ext(local_public_keys, remote_public_key,
				(void **)&cached_key, NULL, 
				silc_hash_public_key, NULL,
				silc_hash_public_key_compare, NULL)) {
    SILC_LOG_ERROR(("Public key not found"));
    return NULL;
  }

  SILC_LOG_DEBUG(("Found public key"));

  return cached_key;
}

/* This returns the first public key from the table of public keys.  This
   is used only in cases where single public key exists in the table and
   we want to get a pointer to it.  For public key tables that has multiple
   keys in it the silc_server_find_public_key must be used. */

SilcPublicKey silc_server_get_public_key(SilcServer server,
					 SilcHashTable local_public_keys)
{
  SilcPublicKey cached_key;
  SilcHashTableList htl;

  SILC_LOG_DEBUG(("Start"));

  assert(silc_hash_table_count(local_public_keys) < 2);

  silc_hash_table_list(local_public_keys, &htl);
  if (!silc_hash_table_get(&htl, NULL, (void **)&cached_key))
    return NULL;
  silc_hash_table_list_reset(&htl);

  return cached_key;
}

/* Check whether the connection `sock' is allowed to connect to us.  This
   checks for example whether there is too much connections for this host,
   and required version for the host etc. */

bool silc_server_connection_allowed(SilcServer server, 
				    SilcSocketConnection sock,
				    SilcSocketType type,
				    SilcServerConfigConnParams *global,
				    SilcServerConfigConnParams *params,
				    SilcSKE ske)
{
  SilcUInt32 conn_number = (type == SILC_SOCKET_TYPE_CLIENT ?
			    server->stat.my_clients :
			    type == SILC_SOCKET_TYPE_SERVER ?
			    server->stat.my_servers :
			    server->stat.my_routers);
  SilcUInt32 num_sockets, max_hosts, max_per_host;
  SilcUInt32 r_protocol_version, l_protocol_version;
  SilcUInt32 r_software_version, l_software_version;
  char *r_vendor_version = NULL, *l_vendor_version;

  SILC_LOG_DEBUG(("Checking whether connection is allowed"));

  /* Check version */

  l_protocol_version = 
    silc_version_to_num(params && params->version_protocol ? 
			params->version_protocol : 
			global->version_protocol);
  l_software_version = 
    silc_version_to_num(params && params->version_software ? 
			params->version_software : 
			global->version_software);
  l_vendor_version = (params && params->version_software_vendor ? 
		      params->version_software_vendor : 
		      global->version_software_vendor);
  
  if (ske && silc_ske_parse_version(ske, &r_protocol_version, NULL,
				    &r_software_version, NULL,
				    &r_vendor_version)) {
    sock->version = r_protocol_version;

    /* Match protocol version */
    if (l_protocol_version && r_protocol_version &&
	r_protocol_version < l_protocol_version) {
      SILC_LOG_INFO(("Connection %s (%s) is too old version",
		     sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock, 
				    SILC_STATUS_ERR_BAD_VERSION,
				    "You support too old protocol version");
      return FALSE;
    }

    /* Math software version */
    if (l_software_version && r_software_version &&
	r_software_version < l_software_version) {
      SILC_LOG_INFO(("Connection %s (%s) is too old version",
		     sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock, 
				    SILC_STATUS_ERR_BAD_VERSION,
				    "You support too old software version");
      return FALSE;
    }

    /* Regex match vendor version */
    if (l_vendor_version && r_vendor_version && 
	!silc_string_match(l_vendor_version, r_vendor_version)) {
      SILC_LOG_INFO(("Connection %s (%s) is unsupported version",
		     sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock, 
				    SILC_STATUS_ERR_BAD_VERSION,
				    "Your software is not supported");
      return FALSE;
    }
  }
  silc_free(r_vendor_version);

  /* Check for maximum connections limit */

  num_sockets = silc_server_num_sockets_by_ip(server, sock->ip, type);
  max_hosts = (params ? params->connections_max : global->connections_max);
  max_per_host = (params ? params->connections_max_per_host :
		  global->connections_max_per_host);

  if (max_hosts && conn_number >= max_hosts) {
    SILC_LOG_INFO(("Server is full, closing %s (%s) connection",
		   sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_RESOURCE_LIMIT,
				  "Server is full, try again later");
    return FALSE;
  }

  if (num_sockets >= max_per_host) {
    SILC_LOG_INFO(("Too many connections from %s (%s), closing connection",
		   sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_RESOURCE_LIMIT,
				  "Too many connections from your host");
    return FALSE;
  }

  return TRUE;
}

/* Checks that client has rights to add or remove channel modes. If any
   of the checks fails FALSE is returned. */

bool silc_server_check_cmode_rights(SilcServer server,
				    SilcChannelEntry channel,
				    SilcChannelClientEntry client,
				    SilcUInt32 mode)
{
  bool is_op = client->mode & SILC_CHANNEL_UMODE_CHANOP;
  bool is_fo = client->mode & SILC_CHANNEL_UMODE_CHANFO;

  /* Check whether has rights to change anything */
  if (!is_op && !is_fo)
    return FALSE;

  /* Check whether has rights to change everything */
  if (is_op && is_fo)
    return TRUE;

  /* Founder implies operator */
  if (is_fo)
    is_op = TRUE;

  /* We know that client is channel operator, check that they are not
     changing anything that requires channel founder rights. Rest of the
     modes are available automatically for channel operator. */

  if (mode & SILC_CHANNEL_MODE_PRIVKEY) {
    if (is_op && !is_fo)
      return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_PASSPHRASE) {
    if (!(channel->mode & SILC_CHANNEL_MODE_PASSPHRASE)) {
      if (is_op && !is_fo)
	return FALSE;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }

  if (mode & SILC_CHANNEL_MODE_CIPHER) {
    if (!(channel->mode & SILC_CHANNEL_MODE_CIPHER)) {
      if (is_op && !is_fo)
	return FALSE;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_CIPHER) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
    if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)) {
      if (is_op && !is_fo)
	return FALSE;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_SILENCE_USERS) {
    if (!(channel->mode & SILC_CHANNEL_MODE_SILENCE_USERS)) {
      if (is_op && !is_fo)
	return FALSE;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_SILENCE_USERS) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_SILENCE_OPERS) {
    if (!(channel->mode & SILC_CHANNEL_MODE_SILENCE_OPERS)) {
      if (is_op && !is_fo)
	return FALSE;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_SILENCE_OPERS) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  return TRUE;
}

/* Check that the client has rights to change its user mode.  Returns
   FALSE if setting some mode is not allowed. */

bool silc_server_check_umode_rights(SilcServer server,
				    SilcClientEntry client,
				    SilcUInt32 mode)
{
  bool server_op = FALSE, router_op = FALSE;

  if (mode & SILC_UMODE_SERVER_OPERATOR) {
    /* Cannot set server operator mode (must use OPER command) */
    if (!(client->mode & SILC_UMODE_SERVER_OPERATOR))
      return FALSE;
  } else {
    /* Remove the server operator rights */
    if (client->mode & SILC_UMODE_SERVER_OPERATOR)
      server_op = TRUE;
  }

  if (mode & SILC_UMODE_ROUTER_OPERATOR) {
    /* Cannot set router operator mode (must use SILCOPER command) */
    if (!(client->mode & SILC_UMODE_ROUTER_OPERATOR))
      return FALSE;
  } else {
    /* Remove the router operator rights */
    if (client->mode & SILC_UMODE_ROUTER_OPERATOR)
      router_op = TRUE;
  }

  if (server_op)
    SILC_UMODE_STATS_UPDATE(server, SILC_UMODE_SERVER_OPERATOR);
  if (router_op)
    SILC_UMODE_STATS_UPDATE(router, SILC_UMODE_ROUTER_OPERATOR);

  return TRUE;
}

/* This function is used to send the notify packets and motd to the
   incoming client connection. */

void silc_server_send_connect_notifys(SilcServer server,
				      SilcSocketConnection sock,
				      SilcClientEntry client)
{
  SilcIDListData idata = (SilcIDListData)client;

  SILC_LOG_DEBUG(("Send welcome notifys"));

  /* Send some nice info to the client */
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Welcome to the SILC Network %s",
			   client->username));
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your host is %s, running version %s",
			   server->server_name, server_version));

  if (server->server_type == SILC_ROUTER) {
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients, %d servers and %d "
			     "routers in SILC Network",
			     server->stat.clients, server->stat.servers + 1,
			     server->stat.routers));
  } else {
    if (server->stat.clients && server->stat.servers + 1)
      SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			      ("There are %d clients, %d servers and %d "
			       "routers in SILC Network",
			       server->stat.clients, server->stat.servers + 1,
			       (server->standalone ? 0 :
				!server->stat.routers ? 1 :
				server->stat.routers)));
  }

  if (server->stat.cell_clients && server->stat.cell_servers + 1)
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients on %d server in our cell",
			     server->stat.cell_clients,
			     server->stat.cell_servers + 1));
  if (server->server_type == SILC_ROUTER) {
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d clients, %d channels, %d servers and "
			     "%d routers",
			     server->stat.my_clients, 
			     server->stat.my_channels,
			     server->stat.my_servers,
			     server->stat.my_routers));
  } else {
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d clients and %d channels formed",
			     server->stat.my_clients,
			     server->stat.my_channels));
  }

  if (server->stat.server_ops || server->stat.router_ops)
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d server operators and %d router "
			     "operators online",
			     server->stat.server_ops,
			     server->stat.router_ops));
  if (server->stat.my_router_ops + server->stat.my_server_ops)
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d operators online",
			     server->stat.my_router_ops +
			     server->stat.my_server_ops));

  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your connection is secured with %s cipher, "
			   "key length %d bits",
			   idata->send_key->cipher->name,
			   idata->send_key->cipher->key_len));
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your current nickname is %s",
			   client->nickname));

  /* Send motd */
  silc_server_send_motd(server, sock);
}

/* Kill the client indicated by `remote_client' sending KILLED notify
   to the client, to all channels client has joined and to primary
   router if needed.  The killed client is also removed from all channels. */

void silc_server_kill_client(SilcServer server,
			     SilcClientEntry remote_client,
			     const char *comment,
			     void *killer_id,
			     SilcIdType killer_id_type)
{
  SilcBuffer killed, killer;

  SILC_LOG_DEBUG(("Killing client %s", 
		  silc_id_render(remote_client->id, SILC_ID_CLIENT)));

  /* Send the KILL notify packets. First send it to the channel, then
     to our primary router and then directly to the client who is being
     killed right now. */

  killed = silc_id_payload_encode(remote_client->id, SILC_ID_CLIENT);
  killer = silc_id_payload_encode(killer_id, killer_id_type);

  /* Send KILLED notify to the channels. It is not sent to the client
     as it will be sent differently destined directly to the client and not
     to the channel. */
  silc_server_send_notify_on_channels(server, remote_client, 
				      remote_client, SILC_NOTIFY_TYPE_KILLED,
				      3, killed->data, killed->len,
				      comment, comment ? strlen(comment) : 0,
				      killer->data, killer->len);

  /* Send KILLED notify to primary route */
  silc_server_send_notify_killed(server, SILC_PRIMARY_ROUTE(server),
				 SILC_BROADCAST(server), remote_client->id,
				 comment, killer_id, killer_id_type);

  /* Send KILLED notify to the client directly */
  if (remote_client->connection || remote_client->router)
    silc_server_send_notify_killed(server, remote_client->connection ? 
				   remote_client->connection : 
				   remote_client->router->connection, FALSE,
				   remote_client->id, comment, 
				   killer_id, killer_id_type);

  /* Remove the client from all channels. This generates new keys to the
     channels as well. */
  silc_server_remove_from_channels(server, NULL, remote_client, FALSE, 
				   NULL, TRUE);

  /* Remove the client entry, If it is locally connected then we will also
     disconnect the client here */
  if (remote_client->connection) {
    /* Remove locally conneted client */
    SilcSocketConnection sock = remote_client->connection;
    silc_server_free_client_data(server, sock, remote_client, FALSE, NULL);
    silc_server_close_connection(server, sock);
  } else {
    /* Update statistics */
    server->stat.clients--;
    if (server->stat.cell_clients)
      server->stat.cell_clients--;
    SILC_OPER_STATS_UPDATE(remote_client, server, SILC_UMODE_SERVER_OPERATOR);
    SILC_OPER_STATS_UPDATE(remote_client, router, SILC_UMODE_ROUTER_OPERATOR);

    if (SILC_IS_LOCAL(remote_client)) {
      server->stat.my_clients--;
      silc_schedule_task_del_by_context(server->schedule, remote_client);
      silc_idlist_del_data(remote_client);
    }

    /* Remove remote client */
    if (!silc_idlist_del_client(server->global_list, remote_client)) {
      /* Remove this client from watcher list if it is */
      silc_server_del_from_watcher_list(server, remote_client);
      silc_idlist_del_client(server->local_list, remote_client);  
    }
  }

  silc_buffer_free(killer);
  silc_buffer_free(killed);
}

typedef struct {
  SilcServer server;
  SilcClientEntry client;
  SilcNotifyType notify;
  const char *new_nick;
} WatcherNotifyContext;

static void 
silc_server_check_watcher_list_foreach(void *key, void *context, 
				       void *user_context)
{
  WatcherNotifyContext *notify = user_context;
  SilcClientEntry entry = context;
  SilcSocketConnection sock;

  if (entry == notify->client)
    return;

  sock = silc_server_get_client_route(notify->server, NULL, 0, entry->id,
				      NULL, NULL);
  if (sock) {
    SILC_LOG_DEBUG(("Sending WATCH notify to %s",
		    silc_id_render(entry->id, SILC_ID_CLIENT)));

    /* Send the WATCH notify */
    silc_server_send_notify_watch(notify->server, sock, entry, 
				  notify->client, 
				  notify->new_nick ? notify->new_nick :
				  (const char *)notify->client->nickname, 
				  notify->notify);
  }
}

/* This function checks whether the `client' nickname is being watched
   by someone, and notifies the watcher of the notify change of notify
   type indicated by `notify'. */

bool silc_server_check_watcher_list(SilcServer server,
				    SilcClientEntry client,
				    const char *new_nick,
				    SilcNotifyType notify)
{
  unsigned char hash[16];
  WatcherNotifyContext n;

  SILC_LOG_DEBUG(("Checking watcher list %s",
		  client->nickname ? client->nickname : (unsigned char *)""));

  /* If the watching is rejected by the client do nothing */
  if (client->mode & SILC_UMODE_REJECT_WATCHING)
    return FALSE;

  /* Make hash from the nick, or take it from Client ID */
  if (client->nickname) {
    char nick[128 + 1];
    memset(nick, 0, sizeof(nick));
    silc_to_lower(client->nickname, nick, sizeof(nick) - 1);
    silc_hash_make(server->md5hash, nick, strlen(nick), hash);
  } else {
    memset(hash, 0, sizeof(hash));
    memcpy(hash, client->id->hash, sizeof(client->id->hash));
  }

  n.server = server;
  n.client = client;
  n.new_nick = new_nick;
  n.notify = notify;

  /* Send notify to all watchers */
  silc_hash_table_find_foreach(server->watcher_list, hash,
			       silc_server_check_watcher_list_foreach, &n);

  return TRUE;
}

/* Remove the `client' from watcher list. After calling this the `client'
   is not watching any nicknames. */

bool silc_server_del_from_watcher_list(SilcServer server,
				       SilcClientEntry client)
{
  SilcHashTableList htl;
  void *key;
  SilcClientEntry entry;
  bool found = FALSE;

  silc_hash_table_list(server->watcher_list, &htl);
  while (silc_hash_table_get(&htl, &key, (void **)&entry)) {
    if (entry == client) {
      silc_hash_table_del_by_context(server->watcher_list, key, client);

      if (client->id)
	SILC_LOG_DEBUG(("Removing %s from WATCH list",
			silc_id_render(client->id, SILC_ID_CLIENT)));

      /* Now check whether there still exists entries with this key, if not
	 then free the key to not leak memory. */
      if (!silc_hash_table_find(server->watcher_list, key, NULL, NULL))
	silc_free(key);

      found = TRUE;
    }
  }
  silc_hash_table_list_reset(&htl);

  return found;
}

/* Force the client indicated by `chl' to change the channel user mode
   on channel indicated by `channel' to `forced_mode'. */

bool silc_server_force_cumode_change(SilcServer server,
				     SilcSocketConnection sock,
				     SilcChannelEntry channel,
				     SilcChannelClientEntry chl,
				     SilcUInt32 forced_mode)
{
  SilcBuffer idp1, idp2;
  unsigned char cumode[4];

  SILC_LOG_DEBUG(("Enforcing sender to change mode"));

  if (sock)
    silc_server_send_notify_cumode(server, sock, FALSE, channel, forced_mode,
				   server->id, SILC_ID_SERVER,
				   chl->client->id, NULL);

  idp1 = silc_id_payload_encode(server->id, SILC_ID_SERVER);
  idp2 = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
  SILC_PUT32_MSB(forced_mode, cumode);
  silc_server_send_notify_to_channel(server, sock, channel, FALSE,
				     SILC_NOTIFY_TYPE_CUMODE_CHANGE,
				     3, idp1->data, idp1->len,
				     cumode, sizeof(cumode),
				     idp2->data, idp2->len);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);

  return TRUE;
}

/* Find active socket connection by the IP address and port indicated by
   `ip' and `port', and socket connection type of `type'. */

SilcSocketConnection
silc_server_find_socket_by_host(SilcServer server,
				SilcSocketType type,
				const char *ip, SilcUInt16 port)
{
  int i;

  for (i = 0; i < server->config->param.connections_max; i++) {
    if (!server->sockets[i])
      continue;
    if (!strcmp(server->sockets[i]->ip, ip) &&
	(!port || server->sockets[i]->port == port) &&
	server->sockets[i]->type == type)
      return server->sockets[i];
  }

  return NULL;
}
