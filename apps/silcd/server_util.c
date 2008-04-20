/*

  server_util.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2008 Pekka Riikonen

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

  SILC_LOG_DEBUG(("Remove client %s from all channels",
		 client->nickname ? client->nickname :
		  (unsigned char *)""));

  if (silc_hash_table_find(clients, client, NULL, NULL))
    silc_hash_table_del(clients, client);

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    /* Remove channel if this is last client leaving the channel, unless
       the channel is permanent. */
    if (server->server_type != SILC_SERVER &&
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
    if (server->server_type == SILC_SERVER &&
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
    while (silc_hash_table_get(&htl2, NULL, (void *)&chl2)) {
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
  assert(!silc_hash_table_count(client->channels));
}

/* This function removes all client entries that are originated from
   `router' and are owned by `entry'.  `router' and `entry' can be same
   too.  If `server_signoff' is TRUE then SERVER_SIGNOFF notify is
   distributed to our local clients. */

SilcBool silc_server_remove_clients_by_server(SilcServer server,
					      SilcServerEntry router,
					      SilcServerEntry entry,
					      SilcBool server_signoff)
{
  SilcList list;
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
    argv[argc] = silc_calloc(silc_buffer_len(idp), sizeof(*argv[0]));
    memcpy(argv[argc], idp->data, silc_buffer_len(idp));
    argv_lens[argc] = silc_buffer_len(idp);
    argv_types[argc] = argc + 1;
    argc++;
    silc_buffer_free(idp);
  }

  if (silc_idcache_get_all(server->local_list->clients, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      client = (SilcClientEntry)id_cache->context;

      /* If client is not registered, is not originated from `router'
	 and is not owned by `entry', skip it. */
      if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	  client->router != router ||
	  (router != entry && !SILC_ID_COMPARE(client->id, entry->id,
					       client->id->ip.data_len))) {
	continue;
      }

      if (server_signoff) {
	idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
	if (idp) {
	  argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
	  argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) *
				   (argc + 1));
	  argv_types = silc_realloc(argv_types, sizeof(*argv_types) *
				    (argc + 1));
	  argv[argc] = silc_calloc(silc_buffer_len(idp), sizeof(*argv[0]));
	  memcpy(argv[argc], idp->data, silc_buffer_len(idp));
	  argv_lens[argc] = silc_buffer_len(idp);
	  argv_types[argc] = argc + 1;
	  argc++;
	  silc_buffer_free(idp);
	}
      }

      /* Update statistics */
      server->stat.clients--;
      if (server->stat.cell_clients)
	server->stat.cell_clients--;
      SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
      SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

      /* Remove client's public key from repository, this will free it too. */
      if (client->data.public_key) {
	silc_skr_del_public_key(server->repository, client->data.public_key,
				client);
	client->data.public_key = NULL;
      }

      silc_server_remove_clients_channels(server, entry, clients,
					  client, channels);
      silc_server_del_from_watcher_list(server, client);

      /* Remove the client entry */
      if (!server_signoff) {
	client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
	client->mode = 0;
	client->router = NULL;
	client->connection = NULL;
	silc_dlist_add(server->expired_clients, client);
      } else {
	silc_idlist_del_data(client);
	silc_idlist_del_client(server->local_list, client);
      }
    }
  }

  if (silc_idcache_get_all(server->global_list->clients, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      client = (SilcClientEntry)id_cache->context;

      /* If client is not registered, is not originated from `router'
	 and is not owned by `entry', skip it. */
      if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	  client->router != router ||
	  (router != entry && !SILC_ID_COMPARE(client->id, entry->id,
					       client->id->ip.data_len))) {
	continue;
      }

      if (server_signoff) {
	idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
	argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
	argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) *
				 (argc + 1));
	argv_types = silc_realloc(argv_types, sizeof(*argv_types) *
				  (argc + 1));
	argv[argc] = silc_calloc(silc_buffer_len(idp), sizeof(*argv[0]));
	memcpy(argv[argc], idp->data, silc_buffer_len(idp));
	argv_lens[argc] = silc_buffer_len(idp);
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

      /* Remove client's public key from repository, this will free it too. */
      if (client->data.public_key) {
	silc_skr_del_public_key(server->repository, client->data.public_key,
				client);
	client->data.public_key = NULL;
      }

      silc_server_remove_clients_channels(server, entry, clients,
					  client, channels);
      silc_server_del_from_watcher_list(server, client);

      /* Remove the client entry */
      if (!server_signoff) {
	client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
	client->mode = 0;
	client->router = NULL;
	client->connection = NULL;
	silc_dlist_add(server->expired_clients, client);
      } else {
	silc_idlist_del_data(client);
	silc_idlist_del_client(server->global_list, client);
      }
    }
  }

  /* Return now if we are shutting down */
  if (server->server_shutdown) {
    silc_hash_table_free(channels);

    if (server_signoff) {
      for (i = 0; i < argc; i++)
	silc_free(argv[i]);
      silc_free(argv);
      silc_free(argv_lens);
      silc_free(argv_types);
      silc_hash_table_free(clients);
    }
    return TRUE;
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
				    not->data, silc_buffer_len(not));

    /* Send notify also to local backup routers */
    silc_server_backup_send(server, NULL, SILC_PACKET_NOTIFY, 0,
			    not->data, silc_buffer_len(not), FALSE, TRUE);

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
  while (silc_hash_table_get(&htl, NULL, (void *)&channel)) {
    if (!silc_server_create_channel_key(server, channel, 0)) {
      silc_hash_table_list_reset(&htl);
      silc_hash_table_free(channels);
      return FALSE;
    }

    /* Do not send the channel key if private channel key mode is set */
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY || !channel->send_key)
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
					  SilcServerEntry to,
					  SilcClientEntry client,
					  SilcBool local,
					  SilcIDCacheEntry client_cache)
{
  SilcServerEntry server_entry;
  SilcIDCacheEntry id_cache = NULL;
  SilcList list;
  SilcBool tolocal = (to == server->id_entry);

  SILC_LOG_DEBUG(("Start"));

  if (!silc_idcache_get_all(server->local_list->servers, &list))
    return NULL;

  silc_list_start(list);
  while ((id_cache = silc_list_get(list))) {
    server_entry = (SilcServerEntry)id_cache->context;
    if (server_entry != from &&
	(tolocal || server_entry != server->id_entry) &&
	SILC_ID_COMPARE(server_entry->id, client->id,
			client->id->ip.data_len)) {
      SILC_LOG_DEBUG(("Found (local) %s",
		      silc_id_render(server_entry->id, SILC_ID_SERVER)));

      if (!SILC_IS_LOCAL(server_entry) && server_entry->router) {
	SILC_LOG_DEBUG(("Server not locally connected, use its router"));
	/* If the client is not marked as local then move it to local list
	   since the server is local. */
	if (!local) {
	  SILC_LOG_DEBUG(("Moving client to local list"));
	  silc_idcache_move(server->global_list->clients,
			    server->local_list->clients, client_cache);
	}
	server_entry = server_entry->router;
      } else {
	SILC_LOG_DEBUG(("Server locally connected"));
	/* If the client is not marked as local then move it to local list
	   since the server is local. */
	if (server_entry->server_type != SILC_BACKUP_ROUTER && !local) {
	  SILC_LOG_DEBUG(("Moving client to local list"));
	  silc_idcache_move(server->global_list->clients,
			    server->local_list->clients, client_cache);

	} else if (server->server_type == SILC_BACKUP_ROUTER && local) {
	  /* If we are backup router and this client is on local list, we
	     must move it to global list, as it is not currently local to
	     us (we are not primary). */
	  SILC_LOG_DEBUG(("Moving client to global list"));
	  silc_idcache_move(server->local_list->clients,
			    server->global_list->clients, client_cache);
	}
      }

      return server_entry;
    }
  }

  if (!silc_idcache_get_all(server->global_list->servers, &list))
    return NULL;

  silc_list_start(list);
  while ((id_cache = silc_list_get(list))) {
    server_entry = (SilcServerEntry)id_cache->context;
    if (server_entry != from && server_entry != server->id_entry &&
	(tolocal || server_entry != server->id_entry) &&
	SILC_ID_COMPARE(server_entry->id, client->id,
			client->id->ip.data_len)) {
      SILC_LOG_DEBUG(("Found (global) %s",
		      silc_id_render(server_entry->id, SILC_ID_SERVER)));

      if (!SILC_IS_LOCAL(server_entry) && server_entry->router) {
	SILC_LOG_DEBUG(("Server not locally connected, use its router"));
	/* If the client is marked as local then move it to global list
	   since the server is global. */
	if (local) {
	  SILC_LOG_DEBUG(("Moving client to global list"));
	  silc_idcache_move(server->local_list->clients,
			    server->global_list->clients, client_cache);
	}
	server_entry = server_entry->router;
      } else {
	SILC_LOG_DEBUG(("Server locally connected"));
	/* If the client is marked as local then move it to global list
	   since the server is global. */
	if (server_entry->server_type != SILC_BACKUP_ROUTER && local) {
	  SILC_LOG_DEBUG(("Moving client to global list"));
	  silc_idcache_move(server->local_list->clients,
			    server->global_list->clients, client_cache);
	}
      }
      return server_entry;
    }
  }

  return NULL;
}

/* Updates the clients that are originated from the `from' to be originated
   from the `to'. If the `resolve_real_server' is TRUE then this will
   attempt to figure out which clients really are originated from the
   `from' and which are originated from a server that we have connection
   to, when we've acting as backup router. If it is FALSE the `to' will
   be the new source. */

void silc_server_update_clients_by_server(SilcServer server,
					  SilcServerEntry from,
					  SilcServerEntry to,
					  SilcBool resolve_real_server)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  SilcBool local;

  if (from && from->id) {
    SILC_LOG_DEBUG(("Changing from server %s",
		    silc_id_render(from->id, SILC_ID_SERVER)));
  }
  if (to && to->id) {
    SILC_LOG_DEBUG(("Changing to server %s",
		    silc_id_render(to->id, SILC_ID_SERVER)));
  }

  SILC_LOG_DEBUG(("global list"));
  local = FALSE;
  if (silc_idcache_get_all(server->global_list->clients, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      client = (SilcClientEntry)id_cache->context;

      /* If entry is disabled skip it.  If entry is local to us, do not
	 switch it to anyone else, it is ours so skip it. */
      if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	  SILC_IS_LOCAL(client))
	continue;

      SILC_LOG_DEBUG(("Client %s",
		      silc_id_render(client->id, SILC_ID_CLIENT)));
      if (client->router && client->router->id)
	SILC_LOG_DEBUG(("Client->router %s",
			silc_id_render(client->router->id, SILC_ID_SERVER)));

      if (from) {
	if (client->router == from) {
	  if (resolve_real_server) {
	    client->router =
	      silc_server_update_clients_by_real_server(server, from, to,
							client, local,
							id_cache);
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
	if (resolve_real_server)
	  /* Call this so that the entry is moved to correct list if
	     needed.  No resolving by real server is actually done. */
	  silc_server_update_clients_by_real_server(server, NULL, to,
						    client, local,
						    id_cache);

	client->router = to;
      }

      if (client->router && client->router->id)
	SILC_LOG_DEBUG(("Client changed to %s",
			silc_id_render(client->router->id, SILC_ID_SERVER)));
    }
  }

  SILC_LOG_DEBUG(("local list"));
  local = TRUE;
  if (silc_idcache_get_all(server->local_list->clients, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      client = (SilcClientEntry)id_cache->context;

      /* If entry is disabled skip it.  If entry is local to us, do not
	 switch it to anyone else, it is ours so skip it. */
      if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	  SILC_IS_LOCAL(client))
	continue;

      SILC_LOG_DEBUG(("Client %s",
		      silc_id_render(client->id, SILC_ID_CLIENT)));
      if (client->router && client->router->id)
	SILC_LOG_DEBUG(("Client->router %s",
			silc_id_render(client->router->id, SILC_ID_SERVER)));

      if (from) {
	if (client->router == from) {
	  if (resolve_real_server) {
	    client->router =
	      silc_server_update_clients_by_real_server(server, from, to,
							client, local,
							id_cache);
	    if (!client->router)
	      client->router = from;
	  } else {
	    client->router = to;
	  }
	}
      } else {
	/* All are changed */
	if (resolve_real_server)
	  /* Call this so that the entry is moved to correct list if
	     needed.  No resolving by real server is actually done. */
	  silc_server_update_clients_by_real_server(server, NULL, to,
						    client, local,
						    id_cache);

	client->router = to;
      }

      if (client->router && client->router->id)
	SILC_LOG_DEBUG(("Client changed to %s",
			silc_id_render(client->router->id, SILC_ID_SERVER)));
    }
  }
}

/* Updates servers that are from `from' to be originated from `to'.  This
   will also update the server's connection to `to's connection. */

void silc_server_update_servers_by_server(SilcServer server,
					  SilcServerEntry from,
					  SilcServerEntry to)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server_entry = NULL;

  SILC_LOG_DEBUG(("Updating servers"));

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      server_entry = (SilcServerEntry)id_cache->context;

      /* If entry is local to us, do not switch it to any anyone else,
	 it is ours. */
      if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	  server_entry == from)
	continue;

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

	if (from) {
	  if (server_entry->router == from) {
	    SILC_LOG_DEBUG(("Updating server (local) %s",
			    server_entry->server_name ?
			    server_entry->server_name : ""));
	    server_entry->router = to;
	    server_entry->connection = to->connection;
	  }
	} else {
	  /* Update all */
	  SILC_LOG_DEBUG(("Updating server (local) %s",
			  server_entry->server_name ?
			  server_entry->server_name : ""));
	  server_entry->router = to;
	  server_entry->connection = to->connection;
	}
      }
    }
  }

  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      server_entry = (SilcServerEntry)id_cache->context;

      /* If entry is local to us, do not switch it to anyone else,
	 it is ours. */
      if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	  server_entry == from)
	continue;

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

	if (from) {
	  if (server_entry->router == from) {
	    SILC_LOG_DEBUG(("Updating server (global) %s",
			    server_entry->server_name ?
			    server_entry->server_name : ""));
	    server_entry->router = to;
	    server_entry->connection = to->connection;
	  }
	} else {
	  /* Update all */
	  SILC_LOG_DEBUG(("Updating server (global) %s",
			  server_entry->server_name ?
			  server_entry->server_name : ""));
	  server_entry->router = to;
	  server_entry->connection = to->connection;
	}
      }
    }
  }
}


/* Toggles the enabled/disabled status of local server connections.  Packets
   can be sent to the servers when `toggle_enabled' is TRUE and will be
   dropped if `toggle_enabled' is FALSE, after this function is called. */

void silc_server_local_servers_toggle_enabled(SilcServer server,
					      SilcBool toggle_enabled)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server_entry = NULL;

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (!SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry)
	continue;

      if (toggle_enabled)
	server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
      else
	server_entry->data.status |= SILC_IDLIST_STATUS_DISABLED;

    }
  }

  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (!SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry)
	continue;

      if (toggle_enabled)
	server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
      else
	server_entry->data.status |= SILC_IDLIST_STATUS_DISABLED;

    }
  }
}

/* Removes servers that are originated from the `from'.  The server
   entry is deleted in this function.  If `remove_clients' is TRUE then
   all clients originated from the server are removed too, and server
   signoff is sent.  Note that this does not remove the `from'.  This
   also does not remove locally connected servers. */

void silc_server_remove_servers_by_server(SilcServer server,
					  SilcServerEntry from,
					  SilcBool remove_clients)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcServerEntry server_entry = NULL;

  SILC_LOG_DEBUG(("Removing servers by %s",
		  from->server_name ? from->server_name : "server"));

  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	  server_entry->router != from || server_entry == from)
	continue;

      /* Remove clients owned by this server */
      if (remove_clients)
	silc_server_remove_clients_by_server(server, from, server_entry,
					     TRUE);

      /* Remove the server */
      silc_server_backup_del(server, server_entry);
      silc_idlist_del_server(server->local_list, server_entry);
    }
  }

  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      server_entry = (SilcServerEntry)id_cache->context;
      if (SILC_IS_LOCAL(server_entry) || server_entry == server->id_entry ||
	  server_entry->router != from || server_entry == from)
	continue;

      /* Remove clients owned by this server */
      if (remove_clients)
	silc_server_remove_clients_by_server(server, from, server_entry,
					     TRUE);

      /* Remove the server */
      silc_server_backup_del(server, server_entry);
      silc_idlist_del_server(server->global_list, server_entry);
    }
  }
}

/* Removes channels that are from `from. */

void silc_server_remove_channels_by_server(SilcServer server,
					   SilcServerEntry from)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel = NULL;

  SILC_LOG_DEBUG(("Removing channels by server"));

  if (silc_idcache_get_all(server->global_list->channels, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      channel = (SilcChannelEntry)id_cache->context;
      if (channel->router == from)
	silc_idlist_del_channel(server->global_list, channel);
    }
  }
}

/* Updates channels that are from `from' to be originated from `to'.  */

void silc_server_update_channels_by_server(SilcServer server,
					   SilcServerEntry from,
					   SilcServerEntry to)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel = NULL;

  SILC_LOG_DEBUG(("Updating channels by server"));

  if (silc_idcache_get_all(server->global_list->channels, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      channel = (SilcChannelEntry)id_cache->context;
      if (from) {
	if (channel->router == from)
	  channel->router = to;
      } else {
	/* Update all */
	channel->router = to;
      }
    }
  }
}

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */

SilcBool silc_server_channel_has_global(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
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

SilcBool silc_server_channel_has_local(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    if (SILC_IS_LOCAL(chl->client)) {
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

SilcBool silc_server_channel_delete(SilcServer server,
				    SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBool delchan = !(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH);

  SILC_LOG_DEBUG(("Deleting channel %s", channel->channel_name));

  if (delchan) {
    /* Update statistics */
    if (server->server_type == SILC_ROUTER)
      server->stat.chanclients -= channel->user_count;

    /* Totally delete the channel and all users on the channel. The
       users are deleted automatically in silc_idlist_del_channel. */
    channel->disabled = TRUE;
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

  SILC_LOG_DEBUG(("Channel %s remains (permanent)", channel->channel_name));

  return TRUE;
}

/* Returns TRUE if the given client is on the channel.  FALSE if not.
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from
   `client' which is faster than checking the user list from `channel'. */

SilcBool silc_server_client_on_channel(SilcClientEntry client,
				       SilcChannelEntry channel,
				       SilcChannelClientEntry *chl)
{
  if (!client || !channel)
    return FALSE;

  return silc_hash_table_find(client->channels, channel, NULL,
			      (void *)chl);
}

/* Find number of sockets by IP address indicated by `ip'. Returns 0 if
   socket connections with the IP address does not exist.  Counts only
   fully established connections. */

SilcUInt32 silc_server_num_sockets_by_ip(SilcServer server, const char *ip,
					 SilcConnectionType type)
{
  SilcServerConnection conn;
  SilcIDListData idata;
  const char *ipaddr;
  int count = 0;

  silc_dlist_start(server->conns);
  while ((conn = silc_dlist_get(server->conns))) {
    if (!conn->sock || !silc_packet_stream_is_valid(conn->sock))
      continue;
    silc_socket_stream_get_info(silc_packet_stream_get_stream(conn->sock),
				NULL, NULL, &ipaddr, NULL);
    idata = silc_packet_get_context(conn->sock);
    if (!strcmp(ipaddr, ip) && idata && idata->conn_type == type)
      count++;
  }

  return count;
}

/* Find active socket connection by the IP address and port indicated by
   `ip' and `port', and socket connection type of `type'. */

SilcPacketStream
silc_server_find_socket_by_host(SilcServer server,
				SilcConnectionType type,
				const char *ip, SilcUInt16 port)
{
  SilcServerConnection conn;
  SilcIDListData idata;
  const char *ipaddr;

  silc_dlist_start(server->conns);
  while ((conn = silc_dlist_get(server->conns))) {
    if (!conn->sock || !silc_packet_stream_is_valid(conn->sock))
      continue;
    idata = silc_packet_get_context(conn->sock);
    silc_socket_stream_get_info(silc_packet_stream_get_stream(conn->sock),
				NULL, NULL, &ipaddr, NULL);
    if (!strcmp(ipaddr, ip) &&
	(!port || conn->remote_port == port) &&
	idata->conn_type == type)
      return conn->sock;
  }

  return NULL;
}

/* Find number of sockets by IP address indicated by remote host, indicatd
   by `ip' or `hostname', `port', and `type'.  Returns 0 if socket connections
   does not exist. If `ip' is provided then `hostname' is ignored. */

SilcUInt32 silc_server_num_sockets_by_remote(SilcServer server,
					     const char *ip,
					     const char *hostname,
					     SilcUInt16 port,
					     SilcConnectionType type)
{
  SilcServerConnection conn;
  SilcIDListData idata;
  SilcConnectionType t = SILC_CONN_UNKNOWN;
  int count = 0;

  if (!ip && !hostname)
    return 0;

  SILC_LOG_DEBUG(("Num connections %d", silc_dlist_count(server->conns)));

  silc_dlist_start(server->conns);
  while ((conn = silc_dlist_get(server->conns))) {
    if (conn->sock) {
      idata = silc_packet_get_context(conn->sock);
      if (idata)
	t = idata->conn_type;
    }
    if (((ip && !strcmp(conn->remote_host, ip)) ||
	 (hostname && !strcmp(conn->remote_host, hostname))) &&
	conn->remote_port == port && t == type)
      count++;
  }

  return count;
}

/* SKR find callbcak */

static void find_callback(SilcSKR skr, SilcSKRFind find,
			  SilcSKRStatus status, SilcDList keys,
			  void *context)
{
  SilcPublicKey *public_key = context;
  SilcSKRKey key;

  if (keys) {
    silc_dlist_start(keys);
    key = silc_dlist_get(keys);
    *public_key = key->key;
    silc_dlist_uninit(keys);
  }

  silc_skr_find_free(find);
}

/* Get public key by key usage and key context. */

SilcPublicKey silc_server_get_public_key(SilcServer server,
					 SilcSKRKeyUsage usage,
					 void *key_context)
{
  SilcSKRFind find;
  SilcPublicKey public_key = NULL;

  SILC_LOG_DEBUG(("Start"));

  find = silc_skr_find_alloc();
  if (!find)
    return NULL;

  silc_skr_find_set_usage(find, usage);
  silc_skr_find_set_context(find, key_context);
  silc_skr_find(server->repository, server->schedule,
		find, find_callback, &public_key);

#ifdef SILC_DEBUG
  if (public_key)
    SILC_LOG_DEBUG(("Found public key"));
  else
    SILC_LOG_DEBUG(("Public key not found"));
#endif /* SILC_DEBUG */

  return public_key;
}

/* Find public key by client for identification purposes.  Finds keys
   with SILC_SKR_USAGE_IDENTIFICATION. */

SilcBool silc_server_get_public_key_by_client(SilcServer server,
					      SilcClientEntry client,
					      SilcPublicKey *public_key)
{
  SilcPublicKey pubkey = NULL;
  SilcBool ret = FALSE;

  pubkey = silc_server_get_public_key(server, SILC_SKR_USAGE_IDENTIFICATION,
				      client);
  if (pubkey)
    ret = TRUE;

  if (public_key)
    *public_key = pubkey;

  return ret;
}

/* Check whether the connection `sock' is allowed to connect to us.  This
   checks for example whether there is too much connections for this host,
   and required version for the host etc. */

SilcBool silc_server_connection_allowed(SilcServer server,
					SilcPacketStream sock,
					SilcConnectionType type,
					SilcServerConfigConnParams *global,
					SilcServerConfigConnParams *params,
					SilcSKE ske)
{
  SilcUInt32 conn_number = (type == SILC_CONN_CLIENT ?
			    server->stat.my_clients :
			    type == SILC_CONN_SERVER ?
			    server->stat.my_servers :
			    server->stat.my_routers);
  SilcUInt32 num_sockets, max_hosts, max_per_host;
  SilcUInt32 r_protocol_version, l_protocol_version;
  SilcUInt32 r_software_version, l_software_version;
  char *r_vendor_version = NULL, *l_vendor_version;
  const char *hostname, *ip;

  silc_socket_stream_get_info(silc_packet_stream_get_stream(sock),
			      NULL, &hostname, &ip, NULL);

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
    /* Match protocol version */
    if (l_protocol_version && r_protocol_version &&
	r_protocol_version < l_protocol_version) {
      SILC_LOG_INFO(("Connection %s (%s) is too old version",
		     hostname, ip));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_BAD_VERSION,
				    "You support too old protocol version");
      silc_server_free_sock_user_data(server, sock, NULL);
      return FALSE;
    }

    /* Math software version */
    if (l_software_version && r_software_version &&
	r_software_version < l_software_version) {
      SILC_LOG_INFO(("Connection %s (%s) is too old version",
		     hostname, ip));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_BAD_VERSION,
				    "You support too old software version");
      silc_server_free_sock_user_data(server, sock, NULL);
      return FALSE;
    }

    /* Regex match vendor version */
    if (l_vendor_version && r_vendor_version &&
	!silc_string_match(l_vendor_version, r_vendor_version)) {
      SILC_LOG_INFO(("Connection %s (%s) is unsupported version",
		     hostname, ip));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_BAD_VERSION,
				    "Your software is not supported");
      silc_server_free_sock_user_data(server, sock, NULL);
      return FALSE;
    }
  }
  silc_free(r_vendor_version);

  /* Check for maximum connections limit */

  num_sockets = silc_server_num_sockets_by_ip(server, ip, type);
  max_hosts = (params ? params->connections_max : global->connections_max);
  max_per_host = (params ? params->connections_max_per_host :
		  global->connections_max_per_host);

  if (max_hosts && conn_number >= max_hosts) {
    SILC_LOG_DEBUG(("Server is full, %d >= %d", conn_number, max_hosts));
    SILC_LOG_INFO(("Server is full, closing %s (%s) connection",
		   hostname, ip));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_RESOURCE_LIMIT,
				  "Server is full, try again later");
    silc_server_free_sock_user_data(server, sock, NULL);
    return FALSE;
  }

  if (num_sockets >= max_per_host) {
    SILC_LOG_DEBUG(("Too many connections, %d >= %d", num_sockets,
		    max_per_host));
    SILC_LOG_INFO(("Too many connections from %s (%s), closing connection",
		   hostname, ip));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_RESOURCE_LIMIT,
				  "Too many connections from your host");
    silc_server_free_sock_user_data(server, sock, NULL);
    return FALSE;
  }

  return TRUE;
}

/* Checks that client has rights to add or remove channel modes. If any
   of the checks fails FALSE is returned. */

SilcBool silc_server_check_cmode_rights(SilcServer server,
					SilcChannelEntry channel,
					SilcChannelClientEntry client,
					SilcUInt32 mode)
{
  SilcBool is_op = client->mode & SILC_CHANNEL_UMODE_CHANOP;
  SilcBool is_fo = client->mode & SILC_CHANNEL_UMODE_CHANFO;

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

  if (mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
    if (!(channel->mode & SILC_CHANNEL_MODE_CHANNEL_AUTH)) {
      if (is_op && !is_fo)
	return FALSE;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }

  return TRUE;
}

/* Check that the client has rights to change its user mode.  Returns
   FALSE if setting some mode is not allowed. */

SilcBool silc_server_check_umode_rights(SilcServer server,
					SilcClientEntry client,
					SilcUInt32 mode)
{
  SilcBool server_op = FALSE, router_op = FALSE;

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
				      SilcPacketStream sock,
				      SilcClientEntry client)
{
  SilcCipher key;

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
			     server->stat.clients, server->stat.servers,
			     server->stat.routers));
  } else {
    if (server->stat.clients && server->stat.servers + 1)
      SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			      ("There are %d clients, %d servers and %d "
			       "routers in SILC Network",
			       server->stat.clients, server->stat.servers,
			       (server->standalone ? 0 :
				!server->stat.routers ? 1 :
				server->stat.routers)));
  }

  if (server->stat.cell_clients && server->stat.cell_servers + 1)
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients on %d servers in our cell",
			     server->stat.cell_clients,
			     server->stat.cell_servers));
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

  silc_packet_get_keys(sock, &key, NULL, NULL, NULL);
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your connection is secured with %s cipher, "
			   "key length %d bits",
			   silc_cipher_get_name(key),
			   silc_cipher_get_key_len(key)));
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
				      3, killed->data, silc_buffer_len(killed),
				      comment, comment ? strlen(comment) : 0,
				      killer->data, silc_buffer_len(killer));

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
				   NULL, TRUE, TRUE);

  /* Remove the client entry, If it is locally connected then we will also
     disconnect the client here */
  if (remote_client->connection) {
    /* Remove locally conneted client */
    SilcPacketStream sock = remote_client->connection;
    silc_server_free_sock_user_data(server, sock, NULL);
    silc_server_close_connection(server, sock);
  } else {
    /* Update statistics */
    server->stat.clients--;
    if (server->stat.cell_clients)
      server->stat.cell_clients--;
    SILC_OPER_STATS_UPDATE(remote_client, server, SILC_UMODE_SERVER_OPERATOR);
    SILC_OPER_STATS_UPDATE(remote_client, router, SILC_UMODE_ROUTER_OPERATOR);

    /* Remove client's public key from repository, this will free it too. */
    if (remote_client->data.public_key) {
      silc_skr_del_public_key(server->repository,
			      remote_client->data.public_key, remote_client);
      remote_client->data.public_key = NULL;
    }

    if (SILC_IS_LOCAL(remote_client)) {
      server->stat.my_clients--;
      silc_schedule_task_del_by_context(server->schedule, remote_client);
    }

    /* Remove remote client */
    silc_idlist_del_data(remote_client);
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
  SilcPacketStream sock;

  if (!context)
    return;

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
				  notify->notify,
				  notify->client->data.public_key);
  }
}

/* This function checks whether the `client' nickname and/or 'client'
   public key is being watched by someone, and notifies the watcher of the
   notify change of notify type indicated by `notify'. */

SilcBool silc_server_check_watcher_list(SilcServer server,
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
    unsigned char *nickc;
    nickc = silc_identifier_check(client->nickname, strlen(client->nickname),
				  SILC_STRING_UTF8, 128, NULL);
    if (!nickc)
      return FALSE;
    silc_hash_make(server->md5hash, nickc, strlen(nickc), hash);
    silc_free(nickc);
  } else {
    memset(hash, 0, sizeof(hash));
    memcpy(hash, client->id->hash, sizeof(client->id->hash));
  }

  n.server = server;
  n.client = client;
  n.new_nick = new_nick;
  n.notify = notify;

  /* Send notify to all watchers watching this nickname */
  silc_hash_table_find_foreach(server->watcher_list, hash,
			       silc_server_check_watcher_list_foreach, &n);

  /* Send notify to all watchers watching this public key */
  if (client->data.public_key)
    silc_hash_table_find_foreach(server->watcher_list_pk,
				 client->data.public_key,
			         silc_server_check_watcher_list_foreach,
				 &n);

  return TRUE;
}

/* Remove the `client' from watcher list. After calling this the `client'
   is not watching any nicknames. */

SilcBool silc_server_del_from_watcher_list(SilcServer server,
					   SilcClientEntry client)
{
  SilcHashTableList htl;
  void *key;
  SilcClientEntry entry;
  SilcBool found = FALSE;

  silc_hash_table_list(server->watcher_list, &htl);
  while (silc_hash_table_get(&htl, &key, (void *)&entry)) {
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

  silc_hash_table_list(server->watcher_list_pk, &htl);
  while (silc_hash_table_get(&htl, &key, (void *)&entry)) {
    if (entry == client) {
      silc_hash_table_del_by_context(server->watcher_list_pk, key, client);

      if (client->id)
	SILC_LOG_DEBUG(("Removing %s from WATCH list",
			silc_id_render(client->id, SILC_ID_CLIENT)));

      /* Now check whether there still exists entries with this key, if not
	 then free the key to not leak memory. */
      if (!silc_hash_table_find(server->watcher_list_pk, key, NULL, NULL))
        silc_pkcs_public_key_free(key);

      found = TRUE;
    }
  }
  silc_hash_table_list_reset(&htl);

  return found;
}

/* Force the client indicated by `chl' to change the channel user mode
   on channel indicated by `channel' to `forced_mode'. */

SilcBool silc_server_force_cumode_change(SilcServer server,
					 SilcPacketStream sock,
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
  silc_server_send_notify_to_channel(server, sock, channel, FALSE, TRUE,
				     SILC_NOTIFY_TYPE_CUMODE_CHANGE,
				     3, idp1->data, silc_buffer_len(idp1),
				     cumode, sizeof(cumode),
				     idp2->data, silc_buffer_len(idp2));
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);

  return TRUE;
}

/* This function can be used to match the invite and ban lists. */

SilcBool silc_server_inviteban_match(SilcServer server, SilcHashTable list,
				     SilcUInt8 type, void *check)
{
  unsigned char *tmp = NULL;
  SilcUInt32 len = 0;
  SilcHashTableList htl;
  SilcBuffer entry, idp = NULL, pkp = NULL;
  SilcBool ret = FALSE;
  void *t;

  SILC_LOG_DEBUG(("Matching invite/ban"));

  if (type < 1 || type > 3 || !check)
    return FALSE;

  if (type == 1) {
    tmp = strdup((char *)check);
    if (!tmp)
      return FALSE;
  }
  if (type == 2) {
    pkp = silc_public_key_payload_encode(check);
    if (!pkp)
      return FALSE;
    tmp = pkp->data;
    len = silc_buffer_len(pkp);
  }
  if (type == 3) {
    idp = silc_id_payload_encode(check, SILC_ID_CLIENT);
    if (!idp)
      return FALSE;
    tmp = idp->data;
    len = silc_buffer_len(idp);
  }

  /* Compare the list */
  silc_hash_table_list(list, &htl);
  while (silc_hash_table_get(&htl, (void *)&t, (void *)&entry)) {
    if (type == SILC_PTR_TO_32(t)) {
      if (type == 1) {
	if (silc_string_match(entry->data, tmp)) {
	  ret = TRUE;
	  break;
	}
      } else if (silc_buffer_len(entry) == len &&
		 !memcmp(entry->data, tmp, len)) {
	ret = TRUE;
	break;
      }
    }
  }
  silc_hash_table_list_reset(&htl);

  if (type == 1)
    silc_free(tmp);
  silc_buffer_free(idp);
  silc_buffer_free(pkp);
  return ret;
}

/* Process invite or ban information */

SilcBool silc_server_inviteban_process(SilcServer server,
				       SilcHashTable list,
				       SilcUInt8 action,
				       SilcArgumentPayload args)
{
  unsigned char *tmp;
  SilcUInt32 type, len;
  void *ptype;
  SilcBuffer tmp2;
  SilcHashTableList htl;

  SILC_LOG_DEBUG(("Processing invite/ban for %s action",
		  action == 0x01 ? "DEL" : "ADD"));

  /* Add the information to invite list */
  if (action == 0x00 || action == 0x03) {
    /* Traverse all arguments and add to the hash table according to
       their type. */
    tmp = silc_argument_get_first_arg(args, &type, &len);
    while (tmp) {
      if (type == 1) {
	/* Check validity of the string.  Actually we should parse the
	   whole string and verify all components individually. */
	if (!silc_utf8_valid(tmp, len) || !len) {
	  tmp = silc_argument_get_next_arg(args, &type, &len);
	  continue;
	}
	if (strchr(tmp, ',')) {
	  tmp = silc_argument_get_next_arg(args, &type, &len);
	  continue;
	}

	/* Check if the string is added already */
	silc_hash_table_list(list, &htl);
	while (silc_hash_table_get(&htl, (void *)&ptype, (void *)&tmp2)) {
	  if (SILC_PTR_TO_32(ptype) == 1 &&
	      silc_string_match(tmp2->data, tmp)) {
	    tmp = NULL;
	    break;
	  }
	}
	silc_hash_table_list_reset(&htl);

	if (tmp) {
	  /* Add the string to hash table */
	  tmp2 = silc_buffer_alloc_size(len + 1);
	  if (tmp[len - 1] == ',')
	    tmp[len - 1] = '\0';
	  silc_buffer_put(tmp2, tmp, len);
	  silc_hash_table_add(list, (void *)1, tmp2);
	}

      } else if (type == 2) {
	/* Public key.  Check first if the public key is already on the
	   list and ignore it if it is, otherwise, add it to hash table. */
	SilcPublicKey pk;

	/* Verify validity of the public key */
	if (!silc_public_key_payload_decode(tmp, len, &pk)) {
	  tmp = silc_argument_get_next_arg(args, &type, &len);
	  continue;
	}
	silc_pkcs_public_key_free(pk);

	/* Check if the public key is in the list already */
	silc_hash_table_list(list, &htl);
	while (silc_hash_table_get(&htl, (void *)&ptype, (void *)&tmp2)) {
	  if (SILC_PTR_TO_32(ptype) == 2 && !memcmp(tmp2->data, tmp, len)) {
	    tmp = NULL;
	    break;
	  }
	}
	silc_hash_table_list_reset(&htl);

	/* Add new public key to invite list */
	if (tmp) {
	  tmp2 = silc_buffer_alloc_size(len);
	  silc_buffer_put(tmp2, tmp, len);
	  silc_hash_table_add(list, (void *)2, tmp2);
	}

      } else if (type == 3) {
	/* Client ID */

	/* Check if the ID is in the list already */
	silc_hash_table_list(list, &htl);
	while (silc_hash_table_get(&htl, (void *)&ptype, (void *)&tmp2)) {
	  if (SILC_PTR_TO_32(ptype) == 3 && !memcmp(tmp2->data, tmp, len)) {
	    tmp = NULL;
	    break;
	  }
	}
	silc_hash_table_list_reset(&htl);

	/* Add new Client ID to invite list */
	if (tmp) {
	  tmp2 = silc_buffer_alloc_size(len);
	  silc_buffer_put(tmp2, tmp, len);
	  silc_hash_table_add(list, (void *)3, tmp2);
	}
      }

      tmp = silc_argument_get_next_arg(args, &type, &len);
    }
  }

  /* Delete information to invite list */
  if (action == 0x01 && list) {
    /* Now delete the arguments from invite list */
    tmp = silc_argument_get_first_arg(args, &type, &len);
    while (tmp) {
      if (type == 1) {
	/* Check validity of the string.  Actually we should parse the
	   whole string and verify all components individually. */
	if (!silc_utf8_valid(tmp, len)) {
	  tmp = silc_argument_get_next_arg(args, &type, &len);
	  continue;
	}
	if (strchr(tmp, ',')) {
	  tmp = silc_argument_get_next_arg(args, &type, &len);
	  continue;
	}

	/* Delete from the list */
	silc_hash_table_list(list, &htl);
	while (silc_hash_table_get(&htl, (void *)&ptype, (void *)&tmp2)) {
	  if (SILC_PTR_TO_32(ptype) == 1 &&
	      silc_string_match(tmp2->data, tmp)) {
	    silc_hash_table_del_by_context(list, (void *)1, tmp2);
	    break;
	  }
	}
	silc_hash_table_list_reset(&htl);

      } else if (type == 2) {
	/* Public key. */
	SilcPublicKey pk;

	/* Verify validity of the public key */
	if (!silc_public_key_payload_decode(tmp, len, &pk)) {
	  tmp = silc_argument_get_next_arg(args, &type, &len);
	  continue;
	}
	silc_pkcs_public_key_free(pk);

	/* Delete from the invite list */
	silc_hash_table_list(list, &htl);
	while (silc_hash_table_get(&htl, (void *)&ptype, (void *)&tmp2)) {
	  if (SILC_PTR_TO_32(ptype) == 2 && !memcmp(tmp2->data, tmp, len)) {
	    silc_hash_table_del_by_context(list, (void *)2, tmp2);
	    break;
	  }
	}
	silc_hash_table_list_reset(&htl);

      } else if (type == 3) {
	/* Client ID */

	/* Delete from the invite list */
	silc_hash_table_list(list, &htl);
	while (silc_hash_table_get(&htl, (void *)&ptype, (void *)&tmp2)) {
	  if (SILC_PTR_TO_32(ptype) == 3 && !memcmp(tmp2->data, tmp, len)) {
	    silc_hash_table_del_by_context(list, (void *)3, tmp2);
	    break;
	  }
	}
	silc_hash_table_list_reset(&htl);
      }

      tmp = silc_argument_get_next_arg(args, &type, &len);
    }
  }

  return TRUE;
}

/* Destructor for invite and ban list entrys */

void silc_server_inviteban_destruct(void *key, void *context,
				    void *user_context)
{
  silc_buffer_free(context);
}

/* Creates connections accoring to configuration. */

void silc_server_create_connections(SilcServer server)
{
  silc_schedule_task_del_by_callback(server->schedule,
				     silc_server_connect_to_router);
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_connect_to_router, server, 1, 0);
}

static void
silc_server_process_channel_pk_destruct(void *key, void *context,
					void *user_context)
{
  silc_free(key);
  silc_pkcs_public_key_free(context);
}

/* Processes a channel public key, either adds or removes it. */

SilcStatus
silc_server_process_channel_pk(SilcServer server,
			       SilcChannelEntry channel,
			       SilcUInt32 type, const unsigned char *pk,
			       SilcUInt32 pk_len)
{
  unsigned char pkhash[20];
  SilcPublicKey chpk;

  SILC_LOG_DEBUG(("Processing channel public key"));

  if (!pk || !pk_len)
    return SILC_STATUS_ERR_NOT_ENOUGH_PARAMS;

  /* Decode the public key */
  if (!silc_public_key_payload_decode((unsigned char *)pk, pk_len, &chpk))
    return SILC_STATUS_ERR_UNSUPPORTED_PUBLIC_KEY;

  /* Create channel public key list (hash table) if needed */
  if (!channel->channel_pubkeys) {
    channel->channel_pubkeys =
      silc_hash_table_alloc(0, silc_hash_data, (void *)20,
			    silc_hash_data_compare, (void *)20,
			    silc_server_process_channel_pk_destruct, channel,
			    TRUE);
  }

  /* Create SHA-1 digest of the public key data */
  silc_hash_make(server->sha1hash, pk + 4, pk_len - 4, pkhash);

  if (type == 0x00) {
    /* Add new public key to channel public key list */
    SILC_LOG_DEBUG(("Add new channel public key to channel %s",
		    channel->channel_name));

    /* Check for resource limit */
    if (silc_hash_table_count(channel->channel_pubkeys) > 64) {
      silc_pkcs_public_key_free(chpk);
      return SILC_STATUS_ERR_RESOURCE_LIMIT;
    }

    /* Add if doesn't exist already */
    if (!silc_hash_table_find(channel->channel_pubkeys, pkhash,
			      NULL, NULL))
      silc_hash_table_add(channel->channel_pubkeys, silc_memdup(pkhash, 20),
			  chpk);
  } else if (type == 0x01) {
    /* Delete public key from channel public key list */
    SILC_LOG_DEBUG(("Delete a channel public key from channel %s",
		    channel->channel_name));
    if (!silc_hash_table_del(channel->channel_pubkeys, pkhash))
      silc_pkcs_public_key_free(chpk);
  } else {
    silc_pkcs_public_key_free(chpk);
    return SILC_STATUS_ERR_NOT_ENOUGH_PARAMS;
  }

  return SILC_STATUS_OK;
}

/* Returns the channel public keys as Argument List payload. */

SilcBuffer silc_server_get_channel_pk_list(SilcServer server,
					   SilcChannelEntry channel,
					   SilcBool announce,
					   SilcBool delete)
{
  SilcHashTableList htl;
  SilcBuffer list, pkp;
  SilcPublicKey pk;

  SILC_LOG_DEBUG(("Encoding channel public keys list"));

  if (!channel->channel_pubkeys ||
      !silc_hash_table_count(channel->channel_pubkeys))
    return NULL;

  /* Encode the list */
  list = silc_buffer_alloc_size(2);
  silc_buffer_format(list,
		     SILC_STR_UI_SHORT(silc_hash_table_count(
				       channel->channel_pubkeys)),
		     SILC_STR_END);

  silc_hash_table_list(channel->channel_pubkeys, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&pk)) {
    pkp = silc_public_key_payload_encode(pk);
    list = silc_argument_payload_encode_one(list, pkp->data,
					    silc_buffer_len(pkp),
					    announce ? 0x03 :
					    delete ? 0x01 : 0x00);
    silc_buffer_free(pkp);
  }
  silc_hash_table_list_reset(&htl);

  return list;
}

/* Sets the channel public keys into channel from the list of public keys. */

SilcStatus silc_server_set_channel_pk_list(SilcServer server,
					   SilcPacketStream sender,
					   SilcChannelEntry channel,
					   const unsigned char *pklist,
					   SilcUInt32 pklist_len)
{
  SilcUInt16 argc;
  SilcArgumentPayload args;
  unsigned char *chpk;
  SilcUInt32 chpklen, type;
  SilcStatus ret = SILC_STATUS_OK;

  SILC_LOG_DEBUG(("Setting channel public keys list"));

  if (!pklist || pklist_len < 2)
    return SILC_STATUS_ERR_NOT_ENOUGH_PARAMS;

  /* Get the argument from the Argument List Payload */
  SILC_GET16_MSB(argc, pklist);
  args = silc_argument_payload_parse(pklist + 2, pklist_len - 2, argc);
  if (!args)
    return SILC_STATUS_ERR_NOT_ENOUGH_PARAMS;

  /* Process the public keys one by one */
  chpk = silc_argument_get_first_arg(args, &type, &chpklen);

  /* If announcing keys and we have them set already, do not allow this */
  if (chpk && type == 0x03 && channel->channel_pubkeys &&
      server->server_type == SILC_ROUTER &&
      sender != SILC_PRIMARY_ROUTE(server)) {
    SILC_LOG_DEBUG(("Channel public key list set already, enforce our list"));
    silc_argument_payload_free(args);
    return SILC_STATUS_ERR_OPERATION_ALLOWED;
  }

  /* If we are normal server and receive announcement list and we already
     have keys set, we replace the old list with the announced one. */
  if (chpk && type == 0x03 && channel->channel_pubkeys &&
      server->server_type != SILC_ROUTER) {
    SilcBuffer sidp;
    unsigned char mask[4], ulimit[4];

    SILC_LOG_DEBUG(("Router enforces its list, remove old list"));
    silc_hash_table_free(channel->channel_pubkeys);
    channel->channel_pubkeys = NULL;

    /* Send notify that removes the old list */
    sidp = silc_id_payload_encode(server->id, SILC_ID_SERVER);
    SILC_PUT32_MSB((channel->mode & (~SILC_CHANNEL_MODE_CHANNEL_AUTH)), mask);
    if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
      SILC_PUT32_MSB(channel->user_limit, ulimit);
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
				       SILC_NOTIFY_TYPE_CMODE_CHANGE, 8,
				       sidp->data, silc_buffer_len(sidp),
				       mask, 4,
				       channel->cipher,
				       channel->cipher ?
				       strlen(channel->cipher) : 0,
				       channel->hmac_name,
				       channel->hmac_name ?
				       strlen(channel->hmac_name) : 0,
				       channel->passphrase,
				       channel->passphrase ?
				       strlen(channel->passphrase) : 0,
				       NULL, 0, NULL, 0,
				       (channel->mode &
					SILC_CHANNEL_MODE_ULIMIT ?
					ulimit : NULL),
				       (channel->mode &
					SILC_CHANNEL_MODE_ULIMIT ?
					sizeof(ulimit) : 0));
    silc_buffer_free(sidp);
  }

  while (chpk) {
    if (type == 0x03)
      type = 0x00;
    ret = silc_server_process_channel_pk(server, channel, type,
					 chpk, chpklen);
    if (ret != SILC_STATUS_OK)
      break;
    chpk = silc_argument_get_next_arg(args, &type, &chpklen);
  }

  silc_argument_payload_free(args);
  return ret;
}

/* Verifies the Authentication Payload `auth' with one of the public keys
   on the `channel' public key list. */

SilcBool silc_server_verify_channel_auth(SilcServer server,
					 SilcChannelEntry channel,
					 SilcClientID *client_id,
					 const unsigned char *auth,
					 SilcUInt32 auth_len)
{
  SilcAuthPayload ap;
  SilcPublicKey chpk;
  unsigned char *pkhash;
  SilcUInt32 pkhash_len;
  SilcBool ret = FALSE;

  SILC_LOG_DEBUG(("Verifying channel authentication"));

  if (!auth || !auth_len || !channel->channel_pubkeys)
    return FALSE;

  /* Get the hash from the auth data which tells us what public key we
     must use in verification. */

  ap = silc_auth_payload_parse(auth, auth_len);
  if (!ap)
    return FALSE;

  pkhash = silc_auth_get_public_data(ap, &pkhash_len);
  if (pkhash_len < 128)
    goto out;

  /* Find the public key with the hash */
  if (!silc_hash_table_find(channel->channel_pubkeys, pkhash,
			    NULL, (void *)&chpk)) {
    SILC_LOG_DEBUG(("Public key not found in channel public key list"));
    goto out;
  }

  /* Verify the signature */
  if (!silc_auth_verify(ap, SILC_AUTH_PUBLIC_KEY, (void *)chpk, 0,
			server->sha1hash, client_id, SILC_ID_CLIENT)) {
    SILC_LOG_DEBUG(("Authentication failed"));
    goto out;
  }

  ret = TRUE;

 out:
  silc_auth_payload_free(ap);
  return ret;
}
