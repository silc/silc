/*

  server.c 

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
/*
 * This is the actual SILC server than handles everything relating to
 * servicing the SILC connections. This is also a SILC router as a router
 * is also normal server.
 */
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

/* Static prototypes */
SILC_TASK_CALLBACK(silc_server_rehash_close_connection);
SILC_TASK_CALLBACK(silc_server_connect_to_router_retry);
SILC_TASK_CALLBACK(silc_server_connect_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router_second);
SILC_TASK_CALLBACK(silc_server_connect_to_router_final);
SILC_TASK_CALLBACK(silc_server_accept_new_connection);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_second);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_final);
SILC_TASK_CALLBACK(silc_server_packet_process);
SILC_TASK_CALLBACK(silc_server_packet_parse_real);
SILC_TASK_CALLBACK(silc_server_close_connection_final);
SILC_TASK_CALLBACK(silc_server_free_client_data_timeout);
SILC_TASK_CALLBACK(silc_server_timeout_remote);
SILC_TASK_CALLBACK(silc_server_channel_key_rekey);
SILC_TASK_CALLBACK(silc_server_get_stats);

/* Allocates a new SILC server object. This has to be done before the server
   can be used. After allocation one must call silc_server_init to initialize
   the server. The new allocated server object is returned to the new_server
   argument. */

int silc_server_alloc(SilcServer *new_server)
{
  SilcServer server;

  SILC_LOG_DEBUG(("Allocating new server object"));

  server = silc_calloc(1, sizeof(*server));
  server->server_type = SILC_SERVER;
  server->standalone = TRUE;
  server->local_list = silc_calloc(1, sizeof(*server->local_list));
  server->global_list = silc_calloc(1, sizeof(*server->global_list));
  server->pending_commands = silc_dlist_init();
#ifdef SILC_SIM
  server->sim = silc_dlist_init();
#endif

  *new_server = server;

  return TRUE;
}

/* Free's the SILC server object. This is called at the very end before
   the program ends. */

void silc_server_free(SilcServer server)
{
  SilcIDCacheList list;
  SilcIDCacheEntry cache;

  if (!server)
    return;

#ifdef SILC_SIM
  {
    SilcSim sim;
    silc_dlist_start(server->sim);
    while ((sim = silc_dlist_get(server->sim)) != SILC_LIST_END) {
      silc_dlist_del(server->sim, sim);
      silc_sim_close(sim);
      silc_sim_free(sim);
    }
    silc_dlist_uninit(server->sim);
  }
#endif

  silc_server_backup_free(server);
  silc_server_config_unref(&server->config_ref);
  if (server->rng)
    silc_rng_free(server->rng);
  if (server->pkcs)
    silc_pkcs_free(server->pkcs);
  if (server->public_key)
    silc_pkcs_public_key_free(server->public_key);
  if (server->private_key)
    silc_pkcs_private_key_free(server->private_key);
  if (server->pending_commands)
    silc_dlist_uninit(server->pending_commands);
  if (server->id_entry)
    silc_idlist_del_server(server->local_list, server->id_entry);

  /* Delete all channels */
  list = NULL;
  if (silc_idcache_get_all(server->local_list->channels, &list) &&
      silc_idcache_list_first(list, &cache)) {
    silc_idlist_del_channel(server->local_list, cache->context);
    while (silc_idcache_list_next(list, &cache))
      silc_idlist_del_channel(server->local_list, cache->context);
  }
  if (list)
    silc_idcache_list_free(list);
  list = NULL;
  if (silc_idcache_get_all(server->global_list->channels, &list) &&
      silc_idcache_list_first(list, &cache)) {
    silc_idlist_del_channel(server->global_list, cache->context);
    while (silc_idcache_list_next(list, &cache))
      silc_idlist_del_channel(server->global_list, cache->context);
  }
  if (list)
    silc_idcache_list_free(list);

  /* Delete all clients */
  list = NULL;
  if (silc_idcache_get_all(server->local_list->clients, &list) &&
      silc_idcache_list_first(list, &cache)) {
    silc_idlist_del_client(server->local_list, cache->context);
    while (silc_idcache_list_next(list, &cache))
      silc_idlist_del_client(server->local_list, cache->context);
  }
  if (list)
    silc_idcache_list_free(list);
  list = NULL;
  if (silc_idcache_get_all(server->global_list->clients, &list) &&
      silc_idcache_list_first(list, &cache)) {
    silc_idlist_del_client(server->global_list, cache->context);
    while (silc_idcache_list_next(list, &cache))
      silc_idlist_del_client(server->global_list, cache->context);
  }
  if (list)
    silc_idcache_list_free(list);

  /* Delete all servers */
  list = NULL;
  if (silc_idcache_get_all(server->local_list->servers, &list) &&
      silc_idcache_list_first(list, &cache)) {
    silc_idlist_del_server(server->local_list, cache->context);
    while (silc_idcache_list_next(list, &cache))
      silc_idlist_del_server(server->local_list, cache->context);
  }
  if (list)
    silc_idcache_list_free(list);
  list = NULL;
  if (silc_idcache_get_all(server->global_list->servers, &list) &&
      silc_idcache_list_first(list, &cache)) {
    silc_idlist_del_server(server->global_list, cache->context);
    while (silc_idcache_list_next(list, &cache))
      silc_idlist_del_server(server->global_list, cache->context);
  }
  if (list)
    silc_idcache_list_free(list);

  silc_idcache_free(server->local_list->clients);
  silc_idcache_free(server->local_list->servers);
  silc_idcache_free(server->local_list->channels);
  silc_idcache_free(server->global_list->clients);
  silc_idcache_free(server->global_list->servers);
  silc_idcache_free(server->global_list->channels);
  silc_hash_table_free(server->watcher_list);

  silc_hash_free(server->md5hash);
  silc_hash_free(server->sha1hash);
  silc_hmac_unregister_all();
  silc_hash_unregister_all();
  silc_cipher_unregister_all();
  silc_pkcs_unregister_all();

  silc_free(server->local_list);
  silc_free(server->global_list);
  silc_free(server->server_name);
  silc_free(server->id_string);
  silc_free(server->purge_i);
  silc_free(server->purge_g);
  silc_free(server);
}

/* Creates a new server listener. */

static bool silc_server_listen(SilcServer server, const char *server_ip,
			       SilcUInt16 port, int *sock)
{
  *sock = silc_net_create_server(port, server_ip);
  if (*sock < 0) {
    SILC_SERVER_LOG_ERROR(("Could not create server listener: %s on %hu",
			server_ip, port));
    return FALSE;
  }
  return TRUE;
}

/* Adds a secondary listener. */

bool silc_server_init_secondary(SilcServer server)
{
  int sock = 0, sock_list[server->config->param.connections_max];
  SilcSocketConnection newsocket = NULL;
  SilcServerConfigServerInfoInterface *interface;

  for (interface = server->config->server_info->secondary; interface; 
	interface = interface->next, sock++) {

    if (!silc_server_listen(server,
	interface->server_ip, interface->port, &sock_list[sock]))
      goto err;

    /* Set socket to non-blocking mode */
    silc_net_set_socket_nonblock(sock_list[sock]);

    /* Add ourselves also to the socket table. The entry allocated above
       is sent as argument for fast referencing in the future. */
    silc_socket_alloc(sock_list[sock],
		      SILC_SOCKET_TYPE_SERVER, NULL, &newsocket);
    server->sockets[sock_list[sock]] = newsocket;
    SILC_SET_LISTENER(newsocket);

    /* Perform name and address lookups to resolve the listenning address
       and port. */
    if (!silc_net_check_local_by_sock(sock_list[sock], &newsocket->hostname,
      			    &newsocket->ip)) {
      if ((server->config->require_reverse_lookup && !newsocket->hostname) ||
        !newsocket->ip) {
        SILC_LOG_ERROR(("IP/DNS lookup failed for local host %s",
        	      newsocket->hostname ? newsocket->hostname :
        	      newsocket->ip ? newsocket->ip : ""));
        server->stat.conn_failures++;
        goto err;
      }
      if (!newsocket->hostname)
        newsocket->hostname = strdup(newsocket->ip);
    }
    newsocket->port = silc_net_get_local_port(sock);

    newsocket->user_data = (void *)server->id_entry;
    silc_schedule_task_add(server->schedule, sock_list[sock],
			   silc_server_accept_new_connection,
			   (void *)server, 0, 0,
			   SILC_TASK_FD,
			   SILC_TASK_PRI_NORMAL);
  }

  return TRUE;

 err:
  do silc_net_close_server(sock_list[sock--]); while (sock >= 0);
  return FALSE;
}

/* Initializes the entire SILC server. This is called always before running
   the server. This is called only once at the initialization of the program.
   This binds the server to its listenning port. After this function returns
   one should call silc_server_run to start the server. This returns TRUE
   when everything is ok to run the server. Configuration file must be
   read and parsed before calling this. */

bool silc_server_init(SilcServer server)
{
  int sock;
  SilcServerID *id;
  SilcServerEntry id_entry;
  SilcIDListPurge purge;
  SilcSocketConnection newsocket = NULL;

  SILC_LOG_DEBUG(("Initializing server"));

  server->starttime = time(NULL);

  /* Take config object for us */
  silc_server_config_ref(&server->config_ref, server->config,
			 server->config);

  /* Steal public and private key from the config object */
  server->public_key = server->config->server_info->public_key;
  server->private_key = server->config->server_info->private_key;
  server->config->server_info->public_key = NULL;
  server->config->server_info->private_key = NULL;

  /* Register all configured ciphers, PKCS and hash functions. */
  if (!silc_server_config_register_ciphers(server))
    silc_cipher_register_default();
  if (!silc_server_config_register_pkcs(server))
    silc_pkcs_register_default();
  if (!silc_server_config_register_hashfuncs(server))
    silc_hash_register_default();
  if (!silc_server_config_register_hmacs(server))
    silc_hmac_register_default();

  /* Initialize random number generator for the server. */
  server->rng = silc_rng_alloc();
  silc_rng_init(server->rng);
  silc_rng_global_init(server->rng);

  /* Initialize hash functions for server to use */
  silc_hash_alloc("md5", &server->md5hash);
  silc_hash_alloc("sha1", &server->sha1hash);

  /* Allocate PKCS context for local public and private keys */
  if (!silc_pkcs_alloc(server->public_key->name, &server->pkcs))
    goto err;
  silc_pkcs_public_key_set(server->pkcs, server->public_key);
  silc_pkcs_private_key_set(server->pkcs, server->private_key);

  /* Initialize the scheduler */
  server->schedule = silc_schedule_init(server->config->param.connections_max,
					server);
  if (!server->schedule)
    goto err;

  /* First, register log files configuration for error output */
  silc_server_config_setlogfiles(server);

  /* Initialize ID caches */
  server->local_list->clients =
    silc_idcache_alloc(0, SILC_ID_CLIENT, silc_idlist_client_destructor);
  server->local_list->servers = silc_idcache_alloc(0, SILC_ID_SERVER, NULL);
  server->local_list->channels = silc_idcache_alloc(0, SILC_ID_CHANNEL, NULL);

  /* These are allocated for normal server as well as these hold some
     global information that the server has fetched from its router. For
     router these are used as they are supposed to be used on router. */
  server->global_list->clients =
    silc_idcache_alloc(0, SILC_ID_CLIENT, silc_idlist_client_destructor);
  server->global_list->servers = silc_idcache_alloc(0, SILC_ID_SERVER, NULL);
  server->global_list->channels = silc_idcache_alloc(0, SILC_ID_CHANNEL, NULL);

  /* Init watcher list */
  server->watcher_list =
    silc_hash_table_alloc(1, silc_hash_client_id_hash, NULL,
			  silc_hash_data_compare, (void *)CLIENTID_HASH_LEN,
			  NULL, NULL, TRUE);
  if (!server->watcher_list)
    goto err;

  /* Create a listening server */
  if (!silc_server_listen(server,
		server->config->server_info->primary == NULL ? NULL :
			server->config->server_info->primary->server_ip,
		server->config->server_info->primary == NULL ? 0 :
			server->config->server_info->primary->port,
		&sock))
    goto err;

  /* Set socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);
  server->sock = sock;

  /* Allocate the entire socket list that is used in server. Eventually
     all connections will have entry in this table (it is a table of
     pointers to the actual object that is allocated individually
     later). */
  server->sockets = silc_calloc(server->config->param.connections_max,
				sizeof(*server->sockets));
  if (!server->sockets)
    goto err;

  /* Add ourselves also to the socket table. The entry allocated above
     is sent as argument for fast referencing in the future. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_SERVER, NULL, &newsocket);
  server->sockets[sock] = newsocket;
  SILC_SET_LISTENER(newsocket);

  /* Perform name and address lookups to resolve the listenning address
     and port. */
  if (!silc_net_check_local_by_sock(sock, &newsocket->hostname,
				    &newsocket->ip)) {
    if ((server->config->require_reverse_lookup && !newsocket->hostname) ||
	!newsocket->ip) {
      SILC_LOG_ERROR(("IP/DNS lookup failed for local host %s",
		      newsocket->hostname ? newsocket->hostname :
		      newsocket->ip ? newsocket->ip : ""));
      server->stat.conn_failures++;
      goto err;
    }
    if (!newsocket->hostname)
      newsocket->hostname = strdup(newsocket->ip);
  }
  newsocket->port = silc_net_get_local_port(sock);

  /* Create a Server ID for the server. */
  silc_id_create_server_id(newsocket->ip, newsocket->port, server->rng, &id);
  if (!id)
    goto err;

  server->id = id;
  server->id_string = silc_id_id2str(id, SILC_ID_SERVER);
  server->id_string_len = silc_id_get_len(id, SILC_ID_SERVER);
  server->server_name = server->config->server_info->server_name;
  server->config->server_info->server_name = NULL;

  /* Add ourselves to the server list. We don't have a router yet
     beacuse we haven't established a route yet. It will be done later.
     For now, NULL is sent as router. This allocates new entry to
     the ID list. */
  id_entry =
    silc_idlist_add_server(server->local_list, strdup(server->server_name),
			   server->server_type, server->id, NULL, NULL);
  if (!id_entry) {
    SILC_LOG_ERROR(("Could not add ourselves to cache"));
    goto err;
  }
  id_entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;

  /* Put the allocated socket pointer also to the entry allocated above
     for fast back-referencing to the socket list. */
  newsocket->user_data = (void *)id_entry;
  id_entry->connection = (void *)newsocket;
  server->id_entry = id_entry;

  /* Register protocols */
  silc_server_protocols_register();

  /* Add the first task to the scheduler. This is task that is executed by
     timeout. It expires as soon as the caller calls silc_server_run. This
     task performs authentication protocol and key exchange with our
     primary router. */
  silc_server_create_connections(server);

  /* Add listener task to the scheduler. This task receives new connections
     to the server. This task remains on the queue until the end of the
     program. */
  silc_schedule_task_add(server->schedule, sock,
			 silc_server_accept_new_connection,
			 (void *)server, 0, 0,
			 SILC_TASK_FD,
			 SILC_TASK_PRI_NORMAL);

  if (silc_server_init_secondary(server) == FALSE)
    goto err;
  
  server->listenning = TRUE;

  /* If server connections has been configured then we must be router as
     normal server cannot have server connections, only router connections. */
  if (server->config->servers) {
    SilcServerConfigServer *ptr = server->config->servers;

    server->server_type = SILC_ROUTER;
    while (ptr) {
      if (ptr->backup_router) {
	server->server_type = SILC_BACKUP_ROUTER;
	server->backup_router = TRUE;
	server->id_entry->server_type = SILC_BACKUP_ROUTER;
	break;
      }
      ptr = ptr->next;
    }
  }

  /* Register the ID Cache purge task. This periodically purges the ID cache
     and removes the expired cache entries. */

  /* Clients local list */
  server->purge_i = purge = silc_calloc(1, sizeof(*purge));
  purge->cache = server->local_list->clients;
  purge->timeout = 600;
  silc_schedule_task_add(server->schedule, 0, silc_idlist_purge,
			 (void *)purge, purge->timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

  /* Clients global list */
  server->purge_g = purge = silc_calloc(1, sizeof(*purge));
  purge->cache = server->global_list->clients;
  purge->timeout = 300;
  silc_schedule_task_add(server->schedule, 0, silc_idlist_purge,
			 (void *)purge, purge->timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

  /* If we are normal server we'll retrieve network statisticial information
     once in a while from the router. */
  if (server->server_type != SILC_ROUTER)
    silc_schedule_task_add(server->schedule, 0, silc_server_get_stats,
			   server, 10, 0, SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);

  if (server->server_type == SILC_ROUTER)
    server->stat.routers++;

  SILC_LOG_DEBUG(("Server initialized"));

  /* We are done here, return succesfully */
  return TRUE;

 err:
  silc_server_config_unref(&server->config_ref);
  silc_net_close_server(sock);
  return FALSE;
}

/* Task callback to close a socket connection after rehash */

SILC_TASK_CALLBACK(silc_server_rehash_close_connection)
{
  SilcServer server = context;
  SilcSocketConnection sock = server->sockets[fd];

  if (!sock)
    return;

  SILC_LOG_INFO(("Connection %s:%d [%s] is unconfigured",
		 sock->hostname, sock->port,
		 (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
		  sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
		  sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
		  "Router")));
  silc_schedule_task_del_by_context(server->schedule, sock);
  silc_server_disconnect_remote(server, sock,
				SILC_STATUS_ERR_BANNED_FROM_SERVER,
				"This connection is removed from "
				"configuration");
  if (sock->user_data)
    silc_server_free_sock_user_data(server, sock, NULL);
}

/* This function basically reads the config file again and switches the config
   object pointed by the server object. After that, we have to fix various
   things such as the server_name and the listening ports.
   Keep in mind that we no longer have the root privileges at this point. */

bool silc_server_rehash(SilcServer server)
{
  SilcServerConfig newconfig;

  SILC_LOG_INFO(("Rehashing server"));

  /* Reset the logging system */
  silc_log_quick = TRUE;
  silc_log_flush_all();

  /* Start the main rehash phase (read again the config file) */
  newconfig = silc_server_config_alloc(server->config_file);
  if (!newconfig) {
    SILC_LOG_ERROR(("Rehash FAILED."));
    return FALSE;
  }

  /* Reinit scheduler if necessary */
  if (newconfig->param.connections_max > server->config->param.connections_max)
    if (!silc_schedule_reinit(server->schedule, 
			      newconfig->param.connections_max))
      return FALSE;

  /* Fix the server_name field */
  if (strcmp(server->server_name, newconfig->server_info->server_name)) {
    silc_free(server->server_name);
    server->server_name = newconfig->server_info->server_name;
    newconfig->server_info->server_name = NULL;

    /* Update the idcache list with a fresh pointer */
    silc_free(server->id_entry->server_name);
    server->id_entry->server_name = strdup(server->server_name);
    if (!silc_idcache_del_by_context(server->local_list->servers, 
				     server->id_entry))
      return FALSE;
    if (!silc_idcache_add(server->local_list->servers,
			  server->id_entry->server_name,
			  server->id_entry->id, server->id_entry, 0, NULL))
      return FALSE;
  }

  /* Set logging */
  silc_server_config_setlogfiles(server);

  /* Change new key pair if necessary */
  if (newconfig->server_info->public_key &&
      !silc_pkcs_public_key_compare(server->public_key,
				    newconfig->server_info->public_key)) {
    silc_pkcs_public_key_free(server->public_key);
    silc_pkcs_private_key_free(server->private_key);
    server->public_key = newconfig->server_info->public_key;
    server->private_key = newconfig->server_info->private_key;
    newconfig->server_info->public_key = NULL;
    newconfig->server_info->private_key = NULL;

    /* Allocate PKCS context for local public and private keys */
    silc_pkcs_free(server->pkcs);
    if (!silc_pkcs_alloc(server->public_key->name, &server->pkcs))
      return FALSE;
    silc_pkcs_public_key_set(server->pkcs, server->public_key);
    silc_pkcs_private_key_set(server->pkcs, server->private_key);
  }

  /* Check for unconfigured server and router connections and close
     connections that were unconfigured. */

  if (server->config->routers) {
    SilcServerConfigRouter *ptr;
    SilcServerConfigRouter *newptr;
    bool found;

    for (ptr = server->config->routers; ptr; ptr = ptr->next) {
      found = FALSE;

      /* Check whether new config has this one too */
      for (newptr = newconfig->routers; newptr; newptr = newptr->next) {
	if (silc_string_compare(newptr->host, ptr->host) && 
	    newptr->port == ptr->port &&
	    newptr->initiator == ptr->initiator) {
	  found = TRUE;
	  break;
	}
      }

      if (!found && ptr->host) {
	/* Remove this connection */
	SilcSocketConnection sock;
	sock = silc_server_find_socket_by_host(server, SILC_SOCKET_TYPE_ROUTER,
					       ptr->host, ptr->port);
	if (sock && !SILC_IS_LISTENER(sock))
	  silc_schedule_task_add(server->schedule, sock->sock,
				 silc_server_rehash_close_connection,
				 server, 0, 1, SILC_TASK_TIMEOUT,
				 SILC_TASK_PRI_NORMAL);
      }
    }
  }

  if (server->config->servers) {
    SilcServerConfigServer *ptr;
    SilcServerConfigServer *newptr;
    bool found;

    for (ptr = server->config->servers; ptr; ptr = ptr->next) {
      found = FALSE;

      /* Check whether new config has this one too */
      for (newptr = newconfig->servers; newptr; newptr = newptr->next) {
	if (silc_string_compare(newptr->host, ptr->host)) {
	  found = TRUE;
	  break;
	}
      }

      if (!found && ptr->host) {
	/* Remove this connection */
	SilcSocketConnection sock;
	sock = silc_server_find_socket_by_host(server, SILC_SOCKET_TYPE_SERVER,
					       ptr->host, 0);
	if (sock && !SILC_IS_LISTENER(sock))
	  silc_schedule_task_add(server->schedule, sock->sock,
				 silc_server_rehash_close_connection,
				 server, 0, 1, SILC_TASK_TIMEOUT,
				 SILC_TASK_PRI_NORMAL);
      }
    }
  }

  if (server->config->clients) {
    SilcServerConfigClient *ptr;
    SilcServerConfigClient *newptr;
    bool found;

    for (ptr = server->config->clients; ptr; ptr = ptr->next) {
      found = FALSE;

      /* Check whether new config has this one too */
      for (newptr = newconfig->clients; newptr; newptr = newptr->next) {
	if (silc_string_compare(newptr->host, ptr->host)) {
	  found = TRUE;
	  break;
	}
      }

      if (!found && ptr->host) {
	/* Remove this connection */
	SilcSocketConnection sock;
	sock = silc_server_find_socket_by_host(server, SILC_SOCKET_TYPE_CLIENT,
					       ptr->host, 0);
	if (sock)
	  silc_schedule_task_add(server->schedule, sock->sock,
				 silc_server_rehash_close_connection,
				 server, 0, 1, SILC_TASK_TIMEOUT,
				 SILC_TASK_PRI_NORMAL);
      }
    }
  }

  /* Create connections after rehash */
  silc_server_create_connections(server);

  /* Check whether our router status has changed */
  if (newconfig->servers) {
    SilcServerConfigServer *ptr = newconfig->servers;

    server->server_type = SILC_ROUTER;
    while (ptr) {
      if (ptr->backup_router) {
	server->server_type = SILC_BACKUP_ROUTER;
	server->backup_router = TRUE;
	server->id_entry->server_type = SILC_BACKUP_ROUTER;
	break;
      }
      ptr = ptr->next;
    }
  }

  /* Our old config is gone now. We'll unreference our reference made in
     silc_server_init and then destroy it since we are destroying it
     underneath the application (layer which called silc_server_init). */
  silc_server_config_unref(&server->config_ref);
  silc_server_config_destroy(server->config);

  /* Take new config context */
  server->config = newconfig;
  silc_server_config_ref(&server->config_ref, server->config, server->config);

  SILC_LOG_DEBUG(("Server rehashed"));

  return TRUE;
}

/* The heart of the server. This runs the scheduler thus runs the server.
   When this returns the server has been stopped and the program will
   be terminated. */

void silc_server_run(SilcServer server)
{
  SILC_LOG_INFO(("SILC Server started"));

  /* Start the scheduler, the heart of the SILC server. When this returns
     the program will be terminated. */
  silc_schedule(server->schedule);
}

/* Stops the SILC server. This function is used to shutdown the server.
   This is usually called after the scheduler has returned. After stopping
   the server one should call silc_server_free. */

void silc_server_stop(SilcServer server)
{
  SILC_LOG_INFO(("SILC Server shutting down"));

  if (server->schedule) {
    int i;

    server->server_shutdown = TRUE;

    /* Close all connections */
    for (i = 0; i < server->config->param.connections_max; i++) {
      if (!server->sockets[i])
	continue;
      if (!SILC_IS_LISTENER(server->sockets[i])) {
	SilcSocketConnection sock = server->sockets[i];
	SilcIDListData idata = sock->user_data;

	if (idata)
	  idata->status &= ~SILC_IDLIST_STATUS_DISABLED;

	silc_schedule_task_del_by_context(server->schedule,
					  server->sockets[i]);
	silc_server_disconnect_remote(server, server->sockets[i], 
				      SILC_STATUS_OK, 
				      "Server is shutting down");
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock,
					  "Server is shutting down");
	silc_socket_free(sock);
      } else {
	silc_socket_free(server->sockets[i]);
	server->sockets[i] = NULL;
      }
    }

    /* We are not connected to network anymore */
    server->standalone = TRUE;

    silc_schedule_stop(server->schedule);
    silc_schedule_uninit(server->schedule);
    server->schedule = NULL;

    silc_free(server->sockets);
    server->sockets = NULL;
  }

  silc_server_protocols_unregister();

  SILC_LOG_DEBUG(("Server stopped"));
}

/* Function that is called when the network connection to a router has
   been established.  This will continue with the key exchange protocol
   with the remote router. */

void silc_server_start_key_exchange(SilcServer server,
				    SilcServerConnection sconn,
				    int sock)
{
  SilcSocketConnection newsocket;
  SilcProtocol protocol;
  SilcServerKEInternalContext *proto_ctx;
  SilcServerConfigRouter *conn =
    (SilcServerConfigRouter *) sconn->conn.ref_ptr;
  void *context;

  /* Cancel any possible retry timeouts */
  silc_schedule_task_del_by_callback(server->schedule,
				     silc_server_connect_to_router_retry);

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* Create socket connection for the connection. Even though we
     know that we are connecting to a router we will mark the socket
     to be unknown connection until we have executed authentication
     protocol. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, NULL, &newsocket);
  server->sockets[sock] = newsocket;
  newsocket->hostname = strdup(sconn->remote_host);
  newsocket->ip = strdup(sconn->remote_host);
  newsocket->port = sconn->remote_port;
  sconn->sock = newsocket;

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->context = (void *)sconn;
  proto_ctx->sock = newsocket;
  proto_ctx->rng = server->rng;
  proto_ctx->responder = FALSE;

  /* Set Key Exchange flags from configuration, but fall back to global
     settings too. */
  SILC_GET_SKE_FLAGS(conn, proto_ctx);
  if (server->config->param.key_exchange_pfs)
    proto_ctx->flags |= SILC_SKE_SP_FLAG_PFS;

  /* Perform key exchange protocol. silc_server_connect_to_router_second
     will be called after the protocol is finished. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE,
		      &protocol, proto_ctx,
		      silc_server_connect_to_router_second);
  newsocket->protocol = protocol;

  /* Register a timeout task that will be executed if the protocol
     is not executed within set limit. */
  proto_ctx->timeout_task =
    silc_schedule_task_add(server->schedule, sock,
			   silc_server_timeout_remote,
			   server, server->config->key_exchange_timeout, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection
     and sets that outgoing packets may be sent to this connection as
     well. However, this doesn't set the scheduler for outgoing traffic,
     it will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)server;
  SILC_REGISTER_CONNECTION_FOR_IO(sock);

  /* Run the protocol */
  silc_protocol_execute(protocol, server->schedule, 0, 0);
}

/* Timeout callback that will be called to retry connecting to remote
   router. This is used by both normal and router server. This will wait
   before retrying the connecting. The timeout is generated by exponential
   backoff algorithm. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_retry)
{
  SilcServer server = app_context;
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServerConfigRouter *conn = sconn->conn.ref_ptr;
  SilcServerConfigConnParams *param =
		(conn->param ? conn->param : &server->config->param);

  /* Don't retry if we are shutting down. */
  if (server->server_shutdown) {
    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    return;
  }

  SILC_LOG_INFO(("Retrying connecting to a router"));

  /* Calculate next timeout */
  if (sconn->retry_count >= 1) {
    sconn->retry_timeout = sconn->retry_timeout * SILC_SERVER_RETRY_MULTIPLIER;
    if (sconn->retry_timeout > param->reconnect_interval_max)
      sconn->retry_timeout = param->reconnect_interval_max;
  } else {
    sconn->retry_timeout = param->reconnect_interval;
  }
  sconn->retry_count++;
  sconn->retry_timeout = sconn->retry_timeout +
    silc_rng_get_rn32(server->rng) % SILC_SERVER_RETRY_RANDOMIZER;

  /* If we've reached max retry count, give up. */
  if ((sconn->retry_count > param->reconnect_count) &&
      !param->reconnect_keep_trying) {
    SILC_LOG_ERROR(("Could not connect to router, giving up"));
    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    return;
  }

  SILC_LOG_DEBUG(("Retrying connecting to a router in %d seconds",
		  sconn->retry_timeout));

  /* We will lookup a fresh pointer later */
  silc_server_config_unref(&sconn->conn);

  /* Wait one before retrying */
  silc_schedule_task_add(server->schedule, 0, silc_server_connect_router,
			 context, sconn->retry_timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* Generic routine to use connect to a router. */

SILC_TASK_CALLBACK(silc_server_connect_router)
{
  SilcServer server = app_context;
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServerConfigRouter *rconn;
  int sock;

  /* Don't connect if we are shutting down. */
  if (server->server_shutdown) {
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    return;
  }

  SILC_LOG_INFO(("Connecting to the %s %s on port %d",
		 (sconn->backup ? "backup router" : "router"),
		 sconn->remote_host, sconn->remote_port));

  server->router_connect = time(NULL);
  rconn = silc_server_config_find_router_conn(server, sconn->remote_host,
					      sconn->remote_port);
  if (!rconn) {
    SILC_LOG_INFO(("Unconfigured %s connection %s:%d, cannot connect",
		   (sconn->backup ? "backup router" : "router"),
		   sconn->remote_host, sconn->remote_port));
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    return;
  }
  silc_server_config_ref(&sconn->conn, server->config, (void *)rconn);

  /* Connect to remote host */
  sock = silc_net_create_connection(
		 (!server->config->server_info->primary ? NULL :
		  server->config->server_info->primary->server_ip),
		 sconn->remote_port, sconn->remote_host);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not connect to router %s:%d",
		    sconn->remote_host, sconn->remote_port));
    if (!sconn->no_reconnect)
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_connect_to_router_retry,
			     context, 0, 1, SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
    else {
      silc_server_config_unref(&sconn->conn);
      silc_free(sconn->remote_host);
      silc_free(sconn->backup_replace_ip);
      silc_free(sconn);
    }
    return;
  }

  /* Continue with key exchange protocol */
  silc_server_start_key_exchange(server, sconn, sock);
}

/* This function connects to our primary router or if we are a router this
   establishes all our primary routes. This is called at the start of the
   server to do authentication and key exchange with our router - called
   from schedule. */

SILC_TASK_CALLBACK_GLOBAL(silc_server_connect_to_router)
{
  SilcServer server = (SilcServer)context;
  SilcServerConnection sconn;
  SilcServerConfigRouter *ptr;

  /* Don't connect if we are shutting down. */
  if (server->server_shutdown)
    return;

  SILC_LOG_DEBUG(("We are %s",
		  (server->server_type == SILC_SERVER ?
		   "normal server" : server->server_type == SILC_ROUTER ?
		   "router" : "backup router/normal server")));

  if (!server->config->routers) {
    /* There wasn't a configured router, we will continue but we don't
       have a connection to outside world.  We will be standalone server. */
    SILC_LOG_DEBUG(("No router(s), we are standalone"));
    server->standalone = TRUE;
    return;
  }

  /* Cancel any possible retry timeouts */
  silc_schedule_task_del_by_callback(server->schedule,
				     silc_server_connect_router);
  silc_schedule_task_del_by_callback(server->schedule,
				     silc_server_connect_to_router_retry);

  /* Create the connections to all our routes */
  for (ptr = server->config->routers; ptr; ptr = ptr->next) {

    SILC_LOG_DEBUG(("%s connection [%s] %s:%d",
		    ptr->backup_router ? "Backup router" : "Router",
		    ptr->initiator ? "Initiator" : "Responder",
		    ptr->host, ptr->port));

    if (server->server_type == SILC_ROUTER && ptr->backup_router &&
	ptr->initiator == FALSE && !server->backup_router &&
	!silc_server_config_get_backup_router(server))
      server->wait_backup = TRUE;

    if (ptr->initiator) {
      /* Check whether we are connecting or connected to this host already */
      if (silc_server_num_sockets_by_remote(server, 
					    silc_net_is_ip(ptr->host) ?
					    ptr->host : NULL,
					    silc_net_is_ip(ptr->host) ?
					    NULL : ptr->host, ptr->port,
					    SILC_SOCKET_TYPE_ROUTER)) {
	SILC_LOG_DEBUG(("We are already connected to this router"));
	continue;
      }
      if (silc_server_num_sockets_by_remote(server, 
					    silc_net_is_ip(ptr->host) ?
					    ptr->host : NULL,
					    silc_net_is_ip(ptr->host) ?
					    NULL : ptr->host, ptr->port,
					    SILC_SOCKET_TYPE_UNKNOWN)) {
	SILC_LOG_DEBUG(("We are already connecting to this router"));
	continue;
      }

      /* Allocate connection object for hold connection specific stuff. */
      sconn = silc_calloc(1, sizeof(*sconn));
      sconn->remote_host = strdup(ptr->host);
      sconn->remote_port = ptr->port;
      sconn->backup = ptr->backup_router;
      if (sconn->backup) {
	sconn->backup_replace_ip = strdup(ptr->backup_replace_ip);
	sconn->backup_replace_port = ptr->backup_replace_port;
      }

      if (!server->router_conn && !sconn->backup)
	server->router_conn = sconn;

      silc_schedule_task_add(server->schedule, 0,
			     silc_server_connect_router,
			     (void *)sconn, 0, 1, SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
    }
  }
}

/* Second part of connecting to router(s). Key exchange protocol has been
   executed and now we will execute authentication protocol. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_second)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx =
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcServerConnection sconn = (SilcServerConnection)ctx->context;
  SilcSocketConnection sock = ctx->sock;
  SilcServerConnAuthInternalContext *proto_ctx;
  SilcServerConfigRouter *conn = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);

    /* Try reconnecting if configuration wants it */
    if (!sconn->no_reconnect) {
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_connect_to_router_retry,
			     sconn, 0, 1, SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
      return;
    }

    /* Call completion to indicate error */
    if (sconn->callback)
      (*sconn->callback)(server, NULL, sconn->callback_context);

    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    return;
  }

  /* We now have the key material as the result of the key exchange
     protocol. Take the key material into use. Free the raw key material
     as soon as we've set them into use. */
  if (!silc_server_protocol_ke_set_keys(server, ctx->ske,
					ctx->sock, ctx->keymat,
					ctx->ske->prop->cipher,
					ctx->ske->prop->pkcs,
					ctx->ske->prop->hash,
					ctx->ske->prop->hmac,
					ctx->ske->prop->group,
					ctx->responder)) {
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);

    /* Try reconnecting if configuration wants it */
    if (!sconn->no_reconnect) {
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_connect_to_router_retry,
			     sconn, 0, 1, SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
      return;
    }

    /* Call completion to indicate error */
    if (sconn->callback)
      (*sconn->callback)(server, NULL, sconn->callback_context);

    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    return;
  }
  silc_ske_free_key_material(ctx->keymat);

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->context = (void *)sconn;
  proto_ctx->sock = sock;
  proto_ctx->ske = ctx->ske;	   /* Save SKE object from previous protocol */
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

  /* Resolve the authentication method used in this connection. Check if
     we find a match from user configured connections */
  if (!sconn->conn.ref_ptr)
    conn = silc_server_config_find_router_conn(server, sock->hostname,
					       sock->port);
  else
    conn = sconn->conn.ref_ptr;

  if (conn) {
    /* Match found. Use the configured authentication method. Take only
       the passphrase, since for public key auth we automatically use
       our local key pair. */
    if (conn->passphrase) {
      if (conn->publickeys && !server->config->prefer_passphrase_auth) {
	proto_ctx->auth_meth = SILC_AUTH_PUBLIC_KEY;
      } else {
	proto_ctx->auth_data = strdup(conn->passphrase);
	proto_ctx->auth_data_len = strlen(conn->passphrase);
	proto_ctx->auth_meth = SILC_AUTH_PASSWORD;
      }
    } else if (conn->publickeys) {
      proto_ctx->auth_meth = SILC_AUTH_PUBLIC_KEY;
    } else {
      proto_ctx->auth_meth = SILC_AUTH_NONE;
    }
  } else {
    SILC_LOG_ERROR(("Could not find connection data for %s (%s) on port",
		    sock->hostname, sock->ip, sock->port));
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx->dest_id);
    silc_free(ctx);
    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    return;
  }

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
  sock->protocol = NULL;

  /* Allocate the authentication protocol. This is allocated here
     but we won't start it yet. We will be receiving party of this
     protocol thus we will wait that connecting party will make
     their first move. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_CONNECTION_AUTH,
		      &sock->protocol, proto_ctx,
		      silc_server_connect_to_router_final);

  /* Register timeout task. If the protocol is not executed inside
     this timelimit the connection will be terminated. */
  proto_ctx->timeout_task =
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_timeout_remote,
			   (void *)server,
			   server->config->conn_auth_timeout, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);

  /* Run the protocol */
  silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
}

/* Finalizes the connection to router. Registers a server task to the
   queue so that we can accept new connections. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerConnAuthInternalContext *ctx =
    (SilcServerConnAuthInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcServerConnection sconn = (SilcServerConnection)ctx->context;
  SilcSocketConnection sock = ctx->sock;
  SilcServerEntry id_entry = NULL;
  SilcBuffer packet;
  unsigned char *id_string;
  SilcUInt32 id_len;
  SilcIDListData idata;
  SilcServerConfigRouter *conn = NULL;
  SilcServerConfigConnParams *param = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_free(ctx->dest_id);
    silc_server_disconnect_remote(server, sock, SILC_STATUS_ERR_AUTH_FAILED,
				  NULL);

    /* Try reconnecting if configuration wants it */
    if (!sconn->no_reconnect) {
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_connect_to_router_retry,
			     sconn, 0, 1, SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
      goto out2;
    }

    goto out;
  }

  /* Add a task to the queue. This task receives new connections to the
     server. This task remains on the queue until the end of the program. */
  if (!server->listenning && !sconn->backup) {
    silc_schedule_task_add(server->schedule, server->sock,
			   silc_server_accept_new_connection,
			   (void *)server, 0, 0,
			   SILC_TASK_FD,
			   SILC_TASK_PRI_NORMAL);
    server->listenning = TRUE;
  }

  /* Send NEW_SERVER packet to the router. We will become registered
     to the SILC network after sending this packet. */
  id_string = silc_id_id2str(server->id, SILC_ID_SERVER);
  id_len = silc_id_get_len(server->id, SILC_ID_SERVER);
  packet = silc_buffer_alloc(2 + 2 + id_len + strlen(server->server_name));
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(id_len),
		     SILC_STR_UI_XNSTRING(id_string, id_len),
		     SILC_STR_UI_SHORT(strlen(server->server_name)),
		     SILC_STR_UI_XNSTRING(server->server_name,
					  strlen(server->server_name)),
		     SILC_STR_END);

  /* Send the packet */
  silc_server_packet_send(server, ctx->sock, SILC_PACKET_NEW_SERVER, 0,
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);
  silc_free(id_string);

  SILC_LOG_INFO(("Connected to router %s", sock->hostname));

  /* Check that we do not have this ID already */
  id_entry = silc_idlist_find_server_by_id(server->local_list,
					   ctx->dest_id, TRUE, NULL);
  if (id_entry) {
    silc_idcache_del_by_context(server->local_list->servers, id_entry);
  } else {
    id_entry = silc_idlist_find_server_by_id(server->global_list,
					     ctx->dest_id, TRUE, NULL);
    if (id_entry)
      silc_idcache_del_by_context(server->global_list->servers, id_entry);
  }

  SILC_LOG_DEBUG(("New server id(%s)",
		  silc_id_render(ctx->dest_id, SILC_ID_SERVER)));

  /* Add the connected router to global server list.  Router is sent
     as NULL since it's local to us. */
  id_entry = silc_idlist_add_server(server->global_list,
				    strdup(sock->hostname),
				    SILC_ROUTER, ctx->dest_id, NULL, sock);
  if (!id_entry) {
    silc_free(ctx->dest_id);
    SILC_LOG_ERROR(("Cannot add new server entry to cache"));
    silc_server_disconnect_remote(server, sock, SILC_STATUS_ERR_AUTH_FAILED,
				  NULL);
    goto out;
  }

  silc_idlist_add_data(id_entry, (SilcIDListData)sock->user_data);
  silc_free(sock->user_data);
  sock->user_data = (void *)id_entry;
  sock->type = SILC_SOCKET_TYPE_ROUTER;
  idata = (SilcIDListData)sock->user_data;
  idata->status |= (SILC_IDLIST_STATUS_REGISTERED |
		    SILC_IDLIST_STATUS_LOCAL);

  conn = sconn->conn.ref_ptr;
  param = &server->config->param;
  if (conn && conn->param)
    param = conn->param;

  /* Perform keepalive. */
  silc_socket_set_heartbeat(sock, param->keepalive_secs, server,
			    silc_server_perform_heartbeat,
			    server->schedule);

  /* Register re-key timeout */
  idata->rekey->timeout = param->key_exchange_rekey;
  silc_schedule_task_add(server->schedule, sock->sock,
			 silc_server_rekey_callback,
			 (void *)sock, idata->rekey->timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  if (!sconn->backup) {
    /* Mark this router our primary router if we're still standalone */
    if (server->standalone) {
      SILC_LOG_DEBUG(("This connection is our primary router"));
      server->id_entry->router = id_entry;
      server->router = id_entry;
      server->standalone = FALSE;

      /* If we are router then announce our possible servers.  Backup
	 router announces also global servers. */
      if (server->server_type == SILC_ROUTER)
	silc_server_announce_servers(server,
				     server->backup_router ? TRUE : FALSE,
				     0, SILC_PRIMARY_ROUTE(server));

      /* Announce our clients and channels to the router */
      silc_server_announce_clients(server, 0, SILC_PRIMARY_ROUTE(server));
      silc_server_announce_channels(server, 0, SILC_PRIMARY_ROUTE(server));

      /* If we are backup router then this primary router is whom we are
	 backing up. */
      if (server->server_type == SILC_BACKUP_ROUTER)
	silc_server_backup_add(server, server->id_entry, sock->ip,
			       sconn->remote_port, TRUE);
    }
  } else {
    /* Add this server to be our backup router */
    silc_server_backup_add(server, id_entry, sconn->backup_replace_ip,
			   sconn->backup_replace_port, FALSE);
  }

  sock->protocol = NULL;

 out:
  /* Call the completion callback to indicate that we've connected to
     the router */
  if (sconn && sconn->callback)
    (*sconn->callback)(server, id_entry, sconn->callback_context);

  /* Free the temporary connection data context */
  if (sconn) {
    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
  }
  if (sconn == server->router_conn)
    server->router_conn = NULL;

 out2:
  /* Free the protocol object */
  if (sock->protocol == protocol)
    sock->protocol = NULL;
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  if (ctx->auth_meth == SILC_AUTH_PASSWORD)
    silc_free(ctx->auth_data);
  silc_free(ctx);
}

/* Host lookup callback that is called after the incoming connection's
   IP and FQDN lookup is performed. This will actually check the acceptance
   of the incoming connection and will register the key exchange protocol
   for this connection. */

static void
silc_server_accept_new_connection_lookup(SilcSocketConnection sock,
					 void *context)
{
  SilcServerKEInternalContext *proto_ctx =
    (SilcServerKEInternalContext *)context;
  SilcServer server = (SilcServer)proto_ctx->server;
  SilcServerConfigClient *cconfig = NULL;
  SilcServerConfigServer *sconfig = NULL;
  SilcServerConfigRouter *rconfig = NULL;
  SilcServerConfigDeny *deny;
  int port;

  /* Check whether we could resolve both IP and FQDN. */
  if (!sock->ip || (!strcmp(sock->ip, sock->hostname) &&
		    server->config->require_reverse_lookup)) {
    SILC_LOG_ERROR(("IP/DNS lookup failed %s",
		    sock->hostname ? sock->hostname :
		    sock->ip ? sock->ip : ""));
    server->stat.conn_failures++;
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  "Unknown host or IP");
    silc_free(proto_ctx);
    return;
  }

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it
     will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)server;
  SILC_REGISTER_CONNECTION_FOR_IO(sock->sock);

  SILC_LOG_INFO(("Incoming connection %s (%s)", sock->hostname,
		 sock->ip));

  /* Listenning port */
  if (!server->sockets[(SilcUInt32)proto_ctx->context]) {
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_RESOURCE_LIMIT,
				  "Connection refused");
    server->stat.conn_failures++;
    silc_free(proto_ctx);
    return;
  }
  port = server->sockets[(SilcUInt32)proto_ctx->context]->port;

  /* Check whether this connection is denied to connect to us. */
  deny = silc_server_config_find_denied(server, sock->ip);
  if (!deny)
    deny = silc_server_config_find_denied(server, sock->hostname);
  if (deny) {
    /* The connection is denied */
    SILC_LOG_INFO(("Connection %s (%s) is denied",
		   sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_BANNED_FROM_SERVER,
				  deny->reason);
    server->stat.conn_failures++;
    silc_free(proto_ctx);
    return;
  }

  /* Check whether we have configured this sort of connection at all. We
     have to check all configurations since we don't know what type of
     connection this is. */
  if (!(cconfig = silc_server_config_find_client(server, sock->ip)))
    cconfig = silc_server_config_find_client(server, sock->hostname);
  if (!(sconfig = silc_server_config_find_server_conn(server, sock->ip)))
    sconfig = silc_server_config_find_server_conn(server, sock->hostname);
  if (server->server_type == SILC_ROUTER) {
    if (!(rconfig = silc_server_config_find_router_conn(server,
							sock->ip, sock->port)))
      rconfig = silc_server_config_find_router_conn(server, sock->hostname,
						    sock->port);
  }
  if (!cconfig && !sconfig && !rconfig) {
    SILC_LOG_INFO(("Connection %s (%s) is not allowed", sock->hostname,
		   sock->ip));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_BANNED_FROM_SERVER, NULL);
    server->stat.conn_failures++;
    silc_free(proto_ctx);
    return;
  }

  /* The connection is allowed */

  /* Set internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx->sock = sock;
  proto_ctx->rng = server->rng;
  proto_ctx->responder = TRUE;
  silc_server_config_ref(&proto_ctx->cconfig, server->config, cconfig);
  silc_server_config_ref(&proto_ctx->sconfig, server->config, sconfig);
  silc_server_config_ref(&proto_ctx->rconfig, server->config, rconfig);

  /* Take flags for key exchange. Since we do not know what type of connection
     this is, we go through all found configurations and use the global ones
     as well. This will result always into strictest key exchange flags. */
  SILC_GET_SKE_FLAGS(cconfig, proto_ctx);
  SILC_GET_SKE_FLAGS(sconfig, proto_ctx);
  SILC_GET_SKE_FLAGS(rconfig, proto_ctx);
  if (server->config->param.key_exchange_pfs)
    proto_ctx->flags |= SILC_SKE_SP_FLAG_PFS;

  /* Prepare the connection for key exchange protocol. We allocate the
     protocol but will not start it yet. The connector will be the
     initiator of the protocol thus we will wait for initiation from
     there before we start the protocol. */
  server->stat.auth_attempts++;
  SILC_LOG_DEBUG(("Starting key exchange protocol"));
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE,
		      &sock->protocol, proto_ctx,
		      silc_server_accept_new_connection_second);

  /* Register a timeout task that will be executed if the connector
     will not start the key exchange protocol within specified timeout
     and the connection will be closed. */
  proto_ctx->timeout_task =
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_timeout_remote,
			   (void *)server,
			   server->config->key_exchange_timeout, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);
}

/* Accepts new connections to the server. Accepting new connections are
   done in three parts to make it async. */

SILC_TASK_CALLBACK(silc_server_accept_new_connection)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection newsocket;
  SilcServerKEInternalContext *proto_ctx;
  int sock;

  SILC_LOG_DEBUG(("Accepting new connection"));

  server->stat.conn_attempts++;

  sock = silc_net_accept_connection(fd);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not accept new connection: %s", strerror(errno)));
    server->stat.conn_failures++;
    return;
  }

  /* Check for maximum allowed connections */
  if (sock > server->config->param.connections_max) {
    SILC_LOG_ERROR(("Refusing connection, server is full"));
    server->stat.conn_failures++;
    silc_net_close_connection(sock);
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* We don't create a ID yet, since we don't know what type of connection
     this is yet. But, we do add the connection to the socket table. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, NULL, &newsocket);
  server->sockets[sock] = newsocket;

  /* Perform asynchronous host lookup. This will lookup the IP and the
     FQDN of the remote connection. After the lookup is done the connection
     is accepted further. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = server;
  proto_ctx->context = (void *)fd;
  silc_socket_host_lookup(newsocket, TRUE,
			  silc_server_accept_new_connection_lookup,
			  (void *)proto_ctx, server->schedule);
}

/* Second part of accepting new connection. Key exchange protocol has been
   performed and now it is time to do little connection authentication
   protocol to figure out whether this connection is client or server
   and whether it has right to access this server (especially server
   connections needs to be authenticated). */

SILC_TASK_CALLBACK(silc_server_accept_new_connection_second)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx =
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSocketConnection sock = ctx->sock;
  SilcServerConnAuthInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  if ((protocol->state == SILC_PROTOCOL_STATE_ERROR) ||
      (protocol->state == SILC_PROTOCOL_STATE_FAILURE)) {
    /* Error occured during protocol */
    SILC_LOG_DEBUG(("Error key exchange protocol"));
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx->dest_id);
    silc_server_config_unref(&ctx->cconfig);
    silc_server_config_unref(&ctx->sconfig);
    silc_server_config_unref(&ctx->rconfig);
    silc_free(ctx);
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED,
				  NULL);
    server->stat.auth_failures++;
    return;
  }

  /* We now have the key material as the result of the key exchange
     protocol. Take the key material into use. Free the raw key material
     as soon as we've set them into use. */
  if (!silc_server_protocol_ke_set_keys(server, ctx->ske,
					ctx->sock, ctx->keymat,
					ctx->ske->prop->cipher,
					ctx->ske->prop->pkcs,
					ctx->ske->prop->hash,
					ctx->ske->prop->hmac,
					ctx->ske->prop->group,
					ctx->responder)) {
    SILC_LOG_ERROR(("Error setting key material in use"));
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx->dest_id);
    silc_server_config_unref(&ctx->cconfig);
    silc_server_config_unref(&ctx->sconfig);
    silc_server_config_unref(&ctx->rconfig);
    silc_free(ctx);
    silc_server_disconnect_remote(server, sock, 
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    server->stat.auth_failures++;
    return;
  }
  silc_ske_free_key_material(ctx->keymat);

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = sock;
  proto_ctx->ske = ctx->ske;	/* Save SKE object from previous protocol */
  proto_ctx->responder = TRUE;
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;
  proto_ctx->cconfig = ctx->cconfig;
  proto_ctx->sconfig = ctx->sconfig;
  proto_ctx->rconfig = ctx->rconfig;

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
  sock->protocol = NULL;

  /* Allocate the authentication protocol. This is allocated here
     but we won't start it yet. We will be receiving party of this
     protocol thus we will wait that connecting party will make
     their first move. */
  SILC_LOG_DEBUG(("Starting connection authentication protocol"));
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_CONNECTION_AUTH,
		      &sock->protocol, proto_ctx,
		      silc_server_accept_new_connection_final);

  /* Register timeout task. If the protocol is not executed inside
     this timelimit the connection will be terminated. */
  proto_ctx->timeout_task =
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_timeout_remote,
			   (void *)server,
			   server->config->conn_auth_timeout, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);
}

/* After this is called, server don't wait for backup router anymore.  
   This gets called automatically even after we have backup router
   connection established. */

SILC_TASK_CALLBACK(silc_server_backup_router_wait)
{
  SilcServer server = context;
  server->wait_backup = FALSE;
}

/* Final part of accepting new connection. The connection has now
   been authenticated and keys has been exchanged. We also know whether
   this is client or server connection. */

SILC_TASK_CALLBACK(silc_server_accept_new_connection_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerConnAuthInternalContext *ctx =
    (SilcServerConnAuthInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSocketConnection sock = ctx->sock;
  SilcUnknownEntry entry = (SilcUnknownEntry)sock->user_data;
  void *id_entry;
  SilcServerConfigConnParams *param = &server->config->param;

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    SILC_LOG_DEBUG(("Error during authentication protocol"));
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx->dest_id);
    silc_server_config_unref(&ctx->cconfig);
    silc_server_config_unref(&ctx->sconfig);
    silc_server_config_unref(&ctx->rconfig);
    silc_free(ctx);
    silc_server_disconnect_remote(server, sock, SILC_STATUS_ERR_AUTH_FAILED,
				  NULL);
    server->stat.auth_failures++;
    return;
  }

  entry->data.last_receive = time(NULL);

  switch (ctx->conn_type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry client;
      SilcServerConfigClient *conn = ctx->cconfig.ref_ptr;

      /* Verify whether this connection is after all allowed to connect */
      if (!silc_server_connection_allowed(server, sock, ctx->conn_type,
					  &server->config->param,
					  conn->param, ctx->ske)) {
	server->stat.auth_failures++;
	goto out;
      }

      /* If we are primary router and we have backup router configured
	 but it has not connected to use yet, do not accept any other
	 connection. */
      if (server->wait_backup && server->server_type == SILC_ROUTER &&
	  !server->backup_router) {
	SilcServerConfigRouter *router;
	router = silc_server_config_get_backup_router(server);
	if (router && strcmp(server->config->server_info->primary->server_ip,
			     sock->ip) &&
	    silc_server_find_socket_by_host(server,
					    SILC_SOCKET_TYPE_SERVER,
					    router->backup_replace_ip, 0)) {
	  SILC_LOG_INFO(("Will not accept connections because we do "
			 "not have backup router connection established"));
	  silc_server_disconnect_remote(server, sock, 
					SILC_STATUS_ERR_PERM_DENIED,
					"We do not have connection to backup "
					"router established, try later");
	  silc_free(sock->user_data);
	  server->stat.auth_failures++;

	  /* From here on, wait 10 seconds for the backup router to appear. */
	  silc_schedule_task_add(server->schedule, 0,
				 silc_server_backup_router_wait,
				 (void *)server, 10, 0,
				 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
	  goto out;
	}
      }

      SILC_LOG_DEBUG(("Remote host is client"));
      SILC_LOG_INFO(("Connection %s (%s) is client", sock->hostname,
		     sock->ip));

      /* Add the client to the client ID cache. The nickname and Client ID
	 and other information is created after we have received NEW_CLIENT
	 packet from client. */
      client = silc_idlist_add_client(server->local_list,
				      NULL, NULL, NULL, NULL, NULL, sock, 0);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to cache"));
	silc_free(sock->user_data);
	silc_server_disconnect_remote(server, sock, 
				      SILC_STATUS_ERR_AUTH_FAILED, NULL);
	server->stat.auth_failures++;
	goto out;
      }
      entry->data.status |= SILC_IDLIST_STATUS_LOCAL;

      /* Statistics */
      server->stat.my_clients++;
      server->stat.clients++;
      server->stat.cell_clients++;

      /* Get connection parameters */
      if (conn->param) {
	param = conn->param;

	if (!param->keepalive_secs)
	  param->keepalive_secs = server->config->param.keepalive_secs;

	if (!param->qos && server->config->param.qos) {
	  param->qos = server->config->param.qos;
	  param->qos_rate_limit = server->config->param.qos_rate_limit;
	  param->qos_bytes_limit = server->config->param.qos_bytes_limit;
	  param->qos_limit_sec = server->config->param.qos_limit_sec;
	  param->qos_limit_usec = server->config->param.qos_limit_usec;
	}

	/* Check if to be anonymous connection */
	if (param->anonymous)
	  client->mode |= SILC_UMODE_ANONYMOUS;
      }

      id_entry = (void *)client;
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry new_server;
      bool initiator = FALSE;
      bool backup_local = FALSE;
      bool backup_router = FALSE;
      char *backup_replace_ip = NULL;
      SilcUInt16 backup_replace_port = 0;
      SilcServerConfigServer *sconn = ctx->sconfig.ref_ptr;
      SilcServerConfigRouter *rconn = ctx->rconfig.ref_ptr;

      /* If we are backup router and this is incoming server connection
	 and we do not have connection to primary router, do not allow
	 the connection. */
      if (server->server_type == SILC_BACKUP_ROUTER &&
	  ctx->conn_type == SILC_SOCKET_TYPE_SERVER &&
	  !SILC_PRIMARY_ROUTE(server)) {
	SILC_LOG_INFO(("Will not accept server connection because we do "
		       "not have primary router connection established"));
	silc_server_disconnect_remote(server, sock, 
				      SILC_STATUS_ERR_PERM_DENIED,
				      "We do not have connection to primary "
				      "router established, try later");
	silc_free(sock->user_data);
	server->stat.auth_failures++;
	goto out;
      }

      if (ctx->conn_type == SILC_SOCKET_TYPE_ROUTER) {
	/* Verify whether this connection is after all allowed to connect */
	if (!silc_server_connection_allowed(server, sock, ctx->conn_type,
					    &server->config->param,
					    rconn ? rconn->param : NULL,
					    ctx->ske)) {
	  silc_free(sock->user_data);
	  server->stat.auth_failures++;
	  goto out;
	}

	if (rconn) {
	  if (rconn->param) {
	    param = rconn->param;

	    if (!param->keepalive_secs)
	      param->keepalive_secs = server->config->param.keepalive_secs;

	    if (!param->qos && server->config->param.qos) {
	      param->qos = server->config->param.qos;
	      param->qos_rate_limit = server->config->param.qos_rate_limit;
	      param->qos_bytes_limit = server->config->param.qos_bytes_limit;
	      param->qos_limit_sec = server->config->param.qos_limit_sec;
	      param->qos_limit_usec = server->config->param.qos_limit_usec;
	    }
	  }

	  initiator = rconn->initiator;
	  backup_local = rconn->backup_local;
	  backup_router = rconn->backup_router;
	  backup_replace_ip = rconn->backup_replace_ip;
	  backup_replace_port = rconn->backup_replace_port;
	}
      }

      if (ctx->conn_type == SILC_SOCKET_TYPE_SERVER) {
	/* Verify whether this connection is after all allowed to connect */
	if (!silc_server_connection_allowed(server, sock, ctx->conn_type,
					    &server->config->param,
					    sconn ? sconn->param : NULL,
					    ctx->ske)) {
	  silc_free(sock->user_data);
	  server->stat.auth_failures++;
	  goto out;
	}
	if (sconn) {
	  if (sconn->param) {
	    param = sconn->param;

	    if (!param->keepalive_secs)
	      param->keepalive_secs = server->config->param.keepalive_secs;

	    if (!param->qos && server->config->param.qos) {
	      param->qos = server->config->param.qos;
	      param->qos_rate_limit = server->config->param.qos_rate_limit;
	      param->qos_bytes_limit = server->config->param.qos_bytes_limit;
	      param->qos_limit_sec = server->config->param.qos_limit_sec;
	      param->qos_limit_usec = server->config->param.qos_limit_usec;
	    }
	  }

	  backup_router = sconn->backup_router;
	}
      }

      /* If we are primary router and we have backup router configured
	 but it has not connected to use yet, do not accept any other
	 connection. */
      if (server->wait_backup && server->server_type == SILC_ROUTER &&
	  !server->backup_router && !backup_router) {
	SilcServerConfigRouter *router;
	router = silc_server_config_get_backup_router(server);
	if (router && strcmp(server->config->server_info->primary->server_ip,
			     sock->ip) &&
	    silc_server_find_socket_by_host(server,
					    SILC_SOCKET_TYPE_SERVER,
					    router->backup_replace_ip, 0)) {
	  SILC_LOG_INFO(("Will not accept connections because we do "
			 "not have backup router connection established"));
	  silc_server_disconnect_remote(server, sock, 
					SILC_STATUS_ERR_PERM_DENIED,
					"We do not have connection to backup "
					"router established, try later");
	  silc_free(sock->user_data);
	  server->stat.auth_failures++;

	  /* From here on, wait 10 seconds for the backup router to appear. */
	  silc_schedule_task_add(server->schedule, 0,
				 silc_server_backup_router_wait,
				 (void *)server, 10, 0,
				 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
	  goto out;
	}
      }

      SILC_LOG_DEBUG(("Remote host is %s",
		      ctx->conn_type == SILC_SOCKET_TYPE_SERVER ?
		      "server" : (backup_router ?
				  "backup router" : "router")));
      SILC_LOG_INFO(("Connection %s (%s) is %s", sock->hostname,
		     sock->ip, ctx->conn_type == SILC_SOCKET_TYPE_SERVER ?
		     "server" : (backup_router ?
				 "backup router" : "router")));

      /* Add the server into server cache. The server name and Server ID
	 is updated after we have received NEW_SERVER packet from the
	 server. We mark ourselves as router for this server if we really
	 are router. */
      new_server =
	silc_idlist_add_server((ctx->conn_type == SILC_SOCKET_TYPE_SERVER ?
				server->local_list : (backup_router ?
						      server->local_list :
						      server->global_list)),
			       NULL,
			       (ctx->conn_type == SILC_SOCKET_TYPE_SERVER ?
				SILC_SERVER : SILC_ROUTER),
			       NULL,
			       (ctx->conn_type == SILC_SOCKET_TYPE_SERVER ?
				server->id_entry : (backup_router ?
						    server->id_entry : NULL)),
			       sock);
      if (!new_server) {
	SILC_LOG_ERROR(("Could not add new server to cache"));
	silc_free(sock->user_data);
	silc_server_disconnect_remote(server, sock, 
				      SILC_STATUS_ERR_AUTH_FAILED, NULL);
	server->stat.auth_failures++;
	goto out;
      }
      entry->data.status |= SILC_IDLIST_STATUS_LOCAL;

      id_entry = (void *)new_server;

      /* If the incoming connection is router and marked as backup router
	 then add it to be one of our backups */
      if (ctx->conn_type == SILC_SOCKET_TYPE_ROUTER && backup_router) {
	/* Change it back to SERVER type since that's what it really is. */
	if (backup_local)
	  ctx->conn_type = SILC_SOCKET_TYPE_SERVER;
	new_server->server_type = SILC_BACKUP_ROUTER;

	SILC_SERVER_SEND_OPERS(server, FALSE, TRUE, SILC_NOTIFY_TYPE_NONE,
			       ("Backup router %s is now online",
				sock->hostname));

	/* Remove the backup waiting with timeout */
	silc_schedule_task_add(server->schedule, 0,
			       silc_server_backup_router_wait,
			       (void *)server, 5, 0,
			       SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
      }

      /* Statistics */
      if (ctx->conn_type == SILC_SOCKET_TYPE_SERVER) {
	server->stat.my_servers++;
      } else {
	server->stat.my_routers++;
	server->stat.routers++;
      }
      server->stat.servers++;

      /* Check whether this connection is to be our primary router connection
	 if we do not already have the primary route. */
      if (!backup_router &&
	  server->standalone && ctx->conn_type == SILC_SOCKET_TYPE_ROUTER) {
	if (silc_server_config_is_primary_route(server) && !initiator)
	  break;

	SILC_LOG_DEBUG(("We are not standalone server anymore"));
	server->standalone = FALSE;
	if (!server->id_entry->router) {
	  server->id_entry->router = id_entry;
	  server->router = id_entry;
	}
      }

      break;
    }
  default:
    goto out;
    break;
  }

  sock->type = ctx->conn_type;

  /* Add the common data structure to the ID entry. */
  silc_idlist_add_data(id_entry, (SilcIDListData)sock->user_data);

  /* Add to sockets internal pointer for fast referencing */
  silc_free(sock->user_data);
  sock->user_data = id_entry;

  /* Connection has been fully established now. Everything is ok. */
  SILC_LOG_DEBUG(("New connection authenticated"));

  /* Perform keepalive. */
  if (param->keepalive_secs)
    silc_socket_set_heartbeat(sock, param->keepalive_secs, server,
			      silc_server_perform_heartbeat,
			      server->schedule);

  /* Perform Quality of Service */
  if (param->qos)
    silc_socket_set_qos(sock, param->qos_rate_limit, param->qos_bytes_limit,
			param->qos_limit_sec, param->qos_limit_usec,
			server->schedule);

 out:
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx->dest_id);
  silc_server_config_unref(&ctx->cconfig);
  silc_server_config_unref(&ctx->sconfig);
  silc_server_config_unref(&ctx->rconfig);
  silc_free(ctx);
  sock->protocol = NULL;
}

/* This function is used to read packets from network and send packets to
   network. This is usually a generic task. */

SILC_TASK_CALLBACK(silc_server_packet_process)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = server->sockets[fd];
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  SilcUInt32 sequence = 0;
  bool local_is_router;
  int ret;

  if (!sock) {
    SILC_LOG_DEBUG(("Unknown socket connection"));
    return;
  }

  /* Packet sending */

  if (type == SILC_TASK_WRITE) {
    /* Do not send data to disconnected connection */
    if (SILC_IS_DISCONNECTED(sock)) {
      SILC_LOG_DEBUG(("Disconnected socket connection, cannot send"));
      return;
    }

    server->stat.packets_sent++;

    /* Send the packet */
    ret = silc_packet_send(sock, TRUE);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;

    /* The packet has been sent and now it is time to set the connection
       back to only for input. When there is again some outgoing data
       available for this connection it will be set for output as well.
       This call clears the output setting and sets it only for input. */
    SILC_SET_CONNECTION_FOR_INPUT(server->schedule, fd);
    SILC_UNSET_OUTBUF_PENDING(sock);
    silc_buffer_clear(sock->outbuf);

    if (ret == -1) {
      SILC_LOG_ERROR(("Error sending packet to connection "
		      "%s:%d [%s]", sock->hostname, sock->port,
		      (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
		       sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
		       sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
		       "Router")));

      SILC_SET_DISCONNECTING(sock);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_server_close_connection(server, sock);
    }
    return;
  }

  /* Packet receiving */

  /* Read some data from connection */
  ret = silc_packet_receive(sock);
  if (ret < 0) {

    if (ret == -1) {
      SILC_LOG_ERROR(("Error receiving packet from connection "
		      "%s:%d [%s] %s", sock->hostname, sock->port,
		      (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
		       sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
		       sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
		       "Router"), strerror(errno)));

      SILC_SET_DISCONNECTING(sock);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_server_close_connection(server, sock);
    }
    return;
  }

  /* EOF */
  if (ret == 0) {
    SILC_LOG_DEBUG(("Read EOF"));

    /* If connection is disconnecting already we will finally
       close the connection */
    if (SILC_IS_DISCONNECTING(sock)) {
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_server_close_connection(server, sock);
      return;
    }

    SILC_LOG_DEBUG(("Premature EOF from connection %d", sock->sock));
    SILC_SET_DISCONNECTING(sock);

    if (sock->user_data) {
      char tmp[128];
      if (silc_socket_get_error(sock, tmp, sizeof(tmp) - 1))
	silc_server_free_sock_user_data(server, sock, tmp);
      else
	silc_server_free_sock_user_data(server, sock, NULL);
    } else if (server->router_conn && server->router_conn->sock == sock &&
	       !server->router && server->standalone) {
      silc_server_create_connections(server);
    }

    silc_server_close_connection(server, sock);
    return;
  }

  /* If connection is disconnecting or disconnected we will ignore
     what we read. */
  if (SILC_IS_DISCONNECTING(sock) || SILC_IS_DISCONNECTED(sock)) {
    SILC_LOG_DEBUG(("Ignoring read data from disconnected connection"));
    return;
  }

  /* Get keys and stuff from ID entry */
  idata = (SilcIDListData)sock->user_data;
  if (idata) {
    cipher = idata->receive_key;
    hmac = idata->hmac_receive;
    sequence = idata->psn_receive;
  }

  /* Then, process the packet. This will call the parser that will then
     decrypt and parse the packet. */

  local_is_router = (server->server_type == SILC_ROUTER);

  /* If socket connection is our primary, we are backup and we are doing
     backup resuming, we won't process the packet as being a router 
     (affects channel message decryption). */
  if (server->backup_router && SILC_SERVER_IS_BACKUP(sock) &&
      SILC_PRIMARY_ROUTE(server) == sock)
    local_is_router = FALSE;

  ret = silc_packet_receive_process(sock, local_is_router,
			            cipher, hmac, sequence,
			            silc_server_packet_parse, server);

  /* If processing failed the connection is closed. */
  if (!ret) {
    /* On packet processing errors we may close our primary router 
       connection but won't become primary router if we are the backup
       since this is local error condition. */
    if (SILC_PRIMARY_ROUTE(server) == sock && server->backup_router)
      server->backup_noswitch = TRUE;

    if (sock->protocol && sock->protocol->protocol) {
      SILC_LOG_INFO(("Error during %d protocol",
		    sock->protocol->protocol->type));
    }

    SILC_SET_DISCONNECTING(sock);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    silc_server_close_connection(server, sock);
  }
}

/* Parses whole packet, received earlier. */

SILC_TASK_CALLBACK(silc_server_packet_parse_real)
{
  SilcPacketParserContext *parse_ctx = (SilcPacketParserContext *)context;
  SilcServer server = (SilcServer)parse_ctx->context;
  SilcSocketConnection sock = parse_ctx->sock;
  SilcPacketContext *packet = parse_ctx->packet;
  SilcIDListData idata = (SilcIDListData)sock->user_data;
  int ret;

  server->stat.packets_received++;

  /* Parse the packet */
  if (parse_ctx->normal)
    ret = silc_packet_parse(packet, idata ? idata->receive_key : NULL);
  else
    ret = silc_packet_parse_special(packet, idata ? idata->receive_key : NULL);

  /* If entry is disabled ignore what we got. */
  if (idata && idata->status & SILC_IDLIST_STATUS_DISABLED && 
      ret != SILC_PACKET_HEARTBEAT && ret != SILC_PACKET_RESUME_ROUTER &&
      ret != SILC_PACKET_REKEY && ret != SILC_PACKET_REKEY_DONE) {
    SILC_LOG_DEBUG(("Connection is disabled"));
    goto out;
  }

  if (ret == SILC_PACKET_NONE) {
    SILC_LOG_DEBUG(("Error parsing packet"));
    goto out;
  }

  /* Check that the the current client ID is same as in the client's packet. */
  if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
    SilcClientEntry client = (SilcClientEntry)sock->user_data;
    if (client && client->id && packet->src_id) {
      void *id = silc_id_str2id(packet->src_id, packet->src_id_len,
				packet->src_id_type);
      if (!id || !SILC_ID_CLIENT_COMPARE(client->id, id)) {
	silc_free(id);
	SILC_LOG_DEBUG(("Packet source is not same as sender"));
	goto out;
      }
      silc_free(id);
    }
  }

  if (server->server_type == SILC_ROUTER) {
    /* Route the packet if it is not destined to us. Other ID types but
       server are handled separately after processing them. */
    if (packet->dst_id && !(packet->flags & SILC_PACKET_FLAG_BROADCAST) &&
	packet->dst_id_type == SILC_ID_SERVER &&
	sock->type != SILC_SOCKET_TYPE_CLIENT &&
	memcmp(packet->dst_id, server->id_string, server->id_string_len)) {

      /* Route the packet to fastest route for the destination ID */
      void *id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				packet->dst_id_type);
      if (!id)
	goto out;
      silc_server_packet_route(server,
			       silc_server_route_get(server, id,
						     packet->dst_id_type),
			       packet);
      silc_free(id);
      goto out;
    }
  }

  /* Parse the incoming packet type */
  silc_server_packet_parse_type(server, sock, packet);

  /* Broadcast packet if it is marked as broadcast packet and it is
     originated from router and we are router. */
  if (server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_ROUTER &&
      packet->flags & SILC_PACKET_FLAG_BROADCAST) {
    /* Broadcast to our primary route */
    silc_server_packet_broadcast(server, SILC_PRIMARY_ROUTE(server), packet);

    /* If we have backup routers then we need to feed all broadcast
       data to those servers. */
    silc_server_backup_broadcast(server, sock, packet);
  }

 out:
  silc_packet_context_free(packet);
  silc_free(parse_ctx);
}

/* Parser callback called by silc_packet_receive_process. This merely
   registers timeout that will handle the actual parsing when appropriate. */

bool silc_server_packet_parse(SilcPacketParserContext *parser_context,
			      void *context)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = parser_context->sock;
  SilcIDListData idata = (SilcIDListData)sock->user_data;
  bool ret;

  if (idata)
    idata->psn_receive = parser_context->packet->sequence + 1;

  /* If protocol for this connection is key exchange or rekey then we'll
     process all packets synchronously, since there might be packets in
     queue that we are not able to decrypt without first processing the
     packets before them. */
  if ((parser_context->packet->type == SILC_PACKET_REKEY ||
       parser_context->packet->type == SILC_PACKET_REKEY_DONE) ||
      (sock->protocol && sock->protocol->protocol &&
       (sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE ||
	sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY))) {
    silc_server_packet_parse_real(server->schedule, server, 0, sock->sock,
				  parser_context);

    /* Reprocess data since we'll return FALSE here.  This is because
       the idata->receive_key might have become valid in the last packet
       and we want to call this processor with valid cipher. */
    if (idata)
      ret = silc_packet_receive_process(
				  sock, server->server_type == SILC_ROUTER,
				  idata->receive_key,
				  idata->hmac_receive, idata->psn_receive,
				  silc_server_packet_parse, server);
    else
      ret = silc_packet_receive_process(
				  sock, server->server_type == SILC_ROUTER,
				  NULL, NULL, 0,
				  silc_server_packet_parse, server);

    if (!ret) {
      /* On packet processing errors we may close our primary router 
         connection but won't become primary router if we are the backup
         since this is local error condition. */
      if (SILC_PRIMARY_ROUTE(server) == sock && server->backup_router)
	server->backup_noswitch = TRUE;

      SILC_SET_DISCONNECTING(sock);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_server_close_connection(server, sock);
    }

    return FALSE;
  }

  switch (sock->type) {
  case SILC_SOCKET_TYPE_UNKNOWN:
  case SILC_SOCKET_TYPE_CLIENT:
    /* Parse the packet with timeout */
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_packet_parse_real,
			   (void *)parser_context, 0, 100000,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    /* Packets from servers are parsed immediately */
    silc_server_packet_parse_real(server->schedule, server, 0, sock->sock,
				  parser_context);
    break;
  default:
    return TRUE;
  }

  return TRUE;
}

/* Parses the packet type and calls what ever routines the packet type
   requires. This is done for all incoming packets. */

void silc_server_packet_parse_type(SilcServer server,
				   SilcSocketConnection sock,
				   SilcPacketContext *packet)
{
  SilcPacketType type = packet->type;
  SilcIDListData idata = (SilcIDListData)sock->user_data;

  SILC_LOG_DEBUG(("Received %s packet [flags %d]",
		  silc_get_packet_name(type), packet->flags));

  /* Parse the packet type */
  switch (type) {
  case SILC_PACKET_DISCONNECT:
    {
      SilcStatus status;
      char *message = NULL;

      if (packet->flags & SILC_PACKET_FLAG_LIST)
	break;
      if (packet->buffer->len < 1)
	break;

      status = (SilcStatus)packet->buffer->data[0];
      if (packet->buffer->len > 1 &&
	  silc_utf8_valid(packet->buffer->data + 1, packet->buffer->len - 1))
	message = silc_memdup(packet->buffer->data + 1,
			      packet->buffer->len - 1);

      SILC_LOG_INFO(("Disconnected by %s (%s): %s (%d) %s", 
		     sock->ip, sock->hostname,
		     silc_get_status_message(status), status,
		     message ? message : ""));
      silc_free(message);

      /* Do not switch to backup in case of error */
      server->backup_noswitch = (status == SILC_STATUS_OK ? FALSE : TRUE);

      /* Handle the disconnection from our end too */
      SILC_SET_DISCONNECTING(sock);
      if (sock->user_data && SILC_IS_LOCAL(sock->user_data))
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_server_close_connection(server, sock);
      server->backup_noswitch = FALSE;
    }
    break;

  case SILC_PACKET_SUCCESS:
    /*
     * Success received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * success message is for whatever protocol is executing currently.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    if (sock->protocol)
      silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
    break;

  case SILC_PACKET_FAILURE:
    /*
     * Failure received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * failure message is for whatever protocol is executing currently.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    if (sock->protocol) {
      sock->protocol->state = SILC_PROTOCOL_STATE_FAILURE;
      silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
    }
    break;

  case SILC_PACKET_REJECT:
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    return;
    break;

  case SILC_PACKET_NOTIFY:
    /*
     * Received notify packet. Server can receive notify packets from
     * router. Server then relays the notify messages to clients if needed.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_notify_list(server, sock, packet);
    else
      silc_server_notify(server, sock, packet);
    break;

    /*
     * Channel packets
     */
  case SILC_PACKET_CHANNEL_MESSAGE:
    /*
     * Received channel message. Channel messages are special packets
     * (although probably most common ones) thus they are handled
     * specially.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    idata->last_receive = time(NULL);
    silc_server_channel_message(server, sock, packet);
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /*
     * Received key for channel. As channels are created by the router
     * the keys are as well. We will distribute the key to all of our
     * locally connected clients on the particular channel. Router
     * never receives this channel and thus is ignored.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_channel_key(server, sock, packet);
    break;

    /*
     * Command packets
     */
  case SILC_PACKET_COMMAND:
    /*
     * Recived command. Processes the command request and allocates the
     * command context and calls the command.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_command_process(server, sock, packet);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Received command reply packet. Received command reply to command. It
     * may be reply to command sent by us or reply to command sent by client
     * that we've routed further.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_command_reply(server, sock, packet);
    break;

    /*
     * Private Message packets
     */
  case SILC_PACKET_PRIVATE_MESSAGE:
    /*
     * Received private message packet. The packet is coming from either
     * client or server.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    idata->last_receive = time(NULL);
    silc_server_private_message(server, sock, packet);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /*
     * Private message key packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_private_message_key(server, sock, packet);
    break;

    /*
     * Key Exchange protocol packets
     */
  case SILC_PACKET_KEY_EXCHANGE:
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE) {
      SilcServerKEInternalContext *proto_ctx =
	(SilcServerKEInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      silc_protocol_execute(sock->protocol, server->schedule, 0, 100000);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_1:
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	(sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE ||
	 sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY)) {

      if (sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY) {
	SilcServerRekeyInternalContext *proto_ctx =
	  (SilcServerRekeyInternalContext *)sock->protocol->context;

	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);

	proto_ctx->packet = silc_packet_context_dup(packet);

	/* Let the protocol handle the packet */
	silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
      } else {
	SilcServerKEInternalContext *proto_ctx =
	  (SilcServerKEInternalContext *)sock->protocol->context;

	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);

	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;

	/* Let the protocol handle the packet */
	silc_protocol_execute(sock->protocol, server->schedule,
			      0, 100000);
      }
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 1 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_2:
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	(sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_KEY_EXCHANGE ||
	 sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY)) {

      if (sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY) {
	SilcServerRekeyInternalContext *proto_ctx =
	  (SilcServerRekeyInternalContext *)sock->protocol->context;

	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);

	proto_ctx->packet = silc_packet_context_dup(packet);

	/* Let the protocol handle the packet */
	silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
      } else {
	SilcServerKEInternalContext *proto_ctx =
	  (SilcServerKEInternalContext *)sock->protocol->context;

	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);

	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;

	/* Let the protocol handle the packet */
	silc_protocol_execute(sock->protocol, server->schedule,
			      0, 100000);
      }
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 2 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /*
     * Connection authentication request packet. When we receive this packet
     * we will send to the other end information about our mandatory
     * authentication method for the connection. This packet maybe received
     * at any time.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_connection_auth_request(server, sock, packet);
    break;

    /*
     * Connection Authentication protocol packets
     */
  case SILC_PACKET_CONNECTION_AUTH:
    /* Start of the authentication protocol. We receive here the
       authentication data and will verify it. */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol->type
	== SILC_PROTOCOL_SERVER_CONNECTION_AUTH) {

      SilcServerConnAuthInternalContext *proto_ctx =
	(SilcServerConnAuthInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Connection Auth packet but no authentication "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_NEW_ID:
    /*
     * Received New ID packet. This includes some new ID that has been
     * created. It may be for client, server or channel. This is the way
     * to distribute information about new registered entities in the
     * SILC network.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_id_list(server, sock, packet);
    else
      silc_server_new_id(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CLIENT:
    /*
     * Received new client packet. This includes client information that
     * we will use to create initial client ID. After creating new
     * ID we will send it to the client.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_new_client(server, sock, packet);
    break;

  case SILC_PACKET_NEW_SERVER:
    /*
     * Received new server packet. This includes Server ID and some other
     * information that we may save. This is received after server has
     * connected to us.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_new_server(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CHANNEL:
    /*
     * Received new channel packet. Information about new channel in the
     * network are distributed using this packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_channel_list(server, sock, packet);
    else
      silc_server_new_channel(server, sock, packet);
    break;

  case SILC_PACKET_HEARTBEAT:
    /*
     * Received heartbeat.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    break;

  case SILC_PACKET_KEY_AGREEMENT:
    /*
     * Received heartbeat.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_key_agreement(server, sock, packet);
    break;

  case SILC_PACKET_REKEY:
    /*
     * Received re-key packet. The sender wants to regenerate the session
     * keys.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_rekey(server, sock, packet);
    break;

  case SILC_PACKET_REKEY_DONE:
    /*
     * The re-key is done.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;

    if (sock->protocol && sock->protocol->protocol &&
	sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY) {

      SilcServerRekeyInternalContext *proto_ctx =
	(SilcServerRekeyInternalContext *)sock->protocol->context;

      if (proto_ctx->packet)
	silc_packet_context_free(proto_ctx->packet);

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Re-key done packet but no re-key "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_FTP:
    /* FTP packet */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_ftp(server, sock, packet);
    break;

  case SILC_PACKET_RESUME_CLIENT:
    /* Resume client */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_resume_client(server, sock, packet);
    break;

  case SILC_PACKET_RESUME_ROUTER:
    /* Resume router packet received. This packet is received for backup
       router resuming protocol. */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_backup_resume_router(server, sock, packet);
    break;

  default:
    SILC_LOG_ERROR(("Incorrect packet type %d, packet dropped", type));
    break;
  }
}

/* Creates connection to a remote router. */

void silc_server_create_connection(SilcServer server,
				   const char *remote_host, SilcUInt32 port)
{
  SilcServerConnection sconn;

  /* Allocate connection object for hold connection specific stuff. */
  sconn = silc_calloc(1, sizeof(*sconn));
  sconn->remote_host = strdup(remote_host);
  sconn->remote_port = port;
  sconn->no_reconnect = TRUE;

  silc_schedule_task_add(server->schedule, 0,
			 silc_server_connect_router,
			 (void *)sconn, 0, 1, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

SILC_TASK_CALLBACK(silc_server_close_connection_final)
{
  silc_socket_free(context);
}

/* Closes connection to socket connection */

void silc_server_close_connection(SilcServer server,
				  SilcSocketConnection sock)
{
  char tmp[128];

  if (!server->sockets[sock->sock] && SILC_IS_DISCONNECTED(sock)) {
    silc_schedule_unset_listen_fd(server->schedule, sock->sock);
    silc_schedule_task_del_by_fd(server->schedule, sock->sock);
    silc_net_close_connection(sock->sock);
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_close_connection_final,
			   (void *)sock, 0, 1, SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
    return;
  }

  memset(tmp, 0, sizeof(tmp));
  silc_socket_get_error(sock, tmp, sizeof(tmp));
  SILC_LOG_INFO(("Closing connection %s:%d [%s] %s", sock->hostname,
                  sock->port,
                  (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
                   sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
                   sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
                   "Router"), tmp[0] ? tmp : ""));

  /* Unregister all tasks */
  silc_schedule_task_del_by_fd(server->schedule, sock->sock);

  server->sockets[sock->sock] = NULL;

  /* If sock->user_data is NULL then we'll check for active protocols
     here since the silc_server_free_sock_user_data has not been called
     for this connection. */
  if (!sock->user_data) {
    /* If any protocol is active cancel its execution. It will call
       the final callback which will finalize the disconnection. */
    if (sock->protocol && sock->protocol->protocol &&
	sock->protocol->protocol->type != SILC_PROTOCOL_SERVER_BACKUP) {
      SILC_LOG_DEBUG(("Cancelling protocol, calling final callback"));
      silc_protocol_cancel(sock->protocol, server->schedule);
      sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
      silc_protocol_execute_final(sock->protocol, server->schedule);
      sock->protocol = NULL;
      return;
    }
  }

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(server->schedule, sock->sock);

  silc_schedule_task_add(server->schedule, sock->sock,
			 silc_server_close_connection_final,
			 (void *)sock, 0, 1, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Sends disconnect message to remote connection and disconnects the
   connection. */

void silc_server_disconnect_remote(SilcServer server,
				   SilcSocketConnection sock,
				   SilcStatus status, ...)
{
  va_list ap;
  unsigned char buf[512];
  SilcBuffer buffer;
  char *cp;
  int len;

  if (!sock)
    return;

  if (SILC_IS_DISCONNECTED(sock)) {
    silc_server_close_connection(server, sock);
    return;
  }

  memset(buf, 0, sizeof(buf));
  va_start(ap, status);
  cp = va_arg(ap, char *);
  if (cp) {
    vsnprintf(buf, sizeof(buf) - 1, cp, ap);
    cp = buf;
  }
  va_end(ap);

  SILC_LOG_DEBUG(("Disconnecting remote host"));

  /* Notify remote end that the conversation is over. The notify message
     is tried to be sent immediately. */

  len = 1;
  if (cp)
    len += silc_utf8_encoded_len(buf, strlen(buf), SILC_STRING_ASCII);

  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    goto out;

  buffer->data[0] = status;
  if (cp)
    silc_utf8_encode(buf, strlen(buf), SILC_STRING_ASCII, buffer->data + 1,
		     buffer->len - 1);
  silc_server_packet_send(server, sock, SILC_PACKET_DISCONNECT, 0,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

 out:
  silc_server_packet_queue_purge(server, sock);

  /* Mark the connection to be disconnected */
  SILC_SET_DISCONNECTED(sock);
  silc_server_close_connection(server, sock);
}

SILC_TASK_CALLBACK(silc_server_free_client_data_timeout)
{
  SilcServer server = app_context;
  SilcClientEntry client = context;

  assert(!silc_hash_table_count(client->channels));

  silc_idlist_del_data(client);
  silc_idcache_purge_by_context(server->local_list->clients, client);
}

/* Frees client data and notifies about client's signoff. */

void silc_server_free_client_data(SilcServer server,
				  SilcSocketConnection sock,
				  SilcClientEntry client,
				  int notify,
				  const char *signoff)
{
  SILC_LOG_DEBUG(("Freeing client data"));

  /* If there is pending outgoing data for the client then purge it
     to the network before removing the client entry. */
  silc_server_packet_queue_purge(server, sock);

  if (client->id) {
    /* Check if anyone is watching this nickname */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_SIGNOFF);

    /* Send SIGNOFF notify to routers. */
    if (notify)
      silc_server_send_notify_signoff(server, SILC_PRIMARY_ROUTE(server),
				      SILC_BROADCAST(server), client->id,
				      signoff);
  }

  /* Remove client from all channels */
  if (notify)
    silc_server_remove_from_channels(server, NULL, client,
				     TRUE, (char *)signoff, TRUE, FALSE);
  else
    silc_server_remove_from_channels(server, NULL, client,
				     FALSE, NULL, FALSE, FALSE);

  /* Remove this client from watcher list if it is */
  silc_server_del_from_watcher_list(server, client);

  /* Update statistics */
  server->stat.my_clients--;
  server->stat.clients--;
  if (server->stat.cell_clients)
    server->stat.cell_clients--;
  SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
  SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);
  silc_schedule_task_del_by_context(server->schedule, client);

  /* We will not delete the client entry right away. We will take it
     into history (for WHOWAS command) for 5 minutes, unless we're
     shutting down server. */
  if (!server->server_shutdown) {
    silc_schedule_task_add(server->schedule, 0,
			   silc_server_free_client_data_timeout,
			   client, 300, 0,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
    client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
    client->data.status &= ~SILC_IDLIST_STATUS_LOCAL;
    client->mode = 0;
    client->router = NULL;
    client->connection = NULL;
  } else {
    /* Delete directly since we're shutting down server */
    silc_idlist_del_data(client);
    silc_idlist_del_client(server->local_list, client);
  }
}

/* Frees user_data pointer from socket connection object. This also sends
   appropriate notify packets to the network to inform about leaving
   entities. */

void silc_server_free_sock_user_data(SilcServer server,
				     SilcSocketConnection sock,
				     const char *signoff_message)
{
  switch (sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry user_data = (SilcClientEntry)sock->user_data;
      silc_server_free_client_data(server, sock, user_data, TRUE,
				   signoff_message);
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry user_data = (SilcServerEntry)sock->user_data;
      SilcServerEntry backup_router = NULL;

      SILC_LOG_DEBUG(("Freeing server data"));

      if (user_data->id)
	backup_router = silc_server_backup_get(server, user_data->id);

      if (!server->backup_router && server->server_type == SILC_ROUTER &&
	  backup_router == server->id_entry &&
	  sock->type != SILC_SOCKET_TYPE_ROUTER)
	backup_router = NULL;

      if (server->server_shutdown || server->backup_noswitch)
      	backup_router = NULL;

      /* If this was our primary router connection then we're lost to
	 the outside world. */
      if (server->router == user_data) {
	/* Check whether we have a backup router connection */
	if (!backup_router || backup_router == user_data) {
	  silc_server_create_connections(server);
	  server->id_entry->router = NULL;
	  server->router = NULL;
	  server->standalone = TRUE;
	  server->backup_primary = FALSE;
	  backup_router = NULL;
	} else {
	  if (server->id_entry != backup_router) {
	    SILC_LOG_INFO(("New primary router is backup router %s",
			   backup_router->server_name));
	    server->id_entry->router = backup_router;
	    server->router = backup_router;
	    server->router_connect = time(0);
	    server->backup_primary = TRUE;
	  } else {
	    SILC_LOG_INFO(("We are now new primary router in this cell"));
	    server->id_entry->router = NULL;
	    server->router = NULL;
	    server->standalone = TRUE;

	    /* We stop here to take a breath */
	    sleep(2);
	  }

	  if (server->server_type == SILC_BACKUP_ROUTER) {
	    server->server_type = SILC_ROUTER;

	    /* We'll need to constantly try to reconnect to the primary
	       router so that we'll see when it comes back online. */
	    silc_server_backup_reconnect(server, sock->ip, sock->port,
					 silc_server_backup_connected,
					 NULL);
	  }

	  /* Mark this connection as replaced */
	  silc_server_backup_replaced_add(server, user_data->id,
					  backup_router);
	}
      } else if (backup_router) {
	SILC_LOG_INFO(("Enabling the use of backup router %s",
		       backup_router->server_name));

	/* Mark this connection as replaced */
	silc_server_backup_replaced_add(server, user_data->id,
					backup_router);
      } else if (server->server_type == SILC_SERVER &&
		 sock->type == SILC_SOCKET_TYPE_ROUTER) {
	/* Reconnect to the router (backup) */
	silc_server_create_connections(server);
      }

      if (user_data->server_name)
	SILC_SERVER_SEND_OPERS(server, FALSE, TRUE, SILC_NOTIFY_TYPE_NONE,
			       ("Server %s signoff", user_data->server_name));

      if (!backup_router) {
	/* Remove all servers that are originated from this server, and
	   remove the clients of those servers too. */
	silc_server_remove_servers_by_server(server, user_data, TRUE);

#if 0
	/* Remove the clients that this server owns as they will become
	   invalid now too.  For backup router the server is actually
	   coming from the primary router, so mark that as the owner
	   of this entry. */
	if (server->server_type == SILC_BACKUP_ROUTER &&
	    sock->type == SILC_SOCKET_TYPE_SERVER)
	  silc_server_remove_clients_by_server(server, server->router,
					       user_data, TRUE);
	else
#endif
	  silc_server_remove_clients_by_server(server, user_data,
					       user_data, TRUE);

	/* Remove channels owned by this server */
	if (server->server_type == SILC_SERVER)
	  silc_server_remove_channels_by_server(server, user_data);
      } else {
	/* Enable local server connections that may be disabled */
	silc_server_local_servers_toggle_enabled(server, TRUE);

	/* Update the client entries of this server to the new backup
	   router.  If we are the backup router we also resolve the real
	   servers for the clients.  After updating is over this also
	   removes the clients that this server explicitly owns. */
	silc_server_update_clients_by_server(server, user_data,
					     backup_router, TRUE);

	/* If we are router and just lost our primary router (now standlaone)
	   we remove everything that was behind it, since we don't know
	   any better. */
	if (server->server_type == SILC_ROUTER && server->standalone)
	  /* Remove all servers that are originated from this server, and
	     remove the clients of those servers too. */
	  silc_server_remove_servers_by_server(server, user_data, TRUE);

	/* Finally remove the clients that are explicitly owned by this
	   server.  They go down with the server. */
	silc_server_remove_clients_by_server(server, user_data,
					     user_data, TRUE);

	/* Update our server cache to use the new backup router too. */
	silc_server_update_servers_by_server(server, user_data, backup_router);
	if (server->server_type == SILC_SERVER)
	  silc_server_update_channels_by_server(server, user_data,
						backup_router);

	/* Send notify about primary router going down to local operators */
	if (server->backup_router)
	  SILC_SERVER_SEND_OPERS(server, FALSE, TRUE,
				 SILC_NOTIFY_TYPE_NONE,
				 ("%s switched to backup router %s "
				  "(we are primary router now)",
				  server->server_name, server->server_name));
	else if (server->router)
	  SILC_SERVER_SEND_OPERS(server, FALSE, TRUE,
				 SILC_NOTIFY_TYPE_NONE,
				 ("%s switched to backup router %s",
				  server->server_name,
				  server->router->server_name));
      }
      server->backup_noswitch = FALSE;

      /* Free the server entry */
      silc_server_backup_del(server, user_data);
      silc_server_backup_replaced_del(server, user_data);
      silc_idlist_del_data(user_data);
      if (!silc_idlist_del_server(server->local_list, user_data))
	silc_idlist_del_server(server->global_list, user_data);
      if (sock->type == SILC_SOCKET_TYPE_SERVER) {
	server->stat.my_servers--;
      } else {
	server->stat.my_routers--;
	server->stat.routers--;
      }
      server->stat.servers--;
      if (server->server_type == SILC_ROUTER)
	server->stat.cell_servers--;

      if (backup_router && backup_router != server->id_entry) {
	/* Announce all of our stuff that was created about 5 minutes ago.
	   The backup router knows all the other stuff already. */
	if (server->server_type == SILC_ROUTER)
	  silc_server_announce_servers(server, FALSE, time(0) - 300,
				       backup_router->connection);

	/* Announce our clients and channels to the router */
	silc_server_announce_clients(server, time(0) - 300,
				     backup_router->connection);
	silc_server_announce_channels(server, time(0) - 300,
				      backup_router->connection);
      }
      break;
    }
  default:
    {
      SilcUnknownEntry user_data = (SilcUnknownEntry)sock->user_data;

      SILC_LOG_DEBUG(("Freeing unknown connection data"));

      silc_idlist_del_data(user_data);
      silc_free(user_data);
      break;
    }
  }

  /* If any protocol is active cancel its execution */
  if (sock->protocol && sock->protocol->protocol &&
      sock->protocol->protocol->type != SILC_PROTOCOL_SERVER_BACKUP) {
    SILC_LOG_DEBUG(("Cancelling protocol, calling final callback"));
    silc_protocol_cancel(sock->protocol, server->schedule);
    sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
    silc_protocol_execute_final(sock->protocol, server->schedule);
    sock->protocol = NULL;
  }

  sock->user_data = NULL;
}

/* Removes client from all channels it has joined. This is used when client
   connection is disconnected. If the client on a channel is last, the
   channel is removed as well. This sends the SIGNOFF notify types. */

void silc_server_remove_from_channels(SilcServer server,
				      SilcSocketConnection sock,
				      SilcClientEntry client,
				      bool notify,
				      const char *signoff_message,
				      bool keygen,
				      bool killed)
{
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer clidp = NULL;

  if (!client)
    return;

  SILC_LOG_DEBUG(("Removing client from joined channels"));

  if (notify && !client->id)
    notify = FALSE;

  if (notify) {
    clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    if (!clidp)
      notify = FALSE;
  }

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    /* Remove channel if this is last client leaving the channel, unless
       the channel is permanent. */
    if (server->server_type != SILC_SERVER &&
	silc_hash_table_count(channel->user_list) < 2) {
      silc_server_channel_delete(server, channel);
      continue;
    }

    silc_hash_table_del(client->channels, channel);
    silc_hash_table_del(channel->user_list, client);
    channel->user_count--;

    /* If there is no global users on the channel anymore mark the channel
       as local channel. Do not check if the removed client is local client. */
    if (server->server_type == SILC_SERVER && channel->global_users &&
	chl->client->router && !silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    memset(chl, 'A', sizeof(*chl));
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
      /* Notify about leaving client if this channel has global users. */
      if (notify && channel->global_users)
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					   SILC_NOTIFY_TYPE_SIGNOFF,
					   signoff_message ? 2 : 1,
					   clidp->data, clidp->len,
					   signoff_message, signoff_message ?
					   strlen(signoff_message) : 0);

      silc_schedule_task_del_by_context(server->schedule, channel->rekey);
      silc_server_channel_delete(server, channel);
      continue;
    }

    /* Send notify to channel about client leaving SILC and channel too */
    if (notify)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					 SILC_NOTIFY_TYPE_SIGNOFF,
					 signoff_message ? 2 : 1,
					 clidp->data, clidp->len,
					 signoff_message, signoff_message ?
					 strlen(signoff_message) : 0);

    if (killed && clidp) {
      /* Remove the client from channel's invite list */
      if (channel->invite_list &&
	  silc_hash_table_count(channel->invite_list)) {
	SilcBuffer ab;
	SilcArgumentPayload iargs;
	ab = silc_argument_payload_encode_one(NULL, clidp->data,
					      clidp->len, 3);
	iargs = silc_argument_payload_parse(ab->data, ab->len, 1);
	silc_server_inviteban_process(server, channel->invite_list, 1, iargs);
	silc_buffer_free(ab);
	silc_argument_payload_free(iargs);
      }
    }

    /* Don't create keys if we are shutting down */
    if (server->server_shutdown)
      continue;

    /* Re-generate channel key if needed */
    if (keygen && !(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
      if (!silc_server_create_channel_key(server, channel, 0))
	continue;

      /* Send the channel key to the channel. The key of course is not sent
	 to the client who was removed from the channel. */
      silc_server_send_channel_key(server, client->connection, channel,
				   server->server_type == SILC_ROUTER ?
				   FALSE : !server->standalone);
    }
  }

  silc_hash_table_list_reset(&htl);
  if (clidp)
    silc_buffer_free(clidp);
}

/* Removes client from one channel. This is used for example when client
   calls LEAVE command to remove itself from the channel. Returns TRUE
   if channel still exists and FALSE if the channel is removed when
   last client leaves the channel. If `notify' is FALSE notify messages
   are not sent. */

bool silc_server_remove_from_one_channel(SilcServer server,
					 SilcSocketConnection sock,
					 SilcChannelEntry channel,
					 SilcClientEntry client,
					 bool notify)
{
  SilcChannelClientEntry chl;
  SilcBuffer clidp;

  SILC_LOG_DEBUG(("Removing %s from channel %s",
		  silc_id_render(client->id, SILC_ID_CLIENT), 
		  channel->channel_name));

  /* Get the entry to the channel, if this client is not on the channel
     then return Ok. */
  if (!silc_hash_table_find(client->channels, channel, NULL, (void *)&chl))
    return TRUE;

  /* Remove channel if this is last client leaving the channel, unless
     the channel is permanent. */
  if (server->server_type != SILC_SERVER &&
      silc_hash_table_count(channel->user_list) < 2) {
    silc_server_channel_delete(server, channel);
    return FALSE;
  }

  silc_hash_table_del(client->channels, channel);
  silc_hash_table_del(channel->user_list, client);
  channel->user_count--;

  /* If there is no global users on the channel anymore mark the channel
     as local channel. Do not check if the client is local client. */
  if (server->server_type == SILC_SERVER && channel->global_users &&
      chl->client->router && !silc_server_channel_has_global(channel))
    channel->global_users = FALSE;

  memset(chl, 'O', sizeof(*chl));
  silc_free(chl);

  /* Update statistics */
  if (SILC_IS_LOCAL(client))
    server->stat.my_chanclients--;
  if (server->server_type == SILC_ROUTER) {
    server->stat.cell_chanclients--;
    server->stat.chanclients--;
  }

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  if (!clidp)
    notify = FALSE;

  /* If there is not at least one local user on the channel then we don't
     need the channel entry anymore, we can remove it safely, unless the
     channel is permanent channel */
  if (server->server_type == SILC_SERVER &&
      !silc_server_channel_has_local(channel)) {
    /* Notify about leaving client if this channel has global users. */
    if (notify && channel->global_users)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					 SILC_NOTIFY_TYPE_LEAVE, 1,
					 clidp->data, clidp->len);

    silc_schedule_task_del_by_context(server->schedule, channel->rekey);
    silc_server_channel_delete(server, channel);
    silc_buffer_free(clidp);
    return FALSE;
  }

  /* Send notify to channel about client leaving the channel */
  if (notify)
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				       SILC_NOTIFY_TYPE_LEAVE, 1,
				       clidp->data, clidp->len);

  silc_buffer_free(clidp);
  return TRUE;
}

/* Timeout callback. This is called if connection is idle or for some
   other reason is not responding within some period of time. This
   disconnects the remote end. */

SILC_TASK_CALLBACK(silc_server_timeout_remote)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = server->sockets[fd];
  SilcProtocolType protocol = 0;

  SILC_LOG_DEBUG(("Start"));

  if (!sock)
    return;

  SILC_LOG_ERROR(("No response from %s (%s), Connection timeout",
		  sock->hostname, sock->ip));

  /* If we have protocol active we must assure that we call the protocol's
     final callback so that all the memory is freed. */
  if (sock->protocol && sock->protocol->protocol &&
      sock->protocol->protocol->type != SILC_PROTOCOL_SERVER_BACKUP) {
    protocol = sock->protocol->protocol->type;
    silc_protocol_cancel(sock->protocol, server->schedule);
    sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
    silc_protocol_execute_final(sock->protocol, server->schedule);
    sock->protocol = NULL;
    return;
  }

  silc_server_disconnect_remote(server, sock, 
				protocol == 
				SILC_PROTOCOL_SERVER_CONNECTION_AUTH ?
				SILC_STATUS_ERR_AUTH_FAILED :
				SILC_STATUS_ERR_KEY_EXCHANGE_FAILED,
				"Connection timeout");

  if (sock->user_data)
    silc_server_free_sock_user_data(server, sock, NULL);
}

/* Creates new channel. Sends NEW_CHANNEL packet to primary route. This
   function may be used only by router. In real SILC network all channels
   are created by routers thus this function is never used by normal
   server. */

SilcChannelEntry silc_server_create_new_channel(SilcServer server,
						SilcServerID *router_id,
						char *cipher,
						char *hmac,
						char *channel_name,
						int broadcast)
{
  SilcChannelID *channel_id;
  SilcChannelEntry entry;
  SilcCipher key;
  SilcHmac newhmac;

  SILC_LOG_DEBUG(("Creating new channel %s", channel_name));

  if (!cipher)
    cipher = SILC_DEFAULT_CIPHER;
  if (!hmac)
    hmac = SILC_DEFAULT_HMAC;

  /* Allocate cipher */
  if (!silc_cipher_alloc(cipher, &key))
    return NULL;

  /* Allocate hmac */
  if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
    silc_cipher_free(key);
    return NULL;
  }

  channel_name = strdup(channel_name);

  /* Create the channel ID */
  if (!silc_id_create_channel_id(server, router_id, server->rng,
				 &channel_id)) {
    silc_free(channel_name);
    silc_cipher_free(key);
    silc_hmac_free(newhmac);
    return NULL;
  }

  /* Create the channel */
  entry = silc_idlist_add_channel(server->local_list, channel_name,
				  SILC_CHANNEL_MODE_NONE, channel_id,
				  NULL, key, newhmac, 0);
  if (!entry) {
    silc_free(channel_name);
    silc_cipher_free(key);
    silc_hmac_free(newhmac);
    silc_free(channel_id);
    return NULL;
  }

  entry->cipher = strdup(cipher);
  entry->hmac_name = strdup(hmac);

  /* Now create the actual key material */
  if (!silc_server_create_channel_key(server, entry,
				      silc_cipher_get_key_len(key) / 8)) {
    silc_idlist_del_channel(server->local_list, entry);
    return NULL;
  }

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (broadcast)
    silc_server_send_new_channel(server, SILC_PRIMARY_ROUTE(server), TRUE,
				 channel_name, entry->id,
				 silc_id_get_len(entry->id, SILC_ID_CHANNEL),
				 entry->mode);

  /* Distribute to backup routers */
  if (broadcast && server->server_type == SILC_ROUTER) {
    SilcBuffer packet;
    unsigned char *cid;
    SilcUInt32 name_len = strlen(channel_name);
    SilcUInt32 channel_id_len = silc_id_get_len(entry->id, SILC_ID_CHANNEL);
    cid = silc_id_id2str(entry->id, SILC_ID_CHANNEL);

    packet = silc_channel_payload_encode(channel_name, name_len,
					 cid, channel_id_len, entry->mode);
    silc_server_backup_send(server, NULL, SILC_PACKET_NEW_CHANNEL, 0,
			    packet->data, packet->len, FALSE, TRUE);
    silc_free(cid);
    silc_buffer_free(packet);
  }

  server->stat.my_channels++;
  if (server->server_type == SILC_ROUTER) {
    server->stat.channels++;
    server->stat.cell_channels++;
    entry->users_resolved = TRUE;
  }

  return entry;
}

/* Same as above but creates the channel with Channel ID `channel_id. */

SilcChannelEntry
silc_server_create_new_channel_with_id(SilcServer server,
				       char *cipher,
				       char *hmac,
				       char *channel_name,
				       SilcChannelID *channel_id,
				       int broadcast)
{
  SilcChannelEntry entry;
  SilcCipher key;
  SilcHmac newhmac;

  SILC_LOG_DEBUG(("Creating new channel %s", channel_name));

  if (!cipher)
    cipher = SILC_DEFAULT_CIPHER;
  if (!hmac)
    hmac = SILC_DEFAULT_HMAC;

  /* Allocate cipher */
  if (!silc_cipher_alloc(cipher, &key))
    return NULL;

  /* Allocate hmac */
  if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
    silc_cipher_free(key);
    return NULL;
  }

  channel_name = strdup(channel_name);

  /* Create the channel */
  entry = silc_idlist_add_channel(server->local_list, channel_name,
				  SILC_CHANNEL_MODE_NONE, channel_id,
				  NULL, key, newhmac, 0);
  if (!entry) {
    silc_cipher_free(key);
    silc_hmac_free(newhmac);
    silc_free(channel_name);
    return NULL;
  }

  /* Now create the actual key material */
  if (!silc_server_create_channel_key(server, entry,
				      silc_cipher_get_key_len(key) / 8)) {
    silc_idlist_del_channel(server->local_list, entry);
    return NULL;
  }

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (broadcast)
    silc_server_send_new_channel(server, SILC_PRIMARY_ROUTE(server), TRUE,
				 channel_name, entry->id,
				 silc_id_get_len(entry->id, SILC_ID_CHANNEL),
				 entry->mode);

  /* Distribute to backup routers */
  if (broadcast && server->server_type == SILC_ROUTER) {
    SilcBuffer packet;
    unsigned char *cid;
    SilcUInt32 name_len = strlen(channel_name);
    SilcUInt32 channel_id_len = silc_id_get_len(entry->id, SILC_ID_CHANNEL);
    cid = silc_id_id2str(entry->id, SILC_ID_CHANNEL);

    packet = silc_channel_payload_encode(channel_name, name_len,
					 cid, channel_id_len, entry->mode);
    silc_server_backup_send(server, NULL, SILC_PACKET_NEW_CHANNEL, 0,
			    packet->data, packet->len, FALSE, TRUE);
    silc_free(cid);
    silc_buffer_free(packet);
  }

  server->stat.my_channels++;
  if (server->server_type == SILC_ROUTER) {
    server->stat.channels++;
    server->stat.cell_channels++;
    entry->users_resolved = TRUE;
  }

  return entry;
}

/* Channel's key re-key timeout callback. */

SILC_TASK_CALLBACK(silc_server_channel_key_rekey)
{
  SilcServer server = app_context;
  SilcServerChannelRekey rekey = (SilcServerChannelRekey)context;

  rekey->task = NULL;

  /* Return now if we are shutting down */
  if (server->server_shutdown)
    return;

  if (!silc_server_create_channel_key(server, rekey->channel, rekey->key_len))
    return;

  silc_server_send_channel_key(server, NULL, rekey->channel, FALSE);
}

/* Generates new channel key. This is used to create the initial channel key
   but also to re-generate new key for channel. If `key_len' is provided
   it is the bytes of the key length. */

bool silc_server_create_channel_key(SilcServer server,
				    SilcChannelEntry channel,
				    SilcUInt32 key_len)
{
  int i;
  unsigned char channel_key[32], hash[32];
  SilcUInt32 len;

  if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
    SILC_LOG_DEBUG(("Channel has private keys, will not generate new key"));
    return TRUE;
  }

  SILC_LOG_DEBUG(("Generating channel %s key", channel->channel_name));

  if (!channel->channel_key)
    if (!silc_cipher_alloc(SILC_DEFAULT_CIPHER, &channel->channel_key)) {
      channel->channel_key = NULL;
      return FALSE;
    }

  if (key_len)
    len = key_len;
  else if (channel->key_len)
    len = channel->key_len / 8;
  else
    len = silc_cipher_get_key_len(channel->channel_key) / 8;

  /* Create channel key */
  for (i = 0; i < len; i++) channel_key[i] = silc_rng_get_byte(server->rng);

  /* Set the key */
  silc_cipher_set_key(channel->channel_key, channel_key, len * 8);

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
  }

  /* Save the key */
  channel->key_len = len * 8;
  channel->key = silc_memdup(channel_key, len);
  memset(channel_key, 0, sizeof(channel_key));

  /* Generate HMAC key from the channel key data and set it */
  if (!channel->hmac)
    if (!silc_hmac_alloc(SILC_DEFAULT_HMAC, NULL, &channel->hmac)) {
      memset(channel->key, 0, channel->key_len / 8);
      silc_free(channel->key);
      channel->channel_key = NULL;
      return FALSE;
    }
  silc_hash_make(silc_hmac_get_hash(channel->hmac), channel->key, len, hash);
  silc_hmac_set_key(channel->hmac, hash,
		    silc_hash_len(silc_hmac_get_hash(channel->hmac)));
  memset(hash, 0, sizeof(hash));

  if (server->server_type == SILC_ROUTER) {
    if (!channel->rekey)
      channel->rekey = silc_calloc(1, sizeof(*channel->rekey));
    channel->rekey->channel = channel;
    channel->rekey->key_len = key_len;
    if (channel->rekey->task)
      silc_schedule_task_del(server->schedule, channel->rekey->task);

    channel->rekey->task =
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_channel_key_rekey,
			     (void *)channel->rekey,
			     server->config->channel_rekey_secs, 0,
			     SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
  }

  return TRUE;
}

/* Saves the channel key found in the encoded `key_payload' buffer. This
   function is used when we receive Channel Key Payload and also when we're
   processing JOIN command reply. Returns entry to the channel. */

SilcChannelEntry silc_server_save_channel_key(SilcServer server,
					      SilcBuffer key_payload,
					      SilcChannelEntry channel)
{
  SilcChannelKeyPayload payload = NULL;
  SilcChannelID *id = NULL;
  unsigned char *tmp, hash[32];
  SilcUInt32 tmp_len;
  char *cipher;

  /* Decode channel key payload */
  payload = silc_channel_key_payload_parse(key_payload->data,
					   key_payload->len);
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload received, dropped"));
    channel = NULL;
    goto out;
  }

  /* Get the channel entry */
  if (!channel) {

    /* Get channel ID */
    tmp = silc_channel_key_get_id(payload, &tmp_len);
    id = silc_id_str2id(tmp, tmp_len, SILC_ID_CHANNEL);
    if (!id) {
      channel = NULL;
      goto out;
    }

    channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
      if (!channel) {
	if (server->server_type == SILC_ROUTER)
	  SILC_LOG_ERROR(("Received key for non-existent channel %s",
			  silc_id_render(id, SILC_ID_CHANNEL)));
	goto out;
      }
    }
  }

  SILC_LOG_DEBUG(("Saving new channel %s key", channel->channel_name));

  tmp = silc_channel_key_get_key(payload, &tmp_len);
  if (!tmp) {
    channel = NULL;
    goto out;
  }

  cipher = silc_channel_key_get_cipher(payload, NULL);
  if (!cipher) {
    channel = NULL;
    goto out;
  }

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
    silc_cipher_free(channel->channel_key);
  }

  /* Create new cipher */
  if (!silc_cipher_alloc(cipher, &channel->channel_key)) {
    channel->channel_key = NULL;
    channel = NULL;
    goto out;
  }

  if (channel->cipher)
    silc_free(channel->cipher);
  channel->cipher = strdup(cipher);

  /* Save the key */
  channel->key_len = tmp_len * 8;
  channel->key = silc_memdup(tmp, tmp_len);
  silc_cipher_set_key(channel->channel_key, tmp, channel->key_len);

  /* Generate HMAC key from the channel key data and set it */
  if (!channel->hmac)
    if (!silc_hmac_alloc(SILC_DEFAULT_HMAC, NULL, &channel->hmac)) {
      memset(channel->key, 0, channel->key_len / 8);
      silc_free(channel->key);
      channel->channel_key = NULL;
      return FALSE;
    }
  silc_hash_make(silc_hmac_get_hash(channel->hmac), tmp, tmp_len, hash);
  silc_hmac_set_key(channel->hmac, hash,
		    silc_hash_len(silc_hmac_get_hash(channel->hmac)));

  memset(hash, 0, sizeof(hash));
  memset(tmp, 0, tmp_len);

  if (server->server_type == SILC_ROUTER) {
    if (!channel->rekey)
      channel->rekey = silc_calloc(1, sizeof(*channel->rekey));
    channel->rekey->channel = channel;
    if (channel->rekey->task)
      silc_schedule_task_del(server->schedule, channel->rekey->task);

    channel->rekey->task =
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_channel_key_rekey,
			     (void *)channel->rekey,
			     server->config->channel_rekey_secs, 0,
			     SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
  }

 out:
  silc_free(id);
  if (payload)
    silc_channel_key_payload_free(payload);

  return channel;
}

/* Heartbeat callback. This function is set as argument for the
   silc_socket_set_heartbeat function. The library will call this function
   at the set time interval. */

void silc_server_perform_heartbeat(SilcSocketConnection sock,
				   void *hb_context)
{
  SilcServer server = hb_context;

  SILC_LOG_DEBUG(("Sending heartbeat to %s:%d (%s)", sock->hostname, 
		 sock->port, sock->ip));

  /* Send the heartbeat */
  silc_server_send_heartbeat(server, sock);
}

/* Returns assembled of all servers in the given ID list. The packet's
   form is dictated by the New ID payload. */

static void silc_server_announce_get_servers(SilcServer server,
					     SilcServerEntry remote,
					     SilcIDList id_list,
					     SilcBuffer *servers,
					     unsigned long creation_time)
{
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;
  SilcBuffer idp;

  /* Go through all clients in the list */
  if (silc_idcache_get_all(id_list->servers, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	entry = (SilcServerEntry)id_cache->context;

	/* Do not announce the one we've sending our announcements and
	   do not announce ourself. Also check the creation time if it's
	   provided. */
	if ((entry == remote) || (entry == server->id_entry) ||
	    (creation_time && entry->data.created < creation_time)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  continue;
	}

	idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);

	*servers = silc_buffer_realloc(*servers,
				       (*servers ?
					(*servers)->truelen + idp->len :
					idp->len));
	silc_buffer_pull_tail(*servers, ((*servers)->end - (*servers)->data));
	silc_buffer_put(*servers, idp->data, idp->len);
	silc_buffer_pull(*servers, idp->len);
	silc_buffer_free(idp);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }

    silc_idcache_list_free(list);
  }
}

static SilcBuffer
silc_server_announce_encode_notify(SilcNotifyType notify, SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer p;

  va_start(ap, argc);
  p = silc_notify_payload_encode(notify, argc, ap);
  va_end(ap);

  return p;
}

/* This function is used by router to announce existing servers to our
   primary router when we've connected to it. If `creation_time' is non-zero
   then only the servers that has been created after the `creation_time'
   will be announced. */

void silc_server_announce_servers(SilcServer server, bool global,
				  unsigned long creation_time,
				  SilcSocketConnection remote)
{
  SilcBuffer servers = NULL;

  SILC_LOG_DEBUG(("Announcing servers"));

  /* Get servers in local list */
  silc_server_announce_get_servers(server, remote->user_data,
				   server->local_list, &servers,
				   creation_time);

  if (global)
    /* Get servers in global list */
    silc_server_announce_get_servers(server, remote->user_data,
				     server->global_list, &servers,
				     creation_time);

  if (servers) {
    silc_buffer_push(servers, servers->data - servers->head);
    SILC_LOG_HEXDUMP(("servers"), servers->data, servers->len);

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NEW_ID, SILC_PACKET_FLAG_LIST,
			    servers->data, servers->len, TRUE);

    silc_buffer_free(servers);
  }
}

/* Returns assembled packet of all clients in the given ID list. The
   packet's form is dictated by the New ID Payload. */

static void silc_server_announce_get_clients(SilcServer server,
					     SilcIDList id_list,
					     SilcBuffer *clients,
					     SilcBuffer *umodes,
					     unsigned long creation_time)
{
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcClientEntry client;
  SilcBuffer idp;
  SilcBuffer tmp;
  unsigned char mode[4];

  /* Go through all clients in the list */
  if (silc_idcache_get_all(id_list->clients, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	client = (SilcClientEntry)id_cache->context;

	if (creation_time && client->data.created < creation_time) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  continue;
	}
	if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED) &&
	    !client->connection && !client->router && !SILC_IS_LOCAL(client)) {
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  continue;
	}

	idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

	*clients = silc_buffer_realloc(*clients,
				       (*clients ?
					(*clients)->truelen + idp->len :
					idp->len));
	silc_buffer_pull_tail(*clients, ((*clients)->end - (*clients)->data));
	silc_buffer_put(*clients, idp->data, idp->len);
	silc_buffer_pull(*clients, idp->len);

	SILC_PUT32_MSB(client->mode, mode);
	tmp =
	  silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_UMODE_CHANGE,
					     2, idp->data, idp->len,
					     mode, 4);
	*umodes = silc_buffer_realloc(*umodes,
				      (*umodes ?
				       (*umodes)->truelen + tmp->len :
				       tmp->len));
	silc_buffer_pull_tail(*umodes, ((*umodes)->end - (*umodes)->data));
	silc_buffer_put(*umodes, tmp->data, tmp->len);
	silc_buffer_pull(*umodes, tmp->len);
	silc_buffer_free(tmp);

	silc_buffer_free(idp);

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }

    silc_idcache_list_free(list);
  }
}

/* This function is used to announce our existing clients to our router
   when we've connected to it. If `creation_time' is non-zero then only
   the clients that has been created after the `creation_time' will be
   announced. */

void silc_server_announce_clients(SilcServer server,
				  unsigned long creation_time,
				  SilcSocketConnection remote)
{
  SilcBuffer clients = NULL;
  SilcBuffer umodes = NULL;

  SILC_LOG_DEBUG(("Announcing clients"));

  /* Get clients in local list */
  silc_server_announce_get_clients(server, server->local_list,
				   &clients, &umodes, creation_time);

  /* As router we announce our global list as well */
  if (server->server_type == SILC_ROUTER)
    silc_server_announce_get_clients(server, server->global_list,
				     &clients, &umodes, creation_time);

  if (clients) {
    silc_buffer_push(clients, clients->data - clients->head);
    SILC_LOG_HEXDUMP(("clients"), clients->data, clients->len);

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NEW_ID, SILC_PACKET_FLAG_LIST,
			    clients->data, clients->len, TRUE);

    silc_buffer_free(clients);
  }

  if (umodes) {
    silc_buffer_push(umodes, umodes->data - umodes->head);
    SILC_LOG_HEXDUMP(("umodes"), umodes->data, umodes->len);

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
			    umodes->data, umodes->len, TRUE);

    silc_buffer_free(umodes);
  }
}

/* Returns channel's topic for announcing it */

void silc_server_announce_get_channel_topic(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *topic)
{
  SilcBuffer chidp;

  if (channel->topic) {
    chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
    *topic = silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_TOPIC_SET, 2,
						chidp->data, chidp->len,
						channel->topic,
						strlen(channel->topic));
    silc_buffer_free(chidp);
  }
}

/* Returns assembled packets for channel users of the `channel'. */

void silc_server_announce_get_channel_users(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *channel_modes,
					    SilcBuffer *channel_users,
					    SilcBuffer *channel_users_modes)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer chidp, clidp, csidp;
  SilcBuffer tmp, fkey = NULL;
  int len;
  unsigned char mode[4];
  char *hmac;

  SILC_LOG_DEBUG(("Start"));

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  csidp = silc_id_payload_encode(server->id, SILC_ID_SERVER);

  /* CMODE notify */
  SILC_PUT32_MSB(channel->mode, mode);
  hmac = channel->hmac ? (char *)silc_hmac_get_name(channel->hmac) : NULL;
  if (channel->founder_key)
    fkey = silc_pkcs_public_key_payload_encode(channel->founder_key);
  tmp = 
    silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_CMODE_CHANGE,
				       6, csidp->data, csidp->len,
				       mode, sizeof(mode),
				       NULL, 0,
				       hmac, hmac ? strlen(hmac) : 0,
				       channel->passphrase,
				       channel->passphrase ?
				       strlen(channel->passphrase) : 0,
				       fkey ? fkey->data : NULL,
				       fkey ? fkey->len : 0);
  len = tmp->len;
  *channel_modes =
    silc_buffer_realloc(*channel_modes,
			(*channel_modes ?
			 (*channel_modes)->truelen + len : len));
  silc_buffer_pull_tail(*channel_modes,
			((*channel_modes)->end -
			 (*channel_modes)->data));
  silc_buffer_put(*channel_modes, tmp->data, tmp->len);
  silc_buffer_pull(*channel_modes, len);
  silc_buffer_free(tmp);
  silc_buffer_free(fkey);
  fkey = NULL;

  /* Now find all users on the channel */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    clidp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);

    /* JOIN Notify */
    tmp = silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_JOIN, 2,
					     clidp->data, clidp->len,
					     chidp->data, chidp->len);
    len = tmp->len;
    *channel_users =
      silc_buffer_realloc(*channel_users,
			  (*channel_users ?
			   (*channel_users)->truelen + len : len));
    silc_buffer_pull_tail(*channel_users,
			  ((*channel_users)->end -
			   (*channel_users)->data));

    silc_buffer_put(*channel_users, tmp->data, tmp->len);
    silc_buffer_pull(*channel_users, len);
    silc_buffer_free(tmp);

    /* CUMODE notify for mode change on the channel */
    SILC_PUT32_MSB(chl->mode, mode);
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO && channel->founder_key)
      fkey = silc_pkcs_public_key_payload_encode(channel->founder_key);
    tmp = silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_CUMODE_CHANGE,
					     4, csidp->data, csidp->len,
					     mode, sizeof(mode),
					     clidp->data, clidp->len,
					     fkey ? fkey->data : NULL,
					     fkey ? fkey->len : 0);
    len = tmp->len;
    *channel_users_modes =
      silc_buffer_realloc(*channel_users_modes,
			  (*channel_users_modes ?
			   (*channel_users_modes)->truelen + len : len));
    silc_buffer_pull_tail(*channel_users_modes,
			  ((*channel_users_modes)->end -
			   (*channel_users_modes)->data));

    silc_buffer_put(*channel_users_modes, tmp->data, tmp->len);
    silc_buffer_pull(*channel_users_modes, len);
    silc_buffer_free(tmp);
    silc_buffer_free(fkey);
    fkey = NULL;
    silc_buffer_free(clidp);
  }
  silc_hash_table_list_reset(&htl);
  silc_buffer_free(chidp);
  silc_buffer_free(csidp);
}

/* Returns assembled packets for all channels and users on those channels
   from the given ID List. The packets are in the form dictated by the
   New Channel and New Channel User payloads. */

void silc_server_announce_get_channels(SilcServer server,
				       SilcIDList id_list,
				       SilcBuffer *channels,
				       SilcBuffer **channel_modes,
				       SilcBuffer *channel_users,
				       SilcBuffer **channel_users_modes,
				       SilcUInt32 *channel_users_modes_c,
				       SilcBuffer **channel_topics,
				       SilcChannelID ***channel_ids,
				       unsigned long creation_time)
{
  SilcIDCacheList list;
  SilcIDCacheEntry id_cache;
  SilcChannelEntry channel;
  unsigned char *cid;
  SilcUInt32 id_len;
  SilcUInt16 name_len;
  int len;
  int i = *channel_users_modes_c;
  bool announce;

  SILC_LOG_DEBUG(("Start"));

  /* Go through all channels in the list */
  if (silc_idcache_get_all(id_list->channels, &list)) {
    if (silc_idcache_list_first(list, &id_cache)) {
      while (id_cache) {
	channel = (SilcChannelEntry)id_cache->context;

	if (creation_time && channel->created < creation_time)
	  announce = FALSE;
	else
	  announce = TRUE;

	cid = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
	id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
	name_len = strlen(channel->channel_name);

	if (announce) {
	  len = 4 + name_len + id_len + 4;
	  *channels =
	    silc_buffer_realloc(*channels,
				(*channels ? (*channels)->truelen +
				 len : len));
	  silc_buffer_pull_tail(*channels,
				((*channels)->end - (*channels)->data));
	  silc_buffer_format(*channels,
			     SILC_STR_UI_SHORT(name_len),
			     SILC_STR_UI_XNSTRING(channel->channel_name,
						  name_len),
			     SILC_STR_UI_SHORT(id_len),
			     SILC_STR_UI_XNSTRING(cid, id_len),
			     SILC_STR_UI_INT(channel->mode),
			     SILC_STR_END);
	  silc_buffer_pull(*channels, len);
	}

	if (creation_time && channel->updated < creation_time)
	  announce = FALSE;
	else
	  announce = TRUE;

	if (announce) {
	  /* Channel user modes */
	  *channel_users_modes = silc_realloc(*channel_users_modes,
					      sizeof(**channel_users_modes) *
					      (i + 1));
	  (*channel_users_modes)[i] = NULL;
	  *channel_modes = silc_realloc(*channel_modes,
					sizeof(**channel_modes) * (i + 1));
	  (*channel_modes)[i] = NULL;
	  *channel_ids = silc_realloc(*channel_ids,
				      sizeof(**channel_ids) * (i + 1));
	  (*channel_ids)[i] = NULL;
	  silc_server_announce_get_channel_users(server, channel,
						 &(*channel_modes)[i], 
						 channel_users,
						 &(*channel_users_modes)[i]);
	  (*channel_ids)[i] = channel->id;

	  /* Channel's topic */
	  *channel_topics = silc_realloc(*channel_topics,
					 sizeof(**channel_topics) * (i + 1));
	  (*channel_topics)[i] = NULL;
	  silc_server_announce_get_channel_topic(server, channel,
						 &(*channel_topics)[i]);
	  (*channel_users_modes_c)++;

	  silc_free(cid);

	  i++;
	}

	if (!silc_idcache_list_next(list, &id_cache))
	  break;
      }
    }

    silc_idcache_list_free(list);
  }
}

/* This function is used to announce our existing channels to our router
   when we've connected to it. This also announces the users on the
   channels to the router. If the `creation_time' is non-zero only the
   channels that was created after the `creation_time' are announced.
   Note that the channel users are still announced even if the `creation_time'
   was provided. */

void silc_server_announce_channels(SilcServer server,
				   unsigned long creation_time,
				   SilcSocketConnection remote)
{
  SilcBuffer channels = NULL, *channel_modes = NULL, channel_users = NULL;
  SilcBuffer *channel_users_modes = NULL;
  SilcBuffer *channel_topics = NULL;
  SilcUInt32 channel_users_modes_c = 0;
  SilcChannelID **channel_ids = NULL;

  SILC_LOG_DEBUG(("Announcing channels and channel users"));

  /* Get channels and channel users in local list */
  silc_server_announce_get_channels(server, server->local_list,
				    &channels, &channel_modes,
				    &channel_users,
				    &channel_users_modes,
				    &channel_users_modes_c,
				    &channel_topics,
				    &channel_ids, creation_time);

  /* Get channels and channel users in global list */
  if (server->server_type != SILC_SERVER)
    silc_server_announce_get_channels(server, server->global_list,
				      &channels, &channel_modes,
				      &channel_users,
				      &channel_users_modes,
				      &channel_users_modes_c,
				      &channel_topics,
				      &channel_ids, creation_time);

  if (channels) {
    silc_buffer_push(channels, channels->data - channels->head);
    SILC_LOG_HEXDUMP(("channels"), channels->data, channels->len);

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NEW_CHANNEL, SILC_PACKET_FLAG_LIST,
			    channels->data, channels->len,
			    FALSE);

    silc_buffer_free(channels);
  }

  if (channel_users) {
    silc_buffer_push(channel_users, channel_users->data - channel_users->head);
    SILC_LOG_HEXDUMP(("channel users"), channel_users->data,
		     channel_users->len);

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
			    channel_users->data, channel_users->len,
			    FALSE);

    silc_buffer_free(channel_users);
  }

  if (channel_modes) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_modes[i])
        continue;
      silc_buffer_push(channel_modes[i],
		       channel_modes[i]->data -
		       channel_modes[i]->head);
      SILC_LOG_HEXDUMP(("channel modes"), channel_modes[i]->data,
		       channel_modes[i]->len);
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_modes[i]->data,
				   channel_modes[i]->len,
				   FALSE);
      silc_buffer_free(channel_modes[i]);
    }
    silc_free(channel_modes);
  }

  if (channel_users_modes) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_users_modes[i])
        continue;
      silc_buffer_push(channel_users_modes[i],
		       channel_users_modes[i]->data -
		       channel_users_modes[i]->head);
      SILC_LOG_HEXDUMP(("channel users modes"), channel_users_modes[i]->data,
		       channel_users_modes[i]->len);
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_users_modes[i]->data,
				   channel_users_modes[i]->len,
				   FALSE);
      silc_buffer_free(channel_users_modes[i]);
    }
    silc_free(channel_users_modes);
  }

  if (channel_topics) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_topics[i])
	continue;

      silc_buffer_push(channel_topics[i],
		       channel_topics[i]->data -
		       channel_topics[i]->head);
      SILC_LOG_HEXDUMP(("channel topic"), channel_topics[i]->data,
		       channel_topics[i]->len);
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_topics[i]->data,
				   channel_topics[i]->len,
				   FALSE);
      silc_buffer_free(channel_topics[i]);
    }
    silc_free(channel_topics);
  }

  silc_free(channel_ids);
}

/* Assembles user list and users mode list from the `channel'. */

bool silc_server_get_users_on_channel(SilcServer server,
				      SilcChannelEntry channel,
				      SilcBuffer *user_list,
				      SilcBuffer *mode_list,
				      SilcUInt32 *user_count)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  SilcBuffer idp;
  SilcUInt32 list_count = 0, len = 0;

  if (!silc_hash_table_count(channel->user_list))
    return FALSE;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl))
    len += (silc_id_get_len(chl->client->id, SILC_ID_CLIENT) + 4);
  silc_hash_table_list_reset(&htl);

  client_id_list = silc_buffer_alloc(len);
  client_mode_list =
    silc_buffer_alloc(4 * silc_hash_table_count(channel->user_list));
  silc_buffer_pull_tail(client_id_list, SILC_BUFFER_END(client_id_list));
  silc_buffer_pull_tail(client_mode_list, SILC_BUFFER_END(client_mode_list));

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    /* Client ID */
    idp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
    silc_buffer_put(client_id_list, idp->data, idp->len);
    silc_buffer_pull(client_id_list, idp->len);
    silc_buffer_free(idp);

    /* Client's mode on channel */
    SILC_PUT32_MSB(chl->mode, client_mode_list->data);
    silc_buffer_pull(client_mode_list, 4);

    list_count++;
  }
  silc_hash_table_list_reset(&htl);
  silc_buffer_push(client_id_list,
		   client_id_list->data - client_id_list->head);
  silc_buffer_push(client_mode_list,
		   client_mode_list->data - client_mode_list->head);

  *user_list = client_id_list;
  *mode_list = client_mode_list;
  *user_count = list_count;
  return TRUE;
}

/* Saves users and their modes to the `channel'. */

void silc_server_save_users_on_channel(SilcServer server,
				       SilcSocketConnection sock,
				       SilcChannelEntry channel,
				       SilcClientID *noadd,
				       SilcBuffer user_list,
				       SilcBuffer mode_list,
				       SilcUInt32 user_count)
{
  int i;
  SilcUInt16 idp_len;
  SilcUInt32 mode;
  SilcClientID *client_id;
  SilcClientEntry client;
  SilcIDCacheEntry cache;
  SilcChannelClientEntry chl;

  SILC_LOG_DEBUG(("Saving %d users on %s channel", user_count,
		  channel->channel_name));

  for (i = 0; i < user_count; i++) {
    /* Client ID */
    SILC_GET16_MSB(idp_len, user_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(user_list->data, idp_len, NULL);
    silc_buffer_pull(user_list, idp_len);
    if (!client_id)
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, mode_list->data);
    silc_buffer_pull(mode_list, 4);

    if (noadd && SILC_ID_CLIENT_COMPARE(client_id, noadd)) {
      silc_free(client_id);
      continue;
    }

    cache = NULL;

    /* Check if we have this client cached already. */
    client = silc_idlist_find_client_by_id(server->local_list, client_id,
					   server->server_type, &cache);
    if (!client)
      client = silc_idlist_find_client_by_id(server->global_list,
					     client_id, server->server_type,
					     &cache);
    if (!client) {
      /* If router did not find such Client ID in its lists then this must
	 be bogus client or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER) {
	silc_free(client_id);
	continue;
      }

      /* We don't have that client anywhere, add it. The client is added
	 to global list since server didn't have it in the lists so it must be
	 global. */
      client = silc_idlist_add_client(server->global_list, NULL, NULL, NULL,
				      silc_id_dup(client_id, SILC_ID_CLIENT),
				      sock->user_data, NULL, 0);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
	silc_free(client_id);
	continue;
      }

      client->data.status |= SILC_IDLIST_STATUS_REGISTERED;
    }

    if (cache)
      cache->expire = 0;
    silc_free(client_id);

    if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
      SILC_LOG_ERROR(("Attempting to add unregistered client to channel ",
		      "%s", channel->channel_name));
      continue;
    }

    if (!silc_server_client_on_channel(client, channel, &chl)) {
      /* Client was not on the channel, add it. */
      chl = silc_calloc(1, sizeof(*chl));
      chl->client = client;
      chl->mode = mode;
      chl->channel = channel;
      silc_hash_table_add(channel->user_list, chl->client, chl);
      silc_hash_table_add(client->channels, chl->channel, chl);
      channel->user_count++;
    } else {
      /* Update mode */
      chl->mode = mode;
    }
  }
}

/* Saves channels and channels user modes to the `client'.  Removes
   the client from those channels that are not sent in the list but
   it has joined. */

void silc_server_save_user_channels(SilcServer server,
				    SilcSocketConnection sock,
				    SilcClientEntry client,
				    SilcBuffer channels,
				    SilcBuffer channels_user_modes)
{
  SilcDList ch;
  SilcUInt32 *chumodes;
  SilcChannelPayload entry;
  SilcChannelEntry channel;
  SilcChannelID *channel_id;
  SilcChannelClientEntry chl;
  SilcHashTable ht = NULL;
  SilcHashTableList htl;
  char *name;
  int i = 0;

  if (!channels || !channels_user_modes ||
      !(client->data.status & SILC_IDLIST_STATUS_REGISTERED))
    goto out;
  
  ch = silc_channel_payload_parse_list(channels->data, channels->len);
  if (ch && silc_get_mode_list(channels_user_modes, silc_dlist_count(ch),
			       &chumodes)) {
    ht = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL, 
			       NULL, NULL, NULL, TRUE);
    silc_dlist_start(ch);
    while ((entry = silc_dlist_get(ch)) != SILC_LIST_END) {
      /* Check if we have this channel, and add it if we don't have it.
	 Also add the client on the channel unless it is there already. */
      channel_id = silc_channel_get_id_parse(entry);
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel)
	channel = silc_idlist_find_channel_by_id(server->global_list,
						 channel_id, NULL);
      if (!channel) {
	if (server->server_type != SILC_SERVER) {
	  silc_free(channel_id);
	  i++;
	  continue;
	}
	
	/* We don't have that channel anywhere, add it. */
	name = silc_channel_get_name(entry, NULL);
	channel = silc_idlist_add_channel(server->global_list, strdup(name), 0,
					  channel_id, server->router,
					  NULL, NULL, 0);
	if (!channel) {
	  silc_free(channel_id);
	  i++;
	  continue;
	}
	channel_id = NULL;
      }

      channel->mode = silc_channel_get_mode(entry);

      /* Add the client on the channel */
      if (!silc_server_client_on_channel(client, channel, &chl)) {
	chl = silc_calloc(1, sizeof(*chl));
	chl->client = client;
	chl->mode = chumodes[i++];
	chl->channel = channel;
	silc_hash_table_add(channel->user_list, chl->client, chl);
	silc_hash_table_add(client->channels, chl->channel, chl);
	channel->user_count++;
      } else {
	/* Update mode */
	chl->mode = chumodes[i++];
      }

      silc_hash_table_add(ht, channel, channel);
      silc_free(channel_id);
    }
    silc_channel_payload_list_free(ch);
    silc_free(chumodes);
  }

 out:
  /* Go through the list again and remove client from channels that
     are no part of the list. */
  if (ht) {
    silc_hash_table_list(client->channels, &htl);
    while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
      if (!silc_hash_table_find(ht, chl->channel, NULL, NULL)) {
	silc_hash_table_del(chl->channel->user_list, chl->client);
	silc_hash_table_del(chl->client->channels, chl->channel);
	silc_free(chl);
      }
    }
    silc_hash_table_list_reset(&htl);
    silc_hash_table_free(ht);
  } else {
    silc_hash_table_list(client->channels, &htl);
    while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
      silc_hash_table_del(chl->channel->user_list, chl->client);
      silc_hash_table_del(chl->client->channels, chl->channel);
      silc_free(chl);
    }
    silc_hash_table_list_reset(&htl);
  }
}

/* Lookups route to the client indicated by the `id_data'. The connection
   object and internal data object is returned. Returns NULL if route
   could not be found to the client. If the `client_id' is specified then
   it is used and the `id_data' is ignored. */

SilcSocketConnection
silc_server_get_client_route(SilcServer server,
			     unsigned char *id_data,
			     SilcUInt32 id_len,
			     SilcClientID *client_id,
			     SilcIDListData *idata,
			     SilcClientEntry *client_entry)
{
  SilcClientID *id;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  if (client_entry)
    *client_entry = NULL;

  /* Decode destination Client ID */
  if (!client_id) {
    id = silc_id_str2id(id_data, id_len, SILC_ID_CLIENT);
    if (!id) {
      SILC_LOG_ERROR(("Could not decode destination Client ID, dropped"));
      return NULL;
    }
  } else {
    id = silc_id_dup(client_id, SILC_ID_CLIENT);
  }

  /* If the destination belongs to our server we don't have to route
     the packet anywhere but to send it to the local destination. */
  client = silc_idlist_find_client_by_id(server->local_list, id, TRUE, NULL);
  if (client) {
    silc_free(id);

    /* If we are router and the client has router then the client is in
       our cell but not directly connected to us. */
    if (server->server_type == SILC_ROUTER && client->router) {
      /* We are of course in this case the client's router thus the route
	 to the client is the server who owns the client. So, we will send
	 the packet to that server. */
      if (idata)
	*idata = (SilcIDListData)client->router;
      return client->router->connection;
    }

    /* Seems that client really is directly connected to us */
    if (idata)
      *idata = (SilcIDListData)client;
    if (client_entry)
      *client_entry = client;
    return client->connection;
  }

  /* Destination belongs to someone not in this server. If we are normal
     server our action is to send the packet to our router. */
  if (server->server_type != SILC_ROUTER && !server->standalone) {
    silc_free(id);
    if (idata)
      *idata = (SilcIDListData)server->router;
    return SILC_PRIMARY_ROUTE(server);
  }

  /* We are router and we will perform route lookup for the destination
     and send the packet to fastest route. */
  if (server->server_type == SILC_ROUTER && !server->standalone) {
    /* Check first that the ID is valid */
    client = silc_idlist_find_client_by_id(server->global_list, id,
					   TRUE, NULL);
    if (client) {
      SilcSocketConnection dst_sock;

      dst_sock = silc_server_route_get(server, id, SILC_ID_CLIENT);

      silc_free(id);
      if (idata)
	*idata = (SilcIDListData)dst_sock->user_data;
      return dst_sock;
    }
  }

  silc_free(id);
  return NULL;
}

/* Encodes and returns channel list of channels the `client' has joined.
   Secret channels are not put to the list. */

SilcBuffer silc_server_get_client_channel_list(SilcServer server,
					       SilcClientEntry client,
					       bool get_private,
					       bool get_secret,
					       SilcBuffer *user_mode_list)
{
  SilcBuffer buffer = NULL;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  unsigned char *cid;
  SilcUInt32 id_len;
  SilcUInt16 name_len;
  int len;

  if (user_mode_list)
    *user_mode_list = NULL;

  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    if (channel->mode & SILC_CHANNEL_MODE_SECRET && !get_secret)
      continue;
    if (channel->mode & SILC_CHANNEL_MODE_PRIVATE && !get_private)
      continue;

    cid = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
    id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
    name_len = strlen(channel->channel_name);

    len = 4 + name_len + id_len + 4;
    buffer = silc_buffer_realloc(buffer,
				 (buffer ? buffer->truelen + len : len));
    silc_buffer_pull_tail(buffer, (buffer->end - buffer->data));
    silc_buffer_format(buffer,
		       SILC_STR_UI_SHORT(name_len),
		       SILC_STR_UI_XNSTRING(channel->channel_name,
					    name_len),
		       SILC_STR_UI_SHORT(id_len),
		       SILC_STR_UI_XNSTRING(cid, id_len),
		       SILC_STR_UI_INT(chl->channel->mode),
		       SILC_STR_END);
    silc_buffer_pull(buffer, len);
    silc_free(cid);

    if (user_mode_list) {
      *user_mode_list = silc_buffer_realloc(*user_mode_list,
					    (*user_mode_list ?
					     (*user_mode_list)->truelen + 4 :
					     4));
      silc_buffer_pull_tail(*user_mode_list, ((*user_mode_list)->end -
					      (*user_mode_list)->data));
      SILC_PUT32_MSB(chl->mode, (*user_mode_list)->data);
      silc_buffer_pull(*user_mode_list, 4);
    }
  }
  silc_hash_table_list_reset(&htl);

  if (buffer)
    silc_buffer_push(buffer, buffer->data - buffer->head);
  if (user_mode_list && *user_mode_list)
    silc_buffer_push(*user_mode_list, ((*user_mode_list)->data -
				       (*user_mode_list)->head));

  return buffer;
}

/* A timeout callback for the re-key. We will be the initiator of the
   re-key protocol. */

SILC_TASK_CALLBACK_GLOBAL(silc_server_rekey_callback)
{
  SilcServer server = app_context;
  SilcSocketConnection sock = (SilcSocketConnection)context;
  SilcIDListData idata = (SilcIDListData)sock->user_data;
  SilcProtocol protocol;
  SilcServerRekeyInternalContext *proto_ctx;

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = sock;
  proto_ctx->responder = FALSE;
  proto_ctx->pfs = idata->rekey->pfs;

  /* Perform rekey protocol. Will call the final callback after the
     protocol is over. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_REKEY,
		      &protocol, proto_ctx, silc_server_rekey_final);
  sock->protocol = protocol;

  /* Run the protocol */
  silc_protocol_execute(protocol, server->schedule, 0, 0);

  SILC_LOG_DEBUG(("Rekey protocol completed"));

  /* Re-register re-key timeout */
  silc_schedule_task_add(server->schedule, sock->sock,
			 silc_server_rekey_callback,
			 context, idata->rekey->timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* The final callback for the REKEY protocol. This will actually take the
   new key material into use. */

SILC_TASK_CALLBACK_GLOBAL(silc_server_rekey_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerRekeyInternalContext *ctx =
    (SilcServerRekeyInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSocketConnection sock = ctx->sock;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    SILC_LOG_ERROR(("Error occurred during rekey protocol with "
		    "%s (%s)", sock->hostname, sock->ip));
    silc_protocol_cancel(protocol, server->schedule);
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx);

    /* Reconnect */
    SILC_SET_DISCONNECTING(sock);
    server->backup_noswitch = TRUE;
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    silc_server_close_connection(server, sock);
    silc_server_create_connections(server);
    return;
  }

  /* Purge the outgoing data queue to assure that all rekey packets really
     go to the network before we quit the protocol. */
  silc_server_packet_queue_purge(server, sock);

  /* Cleanup */
  silc_protocol_free(protocol);
  sock->protocol = NULL;
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx);
}

/* Task callback used to retrieve network statistical information from
   router server once in a while. */

SILC_TASK_CALLBACK(silc_server_get_stats)
{
  SilcServer server = (SilcServer)context;
  SilcBuffer idp, packet;

  SILC_LOG_DEBUG(("Retrieving stats from router"));

  if (!server->standalone) {
    idp = silc_id_payload_encode(server->router->id, SILC_ID_SERVER);
    packet = silc_command_payload_encode_va(SILC_COMMAND_STATS, 
					    ++server->cmd_ident, 1,
					    1, idp->data, idp->len);
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, 0, packet->data,
			    packet->len, FALSE);
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

  silc_schedule_task_add(server->schedule, 0, silc_server_get_stats,
			 server, 120, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_LOW);
}
