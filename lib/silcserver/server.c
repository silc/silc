/*

  server.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

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

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

/************************** Types and definitions ***************************/


/************************ Static utility functions **************************/

/* Packet engine callback to receive a packet */

static SilcBool silc_server_packet_receive(SilcPacketEngine engine,
					   SilcPacketStream stream,
					   SilcPacket packet,
					   void *callback_context,
					   void *stream_context)
{
  SilcServerThread thread = callback_context;
  SilcEntryData data = silc_packet_get_context(stream);

  /* Packets we do not handle */
  switch (packet->type) {
  case SILC_PACKET_HEARTBEAT:
  case SILC_PACKET_SUCCESS:
  case SILC_PACKET_FAILURE:
  case SILC_PACKET_REJECT:
  case SILC_PACKET_KEY_EXCHANGE:
  case SILC_PACKET_KEY_EXCHANGE_1:
  case SILC_PACKET_KEY_EXCHANGE_2:
  case SILC_PACKET_REKEY:
  case SILC_PACKET_REKEY_DONE:
  case SILC_PACKET_CONNECTION_AUTH:
  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    return FALSE;
    break;
  }

  /* Only specific packets can come without source ID present. */
  if ((!packet->src_id || data->registered == FALSE) &&
      packet->type != SILC_PACKET_NEW_CLIENT &&
      packet->type != SILC_PACKET_NEW_SERVER &&
      packet->type != SILC_PACKET_DISCONNECT)
    return FALSE;

  /* NEW_CLIENT and NEW_SERVER are accepted only without source ID
     and for unregistered connection. */
  if (packet->src_id && (packet->type == SILC_PACKET_NEW_CLIENT ||
			 packet->type == SILC_PACKET_NEW_SERVER) &&
      data->registered == TRUE)
    return FALSE;

  /* Add the packet to packet queue */
  silc_list_add(thread->packet_queue, packet);

  /* Signal thread that packet has arrived */
  if (!thread->new_packet) {
    thread->new_packet = TRUE;
    SILC_FSM_SEMA_POST(&thread->wait_event);
  }

  return TRUE;
}

/* Packet engine callback to indicate end of stream */

static void silc_server_packet_eos(SilcPacketEngine engine,
				   SilcPacketStream stream,
				   void *callback_context,
				   void *stream_context)
{
  SILC_LOG_DEBUG(("End of stream received"));
}

/* Packet engine callback to indicate error */

static void silc_server_packet_error(SilcPacketEngine engine,
				     SilcPacketStream stream,
				     SilcPacketError error,
				     void *callback_context,
				     void *stream_context)
{

}

/* Packet stream callbacks */
static SilcPacketCallbacks silc_server_stream_cbs =
{
  silc_server_packet_receive,
  silc_server_packet_eos,
  silc_server_packet_error
};

/* Server FSM destructor */

static void silc_server_destructor(SilcFSM fsm, void *fsm_context,
				   void *destructor_context)
{

}

/* Creates new server thread.  Adds to server threads list automatically and
   starts the thread.  Depending on server configuration the created thread
   is either FSM thread of real thread. */

static SilcServerThread silc_server_new_thread(SilcServer server)
{
  SilcServerThread thread;

  SILC_LOG_DEBUG(("Creating new server thread"));

  thread = silc_calloc(1, sizeof(*thread));
  if (!thread)
    return NULL;

  thread->server = server;
  silc_list_init(thread->new_conns, struct SilcServerAcceptStruct, next);

  /* Start packet engine */
  thread->packet_engine =
    silc_packet_engine_start(server->rng, server->server_type == SILC_ROUTER,
			     &silc_server_stream_cbs, thread);
  if (!thread->packet_engine) {
    silc_free(thread);
    return NULL;
  }

  /* Add to server */
  silc_list_add(server->threads, thread);

  /* Start the thread */
  silc_fsm_thread_init(&thread->thread, &server->fsm, thread,
		       NULL, NULL, server->params->use_threads);
  silc_fsm_start(&thread->thread, silc_server_thread_st_start);

  /* Allocate data stack.  Its allocation is allowed to fail so we don't
     check for it. */
  thread->stack = silc_stack_alloc(0);

  return thread;
}

/* Network listener callback to accept new connections */

static void silc_server_accept_connection(SilcNetStatus status,
					  SilcStream stream, void *context)
{
  SilcServer server = context;
  SilcServerAccept ac;

  if (status != SILC_NET_OK) {
    SILC_LOG_ERROR(("Error %d accepting new connection", status));
    return;
  }

  ac = silc_calloc(1, sizeof(*ac));
  if (!ac) {
    silc_stream_destroy(stream);
    return;
  }
  ac->stream = stream;

  /* Add as new connection */
  silc_list_add(server->new_conns, ac);

  /* Signal server of new connection */
  if (!server->new_connection) {
    server->new_connection = TRUE;
    SILC_FSM_SEMA_POST(&server->wait_event);
  }
}

/* Packet thread destructor */

static void silc_server_thread_packet_dest(SilcFSM fsm, void *fsm_context,
					   void *destructor_context)
{
  silc_fsm_free(fsm);
}


/****************************** Server thread *******************************/

/* Thread's start function.  This may be FSM thread or real system thread,
   depending on server configuration. */

SILC_FSM_STATE(silc_server_thread_st_start)
{
  SilcServerThread thread = fsm_context;

  SILC_LOG_DEBUG(("New server thread started"));

  /*** Run thread's machine */
  silc_fsm_init(&thread->fsm, thread, NULL, NULL, silc_fsm_get_schedule(fsm));
  silc_fsm_sema_init(&thread->wait_event, &thread->fsm, 0);
  silc_fsm_start_sync(&thread->fsm, silc_server_thread_st_run);

  /* Signal server that we are up */
  SILC_FSM_SEMA_POST(&thread->server->thread_up);

  /* Wait here for this thread to finish */
  return SILC_FSM_WAIT;
}

/* Thread's machine's main state where we wait for various events. */

SILC_FSM_STATE(silc_server_thread_st_run)
{
  SilcServerThread thread = fsm_context;

  SILC_LOG_DEBUG(("Start"));

  /* Wait for events */
  SILC_FSM_SEMA_WAIT(&thread->wait_event);

  /* Process events */

  if (thread->new_packet) {
    /*** Packet received */
    SilcPacket packet;
    SilcFSMThread t;

    SILC_LOG_DEBUG(("Processing incoming packets"));

    /* Each packet is processed in FSM thread */
    silc_list_start(thread->packet_queue);
    while ((packet = silc_list_get(thread->packet_queue)) != SILC_LIST_END) {
      t = silc_fsm_thread_alloc(fsm, thread, silc_server_thread_packet_dest,
				NULL, FALSE);
      if (t) {
	silc_fsm_set_state_context(t, packet);
	silc_fsm_start_sync(t, silc_server_st_packet_received);
      }
    }

    /* Empty the queue */
    silc_list_init(thread->packet_queue, struct SilcPacketStruct, next);

    thread->new_packet = FALSE;
    return SILC_FSM_CONTINUE;
  }

  silc_mutex_lock(thread->server->lock);

  if (thread->new_connection) {
    /*** Accept new connection */
    SilcServerAccept ac;

    SILC_LOG_DEBUG(("Processing incoming connections"));

    /* Accept the new connection in own thread */
    silc_list_start(thread->new_conns);
    while ((ac = silc_list_get(thread->new_conns)) != SILC_LIST_END) {
      ac->thread = thread;
      ac->t = silc_fsm_thread_alloc(&thread->fsm, ac,
				    silc_server_accept_connection_dest,
				    NULL, FALSE);
      silc_fsm_start(ac->t, silc_server_st_accept_connection);
    }

    /* Empty the list */
    silc_list_init(thread->new_conns, struct SilcServerAcceptStruct, next);

    thread->new_connection = FALSE;
    silc_mutex_unlock(thread->server->lock);
    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
#if defined(SILC_DEBUG)
  assert(FALSE);
#endif /* SILC_DEBUG */
  return SILC_FSM_CONTINUE;
}


/*************************** Main server machine ****************************/

/* The server's main state where we wait for various events */

SILC_FSM_STATE(silc_server_st_run)
{
  SilcServer server = fsm_context;

  SILC_LOG_DEBUG(("Start"));

  /* Wait for events */
  SILC_FSM_SEMA_WAIT(&server->wait_event);

  /* Process events */

  if (server->run_callback && server->running) {
    /* Call running callbcak back to application */
    server->run_callback = FALSE;
    server->running(server, server->running_context);
    return SILC_FSM_CONTINUE;
  }

  if (server->new_connection) {
    /** New connection */
    silc_fsm_next(fsm, silc_server_st_new_connection);
    return SILC_FSM_CONTINUE;
  }

  if (server->connect_router) {
    /** Connect to router(s) */
    silc_fsm_next(fsm, silc_server_st_connect_router);
    return SILC_FSM_CONTINUE;
  }

  if (server->get_statistics) {
    /** Retrieve statistics */
    silc_fsm_next(fsm, silc_server_st_get_stats);
    return SILC_FSM_CONTINUE;
  }

  if (server->reconfigure) {
    /** Reconfigure server */
    silc_fsm_next(fsm, silc_server_st_reconfigure);
    return SILC_FSM_CONTINUE;
  }

  if (server->server_shutdown) {
    /** Shutdown server */
    silc_fsm_next(fsm, silc_server_st_stop);
    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
#if defined(SILC_DEBUG)
  assert(FALSE);
#endif /* SILC_DEBUG */
  return SILC_FSM_CONTINUE;
}

/* New connection received */

SILC_FSM_STATE(silc_server_st_new_connection)
{
  SilcServer server = fsm_context;
  SilcServerThread thread;
  SilcServerAccept ac;

  SILC_LOG_DEBUG(("Process new connections"));

  silc_list_start(server->new_conns);
  while ((ac = silc_list_get(server->new_conns)) != SILC_LIST_END) {

    /* Find thread where to put this connection */
    silc_list_start(server->threads);
    while ((thread = silc_list_get(server->threads)) != SILC_LIST_END) {
      if (!server->params->use_threads)
	break;
      if (thread->num_conns < server->params->connections_per_thread)
	break;
    }

    if (!thread) {
      /** Create new thread */
      thread = silc_server_new_thread(server);
      if (!thread) {
	silc_list_del(server->new_conns, ac);
	silc_stream_destroy(ac->stream);
	silc_free(ac);
	continue;
      }

      silc_fsm_next(fsm, silc_server_st_wait_new_thread);
      return SILC_FSM_CONTINUE;
    }

    silc_list_del(server->new_conns, ac);

    /* Give this connection to this thread */
    silc_mutex_lock(server->lock);
    silc_list_add(thread->new_conns, ac);
    thread->num_conns++;

    SILC_LOG_DEBUG(("Signal thread for new connection"));

    /* Signal the thread for new connection */
    if (!thread->new_connection) {
      thread->new_connection = TRUE;
      SILC_FSM_SEMA_POST(&thread->wait_event);
    }
    silc_mutex_unlock(server->lock);
  }

  server->new_connection = FALSE;

  /** Connections processed */
  silc_fsm_next(fsm, silc_server_st_run);
  return SILC_FSM_CONTINUE;
}

/* Wait here until newly created thread is up */

SILC_FSM_STATE(silc_server_st_wait_new_thread)
{
  SilcServer server = fsm_context;

  /* Wait here until new thread is up */
  SILC_FSM_SEMA_WAIT(&server->thread_up);

  /** Process new connections */
  silc_fsm_next(fsm, silc_server_st_new_connection);
  return SILC_FSM_CONTINUE;
}

/* Stops server */

SILC_FSM_STATE(silc_server_st_stop)
{
#if 0
  SilcServer server = fsm_context;

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
	silc_schedule_task_del_by_fd(server->schedule,
				     server->sockets[i]->sock);
	silc_server_disconnect_remote(server, server->sockets[i],
				      SILC_STATUS_OK,
				      "Server is shutting down");
	if (server->sockets[i]) {
	  if (sock->user_data)
	    silc_server_free_sock_user_data(server, sock,
					    "Server is shutting down");
	  silc_socket_free(sock);
	}
      } else {
	silc_socket_free(server->sockets[i]);
	server->sockets[i] = NULL;
        server->stat.conn_num--;
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
#endif /* 0 */

  /** Wait events */
  silc_fsm_next(fsm, silc_server_st_run);
  return SILC_FSM_CONTINUE;
}

/* Reconfigure server */

SILC_FSM_STATE(silc_server_st_reconfigure)
{
  SilcServer server = fsm_context;

  SILC_LOG_DEBUG(("Reconfiguring server"));

  /** Wait events */
  server->reconfigure = FALSE;
  silc_fsm_next(fsm, silc_server_st_run);
  return SILC_FSM_CONTINUE;
}

/* Get statistics */

SILC_FSM_STATE(silc_server_st_get_stats)
{
  SilcServer server = fsm_context;

  SILC_LOG_DEBUG(("Getting statistics"));

  /** Wait events */
  server->get_statistics = FALSE;
  silc_fsm_next(fsm, silc_server_st_run);
  return SILC_FSM_CONTINUE;
}


/**************************** Public interface ******************************/

/* Allocates server context and returns it */

SilcServer silc_server_alloc(void *app_context, SilcServerParams params,
			     SilcSchedule schedule)
{
  SilcServer server;
  SilcServerParamInterface iface;
  SilcBool id_created = FALSE;

  SILC_LOG_DEBUG(("Allocating new server"));

  if (!schedule || !params)
    return NULL;

  server = silc_calloc(1, sizeof(*server));
  if (!server)
    return NULL;

  server->app_context = app_context;
  server->schedule = schedule;
  server->params = params;
  server->server_type = SILC_SERVER;
  server->standalone = TRUE;
#ifdef SILC_SIM
  server->sim = silc_dlist_init();
#endif

#if defined(SILC_DEBUG)
  /* Set debugging on if configured */
  if (params->debug_string) {
    silc_log_debug(TRUE);
    silc_log_set_debug_string(params->debug_string);
  }
#endif /* SILC_DEBUG */

  /* Allocate ID caches */
  server->clients = silc_idcache_alloc(0, SILC_ID_CLIENT,
				       silc_server_destructor_client, server);
  server->servers = silc_idcache_alloc(0, SILC_ID_SERVER,
				       silc_server_destructor_server, server);
  server->channels = silc_idcache_alloc(0, SILC_ID_CHANNEL,
					silc_server_destructor_channel,
					server);
  if (!server->clients || !server->servers || !server->channels) {
    SILC_LOG_ERROR(("Could not allocate ID cache"));
    goto err;
  }

  /* Allocate key repository */
  server->repository = silc_skr_alloc(schedule);
  if (!server->repository) {
    SILC_LOG_ERROR(("Could not allocate key repository"));
    goto err;
  }

  /* Allocate server lock */
  if (!silc_mutex_alloc(&server->lock)) {
    SILC_LOG_DEBUG(("Could not allocate server lock"));
    goto err;
  }

  /* Init FSM */
  silc_fsm_init(&server->fsm, server, silc_server_destructor, NULL, schedule);

  /* Init semaphore signallers */
  silc_fsm_sema_init(&server->wait_event, &server->fsm, 0);
  silc_fsm_sema_init(&server->thread_up, &server->fsm, 0);

  /* Initialize lists */
  silc_list_init(server->new_conns, struct SilcServerAcceptStruct, next);
  silc_list_init(server->command_pool, struct SilcServerCommandStruct, next);

#if 0
  /* Register all paramsured ciphers, PKCS and hash functions. */
  if (!silc_server_params_register_ciphers(server))
    silc_cipher_register_default();
  if (!silc_server_params_register_pkcs(server))
    silc_pkcs_register_default();
  if (!silc_server_params_register_hashfuncs(server))
    silc_hash_register_default();
  if (!silc_server_params_register_hmacs(server))
    silc_hmac_register_default();
#else
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
#endif /* 0 */

  /* Initialize random number generator for the server. */
  server->rng = silc_rng_alloc();
  if (!server->rng) {
    SILC_LOG_ERROR(("Could not allocate RNG"));
    goto err;
  }
  silc_rng_init(server->rng);
  silc_rng_global_init(server->rng);

  /* Initialize hash functions for server to use */
  silc_hash_alloc("md5", &server->md5hash);
  silc_hash_alloc("sha1", &server->sha1hash);

  /* Steal public and private key from the params object */
  server->public_key = server->params->server_info->public_key;
  server->private_key = server->params->server_info->private_key;
  server->params->server_info->public_key = NULL;
  server->params->server_info->private_key = NULL;

  /* Allocate PKCS context for local public and private keys */
  if (!silc_pkcs_alloc(server->public_key->name, SILC_PKCS_SILC,
		       &server->pkcs))
    goto err;
  silc_pkcs_public_key_set(server->pkcs, server->public_key);
  silc_pkcs_private_key_set(server->pkcs, server->private_key);

  /* Create network listener(s) */
  server->listeners = silc_dlist_init();
  if (!server->listeners)
    goto err;
  silc_list_start(params->server_info->interfaces);
  while ((iface = silc_list_get(params->server_info->interfaces)) !=
	 SILC_LIST_END) {

    if (!id_created) {
      /* Create a Server ID for the server */
      if (!silc_server_create_server_id(server, iface->ip, iface->port,
					&server->id)) {
	SILC_LOG_ERROR(("Could not create Server ID"));
	goto err;
      }

      id_created = TRUE;
    }

    SilcNetServer listener =
      silc_net_create_server((const char **)&iface->ip, 1, iface->port,
			     params->require_reverse_lookup,
			     server->schedule,
			     silc_server_accept_connection, server);
    if (!listener) {
      SILC_LOG_ERROR(("Could not bind %s on %d", iface->ip, iface->port));
      goto err;
    }

    silc_dlist_add(server->listeners, listener);
  }

  /* First, register log files paramsuration for error output */
  //  silc_server_params_setlogfiles(server);

  /* Init watcher lists */
  server->watcher_list =
    silc_hash_table_alloc(1, silc_hash_client_id_hash, NULL,
			  silc_hash_data_compare, (void *)CLIENTID_HASH_LEN,
			  NULL, NULL, TRUE);
  if (!server->watcher_list)
    goto err;
#if 0
  server->watcher_list_pk =
    silc_hash_table_alloc(1, silc_hash_public_key, NULL,
			  silc_hash_public_key_compare, NULL,
			  NULL, NULL, TRUE);
  if (!server->watcher_list_pk)
    goto err;
#endif /* 0 */

  server->server_name = server->params->server_info->server_name;
  server->params->server_info->server_name = NULL;

#if 0
  /* If server connections has been paramsured then we must be router as
     normal server cannot have server connections, only router connections. */
  if (server->params->servers) {
    SilcServerParamsServer *ptr = server->params->servers;

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
#endif /* 0 */

  if (server->server_type == SILC_ROUTER)
    server->stat.routers++;

  return server;

 err:
  return NULL;
}

/* Free's the SILC server context */

void silc_server_free(SilcServer server)
{
#if 0
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
  silc_server_params_unref(&server->params_ref);
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

  if (server->pk_hash)
    silc_hash_table_free(server->pk_hash);

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

#endif /* 0 */

  silc_idcache_free(server->clients);
  silc_idcache_free(server->servers);
  silc_idcache_free(server->channels);
  silc_hash_table_free(server->watcher_list);
  silc_hash_table_free(server->watcher_list_pk);

  silc_hash_free(server->md5hash);
  silc_hash_free(server->sha1hash);
  silc_hmac_unregister_all();
  silc_hash_unregister_all();
  silc_cipher_unregister_all();
  silc_pkcs_unregister_all();
}

/* Starts the SILC server FSM machine and returns immediately.  The
   scheduler must be run or be running already when this returns. */

void silc_server_run(SilcServer server, SilcServerRunning running,
		     void *running_context)
{
  SILC_LOG_INFO(("Starting SILC server"));

  server->starttime = time(NULL);
  server->running = running;
  server->running_context = running_context;

  /* Start the server */
  silc_fsm_start_sync(&server->fsm, silc_server_st_run);

  /* Signal the application when we are running */
  server->run_callback = TRUE;
  SILC_FSM_SEMA_POST(&server->wait_event);

  /* Signal to connect to router */
  server->connect_router = TRUE;
  SILC_FSM_SEMA_POST(&server->wait_event);

  /* Start getting statistics from the network on normal server */
  if (server->server_type != SILC_ROUTER) {
    server->get_statistics = TRUE;
    SILC_FSM_SEMA_POST(&server->wait_event);
  }
}

/* Stops the SILC server */

void silc_server_stop(SilcServer server, SilcServerStop stopped,
		      void *stop_context)
{
  SILC_LOG_INFO(("Stopping SILC server"));

  server->stopped = stopped;
  server->stop_context = stop_context;

  /* Signal that server is going down */
  server->server_shutdown = TRUE;
  SILC_FSM_SEMA_POST(&server->wait_event);
}

/* Disconnects remote connection */

SilcBool silc_server_disconnect(SilcServer server,
				SilcPacketStream stream,
				SilcStatus error,
				const char *error_string)
{
  return TRUE;
}
