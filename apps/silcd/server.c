/*

  server.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
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
SILC_TASK_CALLBACK(silc_server_connect_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router_second);
SILC_TASK_CALLBACK(silc_server_connect_to_router_final);
SILC_TASK_CALLBACK(silc_server_accept_new_connection);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_second);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_final);
SILC_TASK_CALLBACK(silc_server_packet_process);
SILC_TASK_CALLBACK(silc_server_packet_parse_real);
SILC_TASK_CALLBACK(silc_server_timeout_remote);

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
  if (server) {
#ifdef SILC_SIM
    SilcSimContext *sim;
#endif

    if (server->local_list)
      silc_free(server->local_list);
    if (server->global_list)
      silc_free(server->global_list);
    if (server->rng)
      silc_rng_free(server->rng);

#ifdef SILC_SIM
    while ((sim = silc_dlist_get(server->sim)) != SILC_LIST_END) {
      silc_dlist_del(server->sim, sim);
      silc_sim_free(sim);
    }
    silc_dlist_uninit(server->sim);
#endif

    if (server->params)
      silc_free(server->params);

    if (server->pending_commands)
      silc_dlist_uninit(server->pending_commands);

    silc_math_primegen_uninit(); /* XXX */
    silc_free(server);
  }
}

/* Initializes the entire SILC server. This is called always before running
   the server. This is called only once at the initialization of the program.
   This binds the server to its listenning port. After this function returns 
   one should call silc_server_run to start the server. This returns TRUE 
   when everything is ok to run the server. Configuration file must be
   read and parsed before calling this. */

int silc_server_init(SilcServer server)
{
  int *sock = NULL, sock_count = 0, i;
  SilcServerID *id;
  SilcServerEntry id_entry;

  SILC_LOG_DEBUG(("Initializing server"));
  assert(server);
  assert(server->config);

  /* XXX After server is made as Silc Server Library this can be given
     as argument, for now this is hard coded */
  server->params = silc_calloc(1, sizeof(*server->params));
  server->params->retry_count = SILC_SERVER_RETRY_COUNT;
  server->params->retry_interval_min = SILC_SERVER_RETRY_INTERVAL_MIN;
  server->params->retry_interval_max = SILC_SERVER_RETRY_INTERVAL_MAX;
  server->params->retry_keep_trying = FALSE;
  server->params->protocol_timeout = 60;
  server->params->require_reverse_mapping = FALSE;

  /* Set log files where log message should be saved. */
  server->config->server = server;
  silc_config_server_setlogfiles(server->config);
 
  /* Register all configured ciphers, PKCS and hash functions. */
  silc_config_server_register_ciphers(server->config);
  silc_config_server_register_pkcs(server->config);
  silc_config_server_register_hashfuncs(server->config);

  /* Initialize random number generator for the server. */
  server->rng = silc_rng_alloc();
  silc_rng_init(server->rng);
  silc_math_primegen_init(); /* XXX */

  /* Initialize hash functions for server to use */
  silc_hash_alloc("md5", &server->md5hash);
  silc_hash_alloc("sha1", &server->sha1hash);

  /* Initialize none cipher */
  silc_cipher_alloc("none", &server->none_cipher);

  /* XXXXX Generate RSA key pair */
  {
    unsigned char *public_key;
    unsigned char *private_key;
    unsigned int pk_len, prv_len;
    struct stat st;

    if (stat("pubkey.pub", &st) < 0 && stat("privkey.prv", &st) < 0) {

      if (silc_pkcs_alloc("rsa", &server->pkcs) == FALSE) {
	SILC_LOG_ERROR(("Could not create RSA key pair"));
	goto err0;
      }
      
      if (server->pkcs->pkcs->init(server->pkcs->context, 
				   1024, server->rng) == FALSE) {
	SILC_LOG_ERROR(("Could not generate RSA key pair"));
	goto err0;
      }
      
      public_key = server->pkcs->pkcs->get_public_key(server->pkcs->context,
						      &pk_len);
      private_key = server->pkcs->pkcs->get_private_key(server->pkcs->context,
							&prv_len);
      
      SILC_LOG_HEXDUMP(("public key"), public_key, pk_len);
      SILC_LOG_HEXDUMP(("private key"), private_key, prv_len);
      
      server->public_key = 
	silc_pkcs_public_key_alloc("rsa", "UN=root, HN=dummy",
				   public_key, pk_len);
      server->private_key = 
	silc_pkcs_private_key_alloc("rsa", private_key, prv_len);
      
      /* XXX Save keys */
      silc_pkcs_save_public_key("pubkey.pub", server->public_key,
				SILC_PKCS_FILE_PEM);
      silc_pkcs_save_private_key("privkey.prv", server->private_key, NULL,
				 SILC_PKCS_FILE_BIN);

      memset(public_key, 0, pk_len);
      memset(private_key, 0, prv_len);
      silc_free(public_key);
      silc_free(private_key);
    } else {
      silc_pkcs_load_public_key("pubkey.pub", &server->public_key,
				SILC_PKCS_FILE_PEM);
      silc_pkcs_load_private_key("privkey.prv", &server->private_key,
				 SILC_PKCS_FILE_BIN);
    }
  }

  /* Create a listening server. Note that our server can listen on
     multiple ports. All listeners are created here and now. */
  /* XXX Still check this whether to use server_info or listen_port. */
  sock_count = 0;
  while(server->config->listen_port) {
    int tmp;

    tmp = silc_net_create_server(server->config->listen_port->port,
				 server->config->listen_port->host);
    if (tmp < 0)
      goto err0;

    sock = silc_realloc(sock, (sizeof(int *) * (sock_count + 1)));
    sock[sock_count] = tmp;
    server->config->listen_port = server->config->listen_port->next;
    sock_count++;
  }

  /* Initialize ID caches */
  server->local_list->clients = silc_idcache_alloc(0);
  server->local_list->servers = silc_idcache_alloc(0);
  server->local_list->channels = silc_idcache_alloc(0);

  /* These are allocated for normal server as well as these hold some 
     global information that the server has fetched from its router. For 
     router these are used as they are supposed to be used on router. */
  server->global_list->clients = silc_idcache_alloc(0);
  server->global_list->servers = silc_idcache_alloc(0);
  server->global_list->channels = silc_idcache_alloc(0);

  /* Allocate the entire socket list that is used in server. Eventually 
     all connections will have entry in this table (it is a table of 
     pointers to the actual object that is allocated individually 
     later). */
  server->sockets = silc_calloc(SILC_SERVER_MAX_CONNECTIONS,
				sizeof(*server->sockets));

  for (i = 0; i < sock_count; i++) {
    SilcSocketConnection newsocket = NULL;

    /* Set socket to non-blocking mode */
    silc_net_set_socket_nonblock(sock[i]);
    server->sock = sock[i];
    
    /* Create a Server ID for the server. */
    silc_id_create_server_id(sock[i], server->rng, &id);
    if (!id) {
      goto err0;
    }
    
    server->id = id;
    server->id_string = silc_id_id2str(id, SILC_ID_SERVER);
    server->id_string_len = silc_id_get_len(SILC_ID_SERVER);
    server->id_type = SILC_ID_SERVER;
    server->server_name = server->config->server_info->server_name;

    /* Add ourselves to the server list. We don't have a router yet 
       beacuse we haven't established a route yet. It will be done later. 
       For now, NULL is sent as router. This allocates new entry to
       the ID list. */
    id_entry = 
      silc_idlist_add_server(server->local_list,
			     server->config->server_info->server_name,
			     server->server_type, server->id, NULL, NULL);
    if (!id_entry) {
      SILC_LOG_ERROR(("Could not add ourselves to cache"));
      goto err0;
    }
    
    /* Add ourselves also to the socket table. The entry allocated above
       is sent as argument for fast referencing in the future. */
    silc_socket_alloc(sock[i], SILC_SOCKET_TYPE_SERVER, id_entry, 
		      &newsocket);
    if (!newsocket)
      goto err0;

    server->sockets[sock[i]] = newsocket;

    /* Put the allocated socket pointer also to the entry allocated above 
       for fast back-referencing to the socket list. */
    id_entry->connection = (void *)server->sockets[sock[i]];
    server->id_entry = id_entry;
  }

  /* Register the task queues. In SILC we have by default three task queues. 
     One task queue for non-timeout tasks which perform different kind of 
     I/O on file descriptors, timeout task queue for timeout tasks, and,
     generic non-timeout task queue whose tasks apply to all connections. */
  silc_task_queue_alloc(&server->io_queue, TRUE);
  if (!server->io_queue) {
    goto err0;
  }
  silc_task_queue_alloc(&server->timeout_queue, TRUE);
  if (!server->timeout_queue) {
    goto err1;
  }
  silc_task_queue_alloc(&server->generic_queue, TRUE);
  if (!server->generic_queue) {
    goto err1;
  }

  /* Register protocols */
  silc_server_protocols_register();

  /* Initialize the scheduler */
  silc_schedule_init(&server->io_queue, &server->timeout_queue, 
		     &server->generic_queue, 
		     SILC_SERVER_MAX_CONNECTIONS);
  
  /* Add the first task to the queue. This is task that is executed by
     timeout. It expires as soon as the caller calls silc_server_run. This
     task performs authentication protocol and key exchange with our
     primary router. */
  silc_task_register(server->timeout_queue, sock[0], 
		     silc_server_connect_to_router,
		     (void *)server, 0, 1,
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_NORMAL);

  /* Add listener task to the queue. This task receives new connections to the 
     server. This task remains on the queue until the end of the program. */
  silc_task_register(server->io_queue, sock[0],
		     silc_server_accept_new_connection,
		     (void *)server, 0, 0, 
		     SILC_TASK_FD,
		     SILC_TASK_PRI_NORMAL);
  server->listenning = TRUE;

  /* If server connections has been configured then we must be router as
     normal server cannot have server connections, only router connections. */
  if (server->config->servers)
    server->server_type = SILC_ROUTER;

  SILC_LOG_DEBUG(("Server initialized"));

  /* We are done here, return succesfully */
  return TRUE;

  silc_task_queue_free(server->timeout_queue);
 err1:
  silc_task_queue_free(server->io_queue);
 err0:
  for (i = 0; i < sock_count; i++)
    silc_net_close_server(sock[i]);

  return FALSE;
}

/* Stops the SILC server. This function is used to shutdown the server. 
   This is usually called after the scheduler has returned. After stopping 
   the server one should call silc_server_free. */

void silc_server_stop(SilcServer server)
{
  SILC_LOG_DEBUG(("Stopping server"));

  /* Stop the scheduler, although it might be already stopped. This
     doesn't hurt anyone. This removes all the tasks and task queues,
     as well. */
  silc_schedule_stop();
  silc_schedule_uninit();

  silc_server_protocols_unregister();

  SILC_LOG_DEBUG(("Server stopped"));
}

/* The heart of the server. This runs the scheduler thus runs the server. 
   When this returns the server has been stopped and the program will
   be terminated. */

void silc_server_run(SilcServer server)
{
  SILC_LOG_DEBUG(("Running server"));

  /* Start the scheduler, the heart of the SILC server. When this returns
     the program will be terminated. */
  silc_schedule();
}

/* Timeout callback that will be called to retry connecting to remote
   router. This is used by both normal and router server. This will wait
   before retrying the connecting. The timeout is generated by exponential
   backoff algorithm. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_retry)
{
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServer server = sconn->server;

  SILC_LOG_INFO(("Retrying connecting to a router"));

  /* Calculate next timeout */
  if (sconn->retry_count >= 1) {
    sconn->retry_timeout = sconn->retry_timeout * SILC_SERVER_RETRY_MULTIPLIER;
    if (sconn->retry_timeout > SILC_SERVER_RETRY_INTERVAL_MAX)
      sconn->retry_timeout = SILC_SERVER_RETRY_INTERVAL_MAX;
  } else {
    sconn->retry_timeout = server->params->retry_interval_min;
  }
  sconn->retry_count++;
  sconn->retry_timeout = sconn->retry_timeout +
    silc_rng_get_rn32(server->rng) % SILC_SERVER_RETRY_RANDOMIZER;

  /* If we've reached max retry count, give up. */
  if (sconn->retry_count > server->params->retry_count && 
      server->params->retry_keep_trying == FALSE) {
    SILC_LOG_ERROR(("Could not connect to router, giving up"));
    return;
  }

  /* Wait one before retrying */
  silc_task_register(server->timeout_queue, fd, silc_server_connect_router,
		     context, sconn->retry_timeout, 
		     server->params->retry_interval_min_usec,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* Generic routine to use connect to a router. */

SILC_TASK_CALLBACK(silc_server_connect_router)
{    
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcServer server = sconn->server;
  SilcSocketConnection newsocket;
  SilcProtocol protocol;
  SilcServerKEInternalContext *proto_ctx;
  int sock;

  /* Connect to remote host */
  sock = silc_net_create_connection(sconn->remote_port, 
				    sconn->remote_host);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not connect to router"));
    silc_task_register(server->timeout_queue, fd, 
		       silc_server_connect_to_router_retry,
		       context, 0, 1, SILC_TASK_TIMEOUT, 
		       SILC_TASK_PRI_NORMAL);
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* Create socket connection for the connection. Even though we
     know that we are connecting to a router we will mark the socket
     to be unknown connection until we have executed authentication
     protocol. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, NULL, &newsocket);
  server->sockets[sock] = newsocket;
  newsocket->hostname = sconn->remote_host;
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
      
  /* Perform key exchange protocol. silc_server_connect_to_router_second
     will be called after the protocol is finished. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE, 
		      &protocol, proto_ctx,
		      silc_server_connect_to_router_second);
  newsocket->protocol = protocol;
      
  /* Register a timeout task that will be executed if the protocol
     is not executed within set limit. */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, sock, 
		       silc_server_timeout_remote,
		       server, server->params->protocol_timeout,
		       server->params->protocol_timeout_usec,
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
  protocol->execute(server->timeout_queue, 0, protocol, sock, 0, 0);
}
  
/* This function connects to our primary router or if we are a router this
   establishes all our primary routes. This is called at the start of the
   server to do authentication and key exchange with our router - called
   from schedule. */

SILC_TASK_CALLBACK(silc_server_connect_to_router)
{
  SilcServer server = (SilcServer)context;
  SilcServerConnection sconn;

  SILC_LOG_DEBUG(("Connecting to router(s)"));

  /* If we are normal SILC server we need to connect to our cell's
     router. */
  if (server->server_type == SILC_SERVER) {
    SILC_LOG_DEBUG(("We are normal server"));

    /* Create connection to the router, if configured. */
    if (server->config->routers) {

      /* Allocate connection object for hold connection specific stuff. */
      sconn = silc_calloc(1, sizeof(*sconn));
      sconn->server = server;
      sconn->remote_host = server->config->routers->host;
      sconn->remote_port = server->config->routers->port;

      silc_task_register(server->timeout_queue, fd, 
			 silc_server_connect_router,
			 (void *)sconn, 0, 1, SILC_TASK_TIMEOUT, 
			 SILC_TASK_PRI_NORMAL);
      return;
    }
  }

  /* If we are a SILC router we need to establish all of our primary
     routes. */
  if (server->server_type == SILC_ROUTER) {
    SilcConfigServerSectionServerConnection *ptr;

    SILC_LOG_DEBUG(("We are router"));

    /* Create the connections to all our routes */
    ptr = server->config->routers;
    while (ptr) {

      SILC_LOG_DEBUG(("Router connection [%s] %s:%d",
		      ptr->initiator ? "Initiator" : "Responder",
		      ptr->host, ptr->port));

      if (ptr->initiator) {
	/* Allocate connection object for hold connection specific stuff. */
	sconn = silc_calloc(1, sizeof(*sconn));
	sconn->server = server;
	sconn->remote_host = ptr->host;
	sconn->remote_port = ptr->port;

	silc_task_register(server->timeout_queue, fd, 
			   silc_server_connect_router,
			   (void *)sconn, 0, 1, SILC_TASK_TIMEOUT, 
			   SILC_TASK_PRI_NORMAL);
      }

      if (!ptr->next)
	return;

      ptr = ptr->next;
    }
  }

  SILC_LOG_DEBUG(("No router(s), server will be standalone"));
  
  /* There wasn't a configured router, we will continue but we don't
     have a connection to outside world.  We will be standalone server. */
  server->standalone = TRUE;
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
  SilcSocketConnection sock = NULL;
  SilcServerConnAuthInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    sock->protocol = NULL;
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    return;
  }
  
  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->context = (void *)sconn;
  proto_ctx->sock = sock = server->sockets[fd];
  proto_ctx->ske = ctx->ske;	   /* Save SKE object from previous protocol */
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

  /* Resolve the authentication method used in this connection */
  proto_ctx->auth_meth = SILC_PROTOCOL_CONN_AUTH_PASSWORD;
  if (server->config->routers) {
    SilcConfigServerSectionServerConnection *conn = NULL;

    /* Check if we find a match from user configured connections */
    conn = silc_config_server_find_router_conn(server->config,
					       sock->hostname,
					       sock->port);
    if (conn) {
      /* Match found. Use the configured authentication method */
      proto_ctx->auth_meth = conn->auth_meth;
      if (conn->auth_data) {
	proto_ctx->auth_data = strdup(conn->auth_data);
	proto_ctx->auth_data_len = strlen(conn->auth_data);
      }
    } else {
      /* No match found. */
      /* XXX */
    }
  } else {
    /* XXX */
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
     this timelimit the connection will be terminated. Currently
     this is 15 seconds and is hard coded limit (XXX). */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, sock->sock, 
		       silc_server_timeout_remote,
		       (void *)server, 15, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);

  /* Run the protocol */
  sock->protocol->execute(server->timeout_queue, 0, 
			  sock->protocol, sock->sock, 0, 0);
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
  SilcServerEntry id_entry;
  SilcBuffer packet;
  unsigned char *id_string;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR) {
    /* Error occured during protocol */
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
    goto out;
  }

  /* Add a task to the queue. This task receives new connections to the 
     server. This task remains on the queue until the end of the program. */
  if (!server->listenning) {
    silc_task_register(server->io_queue, server->sock, 
		       silc_server_accept_new_connection,
		       (void *)server, 0, 0, 
		       SILC_TASK_FD,
		       SILC_TASK_PRI_NORMAL);
    server->listenning = TRUE;
  }

  /* Send NEW_SERVER packet to the router. We will become registered
     to the SILC network after sending this packet. */
  id_string = silc_id_id2str(server->id, SILC_ID_SERVER);
  packet = silc_buffer_alloc(2 + 2 + SILC_ID_SERVER_LEN + 
			     strlen(server->server_name));
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(SILC_ID_SERVER_LEN),
		     SILC_STR_UI_XNSTRING(id_string, SILC_ID_SERVER_LEN),
		     SILC_STR_UI_SHORT(strlen(server->server_name)),
		     SILC_STR_UI_XNSTRING(server->server_name,
					  strlen(server->server_name)),
		     SILC_STR_END);

  /* Send the packet */
  silc_server_packet_send(server, ctx->sock, SILC_PACKET_NEW_SERVER, 0,
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);
  silc_free(id_string);

  SILC_LOG_DEBUG(("Connected to router %s", sock->hostname));

  /* Add the connected router to local server list */
  server->standalone = FALSE;
  id_entry = silc_idlist_add_server(server->local_list, sock->hostname,
				    SILC_ROUTER, ctx->dest_id, NULL, sock);
  if (!id_entry) {
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
    goto out;
  }

  silc_idlist_add_data(id_entry, (SilcIDListData)sock->user_data);
  silc_free(sock->user_data);
  sock->user_data = (void *)id_entry;
  sock->type = SILC_SOCKET_TYPE_ROUTER;
  server->id_entry->router = id_entry;
  server->router = id_entry;
  server->router->data.registered = TRUE;

 out:
  /* Free the temporary connection data context */
  if (sconn)
    silc_free(sconn);

  /* Free the protocol object */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx);
  sock->protocol = NULL;
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

  sock = silc_net_accept_connection(server->sock);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not accept new connection: %s", strerror(errno)));
    server->stat.conn_failures++;
    return;
  }

  /* Check max connections */
  if (sock > SILC_SERVER_MAX_CONNECTIONS) {
    if (server->config->redirect) {
      /* XXX Redirecting connection to somewhere else now?? */
      /*silc_server_send_notify("Server is full, trying to redirect..."); */
    } else {
      SILC_LOG_ERROR(("Refusing connection, server is full"));
      server->stat.conn_failures++;
    }
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* We don't create a ID yet, since we don't know what type of connection
     this is yet. But, we do add the connection to the socket table. */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, NULL, &newsocket);
  server->sockets[sock] = newsocket;

  /* XXX This MUST be done async as this will block the entire server
     process. Either we have to do our own resolver stuff or in the future
     we can use threads. */
  /* Perform name and address lookups for the remote host. */
  silc_net_check_host_by_sock(sock, &newsocket->hostname, &newsocket->ip);
  if ((server->params->require_reverse_mapping && !newsocket->hostname) ||
      !newsocket->ip) {
    SILC_LOG_ERROR(("IP/DNS lookup failed"));
    server->stat.conn_failures++;
    return;
  }
  if (!newsocket->hostname)
    newsocket->hostname = strdup(newsocket->ip);

  SILC_LOG_INFO(("Incoming connection from %s (%s)", newsocket->hostname,
		 newsocket->ip));

  /* Allocate internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = context;
  proto_ctx->sock = newsocket;
  proto_ctx->rng = server->rng;
  proto_ctx->responder = TRUE;

  /* Prepare the connection for key exchange protocol. We allocate the
     protocol but will not start it yet. The connector will be the
     initiator of the protocol thus we will wait for initiation from 
     there before we start the protocol. */
  server->stat.auth_attempts++;
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE, 
		      &newsocket->protocol, proto_ctx, 
		      silc_server_accept_new_connection_second);

  /* Register a timeout task that will be executed if the connector
     will not start the key exchange protocol within 60 seconds. For
     now, this is a hard coded limit. After 60 secs the connection will
     be closed if the key exchange protocol has not been started. */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, newsocket->sock, 
		       silc_server_timeout_remote,
		       context, 60, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it
     will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  SILC_REGISTER_CONNECTION_FOR_IO(sock);
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
  SilcSocketConnection sock = NULL;
  SilcServerConnAuthInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    if (sock)
      sock->protocol = NULL;
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
    server->stat.auth_failures++;
    return;
  }

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = sock = server->sockets[fd];
  proto_ctx->ske = ctx->ske;	/* Save SKE object from previous protocol */
  proto_ctx->responder = TRUE;
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

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
		      silc_server_accept_new_connection_final);

  /* Register timeout task. If the protocol is not executed inside
     this timelimit the connection will be terminated. Currently
     this is 60 seconds and is hard coded limit (XXX). */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, sock->sock, 
		       silc_server_timeout_remote,
		       (void *)server, 60, 0,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);
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
  void *id_entry = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR) {
    /* Error occured during protocol */
    silc_protocol_free(protocol);
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    if (sock)
      sock->protocol = NULL;
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
    server->stat.auth_failures++;
    return;
  }

  sock->type = ctx->conn_type;
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry client;

      SILC_LOG_DEBUG(("Remote host is client"));
      SILC_LOG_INFO(("Connection from %s (%s) is client", sock->hostname,
		     sock->ip));

      /* Add the client to the client ID cache. The nickname and Client ID
	 and other information is created after we have received NEW_CLIENT
	 packet from client. */
      client = silc_idlist_add_client(server->local_list, 
				      NULL, NULL, NULL, NULL, NULL, sock);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to cache"));
	silc_free(sock->user_data);
	break;
      }

      server->stat.my_clients++;

      id_entry = (void *)client;
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry new_server;

      SILC_LOG_DEBUG(("Remote host is %s", 
		      sock->type == SILC_SOCKET_TYPE_SERVER ? 
		      "server" : "router"));
      SILC_LOG_INFO(("Connection from %s (%s) is %s", sock->hostname,
		     sock->ip, sock->type == SILC_SOCKET_TYPE_SERVER ? 
		     "server" : "router"));

      /* Add the server into server cache. The server name and Server ID
	 is updated after we have received NEW_SERVER packet from the
	 server. We mark ourselves as router for this server if we really
	 are router. */
      new_server = 
	silc_idlist_add_server(server->local_list, NULL,
			       sock->type == SILC_SOCKET_TYPE_SERVER ?
			       SILC_SERVER : SILC_ROUTER, NULL, 
			       sock->type == SILC_SOCKET_TYPE_SERVER ?
			       server->id_entry : NULL, sock);
      if (!new_server) {
	SILC_LOG_ERROR(("Could not add new server to cache"));
	silc_free(sock->user_data);
	break;
      }

      if (sock->type == SILC_SOCKET_TYPE_SERVER)
	server->stat.my_servers++;
      else
	server->stat.my_routers++;
      server->stat.servers++;

      id_entry = (void *)new_server;
      
      /* There is connection to other server now, if it is router then
	 we will have connection to outside world.  If we are router but
	 normal server connected to us then we will remain standalone,
	 if we are standlone. */
      if (server->standalone && sock->type == SILC_SOCKET_TYPE_ROUTER) {
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
    break;
  }

  /* Add the common data structure to the ID entry. */
  if (id_entry)
    silc_idlist_add_data(id_entry, (SilcIDListData)sock->user_data);
      
  /* Add to sockets internal pointer for fast referencing */
  silc_free(sock->user_data);
  sock->user_data = id_entry;

  /* Connection has been fully established now. Everything is ok. */
  SILC_LOG_DEBUG(("New connection authenticated"));

  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  if (ctx->dest_id)
    silc_free(ctx->dest_id);
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
  int ret;

  if (!sock)
    return;

  SILC_LOG_DEBUG(("Processing packet"));

  /* Packet sending */

  if (type == SILC_TASK_WRITE) {
    server->stat.packets_sent++;

    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    ret = silc_server_packet_send_real(server, sock, TRUE);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;
    
    /* The packet has been sent and now it is time to set the connection
       back to only for input. When there is again some outgoing data 
       available for this connection it will be set for output as well. 
       This call clears the output setting and sets it only for input. */
    SILC_SET_CONNECTION_FOR_INPUT(fd);
    SILC_UNSET_OUTBUF_PENDING(sock);

    silc_buffer_clear(sock->outbuf);
    return;
  }

  /* Packet receiving */

  /* Read some data from connection */
  ret = silc_packet_receive(sock);
  if (ret < 0)
    return;
    
  /* EOF */
  if (ret == 0) {
    SILC_LOG_DEBUG(("Read EOF"));
      
    /* If connection is disconnecting already we will finally
       close the connection */
    if (SILC_IS_DISCONNECTING(sock)) {
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock);
      silc_server_close_connection(server, sock);
      return;
    }
      
    SILC_LOG_DEBUG(("Premature EOF from connection %d", sock->sock));

    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock);
    silc_server_close_connection(server, sock);
    return;
  }

  /* If connection is disconnecting or disconnected we will ignore
     what we read. */
  if (SILC_IS_DISCONNECTING(sock) || SILC_IS_DISCONNECTED(sock)) {
    SILC_LOG_DEBUG(("Ignoring read data from invalid connection"));
    return;
  }

  server->stat.packets_received++;

  /* Get keys and stuff from ID entry */
  idata = (SilcIDListData)sock->user_data;
  if (idata) {
    idata->last_receive = time(NULL);
    cipher = idata->receive_key;
    hmac = idata->hmac;
  }
 
  /* Process the packet. This will call the parser that will then
     decrypt and parse the packet. */
  silc_packet_receive_process(sock, cipher, hmac, silc_server_packet_parse, 
			      server);
}

/* Parses whole packet, received earlier. */

SILC_TASK_CALLBACK(silc_server_packet_parse_real)
{
  SilcPacketParserContext *parse_ctx = (SilcPacketParserContext *)context;
  SilcServer server = (SilcServer)parse_ctx->context;
  SilcSocketConnection sock = parse_ctx->sock;
  SilcPacketContext *packet = parse_ctx->packet;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Decrypt the received packet */
  ret = silc_packet_decrypt(parse_ctx->cipher, parse_ctx->hmac, 
			    packet->buffer, packet);
  if (ret < 0)
    goto out;

  if (ret == 0) {
    /* Parse the packet. Packet type is returned. */
    ret = silc_packet_parse(packet);
  } else {
    /* Parse the packet header in special way as this is "special"
       packet type. */
    ret = silc_packet_parse_special(packet);
  }

  if (ret == SILC_PACKET_NONE)
    goto out;

  if (server->server_type == SILC_ROUTER) {
    /* Route the packet if it is not destined to us. Other ID types but
       server are handled separately after processing them. */
    if (packet->dst_id_type == SILC_ID_SERVER && 
	sock->type != SILC_SOCKET_TYPE_CLIENT &&
	SILC_ID_SERVER_COMPARE(packet->dst_id, server->id_string)) {
      
      /* Route the packet to fastest route for the destination ID */
      void *id = silc_id_str2id(packet->dst_id, packet->dst_id_type);
      silc_server_packet_route(server,
			       silc_server_route_get(server, id,
						     packet->dst_id_type),
			       packet);
      silc_free(id);
      goto out;
    }
    
    /* Broadcast packet if it is marked as broadcast packet and it is
       originated from router and we are router. */
    if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
	packet->flags & SILC_PACKET_FLAG_BROADCAST) {
      silc_server_packet_broadcast(server, server->router->connection, packet);
    }
  }

  /* Parse the incoming packet type */
  silc_server_packet_parse_type(server, sock, packet);

 out:
  silc_buffer_clear(sock->inbuf);
  silc_packet_context_free(packet);
  silc_free(parse_ctx);
}

/* Parser callback called by silc_packet_receive_process. This merely
   registers timeout that will handle the actual parsing when appropriate. */

void silc_server_packet_parse(SilcPacketParserContext *parser_context)
{
  SilcServer server = (SilcServer)parser_context->context;
  SilcSocketConnection sock = parser_context->sock;

  switch (sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
  case SILC_SOCKET_TYPE_UNKNOWN:
    /* Parse the packet with timeout */
    silc_task_register(server->timeout_queue, sock->sock,
		       silc_server_packet_parse_real,
		       (void *)parser_context, 0, 100000,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    /* Packets from servers are parsed as soon as possible */
    silc_task_register(server->timeout_queue, sock->sock,
		       silc_server_packet_parse_real,
		       (void *)parser_context, 0, 1,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
    break;
  default:
    return;
  }
}

/* Parses the packet type and calls what ever routines the packet type
   requires. This is done for all incoming packets. */

void silc_server_packet_parse_type(SilcServer server, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet)
{
  SilcPacketType type = packet->type;

  SILC_LOG_DEBUG(("Parsing packet type %d", type));

  /* Parse the packet type */
  switch(type) {
  case SILC_PACKET_DISCONNECT:
    SILC_LOG_DEBUG(("Disconnect packet"));
    break;

  case SILC_PACKET_SUCCESS:
    /*
     * Success received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * success message is for whatever protocol is executing currently.
     */
    SILC_LOG_DEBUG(("Success packet"));
    if (sock->protocol) {
      sock->protocol->execute(server->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    }
    break;

  case SILC_PACKET_FAILURE:
    /*
     * Failure received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * failure message is for whatever protocol is executing currently.
     */
    SILC_LOG_DEBUG(("Failure packet"));
    if (sock->protocol) {
      /* XXX Audit the failure type */
      sock->protocol->state = SILC_PROTOCOL_STATE_FAILURE;
      sock->protocol->execute(server->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    }
    break;

  case SILC_PACKET_REJECT:
    SILC_LOG_DEBUG(("Reject packet"));
    return;
    break;

  case SILC_PACKET_NOTIFY:
    /*
     * Received notify packet. Server can receive notify packets from
     * router. Server then relays the notify messages to clients if needed.
     */
    SILC_LOG_DEBUG(("Notify packet"));
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
    SILC_LOG_DEBUG(("Channel Message packet"));
    silc_server_channel_message(server, sock, packet);
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /*
     * Received key for channel. As channels are created by the router
     * the keys are as well. We will distribute the key to all of our
     * locally connected clients on the particular channel. Router
     * never receives this channel and thus is ignored.
     */
    SILC_LOG_DEBUG(("Channel Key packet"));
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
    SILC_LOG_DEBUG(("Command packet"));
    silc_server_command_process(server, sock, packet);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Received command reply packet. Received command reply to command. It
     * may be reply to command sent by us or reply to command sent by client
     * that we've routed further.
     */
    SILC_LOG_DEBUG(("Command Reply packet"));
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
    SILC_LOG_DEBUG(("Private Message packet"));
    silc_server_private_message(server, sock, packet);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /*
     * Private message key packet.
     */
    break;

    /*
     * Key Exchange protocol packets
     */
  case SILC_PACKET_KEY_EXCHANGE:
    SILC_LOG_DEBUG(("KE packet"));
    if (sock->protocol && sock->protocol->protocol->type 
	== SILC_PROTOCOL_SERVER_KEY_EXCHANGE) {

      SilcServerKEInternalContext *proto_ctx = 
	(SilcServerKEInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock, 0, 100000);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange packet but no key exchange "
		      "protocol active, packet dropped."));

      /* XXX Trigger KE protocol?? Rekey actually, maybe. */
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_1:
    SILC_LOG_DEBUG(("KE 1 packet"));
    if (sock->protocol && sock->protocol->protocol->type 
	== SILC_PROTOCOL_SERVER_KEY_EXCHANGE) {

      SilcServerKEInternalContext *proto_ctx = 
	(SilcServerKEInternalContext *)sock->protocol->context;

      if (proto_ctx->packet)
	silc_packet_context_free(proto_ctx->packet);

      proto_ctx->packet = silc_packet_context_dup(packet);
      proto_ctx->dest_id_type = packet->src_id_type;
      proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_type);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock,
			      0, 100000);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 1 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_2:
    SILC_LOG_DEBUG(("KE 2 packet"));
    if (sock->protocol && sock->protocol->protocol->type 
	== SILC_PROTOCOL_SERVER_KEY_EXCHANGE) {

      SilcServerKEInternalContext *proto_ctx = 
	(SilcServerKEInternalContext *)sock->protocol->context;

      if (proto_ctx->packet)
	silc_packet_context_free(proto_ctx->packet);

      proto_ctx->packet = silc_packet_context_dup(packet);
      proto_ctx->dest_id_type = packet->src_id_type;
      proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_type);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock,
			      0, 100000);
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
    SILC_LOG_DEBUG(("Connection authentication request packet"));
    break;

    /*
     * Connection Authentication protocol packets
     */
  case SILC_PACKET_CONNECTION_AUTH:
    /* Start of the authentication protocol. We receive here the 
       authentication data and will verify it. */
    SILC_LOG_DEBUG(("Connection auth packet"));
    if (sock->protocol && sock->protocol->protocol->type 
	== SILC_PROTOCOL_SERVER_CONNECTION_AUTH) {

      SilcServerConnAuthInternalContext *proto_ctx = 
	(SilcServerConnAuthInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);

      /* Let the protocol handle the packet */
      sock->protocol->execute(server->timeout_queue, 0, 
			      sock->protocol, sock->sock, 0, 0);
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
    SILC_LOG_DEBUG(("New ID packet"));
    silc_server_new_id(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CLIENT:
    /*
     * Received new client packet. This includes client information that
     * we will use to create initial client ID. After creating new
     * ID we will send it to the client.
     */
    SILC_LOG_DEBUG(("New Client packet"));
    silc_server_new_client(server, sock, packet);
    break;

  case SILC_PACKET_NEW_SERVER:
    /*
     * Received new server packet. This includes Server ID and some other
     * information that we may save. This is received after server has 
     * connected to us.
     */
    SILC_LOG_DEBUG(("New Server packet"));
    silc_server_new_server(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CHANNEL:
    /*
     * Received new channel packet. Information about new channel in the
     * network are distributed using this packet.
     */
    SILC_LOG_DEBUG(("New Channel packet"));
    silc_server_new_channel(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CHANNEL_USER:
    /*
     * Received new channel user packet. Information about new users on a
     * channel are distributed between routers using this packet.  The
     * router receiving this will redistribute it and also sent JOIN notify
     * to local clients on the same channel. Normal server sends JOIN notify
     * to its local clients on the channel.
     */
    SILC_LOG_DEBUG(("New Channel User packet"));
    silc_server_new_channel_user(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CHANNEL_LIST:
    /*
     * List of new channel packets received. This is usually received when
     * existing server or router connects to us and distributes information
     * of all channels it has.
     */
    break;

  case SILC_PACKET_NEW_CHANNEL_USER_LIST:
    /*
     * List of new channel user packets received. This is usually received
     * when existing server or router connects to us and distributes 
     * information of all channel users it has.
     */
    break;

  case SILC_PACKET_REPLACE_ID:
    /*
     * Received replace ID packet. This sends the old ID that is to be
     * replaced with the new one included into the packet. Client must not
     * send this packet.
     */
    SILC_LOG_DEBUG(("Replace ID packet"));
    silc_server_replace_id(server, sock, packet);
    break;

  case SILC_PACKET_REMOVE_ID:
    /*
     * Received remove ID Packet. 
     */
    SILC_LOG_DEBUG(("Remove ID packet"));
    silc_server_remove_id(server, sock, packet);
    break;

  case SILC_PACKET_REMOVE_CHANNEL_USER:
    /*
     * Received packet to remove user from a channel. Routers notify other
     * routers about a user leaving a channel.
     */
    SILC_LOG_DEBUG(("Remove Channel User packet"));
    silc_server_remove_channel_user(server, sock, packet);
    break;

  default:
    SILC_LOG_ERROR(("Incorrect packet type %d, packet dropped", type));
    break;
  }
  
}

/* Closes connection to socket connection */

void silc_server_close_connection(SilcServer server,
				  SilcSocketConnection sock)
{
  SILC_LOG_DEBUG(("Closing connection %d", sock->sock));

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(sock->sock);

  /* Unregister all tasks */
  silc_task_unregister_by_fd(server->io_queue, sock->sock);
  silc_task_unregister_by_fd(server->timeout_queue, sock->sock);

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);
  server->sockets[sock->sock] = NULL;
  silc_socket_free(sock);
}

/* Sends disconnect message to remote connection and disconnects the 
   connection. */

void silc_server_disconnect_remote(SilcServer server,
				   SilcSocketConnection sock,
				   const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  if (!sock)
    return;

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  SILC_LOG_DEBUG(("Disconnecting remote host"));

  /* Notify remote end that the conversation is over. The notify message
     is tried to be sent immediately. */
  silc_server_packet_send(server, sock, SILC_PACKET_DISCONNECT, 0,  
			  buf, strlen(buf), TRUE);

  /* Mark the connection to be disconnected */
  SILC_SET_DISCONNECTED(sock);
  silc_server_close_connection(server, sock);
}

/* Free's user_data pointer from socket connection object. This also sends
   appropriate notify packets to the network to inform about leaving
   entities. */

void silc_server_free_sock_user_data(SilcServer server, 
				     SilcSocketConnection sock)
{
  SILC_LOG_DEBUG(("Start"));

  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry user_data = (SilcClientEntry)sock->user_data;

      /* Remove client from all channels */
      silc_server_remove_from_channels(server, sock, user_data);

      /* XXX must take some info to history before freeing */

      /* Send REMOVE_ID packet to routers. */
      if (!server->standalone && server->router)
	silc_server_send_remove_id(server, server->router->connection,
				   server->server_type == SILC_SERVER ?
				   FALSE : TRUE, user_data->id, 
				   SILC_ID_CLIENT_LEN, SILC_ID_CLIENT);

      /* Free the client entry and everything in it */
      silc_idlist_del_data(user_data);
      silc_idlist_del_client(server->local_list, user_data);
      server->stat.my_clients--;
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry user_data = (SilcServerEntry)sock->user_data;

      /* Send REMOVE_ID packet to routers. */
      if (!server->standalone && server->router)
	silc_server_send_remove_id(server, server->router->connection,
				   server->server_type == SILC_SERVER ?
				   FALSE : TRUE, user_data->id, 
				   SILC_ID_CLIENT_LEN, SILC_ID_CLIENT);

      /* Free the server entry */
      silc_idlist_del_data(user_data);
      silc_idlist_del_server(server->local_list, user_data);
      server->stat.my_servers--;
      break;
    }
  default:
    {
      SilcUnknownEntry user_data = (SilcUnknownEntry)sock->user_data;

      silc_idlist_del_data(user_data);
      silc_free(user_data);
      break;
    }
  }

  sock->user_data = NULL;
}

/* Checks whether given channel has global users.  If it does this returns
   TRUE and FALSE if there is only locally connected clients on the channel. */

int silc_server_channel_has_global(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;

  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (chl->client->router)
      return TRUE;
  }

  return FALSE;
}

/* Checks whether given channel has locally connected users.  If it does this
   returns TRUE and FALSE if there is not one locally connected client. */

int silc_server_channel_has_local(SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;

  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (!chl->client->router)
      return TRUE;
  }

  return FALSE;
}

/* Removes client from all channels it has joined. This is used when client
   connection is disconnected. If the client on a channel is last, the
   channel is removed as well. This sends the SIGNOFF notify types. */

void silc_server_remove_from_channels(SilcServer server, 
				      SilcSocketConnection sock,
				      SilcClientEntry client)
{
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer chidp, clidp;

  SILC_LOG_DEBUG(("Start"));

  if (!client || !client->id)
    return;

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    channel = chl->channel;
    chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);

    /* Remove from list */
    silc_list_del(client->channels, chl);

    /* If this client is last one on the channel the channel
       is removed all together. */
    if (silc_list_count(channel->user_list) < 2) {

      /* However, if the channel has marked global users then the 
	 channel is not created locally, and this does not remove the
	 channel globally from SILC network, in this case we will
	 notify that this client has left the channel. */
      if (channel->global_users)
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					   SILC_NOTIFY_TYPE_SIGNOFF, 1,
					   clidp->data, clidp->len);
      
      silc_idlist_del_channel(server->local_list, channel);
      server->stat.my_channels--;
      continue;
    }

    /* Remove from list */
    silc_list_del(channel->user_list, chl);
    silc_free(chl);
    server->stat.my_chanclients--;

    /* Send notify to channel about client leaving SILC and thus
       the entire channel. */
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				       SILC_NOTIFY_TYPE_SIGNOFF, 1,
				       clidp->data, clidp->len);
    silc_buffer_free(chidp);
  }

  silc_buffer_free(clidp);
}

/* Removes client from one channel. This is used for example when client
   calls LEAVE command to remove itself from the channel. Returns TRUE
   if channel still exists and FALSE if the channel is removed when
   last client leaves the channel. If `notify' is FALSE notify messages
   are not sent. */

int silc_server_remove_from_one_channel(SilcServer server, 
					SilcSocketConnection sock,
					SilcChannelEntry channel,
					SilcClientEntry client,
					int notify)
{
  SilcChannelEntry ch;
  SilcChannelClientEntry chl;
  SilcBuffer clidp;

  SILC_LOG_DEBUG(("Start"));

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Remove the client from the channel. The client is removed from
     the channel's user list. */
  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    if (chl->channel != channel)
      continue;

    ch = chl->channel;

    /* Remove from list */
    silc_list_del(client->channels, chl);

    /* If this client is last one on the channel the channel
       is removed all together. */
    if (silc_list_count(channel->user_list) < 2) {
      /* Notify about leaving client if this channel has global users. */
      if (notify && channel->global_users)
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					   SILC_NOTIFY_TYPE_LEAVE, 1,
					   clidp->data, clidp->len);
      
      silc_idlist_del_channel(server->local_list, channel);
      silc_buffer_free(clidp);
      server->stat.my_channels--;
      return FALSE;
    }

    /* Remove from list */
    silc_list_del(channel->user_list, chl);
    silc_free(chl);
    server->stat.my_chanclients--;

    /* If there is no global users on the channel anymore mark the channel
       as local channel. */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    /* If tehre is not at least one local user on the channel then we don't
       need the channel entry anymore, we can remove it safely. */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_local(channel)) {
      silc_idlist_del_channel(server->local_list, channel);
      silc_buffer_free(clidp);
      server->stat.my_channels--;
      return FALSE;
    }

    /* Send notify to channel about client leaving the channel */
    if (notify)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
					 SILC_NOTIFY_TYPE_LEAVE, 1,
					 clidp->data, clidp->len);
    break;
  }

  silc_buffer_free(clidp);
  return TRUE;
}

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */

int silc_server_client_on_channel(SilcClientEntry client,
				  SilcChannelEntry channel)
{
  SilcChannelClientEntry chl;

  if (!client || !channel)
    return FALSE;

  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END)
    if (chl->channel == channel)
      return TRUE;

  return FALSE;
}

/* Timeout callback. This is called if connection is idle or for some
   other reason is not responding within some period of time. This 
   disconnects the remote end. */

SILC_TASK_CALLBACK(silc_server_timeout_remote)
{
  SilcServerConnection sconn = (SilcServerConnection)context;
  SilcSocketConnection sock = sconn->server->sockets[fd];

  if (!sock)
    return;

  silc_server_disconnect_remote(sconn->server, sock, 
				"Server closed connection: "
				"Connection timeout");
}

/* Creates new channel. Sends NEW_CHANNEL packet to primary route. This
   function may be used only by router. In real SILC network all channels
   are created by routers thus this function is never used by normal
   server. */

SilcChannelEntry silc_server_create_new_channel(SilcServer server, 
						SilcServerID *router_id,
						char *cipher, 
						char *channel_name)
{
  SilcChannelID *channel_id;
  SilcChannelEntry entry;
  SilcCipher key;

  SILC_LOG_DEBUG(("Creating new channel"));

  if (!cipher)
    cipher = "twofish";

  /* Allocate cipher */
  silc_cipher_alloc(cipher, &key);

  channel_name = strdup(channel_name);

  /* Create the channel */
  silc_id_create_channel_id(router_id, server->rng, &channel_id);
  entry = silc_idlist_add_channel(server->local_list, channel_name, 
				  SILC_CHANNEL_MODE_NONE, channel_id, 
				  NULL, key);
  if (!entry) {
    silc_free(channel_name);
    return NULL;
  }

  /* Now create the actual key material */
  silc_server_create_channel_key(server, entry, 16);

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (server->standalone == FALSE) {
    silc_server_send_new_channel(server, server->router->connection, TRUE, 
				 channel_name, entry->id, SILC_ID_CHANNEL_LEN);
  }

  server->stat.my_channels++;

  return entry;
}

/* Generates new channel key. This is used to create the initial channel key
   but also to re-generate new key for channel. If `key_len' is provided
   it is the bytes of the key length. */

void silc_server_create_channel_key(SilcServer server, 
				    SilcChannelEntry channel,
				    unsigned int key_len)
{
  int i;
  unsigned char channel_key[32];
  unsigned int len;

  if (!channel->channel_key)
    silc_cipher_alloc("twofish", &channel->channel_key);

  if (key_len)
    len = key_len;
  else if (channel->key_len)
    len = channel->key_len / 8;
  else
    len = sizeof(channel_key);

  /* Create channel key */
  for (i = 0; i < len; i++) channel_key[i] = silc_rng_get_byte(server->rng);
  
  /* Set the key */
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					channel_key, len);

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
  }

  /* Save the key */
  channel->key_len = len * 8;
  channel->key = silc_calloc(len, sizeof(*channel->key));
  memcpy(channel->key, channel_key, len);
  memset(channel_key, 0, sizeof(channel_key));
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
  unsigned char *tmp;
  unsigned int tmp_len;
  char *cipher;

  /* Decode channel key payload */
  payload = silc_channel_key_payload_parse(key_payload);
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload, dropped"));
    channel = NULL;
    goto out;
  }

  /* Get the channel entry */
  if (!channel) {

    /* Get channel ID */
    tmp = silc_channel_key_get_id(payload, &tmp_len);
    id = silc_id_str2id(tmp, SILC_ID_CHANNEL);
    if (!id) {
      channel = NULL;
      goto out;
    }

    channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
    if (!channel) {
      SILC_LOG_ERROR(("Received key for non-existent channel"));
      goto out;
    }
  }

  tmp = silc_channel_key_get_key(payload, &tmp_len);
  if (!tmp) {
    channel = NULL;
    goto out;
  }

  cipher = silc_channel_key_get_cipher(payload, NULL);;
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
    channel = NULL;
    goto out;
  }

  /* Save the key */
  channel->key_len = tmp_len * 8;
  channel->key = silc_calloc(tmp_len, sizeof(unsigned char));
  memcpy(channel->key, tmp, tmp_len);
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					tmp, tmp_len);

 out:
  if (id)
    silc_free(id);
  if (payload)
    silc_channel_key_payload_free(payload);

  return channel;
}
