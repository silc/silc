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

extern char *server_version;

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
    SilcSimContext *sim;

    if (server->local_list)
      silc_free(server->local_list);
    if (server->global_list)
      silc_free(server->global_list);
    if (server->rng)
      silc_rng_free(server->rng);

    while ((sim = silc_dlist_get(server->sim)) != SILC_LIST_END) {
      silc_dlist_del(server->sim, sim);
      silc_sim_free(sim);
    }
    silc_dlist_uninit(server->sim);

    if (server->params)
      silc_free(server->params);

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

  /* XXX for now these are allocated for normal server as well as these
     hold some global information that the server has fetched from its
     router. For router these are used as they are supposed to be used
     on router. The XXX can be remoevd later if this is the way we are
     going to do this in the normal server as well. */
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

/* The heart of the server. This runs the scheduler thus runs the server. */

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
      silc_buffer_free(ctx->packet);
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
    silc_buffer_free(ctx->packet);
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
  id_entry = silc_idlist_add_server(server->local_list, 
				    sock->hostname ? sock->hostname : sock->ip,
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

 out:
  /* Free the temporary connection data context */
  if (sconn)
    silc_free(sconn);

  /* Free the protocol object */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_buffer_free(ctx->packet);
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

  sock = silc_net_accept_connection(server->sock);
  if (sock < 0) {
    SILC_LOG_ERROR(("Could not accept new connection: %s", strerror(errno)));
    return;
  }

  /* Check max connections */
  if (sock > SILC_SERVER_MAX_CONNECTIONS) {
    if (server->config->redirect) {
      /* XXX Redirecting connection to somewhere else now?? */
      /*silc_server_send_notify("Server is full, trying to redirect..."); */
    } else {
      SILC_LOG_ERROR(("Refusing connection, server is full"));
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
  /* Perform mandatory name and address lookups for the remote host. */
  silc_net_check_host_by_sock(sock, &newsocket->hostname, &newsocket->ip);
  if (!newsocket->ip || !newsocket->hostname) {
    SILC_LOG_DEBUG(("IP lookup/DNS lookup failed"));
    SILC_LOG_ERROR(("IP lookup/DNS lookup failed"));
    return;
  }

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
      silc_buffer_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    if (sock)
      sock->protocol = NULL;
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Key exchange failed");
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
    silc_buffer_free(ctx->packet);
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
      silc_buffer_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    if (sock)
      sock->protocol = NULL;
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Authentication failed");
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
	 server. */
      new_server = 
	silc_idlist_add_server(server->local_list, NULL,
			       sock->type == SILC_SOCKET_TYPE_SERVER ?
			       SILC_SERVER : SILC_ROUTER, NULL, NULL, sock);
      if (!new_server) {
	SILC_LOG_ERROR(("Could not add new server to cache"));
	silc_free(sock->user_data);
	break;
      }

      id_entry = (void *)new_server;
      
      /* There is connection to other server now, if it is router then
	 we will have connection to outside world.  If we are router but
	 normal server connected to us then we will remain standalone,
	 if we are standlone. */
      if (server->standalone && sock->type == SILC_SOCKET_TYPE_ROUTER) {
	SILC_LOG_DEBUG(("We are not standalone server anymore"));
	server->standalone = FALSE;
	if (!server->id_entry->router)
	  server->id_entry->router = id_entry;
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
    silc_buffer_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  if (ctx->dest_id)
    silc_free(ctx->dest_id);
  silc_free(ctx);
  sock->protocol = NULL;
}

/* Internal routine that sends packet or marks packet to be sent. This
   is used directly only in special cases. Normal cases should use
   silc_server_packet_send. Returns < 0 error. */

static int silc_server_packet_send_real(SilcServer server,
					SilcSocketConnection sock,
					int force_send)
{
  int ret;

  /* Send the packet */
  ret = silc_packet_send(sock, force_send);
  if (ret != -2)
    return ret;

  /* Mark that there is some outgoing data available for this connection. 
     This call sets the connection both for input and output (the input
     is set always and this call keeps the input setting, actually). 
     Actual data sending is performed by silc_server_packet_process. */
  SILC_SET_CONNECTION_FOR_OUTPUT(sock->sock);

  /* Mark to socket that data is pending in outgoing buffer. This flag
     is needed if new data is added to the buffer before the earlier
     put data is sent to the network. */
  SILC_SET_OUTBUF_PENDING(sock);

  return 0;
}

typedef struct {
  SilcPacketContext *packetdata;
  SilcServer server;
  SilcSocketConnection sock;
  SilcCipher cipher;
  SilcHmac hmac;
} SilcServerInternalPacket;

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

  SILC_LOG_DEBUG(("Processing packet"));

  /* Packet sending */
  if (type == SILC_TASK_WRITE) {
    SILC_LOG_DEBUG(("Writing data to connection"));

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
  SILC_LOG_DEBUG(("Reading data from connection"));

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
  SilcBuffer buffer = packet->buffer;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Decrypt the received packet */
  ret = silc_packet_decrypt(parse_ctx->cipher, parse_ctx->hmac, 
			    buffer, packet);
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

  /* Broadcast packet if it is marked as broadcast packet and it is
     originated from router and we are router. */
  if (server->server_type == SILC_ROUTER && 
      sock->type == SILC_SOCKET_TYPE_ROUTER &&
      packet->flags & SILC_PACKET_FLAG_BROADCAST) {
    silc_server_packet_broadcast(server, server->id_entry->router->connection,
				 packet);
  }

  /* Parse the incoming packet type */
  silc_server_packet_parse_type(server, sock, packet);

 out:
  silc_buffer_clear(sock->inbuf);
  if (packet->src_id)
    silc_free(packet->src_id);
  if (packet->dst_id)
    silc_free(packet->dst_id);
  silc_free(packet);
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
  SilcBuffer buffer = packet->buffer;
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

    /* 
     * Channel packets
     */
  case SILC_PACKET_CHANNEL_MESSAGE:
    /*
     * Received channel message. Channel messages are special packets
     * (although probably most common ones) hence they are handled
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
     * Recived command. Allocate command context and execute the command.
     */
    SILC_LOG_DEBUG(("Command packet"));
    silc_server_command_process(server, sock, packet);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Received command reply packet. Servers never send commands thus
     * they don't receive command reply packets either, except in cases
     * where server has forwarded command packet coming from client. 
     * This must be the case here or we will ignore the packet.
     */
    SILC_LOG_DEBUG(("Command Reply packet"));
    silc_server_packet_relay_command_reply(server, sock, packet);
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

      proto_ctx->packet = buffer;

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
	silc_buffer_free(proto_ctx->packet);

      proto_ctx->packet = buffer;
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
	silc_buffer_free(proto_ctx->packet);

      proto_ctx->packet = buffer;
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
    /* If we receive this packet we will send to the other end information
       about our mandatory authentication method for the connection. 
       This packet maybe received at any time. */

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

      proto_ctx->packet = buffer;

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
    break;

  case SILC_PACKET_NEW_CHANNEL_USER:
    break;

  case SILC_PACKET_NEW_CHANNEL_LIST:
    break;

  case SILC_PACKET_NEW_CHANNEL_USER_LIST:
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

/* Assembles a new packet to be sent out to network. This doesn't actually
   send the packet but creates the packet and fills the outgoing data
   buffer and marks the packet ready to be sent to network. However, If 
   argument force_send is TRUE the packet is sent immediately and not put 
   to queue. Normal case is that the packet is not sent immediately. */

void silc_server_packet_send(SilcServer server,
			     SilcSocketConnection sock, 
			     SilcPacketType type, 
			     SilcPacketFlags flags,
			     unsigned char *data, 
			     unsigned int data_len,
			     int force_send)
{
  void *dst_id = NULL;
  SilcIdType dst_id_type = SILC_ID_NONE;

  if (!sock)
    return;

  /* Get data used in the packet sending, keys and stuff */
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    dst_id = ((SilcClientEntry)sock->user_data)->id;
    dst_id_type = SILC_ID_CLIENT;
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    dst_id = ((SilcServerEntry)sock->user_data)->id;
    dst_id_type = SILC_ID_SERVER;
    break;
  default:
    break;
  }

  silc_server_packet_send_dest(server, sock, type, flags, dst_id,
			       dst_id_type, data, data_len, force_send);
}

/* Assembles a new packet to be sent out to network. This doesn't actually
   send the packet but creates the packet and fills the outgoing data
   buffer and marks the packet ready to be sent to network. However, If 
   argument force_send is TRUE the packet is sent immediately and not put 
   to queue. Normal case is that the packet is not sent immediately. 
   Destination information is sent as argument for this function. */

void silc_server_packet_send_dest(SilcServer server,
				  SilcSocketConnection sock, 
				  SilcPacketType type, 
				  SilcPacketFlags flags,
				  void *dst_id,
				  SilcIdType dst_id_type,
				  unsigned char *data, 
				  unsigned int data_len,
				  int force_send)
{
  SilcPacketContext packetdata;
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  unsigned char *dst_id_data = NULL;
  unsigned int dst_id_len = 0;

  SILC_LOG_DEBUG(("Sending packet, type %d", type));

  /* Get data used in the packet sending, keys and stuff */
  idata = (SilcIDListData)sock->user_data;

  if (dst_id) {
    dst_id_data = silc_id_id2str(dst_id, dst_id_type);
    dst_id_len = silc_id_get_len(dst_id_type);
  }

  /* Set the packet context pointers */
  packetdata.type = type;
  packetdata.flags = flags;
  packetdata.src_id = silc_id_id2str(server->id, server->id_type);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = server->id_type;
  packetdata.dst_id = dst_id_data;
  packetdata.dst_id_len = dst_id_len;
  packetdata.dst_id_type = dst_id_type;
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);
  packetdata.rng = server->rng;

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packetdata.src_id_len + 
			   packetdata.dst_id_len,
			   packetdata.padlen,
			   data_len);

  SILC_LOG_DEBUG(("Putting data to outgoing buffer, len %d", data_len));

  packetdata.buffer = sock->outbuf;

  /* Put the data to the buffer */
  if (data && data_len)
    silc_buffer_put(sock->outbuf, data, data_len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  if (idata) {
    cipher = idata->send_key;
    hmac = idata->hmac;
  }

  /* Encrypt the packet */
  silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);

  SILC_LOG_HEXDUMP(("Outgoing packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);

  if (packetdata.src_id)
    silc_free(packetdata.src_id);
  if (packetdata.dst_id)
    silc_free(packetdata.dst_id);
}

/* Forwards packet. Packets sent with this function will be marked as
   forwarded (in the SILC header flags) so that the receiver knows that
   we have forwarded the packet to it. Forwarded packets are handled
   specially by the receiver as they are not destined to the receiver
   originally. However, the receiver knows this because the forwarded
   flag has been set (and the flag is authenticated). */

void silc_server_packet_forward(SilcServer server,
				SilcSocketConnection sock,
				unsigned char *data, unsigned int data_len,
				int force_send)
{
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;

  SILC_LOG_DEBUG(("Forwarding packet"));

  /* Get data used in the packet sending, keys and stuff */
  idata = (SilcIDListData)sock->user_data;

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 0, 0, data_len);

  /* Mungle the packet flags and add the FORWARDED flag */
  if (data)
    data[2] |= (unsigned char)SILC_PACKET_FLAG_FORWARDED;

  /* Put the data to the buffer */
  if (data && data_len)
    silc_buffer_put(sock->outbuf, data, data_len);

  if (idata) {
    cipher = idata->send_key;
    hmac = idata->hmac;
  }

  /* Encrypt the packet */
  silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);

  SILC_LOG_HEXDUMP(("Forwarded packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);
}

/* Broadcast received packet to our primary route. This function is used
   by router to further route received broadcast packet. It is expected
   that the broadcast flag from the packet is checked before calling this
   function. This does not check for the broadcast flag. The `sock' must
   be the socket of the primary route. */

void silc_server_packet_broadcast(SilcServer server,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcIDListData idata;
  void *id;

  SILC_LOG_DEBUG(("Broadcasting received broadcast packet"));

  /* If the packet is originated from our primary route we are
     not allowed to send the packet. */
  id = silc_id_str2id(packet->src_id, packet->src_id_type);
  if (id && SILC_ID_SERVER_COMPARE(id, server->id_entry->router->id)) {
    idata = (SilcIDListData)sock->user_data;
    silc_packet_send_prepare(sock, 0, 0, buffer->len);
    silc_buffer_put(sock->outbuf, buffer->data, buffer->len);
    silc_packet_encrypt(idata->send_key, idata->hmac, 
			sock->outbuf, sock->outbuf->len);

    SILC_LOG_HEXDUMP(("Broadcasted packet, len %d", sock->outbuf->len),
		     sock->outbuf->data, sock->outbuf->len);

    /* Now actually send the packet */
    silc_server_packet_send_real(server, sock, TRUE);
    silc_free(id);
    return;
  }

  SILC_LOG_DEBUG(("Will not broadcast to primary route since it is the "
		  "original sender of this packet"));
  silc_free(id);
}

/* Internal routine to actually create the channel packet and send it
   to network. This is common function in channel message sending. If
   `channel_message' is TRUE this encrypts the message as it is strictly
   a channel message. If FALSE normal encryption process is used. */

static void
silc_server_packet_send_to_channel_real(SilcServer server,
					SilcSocketConnection sock,
					SilcPacketContext *packet,
					SilcCipher cipher,
					SilcHmac hmac,
					unsigned char *data,
					unsigned int data_len,
					int channel_message,
					int force_send)
{
  packet->truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packet->src_id_len + packet->dst_id_len;

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packet->src_id_len + 
			   packet->dst_id_len,
			   packet->padlen,
			   data_len);

  packet->buffer = sock->outbuf;

  /* Put the data to buffer, assemble and encrypt the packet. The packet
     is encrypted with normal session key shared with the client. */
  silc_buffer_put(sock->outbuf, data, data_len);
  silc_packet_assemble(packet);
  if (channel_message)
    silc_packet_encrypt(cipher, hmac, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			packet->src_id_len + packet->dst_id_len +
			packet->padlen);
  else
    silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);
    
  SILC_LOG_HEXDUMP(("Channel packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);
}

/* This routine is used by the server to send packets to channel. The 
   packet sent with this function is distributed to all clients on
   the channel. Usually this is used to send notify messages to the
   channel, things like notify about new user joining to the channel. */

void silc_server_packet_send_to_channel(SilcServer server,
					SilcChannelEntry channel,
					SilcPacketType type,
					unsigned char *data,
					unsigned int data_len,
					int force_send)
{
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl;
  SilcIDListData idata;
  unsigned int routed_count = 0;

  /* This doesn't send channel message packets */
  if (type == SILC_PACKET_CHANNEL_MESSAGE)
    return;
  
  SILC_LOG_DEBUG(("Sending packet to channel"));

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = type;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = SILC_ID_SERVER;
  packetdata.dst_id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_len = SILC_ID_CHANNEL_LEN;
  packetdata.dst_id_type = SILC_ID_CHANNEL;
  packetdata.rng = server->rng;
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (server->server_type == SILC_SERVER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router;

    /* Get data used in packet header encryption, keys and stuff. */
    router = server->id_entry->router;
    sock = (SilcSocketConnection)router->connection;
    idata = (SilcIDListData)router;
    
    SILC_LOG_DEBUG(("Sending channel message to router for routing"));

    silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					    idata->send_key, idata->hmac, 
					    data, data_len, FALSE, force_send);
  }

  /* Send the message to clients on the channel's client list. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    client = chl->client;

    /* If client has router set it is not locally connected client and
       we will route the message to the router set in the client. */
    if (client && client->router && server->server_type == SILC_ROUTER) {
      int k;

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->router->connection;
      idata = (SilcIDListData)client->router;

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, FALSE, 
					      force_send);

      /* We want to make sure that the packet is routed to same router
	 only once. Mark this route as sent route. */
      k = routed_count;
      routed = silc_realloc(routed, sizeof(*routed) * (k + 1));
      routed[k] = client->router;
      routed_count++;

      continue;
    }

    /* Send to locally connected client */
    if (client) {

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->connection;
      idata = (SilcIDListData)client;

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, FALSE, 
					      force_send);
    }
  }

  if (routed_count)
    silc_free(routed);
  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
}

/* This routine is explicitly used to relay messages to some channel.
   Packets sent with this function we have received earlier and are
   totally encrypted. This just sends the packet to all clients on
   the channel. If the sender of the packet is someone on the channel 
   the message will not be sent to that client. The SILC Packet header
   is encrypted with the session key shared between us and the client.
   MAC is also computed before encrypting the header. Rest of the
   packet will be untouched. */

void silc_server_packet_relay_to_channel(SilcServer server,
					 SilcSocketConnection sender_sock,
					 SilcChannelEntry channel,
					 void *sender, 
					 SilcIdType sender_type,
					 unsigned char *data,
					 unsigned int data_len,
					 int force_send)
{
  int found = FALSE;
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl;
  unsigned int routed_count = 0;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Relaying packet to channel"));

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_CHANNEL_MESSAGE;
  packetdata.src_id = silc_id_id2str(sender, sender_type);
  packetdata.src_id_len = silc_id_get_len(sender_type);
  packetdata.src_id_type = sender_type;
  packetdata.dst_id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_len = SILC_ID_CHANNEL_LEN;
  packetdata.dst_id_type = SILC_ID_CHANNEL;
  packetdata.rng = server->rng;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (server->server_type == SILC_SERVER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router;

    router = server->id_entry->router;

    /* Check that the sender is not our router. */
    if (sender_sock != (SilcSocketConnection)router->connection) {

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)router->connection;
      idata = (SilcIDListData)router;

      SILC_LOG_DEBUG(("Sending channel message to router for routing"));

      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, TRUE, 
					      force_send);
    }
  }

  /* Send the message to clients on the channel's client list. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    client = chl->client;

    if (client) {

      /* If sender is one on the channel do not send it the packet. */
      if (!found && !SILC_ID_CLIENT_COMPARE(client->id, sender)) {
	found = TRUE;
	continue;
      }

      /* If the client has set router it means that it is not locally
	 connected client and we will route the packet further. */
      if (server->server_type == SILC_ROUTER && client->router) {
	int k;

	/* Sender maybe server as well so we want to make sure that
	   we won't send the message to the server it came from. */
	if (!found && !SILC_ID_SERVER_COMPARE(client->router->id, sender)) {
	  found = TRUE;
	  continue;
	}

	/* Check if we have sent the packet to this route already */
	for (k = 0; k < routed_count; k++)
	  if (routed[k] == client->router)
	    break;
	if (k < routed_count)
	  continue;
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)client->router->connection;
	idata = (SilcIDListData)client->router;

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, idata->hmac, 
						data, data_len, TRUE, 
						force_send);
	
	/* We want to make sure that the packet is routed to same router
	   only once. Mark this route as sent route. */
	k = routed_count;
	routed = silc_realloc(routed, sizeof(*routed) * (k + 1));
	routed[k] = client->router;
	routed_count++;
	
	continue;
      }

      /* XXX Check client's mode on the channel. */

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->connection;
      idata = (SilcIDListData)client;

      SILC_LOG_DEBUG(("Sending packet to client %s", 
		      sock->hostname ? sock->hostname : sock->ip));

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, TRUE, 
					      force_send);
    }
  }

  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
}

/* This function is used to send packets strictly to all local clients
   on a particular channel.  This is used for example to distribute new
   channel key to all our locally connected clients on the channel. 
   The packets are always encrypted with the session key shared between
   the client, this means these are not _to the channel_ but _to the client_
   on the channel. */

void silc_server_packet_send_local_channel(SilcServer server,
					   SilcChannelEntry channel,
					   SilcPacketType type,
					   SilcPacketFlags flags,
					   unsigned char *data,
					   unsigned int data_len,
					   int force_send)
{
  SilcClientEntry client;
  SilcChannelClientEntry chl;
  SilcSocketConnection sock = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Send the message to clients on the channel's client list. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    client = chl->client;

    if (client) {
      sock = (SilcSocketConnection)client->connection;

      /* Send the packet to the client */
      silc_server_packet_send_dest(server, sock, type, flags, client->id,
				   SILC_ID_CLIENT, data, data_len,
				   force_send);
    }
  }
}

/* Relays received command reply packet to the correct destination. The
   destination must be one of our locally connected client or the packet
   will be ignored. This is called when server has forwarded one of
   client's command request to router and router has now replied to the 
   command. */

void silc_server_packet_relay_command_reply(SilcServer server,
					    SilcSocketConnection sock,
					    SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientEntry client;
  SilcClientID *id;
  SilcSocketConnection dst_sock;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  /* Source must be server or router */
  if (packet->src_id_type != SILC_ID_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    goto out;

  /* Destination must be client */
  if (packet->dst_id_type != SILC_ID_CLIENT)
    goto out;

  /* Execute command reply locally for the command */
  silc_server_command_reply_process(server, sock, buffer);

  id = silc_id_str2id(packet->dst_id, SILC_ID_CLIENT);

  /* Destination must be one of ours */
  client = silc_idlist_find_client_by_id(server->local_list, id);
  if (!client) {
    silc_free(id);
    goto out;
  }

  /* Relay the packet to the client */

  dst_sock = (SilcSocketConnection)client->connection;
  silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		   + packet->dst_id_len + packet->padlen);

  silc_packet_send_prepare(dst_sock, 0, 0, buffer->len);
  silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);

  idata = (SilcIDListData)client;

  /* Encrypt packet */
  silc_packet_encrypt(idata->send_key, idata->hmac, dst_sock->outbuf, 
		      buffer->len);
    
  /* Send the packet */
  silc_server_packet_send_real(server, dst_sock, FALSE);

  silc_free(id);

 out:
  silc_buffer_free(buffer);
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

/* Free's user_data pointer from socket connection object. As this 
   pointer maybe anything we wil switch here to find the correct
   data type and free it the way it needs to be free'd. */

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

      /* Free the client entry and everything in it */
      silc_idlist_del_data(user_data);
      silc_idlist_del_client(server->local_list, user_data);
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {

      break;
    }
    break;
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

/* Removes client from all channels it has joined. This is used when
   client connection is disconnected. If the client on a channel
   is last, the channel is removed as well. */

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
	silc_server_send_notify_to_channel(server, channel,
					   SILC_NOTIFY_TYPE_SIGNOFF, 1,
					   clidp->data, clidp->len);
      
      silc_idlist_del_channel(server->local_list, channel);
      continue;
    }

    /* Remove from list */
    silc_list_del(channel->user_list, chl);
    silc_free(chl);

    /* Send notify to channel about client leaving SILC and thus
       the entire channel. */
    silc_server_send_notify_to_channel(server, channel,
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
      /* Notify about leaving client if this channel has global users,
	 ie. the channel is not created locally. */
      if (notify && channel->global_users)
	silc_server_send_notify_to_channel(server, channel,
					   SILC_NOTIFY_TYPE_LEAVE, 1,
					   clidp->data, clidp->len);
      
      silc_idlist_del_channel(server->local_list, channel);
      silc_buffer_free(clidp);
      return FALSE;
    }

    /* Remove from list */
    silc_list_del(channel->user_list, chl);
    silc_free(chl);

    /* Send notify to channel about client leaving the channel */
    if (notify)
      silc_server_send_notify_to_channel(server, channel,
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

  silc_server_disconnect_remote(sconn->server, sock, 
				"Server closed connection: "
				"Connection timeout");
}

/* Internal routine used to send (relay, route) private messages to some
   destination. If the private message key does not exist then the message
   is re-encrypted, otherwise we just pass it along. */

static void 
silc_server_private_message_send_internal(SilcServer server,
					  SilcSocketConnection dst_sock,
					  SilcCipher cipher,
					  SilcHmac hmac,
					  SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;

  /* Send and re-encrypt if private messge key does not exist */
  if ((packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY) == FALSE) {

    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_packet_send_prepare(dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    
    /* Re-encrypt packet */
    silc_packet_encrypt(cipher, hmac, dst_sock->outbuf, buffer->len);
    
    /* Send the packet */
    silc_server_packet_send_real(server, dst_sock, FALSE);

  } else {
    /* Key exist so just send it */
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_packet_send_prepare(dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    silc_server_packet_send_real(server, dst_sock, FALSE);
  }
}

/* Received private message. This resolves the destination of the message 
   and sends the packet. This is used by both server and router.  If the
   destination is our locally connected client this sends the packet to
   the client. This may also send the message for further routing if
   the destination is not in our server (or router). */

void silc_server_private_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientID *id;
  SilcServerEntry router;
  SilcSocketConnection dst_sock;
  SilcClientEntry client;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (!packet->dst_id) {
    SILC_LOG_ERROR(("Bad Client ID in private message packet, dropped"));
    goto err;
  }

  /* Decode destination Client ID */
  id = silc_id_str2id(packet->dst_id, SILC_ID_CLIENT);
  if (!id) {
    SILC_LOG_ERROR(("Could not decode destination Client ID, dropped"));
    goto err;
  }

  /* If the destination belongs to our server we don't have to route
     the message anywhere but to send it to the local destination. */
  client = silc_idlist_find_client_by_id(server->local_list, id);
  if (client) {
    /* It exists, now deliver the message to the destination */
    dst_sock = (SilcSocketConnection)client->connection;

    /* If we are router and the client has router then the client is in
       our cell but not directly connected to us. */
    if (server->server_type == SILC_ROUTER && client->router) {
      /* We are of course in this case the client's router thus the real
	 "router" of the client is the server who owns the client. Thus
	 we will send the packet to that server. */
      router = (SilcServerEntry)dst_sock->user_data;
      idata = (SilcIDListData)router;
      //      assert(client->router == server->id_entry);

      silc_server_private_message_send_internal(server, dst_sock,
						idata->send_key,
						idata->hmac,
						packet);
      goto out;
    }

    /* Seems that client really is directly connected to us */
    idata = (SilcIDListData)client;
    silc_server_private_message_send_internal(server, dst_sock, 
					      idata->send_key,
					      idata->hmac, packet);
    goto out;
  }

  /* Destination belongs to someone not in this server. If we are normal
     server our action is to send the packet to our router. */
  if (server->server_type == SILC_SERVER && !server->standalone) {
    router = server->id_entry->router;

    /* Send to primary route */
    if (router) {
      dst_sock = (SilcSocketConnection)router->connection;
      idata = (SilcIDListData)router;
      silc_server_private_message_send_internal(server, dst_sock, 
						idata->send_key,
						idata->hmac, packet);
    }
    goto out;
  }

  /* We are router and we will perform route lookup for the destination 
     and send the message to fastest route. */
  if (server->server_type == SILC_ROUTER && !server->standalone) {
    dst_sock = silc_server_get_route(server, id, SILC_ID_CLIENT);
    router = (SilcServerEntry)dst_sock->user_data;
    idata = (SilcIDListData)router;

    /* Get fastest route and send packet. */
    if (router)
      silc_server_private_message_send_internal(server, dst_sock, 
						idata->send_key,
						idata->hmac, packet);

    goto out;
  }

 err:
  silc_server_send_error(server, sock, 
			 "No such nickname: Private message not sent");
 out:
  silc_buffer_free(buffer);
}

/* Process received channel message. The message can be originated from
   client or server. */

void silc_server_channel_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcChannelEntry channel = NULL;
  SilcChannelClientEntry chl;
  SilcChannelID *id = NULL;
  void *sender = NULL;
  SilcBuffer buffer = packet->buffer;

  SILC_LOG_DEBUG(("Processing channel message"));

  /* Sanity checks */
  if (packet->dst_id_type != SILC_ID_CHANNEL) {
    SILC_LOG_ERROR(("Received bad message for channel, dropped"));
    SILC_LOG_DEBUG(("Received bad message for channel, dropped"));
    goto out;
  }

  /* Find channel entry */
  id = silc_id_str2id(packet->dst_id, SILC_ID_CHANNEL);
  channel = silc_idlist_find_channel_by_id(server->local_list, id);
  if (!channel) {
    SILC_LOG_DEBUG(("Could not find channel"));
    goto out;
  }

  /* See that this client is on the channel. If the message is coming
     from router we won't do the check as the message is from client that
     we don't know about. Also, if the original sender is not client
     (as it can be server as well) we don't do the check. */
  sender = silc_id_str2id(packet->src_id, packet->src_id_type);
  if (sock->type != SILC_SOCKET_TYPE_ROUTER && 
      packet->src_id_type == SILC_ID_CLIENT) {
    silc_list_start(channel->user_list);
    while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
      if (chl->client && !SILC_ID_CLIENT_COMPARE(chl->client->id, sender))
	break;
    }
    if (chl == SILC_LIST_END)
      goto out;
  }

  /* Distribute the packet to our local clients. This will send the
     packet for further routing as well, if needed. */
  silc_server_packet_relay_to_channel(server, sock, channel, sender,
				      packet->src_id_type,
				      packet->buffer->data,
				      packet->buffer->len, FALSE);

 out:
  if (sender)
    silc_free(sender);
  if (id)
    silc_free(id);
  silc_buffer_free(buffer);
}

/* Received channel key packet. We distribute the key to all of our locally
   connected clients on the channel. */
/* XXX Router must accept this packet and distribute the key to all its
   server that has clients on the channel */

void silc_server_channel_key(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcChannelKeyPayload payload = NULL;
  SilcChannelID *id = NULL;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcClientEntry client;
  unsigned char *tmp;
  unsigned int tmp_len;
  char *cipher;

  if (packet->src_id_type != SILC_ID_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    goto out;

  /* Decode channel key payload */
  payload = silc_channel_key_payload_parse(buffer);
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload, dropped"));
    goto out;
  }

  /* Get channel ID */
  tmp = silc_channel_key_get_id(payload, &tmp_len);
  id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!id)
    goto out;

  /* Get the channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, id);
  if (!channel) {
    SILC_LOG_ERROR(("Received key for non-existent channel"));
    goto out;
  }

  /* Save the key for us as well */
  tmp = silc_channel_key_get_key(payload, &tmp_len);
  if (!tmp)
    goto out;
  cipher = silc_channel_key_get_cipher(payload, NULL);;
  if (!cipher)
    goto out;
  if (!silc_cipher_alloc(cipher, &channel->channel_key))
    goto out;

  channel->key_len = tmp_len * 8;
  channel->key = silc_calloc(tmp_len, sizeof(unsigned char));
  memcpy(channel->key, tmp, tmp_len);
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					tmp, tmp_len);

  /* Distribute the key to all clients on the channel */
  /* XXX Some other sender should be used, I think this is not correct */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    client = chl->client;

    if (client)
      silc_server_packet_send_dest(server, client->connection,
				   SILC_PACKET_CHANNEL_KEY, 0,
				   client->id, SILC_ID_CLIENT,
				   buffer->data, buffer->len, FALSE);
  }

 out:
  if (id)
    silc_free(id);
  if (payload)
    silc_channel_key_payload_free(payload);
  silc_buffer_free(buffer);
}

/* Sends current motd to client */

void silc_server_send_motd(SilcServer server,
			   SilcSocketConnection sock)
{
  char *motd;
  int motd_len;

  if (server->config && server->config->motd && 
      server->config->motd->motd_file) {

    motd = silc_file_read(server->config->motd->motd_file, &motd_len);
    if (!motd)
      return;

    silc_server_send_notify(server, sock, SILC_NOTIFY_TYPE_MOTD, 1,
			    motd, motd_len);
    silc_free(motd);
  }
}

/* Sends error message. Error messages may or may not have any 
   implications. */

void silc_server_send_error(SilcServer server,
			    SilcSocketConnection sock,
			    const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  silc_server_packet_send(server, sock, SILC_PACKET_ERROR, 0, 
			  buf, strlen(buf), FALSE);
}

/* Sends notify message. If format is TRUE the variable arguments are
   formatted and the formatted string is sent as argument payload. If it is
   FALSE then each argument is sent as separate argument and their format
   in the argument list must be { argument data, argument length }. */

void silc_server_send_notify(SilcServer server,
			     SilcSocketConnection sock,
			     SilcNotifyType type,
			     unsigned int argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY, 0, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Sends notify message destined to specific entity. */

void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  unsigned int argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY, 0, 
			       dest_id, dest_id_type,
			       packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Sends notify message to a channel. The notify message sent is 
   distributed to all clients on the channel. */

void silc_server_send_notify_to_channel(SilcServer server,
					SilcChannelEntry channel,
					SilcNotifyType type,
					unsigned int argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send_to_channel(server, channel, 
				     SILC_PACKET_NOTIFY,
				     packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Send notify message to all clients the client has joined. It is quaranteed
   that the message is sent only once to a client (ie. if a client is joined
   on two same channel it will receive only one notify message). Also, this
   sends only to local clients (locally connected if we are server, and to
   local servers if we are router). */

void silc_server_send_notify_on_channels(SilcServer server,
					 SilcClientEntry client,
					 SilcNotifyType type,
					 unsigned int argc, ...)
{
  int k;
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry c;
  SilcClientEntry *sent_clients = NULL;
  unsigned int sent_clients_count = 0;
  SilcServerEntry *routed = NULL;
  unsigned int routed_count = 0;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl, chl2;
  SilcIDListData idata;
  SilcBuffer packet;
  unsigned char *data;
  unsigned int data_len;
  int force_send = FALSE;
  va_list ap;

  if (!silc_list_count(client->channels))
    return;

  va_start(ap, argc);
  packet = silc_notify_payload_encode(type, argc, ap);
  data = packet->data;
  data_len = packet->len;

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_NOTIFY;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = SILC_ID_SERVER;
  packetdata.rng = server->rng;

  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    channel = chl->channel;

    /* Send the message to all clients on the channel's client list. */
    silc_list_start(channel->user_list);
    while ((chl2 = silc_list_get(channel->user_list)) != SILC_LIST_END) {
      c = chl2->client;
      
      /* Check if we have sent the packet to this client already */
      for (k = 0; k < sent_clients_count; k++)
	if (sent_clients[k] == c)
	  break;
      if (k < sent_clients_count)
	continue;

      /* If we are router and if this client has router set it is not
	 locally connected client and we will route the message to the
	 router set in the client. */
      if (c && c->router && server->server_type == SILC_ROUTER) {
	/* Check if we have sent the packet to this route already */
	for (k = 0; k < routed_count; k++)
	  if (routed[k] == c->router)
	    break;
	if (k < routed_count)
	  continue;
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)c->router->connection;
	idata = (SilcIDListData)c->router;
	
	packetdata.dst_id = silc_id_id2str(c->router->id, SILC_ID_SERVER);
	packetdata.dst_id_len = SILC_ID_SERVER_LEN;
	packetdata.dst_id_type = SILC_ID_SERVER;
	packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	  packetdata.src_id_len + packetdata.dst_id_len;
	packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, idata->hmac, 
						data, data_len, FALSE, 
						force_send);
	
	silc_free(packetdata.dst_id);

	/* We want to make sure that the packet is routed to same router
	   only once. Mark this route as sent route. */
	k = routed_count;
	routed = silc_realloc(routed, sizeof(*routed) * (k + 1));
	routed[k] = c->router;
	routed_count++;

	continue;
      }

      /* Send to locally connected client */
      if (c) {
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)c->connection;
	idata = (SilcIDListData)c;
	
	packetdata.dst_id = silc_id_id2str(c->id, SILC_ID_CLIENT);
	packetdata.dst_id_len = SILC_ID_CLIENT_LEN;
	packetdata.dst_id_type = SILC_ID_CLIENT;
	packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	  packetdata.src_id_len + packetdata.dst_id_len;
	packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, idata->hmac, 
						data, data_len, FALSE, 
						force_send);

	silc_free(packetdata.dst_id);

	/* Make sure that we send the notify only once per client. */
	sent_clients = silc_realloc(sent_clients, sizeof(*sent_clients) * 
				    (sent_clients_count + 1));
	sent_clients[sent_clients_count] = c;
	sent_clients_count++;
      }
    }
  }

  if (routed_count)
    silc_free(routed);
  if (sent_clients_count)
    silc_free(sent_clients);
  silc_free(packetdata.src_id);
}

/* Sends New ID Payload to remote end. The packet is used to distribute
   information about new registered clients, servers, channel etc. usually
   to routers so that they can keep these information up to date. 
   If the argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */

void silc_server_send_new_id(SilcServer server,
			     SilcSocketConnection sock,
			     int broadcast,
			     void *id, SilcIdType id_type, 
			     unsigned int id_len)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode(id, id_type);
  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  idp->data, idp->len, FALSE);
  silc_buffer_free(idp);
}

/* Sends Replace ID payload to remote end. This is used to replace old
   ID with new ID sent in the packet.  This is called for example when
   user changes nickname and we create new ID for the user.  If the 
   argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */
/* XXX It would be expected that the new id is same type as the old
   ID. :) */

void silc_server_send_replace_id(SilcServer server,
				 SilcSocketConnection sock,
				 int broadcast,
				 void *old_id, SilcIdType old_id_type,
				 unsigned int old_id_len,
				 void *new_id, SilcIdType new_id_type,
				 unsigned int new_id_len)
{
  SilcBuffer packet;
  unsigned char *oid;
  unsigned char *nid;

  oid = silc_id_id2str(old_id, old_id_type);
  if (!oid)
    return;

  nid = silc_id_id2str(new_id, new_id_type);
  if (!nid)
    return;

  packet = silc_buffer_alloc(2 + 2 + 2 + 2 + old_id_len + new_id_len);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(old_id_type),
		     SILC_STR_UI_SHORT(old_id_len),
		     SILC_STR_UI_XNSTRING(oid, old_id_len),
		     SILC_STR_UI_SHORT(new_id_type),
		     SILC_STR_UI_SHORT(new_id_len),
		     SILC_STR_UI_XNSTRING(nid, new_id_len),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_REPLACE_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);
  silc_free(oid);
  silc_free(nid);
  silc_buffer_free(packet);
}

/* This function is used to send Remove Channel User payload. This may sent
   by server but is usually used only by router to notify other routers that
   user has left a channel. Normal server sends this packet to its router
   to notify that the router should not hold a record about this client
   on a channel anymore. Router distributes it further to other routers. */

void silc_server_send_remove_channel_user(SilcServer server,
					  SilcSocketConnection sock,
					  int broadcast,
					  void *client_id, void *channel_id)
{
  SilcBuffer packet;
  unsigned char *clid, *chid;

  clid = silc_id_id2str(client_id, SILC_ID_CLIENT);
  if (!clid)
    return;

  chid = silc_id_id2str(channel_id, SILC_ID_CHANNEL);
  if (!chid)
    return;

  packet = silc_buffer_alloc(2 + 2 + SILC_ID_CLIENT_LEN + SILC_ID_CHANNEL_LEN);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT_LEN),
		     SILC_STR_UI_XNSTRING(clid, SILC_ID_CLIENT_LEN),
		     SILC_STR_UI_SHORT(SILC_ID_CHANNEL_LEN),
		     SILC_STR_UI_XNSTRING(chid, SILC_ID_CHANNEL_LEN),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_REMOVE_CHANNEL_USER, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);
  silc_free(clid);
  silc_free(chid);
  silc_buffer_free(packet);
}

/* Received packet to replace a ID. This checks that the requested ID
   exists and replaces it with the new one. */

void silc_server_replace_id(SilcServer server,
			    SilcSocketConnection sock,
			    SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  unsigned char *old_id = NULL, *new_id = NULL;
  SilcIdType old_id_type, new_id_type;
  unsigned short old_id_len, new_id_len;
  void *id = NULL, *id2 = NULL;

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type == SILC_ID_CLIENT)
    return;

  SILC_LOG_DEBUG(("Replacing ID"));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&old_id_type),
		       SILC_STR_UI16_NSTRING_ALLOC(&old_id, &old_id_len),
		       SILC_STR_UI_SHORT(&new_id_type),
		       SILC_STR_UI16_NSTRING_ALLOC(&new_id, &new_id_len),
		       SILC_STR_END);

  if (old_id_type != new_id_type)
    goto out;

  if (old_id_len != silc_id_get_len(old_id_type) ||
      new_id_len != silc_id_get_len(new_id_type))
    goto out;

  id = silc_id_str2id(old_id, old_id_type);
  if (!id)
    goto out;

  id2 = silc_id_str2id(new_id, new_id_type);
  if (!id2)
    goto out;

  /* Replace the old ID */
  switch(old_id_type) {
  case SILC_ID_CLIENT:
    if (silc_idlist_replace_client_id(server->local_list, id, id2) == NULL)
      if (server->server_type == SILC_ROUTER)
	silc_idlist_replace_client_id(server->global_list, id, id2);
    break;

  case SILC_ID_SERVER:
    if (silc_idlist_replace_server_id(server->local_list, id, id2) == NULL)
      if (server->server_type == SILC_ROUTER)
	silc_idlist_replace_server_id(server->global_list, id, id2);
    break;

  case SILC_ID_CHANNEL:
    /* XXX Hmm... Basically this cannot occur. Channel ID's cannot be
       re-generated. */
    silc_free(id2);
    break;

  default:
    silc_free(id2);
    break;
  }

 out:
  if (id)
    silc_free(id);
  if (old_id)
    silc_free(old_id);
  if (new_id)
    silc_free(new_id);
}

/* Creates new channel. */

SilcChannelEntry silc_server_new_channel(SilcServer server, 
					 SilcServerID *router_id,
					 char *cipher, char *channel_name)
{
  int i, channel_len, key_len;
  SilcChannelID *channel_id;
  SilcChannelEntry entry;
  SilcCipher key;
  unsigned char channel_key[32], *id_string;
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Creating new channel"));

  /* Create channel key */
  for (i = 0; i < 32; i++) channel_key[i] = silc_rng_get_byte(server->rng);

  if (!cipher)
    cipher = "twofish";

  /* Allocate keys */
  key_len = 16;
  silc_cipher_alloc(cipher, &key);
  key->cipher->set_key(key->context, channel_key, key_len);

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

  entry->key = silc_calloc(key_len, sizeof(*entry->key));
  entry->key_len = key_len * 8;
  memcpy(entry->key, channel_key, key_len);
  memset(channel_key, 0, sizeof(channel_key));

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (server->standalone == FALSE) {
    channel_len = strlen(channel_name);
    id_string = silc_id_id2str(entry->id, SILC_ID_CHANNEL);
    packet = silc_buffer_alloc(2 + SILC_ID_CHANNEL_LEN);

    silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
    silc_buffer_format(packet,
		       SILC_STR_UI_SHORT(channel_len),
		       SILC_STR_UI_XNSTRING(channel_name, channel_len),
		       SILC_STR_UI_SHORT(SILC_ID_CHANNEL_LEN),
		       SILC_STR_UI_XNSTRING(id_string, SILC_ID_CHANNEL_LEN),
		       SILC_STR_END);

    /* Send the packet to our router. */
    silc_server_packet_send(server, (SilcSocketConnection) 
			    server->id_entry->router->connection,
			    SILC_PACKET_NEW_CHANNEL_USER, 0, 
			    packet->data, packet->len, TRUE);
    
    silc_free(id_string);
    silc_buffer_free(packet);
  }

  return entry;
}

/* Create new client. This processes incoming NEW_CLIENT packet and creates
   Client ID for the client. Client becomes registered after calling this
   functions. */

SilcClientEntry silc_server_new_client(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientEntry client;
  SilcIDCacheEntry cache;
  SilcClientID *client_id;
  SilcBuffer reply;
  SilcIDListData idata;
  char *username = NULL, *realname = NULL, *id_string;

  SILC_LOG_DEBUG(("Creating new client"));

  if (sock->type != SILC_SOCKET_TYPE_CLIENT)
    return NULL;

  /* Take client entry */
  client = (SilcClientEntry)sock->user_data;
  idata = (SilcIDListData)client;

  /* Fetch the old client cache entry so that we can update it. */
  if (!silc_idcache_find_by_context(server->local_list->clients,
				    sock->user_data, &cache)) {
    SILC_LOG_ERROR(("Lost client's cache entry - bad thing"));
    return NULL;
  }

  /* Parse incoming packet */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_STRING_ALLOC(&username),
		       SILC_STR_UI16_STRING_ALLOC(&realname),
		       SILC_STR_END);

  /* Create Client ID */
  silc_id_create_client_id(server->id, server->rng, server->md5hash,
			   username, &client_id);

  /* Update client entry */
  idata->registered = TRUE;
  client->nickname = strdup(username);
  client->username = username;
  client->userinfo = realname;
  client->id = client_id;

  /* Update the cache entry */
  cache->id = (void *)client_id;
  cache->type = SILC_ID_CLIENT;
  cache->data = username;
  silc_idcache_sort_by_data(server->local_list->clients);

  /* Notify our router about new client on the SILC network */
  if (!server->standalone)
    silc_server_send_new_id(server, (SilcSocketConnection) 
			    server->id_entry->router->connection, 
			    server->server_type == SILC_ROUTER ? TRUE : FALSE,
			    client->id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);
  
  /* Send the new client ID to the client. */
  id_string = silc_id_id2str(client->id, SILC_ID_CLIENT);
  reply = silc_buffer_alloc(2 + 2 + SILC_ID_CLIENT_LEN);
  silc_buffer_pull_tail(reply, SILC_BUFFER_END(reply));
  silc_buffer_format(reply,
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT),
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT_LEN),
		     SILC_STR_UI_XNSTRING(id_string, SILC_ID_CLIENT_LEN),
		     SILC_STR_END);
  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 0, 
			  reply->data, reply->len, FALSE);
  silc_free(id_string);
  silc_buffer_free(reply);

  /* Send some nice info to the client */
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Welcome to the SILC Network %s@%s",
			   username, sock->hostname));
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your host is %s, running version %s",
			   server->config->server_info->server_name,
			   server_version));
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

  return client;
}

/* Create new server. This processes incoming NEW_SERVER packet and
   saves the received Server ID. The server is our locally connected
   server thus we save all the information and save it to local list. 
   This funtion can be used by both normal server and router server.
   If normal server uses this it means that its router has connected
   to the server. If router uses this it means that one of the cell's
   servers is connected to the router. */

SilcServerEntry silc_server_new_server(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcServerEntry new_server;
  SilcIDCacheEntry cache;
  SilcServerID *server_id;
  SilcIDListData idata;
  unsigned char *server_name, *id_string;
  unsigned short id_len;

  SILC_LOG_DEBUG(("Creating new server"));

  if (sock->type != SILC_SOCKET_TYPE_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return NULL;

  /* Take server entry */
  new_server = (SilcServerEntry)sock->user_data;
  idata = (SilcIDListData)new_server;

  /* Fetch the old server cache entry so that we can update it. */
  if (!silc_idcache_find_by_context(server->local_list->servers,
				    sock->user_data, &cache)) {
    SILC_LOG_ERROR(("Lost server's cache entry - bad thing"));
    return NULL;
  }

  /* Parse the incoming packet */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_NSTRING_ALLOC(&id_string, &id_len),
		       SILC_STR_UI16_STRING_ALLOC(&server_name),
		       SILC_STR_END);

  if (id_len > buffer->len) {
    silc_free(id_string);
    silc_free(server_name);
    return NULL;
  }

  /* Get Server ID */
  server_id = silc_id_str2id(id_string, SILC_ID_SERVER);
  silc_free(id_string);

  /* Update client entry */
  idata->registered = TRUE;
  new_server->server_name = server_name;
  new_server->id = server_id;

  /* Update the cache entry */
  cache->id = (void *)server_id;
  cache->type = SILC_ID_SERVER;
  cache->data = server_name;
  silc_idcache_sort_by_data(server->local_list->servers);

  /* Distribute the information about new server in the SILC network
     to our router. If we are normal server we won't send anything
     since this connection must be our router connection. */
  if (server->server_type == SILC_ROUTER && !server->standalone &&
      server->id_entry->router->connection != sock)
    silc_server_send_new_id(server, server->id_entry->router->connection,
			    TRUE, new_server->id, SILC_ID_SERVER, 
			    SILC_ID_SERVER_LEN);

  return new_server;
}

/* Processes incoming New ID Payload. New ID Payload is used to distribute
   information about newly registered clients, servers and created 
   channels. */

void silc_server_new_id(SilcServer server, SilcSocketConnection sock,
			SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcIDList id_list;
  SilcServerEntry tmpserver, router;
  SilcSocketConnection router_sock;
  SilcIDPayload idp;
  SilcIdType id_type;
  void *id, *tmpid;

  SILC_LOG_DEBUG(("Processing new ID"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type == SILC_SERVER ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  idp = silc_id_payload_parse(buffer);
  if (!idp)
    return;

  id_type = silc_id_payload_get_type(idp);

  /* Normal server cannot have other normal server connections */
  if (id_type == SILC_ID_SERVER && sock->type == SILC_SOCKET_TYPE_SERVER)
    goto out;

  id = silc_id_payload_get_id(idp);
  if (!id)
    goto out;

  /* If the sender of this packet is server and we are router we need to
     broadcast this packet to other routers in the network. */
  if (!server->standalone && sock->type == SILC_SOCKET_TYPE_SERVER &&
      server->server_type == SILC_ROUTER) {
    SILC_LOG_DEBUG(("Broadcasting received New ID packet"));
    silc_server_packet_send(server, server->id_entry->router->connection,
			    packet->type, 
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    buffer->data, buffer->len, FALSE);
  }

  /* If the packet is originated from the one who sent it to us we know
     that the ID belongs to our cell, unless the sender was router. */
  tmpid = silc_id_str2id(packet->src_id, SILC_ID_SERVER);
  tmpserver = (SilcServerEntry)sock->user_data;

  if (!SILC_ID_SERVER_COMPARE(tmpid, tmpserver->id) &&
      sock->type == SILC_SOCKET_TYPE_SERVER) {
    id_list = server->local_list;
    router_sock = sock;
    router = sock->user_data;
    /*    router = server->id_entry; */
  } else {
    id_list = server->global_list;
    router_sock = (SilcSocketConnection)server->id_entry->router->connection;
    router = server->id_entry->router;
  }

  silc_free(tmpid);

  switch(id_type) {
  case SILC_ID_CLIENT:
    {
      SilcClientEntry idlist;

      SILC_LOG_DEBUG(("New client id(%s) from [%s] %s",
		      silc_id_render(id, SILC_ID_CLIENT),
		      sock->type == SILC_SOCKET_TYPE_SERVER ?
		      "Server" : "Router", sock->hostname));

      /* Add the client to our local list. We are router and we keep
	 cell specific local database of all clients in the cell. */
      idlist = silc_idlist_add_client(id_list, NULL, NULL, NULL,
				      id, router, router_sock);
    }
    break;

  case SILC_ID_SERVER:
    {
      SilcServerEntry idlist;

      SILC_LOG_DEBUG(("New server id(%s) from [%s] %s",
		      silc_id_render(id, SILC_ID_SERVER),
		      sock->type == SILC_SOCKET_TYPE_SERVER ?
		      "Server" : "Router", sock->hostname));

      /* Add the server to our local list. We are router and we keep
	 cell specific local database of all servers in the cell. */
      idlist = silc_idlist_add_server(id_list, NULL, 0, id, router, 
				      router_sock);
    }
    break;

  case SILC_ID_CHANNEL:
    SILC_LOG_DEBUG(("New channel id(%s) from [%s] %s",
		    silc_id_render(id, SILC_ID_CHANNEL),
		    sock->type == SILC_SOCKET_TYPE_SERVER ?
		    "Server" : "Router", sock->hostname));

    /* Add the channel to our local list. We are router and we keep
       cell specific local database of all channels in the cell. */
    silc_idlist_add_channel(id_list, NULL, 0, id, router, NULL);
    break;

  default:
    break;
  }

 out:
  silc_id_payload_free(idp);
}

/* Received packet to remove a user from a channel. Routers notify other
   routers that user has left a channel. Client must not send this packet. 
   Normal server may send this packet but ignores if it receives one. */

void silc_server_remove_channel_user(SilcServer server,
				     SilcSocketConnection sock,
				     SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  unsigned char *tmp1 = NULL, *tmp2 = NULL;
  SilcClientID *client_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcChannelEntry channel;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Removing user from channel"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type == SILC_SERVER)
    return;

  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_STRING_ALLOC(&tmp1),
		       SILC_STR_UI16_STRING_ALLOC(&tmp2),
		       SILC_STR_END);

  if (!tmp1 || !tmp2)
    goto out;

  client_id = silc_id_str2id(tmp1, SILC_ID_CLIENT);
  channel_id = silc_id_str2id(tmp2, SILC_ID_CHANNEL);
  if (!client_id || !channel_id)
    goto out;

  /* XXX routers should check server->global_list as well */
  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
  if (!channel)
    goto out;
  
  /* XXX routers should check server->global_list as well */
  /* Get client entry */
  client = silc_idlist_find_client_by_id(server->local_list, client_id);
  if (!client)
    goto out;

  /* Remove from channel */
  silc_server_remove_from_one_channel(server, sock, channel, client, FALSE);

 out:
  if (tmp1)
    silc_free(tmp1);
  if (tmp2)
    silc_free(tmp2);
  if (client_id)
    silc_free(client_id);
  if (channel_id)
    silc_free(channel_id);
}
