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
/*
 * $Id$
 * $Log$
 * Revision 1.5  2000/07/06 13:18:07  priikone
 * 	Check for NULL in client_on_channel.
 *
 * Revision 1.4  2000/07/05 06:14:01  priikone
 * 	Global costemic changes.
 *
 * Revision 1.3  2000/07/04 08:13:53  priikone
 * 	Changed message route discovery to use silc_server_get_route.
 * 	Added silc_server_client_on_channel function.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "serverincludes.h"
#include "server_internal.h"

/* Static prototypes */
SILC_TASK_CALLBACK(silc_server_connect_to_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router_second);
SILC_TASK_CALLBACK(silc_server_connect_to_router_final);
SILC_TASK_CALLBACK(silc_server_accept_new_connection);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_second);
SILC_TASK_CALLBACK(silc_server_accept_new_connection_final);
SILC_TASK_CALLBACK(silc_server_packet_process);
SILC_TASK_CALLBACK(silc_server_packet_parse);
SILC_TASK_CALLBACK(silc_server_timeout_remote);

/* XXX */
void silc_server_packet_parse_type(SilcServer server, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet);

static int silc_server_packet_check_mac(SilcServer server,
					SilcSocketConnection sock,
					SilcBuffer buffer);
static int silc_server_packet_decrypt_rest(SilcServer server, 
					   SilcSocketConnection sock,
					   SilcBuffer buffer);
static int silc_server_packet_decrypt_rest_special(SilcServer server, 
						   SilcSocketConnection sock,
						   SilcBuffer buffer);

extern char server_version[];

/* Allocates a new SILC server object. This has to be done before the server
   can be used. After allocation one must call silc_server_init to initialize
   the server. The new allocated server object is returned to the new_server
   argument. */

int silc_server_alloc(SilcServer *new_server)
{
  SILC_LOG_DEBUG(("Allocating new server object"));

  *new_server = silc_calloc(1, sizeof(**new_server));
  if (*new_server == NULL) {
    SILC_LOG_ERROR(("Could not allocate new server object"));
    return FALSE;
  }

  /* Set default values */
  (*new_server)->server_name = NULL;
  (*new_server)->server_type = SILC_SERVER;
  (*new_server)->standalone = FALSE;
  (*new_server)->id = NULL;
  (*new_server)->io_queue = NULL;
  (*new_server)->timeout_queue = NULL;
  (*new_server)->local_list = silc_calloc(1, sizeof(SilcIDListObject));
  (*new_server)->global_list = silc_calloc(1, sizeof(SilcIDListObject));
  (*new_server)->rng = NULL;
  (*new_server)->md5hash = NULL;
  (*new_server)->sha1hash = NULL;
  /*  (*new_server)->public_key = NULL;*/

  return TRUE;
}

/* Free's the SILC server object. This is called at the very end before
   the program ends. */

void silc_server_free(SilcServer server)
{
  if (server) {
    if (server->local_list)
      silc_free(server->local_list);
    if (server->global_list)
      silc_free(server->global_list);
    if (server->rng)
      silc_rng_free(server->rng);

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
  int *sock = NULL, sock_count, i;
  SilcServerID *id;
  SilcServerList *id_entry;
  SilcHashObject hash;

  SILC_LOG_DEBUG(("Initializing server"));
  assert(server);
  assert(server->config);

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
    SilcPublicKey pub_key;
    SilcPrivateKey prv_key;

    if (silc_pkcs_alloc("rsa", &server->public_key) == FALSE) {
      SILC_LOG_ERROR(("Could not create RSA key pair"));
      goto err0;
    }

    if (server->public_key->pkcs->init(server->public_key->context, 
				       1024, server->rng) == FALSE) {
      SILC_LOG_ERROR(("Could not generate RSA key pair"));
      goto err0;
    }

    public_key = 
      server->public_key->pkcs->get_public_key(server->public_key->context,
					       &pk_len);
    private_key = 
      server->public_key->pkcs->get_private_key(server->public_key->context,
						&prv_len);

    SILC_LOG_HEXDUMP(("public key"), public_key, pk_len);
    SILC_LOG_HEXDUMP(("private key"), private_key, prv_len);

    pub_key = silc_pkcs_public_key_alloc("rsa", "UN=root, HN=dummy",
					 public_key, pk_len);
    prv_key = silc_pkcs_private_key_alloc("rsa", private_key, prv_len);

    /* XXX Save keys */
    silc_pkcs_save_public_key("pubkey.pub", pub_key);
    silc_pkcs_save_private_key("privkey.prv", prv_key, NULL);

    memset(public_key, 0, pk_len);
    memset(private_key, 0, prv_len);
    silc_free(public_key);
    silc_free(private_key);
    silc_pkcs_public_key_free(pub_key);
    silc_pkcs_private_key_free(prv_key);
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
    silc_idlist_add_server(&server->local_list->servers, 
			   server->config->server_info->server_name,
			   server->server_type, server->id, NULL,
			   server->send_key, server->receive_key,
			   NULL, NULL, &id_entry);
    if (!id_entry)
      goto err0;
    
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

  /* Initialize the scheduler */
  silc_schedule_init(server->io_queue, server->timeout_queue, 
		     server->generic_queue, 
		     SILC_SERVER_MAX_CONNECTIONS);
  
  /* Add the first task to the queue. This is task that is executed by
     timeout. It expires as soon as the caller calls silc_server_run. This
     task performs authentication protocol and key exchange with our
     primary router. */
  if (silc_task_register(server->timeout_queue, sock[0], 
			 silc_server_connect_to_router,
			 (void *)server, 0, 1,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL) == NULL) {
    goto err2;
  }

  /* If server connections has been configured then we must be router as
     normal server cannot have server connections, only router connections. */
  if (server->config->servers)
    server->server_type = SILC_ROUTER;

  SILC_LOG_DEBUG(("Server initialized"));

  /* We are done here, return succesfully */
  return TRUE;

 err2:
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

/* This function connects to our primary router or if we are a router this
   establishes all our primary routes. This is called at the start of the
   server to do authentication and key exchange with our router - called
   from schedule. */

SILC_TASK_CALLBACK(silc_server_connect_to_router)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection newsocket;
  int sock;

  SILC_LOG_DEBUG(("Connecting to router(s)"));

  /* if we are normal SILC server we need to connect to our cell's
     router. */
  if (server->server_type == SILC_SERVER) {
    SilcProtocol protocol;
    SilcServerKEInternalContext *proto_ctx;

    /* Create connection to the router, if configured. */
    if (server->config->routers) {
      sock = silc_net_create_connection(server->config->routers->port, 
					server->config->routers->host);
      if (sock < 0) {
	SILC_LOG_ERROR(("Could not connect to router"));
	silc_schedule_stop();
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
      newsocket->hostname = server->config->routers->host;
      newsocket->port = server->config->routers->port;

      /* Allocate internal protocol context. This is sent as context
	 to the protocol. */
      proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
      proto_ctx->server = context;
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
	 is not executed within 15 seconds. For now, this is a hard coded 
	 limit. After 15 secs the connection will be closed if the key 
	 exchange protocol has not been executed. */
      proto_ctx->timeout_task = 
	silc_task_register(server->timeout_queue, sock, 
			   silc_server_timeout_remote,
			   context, 15, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);

      /* Register the connection for network input and output. This sets
	 that scheduler will listen for incoming packets for this connection 
	 and sets that outgoing packets may be sent to this connection as 
	 well. However, this doesn't set the scheduler for outgoing traffic,
	 it will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
	 later when outgoing data is available. */
      SILC_REGISTER_CONNECTION_FOR_IO(sock);
      
      /* Run the protocol */
      protocol->execute(server->timeout_queue, 0, protocol, sock, 0, 0);
      return;
    }
  }
  
  /* if we are a SILC router we need to establish all of our primary
     routes. */
  if (server->server_type == SILC_ROUTER) {
    SilcConfigServerSectionServerConnection *ptr;

    /* Create the connections to all our routes */
    ptr = server->config->routers;
    while (ptr) {
      SilcProtocol protocol;
      SilcServerKEInternalContext *proto_ctx;

      /* Create the connection to the remote end */
      sock = silc_net_create_connection(ptr->port, ptr->host);
      if (sock < 0) {
	SILC_LOG_ERROR(("Could not connect to router"));
	silc_schedule_stop();
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
      newsocket->hostname = ptr->host;
      newsocket->port = ptr->port;

      /* Allocate internal protocol context. This is sent as context
	 to the protocol. */
      proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
      proto_ctx->server = context;
      proto_ctx->sock = newsocket;
      proto_ctx->rng = server->rng;
      proto_ctx->responder = FALSE;
      
      /* Perform key exchange protocol. silc_server_connect_to_router_final
	 will be called after the protocol is finished. */
      silc_protocol_alloc(SILC_PROTOCOL_SERVER_KEY_EXCHANGE, 
			  &protocol, proto_ctx,
			  silc_server_connect_to_router_second);
      newsocket->protocol = protocol;

      /* Register a timeout task that will be executed if the protocol
	 is not executed within 15 seconds. For now, this is a hard coded 
	 limit. After 15 secs the connection will be closed if the key 
	 exchange protocol has not been executed. */
      proto_ctx->timeout_task = 
	silc_task_register(server->timeout_queue, sock, 
			   silc_server_timeout_remote,
			   context, 15, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW);

      /* Register the connection for network input and output. This sets
	 that scheduler will listen for incoming packets for this connection 
	 and sets that outgoing packets may be sent to this connection as 
	 well. However, this doesn't set the scheduler for outgoing traffic,
	 it will be set separately by calling SILC_SET_CONNECTION_FOR_OUTPUT,
	 later when outgoing data is available. */
      SILC_REGISTER_CONNECTION_FOR_IO(sock);
      
      /* Run the protocol */
      protocol->execute(server->timeout_queue, 0, protocol, sock, 0, 0);

      if (!ptr->next)
	return;

      ptr = ptr->next;
    }
  }

  SILC_LOG_DEBUG(("No router(s), server will be standalone"));
  
  /* There wasn't a configured router, we will continue but we don't
     have a connection to outside world.  We will be standalone server. */
  server->standalone = TRUE;

  /* Add a task to the queue. This task receives new connections to the 
     server. This task remains on the queue until the end of the program. */
  if (silc_task_register(server->io_queue, fd, 
			 silc_server_accept_new_connection,
			 (void *)server, 0, 0, 
			 SILC_TASK_FD,
			 SILC_TASK_PRI_NORMAL) == NULL) {
    silc_schedule_stop();
    return;
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
  SilcSocketConnection sock = ctx->sock;
  SilcServerList *id_entry;
  SilcIDListUnknown *conn_data;
  SilcBuffer packet;
  unsigned char *id_string;

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
				  "Authentication failed");
    return;
  }

  /* Add a task to the queue. This task receives new connections to the 
     server. This task remains on the queue until the end of the program. */
  if (!server->listenning) {
    if (silc_task_register(server->io_queue, server->sock, 
			   silc_server_accept_new_connection,
			   (void *)server, 0, 0, 
			   SILC_TASK_FD,
			   SILC_TASK_PRI_NORMAL) == NULL) {
      silc_schedule_stop();
      return;
    } else {
      server->listenning = TRUE;
    }
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
  conn_data = (SilcIDListUnknown *)sock->user_data;
  silc_idlist_add_server(&server->local_list->servers, 
			 sock->hostname ? sock->hostname : sock->ip,
			 SILC_ROUTER, ctx->dest_id, NULL,
			 conn_data->send_key, conn_data->receive_key,
			 conn_data->pkcs, conn_data->hmac, &id_entry);

  id_entry->hmac_key = conn_data->hmac_key;
  id_entry->hmac_key_len = conn_data->hmac_key_len;
  id_entry->connection = sock;
  sock->user_data = (void *)id_entry;
  sock->type = SILC_SOCKET_TYPE_ROUTER;
  server->id_entry->router = id_entry;

  /* Free the temporary connection data context from key exchange */
  silc_free(conn_data);

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
     will not start the key exchange protocol within 15 seconds. For
     now, this is a hard coded limit. After 15 secs the connection will
     be closed if the key exchange protocol has not been started. */
  proto_ctx->timeout_task = 
    silc_task_register(server->timeout_queue, newsocket->sock, 
		       silc_server_timeout_remote,
		       context, 15, 0,
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
				  "Authentication failed");
    return;
  }

  sock->type = ctx->conn_type;
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientList *id_entry = NULL;
      SilcIDListUnknown *conn_data = sock->user_data;

      SILC_LOG_DEBUG(("Remote host is client"));

      SILC_LOG_INFO(("Connection from %s (%s) is client", sock->hostname,
		     sock->ip));

      /* Add the client to the client ID list. We have not created the
	 client ID for the client yet. This is done when client registers
	 itself by sending NEW_CLIENT packet. */
      silc_idlist_add_client(&server->local_list->clients, 
			     NULL, NULL, NULL, NULL, NULL,
			     conn_data->send_key, conn_data->receive_key, 
			     conn_data->pkcs, conn_data->hmac, &id_entry);

      id_entry->hmac_key = conn_data->hmac_key;
      id_entry->hmac_key_len = conn_data->hmac_key_len;
      id_entry->connection = sock;

      /* Free the temporary connection data context from key exchange */
      silc_free(conn_data);

      /* Mark the entry to the ID list to the socket connection for
	 fast referencing in the future. */
      sock->user_data = (void *)id_entry;
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerList *id_entry;
      SilcIDListUnknown *conn_data = sock->user_data;
      
      SILC_LOG_DEBUG(("Remote host is %s", 
		      sock->type == SILC_SOCKET_TYPE_SERVER ? 
		      "server" : "router"));
      
      SILC_LOG_INFO(("Connection from %s (%s) is %s", sock->hostname,
		     sock->ip, sock->type == SILC_SOCKET_TYPE_SERVER ? 
		     "server" : "router"));

      /* Add the server to the ID list. We don't have the server's ID
	 yet but we will receive it after the server sends NEW_SERVER
	 packet to us. */
      silc_idlist_add_server(&server->local_list->servers, NULL,
			     sock->type == SILC_SOCKET_TYPE_SERVER ?
			     SILC_SERVER : SILC_ROUTER, NULL, NULL,
			     conn_data->send_key, conn_data->receive_key,
			     conn_data->pkcs, conn_data->hmac, &id_entry);

      id_entry->hmac_key = conn_data->hmac_key;
      id_entry->hmac_key_len = conn_data->hmac_key_len;
      id_entry->connection = sock;

      /* Free the temporary connection data context from key exchange */
      silc_free(conn_data);

      /* Mark the entry to the ID list to the socket connection for
	 fast referencing in the future. */
      sock->user_data = (void *)id_entry;

      /* There is connection to other server now, if it is router then
	 we will have connection to outside world.  If we are router but
	 normal server connected to us then we will remain standalone,
	 if we are standlone. */
      if (server->standalone && sock->type == SILC_SOCKET_TYPE_ROUTER) {
	SILC_LOG_DEBUG(("We are not standalone server anymore"));
	server->standalone = FALSE;
      }
      break;
    }
  default:
    break;
  }

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
  int ret, packetlen, paddedlen;

  SILC_LOG_DEBUG(("Processing packet"));

  /* Packet sending */
  if (type == SILC_TASK_WRITE) {
    SILC_LOG_DEBUG(("Writing data to connection"));

    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, 
		       sock->outbuf->data - sock->outbuf->head);

    /* Write the packet out to the connection */
    ret = silc_packet_write(fd, sock->outbuf);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;
    
    /* Error */
    if (ret == -1)
      SILC_LOG_ERROR(("Could not write, packet dropped"));

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
  if (type == SILC_TASK_READ) {
    SILC_LOG_DEBUG(("Reading data from connection"));

    /* Allocate the incoming data buffer if not done already. */
    if (!sock->inbuf)
      sock->inbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);

    /* Read some data from connection */
    ret = silc_packet_read(fd, sock->inbuf);
    
    /* If returned -2 data was not available now, will read it later. */
    if (ret == -2)
      return;
    
    /* Error */
    if (ret == -1) {
      SILC_LOG_ERROR(("Could not read, packet dropped"));
      return;
    }
    
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

    /* Check whether we received a whole packet. If reading went without
       errors we either read a whole packet or the read packet is 
       incorrect and will be dropped. */
    SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);
    if (sock->inbuf->len < paddedlen || (packetlen < SILC_PACKET_MIN_LEN)) {
      SILC_LOG_DEBUG(("Received incorrect packet, dropped"));
      silc_buffer_clear(sock->inbuf);
      silc_server_disconnect_remote(server, sock, "Incorrect packet");
      return;
    }

    /* Decrypt a packet coming from client. */
    if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
      SilcClientList *clnt = (SilcClientList *)sock->user_data;
      SilcServerInternalPacket *packet;
      int mac_len = 0;
      
      if (clnt->hmac)
	mac_len = clnt->hmac->hash->hash->hash_len;

      if (sock->inbuf->len - 2 > (paddedlen + mac_len)) {
	/* Received possibly many packets at once */

	while(sock->inbuf->len > 0) {
	  SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);
	  if (sock->inbuf->len < paddedlen) {
	    SILC_LOG_DEBUG(("Receive incorrect packet, dropped"));
	    return;
	  }

	  paddedlen += 2;
	  packet = silc_calloc(1, sizeof(*packet));
	  packet->server = server;
	  packet->sock = sock;
	  packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
	  packet->packetdata->buffer = silc_buffer_alloc(paddedlen + mac_len);
	  silc_buffer_pull_tail(packet->packetdata->buffer, 
				SILC_BUFFER_END(packet->packetdata->buffer));
	  silc_buffer_put(packet->packetdata->buffer, sock->inbuf->data, 
			  paddedlen + mac_len);
	  if (clnt) {
	    packet->cipher = clnt->receive_key;
	    packet->hmac = clnt->hmac;
	  }

	  SILC_LOG_HEXDUMP(("Incoming packet, len %d", 
			    packet->packetdata->buffer->len),
			   packet->packetdata->buffer->data, 
			   packet->packetdata->buffer->len);

	  /* Parse the packet with timeout */
	  silc_task_register(server->timeout_queue, fd, 
			     silc_server_packet_parse,
			     (void *)packet, 0, 100000, 
			     SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);

	  /* Pull the packet from inbuf thus we'll get the next one
	     in the inbuf. */
	  silc_buffer_pull(sock->inbuf, paddedlen);
	  if (clnt->hmac)
	    silc_buffer_pull(sock->inbuf, mac_len);
	}
	silc_buffer_clear(sock->inbuf);
	return;
      } else {
	SILC_LOG_HEXDUMP(("An incoming packet, len %d", sock->inbuf->len),
			 sock->inbuf->data, sock->inbuf->len);
	
	SILC_LOG_DEBUG(("Packet from client, length %d", paddedlen));
	
	packet = silc_calloc(1, sizeof(*packet));
	packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
	packet->packetdata->buffer = silc_buffer_copy(sock->inbuf);
	packet->server = server;
	packet->sock = sock;
	if (clnt) {
	  packet->cipher = clnt->receive_key;
	  packet->hmac = clnt->hmac;
	}
	silc_buffer_clear(sock->inbuf);
	
	/* The packet is ready to be parsed now. However, this is a client 
	   connection so we will parse the packet with timeout. */
	silc_task_register(server->timeout_queue, fd, 
			   silc_server_packet_parse,
			   (void *)packet, 0, 100000, 
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
	return;
      }
    }
    
    /* Decrypt a packet coming from server connection */
    if (sock->type == SILC_SOCKET_TYPE_SERVER ||
	sock->type == SILC_SOCKET_TYPE_ROUTER) {
      SilcServerList *srvr = (SilcServerList *)sock->user_data;
      SilcServerInternalPacket *packet;
      int mac_len = 0;
      
      if (srvr->hmac)
	mac_len = srvr->hmac->hash->hash->hash_len;

      if (sock->inbuf->len - 2 > (paddedlen + mac_len)) {
	/* Received possibly many packets at once */

	while(sock->inbuf->len > 0) {
	  SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);
	  if (sock->inbuf->len < paddedlen) {
	    SILC_LOG_DEBUG(("Received incorrect packet, dropped"));
	    return;
	  }

	  paddedlen += 2;
	  packet = silc_calloc(1, sizeof(*packet));
	  packet->server = server;
	  packet->sock = sock;
	  packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
	  packet->packetdata->buffer = silc_buffer_alloc(paddedlen + mac_len);
	  silc_buffer_pull_tail(packet->packetdata->buffer, 
				SILC_BUFFER_END(packet->packetdata->buffer));
	  silc_buffer_put(packet->packetdata->buffer, sock->inbuf->data, 
			  paddedlen + mac_len);
	  if (srvr) {
	    packet->cipher = srvr->receive_key;
	    packet->hmac = srvr->hmac;
	  }

	  SILC_LOG_HEXDUMP(("Incoming packet, len %d", 
			    packet->packetdata->buffer->len),
			   packet->packetdata->buffer->data, 
			   packet->packetdata->buffer->len);

	  SILC_LOG_DEBUG(("Packet from %s %s, packet length %d", 
			  srvr->server_type == SILC_SERVER ? 
			  "server" : "router",
			  srvr->server_name, paddedlen));
	
	  /* Parse it real soon as the packet is from server. */
	  silc_task_register(server->timeout_queue, fd, 
			     silc_server_packet_parse,
			     (void *)packet, 0, 1, 
			     SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);

	  /* Pull the packet from inbuf thus we'll get the next one
	     in the inbuf. */
	  silc_buffer_pull(sock->inbuf, paddedlen);
	  if (srvr->hmac)
	    silc_buffer_pull(sock->inbuf, mac_len);
	}
	silc_buffer_clear(sock->inbuf);
	return;
      } else {

	SILC_LOG_HEXDUMP(("An incoming packet, len %d", sock->inbuf->len),
			 sock->inbuf->data, sock->inbuf->len);
	
	SILC_LOG_DEBUG(("Packet from %s %s, packet length %d", 
			srvr->server_type == SILC_SERVER ? 
			"server" : "router",
			srvr->server_name, paddedlen));
	
	packet = silc_calloc(1, sizeof(*packet));
	packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
	packet->packetdata->buffer = silc_buffer_copy(sock->inbuf);
	packet->server = server;
	packet->sock = sock;
	if (srvr) {
	  packet->cipher = srvr->receive_key;
	  packet->hmac = srvr->hmac;
	}
	silc_buffer_clear(sock->inbuf);
	
	/* The packet is ready to be parsed now. However, this is a client 
	   connection so we will parse the packet with timeout. */
	silc_task_register(server->timeout_queue, fd, 
			   silc_server_packet_parse,
			   (void *)packet, 0, 1, 
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
	return;
      }
    }

    /* Decrypt a packet coming from client. */
    if (sock->type == SILC_SOCKET_TYPE_UNKNOWN) {
      SilcIDListUnknown *conn_data = (SilcIDListUnknown *)sock->user_data;
      SilcServerInternalPacket *packet;
      
      SILC_LOG_HEXDUMP(("Incoming packet, len %d", sock->inbuf->len),
		       sock->inbuf->data, sock->inbuf->len);

      SILC_LOG_DEBUG(("Packet from unknown connection, length %d", 
		      paddedlen));

      packet = silc_calloc(1, sizeof(*packet));
      packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
      packet->packetdata->buffer = silc_buffer_copy(sock->inbuf);
      packet->server = server;
      packet->sock = sock;
      if (conn_data) {
	packet->cipher = conn_data->receive_key;
	packet->hmac = conn_data->hmac;
      }

      silc_buffer_clear(sock->inbuf);

      /* The packet is ready to be parsed now. However, this is unknown 
	 connection so we will parse the packet with timeout. */
      silc_task_register(server->timeout_queue, fd, 
			 silc_server_packet_parse,
			 (void *)packet, 0, 100000, 
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
      return;
    }
  }

  SILC_LOG_ERROR(("Weird, nothing happened - ignoring"));
}

/* Checks MAC in the packet. Returns TRUE if MAC is Ok. This is called
   after packet has been totally decrypted and parsed. */

static int silc_server_packet_check_mac(SilcServer server,
					SilcSocketConnection sock,
					SilcBuffer buffer)
{
  SilcHmac hmac = NULL;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned int mac_len = 0;

  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (sock->user_data) {
      hmac = ((SilcClientList *)sock->user_data)->hmac;
      hmac_key = ((SilcClientList *)sock->user_data)->hmac_key;
      hmac_key_len = ((SilcClientList *)sock->user_data)->hmac_key_len;
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (sock->user_data) {
      hmac = ((SilcServerList *)sock->user_data)->hmac;
      hmac_key = ((SilcServerList *)sock->user_data)->hmac_key;
      hmac_key_len = ((SilcServerList *)sock->user_data)->hmac_key_len;
    }
    break;
  default:
    if (sock->user_data) {
      hmac = ((SilcIDListUnknown *)sock->user_data)->hmac;
      hmac_key = ((SilcIDListUnknown *)sock->user_data)->hmac_key;
      hmac_key_len = ((SilcIDListUnknown *)sock->user_data)->hmac_key_len;
    }
  }

  /* Check MAC */
  if (hmac) {
    int headlen = buffer->data - buffer->head;
    unsigned char *packet_mac, mac[32];
    
    SILC_LOG_DEBUG(("Verifying MAC"));

    mac_len = hmac->hash->hash->hash_len;

    silc_buffer_push(buffer, headlen);
    
    /* Take mac from packet */
    packet_mac = buffer->tail;
    
    /* Make MAC and compare */
    memset(mac, 0, sizeof(mac));
    silc_hmac_make_with_key(hmac, 
			    buffer->data, buffer->len,
			    hmac_key, hmac_key_len, mac);
#if 0
    SILC_LOG_HEXDUMP(("PMAC"), packet_mac, mac_len);
    SILC_LOG_HEXDUMP(("CMAC"), mac, mac_len);
#endif
    if (memcmp(mac, packet_mac, mac_len)) {
      SILC_LOG_DEBUG(("MAC failed"));
      return FALSE;
    }
    
    SILC_LOG_DEBUG(("MAC is Ok"));
    memset(mac, 0, sizeof(mac));

    silc_buffer_pull(buffer, headlen);
  }
  
  return TRUE;
}

/* Decrypts rest of the packet (after decrypting just the SILC header).
   After calling this function the packet is ready to be parsed by calling 
   silc_packet_parse. */

static int silc_server_packet_decrypt_rest(SilcServer server, 
					   SilcSocketConnection sock,
					   SilcBuffer buffer)
{
  SilcCipher session_key = NULL;
  SilcHmac hmac = NULL;
  unsigned int mac_len = 0;

  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (sock->user_data) {
      session_key = ((SilcClientList *)sock->user_data)->receive_key;
      hmac = ((SilcClientList *)sock->user_data)->hmac;
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (sock->user_data) {
      session_key = ((SilcServerList *)sock->user_data)->receive_key;
      hmac = ((SilcServerList *)sock->user_data)->hmac;
    }
    break;
  default:
    if (sock->user_data) {
      session_key = ((SilcIDListUnknown *)sock->user_data)->receive_key;
      hmac = ((SilcIDListUnknown *)sock->user_data)->hmac;
    }
  }
  
  /* Decrypt */
  if (session_key) {

    /* Pull MAC from packet before decryption */
    if (hmac) {
      mac_len = hmac->hash->hash->hash_len;
      if ((buffer->len - mac_len) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, mac_len);
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }

    SILC_LOG_DEBUG(("Decrypting rest of the packet"));

    /* Decrypt rest of the packet */
    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    silc_packet_decrypt(session_key, buffer, buffer->len);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);

    SILC_LOG_HEXDUMP(("Fully decrypted packet, len %d", buffer->len),
		     buffer->data, buffer->len);
  }

  return TRUE;
}

/* Decrypts rest of the SILC Packet header that has been decrypted partly
   already. This decrypts the padding of the packet also.  After calling 
   this function the packet is ready to be parsed by calling function 
   silc_packet_parse. */

static int silc_server_packet_decrypt_rest_special(SilcServer server, 
						   SilcSocketConnection sock,
						   SilcBuffer buffer)
{
  SilcCipher session_key = NULL;
  SilcHmac hmac = NULL;
  unsigned int mac_len = 0;

  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (sock->user_data) {
      session_key = ((SilcClientList *)sock->user_data)->receive_key;
      hmac = ((SilcClientList *)sock->user_data)->hmac;
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (sock->user_data) {
      session_key = ((SilcServerList *)sock->user_data)->receive_key;
      hmac = ((SilcServerList *)sock->user_data)->hmac;
    }
    break;
  default:
    if (sock->user_data) {
      session_key = ((SilcIDListUnknown *)sock->user_data)->receive_key;
      hmac = ((SilcIDListUnknown *)sock->user_data)->hmac;
    }
  }
  
  /* Decrypt rest of the header plus padding */
  if (session_key) {
    unsigned short truelen, len1, len2, padlen;

    /* Pull MAC from packet before decryption */
    if (hmac) {
      mac_len = hmac->hash->hash->hash_len;
      if ((buffer->len - mac_len) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, mac_len);
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }
  
    SILC_LOG_DEBUG(("Decrypting rest of the header"));

    SILC_GET16_MSB(len1, &buffer->data[4]);
    SILC_GET16_MSB(len2, &buffer->data[6]);

    truelen = SILC_PACKET_HEADER_LEN + len1 + len2;
    padlen = SILC_PACKET_PADLEN(truelen);
    len1 = (truelen + padlen) - (SILC_PACKET_MIN_HEADER_LEN - 2);

    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    silc_packet_decrypt(session_key, buffer, len1);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
  }

  return TRUE;
}

/* Parses whole packet, received earlier. This packet is usually received
   from client. */

SILC_TASK_CALLBACK(silc_server_packet_parse)
{
  SilcServerInternalPacket *packet = (SilcServerInternalPacket *)context;
  SilcServer server = packet->server;
  SilcSocketConnection sock = packet->sock;
  SilcBuffer buffer = packet->packetdata->buffer;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Decrypt start of the packet header */
  if (packet->cipher)
    silc_packet_decrypt(packet->cipher, buffer, SILC_PACKET_MIN_HEADER_LEN);

  /* If the packet type is not any special type lets decrypt rest
     of the packet here. */
  if (buffer->data[3] != SILC_PACKET_CHANNEL_MESSAGE &&
      buffer->data[3] != SILC_PACKET_PRIVATE_MESSAGE) {
  normal:
    /* Normal packet, decrypt rest of the packet */
    if (!silc_server_packet_decrypt_rest(server, sock, buffer))
      goto out;

    /* Parse the packet. Packet type is returned. */
    ret = silc_packet_parse(packet->packetdata);
    if (ret == SILC_PACKET_NONE)
      goto out;

    /* Check MAC */
    if (!silc_server_packet_check_mac(server, sock, buffer))
      goto out;
  } else {
    /* If private message key is not set for private message it is
       handled as normal packet. Go back up. */
    if (buffer->data[3] == SILC_PACKET_PRIVATE_MESSAGE &&
	!(buffer->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
      goto normal;

    /* Packet requires special handling, decrypt rest of the header.
       This only decrypts. This does not do any MAC checking, it must
       be done individually later when doing the special processing. */
    silc_server_packet_decrypt_rest_special(server, sock, buffer);

    /* Parse the packet header in special way as this is "special"
       packet type. */
    ret = silc_packet_parse_special(packet->packetdata);
    if (ret == SILC_PACKET_NONE)
      goto out;
  }
  
  /* Parse the incoming packet type */
  silc_server_packet_parse_type(server, sock, packet->packetdata);

 out:
  silc_buffer_clear(sock->inbuf);
  //  silc_buffer_free(packetdata->packetdata->buffer);
  silc_free(packet->packetdata);
  silc_free(packet);
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
    SILC_LOG_DEBUG(("Failure packet"));
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
    {
      /*
       * Recived command. Allocate command context and execute the command.
       */
      SilcServerCommandContext ctx;

      SILC_LOG_DEBUG(("Command packet"));

      /* Router cannot send command packet */
      if (sock->type == SILC_SOCKET_TYPE_ROUTER)
	break;

      /* Allocate command context. This must be free'd by the
	 command routine receiving it. */
      ctx = silc_calloc(1, sizeof(*ctx));
      ctx->server = server;
      ctx->sock = sock;
      ctx->packet = packet;	/* Save original packet */

      /* Parse the command payload in the packet */
      ctx->payload = silc_command_parse_payload(buffer);
      if (!ctx->payload) {
	SILC_LOG_ERROR(("Bad command payload, packet dropped"));
	silc_free(ctx);
	return;
      }

      /* Execute command. If this fails the packet is dropped. */
      SILC_SERVER_COMMAND_EXEC(ctx);
      silc_buffer_free(buffer);
    }
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
     * information that we may save. This is after server as connected to us.
     */
    SILC_LOG_DEBUG(("New Server packet"));
    silc_server_new_server(server, sock, packet);
    break;

  default:
    SILC_LOG_ERROR(("Incorrect packet type %d, packet dropped", type));
    break;
  }
  
}

/* Internal routine that sends packet or marks packet to be sent. This
   is used directly only in special cases. Normal cases should use
   silc_server_packet_send. Returns < 0 error. */

static int silc_server_packet_send_real(SilcServer server,
					SilcSocketConnection sock,
					int force_send)
{
  /* Send now if forced to do so */
  if (force_send == TRUE) {
    int ret;
    SILC_LOG_DEBUG(("Forcing packet send, packet sent immediately"));
    ret = silc_packet_write(sock->sock, sock->outbuf);

    silc_buffer_clear(sock->outbuf);

    if (ret == -1)
      SILC_LOG_ERROR(("Could not write, packet dropped"));
    if (ret != -2) {
      silc_buffer_clear(sock->outbuf);
      return ret;
    }

    SILC_LOG_DEBUG(("Could not force the send, packet put to queue"));
  }  

  SILC_LOG_DEBUG(("Packet in queue"));

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

/* Prepare outgoing data buffer for packet sending. This is internal
   routine and must always be called before sending any packets out. */

static void silc_server_packet_send_prepare(SilcServer server, 
					    SilcSocketConnection sock,
					    unsigned int header_len,
					    unsigned int padlen,
					    unsigned int data_len)
{
  int totlen, oldlen;

  totlen = header_len + padlen + data_len;

  /* Prepare the outgoing buffer for packet sending. */
  if (!sock->outbuf) {
    /* Allocate new buffer. This is done only once per connection. */
    SILC_LOG_DEBUG(("Allocating outgoing data buffer"));
    
    sock->outbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);
    silc_buffer_pull_tail(sock->outbuf, totlen);
    silc_buffer_pull(sock->outbuf, header_len + padlen);
  } else {
    if (SILC_IS_OUTBUF_PENDING(sock)) {
      /* There is some pending data in the buffer. */

      if ((sock->outbuf->end - sock->outbuf->tail) < data_len) {
	SILC_LOG_DEBUG(("Reallocating outgoing data buffer"));
	/* XXX: not done yet */
      }
      oldlen = sock->outbuf->len;
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen + oldlen);
    } else {
      /* Buffer is free for use */
      silc_buffer_clear(sock->outbuf);
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen);
    }
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

  /* Get data used in the packet sending, keys and stuff */
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (((SilcClientList *)sock->user_data)->id) {
      dst_id = ((SilcClientList *)sock->user_data)->id;
      dst_id_type = SILC_ID_CLIENT;
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (((SilcServerList *)sock->user_data)->id) {
      dst_id = ((SilcServerList *)sock->user_data)->id;
      dst_id_type = SILC_ID_SERVER;
    }
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
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;
  unsigned char *dst_id_data = NULL;
  unsigned int dst_id_len = 0;

  SILC_LOG_DEBUG(("Sending packet, type %d", type));

  /* Get data used in the packet sending, keys and stuff */
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (sock->user_data) {
      cipher = ((SilcClientList *)sock->user_data)->send_key;
      hmac = ((SilcClientList *)sock->user_data)->hmac;
      if (hmac) {
	mac_len = hmac->hash->hash->hash_len;
	hmac_key = ((SilcClientList *)sock->user_data)->hmac_key;
	hmac_key_len = ((SilcClientList *)sock->user_data)->hmac_key_len;
      }
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (sock->user_data) {
      cipher = ((SilcServerList *)sock->user_data)->send_key;
      hmac = ((SilcServerList *)sock->user_data)->hmac;
      if (hmac) {
	mac_len = hmac->hash->hash->hash_len;
	hmac_key = ((SilcServerList *)sock->user_data)->hmac_key;
	hmac_key_len = ((SilcServerList *)sock->user_data)->hmac_key_len;
      }
    }
    break;
  default:
    if (sock->user_data) {
      /* We don't know what type of connection this is thus it must
	 be in authentication phase. */
      cipher = ((SilcIDListUnknown *)sock->user_data)->send_key;
      hmac = ((SilcIDListUnknown *)sock->user_data)->hmac;
      if (hmac) {
	mac_len = hmac->hash->hash->hash_len;
	hmac_key = ((SilcIDListUnknown *)sock->user_data)->hmac_key;
	hmac_key_len = ((SilcIDListUnknown *)sock->user_data)->hmac_key_len;
      }
    }
    break;
  }

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
  silc_server_packet_send_prepare(server, sock, 
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

  /* Compute MAC of the packet */
  if (hmac) {
    silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			    hmac_key, hmac_key_len, mac);
    silc_buffer_put_tail(sock->outbuf, mac, mac_len);
    memset(mac, 0, sizeof(mac));
  }

  /* Encrypt the packet */
  if (cipher)
    silc_packet_encrypt(cipher, sock->outbuf, sock->outbuf->len);

  /* Pull MAC into the visible data area */
  if (hmac)
    silc_buffer_pull_tail(sock->outbuf, mac_len);

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
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;

  SILC_LOG_DEBUG(("Forwarding packet"));

  /* Get data used in the packet sending, keys and stuff */
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (sock->user_data) {
      cipher = ((SilcClientList *)sock->user_data)->send_key;
      hmac = ((SilcClientList *)sock->user_data)->hmac;
      if (hmac) {
	mac_len = hmac->hash->hash->hash_len;
	hmac_key = ((SilcClientList *)sock->user_data)->hmac_key;
	hmac_key_len = ((SilcClientList *)sock->user_data)->hmac_key_len;
      }
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (sock->user_data) {
      cipher = ((SilcServerList *)sock->user_data)->send_key;
      hmac = ((SilcServerList *)sock->user_data)->hmac;
      if (hmac) {
	mac_len = hmac->hash->hash->hash_len;
	hmac_key = ((SilcServerList *)sock->user_data)->hmac_key;
	hmac_key_len = ((SilcServerList *)sock->user_data)->hmac_key_len;
      }
    }
    break;
  default:
    /* We won't forward to unknown destination - keys must exist with
       the destination before forwarding. */
    return;
  }

  /* Prepare outgoing data buffer for packet sending */
  silc_server_packet_send_prepare(server, sock, 0, 0, data_len);

  /* Mungle the packet flags and add the FORWARDED flag */
  if (data)
    data[2] |= (unsigned char)SILC_PACKET_FLAG_FORWARDED;

  /* Put the data to the buffer */
  if (data && data_len)
    silc_buffer_put(sock->outbuf, data, data_len);

  /* Compute MAC of the packet */
  if (hmac) {
    silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			    hmac_key, hmac_key_len, mac);
    silc_buffer_put_tail(sock->outbuf, mac, mac_len);
    memset(mac, 0, sizeof(mac));
  }

  /* Encrypt the packet */
  if (cipher)
    silc_packet_encrypt(cipher, sock->outbuf, sock->outbuf->len);

  /* Pull MAC into the visible data area */
  if (hmac)
    silc_buffer_pull_tail(sock->outbuf, mac_len);

  SILC_LOG_HEXDUMP(("Forwarded packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);
}

/* This routine is used by the server to send packets to channel. The 
   packet sent with this function is distributed to all clients on
   the channel. Usually this is used to send notify messages to the
   channel, things like notify about new user joining to the channel. */

void silc_server_packet_send_to_channel(SilcServer server,
					SilcChannelList *channel,
					unsigned char *data,
					unsigned int data_len,
					int force_send)
{
  int i;
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientList *client = NULL;
  SilcServerList **routed = NULL;
  unsigned int routed_count = 0;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;
  SilcCipher cipher;
  SilcHmac hmac;
  SilcBuffer payload;

  SILC_LOG_DEBUG(("Sending packet to channel"));

  /* Generate IV */
  for (i = 0; i < 16; i++)
    channel->iv[i] = silc_rng_get_byte(server->rng);

  /* Encode the channel payload */
  payload = silc_channel_encode_payload(0, "", data_len, data, 
					16, channel->iv, server->rng);
  if (!payload)
    return;
  
  /* Encrypt payload of the packet. This is encrypted with the 
     channel key. */
  channel->channel_key->cipher->encrypt(channel->channel_key->context,
					payload->data, payload->data,
					payload->len - 16, /* -IV_LEN */
					channel->iv);

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_CHANNEL_MESSAGE;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = SILC_ID_SERVER;
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
    SilcServerList *router;

    /* Get data used in packet header encryption, keys and stuff. */
    router = server->id_entry->router;
    sock = (SilcSocketConnection)router->connection;
    cipher = router->send_key;
    hmac = router->hmac;
    mac_len = hmac->hash->hash->hash_len;
    hmac_key = router->hmac_key;
    hmac_key_len = router->hmac_key_len;
    
    SILC_LOG_DEBUG(("Sending packet to router for routing"));

    packetdata.truelen = payload->len + SILC_PACKET_HEADER_LEN + 
      packetdata.src_id_len + packetdata.dst_id_len;

    /* Prepare outgoing data buffer for packet sending */
    silc_server_packet_send_prepare(server, sock, 
				    SILC_PACKET_HEADER_LEN +
				    packetdata.src_id_len + 
				    packetdata.dst_id_len,
				    packetdata.padlen,
				    payload->len);
    packetdata.buffer = sock->outbuf;

    /* Put the original packet into the buffer. */
    silc_buffer_put(sock->outbuf, payload->data, payload->len);
    
    /* Create the outgoing packet */
    silc_packet_assemble(&packetdata);
    
    /* Compute MAC of the packet. MAC is computed from the header,
       padding and the relayed packet. */
    silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			    hmac_key, hmac_key_len, mac);
    silc_buffer_put_tail(sock->outbuf, mac, mac_len);
    memset(mac, 0, sizeof(mac));

    /* Encrypt the header and padding of the packet. This is encrypted 
       with normal session key shared with the client. */
    silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			packetdata.src_id_len + packetdata.dst_id_len +
			packetdata.padlen);
    
    /* Pull MAC into the visible data area */
    silc_buffer_pull_tail(sock->outbuf, mac_len);
    
    SILC_LOG_HEXDUMP(("Channel packet, len %d", sock->outbuf->len),
		     sock->outbuf->data, sock->outbuf->len);

    /* Now actually send the packet */
    silc_server_packet_send_real(server, sock, force_send);
  }

  /* Send the message to clients on the channel's client list. */
  for (i = 0; i < channel->user_list_count; i++) {
    client = channel->user_list[i].client;

    /* If client has router set it is not locally connected client and
       we will route the message to the router set in the client. */
    if (client && client->router && server->server_type == SILC_ROUTER) {
      int k;

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  continue;

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->router->connection;
      cipher = client->router->send_key;
      hmac = client->router->hmac;
      mac_len = hmac->hash->hash->hash_len;
      hmac_key = client->router->hmac_key;
      hmac_key_len = client->router->hmac_key_len;
      
      packetdata.truelen = payload->len + SILC_PACKET_HEADER_LEN + 
	packetdata.src_id_len + packetdata.dst_id_len;

      /* Prepare outgoing data buffer for packet sending */
      silc_server_packet_send_prepare(server, sock, 
				      SILC_PACKET_HEADER_LEN +
				      packetdata.src_id_len + 
				      packetdata.dst_id_len,
				      packetdata.padlen,
				      payload->len);
      packetdata.buffer = sock->outbuf;

      /* Put the encrypted payload data into the buffer. */
      silc_buffer_put(sock->outbuf, payload->data, payload->len);
      
      /* Create the outgoing packet */
      silc_packet_assemble(&packetdata);
      
      /* Compute MAC of the packet. MAC is computed from the header,
	 padding and the relayed packet. */
      silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			      hmac_key, hmac_key_len, mac);
      silc_buffer_put_tail(sock->outbuf, mac, mac_len);
      memset(mac, 0, sizeof(mac));

      /* Encrypt the header and padding of the packet. This is encrypted 
	 with normal session key shared with the client. */
      silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			  packetdata.src_id_len + packetdata.dst_id_len +
			  packetdata.padlen);
      
      /* Pull MAC into the visible data area */
      silc_buffer_pull_tail(sock->outbuf, mac_len);
      
      SILC_LOG_HEXDUMP(("Packet to channel, len %d", sock->outbuf->len),
		       sock->outbuf->data, sock->outbuf->len);

      /* Now actually send the packet */
      silc_server_packet_send_real(server, sock, force_send);

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

      /* XXX Check client's mode on the channel. */

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->connection;
      cipher = client->send_key;
      hmac = client->hmac;
      mac_len = hmac->hash->hash->hash_len;
      hmac_key = client->hmac_key;
      hmac_key_len = client->hmac_key_len;
      
      packetdata.truelen = payload->len + SILC_PACKET_HEADER_LEN + 
	packetdata.src_id_len + packetdata.dst_id_len;

      /* Prepare outgoing data buffer for packet sending */
      silc_server_packet_send_prepare(server, sock, 
				      SILC_PACKET_HEADER_LEN +
				      packetdata.src_id_len + 
				      packetdata.dst_id_len,
				      packetdata.padlen,
				      payload->len);
      packetdata.buffer = sock->outbuf;

      /* Put the encrypted payload data into the buffer. */
      silc_buffer_put(sock->outbuf, payload->data, payload->len);
      
      /* Create the outgoing packet */
      silc_packet_assemble(&packetdata);
      
      /* Compute MAC of the packet. MAC is computed from the header,
	 padding and the relayed packet. */
      silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			      hmac_key, hmac_key_len, mac);
      silc_buffer_put_tail(sock->outbuf, mac, mac_len);
      memset(mac, 0, sizeof(mac));

      /* Encrypt the header and padding of the packet. This is encrypted 
	 with normal session key shared with the client. */
      silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			  packetdata.src_id_len + packetdata.dst_id_len +
			  packetdata.padlen);
      
      /* Pull MAC into the visible data area */
      silc_buffer_pull_tail(sock->outbuf, mac_len);
      
      SILC_LOG_HEXDUMP(("Packet to channel, len %d", sock->outbuf->len),
		       sock->outbuf->data, sock->outbuf->len);

      /* Now actually send the packet */
      silc_server_packet_send_real(server, sock, force_send);
    }
  }

  if (routed_count)
    silc_free(routed);
  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
  silc_buffer_free(payload);
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
					 SilcChannelList *channel,
					 void *sender, 
					 SilcIdType sender_type,
					 unsigned char *data,
					 unsigned int data_len,
					 int force_send)
{
  int i, found = FALSE;
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientList *client = NULL;
  SilcServerList **routed = NULL;
  unsigned int routed_count = 0;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;
  SilcCipher cipher;
  SilcHmac hmac;

  SILC_LOG_DEBUG(("Relaying packet to channel"));

  SILC_LOG_HEXDUMP(("XXX %d", data_len), data, data_len);

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
    SilcServerList *router;

    router = server->id_entry->router;

    /* Check that the sender is not our router. */
    if (sender_sock != (SilcSocketConnection)router->connection) {

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)router->connection;
      cipher = router->send_key;
      hmac = router->hmac;
      mac_len = hmac->hash->hash->hash_len;
      hmac_key = router->hmac_key;
      hmac_key_len = router->hmac_key_len;
      
      SILC_LOG_DEBUG(("Sending packet to router for routing"));
      
      packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	packetdata.src_id_len + packetdata.dst_id_len;
      
      /* Prepare outgoing data buffer for packet sending */
      silc_server_packet_send_prepare(server, sock, 
				      SILC_PACKET_HEADER_LEN +
				      packetdata.src_id_len + 
				      packetdata.dst_id_len,
				      packetdata.padlen,
				      data_len);
      packetdata.buffer = sock->outbuf;
      
      /* Put the original packet into the buffer. */
      silc_buffer_put(sock->outbuf, data, data_len);
      
      /* Create the outgoing packet */
      silc_packet_assemble(&packetdata);
      
      /* Compute MAC of the packet. MAC is computed from the header,
	 padding and the relayed packet. */
      silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			      hmac_key, hmac_key_len, mac);
      silc_buffer_put_tail(sock->outbuf, mac, mac_len);
      memset(mac, 0, sizeof(mac));
      
      /* Encrypt the header and padding of the packet. This is encrypted 
	 with normal session key shared with the client. */
      silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			  packetdata.src_id_len + packetdata.dst_id_len +
			  packetdata.padlen);
      
      /* Pull MAC into the visible data area */
      silc_buffer_pull_tail(sock->outbuf, mac_len);
      
      SILC_LOG_HEXDUMP(("Channel packet, len %d", sock->outbuf->len),
		       sock->outbuf->data, sock->outbuf->len);
      
      /* Now actually send the packet */
      silc_server_packet_send_real(server, sock, force_send);
    }
  }

  /* Send the message to clients on the channel's client list. */
  for (i = 0; i < channel->user_list_count; i++) {
    client = channel->user_list[i].client;

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
	    continue;
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)client->router->connection;
	cipher = client->router->send_key;
	hmac = client->router->hmac;
	mac_len = hmac->hash->hash->hash_len;
	hmac_key = client->router->hmac_key;
	hmac_key_len = client->router->hmac_key_len;
	
	packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	  packetdata.src_id_len + packetdata.dst_id_len;
	
	/* Prepare outgoing data buffer for packet sending */
	silc_server_packet_send_prepare(server, sock, 
					SILC_PACKET_HEADER_LEN +
					packetdata.src_id_len + 
					packetdata.dst_id_len,
					packetdata.padlen,
					data_len);
	packetdata.buffer = sock->outbuf;
	
	/* Put the original packet into the buffer. */
	silc_buffer_put(sock->outbuf, data, data_len);
	
	/* Create the outgoing packet */
	silc_packet_assemble(&packetdata);
	
	/* Compute MAC of the packet. MAC is computed from the header,
	   padding and the relayed packet. */
	silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
				hmac_key, hmac_key_len, mac);
	silc_buffer_put_tail(sock->outbuf, mac, mac_len);
	memset(mac, 0, sizeof(mac));
	
	/* Encrypt the header and padding of the packet. This is encrypted 
	   with normal session key shared with the client. */
	silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			    packetdata.src_id_len + packetdata.dst_id_len +
			    packetdata.padlen);
	
	/* Pull MAC into the visible data area */
	silc_buffer_pull_tail(sock->outbuf, mac_len);
	
	SILC_LOG_HEXDUMP(("Packet to channel, len %d", sock->outbuf->len),
			 sock->outbuf->data, sock->outbuf->len);
	
	/* Now actually send the packet */
	silc_server_packet_send_real(server, sock, force_send);
	
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
      cipher = client->send_key;
      hmac = client->hmac;
      mac_len = hmac->hash->hash->hash_len;
      hmac_key = client->hmac_key;
      hmac_key_len = client->hmac_key_len;
      
      SILC_LOG_DEBUG(("Sending packet to client %s", 
		      sock->hostname ? sock->hostname : sock->ip));

      packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	packetdata.src_id_len + packetdata.dst_id_len;

      /* Prepare outgoing data buffer for packet sending */
      silc_server_packet_send_prepare(server, sock, 
				      SILC_PACKET_HEADER_LEN +
				      packetdata.src_id_len + 
				      packetdata.dst_id_len,
				      packetdata.padlen,
				      data_len);
      packetdata.buffer = sock->outbuf;

      /* Put the original packet into the buffer. */
      silc_buffer_put(sock->outbuf, data, data_len);
      
      /* Create the outgoing packet */
      silc_packet_assemble(&packetdata);
      
      /* Compute MAC of the packet. MAC is computed from the header,
	 padding and the relayed packet. */
      silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			      hmac_key, hmac_key_len, mac);
      silc_buffer_put_tail(sock->outbuf, mac, mac_len);
      memset(mac, 0, sizeof(mac));

      /* Encrypt the header and padding of the packet. This is encrypted 
	 with normal session key shared with the client. */
      silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			  packetdata.src_id_len + packetdata.dst_id_len +
			  packetdata.padlen);
      
      /* Pull MAC into the visible data area */
      silc_buffer_pull_tail(sock->outbuf, mac_len);
      
      SILC_LOG_HEXDUMP(("Channel packet, len %d", sock->outbuf->len),
		       sock->outbuf->data, sock->outbuf->len);

      /* Now actually send the packet */
      silc_server_packet_send_real(server, sock, force_send);
    }
  }

  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
}

/* This function is used to send packets strictly to all local clients
   on a particular channel.  This is used for example to distribute new
   channel key to all our locally connected clients on the channel. 
   The packets are always encrypted with the session key shared between
   the client. */

void silc_server_packet_send_local_channel(SilcServer server,
					   SilcChannelList *channel,
					   SilcPacketType type,
					   SilcPacketFlags flags,
					   unsigned char *data,
					   unsigned int data_len,
					   int force_send)
{
  int i;
  SilcClientList *client;
  SilcSocketConnection sock = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Send the message to clients on the channel's client list. */
  for (i = 0; i < channel->user_list_count; i++) {
    client = channel->user_list[i].client;

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
  SilcClientList *client;
  SilcClientID *id;
  SilcSocketConnection dst_sock;
  unsigned char mac[32];
  unsigned int mac_len = 0;

  SILC_LOG_DEBUG(("Start"));

  /* Source must be server or router */
  /* XXX: actually it must be only router */
  if (packet->src_id_type != SILC_ID_SERVER &&
      (sock->type != SILC_SOCKET_TYPE_SERVER ||
       sock->type != SILC_SOCKET_TYPE_ROUTER))
    goto out;

  /* Destination must be client */
  if (packet->dst_id_type != SILC_ID_CLIENT)
    goto out;

  /* Execute command reply locally for the command */
  silc_server_command_reply_process(server, sock, buffer);

  id = silc_id_str2id(packet->dst_id, SILC_ID_CLIENT);

  /* Destination must be one of ours */
  client = silc_idlist_find_client_by_id(server->local_list->clients, id);
  if (!client) {
    silc_free(id);
    goto out;
  }

  /* Relay the packet to the client */
  if (client->hmac)
    mac_len = client->hmac->hash->hash->hash_len;

  dst_sock = (SilcSocketConnection)client->connection;

  silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		   + packet->dst_id_len + packet->padlen);
  silc_server_packet_send_prepare(server, dst_sock, 0, 0, buffer->len);
  silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
  
  /* Compute new HMAC */
  if (client->hmac) {
    memset(mac, 0, sizeof(mac));
    silc_hmac_make_with_key(client->hmac, 
			    dst_sock->outbuf->data, 
			    dst_sock->outbuf->len,
			    client->hmac_key, 
			    client->hmac_key_len, 
			    mac);
    silc_buffer_put_tail(dst_sock->outbuf, mac, mac_len);
    memset(mac, 0, sizeof(mac));
  }
    
  /* Encrypt */
  if (client && client->send_key)
    silc_packet_encrypt(client->send_key, dst_sock->outbuf, buffer->len);
    
  if (client->hmac)
    silc_buffer_pull_tail(dst_sock->outbuf, mac_len);
    
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
   pointer maybe anything we wil switch here to find the corrent
   data type and free it the way it needs to be free'd. */

void silc_server_free_sock_user_data(SilcServer server, 
				     SilcSocketConnection sock)
{
  SILC_LOG_DEBUG(("Start"));

#define LCC(x) server->local_list->client_cache[(x) - 32]
#define LCCC(x) server->local_list->client_cache_count[(x) - 32]

  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientList *user_data = (SilcClientList *)sock->user_data;

      /* Remove client from all channels */
      silc_server_remove_from_channels(server, sock, user_data);

      /* Clear ID cache */
      if (user_data->nickname && user_data->id)
	silc_idcache_del_by_id(LCC(user_data->nickname[0]),
			       LCCC(user_data->nickname[0]),
			       SILC_ID_CLIENT, user_data->id);

      /* Free the client entry and everything in it */
      /* XXX must take some info to history before freeing */
      silc_idlist_del_client(&server->local_list->clients, user_data);
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
      SilcIDListUnknown *user_data = (SilcIDListUnknown *)sock->user_data;

      if (user_data->send_key)
	silc_cipher_free(user_data->send_key);
      if (user_data->receive_key)
	silc_cipher_free(user_data->receive_key);
      if (user_data->pkcs)
	silc_pkcs_free(user_data->pkcs);
      if (user_data->hmac) {
	silc_hmac_free(user_data->hmac);
	memset(user_data->hmac_key, 0, user_data->hmac_key_len);
	silc_free(user_data->hmac_key);
      }
      silc_free(user_data);
      break;
    }
  }

  sock->user_data = NULL;
#undef LCC
#undef LCCC
}

/* Removes client from all channels it has joined. This is used when
   client connection is disconnected. If the client on a channel
   is last, the channel is removed as well. */

void silc_server_remove_from_channels(SilcServer server, 
				      SilcSocketConnection sock,
				      SilcClientList *client)
{
  int i, k;
  SilcChannelList *channel;

#define LCC(x) server->local_list->channel_cache[(x) - 32]
#define LCCC(x) server->local_list->channel_cache_count[(x) - 32]

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  for (i = 0; i < client->channel_count; i++) {
    channel = client->channel[i];
    if (!channel)
      continue;

    /* Remove from channel */
    for (k = 0; k < channel->user_list_count; k++) {
      if (channel->user_list[k].client == client) {

	/* If this client is last one on the channel the channel
	   is removed all together. */
	if (channel->user_list_count == 1) {
	  silc_idcache_del_by_id(LCC(channel->channel_name[0]),
				 LCCC(channel->channel_name[0]),
				 SILC_ID_CHANNEL, channel->id);
	  silc_idlist_del_channel(&server->local_list->channels, channel);
	  break;
	}

	channel->user_list[k].client = NULL;
	channel->user_list[k].mode = SILC_CHANNEL_UMODE_NONE;

	/* Send notify to channel about client leaving SILC and thus
	   the entire channel. */
	silc_server_send_notify_to_channel(server, channel,
					   "Signoff: %s",
					   client->nickname);
      }
    }
  }

  if (client->channel_count)
    silc_free(client->channel);
  client->channel = NULL;
#undef LCC
#undef LCCC
}

/* Removes client from one channel. This is used for example when client
   calls LEAVE command to remove itself from the channel. Returns TRUE
   if channel still exists and FALSE if the channel is removed when
   last client leaves the channel. */

int silc_server_remove_from_one_channel(SilcServer server, 
					SilcSocketConnection sock,
					SilcChannelList *channel,
					SilcClientList *client)
{
  int i, k;
  SilcChannelList *ch;

#define LCC(x) server->local_list->channel_cache[(x) - 32]
#define LCCC(x) server->local_list->channel_cache_count[(x) - 32]

  /* Remove the client from the channel. The client is removed from
     the channel's user list. */
  for (i = 0; i < client->channel_count; i++) {
    ch = client->channel[i];
    if (!ch || ch != channel)
      continue;

    /* XXX */
    client->channel[i] = NULL;

    /* Remove from channel */
    for (k = 0; k < channel->user_list_count; k++) {
      if (channel->user_list[k].client == client) {
	
	/* If this client is last one on the channel the channel
	   is removed all together. */
	if (channel->user_list_count == 1) {
	  silc_idcache_del_by_id(LCC(channel->channel_name[0]),
				 LCCC(channel->channel_name[0]),
				 SILC_ID_CHANNEL, channel->id);
	  silc_idlist_del_channel(&server->local_list->channels, channel);
	  return FALSE;
	}
	
	channel->user_list[k].client = NULL;
	channel->user_list[k].mode = SILC_CHANNEL_UMODE_NONE;

	/* Send notify to channel about client leaving the channel */
	silc_server_send_notify_to_channel(server, channel,
					   "%s has left channel %s",
					   client->nickname,
					   channel->channel_name);
      }
    }
  }

  return TRUE;
#undef LCC
#undef LCCC
}

/* Returns TRUE if the given client is on the channel.  FALSE if not. 
   This works because we assure that the user list on the channel is
   always in up to date thus we can only check the channel list from 
   `client' which is faster than checking the user list from `channel'. */
/* XXX This really is utility function and should be in eg. serverutil.c */

int silc_server_client_on_channel(SilcClientList *client,
				  SilcChannelList *channel)
{
  int i;

  if (!client || !channel)
    return FALSE;

  for (i = 0; i < client->channel_count; i++) {
    if (client->channel[i] == channel)
      return TRUE;
  }

  return FALSE;
}

/* Timeout callback. This is called if connection is idle or for some
   other reason is not responding within some period of time. This 
   disconnects the remote end. */

SILC_TASK_CALLBACK(silc_server_timeout_remote)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = server->sockets[fd];

  silc_server_disconnect_remote(server, sock, 
				"Server closed connection: "
				"Connection timeout");
}

/* Internal routine used to send (relay, route) private messages to some
   destination. This is used to by normal server to send the message to
   its primary route and router uses this to send it to any route it
   wants. If the private message key does not exist then the message
   is re-encrypted, otherwise we just pass it along. */
static void 
silc_server_private_message_send_internal(SilcServer server,
					  SilcSocketConnection dst_sock,
					  SilcServerList *router,
					  SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;

  /* Send and re-encrypt if private messge key does not exist */
  if ((packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY) == FALSE) {
    unsigned char mac[32];
    unsigned int mac_len = 0;
    
    if (router->hmac)
      mac_len = router->hmac->hash->hash->hash_len;
    
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_server_packet_send_prepare(server, dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    
    /* Compute new HMAC */
    if (router->hmac) {
      mac_len = router->hmac->hash->hash->hash_len;
      memset(mac, 0, sizeof(mac));
      silc_hmac_make_with_key(router->hmac, 
			      dst_sock->outbuf->data, 
			      dst_sock->outbuf->len,
			      router->hmac_key, 
			      router->hmac_key_len, 
			      mac);
      silc_buffer_put_tail(dst_sock->outbuf, mac, mac_len);
      memset(mac, 0, sizeof(mac));
    }
    
    silc_packet_encrypt(router->send_key, dst_sock->outbuf, buffer->len);
    
    if (router->hmac)
      silc_buffer_pull_tail(dst_sock->outbuf, mac_len);
    
    /* Send the packet */
    silc_server_packet_send_real(server, dst_sock, FALSE);

  } else {
    /* Key exist so just send it */
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_server_packet_send_prepare(server, dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    silc_server_packet_send_real(server, dst_sock, FALSE);
  }
}

/* Internal routine to send the received private message packet to
   our locally connected client. */
static void
silc_server_private_message_send_local(SilcServer server,
				       SilcSocketConnection dst_sock,
				       SilcClientList *client,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;

  /* Re-encrypt packet if needed */
  if ((packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY) == FALSE) {
    unsigned char mac[32];
    unsigned int mac_len = 0;

    if (client->hmac)
      mac_len = client->hmac->hash->hash->hash_len;
    
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_server_packet_send_prepare(server, dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    
    /* Compute new HMAC */
    if (client->hmac) {
      memset(mac, 0, sizeof(mac));
      silc_hmac_make_with_key(client->hmac, 
			      dst_sock->outbuf->data, 
			      dst_sock->outbuf->len,
			      client->hmac_key, 
			      client->hmac_key_len, 
			      mac);
      silc_buffer_put_tail(dst_sock->outbuf, mac, mac_len);
      memset(mac, 0, sizeof(mac));
    }
    
    /* Encrypt */
    if (client && client->send_key)
      silc_packet_encrypt(client->send_key, dst_sock->outbuf, 
			  buffer->len);
    
    if (client->hmac)
      silc_buffer_pull_tail(dst_sock->outbuf, mac_len);
    
    /* Send the packet */
    silc_server_packet_send_real(server, dst_sock, FALSE);
  } else {
    /* Key exist so just send it */
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_server_packet_send_prepare(server, dst_sock, 0, 0, buffer->len);
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
  SilcServerList *router;
  SilcSocketConnection dst_sock;
  SilcClientList *client;

  SILC_LOG_DEBUG(("Start"));

  if (!packet->dst_id) {
    SILC_LOG_DEBUG(("Bad Client ID in private message packet"));
    goto err;
  }

  /* Decode destination Client ID */
  id = silc_id_str2id(packet->dst_id, SILC_ID_CLIENT);
  if (!id) {
    SILC_LOG_DEBUG(("Could not decode destination Client ID"));
    goto err;
  }

  /* If the destination belongs to our server we don't have to route
     the message anywhere but to send it to the local destination. */
  /* XXX: Should use local cache to search but the current idcache system
     is so sucky that it cannot be used... it MUST be rewritten! Using
     this search is probably faster than if we'd use here the current
     idcache system. */
  client = silc_idlist_find_client_by_id(server->local_list->clients, id);
  if (client) {
    /* It exists, now deliver the message to the destination */
    dst_sock = (SilcSocketConnection)client->connection;

    /* If we are router and the client has router then the client is in
       our cell but not directly connected to us. */
    if (server->server_type == SILC_ROUTER && client->router) {
      silc_server_private_message_send_internal(server, dst_sock,
						client->router, packet);
      goto out;
    }

    /* Seems that client really is directly connected to us */
    silc_server_private_message_send_local(server, dst_sock, client, packet);
    goto out;
  }

  /* Destination belongs to someone not in this server. If we are normal
     server our action is to send the packet to our router. */
  if (server->server_type == SILC_SERVER && !server->standalone) {
    router = server->id_entry->router;
    dst_sock = (SilcSocketConnection)router->connection;

    /* Send to primary route */
    silc_server_private_message_send_internal(server, dst_sock, router,
					      packet);
    goto out;
  }

  /* We are router and we will perform route lookup for the destination 
     and send the message to fastest route. */
  if (server->server_type == SILC_ROUTER && !server->standalone) {

    /* Get fastest route and send packet. */
    dst_sock = silc_server_get_route(server, id, SILC_ID_CLIENT);
    silc_server_private_message_send_internal(server, dst_sock, 
					      dst_sock->user_data, packet);
    goto out;
  }

 err:
  silc_server_send_error(server, sock, 
			 "No such nickname: Private message not sent");
 out:
  silc_buffer_free(buffer);
}

SilcChannelList *silc_find_channel(SilcServer server, SilcChannelID *id)
{
  int i;
  SilcIDCache *id_cache;

#define LCC(x) server->local_list->channel_cache[(x)]
#define LCCC(x) server->local_list->channel_cache_count[(x)]

  for (i = 0; i < 96; i++) {
    if (LCC(i) == NULL)
      continue;
    if (silc_idcache_find_by_id(LCC(i), LCCC(i), (void *)id, 
				SILC_ID_CHANNEL, &id_cache))
      return (SilcChannelList *)id_cache->context;
  }
  
  return NULL;
#undef LCC
#undef LCCC
}

/* Process received channel message. */

void silc_server_channel_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcChannelList *channel = NULL;
  SilcClientList *client = NULL;
  SilcChannelID *id = NULL;
  SilcClientID *sender = NULL;
  SilcBuffer buffer = packet->buffer;
  int i;

  SILC_LOG_DEBUG(("Processing channel message"));
  
  /* Check MAC */
  if (!silc_server_packet_check_mac(server, sock, buffer))
    goto out;

  /* Sanity checks */
  if (packet->dst_id_type != SILC_ID_CHANNEL) {
    SILC_LOG_ERROR(("Received bad message for channel, dropped"));
    SILC_LOG_DEBUG(("Received bad message for channel, dropped"));
    goto out;
  }

  /* Find channel entry */
  id = silc_id_str2id(packet->dst_id, SILC_ID_CHANNEL);
  channel = silc_find_channel(server, id);
  if (!channel) {
    SILC_LOG_DEBUG(("Could not find channel"));
    goto out;
  }

  /* See that this client is on the channel */
  sender = silc_id_str2id(packet->src_id, packet->src_id_type);
  for (i = 0; i < channel->user_list_count; i++) {
    client = channel->user_list[i].client;
    if (client && !SILC_ID_CLIENT_COMPARE(client->id, sender))
      break;
  }
  if (i >= channel->user_list_count)
    goto out;

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
  SilcChannelList *channel;
  SilcClientList *client;
  unsigned char *key;
  unsigned int key_len;
  char *cipher;
  int i;

  if (packet->src_id_type != SILC_ID_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    goto out;

  /* Decode channel key payload */
  payload = silc_channel_key_parse_payload(buffer);
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload, dropped"));
    SILC_LOG_DEBUG(("Bad channel key payload, dropped"));
  }

  /* Get channel ID */
  id = silc_id_str2id(silc_channel_key_get_id(payload, NULL), SILC_ID_CHANNEL);
  if (!id)
    goto out;

  /* Get the channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list->channels, id);
  if (!channel) {
    SILC_LOG_ERROR(("Received key for non-existent channel"));
    SILC_LOG_DEBUG(("Received key for non-existent channel"));
    goto out;
  }

  /* Save the key for us as well */
  key = silc_channel_key_get_key(payload, &key_len);
  if (!key)
    goto out;
  cipher = silc_channel_key_get_cipher(payload, NULL);;
  if (!cipher)
    goto out;
  channel->key_len = key_len * 8;
  channel->key = silc_calloc(key_len, sizeof(unsigned char));
  memcpy(channel->key, key, key_len);
  silc_cipher_alloc(cipher, &channel->channel_key);
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					key, key_len);

  /* Distribute the key to all clients on the channel */
  for (i = 0; i < channel->user_list_count; i++) {
    client = channel->user_list[i].client;

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
    silc_channel_key_free_payload(payload);
  silc_buffer_free(buffer);
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

/* Sends notify message */

void silc_server_send_notify(SilcServer server,
			     SilcSocketConnection sock,
			     const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY, 0, 
			  buf, strlen(buf), FALSE);
}

/* Sends notify message destined to specific entity. */

void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY, 0, 
			       dest_id, dest_id_type,
			       buf, strlen(buf), FALSE);
}

/* Sends notify message to a channel. The notify message sent is 
   distributed to all clients on the channel. Actually this is not real
   notify message, instead it is message to channel sent by server. But
   as server is sending it it will appear as notify type message on the
   client side. */

void silc_server_send_notify_to_channel(SilcServer server,
					SilcChannelList *channel,
					const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  silc_server_packet_send_to_channel(server, channel, buf, 
				     strlen(buf), FALSE);
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
  SilcBuffer packet;
  unsigned char *id_string;

  id_string = silc_id_id2str(id, id_type);
  if (!id_string)
    return;

  packet = silc_buffer_alloc(2 + 2 + id_len);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(id_type),
		     SILC_STR_UI_SHORT(id_len),
		     SILC_STR_UI_XNSTRING(id_string, id_len),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);
  silc_free(id_string);
  silc_buffer_free(packet);
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

/* Creates new channel. */

SilcChannelList *silc_server_new_channel(SilcServer server, 
					 SilcServerID *router_id,
					 char *cipher, char *channel_name)
{
  int i, channel_len, key_len;
  SilcChannelID *channel_id;
  SilcChannelList *entry;
  SilcCipher key;
  unsigned char channel_key[32], *id_string;
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Creating new channel"));

#define LCC(x) server->local_list->channel_cache[(x) - 32]
#define LCCC(x) server->local_list->channel_cache_count[(x) - 32]

  /* Create channel key */
  for (i = 0; i < 32; i++)
    channel_key[i] = silc_rng_get_byte(server->rng);

  if (!cipher)
    cipher = "twofish";

  /* Allocate keys */
  key_len = 16;
  silc_cipher_alloc(cipher, &key);
  key->cipher->set_key(key->context, channel_key, key_len);

  /* Create the channel */
  silc_id_create_channel_id(router_id, server->rng, &channel_id);
  silc_idlist_add_channel(&server->local_list->channels, channel_name, 
			  SILC_CHANNEL_MODE_NONE, channel_id, NULL, /*XXX*/
			  key, &entry);
  LCCC(channel_name[0]) = silc_idcache_add(&LCC(channel_name[0]), 
					   LCCC(channel_name[0]),
					   channel_name, SILC_ID_CHANNEL, 
					   channel_id, (void *)entry);
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

#undef LCC
#undef LCCC
  return entry;
}

/* Create new client. This processes incoming NEW_CLIENT packet and creates
   Client ID for the client and adds it to lists and cache. */

SilcClientList *silc_server_new_client(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientList *id_entry;
  char *username = NULL, *realname = NULL, *id_string;
  SilcBuffer reply;

  SILC_LOG_DEBUG(("Creating new client"));

  if (sock->type != SILC_SOCKET_TYPE_CLIENT)
    return NULL;

#define LCC(x) server->local_list->client_cache[(x) - 32]
#define LCCC(x) server->local_list->client_cache_count[(x) - 32]

  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_STRING_ALLOC(&username),
		       SILC_STR_UI16_STRING_ALLOC(&realname),
		       SILC_STR_END);

  /* Set the pointers to the client list and create new client ID */
  id_entry = (SilcClientList *)sock->user_data;
  id_entry->nickname = strdup(username);
  id_entry->username = username;
  id_entry->userinfo = realname;
  silc_id_create_client_id(server->id, server->rng, server->md5hash,
			   username, &id_entry->id);

  /* Add to client cache */
  LCCC(username[0]) = silc_idcache_add(&LCC(username[0]), 
				       LCCC(username[0]),
				       username, SILC_ID_CLIENT, 
				       id_entry->id, (void *)id_entry);

  /* Notify our router about new client on the SILC network */
  if (!server->standalone)
    silc_server_send_new_id(server, (SilcSocketConnection) 
			    server->id_entry->router->connection, 
			    server->server_type == SILC_SERVER ? TRUE : FALSE,
			    id_entry->id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);
  
  /* Send the new client ID to the client. */
  id_string = silc_id_id2str(id_entry->id, SILC_ID_CLIENT);
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
  silc_server_send_notify(server, sock, 
			  "Welcome to the SILC Network %s@%s",
			  username, 
			  sock->hostname ? sock->hostname : sock->ip);
  silc_server_send_notify(server, sock,
			  "Your host is %s, running version %s",
			  server->config->server_info->server_name,
			  server_version);
  silc_server_send_notify(server, sock, 
			  "Your connection is secured with %s cipher, "
			  "key length %d bits",
			  id_entry->send_key->cipher->name,
			  id_entry->send_key->cipher->key_len);
  silc_server_send_notify(server, sock, 
			  "Your current nickname is %s",
			  id_entry->nickname);

  /* XXX Send motd */

#undef LCC
#undef LCCC
  return id_entry;
}

/* Create new server. This processes incoming NEW_SERVER packet and
   saves the received Server ID. The server is our locally connected
   server thus we save all the information and save it to local list. 
   This funtion can be used by both normal server and router server.
   If normal server uses this it means that its router has connected
   to the server.  If router uses this it means that one of the cell's
   servers is connected to the router. */

SilcServerList *silc_server_new_server(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcServerList *id_entry;
  unsigned char *server_name, *id_string;

  SILC_LOG_DEBUG(("Creating new server"));

  if (sock->type != SILC_SOCKET_TYPE_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return NULL;

#define LSC(x) server->local_list->server_cache[(x) - 32]
#define LSCC(x) server->local_list->server_cache_count[(x) - 32]

  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_STRING_ALLOC(&id_string),
		       SILC_STR_UI16_STRING_ALLOC(&server_name),
		       SILC_STR_END);

  /* Save ID and name */
  id_entry = (SilcServerList *)sock->user_data;
  id_entry->id = silc_id_str2id(id_string, SILC_ID_SERVER);
  id_entry->server_name = server_name;
  
  /* Add to server cache */
  LSCC(server_name[0]) = 
    silc_idcache_add(&LSC(server_name[0]), 
		     LSCC(server_name[0]),
		     server_name, SILC_ID_SERVER, 
		     id_entry->id, (void *)id_entry);

  /* Distribute the information about new server in the SILC network
     to our router. If we are normal server we won't send anything
     since this connection must be our router connection. */
  if (server->server_type == SILC_ROUTER && !server->standalone)
    silc_server_send_new_id(server, server->id_entry->router->connection,
			    TRUE, id_entry->id, SILC_ID_SERVER, 
			    SILC_ID_SERVER_LEN);

  silc_free(id_string);

#undef LSC
#undef LSCC
  return id_entry;
}

/* Processes incoming New ID Payload. New ID Payload is used to distribute
   information about newly registered clients, servers and created 
   channels. */

void silc_server_new_id(SilcServer server, SilcSocketConnection sock,
			SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcIdType id_type;
  unsigned char *id_string;
  void *id;

  SILC_LOG_DEBUG(("Processing new ID"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type == SILC_SERVER)
    return;

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&id_type),
		       SILC_STR_UI16_STRING_ALLOC(&id_string),
		       SILC_STR_END);

  /* Normal server cannot have other normal server connections */
  if (id_type == SILC_ID_SERVER && sock->type == SILC_SOCKET_TYPE_SERVER)
    goto out;

  id = silc_id_str2id(id_string, id_type);
  if (!id)
    goto out;

  /* XXX Do check whether the packet is coming outside the cell or
     from someone inside the cell.  If outside use global lists otherwise
     local lists. */
  /* XXX If using local list set the idlist->connection to the sender's
     socket connection as it is used in packet sending */

  switch(id_type) {
  case SILC_ID_CLIENT:
    {
      SilcClientList *idlist;

      /* Add the client to our local list. We are router and we keep
	 cell specific local database of all clients in the cell. */
      silc_idlist_add_client(&server->local_list->clients, NULL, NULL, NULL,
			     id, sock->user_data, NULL, NULL, 
			     NULL, NULL, &idlist);
      idlist->connection = sock;
    }
    break;

  case SILC_ID_SERVER:
    {
      SilcServerList *idlist;

      /* Add the server to our local list. We are router and we keep
	 cell specific local database of all servers in the cell. */
      silc_idlist_add_server(&server->local_list->servers, NULL, 0,
			     id, server->id_entry, NULL, NULL, 
			   NULL, NULL, &idlist);
      idlist->connection = sock;
    }
    break;

  case SILC_ID_CHANNEL:
    /* Add the channel to our local list. We are router and we keep
       cell specific local database of all channels in the cell. */
    silc_idlist_add_channel(&server->local_list->channels, NULL, 0,
			    id, server->id_entry, NULL, NULL);
    break;

  default:
    goto out;
    break;
  }

 out:
  silc_free(id_string);
}
