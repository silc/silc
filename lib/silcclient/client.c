/*

  client.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
#include "client_internal.h"

/* Static task callback prototypes */
SILC_TASK_CALLBACK(silc_client_connect_to_server_start);
SILC_TASK_CALLBACK(silc_client_connect_to_server_second);
SILC_TASK_CALLBACK(silc_client_connect_to_server_final);
SILC_TASK_CALLBACK(silc_client_packet_parse_real);
SILC_TASK_CALLBACK(silc_client_rekey_callback);
SILC_TASK_CALLBACK(silc_client_rekey_final);

static void silc_client_packet_parse(SilcPacketParserContext *parser_context);
static void silc_client_packet_parse_type(SilcClient client, 
					  SilcSocketConnection sock,
					  SilcPacketContext *packet);

/* Allocates new client object. This has to be done before client may
   work. After calling this one must call silc_client_init to initialize
   the client. The `application' is application specific user data pointer
   and caller must free it. */

SilcClient silc_client_alloc(SilcClientOperations *ops, void *application)
{
  SilcClient new_client;

  new_client = silc_calloc(1, sizeof(*new_client));
  new_client->application = application;
  new_client->ops = ops;

  return new_client;
}

/* Frees client object and its internals. */

void silc_client_free(SilcClient client)
{
  if (client) {
    if (client->rng)
      silc_rng_free(client->rng);

    silc_free(client);
  }
}

/* Initializes the client. This makes all the necessary steps to make
   the client ready to be run. One must call silc_client_run to run the
   client. Returns FALSE if error occured, TRUE otherwise. */

int silc_client_init(SilcClient client)
{
  SILC_LOG_DEBUG(("Initializing client"));

  /* Initialize hash functions for client to use */
  silc_hash_alloc("md5", &client->md5hash);
  silc_hash_alloc("sha1", &client->sha1hash);

  /* Initialize none cipher */
  silc_cipher_alloc("none", &client->none_cipher);

  /* Initialize random number generator */
  client->rng = silc_rng_alloc();
  silc_rng_init(client->rng);
  silc_rng_global_init(client->rng);

  /* Register protocols */
  silc_client_protocols_register();

  /* Initialize the scheduler */
  silc_schedule_init(&client->io_queue, &client->timeout_queue, 
		     &client->generic_queue, 5000);

  return TRUE;
}

/* Stops the client. This is called to stop the client and thus to stop
   the program. */

void silc_client_stop(SilcClient client)
{
  SILC_LOG_DEBUG(("Stopping client"));

  /* Stop the scheduler, although it might be already stopped. This
     doesn't hurt anyone. This removes all the tasks and task queues,
     as well. */
  silc_schedule_stop();
  silc_schedule_uninit();

  silc_client_protocols_unregister();

  SILC_LOG_DEBUG(("Client stopped"));
}

/* Runs the client. This starts the scheduler from the utility library.
   When this functions returns the execution of the appliation is over. */

void silc_client_run(SilcClient client)
{
  SILC_LOG_DEBUG(("Running client"));

  /* Start the scheduler, the heart of the SILC client. When this returns
     the program will be terminated. */
  silc_schedule();
}

/* Allocates and adds new connection to the client. This adds the allocated
   connection to the connection table and returns a pointer to it. A client
   can have multiple connections to multiple servers. Every connection must
   be added to the client using this function. User data `context' may
   be sent as argument. This function is normally used only if the 
   application performed the connecting outside the library. The library
   however may use this internally. */

SilcClientConnection silc_client_add_connection(SilcClient client,
						char *hostname,
						int port,
						void *context)
{
  SilcClientConnection conn;
  int i;

  conn = silc_calloc(1, sizeof(*conn));

  /* Initialize ID caches */
  conn->client_cache = silc_idcache_alloc(0, NULL);
  conn->channel_cache = silc_idcache_alloc(0, NULL);
  conn->server_cache = silc_idcache_alloc(0, NULL);
  conn->client = client;
  conn->remote_host = strdup(hostname);
  conn->remote_port = port;
  conn->context = context;
  conn->pending_commands = silc_dlist_init();

  /* Add the connection to connections table */
  for (i = 0; i < client->conns_count; i++)
    if (client->conns && !client->conns[i]) {
      client->conns[i] = conn;
      return conn;
    }

  client->conns = silc_realloc(client->conns, sizeof(*client->conns)
			       * (client->conns_count + 1));
  client->conns[client->conns_count] = conn;
  client->conns_count++;

  return conn;
}

/* Removes connection from client. Frees all memory. */

void silc_client_del_connection(SilcClient client, SilcClientConnection conn)
{
  int i;

  for (i = 0; i < client->conns_count; i++)
    if (client->conns[i] == conn) {
      if (conn->pending_commands)
	silc_dlist_uninit(conn->pending_commands);
      silc_free(conn);
      client->conns[i] = NULL;
    }
}

/* Adds listener socket to the listener sockets table. This function is
   used to add socket objects that are listeners to the client.  This should
   not be used to add other connection objects. */

void silc_client_add_socket(SilcClient client, SilcSocketConnection sock)
{
  int i;

  if (!client->sockets) {
    client->sockets = silc_calloc(1, sizeof(*client->sockets));
    client->sockets[0] = sock;
    client->sockets_count = 1;
    return;
  }

  for (i = 0; i < client->sockets_count; i++) {
    if (client->sockets[i] == NULL) {
      client->sockets[i] = sock;
      return;
    }
  }

  client->sockets = silc_realloc(client->sockets, sizeof(*client->sockets) *
				 (client->sockets_count + 1));
  client->sockets[client->sockets_count] = sock;
  client->sockets_count++;
}

/* Deletes listener socket from the listener sockets table. */

void silc_client_del_socket(SilcClient client, SilcSocketConnection sock)
{
  int i;

  if (!client->sockets)
    return;

  for (i = 0; i < client->sockets_count; i++) {
    if (client->sockets[i] == sock) {
      client->sockets[i] = NULL;
      return;
    }
  }
}

static int 
silc_client_connect_to_server_internal(SilcClientInternalConnectContext *ctx)
{
  int sock;

  /* XXX In the future we should give up this non-blocking connect all
     together and use threads instead. */
  /* Create connection to server asynchronously */
  sock = silc_net_create_connection_async(ctx->port, ctx->host);
  if (sock < 0)
    return -1;

  /* Register task that will receive the async connect and will
     read the result. */
  ctx->task = silc_task_register(ctx->client->io_queue, sock, 
				 silc_client_connect_to_server_start,
				 (void *)ctx, 0, 0, 
				 SILC_TASK_FD,
				 SILC_TASK_PRI_NORMAL);
  silc_task_reset_iotype(ctx->task, SILC_TASK_WRITE);
  silc_schedule_set_listen_fd(sock, ctx->task->iomask);

  ctx->sock = sock;

  return sock;
}

/* Connects to remote server. This is the main routine used to connect
   to SILC server. Returns -1 on error and the created socket otherwise. 
   The `context' is user context that is saved into the SilcClientConnection
   that is created after the connection is created. Note that application
   may handle the connecting process outside the library. If this is the
   case then this function is not used at all. When the connecting is
   done the `connect' client operation is called. */

int silc_client_connect_to_server(SilcClient client, int port,
				  char *host, void *context)
{
  SilcClientInternalConnectContext *ctx;
  SilcClientConnection conn;
  int sock;

  SILC_LOG_DEBUG(("Connecting to port %d of server %s",
		  port, host));

  conn = silc_client_add_connection(client, host, port, context);

  client->ops->say(client, conn, 
		   "Connecting to port %d of server %s", port, host);

  /* Allocate internal context for connection process. This is
     needed as we are doing async connecting. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->client = client;
  ctx->conn = conn;
  ctx->host = strdup(host);
  ctx->port = port;
  ctx->tries = 0;

  /* Do the actual connecting process */
  sock = silc_client_connect_to_server_internal(ctx);
  if (sock == -1)
    silc_client_del_connection(client, conn);
  return sock;
}

/* Start SILC Key Exchange (SKE) protocol to negotiate shared secret
   key material between client and server.  This function can be called
   directly if application is performing its own connecting and does not
   use the connecting provided by this library. This function is normally
   used only if the application performed the connecting outside the library.
   The library however may use this internally. */

int silc_client_start_key_exchange(SilcClient client,
			           SilcClientConnection conn,
                                   int fd)
{
  SilcProtocol protocol;
  SilcClientKEInternalContext *proto_ctx;
  void *context;

  /* Allocate new socket connection object */
  silc_socket_alloc(fd, SILC_SOCKET_TYPE_SERVER, (void *)conn, &conn->sock);

  conn->nickname = strdup(client->username);
  conn->sock->hostname = conn->remote_host;
  conn->sock->ip = strdup(conn->remote_host);
  conn->sock->port = conn->remote_port;

  /* Allocate internal Key Exchange context. This is sent to the
     protocol as context. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = conn->sock;
  proto_ctx->rng = client->rng;
  proto_ctx->responder = FALSE;
  proto_ctx->send_packet = silc_client_protocol_ke_send_packet;
  proto_ctx->verify = silc_client_protocol_ke_verify_key;

  /* Perform key exchange protocol. silc_client_connect_to_server_final
     will be called after the protocol is finished. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
		      &protocol, (void *)proto_ctx,
		      silc_client_connect_to_server_second);
  if (!protocol) {
    client->ops->say(client, conn, 
		     "Error: Could not start authentication protocol");
    return FALSE;
  }
  conn->sock->protocol = protocol;

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it will 
     be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)client;
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(fd);

  /* Execute the protocol */
  protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
  return TRUE;
}

/* Start of the connection to the remote server. This is called after
   succesful TCP/IP connection has been established to the remote host. */

SILC_TASK_CALLBACK(silc_client_connect_to_server_start)
{
  SilcClientInternalConnectContext *ctx =
    (SilcClientInternalConnectContext *)context;
  SilcClient client = ctx->client;
  SilcClientConnection conn = ctx->conn;
  int opt, opt_len = sizeof(opt);

  SILC_LOG_DEBUG(("Start"));

  /* Check the socket status as it might be in error */
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
  if (opt != 0) {
    if (ctx->tries < 2) {
      /* Connection failed but lets try again */
      client->ops->say(client, conn, "Could not connect to server %s: %s",
		       ctx->host, strerror(opt));
      client->ops->say(client, conn, 
		       "Connecting to port %d of server %s resumed", 
		       ctx->port, ctx->host);

      /* Unregister old connection try */
      silc_schedule_unset_listen_fd(fd);
      silc_net_close_connection(fd);
      silc_task_unregister(client->io_queue, ctx->task);

      /* Try again */
      silc_client_connect_to_server_internal(ctx);
      ctx->tries++;
    } else {
      /* Connection failed and we won't try anymore */
      client->ops->say(client, conn, "Could not connect to server %s: %s",
		       ctx->host, strerror(opt));
      silc_schedule_unset_listen_fd(fd);
      silc_net_close_connection(fd);
      silc_task_unregister(client->io_queue, ctx->task);
      silc_free(ctx);

      /* Notify application of failure */
      client->ops->connect(client, conn, FALSE);
      silc_client_del_connection(client, conn);
    }
    return;
  }

  silc_schedule_unset_listen_fd(fd);
  silc_task_unregister(client->io_queue, ctx->task);
  silc_free(ctx);

  if (!silc_client_start_key_exchange(client, conn, fd)) {
    silc_net_close_connection(fd);
    client->ops->connect(client, conn, FALSE);
  }
}

/* Second part of the connecting to the server. This executed 
   authentication protocol. */

SILC_TASK_CALLBACK(silc_client_connect_to_server_second)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcSocketConnection sock = NULL;
  SilcClientConnAuthInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    SILC_LOG_DEBUG(("Error during KE protocol"));
    silc_protocol_free(protocol);
    silc_ske_free_key_material(ctx->keymat);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    ctx->sock->protocol = NULL;
    silc_task_unregister_by_callback(client->timeout_queue,
				     silc_client_failure_callback);

    /* Notify application of failure */
    client->ops->connect(client, ctx->sock->user_data, FALSE);
    silc_free(ctx);
    return;
  }

  /* We now have the key material as the result of the key exchange
     protocol. Take the key material into use. Free the raw key material
     as soon as we've set them into use. */
  silc_client_protocol_ke_set_keys(ctx->ske, ctx->sock, ctx->keymat,
				   ctx->ske->prop->cipher,
				   ctx->ske->prop->pkcs,
				   ctx->ske->prop->hash,
				   ctx->ske->prop->hmac,
				   ctx->ske->prop->group);
  silc_ske_free_key_material(ctx->keymat);

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = sock = ctx->sock;
  proto_ctx->ske = ctx->ske;	/* Save SKE object from previous protocol */
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

  /* Resolve the authentication method to be used in this connection */
  if (!client->ops->get_auth_method(client, sock->user_data, sock->hostname,
				    sock->port, &proto_ctx->auth_meth,
				    &proto_ctx->auth_data, 
				    &proto_ctx->auth_data_len)) {
    client->ops->say(client, ctx->sock->user_data, 
		     "Could not resolve authentication method to use, "
		     "assume no authentication");
    proto_ctx->auth_meth = SILC_AUTH_NONE;
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
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_CONNECTION_AUTH, 
		      &sock->protocol, (void *)proto_ctx, 
		      silc_client_connect_to_server_final);

  /* Execute the protocol */
  sock->protocol->execute(client->timeout_queue, 0, sock->protocol, fd, 0, 0);
}

/* Finalizes the connection to the remote SILC server. This is called
   after authentication protocol has been completed. This send our
   user information to the server to receive our client ID from
   server. */

SILC_TASK_CALLBACK(silc_client_connect_to_server_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientConnAuthInternalContext *ctx = 
    (SilcClientConnAuthInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientConnection conn = (SilcClientConnection)ctx->sock->user_data;
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    SILC_LOG_DEBUG(("Error during authentication protocol"));
    silc_protocol_free(protocol);
    if (ctx->auth_data)
      silc_free(ctx->auth_data);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    conn->sock->protocol = NULL;
    silc_task_unregister_by_callback(client->timeout_queue,
				     silc_client_failure_callback);

    /* Notify application of failure */
    client->ops->connect(client, ctx->sock->user_data, FALSE);
    silc_free(ctx);
    return;
  }

  /* Send NEW_CLIENT packet to the server. We will become registered
     to the SILC network after sending this packet and we will receive
     client ID from the server. */
  packet = silc_buffer_alloc(2 + 2 + strlen(client->username) + 
			     strlen(client->realname));
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(strlen(client->username)),
		     SILC_STR_UI_XNSTRING(client->username,
					  strlen(client->username)),
		     SILC_STR_UI_SHORT(strlen(client->realname)),
		     SILC_STR_UI_XNSTRING(client->realname,
					  strlen(client->realname)),
		     SILC_STR_END);

  /* Send the packet */
  silc_client_packet_send(client, ctx->sock, SILC_PACKET_NEW_CLIENT,
			  NULL, 0, NULL, NULL, 
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);

  /* Save remote ID. */
  conn->remote_id = ctx->dest_id;
  conn->remote_id_data = silc_id_id2str(ctx->dest_id, SILC_ID_SERVER);
  conn->remote_id_data_len = SILC_ID_SERVER_LEN;

  /* Register re-key timeout */
  conn->rekey->timeout = 3600; /* XXX hardcoded */
  conn->rekey->context = (void *)client;
  silc_task_register(client->timeout_queue, conn->sock->sock, 
		     silc_client_rekey_callback,
		     (void *)conn->sock, conn->rekey->timeout, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  silc_task_unregister_by_callback(client->timeout_queue,
				   silc_client_failure_callback);
  silc_protocol_free(protocol);
  if (ctx->auth_data)
    silc_free(ctx->auth_data);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx);
  conn->sock->protocol = NULL;
}

/* Internal routine that sends packet or marks packet to be sent. This
   is used directly only in special cases. Normal cases should use
   silc_server_packet_send. Returns < 0 on error. */

int silc_client_packet_send_real(SilcClient client,
				 SilcSocketConnection sock,
				 bool force_send,
				 bool flush)
{
  int ret;

  /* If rekey protocol is active we must assure that all packets are
     sent through packet queue. */
  if (flush == FALSE && SILC_CLIENT_IS_REKEY(sock))
    force_send = FALSE;

  /* Send the packet */
  ret = silc_packet_send(sock, force_send);
  if (ret != -2)
    return ret;

  /* Mark that there is some outgoing data available for this connection. 
     This call sets the connection both for input and output (the input
     is set always and this call keeps the input setting, actually). 
     Actual data sending is performed by silc_client_packet_process. */
  SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(sock->sock);

  /* Mark to socket that data is pending in outgoing buffer. This flag
     is needed if new data is added to the buffer before the earlier
     put data is sent to the network. */
  SILC_SET_OUTBUF_PENDING(sock);

  return 0;
}

/* Packet processing callback. This is used to send and receive packets
   from network. This is generic task. */

SILC_TASK_CALLBACK_GLOBAL(silc_client_packet_process)
{
  SilcClient client = (SilcClient)context;
  SilcSocketConnection sock = NULL;
  SilcClientConnection conn;
  int ret;

  SILC_LOG_DEBUG(("Processing packet"));

  SILC_CLIENT_GET_SOCK(client, fd, sock);
  if (sock == NULL)
    return;

  conn = (SilcClientConnection)sock->user_data;

  /* Packet sending */
  if (type == SILC_TASK_WRITE) {
    SILC_LOG_DEBUG(("Writing data to connection"));

    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, 
		       sock->outbuf->data - sock->outbuf->head);

    ret = silc_client_packet_send_real(client, sock, TRUE, TRUE);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;
    
    /* The packet has been sent and now it is time to set the connection
       back to only for input. When there is again some outgoing data 
       available for this connection it will be set for output as well. 
       This call clears the output setting and sets it only for input. */
    SILC_CLIENT_SET_CONNECTION_FOR_INPUT(fd);
    SILC_UNSET_OUTBUF_PENDING(sock);

    silc_buffer_clear(sock->outbuf);
    return;
  }

  /* Packet receiving */
  if (type == SILC_TASK_READ) {
    SILC_LOG_DEBUG(("Reading data from connection"));

    /* Read data from network */
    ret = silc_packet_receive(sock);
    if (ret < 0)
      return;
    
    /* EOF */
    if (ret == 0) {
      SILC_LOG_DEBUG(("Read EOF"));

      /* If connection is disconnecting already we will finally
	 close the connection */
      if (SILC_IS_DISCONNECTING(sock)) {
	if (sock == conn->sock)
	  client->ops->disconnect(client, conn);
	silc_client_close_connection(client, sock, conn);
	return;
      }
      
      SILC_LOG_DEBUG(("EOF from connection %d", sock->sock));
      if (sock == conn->sock)
	client->ops->disconnect(client, conn);
      silc_client_close_connection(client, sock, conn);
      return;
    }

    /* Process the packet. This will call the parser that will then
       decrypt and parse the packet. */
    if (sock->type != SILC_SOCKET_TYPE_UNKNOWN)
      silc_packet_receive_process(sock, conn->receive_key, conn->hmac,
				  silc_client_packet_parse, client);
    else
      silc_packet_receive_process(sock, NULL, NULL,
				  silc_client_packet_parse, client);
  }
}

/* Callback function that the silc_packet_decrypt will call to make the
   decision whether the packet is normal or special packet. We will 
   return TRUE if it is normal and FALSE if it is special */

static int silc_client_packet_decrypt_check(SilcPacketType packet_type,
					    SilcBuffer buffer,
					    SilcPacketContext *packet,
					    void *context)
{

  /* Packet is normal packet, if: 

     1) packet is private message packet and does not have private key set
     2) is other packet than channel message packet

     all other packets are special packets 
  */

  if (packet_type == SILC_PACKET_PRIVATE_MESSAGE &&
      (buffer->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
    return FALSE;

  if (packet_type != SILC_PACKET_CHANNEL_MESSAGE)
    return TRUE;

  return FALSE;
}

/* Parses whole packet, received earlier. */

SILC_TASK_CALLBACK(silc_client_packet_parse_real)
{
  SilcPacketParserContext *parse_ctx = (SilcPacketParserContext *)context;
  SilcClient client = (SilcClient)parse_ctx->context;
  SilcPacketContext *packet = parse_ctx->packet;
  SilcBuffer buffer = packet->buffer;
  SilcSocketConnection sock = parse_ctx->sock;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Decrypt the received packet */
  if (sock->type != SILC_SOCKET_TYPE_UNKNOWN)
    ret = silc_packet_decrypt(conn->receive_key, conn->hmac, buffer, packet,
			      silc_client_packet_decrypt_check, parse_ctx);
  else
    ret = silc_packet_decrypt(NULL, NULL, buffer, packet,
			      silc_client_packet_decrypt_check, parse_ctx);

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

  /* Parse the incoming packet type */
  silc_client_packet_parse_type(client, sock, packet);

 out:
  /*  silc_buffer_clear(sock->inbuf); */
  silc_packet_context_free(packet);
  silc_free(parse_ctx);
}

/* Parser callback called by silc_packet_receive_process. Thie merely
   registers timeout that will handle the actual parsing when appropriate. */

void silc_client_packet_parse(SilcPacketParserContext *parser_context)
{
  SilcClient client = (SilcClient)parser_context->context;

  /* Parse the packet */
  silc_task_register(client->timeout_queue, parser_context->sock->sock, 
		     silc_client_packet_parse_real,
		     (void *)parser_context, 0, 1, 
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_NORMAL);
}
  
/* Parses the packet type and calls what ever routines the packet type
   requires. This is done for all incoming packets. */

void silc_client_packet_parse_type(SilcClient client, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcPacketType type = packet->type;

  SILC_LOG_DEBUG(("Parsing packet type %d", type));

  /* Parse the packet type */
  switch(type) {
  case SILC_PACKET_DISCONNECT:
    silc_client_disconnected_by_server(client, sock, buffer);
    break;
  case SILC_PACKET_SUCCESS:
    /*
     * Success received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * success message is for whatever protocol is executing currently.
     */
    if (sock->protocol) {
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    }
    break;
  case SILC_PACKET_FAILURE:
    /*
     * Failure received for some protocol. Set the protocol state to 
     * error and call the protocol callback. This fill cause error on
     * protocol and it will call the final callback.
     */
    silc_client_process_failure(client, sock, packet);
    break;
  case SILC_PACKET_REJECT:
    break;

  case SILC_PACKET_NOTIFY:
    /*
     * Received notify message 
     */
    silc_client_notify_by_server(client, sock, packet);
    break;

  case SILC_PACKET_ERROR:
    /*
     * Received error message
     */
    silc_client_error_by_server(client, sock, buffer);
    break;

  case SILC_PACKET_CHANNEL_MESSAGE:
    /*
     * Received message to (from, actually) a channel
     */
    silc_client_channel_message(client, sock, packet);
    break;
  case SILC_PACKET_CHANNEL_KEY:
    /*
     * Received key for a channel. By receiving this key the client will be
     * able to talk to the channel it has just joined. This can also be
     * a new key for existing channel as keys expire peridiocally.
     */
    silc_client_receive_channel_key(client, sock, buffer);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE:
    /*
     * Received private message
     */
    silc_client_private_message(client, sock, packet);
    break;
  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /*
     * Received private message key
     */
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Recived reply for a command
     */
    silc_client_command_reply_process(client, sock, packet);
    break;

  case SILC_PACKET_KEY_EXCHANGE:
    if (sock->protocol && sock->protocol->protocol && 
	sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE) {
      SilcClientKEInternalContext *proto_ctx = 
	(SilcClientKEInternalContext *)sock->protocol->context;

      proto_ctx->packet = silc_packet_context_dup(packet);
      proto_ctx->dest_id_type = packet->src_id_type;
      proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					  packet->src_id_type);
      if (!proto_ctx->dest_id)
	break;

      /* Let the protocol handle the packet */
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange packet but no key exchange "
		      "protocol active, packet dropped."));

      /* XXX Trigger KE protocol?? Rekey actually! */
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_1:
    if (sock->protocol && sock->protocol->protocol && 
	(sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE ||
	 sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)) {

      if (sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY) {
	SilcClientRekeyInternalContext *proto_ctx = 
	  (SilcClientRekeyInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);

	/* Let the protocol handle the packet */
	sock->protocol->execute(client->timeout_queue, 0, 
				sock->protocol, sock->sock, 0, 0);
      } else {
	SilcClientKEInternalContext *proto_ctx = 
	  (SilcClientKEInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;
	
	/* Let the protocol handle the packet */
	sock->protocol->execute(client->timeout_queue, 0,
				sock->protocol, sock->sock, 0, 0);
      }
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 1 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;
  case SILC_PACKET_KEY_EXCHANGE_2:
    if (sock->protocol && sock->protocol->protocol && 
	(sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE ||
	 sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)) {

      if (sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY) {
	SilcClientRekeyInternalContext *proto_ctx = 
	  (SilcClientRekeyInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);

	/* Let the protocol handle the packet */
	sock->protocol->execute(client->timeout_queue, 0, 
				sock->protocol, sock->sock, 0, 0);
      } else {
	SilcClientKEInternalContext *proto_ctx = 
	  (SilcClientKEInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
	
	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;
	
	/* Let the protocol handle the packet */
	sock->protocol->execute(client->timeout_queue, 0,
				sock->protocol, sock->sock, 0, 0);
      }
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 2 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_NEW_ID:
    {
      /*
       * Received new ID from server. This packet is received at
       * the connection to the server.  New ID is also received when 
       * user changes nickname but in that case the new ID is received
       * as command reply and not as this packet type.
       */
      SilcIDPayload idp;

      idp = silc_id_payload_parse(buffer);
      if (!idp)
	break;
      if (silc_id_payload_get_type(idp) != SILC_ID_CLIENT)
	break;

      silc_client_receive_new_id(client, sock, idp);
      silc_id_payload_free(idp);
      break;
    }

  case SILC_PACKET_HEARTBEAT:
    /*
     * Received heartbeat packet
     */
    SILC_LOG_DEBUG(("Heartbeat packet"));
    break;

  case SILC_PACKET_KEY_AGREEMENT:
    /*
     * Received key agreement packet
     */
    SILC_LOG_DEBUG(("Key agreement packet"));
    silc_client_key_agreement(client, sock, packet);
    break;

  case SILC_PACKET_REKEY:
    SILC_LOG_DEBUG(("Re-key packet"));
    /* We ignore this for now */
    break;

  case SILC_PACKET_REKEY_DONE:
    SILC_LOG_DEBUG(("Re-key done packet"));

    if (sock->protocol && sock->protocol->protocol && 
	sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY) {

      SilcClientRekeyInternalContext *proto_ctx = 
	(SilcClientRekeyInternalContext *)sock->protocol->context;
      
      if (proto_ctx->packet)
	silc_packet_context_free(proto_ctx->packet);
      
      proto_ctx->packet = silc_packet_context_dup(packet);
      
      /* Let the protocol handle the packet */
      sock->protocol->execute(client->timeout_queue, 0, 
			      sock->protocol, sock->sock, 0, 100000);
    } else {
      SILC_LOG_ERROR(("Received Re-key done packet but no re-key "
		      "protocol active, packet dropped."));
    }
    break;

  default:
    SILC_LOG_DEBUG(("Incorrect packet type %d, packet dropped", type));
    break;
  }
}

/* Sends packet. This doesn't actually send the packet instead it assembles
   it and marks it to be sent. However, if force_send is TRUE the packet
   is sent immediately. if dst_id, cipher and hmac are NULL those parameters
   will be derived from sock argument. Otherwise the valid arguments sent
   are used. */

void silc_client_packet_send(SilcClient client, 
			     SilcSocketConnection sock,
			     SilcPacketType type, 
			     void *dst_id,
			     SilcIdType dst_id_type,
			     SilcCipher cipher,
			     SilcHmac hmac,
			     unsigned char *data, 
			     uint32 data_len, 
			     int force_send)
{
  SilcPacketContext packetdata;

  SILC_LOG_DEBUG(("Sending packet, type %d", type));

  /* Get data used in the packet sending, keys and stuff */
  if ((!cipher || !hmac || !dst_id) && sock->user_data) {
    if (!cipher && ((SilcClientConnection)sock->user_data)->send_key)
      cipher = ((SilcClientConnection)sock->user_data)->send_key;

    if (!hmac && ((SilcClientConnection)sock->user_data)->hmac)
      hmac = ((SilcClientConnection)sock->user_data)->hmac;

    if (!dst_id && ((SilcClientConnection)sock->user_data)->remote_id) {
      dst_id = ((SilcClientConnection)sock->user_data)->remote_id;
      dst_id_type = SILC_ID_SERVER;
    }
  }

  /* Set the packet context pointers */
  packetdata.flags = 0;
  packetdata.type = type;
  if (sock->user_data && 
      ((SilcClientConnection)sock->user_data)->local_id_data)
    packetdata.src_id = ((SilcClientConnection)sock->user_data)->local_id_data;
  else 
    packetdata.src_id = silc_calloc(SILC_ID_CLIENT_LEN, sizeof(unsigned char));
  packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  packetdata.src_id_type = SILC_ID_CLIENT;
  if (dst_id) {
    packetdata.dst_id = silc_id_id2str(dst_id, dst_id_type);
    packetdata.dst_id_len = silc_id_get_len(dst_id_type);
    packetdata.dst_id_type = dst_id_type;
  } else {
    packetdata.dst_id = NULL;
    packetdata.dst_id_len = 0;
    packetdata.dst_id_type = SILC_ID_NONE;
  }
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

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

  /* Encrypt the packet */
  if (cipher)
    silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);

  SILC_LOG_HEXDUMP(("Packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send, FALSE);
}

/* Closes connection to remote end. Free's all allocated data except
   for some information such as nickname etc. that are valid at all time. 
   If the `sock' is NULL then the conn->sock will be used.  If `sock' is
   provided it will be checked whether the sock and `conn->sock' are the
   same (they can be different, ie. a socket can use `conn' as its
   connection but `conn->sock' might be actually a different connection
   than the `sock'). */

void silc_client_close_connection(SilcClient client,
				  SilcSocketConnection sock,
				  SilcClientConnection conn)
{
  int del = FALSE;

  if (!sock || (sock && conn->sock == sock))
    del = TRUE;
  if (!sock)
    sock = conn->sock;

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(sock->sock);

  /* Unregister all tasks */
  silc_task_unregister_by_fd(client->io_queue, sock->sock);
  silc_task_unregister_by_fd(client->timeout_queue, sock->sock);

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);

  /* Free everything */
  if (del && sock->user_data) {
    /* XXX Free all client entries and channel entries. */

    client->ops->say(client, sock->user_data,
		     "Closed connection to host %s", sock->hostname);

    /* Clear ID caches */
    silc_idcache_del_all(conn->client_cache);
    silc_idcache_del_all(conn->channel_cache);

    /* Free data */
    if (conn->remote_host)
      silc_free(conn->remote_host);
    if (conn->local_id)
      silc_free(conn->local_id);
    if (conn->local_id_data)
      silc_free(conn->local_id_data);
    if (conn->send_key)
      silc_cipher_free(conn->send_key);
    if (conn->receive_key)
      silc_cipher_free(conn->receive_key);
    if (conn->hmac)
      silc_hmac_free(conn->hmac);
    if (conn->pending_commands)
      silc_dlist_uninit(conn->pending_commands);
    if (conn->rekey)
      silc_free(conn->rekey);

    conn->sock = NULL;
    conn->remote_port = 0;
    conn->remote_type = 0;
    conn->send_key = NULL;
    conn->receive_key = NULL;
    conn->hmac = NULL;
    conn->local_id = NULL;
    conn->local_id_data = NULL;
    conn->remote_host = NULL;
    conn->current_channel = NULL;
    conn->pending_commands = NULL;
    conn->rekey = NULL;

    silc_client_del_connection(client, conn);
  }

  if (sock->protocol) {
    silc_protocol_free(sock->protocol);
    sock->protocol = NULL;
  }
  silc_socket_free(sock);
}

/* Called when we receive disconnection packet from server. This 
   closes our end properly and displays the reason of the disconnection
   on the screen. */

void silc_client_disconnected_by_server(SilcClient client,
					SilcSocketConnection sock,
					SilcBuffer message)
{
  char *msg;

  SILC_LOG_DEBUG(("Server disconnected us, sock %d", sock->sock));

  msg = silc_calloc(message->len + 1, sizeof(char));
  memcpy(msg, message->data, message->len);
  client->ops->say(client, sock->user_data, msg);
  silc_free(msg);

  SILC_SET_DISCONNECTED(sock);
  silc_client_close_connection(client, sock, sock->user_data);
}

/* Received error message from server. Display it on the screen. 
   We don't take any action what so ever of the error message. */

void silc_client_error_by_server(SilcClient client,
				 SilcSocketConnection sock,
				 SilcBuffer message)
{
  char *msg;

  msg = silc_calloc(message->len + 1, sizeof(char));
  memcpy(msg, message->data, message->len);
  client->ops->say(client, sock->user_data, msg);
  silc_free(msg);
}

/* Processes the received new Client ID from server. Old Client ID is
   deleted from cache and new one is added. */

void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				SilcIDPayload idp)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  int connecting = FALSE;

  if (!conn->local_entry)
    connecting = TRUE;

  /* Delete old ID from ID cache */
  silc_idcache_del_by_id(conn->client_cache, SILC_ID_CLIENT, conn->local_id);
  
  /* Save the new ID */
  if (conn->local_id)
    silc_free(conn->local_id);
  if (conn->local_id_data)
    silc_free(conn->local_id_data);

  conn->local_id = silc_id_payload_get_id(idp);
  conn->local_id_data = silc_id_payload_get_data(idp);
  conn->local_id_data_len = silc_id_payload_get_len(idp);;

  if (!conn->local_entry)
    conn->local_entry = silc_calloc(1, sizeof(*conn->local_entry));

  conn->local_entry->nickname = conn->nickname;
  if (!conn->local_entry->username) {
    conn->local_entry->username = 
      silc_calloc(strlen(client->username) + strlen(client->hostname) + 1,
		  sizeof(conn->local_entry->username));
    sprintf(conn->local_entry->username, "%s@%s", client->username,
	    client->hostname);
  }
  conn->local_entry->server = strdup(conn->remote_host);
  conn->local_entry->id = conn->local_id;
  
  /* Put it to the ID cache */
  silc_idcache_add(conn->client_cache, conn->nickname, strlen(conn->nickname),
		   SILC_ID_CLIENT, conn->local_id, (void *)conn->local_entry,
		   TRUE, FALSE);

  /* Notify application of successful connection. We do it here now that
     we've received the Client ID and are allowed to send traffic. */
  if (connecting)
    client->ops->connect(client, conn, TRUE);
}

/* Processed received Channel ID for a channel. This is called when client
   joins to channel and server replies with channel ID. The ID is cached. 
   Returns the created channel entry. */

SilcChannelEntry silc_client_new_channel_id(SilcClient client,
					    SilcSocketConnection sock,
					    char *channel_name,
					    uint32 mode, 
					    SilcIDPayload idp)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("New channel ID"));

  channel = silc_calloc(1, sizeof(*channel));
  channel->channel_name = channel_name;
  channel->id = silc_id_payload_get_id(idp);
  channel->mode = mode;
  silc_list_init(channel->clients, struct SilcChannelUserStruct, next);

  conn->current_channel = channel;

  /* Put it to the ID cache */
  silc_idcache_add(conn->channel_cache, channel_name, strlen(channel_name),
		   SILC_ID_CHANNEL, (void *)channel->id, (void *)channel, 
		   TRUE, FALSE);

  return channel;
}

/* Removes a client entry from all channel it has joined. This really is
   a performance killer (client_entry should have pointers to channel 
   entry list). */

void silc_client_remove_from_channels(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list;
  SilcChannelEntry channel;
  SilcChannelUser chu;

  if (!silc_idcache_find_by_id(conn->channel_cache, SILC_ID_CACHE_ANY,
			       SILC_ID_CHANNEL, &list))
    return;

  silc_idcache_list_first(list, &id_cache);
  channel = (SilcChannelEntry)id_cache->context;
  
  while (channel) {
    
    /* Remove client from channel */
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      if (chu->client == client_entry) {
	silc_list_del(channel->clients, chu);
	silc_free(chu);
	break;
      }
    }

    if (!silc_idcache_list_next(list, &id_cache))
      break;
    
    channel = (SilcChannelEntry)id_cache->context;
  }

  silc_idcache_list_free(list);
}

/* Replaces `old' client entries from all channels to `new' client entry.
   This can be called for example when nickname changes and old ID entry
   is replaced from ID cache with the new one. If the old ID entry is only
   updated, then this fucntion needs not to be called. */

void silc_client_replace_from_channels(SilcClient client, 
				       SilcClientConnection conn,
				       SilcClientEntry old,
				       SilcClientEntry new)
{
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list;
  SilcChannelEntry channel;
  SilcChannelUser chu;

  if (!silc_idcache_find_by_id(conn->channel_cache, SILC_ID_CACHE_ANY,
			       SILC_ID_CHANNEL, &list))
    return;

  silc_idcache_list_first(list, &id_cache);
  channel = (SilcChannelEntry)id_cache->context;
  
  while (channel) {
    
    /* Replace client entry */
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      if (chu->client == old) {
	chu->client = new;
	break;
      }
    }

    if (!silc_idcache_list_next(list, &id_cache))
      break;
    
    channel = (SilcChannelEntry)id_cache->context;
  }

  silc_idcache_list_free(list);
}

/* Parses mode mask and returns the mode as string. */

char *silc_client_chmode(uint32 mode, SilcChannelEntry channel)
{
  char string[100];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_MODE_PRIVATE)
    strncat(string, "p", 1);

  if (mode & SILC_CHANNEL_MODE_SECRET)
    strncat(string, "s", 1);

  if (mode & SILC_CHANNEL_MODE_PRIVKEY)
    strncat(string, "k", 1);

  if (mode & SILC_CHANNEL_MODE_INVITE)
    strncat(string, "i", 1);

  if (mode & SILC_CHANNEL_MODE_TOPIC)
    strncat(string, "t", 1);

  if (mode & SILC_CHANNEL_MODE_ULIMIT)
    strncat(string, "l", 1);

  if (mode & SILC_CHANNEL_MODE_PASSPHRASE)
    strncat(string, "a", 1);

  if (mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_MODE_CIPHER) {
    char cipher[30];
    memset(cipher, 0, sizeof(cipher));
    snprintf(cipher, sizeof(cipher), " c (%s)", 
	     channel->channel_key->cipher->name);
    strncat(string, cipher, strlen(cipher));
  }

  if (mode & SILC_CHANNEL_MODE_HMAC) {
    char hmac[30];
    memset(hmac, 0, sizeof(hmac));
    snprintf(hmac, sizeof(hmac), " h (%s)", 
	     channel->hmac->hmac->name);
    strncat(string, hmac, strlen(hmac));
  }

  /* Rest of mode is ignored */

  return strdup(string);
}

/* Parses channel user mode mask and returns te mode as string */

char *silc_client_chumode(uint32 mode)
{
  char string[4];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "o", 1);

  return strdup(string);
}

/* Parses channel user mode and returns it as special mode character. */

char *silc_client_chumode_char(uint32 mode)
{
  char string[4];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "*", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "@", 1);

  return strdup(string);
}

/* Failure timeout callback. If this is called then we will immediately
   process the received failure. We always process the failure with timeout
   since we do not want to blindly trust to received failure packets. 
   This won't be called (the timeout is cancelled) if the failure was
   bogus (it is bogus if remote does not close the connection after sending
   the failure). */

SILC_TASK_CALLBACK_GLOBAL(silc_client_failure_callback)
{
  SilcClientFailureContext *f = (SilcClientFailureContext *)context;

  if (f->sock->protocol) {
    f->sock->protocol->state = SILC_PROTOCOL_STATE_FAILURE;
    f->sock->protocol->execute(f->client->timeout_queue, 0,
			       f->sock->protocol, f->sock->sock, 0, 0);
    
    /* Notify application */
    f->client->ops->failure(f->client, f->sock->user_data, f->sock->protocol,
			    (void *)f->failure);
  }

  silc_free(f);
}

/* Registers failure timeout to process the received failure packet
   with timeout. */

void silc_client_process_failure(SilcClient client,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcClientFailureContext *f;
  uint32 failure = 0;

  if (sock->protocol) {
    if (packet->buffer->len >= 4)
      SILC_GET32_MSB(failure, packet->buffer->data);

    f = silc_calloc(1, sizeof(*f));
    f->client = client;
    f->sock = sock;
    f->failure = failure;

    /* We will wait 5 seconds to process this failure packet */
    silc_task_register(client->timeout_queue, sock->sock,
		       silc_client_failure_callback, (void *)f, 5, 0,
		       SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
  }
}

/* A timeout callback for the re-key. We will be the initiator of the
   re-key protocol. */

SILC_TASK_CALLBACK(silc_client_rekey_callback)
{
  SilcSocketConnection sock = (SilcSocketConnection)context;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcClient client = (SilcClient)conn->rekey->context;
  SilcProtocol protocol;
  SilcClientRekeyInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = sock;
  proto_ctx->responder = FALSE;
  proto_ctx->pfs = conn->rekey->pfs;
      
  /* Perform rekey protocol. Will call the final callback after the
     protocol is over. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_REKEY, 
		      &protocol, proto_ctx, silc_client_rekey_final);
  sock->protocol = protocol;
      
  /* Run the protocol */
  protocol->execute(client->timeout_queue, 0, protocol, 
		    sock->sock, 0, 0);

  /* Re-register re-key timeout */
  silc_task_register(client->timeout_queue, sock->sock, 
		     silc_client_rekey_callback,
		     context, conn->rekey->timeout, 0,
		     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* The final callback for the REKEY protocol. This will actually take the
   new key material into use. */

SILC_TASK_CALLBACK(silc_client_rekey_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientRekeyInternalContext *ctx =
    (SilcClientRekeyInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcSocketConnection sock = ctx->sock;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    silc_protocol_cancel(client->timeout_queue, protocol);
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_free(ctx);
    return;
  }

  /* Take the keys into use */
  if (ctx->pfs == TRUE)
    silc_client_protocol_rekey_generate_pfs(client, ctx);
  else
    silc_client_protocol_rekey_generate(client, ctx);

  /* Cleanup */
  silc_protocol_free(protocol);
  sock->protocol = NULL;
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_free(ctx);
}
