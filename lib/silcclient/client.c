/*

  client.c

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
/* $Id$ */

#include "clientlibincludes.h"

/* Static task callback prototypes */
SILC_TASK_CALLBACK(silc_client_connect_to_server_start);
SILC_TASK_CALLBACK(silc_client_connect_to_server_second);
SILC_TASK_CALLBACK(silc_client_connect_to_server_final);
SILC_TASK_CALLBACK(silc_client_packet_process);
SILC_TASK_CALLBACK(silc_client_packet_parse_real);

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

/* Free's client object */

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
   client. */

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

/* Runs the client. */

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
   be sent as argument. */

SilcClientConnection silc_client_add_connection(SilcClient client,
						char *hostname,
						int port,
						void *context)
{
  SilcClientConnection conn;
  int i;

  conn = silc_calloc(1, sizeof(*conn));

  /* Initialize ID caches */
  conn->client_cache = silc_idcache_alloc(0);
  conn->channel_cache = silc_idcache_alloc(0);
  conn->server_cache = silc_idcache_alloc(0);
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

/* Removes connection from client. */

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

/* Internal context for connection process. This is needed as we
   doing asynchronous connecting. */
typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcTask task;
  int sock;
  char *host;
  int port;
  int tries;
} SilcClientInternalConnectContext;

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
   that is created after the connection is created. */

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
   use the connecting provided by this library. */

int silc_client_start_key_exchange(SilcClient client,
			           SilcClientConnection conn,
                                   int fd)
{
  SilcProtocol protocol;
  SilcClientKEInternalContext *proto_ctx;
  void *context;

  /* Allocate new socket connection object */
  silc_socket_alloc(fd, SILC_SOCKET_TYPE_SERVER, (void *)conn, &conn->sock);
  if (conn->sock == NULL) {
    client->ops->say(client, conn, 
		     "Error: Could not allocate connection socket");
    return FALSE;
  }

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
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    ctx->sock->protocol = NULL;

    /* Notify application of failure */
    client->ops->connect(client, ctx->sock->user_data, FALSE);
    silc_free(ctx);
    return;
  }

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
				    &proto_ctx->auth_data_len))
    {
      /* XXX do AUTH_REQUEST resolcing with server */
      proto_ctx->auth_meth = SILC_PROTOCOL_CONN_AUTH_NONE;
    }

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
  /* silc_free(ctx->keymat....); */
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

static int silc_client_packet_send_real(SilcClient client,
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

SILC_TASK_CALLBACK(silc_client_packet_process)
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

    ret = silc_client_packet_send_real(client, sock, TRUE);

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
	client->ops->disconnect(client, conn);
	silc_client_close_connection(client, sock);
	return;
      }
      
      client->ops->say(client, conn, "Connection closed: premature EOF");
      SILC_LOG_DEBUG(("Premature EOF from connection %d", sock->sock));
      client->ops->disconnect(client, conn);
      silc_client_close_connection(client, sock);
      return;
    }

    /* Process the packet. This will call the parser that will then
       decrypt and parse the packet. */
    silc_packet_receive_process(sock, conn->receive_key, conn->hmac,
				silc_client_packet_parse, client);
  }
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
  ret = silc_packet_decrypt(conn->receive_key, conn->hmac, buffer, packet);
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
  silc_buffer_clear(sock->inbuf);
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
    if (sock->protocol) {
      sock->protocol->state = SILC_PROTOCOL_STATE_FAILURE;
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);

      /* XXX We have only two protocols currently thus we know what this
	 failure indication is. */
      if (buffer->len >= 4) {
	unsigned int failure;

	SILC_GET32_MSB(failure, buffer->data);

	/* Notify application */
	client->ops->failure(client, sock->user_data, sock->protocol,
			     (void *)failure);
      }
    }
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
    if (sock->protocol) {
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
    if (sock->protocol) {

    } else {
      SILC_LOG_ERROR(("Received Key Exchange 1 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;
  case SILC_PACKET_KEY_EXCHANGE_2:
    if (sock->protocol) {
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
			     unsigned int data_len, 
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
  if (((SilcClientConnection)sock->user_data)->local_id_data)
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
  packetdata.rng = client->rng;
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
  silc_client_packet_send_real(client, sock, force_send);
}

/* Sends packet to a channel. Packet to channel is always encrypted
   differently from "normal" packets. SILC header of the packet is 
   encrypted with the next receiver's key and the rest of the packet is
   encrypted with the channel specific key. Padding and HMAC is computed
   with the next receiver's key. */

void silc_client_packet_send_to_channel(SilcClient client, 
					SilcSocketConnection sock,
					SilcChannelEntry channel,
					unsigned char *data, 
					unsigned int data_len, 
					int force_send)
{
  int i;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcBuffer payload;
  SilcPacketContext packetdata;
  SilcCipher cipher;
  SilcHmac hmac;
  unsigned char *id_string;

  SILC_LOG_DEBUG(("Sending packet to channel"));

  if (!channel || !channel->key) {
    client->ops->say(client, conn, 
		     "Cannot talk to channel: key does not exist");
    return;
  }

  /* Generate IV */
  if (!channel->iv)
    for (i = 0; i < 16; i++) channel->iv[i] = silc_rng_get_byte(client->rng);
  else
    silc_hash_make(client->md5hash, channel->iv, 16, channel->iv);

  /* Encode the channel payload */
  payload = silc_channel_payload_encode(data_len, data, 16, channel->iv, 
					client->rng);
  if (!payload) {
    client->ops->say(client, conn, 
		     "Error: Could not create packet to be sent to channel");
    return;
  }

  /* Get data used in packet header encryption, keys and stuff. Rest
     of the packet (the payload) is, however, encrypted with the 
     specified channel key. */
  cipher = conn->send_key;
  hmac = conn->hmac;
  id_string = silc_id_id2str(channel->id, SILC_ID_CHANNEL);

  /* Set the packet context pointers. The destination ID is always
     the Channel ID of the channel. Server and router will handle the
     distribution of the packet. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_CHANNEL_MESSAGE;
  packetdata.src_id = conn->local_id_data;
  packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  packetdata.src_id_type = SILC_ID_CLIENT;
  packetdata.dst_id = id_string;
  packetdata.dst_id_len = SILC_ID_CHANNEL_LEN;
  packetdata.dst_id_type = SILC_ID_CHANNEL;
  packetdata.rng = client->rng;
  packetdata.truelen = payload->len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packetdata.src_id_len + 
			   packetdata.dst_id_len,
			   packetdata.padlen,
			   payload->len);

  packetdata.buffer = sock->outbuf;

  /* Encrypt payload of the packet. This is encrypted with the channel key. */
  channel->channel_key->cipher->encrypt(channel->channel_key->context,
					payload->data, payload->data,
					payload->len - 16, /* -IV_LEN */
					channel->iv);

  /* Put the actual encrypted payload data into the buffer. */
  silc_buffer_put(sock->outbuf, payload->data, payload->len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  /* Encrypt the header and padding of the packet. This is encrypted 
     with normal session key shared with our server. */
  silc_packet_encrypt(cipher, hmac, sock->outbuf, SILC_PACKET_HEADER_LEN + 
		      packetdata.src_id_len + packetdata.dst_id_len +
		      packetdata.padlen);

  SILC_LOG_HEXDUMP(("Packet to channel, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);
  silc_buffer_free(payload);
  silc_free(id_string);
}

/* Sends private message to remote client. If private message key has
   not been set with this client then the message will be encrypted using
   normal session keys. Private messages are special packets in SILC
   network hence we need this own function for them. This is similiar
   to silc_client_packet_send_to_channel except that we send private
   message. */

void silc_client_packet_send_private_message(SilcClient client,
					     SilcSocketConnection sock,
					     SilcClientEntry client_entry,
					     unsigned char *data, 
					     unsigned int data_len, 
					     int force_send)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcBuffer buffer;
  SilcPacketContext packetdata;
  unsigned int nick_len;
  SilcCipher cipher;
  SilcHmac hmac;

  SILC_LOG_DEBUG(("Sending private message"));

  /* Create private message payload */
  nick_len = strlen(conn->nickname);
  buffer = silc_buffer_alloc(2 + nick_len + data_len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(nick_len),
		     SILC_STR_UI_XNSTRING(conn->nickname,
					  nick_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_END);

  /* If we don't have private message specific key then private messages
     are just as any normal packet thus call normal packet sending.  If
     the key exist then the encryption process is a bit different and
     will be done in the rest of this function. */
  if (!client_entry->send_key) {
    silc_client_packet_send(client, sock, SILC_PACKET_PRIVATE_MESSAGE,
			    client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			    buffer->data, buffer->len, force_send);
    goto out;
  }

  /* We have private message specific key */

  /* Get data used in the encryption */
  cipher = client_entry->send_key;
  hmac = conn->hmac;

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_PRIVATE_MESSAGE;
  packetdata.src_id = conn->local_id_data;
  packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  packetdata.src_id_type = SILC_ID_CLIENT;
  if (client_entry)
    packetdata.dst_id = silc_id_id2str(client_entry->id, SILC_ID_CLIENT);
  else
    packetdata.dst_id = conn->local_id_data;
  packetdata.dst_id_len = SILC_ID_CLIENT_LEN;
  packetdata.dst_id_type = SILC_ID_CLIENT;
  packetdata.rng = client->rng;
  packetdata.truelen = buffer->len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packetdata.src_id_len + 
			   packetdata.dst_id_len,
			   packetdata.padlen,
			   buffer->len);
  
  packetdata.buffer = sock->outbuf;

  /* Encrypt payload of the packet. Encrypt with private message specific
     key if it exist, otherwise with session key. */
  cipher->cipher->encrypt(cipher->context, buffer->data, buffer->data,
			  buffer->len, cipher->iv);
      
  /* Put the actual encrypted payload data into the buffer. */
  silc_buffer_put(sock->outbuf, buffer->data, buffer->len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  /* Encrypt the header and padding of the packet. */
  silc_packet_encrypt(cipher, hmac, sock->outbuf, SILC_PACKET_HEADER_LEN + 
		      packetdata.src_id_len + packetdata.dst_id_len +
		      packetdata.padlen);

  SILC_LOG_HEXDUMP(("Private message packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);
  silc_free(packetdata.dst_id);

 out:
  silc_free(buffer);
}     

/* Closes connection to remote end. Free's all allocated data except
   for some information such as nickname etc. that are valid at all time. */

void silc_client_close_connection(SilcClient client,
				  SilcSocketConnection sock)
{
  SilcClientConnection conn;

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(sock->sock);

  /* Unregister all tasks */
  silc_task_unregister_by_fd(client->io_queue, sock->sock);
  silc_task_unregister_by_fd(client->timeout_queue, sock->sock);

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);

  client->ops->say(client, sock->user_data,
		   "Closed connection to host %s", sock->hostname);

  /* Free everything */
  if (sock->user_data) {
    conn = (SilcClientConnection)sock->user_data;

    /* XXX Free all client entries and channel entries. */

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
    if (conn->hmac_key) {
      memset(conn->hmac_key, 0, conn->hmac_key_len);
      silc_free(conn->hmac_key);
    }
    if (conn->pending_commands)
      silc_dlist_uninit(conn->pending_commands);

    conn->sock = NULL;
    conn->remote_port = 0;
    conn->remote_type = 0;
    conn->send_key = NULL;
    conn->receive_key = NULL;
    conn->hmac = NULL;
    conn->hmac_key = NULL;
    conn->hmac_key_len = 0;
    conn->local_id = NULL;
    conn->local_id_data = NULL;
    conn->remote_host = NULL;
    conn->current_channel = NULL;
    conn->pending_commands = NULL;

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
  silc_client_close_connection(client, sock);
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

/* Called when notify is received and some async operation (such as command)
   is required before processing the notify message. This calls again the
   silc_client_notify_by_server and reprocesses the original notify packet. */

static void silc_client_notify_by_server_pending(void *context)
{
  SilcPacketContext *p = (SilcPacketContext *)context;
  silc_client_notify_by_server(p->context, p->sock, p);
}

/* Destructor for the pending command callback */

static void silc_client_notify_by_server_destructor(void *context)
{
  silc_packet_context_free((SilcPacketContext *)context);
}

/* Resolve client information from server by Client ID. */

static void silc_client_notify_by_server_resolve(SilcClient client,
						 SilcClientConnection conn,
						 SilcPacketContext *packet,
						 SilcClientID *client_id)
{
  SilcPacketContext *p = silc_packet_context_dup(packet);
  SilcBuffer idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);

  p->context = (void *)client;
  p->sock = conn->sock;

  silc_client_send_command(client, conn, SILC_COMMAND_WHOIS, ++conn->cmd_ident,
			   1, 3, idp->data, idp->len);
  silc_client_command_pending(conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			      silc_client_notify_by_server_destructor,
			      silc_client_notify_by_server_pending, p);
  silc_buffer_free(idp);
}

/* Received notify message from server */

void silc_client_notify_by_server(SilcClient client,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcNotifyPayload payload;
  SilcNotifyType type;
  SilcArgumentPayload args;

  SilcClientID *client_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcClientEntry client_entry;
  SilcClientEntry client_entry2;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcIDCacheEntry id_cache = NULL;
  unsigned char *tmp;
  unsigned int tmp_len, mode;

  payload = silc_notify_payload_parse(buffer);
  if (!payload)
    goto out;

  type = silc_notify_get_type(payload);
  args = silc_notify_get_args(payload);
  if (!args)
    goto out;

  switch(type) {
  case SILC_NOTIFY_TYPE_NONE:
    /* Notify application */
    client->ops->notify(client, conn, type, 
			silc_argument_get_arg_type(args, 1, NULL));
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    /* 
     * Someone invited me to a channel. Find Client and Channel entries
     * for the application.
     */
    
    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry and if not found query it */
    client_entry = silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* XXX Will ALWAYS fail because currently we don't have way to resolve
       channel information for channel that we're not joined to. */
    /* XXX ways to fix: use (extended) LIST command, or define the channel
       name to the notfy type when name resolving is not mandatory. */
    /* Find channel entry */
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      goto out;

    channel = (SilcChannelEntry)id_cache->context;

    /* Notify application */
    client->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    /*
     * Someone has joined to a channel. Get their ID and nickname and
     * cache them for later use.
     */

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry and if not found query it */
    client_entry = silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* If nickname or username hasn't been resolved, do so */
    if (!client_entry->nickname || !client_entry->username) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Add client to channel */
    chu = silc_calloc(1, sizeof(*chu));
    chu->client = client_entry;
    silc_list_add(channel->clients, chu);

    /* XXX add support for multiple same nicks on same channel. Check
       for them here */

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /*
     * Someone has left a channel. We will remove it from the channel but
     * we'll keep it in the cache in case we'll need it later.
     */
    
    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Remove client from channel */
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      if (chu->client == client_entry) {
	silc_list_del(channel->clients, chu);
	silc_free(chu);
	break;
      }
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /*
     * Someone left SILC. We'll remove it from all channels and from cache.
     */

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Remove from all channels */
    silc_client_remove_from_channels(client, conn, client_entry);

    /* Remove from cache */
    silc_idcache_del_by_id(conn->client_cache, SILC_ID_CLIENT, 
			   client_entry->id);

    /* Notify application */
    client->ops->notify(client, conn, type, client_entry);

    /* Free data */
    if (client_entry->nickname)
      silc_free(client_entry->nickname);
    if (client_entry->server)
      silc_free(client_entry->server);
    if (client_entry->id)
      silc_free(client_entry->id);
    if (client_entry->send_key)
      silc_cipher_free(client_entry->send_key);
    if (client_entry->receive_key)
      silc_cipher_free(client_entry->receive_key);
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /*
     * Someone set the topic on a channel.
     */

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get topic */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, tmp, channel);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    /*
     * Someone changed their nickname. If we don't have entry for the new
     * ID we will query it and return here after it's done. After we've
     * returned we fetch the old entry and free it and notify the 
     * application.
     */

    /* Get new Client ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Ignore my ID */
    if (!SILC_ID_CLIENT_COMPARE(client_id, conn->local_id))
      break;

    /* Find Client entry and if not found query it */
    client_entry2 = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry2) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }
    silc_free(client_id);

    /* Get old Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find old Client entry */
    client_entry = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Remove the old from cache */
    silc_idcache_del_by_id(conn->client_cache, SILC_ID_CLIENT, 
			   client_entry->id);

    /* Replace old ID entry with new one on all channels. */
    silc_client_replace_from_channels(client, conn, client_entry,
				      client_entry2);

    /* Notify application */
    client->ops->notify(client, conn, type, client_entry, client_entry2);

    /* Free data */
    if (client_entry->nickname)
      silc_free(client_entry->nickname);
    if (client_entry->server)
      silc_free(client_entry->server);
    if (client_entry->id)
      silc_free(client_entry->id);
    if (client_entry->send_key)
      silc_cipher_free(client_entry->send_key);
    if (client_entry->receive_key)
      silc_cipher_free(client_entry->receive_key);
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /*
     * Someone changed a channel mode
     */

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get the mode */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    SILC_GET32_MSB(mode, tmp);

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Save the new mode */
    channel->mode = mode;

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, mode, channel);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    /*
     * Someone changed user's mode on a channel
     */

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get the mode */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    SILC_GET32_MSB(mode, tmp);

    /* Get target Client ID */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (!tmp)
      goto out;

    silc_free(client_id);
    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find target Client entry */
    client_entry2 = 
      silc_idlist_get_client_by_id(client, conn, client_id);
    if (!client_entry2)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Save the mode */
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      if (chu->client == client_entry) {
	chu->mode = mode;
	break;
      }
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, mode, 
			client_entry2, channel);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /*
     * Received Message of the day
     */

    /* Get motd */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    
    /* Notify application */
    client->ops->notify(client, conn, type, tmp);
    break;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    /*
     * Router has enforced a new ID to a channel. Let's change the old
     * ID to the one provided here.
     */

    /* Get the old ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;
    
    /* Get the channel entry */
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     SILC_ID_CHANNEL, &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Free the old ID */
    silc_free(channel_id);
    silc_free(channel->id);

    /* Get the new ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    channel->id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel->id)
      goto out;

    id_cache->id = (void *)channel->id;

    /* Notify application */
    client->ops->notify(client, conn, type, channel, channel);
    break;
    
  default:
    break;
  }

 out:
  silc_notify_payload_free(payload);
  if (client_id)
    silc_free(client_id);
  if (channel_id)
    silc_free(channel_id);
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
  silc_idcache_add(conn->client_cache, conn->nickname, SILC_ID_CLIENT,
		   conn->local_id, (void *)conn->local_entry, TRUE);

  /* Notify application of successful connection. We do it here now that
     we've received the Client ID and are allowed to send traffic. */
  if (connecting)
    client->ops->connect(client, conn, TRUE);
}

/* Processed received Channel ID for a channel. This is called when client
   joins to channel and server replies with channel ID. The ID is cached. */

void silc_client_new_channel_id(SilcClient client,
				SilcSocketConnection sock,
				char *channel_name,
				unsigned int mode, SilcIDPayload idp)
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
  silc_idcache_add(conn->channel_cache, channel_name, SILC_ID_CHANNEL,
		   (void *)channel->id, (void *)channel, TRUE);
}

/* Saves channel key from encoded `key_payload'. This is used when we
   receive Channel Key Payload and when we are processing JOIN command 
   reply. */

void silc_client_save_channel_key(SilcClientConnection conn,
				  SilcBuffer key_payload, 
				  SilcChannelEntry channel)
{
  unsigned char *id_string, *key, *cipher;
  unsigned int tmp_len;
  SilcChannelID *id;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelKeyPayload payload;

  payload = silc_channel_key_payload_parse(key_payload);
  if (!payload)
    return;

  id_string = silc_channel_key_get_id(payload, &tmp_len);
  if (!id_string) {
    silc_channel_key_payload_free(payload);
    return;
  }

  id = silc_id_str2id(id_string, tmp_len, SILC_ID_CHANNEL);
  if (!id) {
    silc_channel_key_payload_free(payload);
    return;
  }

  /* Find channel. */
  if (!channel) {
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)id,
				     SILC_ID_CHANNEL, &id_cache))
      goto out;
    
    /* Get channel entry */
    channel = (SilcChannelEntry)id_cache->context;
  }

  /* Save the key */
  key = silc_channel_key_get_key(payload, &tmp_len);
  cipher = silc_channel_key_get_cipher(payload, NULL);
  channel->key_len = tmp_len;
  channel->key = silc_calloc(tmp_len, sizeof(*channel->key));
  memcpy(channel->key, key, tmp_len);

  if (!silc_cipher_alloc(cipher, &channel->channel_key)) {
    conn->client->ops->say(conn->client, conn,
		     "Cannot talk to channel: unsupported cipher %s", cipher);
    goto out;
  }
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					key, tmp_len);

  /* Client is now joined to the channel */
  channel->on_channel = TRUE;

 out:
  silc_free(id);
  silc_channel_key_payload_free(payload);
}

/* Processes received key for channel. The received key will be used
   to protect the traffic on the channel for now on. Client must receive
   the key to the channel before talking on the channel is possible. 
   This is the key that server has generated, this is not the channel
   private key, it is entirely local setting. */

void silc_client_receive_channel_key(SilcClient client,
				     SilcSocketConnection sock,
				     SilcBuffer packet)
{
  SILC_LOG_DEBUG(("Received key for channel"));

  /* Save the key */
  silc_client_save_channel_key(sock->user_data, packet, NULL);
}

/* Process received message to a channel (or from a channel, really). This
   decrypts the channel message with channel specific key and parses the
   channel payload. Finally it displays the message on the screen. */

void silc_client_channel_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcBuffer buffer = packet->buffer;
  SilcChannelPayload payload = NULL;
  SilcChannelID *id = NULL;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientID *client_id = NULL;
  int found = FALSE;

  /* Sanity checks */
  if (packet->dst_id_type != SILC_ID_CHANNEL)
    goto out;

  client_id = silc_id_str2id(packet->src_id, packet->src_id_len,
			     SILC_ID_CLIENT);
  if (!client_id)
    goto out;
  id = silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL);
  if (!id)
    goto out;

  /* Find the channel entry from channels on this connection */
  if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)id,
				   SILC_ID_CHANNEL, &id_cache))
    goto out;

  channel = (SilcChannelEntry)id_cache->context;

  /* Decrypt the channel message payload. Push the IV out of the way,
     since it is not encrypted (after pushing buffer->tail has the IV). */
  silc_buffer_push_tail(buffer, 16);
  channel->channel_key->cipher->decrypt(channel->channel_key->context,
					buffer->data, buffer->data,
					buffer->len, buffer->tail);
  silc_buffer_pull_tail(buffer, 16);

  /* Parse the channel message payload */
  payload = silc_channel_payload_parse(buffer);
  if (!payload)
    goto out;

  /* Find client entry */
  silc_list_start(channel->clients);
  while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
    if (!SILC_ID_CLIENT_COMPARE(chu->client->id, client_id)) {
      found = TRUE;
      break;
    }
  }

  /* Pass the message to application */
  client->ops->channel_message(client, conn, found ? chu->client : NULL,
			       channel, silc_channel_get_data(payload, NULL));

 out:
  if (id)
    silc_free(id);
  if (client_id)
    silc_free(client_id);
  if (payload)
    silc_channel_payload_free(payload);
}

/* Private message received. This processes the private message and
   finally displays it on the screen. */

void silc_client_private_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcBuffer buffer = packet->buffer;
  SilcIDCacheEntry id_cache;
  SilcClientID *remote_id = NULL;
  SilcClientEntry remote_client;
  unsigned short nick_len;
  unsigned char *nickname, *message = NULL;
  int ret;

  if (packet->src_id_type != SILC_ID_CLIENT)
    goto out;

  /* Get nickname */
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI16_NSTRING_ALLOC(&nickname, &nick_len),
			     SILC_STR_END);
  if (ret == -1)
    return;

  silc_buffer_pull(buffer, 2 + nick_len);

  message = silc_calloc(buffer->len + 1, sizeof(char));
  memcpy(message, buffer->data, buffer->len);

  remote_id = silc_id_str2id(packet->src_id, packet->src_id_len, 
			     SILC_ID_CLIENT);
  if (!remote_id)
    goto out;

  /* Check whether we know this client already */
  if (!silc_idcache_find_by_id_one(conn->client_cache, remote_id,
				   SILC_ID_CLIENT, &id_cache))
    {
      /* Allocate client entry */
      remote_client = silc_calloc(1, sizeof(*remote_client));
      remote_client->id = remote_id;
      silc_parse_nickname(nickname, &remote_client->nickname, 
			  &remote_client->server, &remote_client->num);
      
      /* Save the client to cache */
      silc_idcache_add(conn->client_cache, remote_client->nickname,
		       SILC_ID_CLIENT, remote_client->id, remote_client, 
		       TRUE);
    } else {
      remote_client = (SilcClientEntry)id_cache->context;
    }

  /* Pass the private message to application */
  client->ops->private_message(client, conn, remote_client, message);

  /* See if we are away (gone). If we are away we will reply to the
     sender with the set away message. */
  if (conn->away && conn->away->away) {
    /* If it's me, ignore */
    if (!SILC_ID_CLIENT_COMPARE(remote_id, conn->local_id))
      goto out;

    /* Send the away message */
    silc_client_packet_send_private_message(client, sock, remote_client,
					    conn->away->away,
					    strlen(conn->away->away), TRUE);
  }

 out:
  if (remote_id)
    silc_free(remote_id);

  if (message) {
    memset(message, 0, buffer->len);
    silc_free(message);
  }
  silc_free(nickname);
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

char *silc_client_chmode(unsigned int mode)
{
  char string[20];

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

  /* Rest of mode is ignored */

  return strdup(string);
}

/* Parses channel user mode mask and returns te mode as string */

char *silc_client_chumode(unsigned int mode)
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

char *silc_client_chumode_char(unsigned int mode)
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
