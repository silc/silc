/*

  client.c 

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

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

/* Static task callback prototypes */
SILC_TASK_CALLBACK(silc_client_connect_to_server_start);
SILC_TASK_CALLBACK(silc_client_connect_to_server_second);
SILC_TASK_CALLBACK(silc_client_connect_to_server_final);
SILC_TASK_CALLBACK(silc_client_rekey_callback);
SILC_TASK_CALLBACK(silc_client_rekey_final);

static bool silc_client_packet_parse(SilcPacketParserContext *parser_context,
				     void *context);
static void silc_client_packet_parse_type(SilcClient client, 
					  SilcSocketConnection sock,
					  SilcPacketContext *packet);
void silc_client_resolve_auth_method(bool success,
				     SilcProtocolAuthMeth auth_meth,
				     const unsigned char *auth_data,
				     SilcUInt32 auth_data_len, void *context);

/* Allocates new client object. This has to be done before client may
   work. After calling this one must call silc_client_init to initialize
   the client. The `application' is application specific user data pointer
   and caller must free it. */

SilcClient silc_client_alloc(SilcClientOperations *ops, 
			     SilcClientParams *params,
			     void *application,
			     const char *silc_version)
{
  SilcClient new_client;

  new_client = silc_calloc(1, sizeof(*new_client));
  new_client->application = application;

  new_client->internal = silc_calloc(1, sizeof(*new_client->internal));
  new_client->internal->ops = ops;
  new_client->internal->params = 
    silc_calloc(1, sizeof(*new_client->internal->params));
  new_client->internal->silc_client_version = strdup(silc_version);

  if (params)
    memcpy(new_client->internal->params, params, sizeof(*params));

  if (!new_client->internal->params->task_max)
    new_client->internal->params->task_max = 200;

  if (!new_client->internal->params->rekey_secs)
    new_client->internal->params->rekey_secs = 3600;

  if (!new_client->internal->params->connauth_request_secs)
    new_client->internal->params->connauth_request_secs = 2;

  new_client->internal->params->
    nickname_format[sizeof(new_client->internal->
			   params->nickname_format) - 1] = 0;

  return new_client;
}

/* Frees client object and its internals. */

void silc_client_free(SilcClient client)
{
  if (client) {
    if (client->rng)
      silc_rng_free(client->rng);

    silc_free(client->internal->params);
    silc_free(client->internal->silc_client_version);
    silc_free(client->internal);
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
  silc_hash_alloc("md5", &client->internal->md5hash);
  silc_hash_alloc("sha1", &client->internal->sha1hash);

  /* Initialize none cipher */
  silc_cipher_alloc("none", &client->internal->none_cipher);

  /* Initialize random number generator */
  client->rng = silc_rng_alloc();
  silc_rng_init(client->rng);
  silc_rng_global_init(client->rng);

  /* Register protocols */
  silc_client_protocols_register();

  /* Initialize the scheduler */
  client->schedule = 
    silc_schedule_init(client->internal->params->task_max ?
		       client->internal->params->task_max : 200);
  if (!client->schedule)
    return FALSE;

  /* Register commands */
  silc_client_commands_register(client);

  return TRUE;
}

/* Stops the client. This is called to stop the client and thus to stop
   the program. */

void silc_client_stop(SilcClient client)
{
  SILC_LOG_DEBUG(("Stopping client"));

  silc_schedule_stop(client->schedule);
  silc_schedule_uninit(client->schedule);

  silc_client_protocols_unregister();
  silc_client_commands_unregister(client);

  SILC_LOG_DEBUG(("Client stopped"));
}

/* Runs the client. This starts the scheduler from the utility library.
   When this functions returns the execution of the appliation is over. */

void silc_client_run(SilcClient client)
{
  SILC_LOG_DEBUG(("Running client"));

  /* Start the scheduler, the heart of the SILC client. When this returns
     the program will be terminated. */
  silc_schedule(client->schedule);
}

/* Runs the client and returns immeadiately. This function is used when
   the SILC Client object indicated by the `client' is run under some
   other scheduler, or event loop or main loop.  On GUI applications,
   for example this may be desired to use to run the client under the
   GUI application's main loop.  Typically the GUI application would
   register an idle task that calls this function multiple times in
   a second to quickly process the SILC specific data. */

void silc_client_run_one(SilcClient client)
{
  /* Run the scheduler once. */
  silc_schedule_one(client->schedule, 0);
}

static void silc_client_entry_destructor(SilcIDCache cache,
					 SilcIDCacheEntry entry)
{
  silc_free(entry->name);
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
  conn->client_cache = silc_idcache_alloc(0, SILC_ID_CLIENT, 
					  silc_client_entry_destructor);
  conn->channel_cache = silc_idcache_alloc(0, SILC_ID_CHANNEL, NULL);
  conn->server_cache = silc_idcache_alloc(0, SILC_ID_SERVER, NULL);
  conn->client = client;
  conn->remote_host = strdup(hostname);
  conn->remote_port = port;
  conn->context = context;
  conn->pending_commands = silc_dlist_init();
  conn->ftp_sessions = silc_dlist_init();

  /* Add the connection to connections table */
  for (i = 0; i < client->internal->conns_count; i++)
    if (client->internal->conns && !client->internal->conns[i]) {
      client->internal->conns[i] = conn;
      return conn;
    }

  client->internal->conns = 
    silc_realloc(client->internal->conns, sizeof(*client->internal->conns)
		 * (client->internal->conns_count + 1));
  client->internal->conns[client->internal->conns_count] = conn;
  client->internal->conns_count++;

  return conn;
}

/* Removes connection from client. Frees all memory. */

void silc_client_del_connection(SilcClient client, SilcClientConnection conn)
{
  int i;

  for (i = 0; i < client->internal->conns_count; i++)
    if (client->internal->conns[i] == conn) {

      silc_idcache_free(conn->client_cache);
      silc_idcache_free(conn->channel_cache);
      silc_idcache_free(conn->server_cache);
      if (conn->pending_commands)
	silc_dlist_uninit(conn->pending_commands);
      silc_free(conn->remote_host);
      silc_dlist_uninit(conn->ftp_sessions);
      silc_free(conn);

      client->internal->conns[i] = NULL;
    }
}

/* Adds listener socket to the listener sockets table. This function is
   used to add socket objects that are listeners to the client.  This should
   not be used to add other connection objects. */

void silc_client_add_socket(SilcClient client, SilcSocketConnection sock)
{
  int i;

  if (!client->internal->sockets) {
    client->internal->sockets = 
      silc_calloc(1, sizeof(*client->internal->sockets));
    client->internal->sockets[0] = silc_socket_dup(sock);
    client->internal->sockets_count = 1;
    return;
  }

  for (i = 0; i < client->internal->sockets_count; i++) {
    if (client->internal->sockets[i] == NULL) {
      client->internal->sockets[i] = silc_socket_dup(sock);
      return;
    }
  }

  client->internal->sockets = 
    silc_realloc(client->internal->sockets, 
		 sizeof(*client->internal->sockets) *
		 (client->internal->sockets_count + 1));
  client->internal->sockets[client->internal->sockets_count] = 
    silc_socket_dup(sock);
  client->internal->sockets_count++;
}

/* Deletes listener socket from the listener sockets table. */

void silc_client_del_socket(SilcClient client, SilcSocketConnection sock)
{
  int i;

  if (!client->internal->sockets)
    return;

  for (i = 0; i < client->internal->sockets_count; i++) {
    if (client->internal->sockets[i] == sock) {
      silc_socket_free(sock);
      client->internal->sockets[i] = NULL;
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
  sock = silc_net_create_connection_async(NULL, ctx->port, ctx->host);
  if (sock < 0)
    return -1;

  /* Register task that will receive the async connect and will
     read the result. */
  ctx->task = silc_schedule_task_add(ctx->client->schedule, sock, 
				     silc_client_connect_to_server_start,
				     (void *)ctx, 0, 0, 
				     SILC_TASK_FD,
				     SILC_TASK_PRI_NORMAL);
  silc_schedule_set_listen_fd(ctx->client->schedule, sock, SILC_TASK_WRITE);

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

  client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT, 
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

/* Socket hostname and IP lookup callback that is called before actually
   starting the key exchange.  The lookup is called from the function
   silc_client_start_key_exchange. */

static void silc_client_start_key_exchange_cb(SilcSocketConnection sock,
					      void *context)
{
  SilcClientConnection conn = (SilcClientConnection)context;
  SilcClient client = conn->client;
  SilcProtocol protocol;
  SilcClientKEInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  /* XXX We should most likely use the resolved host name instead of the
     one user provided for us. */
  silc_free(conn->sock->hostname);
  conn->sock->hostname = strdup(conn->remote_host);
  if (!conn->sock->ip)
    conn->sock->ip = strdup(conn->remote_host);
  conn->sock->port = conn->remote_port;

  /* Allocate internal Key Exchange context. This is sent to the
     protocol as context. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = silc_socket_dup(conn->sock);
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
    client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
			       "Error: Could not start key exchange protocol");
    silc_net_close_connection(conn->sock->sock);
    client->internal->ops->connect(client, conn, FALSE);
    return;
  }
  conn->sock->protocol = protocol;

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it will 
     be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)client;
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(conn->sock->sock);

  /* Execute the protocol */
  silc_protocol_execute(protocol, client->schedule, 0, 0);
}

/* Start SILC Key Exchange (SKE) protocol to negotiate shared secret
   key material between client and server.  This function can be called
   directly if application is performing its own connecting and does not
   use the connecting provided by this library. This function is normally
   used only if the application performed the connecting outside the library.
   The library however may use this internally. */

void silc_client_start_key_exchange(SilcClient client,
				    SilcClientConnection conn,
				    int fd)
{
  /* Allocate new socket connection object */
  silc_socket_alloc(fd, SILC_SOCKET_TYPE_SERVER, (void *)conn, &conn->sock);

  /* Sometimes when doing quick reconnects the new socket may be same as
     the old one and there might be pending stuff for the old socket. 
     If new one is same then those pending sutff might cause problems.
     Make sure they do not do that. */
  silc_schedule_task_del_by_fd(client->schedule, fd);

  conn->nickname = (client->nickname ? strdup(client->nickname) :
		    strdup(client->username));

  /* Resolve the remote hostname and IP address for our socket connection */
  silc_socket_host_lookup(conn->sock, FALSE, silc_client_start_key_exchange_cb,
			  conn, client->schedule);
}

/* Callback called when error has occurred during connecting to the server.
   The `connect' client operation will be called. */

SILC_TASK_CALLBACK(silc_client_connect_failure)
{
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)context;
  SilcClient client = (SilcClient)ctx->client;

  client->internal->ops->connect(client, ctx->sock->user_data, FALSE);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
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
  silc_net_get_socket_opt(fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
  if (opt != 0) {
    if (ctx->tries < 2) {
      /* Connection failed but lets try again */
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				 "Could not connect to server %s: %s",
				 ctx->host, strerror(opt));
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT, 
				 "Connecting to port %d of server %s resumed", 
				 ctx->port, ctx->host);

      /* Unregister old connection try */
      silc_schedule_unset_listen_fd(client->schedule, fd);
      silc_net_close_connection(fd);
      silc_schedule_task_del(client->schedule, ctx->task);

      /* Try again */
      silc_client_connect_to_server_internal(ctx);
      ctx->tries++;
    } else {
      /* Connection failed and we won't try anymore */
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				 "Could not connect to server %s: %s",
				 ctx->host, strerror(opt));
      silc_schedule_unset_listen_fd(client->schedule, fd);
      silc_net_close_connection(fd);
      silc_schedule_task_del(client->schedule, ctx->task);
      silc_free(ctx);

      /* Notify application of failure */
      client->internal->ops->connect(client, conn, FALSE);
      silc_client_del_connection(client, conn);
    }
    return;
  }

  silc_schedule_unset_listen_fd(client->schedule, fd);
  silc_schedule_task_del(client->schedule, ctx->task);
  silc_free(ctx);

  silc_client_start_key_exchange(client, conn, fd);
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
    silc_socket_free(ctx->sock);

    /* Notify application of failure */
    silc_schedule_task_add(client->schedule, ctx->sock->sock,
			   silc_client_connect_failure, ctx,
			   0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
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
				   ctx->ske->prop->group,
				   ctx->responder);
  silc_ske_free_key_material(ctx->keymat);

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = sock = ctx->sock;
  proto_ctx->ske = ctx->ske;	/* Save SKE object from previous protocol */
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  silc_free(ctx);
  sock->protocol = NULL;

  /* Resolve the authentication method to be used in this connection. The
     completion callback is called after the application has resolved
     the authentication method. */
  client->internal->ops->get_auth_method(client, sock->user_data, 
					 sock->hostname,
					 sock->port, 
					 silc_client_resolve_auth_method,
					 proto_ctx);
}

/* Authentication method resolving callback. Application calls this function
   after we've called the client->internal->ops->get_auth_method 
   client operation to resolve the authentication method. We will continue
   the executiong of the protocol in this function. */

void silc_client_resolve_auth_method(bool success,
				     SilcProtocolAuthMeth auth_meth,
				     const unsigned char *auth_data,
				     SilcUInt32 auth_data_len, void *context)
{
  SilcClientConnAuthInternalContext *proto_ctx =
    (SilcClientConnAuthInternalContext *)context;
  SilcClient client = (SilcClient)proto_ctx->client;

  if (!success)
    auth_meth = SILC_AUTH_NONE;

  proto_ctx->auth_meth = auth_meth;

  if (auth_data && auth_data_len) {
    proto_ctx->auth_data = silc_memdup(auth_data, auth_data_len);
    proto_ctx->auth_data_len = auth_data_len;
  }

  /* Allocate the authenteication protocol and execute it. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_CONNECTION_AUTH, 
		      &proto_ctx->sock->protocol, (void *)proto_ctx, 
		      silc_client_connect_to_server_final);

  /* Execute the protocol */
  silc_protocol_execute(proto_ctx->sock->protocol, client->schedule, 0, 0);
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
    silc_socket_free(ctx->sock);

    /* Notify application of failure */
    silc_schedule_task_add(client->schedule, ctx->sock->sock,
			   silc_client_connect_failure, ctx,
			   0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
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
  conn->remote_id_data_len = silc_id_get_len(ctx->dest_id, SILC_ID_SERVER);

  /* Register re-key timeout */
  conn->rekey->timeout = client->internal->params->rekey_secs;
  conn->rekey->context = (void *)client;
  silc_schedule_task_add(client->schedule, conn->sock->sock, 
			 silc_client_rekey_callback,
			 (void *)conn->sock, conn->rekey->timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  silc_protocol_free(protocol);
  if (ctx->auth_data)
    silc_free(ctx->auth_data);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_socket_free(ctx->sock);
  silc_free(ctx);
  conn->sock->protocol = NULL;
}

/* Internal routine that sends packet or marks packet to be sent. This
   is used directly only in special cases. Normal cases should use
   silc_server_packet_send. Returns < 0 on error. */

int silc_client_packet_send_real(SilcClient client,
				 SilcSocketConnection sock,
				 bool force_send)
{
  int ret;

  /* If rekey protocol is active we must assure that all packets are
     sent through packet queue. */
  if (SILC_CLIENT_IS_REKEY(sock))
    force_send = FALSE;

  /* If outbound data is already pending do not force send */
  if (SILC_IS_OUTBUF_PENDING(sock))
    force_send = FALSE;

  /* Send the packet */
  ret = silc_packet_send(sock, force_send);
  if (ret != -2)
    return ret;

  /* Mark that there is some outgoing data available for this connection. 
     This call sets the connection both for input and output (the input
     is set always and this call keeps the input setting, actually). 
     Actual data sending is performed by silc_client_packet_process. */
  SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(client->schedule, sock->sock);

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
    /* Do not send data to disconnected connection */
    if (SILC_IS_DISCONNECTED(sock))
      return;

    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    ret = silc_packet_send(sock, TRUE);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;

    /* Error */
    if (ret == -1)
      return;
    
    /* The packet has been sent and now it is time to set the connection
       back to only for input. When there is again some outgoing data 
       available for this connection it will be set for output as well. 
       This call clears the output setting and sets it only for input. */
    SILC_CLIENT_SET_CONNECTION_FOR_INPUT(client->schedule, fd);
    SILC_UNSET_OUTBUF_PENDING(sock);

    silc_buffer_clear(sock->outbuf);
    return;
  }

  /* Packet receiving */
  if (type == SILC_TASK_READ) {
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
	if (sock == conn->sock && sock->type != SILC_SOCKET_TYPE_CLIENT)
	  client->internal->ops->disconnect(client, conn);
	silc_client_close_connection(client, sock, conn);
	return;
      }
      
      SILC_LOG_DEBUG(("EOF from connection %d", sock->sock));
      if (sock == conn->sock && sock->type != SILC_SOCKET_TYPE_CLIENT)
	client->internal->ops->disconnect(client, conn);
      silc_client_close_connection(client, sock, conn);
      return;
    }

    /* Process the packet. This will call the parser that will then
       decrypt and parse the packet. */
    if (sock->type != SILC_SOCKET_TYPE_UNKNOWN)
      silc_packet_receive_process(sock, FALSE, conn->receive_key, 
				  conn->hmac_receive, conn->psn_receive,
				  silc_client_packet_parse, client);
    else
      silc_packet_receive_process(sock, FALSE, NULL, NULL, 0, 
				  silc_client_packet_parse, client);
  }
}

/* Parser callback called by silc_packet_receive_process. Thie merely
   registers timeout that will handle the actual parsing when appropriate. */

static bool silc_client_packet_parse(SilcPacketParserContext *parser_context,
				     void *context)
{
  SilcClient client = (SilcClient)context;
  SilcSocketConnection sock = parser_context->sock;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcPacketContext *packet = parser_context->packet;
  SilcPacketType ret;

  if (conn && conn->hmac_receive && conn->sock == sock)
    conn->psn_receive = parser_context->packet->sequence + 1;

  /* Parse the packet immediately */
  if (parser_context->normal)
    ret = silc_packet_parse(packet, conn->receive_key);
  else
    ret = silc_packet_parse_special(packet, conn->receive_key);

  if (ret == SILC_PACKET_NONE) {
    silc_packet_context_free(packet);
    silc_free(parser_context);
    return FALSE;
  }
  
  /* If protocol for this connection is key exchange or rekey then we'll
     process all packets synchronously, since there might be packets in
     queue that we are not able to decrypt without first processing the
     packets before them. */
  if ((ret == SILC_PACKET_REKEY || ret == SILC_PACKET_REKEY_DONE) ||
      (sock->protocol && sock->protocol->protocol && 
       (sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE ||
	sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY))) {

    /* Parse the incoming packet type */
    silc_client_packet_parse_type(client, sock, packet);
    silc_packet_context_free(packet);
    silc_free(parser_context);

    /* Reprocess the buffer since we'll return FALSE. This is because
       the `conn->receive_key' might have become valid by processing
       the previous packet */
    if (sock->type != SILC_SOCKET_TYPE_UNKNOWN)
      silc_packet_receive_process(sock, FALSE, conn->receive_key, 
				  conn->hmac_receive, conn->psn_receive,
				  silc_client_packet_parse, client);
    else
      silc_packet_receive_process(sock, FALSE, NULL, NULL, 0, 
				  silc_client_packet_parse, client);
    
    return FALSE;
  }

  /* Parse the incoming packet type */
  silc_client_packet_parse_type(client, sock, packet);
  silc_packet_context_free(packet);
  silc_free(parser_context);
  return TRUE;
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
    if (sock->protocol)
      silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
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
      silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange packet but no key exchange "
		      "protocol active, packet dropped."));
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
	silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
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
	silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
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
	silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
      } else {
	SilcClientKEInternalContext *proto_ctx = 
	  (SilcClientKEInternalContext *)sock->protocol->context;
	
	if (proto_ctx->packet)
	  silc_packet_context_free(proto_ctx->packet);
        if (proto_ctx->dest_id)
          silc_free(proto_ctx->dest_id);
	proto_ctx->packet = silc_packet_context_dup(packet);
	proto_ctx->dest_id_type = packet->src_id_type;
	proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_len,
					    packet->src_id_type);
	if (!proto_ctx->dest_id)
	  break;
	
	/* Let the protocol handle the packet */
	silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
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

      idp = silc_id_payload_parse(buffer->data, buffer->len);
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
      if (proto_ctx->responder == FALSE)
	silc_protocol_execute(sock->protocol, client->schedule, 0, 0);
      else
	/* Let the protocol handle the packet */
	silc_protocol_execute(sock->protocol, client->schedule, 
			      0, 100000);
    } else {
      SILC_LOG_ERROR(("Received Re-key done packet but no re-key "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /*
     * Reveived reply to our connection authentication method request
     * packet. This is used to resolve the authentication method for the
     * current session from the server if the client does not know it.
     */
    silc_client_connection_auth_request(client, sock, packet);
    break;

  case SILC_PACKET_FTP:
    /* Received file transfer packet. */
    silc_client_ftp(client, sock, packet);
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
			     SilcUInt32 data_len, 
			     int force_send)
{
  SilcPacketContext packetdata;
  const SilcBufferStruct packet;
  int block_len;
  SilcUInt32 sequence = 0;

  if (!sock)
    return;

  SILC_LOG_DEBUG(("Sending packet, type %d", type));

  /* Get data used in the packet sending, keys and stuff */
  if ((!cipher || !hmac || !dst_id) && sock->user_data) {
    if (!cipher && ((SilcClientConnection)sock->user_data)->send_key)
      cipher = ((SilcClientConnection)sock->user_data)->send_key;

    if (!hmac && ((SilcClientConnection)sock->user_data)->hmac_send)
      hmac = ((SilcClientConnection)sock->user_data)->hmac_send;

    if (!dst_id && ((SilcClientConnection)sock->user_data)->remote_id) {
      dst_id = ((SilcClientConnection)sock->user_data)->remote_id;
      dst_id_type = SILC_ID_SERVER;
    }

    if (hmac)
      sequence = ((SilcClientConnection)sock->user_data)->psn_send++;
  }

  block_len = cipher ? silc_cipher_get_block_len(cipher) : 0;

  /* Set the packet context pointers */
  packetdata.flags = 0;
  packetdata.type = type;
  if (sock->user_data && 
      ((SilcClientConnection)sock->user_data)->local_id_data) {
    packetdata.src_id = ((SilcClientConnection)sock->user_data)->local_id_data;
    packetdata.src_id_len = 
      silc_id_get_len(((SilcClientConnection)sock->user_data)->local_id,
		      SILC_ID_CLIENT);
  } else { 
    packetdata.src_id = silc_calloc(SILC_ID_CLIENT_LEN, sizeof(unsigned char));
    packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  }
  packetdata.src_id_type = SILC_ID_CLIENT;
  if (dst_id) {
    packetdata.dst_id = silc_id_id2str(dst_id, dst_id_type);
    packetdata.dst_id_len = silc_id_get_len(dst_id, dst_id_type);
    packetdata.dst_id_type = dst_id_type;
  } else {
    packetdata.dst_id = NULL;
    packetdata.dst_id_len = 0;
    packetdata.dst_id_type = SILC_ID_NONE;
  }
  data_len = SILC_PACKET_DATALEN(data_len, (SILC_PACKET_HEADER_LEN +
					    packetdata.src_id_len + 
					    packetdata.dst_id_len));
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen, block_len);

  /* Create the outgoing packet */
  if (!silc_packet_assemble(&packetdata, client->rng, cipher, hmac, sock, 
                            data, data_len, (const SilcBuffer)&packet)) {
    SILC_LOG_ERROR(("Error assembling packet"));
    return;
  }

  /* Encrypt the packet */
  if (cipher)
    silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&packet, 
                        packet.len);

  SILC_LOG_HEXDUMP(("Packet (%d), len %d", sequence, packet.len),
		   packet.data, packet.len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);
}

void silc_client_packet_queue_purge(SilcClient client,
				    SilcSocketConnection sock)
{
  if (sock && SILC_IS_OUTBUF_PENDING(sock) && 
      (SILC_IS_DISCONNECTED(sock) == FALSE)) {
    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, sock->outbuf->data - sock->outbuf->head);

    silc_packet_send(sock, TRUE);

    SILC_CLIENT_SET_CONNECTION_FOR_INPUT(client->schedule, sock->sock);
    SILC_UNSET_OUTBUF_PENDING(sock);
    silc_buffer_clear(sock->outbuf);
  }
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

  SILC_LOG_DEBUG(("Start"));

  if (!sock || (sock && conn->sock == sock))
    del = TRUE;
  if (!sock)
    sock = conn->sock;

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(client->schedule, sock->sock);

  /* Unregister all tasks */
  silc_schedule_task_del_by_fd(client->schedule, sock->sock);
  silc_schedule_task_del_by_fd(client->schedule, sock->sock);

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);

  /* Cancel any active protocol */
  if (sock->protocol) {
    if (sock->protocol->protocol->type == 
	SILC_PROTOCOL_CLIENT_KEY_EXCHANGE ||
	sock->protocol->protocol->type == 
	SILC_PROTOCOL_CLIENT_CONNECTION_AUTH) {
      sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
      silc_protocol_execute_final(sock->protocol, client->schedule);
      /* The application will recall this function with these protocols
	 (the ops->connect client operation). */
      return;
    } else {
      sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
      silc_protocol_execute_final(sock->protocol, client->schedule);
      sock->protocol = NULL;
    }
  }

  /* Free everything */
  if (del && sock->user_data) {
    /* Free all cache entries */
    SilcIDCacheList list;
    SilcIDCacheEntry entry;
    bool ret;

    if (silc_idcache_get_all(conn->client_cache, &list)) {
      ret = silc_idcache_list_first(list, &entry);
      while (ret) {
	silc_client_del_client(client, conn, entry->context);
	ret = silc_idcache_list_next(list, &entry);
      }
      silc_idcache_list_free(list);
    }

    if (silc_idcache_get_all(conn->channel_cache, &list)) {
      ret = silc_idcache_list_first(list, &entry);
      while (ret) {
	silc_client_del_channel(client, conn, entry->context);
	ret = silc_idcache_list_next(list, &entry);
      }
      silc_idcache_list_free(list);
    }

    if (silc_idcache_get_all(conn->server_cache, &list)) {
      ret = silc_idcache_list_first(list, &entry);
      while (ret) {
	silc_client_del_server(client, conn, entry->context);
	ret = silc_idcache_list_next(list, &entry);
      }
      silc_idcache_list_free(list);
    }

    /* Clear ID caches */
    if (conn->client_cache)
      silc_idcache_free(conn->client_cache);
    if (conn->channel_cache)
      silc_idcache_free(conn->channel_cache);
    if (conn->server_cache)
      silc_idcache_free(conn->server_cache);

    /* Free data (my ID is freed in above silc_client_del_client).
       conn->nickname is freed when freeing the local_entry->nickname. */
    if (conn->remote_host)
      silc_free(conn->remote_host);
    if (conn->local_id_data)
      silc_free(conn->local_id_data);
    if (conn->send_key)
      silc_cipher_free(conn->send_key);
    if (conn->receive_key)
      silc_cipher_free(conn->receive_key);
    if (conn->hmac_send)
      silc_hmac_free(conn->hmac_send);
    if (conn->hmac_receive)
      silc_hmac_free(conn->hmac_receive);
    if (conn->pending_commands)
      silc_dlist_uninit(conn->pending_commands);
    if (conn->rekey)
      silc_free(conn->rekey);

    if (conn->active_session) {
      sock->user_data = NULL;
      silc_client_ftp_session_free(conn->active_session);
      conn->active_session = NULL;
    }

    silc_client_ftp_free_sessions(client, conn);

    memset(conn, 0, sizeof(*conn));
    silc_client_del_connection(client, conn);
  }

  silc_socket_free(sock);
}

/* Called when we receive disconnection packet from server. This 
   closes our end properly and displays the reason of the disconnection
   on the screen. */

SILC_TASK_CALLBACK(silc_client_disconnected_by_server_later)
{
  SilcClient client = (SilcClient)context;
  SilcSocketConnection sock;

  SILC_CLIENT_GET_SOCK(client, fd, sock);
  if (sock == NULL)
    return;

  silc_client_close_connection(client, sock, sock->user_data);
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

  msg = silc_memdup(message->data, message->len);
  client->internal->ops->say(client, sock->user_data, 
			     SILC_CLIENT_MESSAGE_AUDIT, msg);
  silc_free(msg);

  SILC_SET_DISCONNECTED(sock);

  /* Close connection through scheduler. */
  silc_schedule_task_add(client->schedule, sock->sock, 
			 silc_client_disconnected_by_server_later,
			 client, 0, 1, SILC_TASK_TIMEOUT, 
			 SILC_TASK_PRI_NORMAL);
}

/* Received error message from server. Display it on the screen. 
   We don't take any action what so ever of the error message. */

void silc_client_error_by_server(SilcClient client,
				 SilcSocketConnection sock,
				 SilcBuffer message)
{
  char *msg;

  msg = silc_memdup(message->data, message->len);
  client->internal->ops->say(client, sock->user_data, 
			     SILC_CLIENT_MESSAGE_AUDIT, msg);
  silc_free(msg);
}

/* Auto-nicking callback to send NICK command to server. */

SILC_TASK_CALLBACK(silc_client_send_auto_nick)
{
  SilcClientConnection conn = (SilcClientConnection)context;
  SilcClient client = conn->client;

  silc_client_command_send(client, conn, SILC_COMMAND_NICK, 
			   ++conn->cmd_ident, 1, 1, 
			   client->nickname, strlen(client->nickname));
}

/* Processes the received new Client ID from server. Old Client ID is
   deleted from cache and new one is added. */

void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				SilcIDPayload idp)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  int connecting = FALSE;
  SilcClientID *client_id = silc_id_payload_get_id(idp);
  SilcBuffer sidp;

  if (!conn->local_entry)
    connecting = TRUE;

  /* Delete old ID from ID cache */
  if (conn->local_id) {
    /* Check whether they are different */
    if (SILC_ID_CLIENT_COMPARE(conn->local_id, client_id)) {
      silc_free(client_id);
      return;
    }

    silc_idcache_del_by_context(conn->client_cache, conn->local_entry);
    silc_free(conn->local_id);
  }
  
  /* Save the new ID */

  if (conn->local_id_data)
    silc_free(conn->local_id_data);

  conn->local_id = client_id;
  conn->local_id_data = silc_id_payload_get_data(idp);
  conn->local_id_data_len = silc_id_payload_get_len(idp);;

  if (!conn->local_entry)
    conn->local_entry = silc_calloc(1, sizeof(*conn->local_entry));

  conn->local_entry->nickname = conn->nickname;
  if (!conn->local_entry->username)
    conn->local_entry->username = strdup(client->username);
  if (!conn->local_entry->hostname)
    conn->local_entry->hostname = strdup(client->hostname);
  if (!conn->local_entry->server)
    conn->local_entry->server = strdup(conn->remote_host);
  conn->local_entry->id = conn->local_id;
  conn->local_entry->valid = TRUE;
  if (!conn->local_entry->channels)
    conn->local_entry->channels = silc_hash_table_alloc(1, silc_hash_ptr, 
							NULL, NULL,
							NULL, NULL, NULL, 
							TRUE);

  /* Put it to the ID cache */
  silc_idcache_add(conn->client_cache, strdup(conn->nickname), conn->local_id, 
		   (void *)conn->local_entry, 0, NULL);

  if (connecting) {
    /* Send NICK command if the nickname was set by the application (and is
       not same as the username). Send this with little timeout. */
    if (client->nickname && strcmp(client->nickname, client->username))
      silc_schedule_task_add(client->schedule, 0,
			     silc_client_send_auto_nick, conn,
			     1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

    /* Issue INFO command to fetch the real server name and server information
       and other stuff. */
    silc_client_command_register(client, SILC_COMMAND_INFO, NULL, NULL,
				 silc_client_command_reply_info_i, 0, 
				 ++conn->cmd_ident);
    sidp = silc_id_payload_encode(conn->remote_id, SILC_ID_SERVER);
    silc_client_command_send(client, conn, SILC_COMMAND_INFO,
			     conn->cmd_ident, 1, 2, sidp->data, sidp->len);
    silc_buffer_free(sidp);

    /* Notify application of successful connection. We do it here now that
       we've received the Client ID and are allowed to send traffic. */
    client->internal->ops->connect(client, conn, TRUE);
  }
}

/* Removes a client entry from all channels it has joined. */

void silc_client_remove_from_channels(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry)
{
  SilcHashTableList htl;
  SilcChannelUser chu;

  silc_hash_table_list(client_entry->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
    silc_hash_table_del(chu->client->channels, chu->channel);
    silc_hash_table_del(chu->channel->user_list, chu->client);
    silc_free(chu);
  }

  silc_hash_table_list_reset(&htl);
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
  SilcHashTableList htl;
  SilcChannelUser chu;

  silc_hash_table_list(old->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
    /* Replace client entry */
    silc_hash_table_del(chu->client->channels, chu->channel);
    silc_hash_table_del(chu->channel->user_list, chu->client);
    
    chu->client = new;
    silc_hash_table_add(chu->channel->user_list, chu->client, chu);
    silc_hash_table_add(chu->client->channels, chu->channel, chu);
  }
  silc_hash_table_list_reset(&htl);
}

/* Registers failure timeout to process the received failure packet
   with timeout. */

void silc_client_process_failure(SilcClient client,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcUInt32 failure = 0;

  if (sock->protocol) {
    if (packet->buffer->len >= 4)
      SILC_GET32_MSB(failure, packet->buffer->data);

    /* Notify application */
    client->internal->ops->failure(client, sock->user_data, sock->protocol,
				   (void *)failure);
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
  proto_ctx->sock = silc_socket_dup(sock);
  proto_ctx->responder = FALSE;
  proto_ctx->pfs = conn->rekey->pfs;
      
  /* Perform rekey protocol. Will call the final callback after the
     protocol is over. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_REKEY, 
		      &protocol, proto_ctx, silc_client_rekey_final);
  sock->protocol = protocol;
      
  /* Run the protocol */
  silc_protocol_execute(protocol, client->schedule, 0, 0);

  /* Re-register re-key timeout */
  silc_schedule_task_add(client->schedule, sock->sock, 
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
    silc_protocol_cancel(protocol, client->schedule);
    silc_protocol_free(protocol);
    sock->protocol = NULL;
    if (ctx->packet)
      silc_packet_context_free(ctx->packet);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    silc_socket_free(ctx->sock);
    silc_free(ctx);
    return;
  }

  /* Purge the outgoing data queue to assure that all rekey packets really
     go to the network before we quit the protocol. */
  silc_client_packet_queue_purge(client, sock);

  /* Cleanup */
  silc_protocol_free(protocol);
  sock->protocol = NULL;
  if (ctx->packet)
    silc_packet_context_free(ctx->packet);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_socket_free(ctx->sock);
  silc_free(ctx);
}

/* Processes incoming connection authentication method request packet.
   It is a reply to our previously sent request. The packet can be used
   to resolve the authentication method for the current session if the
   client does not know it beforehand. */

void silc_client_connection_auth_request(SilcClient client,
					 SilcSocketConnection sock,
					 SilcPacketContext *packet)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcUInt16 conn_type, auth_meth;
  int ret;

  /* If we haven't send our request then ignore this one. */
  if (!conn->connauth)
    return;

  /* Parse the payload */
  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI_SHORT(&conn_type),
			     SILC_STR_UI_SHORT(&auth_meth),
			     SILC_STR_END);
  if (ret == -1)
    auth_meth = SILC_AUTH_NONE;

  /* Call the request callback to notify application for received 
     authentication method information. */
  if (conn->connauth->callback)
    (*conn->connauth->callback)(client, conn, auth_meth,
				conn->connauth->context);

  silc_schedule_task_del(client->schedule, conn->connauth->timeout);

  silc_free(conn->connauth);
  conn->connauth = NULL;
}

/* Timeout task callback called if the server does not reply to our 
   connection authentication method request in the specified time interval. */

SILC_TASK_CALLBACK(silc_client_request_authentication_method_timeout)
{
  SilcClientConnection conn = (SilcClientConnection)context;
  SilcClient client = conn->client;

  if (!conn->connauth)
    return;

  /* Call the request callback to notify application */
  if (conn->connauth->callback)
    (*conn->connauth->callback)(client, conn, SILC_AUTH_NONE,
				conn->connauth->context);

  silc_free(conn->connauth);
  conn->connauth = NULL;
}

/* This function can be used to request the current authentication method
   from the server. This may be called when connecting to the server
   and the client library requests the authentication data from the
   application. If the application does not know the current authentication
   method it can request it from the server using this function.
   The `callback' with `context' will be called after the server has
   replied back with the current authentication method. */

void 
silc_client_request_authentication_method(SilcClient client,
					  SilcClientConnection conn,
					  SilcConnectionAuthRequest callback,
					  void *context)
{
  SilcClientConnAuthRequest connauth;
  SilcBuffer packet;

  connauth = silc_calloc(1, sizeof(*connauth));
  connauth->callback = callback;
  connauth->context = context;

  if (conn->connauth)
    silc_free(conn->connauth);

  conn->connauth = connauth;

  /* Assemble the request packet and send it to the server */
  packet = silc_buffer_alloc(4);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(SILC_SOCKET_TYPE_CLIENT),
		     SILC_STR_UI_SHORT(SILC_AUTH_NONE),
		     SILC_STR_END);
  silc_client_packet_send(client, conn->sock, 
			  SILC_PACKET_CONNECTION_AUTH_REQUEST,
			  NULL, 0, NULL, NULL, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);

  /* Register a timeout in case server does not reply anything back. */
  connauth->timeout =
    silc_schedule_task_add(client->schedule, conn->sock->sock, 
			   silc_client_request_authentication_method_timeout,
			   conn, 
			   client->internal->params->connauth_request_secs, 0,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}
