/*

  client_keyagr.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

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
/* This file includes the Key Agreement packet processing and actual
   key agreement routines. This file has nothing to do with the actual
   connection key exchange protocol, it is implemented in the client.c
   and in protocol.c. This file implements the client-to-client key 
   agreement as defined by the SILC protocol. */

#include "clientlibincludes.h"
#include "client_internal.h"

SILC_TASK_CALLBACK(silc_client_key_agreement_final);
SILC_TASK_CALLBACK(silc_client_process_key_agreement);
SILC_TASK_CALLBACK(silc_client_key_agreement_timeout);
SILC_TASK_CALLBACK(silc_client_perform_key_agreement_start);

/* Key agreement context */
struct SilcClientKeyAgreementStruct {
  SilcClient client;
  SilcClientConnection conn;
  int fd;			        /* Listening/connection socket */
  SilcSocketConnection sock;		/* Remote socket connection */
  SilcClientEntry client_entry;		/* Destination client */
  SilcKeyAgreementCallback completion;	/* Key agreement completion */
  void *context;			/* User context */
  SilcTask timeout;		        /* Timeout task */
};

/* Packet sending function used by the SKE in the key agreement process. */

static void silc_client_key_agreement_send_packet(SilcSKE ske,
						  SilcBuffer packet,
						  SilcPacketType type,
						  void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  void *tmp;

  /* Send the packet immediately. We will assure that the packet is not
     encrypted by setting the socket's user_data pointer to NULL. The
     silc_client_packet_send would take the keys (wrong keys that is,
     because user_data is the current SilcClientConnection) from it and
     we cannot allow that. The packets are never encrypted when doing SKE
     with another client. */
  tmp = ske->sock->user_data;
  ske->sock->user_data = NULL;
  silc_client_packet_send(ctx->client, ske->sock, type, NULL, 0, NULL, NULL,
			  packet->data, packet->len, TRUE);
  ske->sock->user_data = tmp;
}

/* This callback is called after the key agreement protocol has been
   performed. This calls the final completion callback for the application. */

SILC_TASK_CALLBACK(silc_client_key_agreement_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientKeyAgreement ke = (SilcClientKeyAgreement)ctx->context;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
      protocol->state == SILC_PROTOCOL_STATE_FAILURE) {
    /* Error occured during protocol */
    ke->client_entry->ke = NULL;
    ke->completion(ke->client, ke->conn, ke->client_entry, NULL, ke->context);
    silc_ske_free_key_material(ctx->keymat);
    goto out;
  }

  /* Pass the negotiated key material to the application. The application
     is responsible of freeing the key material. */
  ke->client_entry->ke = NULL;
  ke->completion(ke->client, ke->conn, ke->client_entry, ctx->keymat, 
		 ke->context);

 out:
  silc_protocol_free(protocol);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  if (ctx->dest_id)
    silc_free(ctx->dest_id);
  silc_task_unregister_by_callback(client->timeout_queue,
				   silc_client_failure_callback);
  silc_task_unregister_by_fd(client->io_queue, ke->fd);
  if (ke->timeout)
    silc_task_unregister(client->timeout_queue, ke->timeout);
  silc_socket_free(ke->sock);
  silc_free(ke);
  silc_free(ctx);
}

/* Key agreement callback that is called when remote end has initiated
   the key agreement protocol. This accepts the incoming TCP/IP connection
   for the key agreement protocol. */

SILC_TASK_CALLBACK(silc_client_process_key_agreement)
{
  SilcClientKeyAgreement ke = (SilcClientKeyAgreement)context;
  SilcClient client = ke->client;
  SilcClientConnection conn = ke->conn;
  SilcSocketConnection newsocket;
  SilcClientKEInternalContext *proto_ctx;
  int sock;

  SILC_LOG_DEBUG(("Start"));

  sock = silc_net_accept_connection(ke->fd);
  if (sock < 0) {
    client->ops->say(client, conn, 
		     "Could not accept key agreement connection: ", 
		     strerror(errno));
    ke->client_entry->ke = NULL;
    ke->completion(ke->client, ke->conn, ke->client_entry, NULL, ke->context);
    silc_task_unregister_by_fd(client->io_queue, ke->fd);
    if (ke->timeout)
      silc_task_unregister(client->timeout_queue, ke->timeout);
    silc_free(ke);
    return;
  }

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* Create socket for this connection (it is of type UNKNOWN since this
     really is not a real SILC connection. It is only for the key
     agreement protocol). */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, (void *)conn, &newsocket);
  ke->sock = newsocket;

  /* Perform name and address lookups for the remote host. */
  silc_net_check_host_by_sock(sock, &newsocket->hostname, &newsocket->ip);
  if (!newsocket->hostname && !newsocket->ip) {
    client->ops->say(client, conn, 
		     "Could not resolve the remote IP or hostname");
    ke->client_entry->ke = NULL;
    ke->completion(ke->client, ke->conn, ke->client_entry, NULL, ke->context);
    silc_task_unregister_by_fd(client->io_queue, ke->fd);
    if (ke->timeout)
      silc_task_unregister(client->timeout_queue, ke->timeout);
    silc_free(ke);
    return;
  }
  if (!newsocket->hostname)
    newsocket->hostname = strdup(newsocket->ip);
  newsocket->port = silc_net_get_remote_port(sock);

  /* Allocate internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = client;
  proto_ctx->sock = newsocket;
  proto_ctx->rng = client->rng;
  proto_ctx->responder = TRUE;
  proto_ctx->context = context;
  proto_ctx->send_packet = silc_client_key_agreement_send_packet;

  /* Prepare the connection for key exchange protocol. We allocate the
     protocol but will not start it yet. The connector will be the
     initiator of the protocol thus we will wait for initiation from 
     there before we start the protocol. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
		      &newsocket->protocol, proto_ctx, 
		      silc_client_key_agreement_final);

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it
     will be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(sock);
}

/* Timeout occured during key agreement. This means that the key agreement
   protocol was not completed in the specified timeout. We will call the 
   completion callback. */

SILC_TASK_CALLBACK(silc_client_key_agreement_timeout)
{
  SilcClientKeyAgreement ke = (SilcClientKeyAgreement)context;

  ke->client_entry->ke = NULL;
  ke->completion(ke->client, ke->conn, ke->client_entry, NULL, ke->context);

  if (ke->sock)
    silc_socket_free(ke->sock);
  ke->client_entry->ke = NULL;
  silc_free(ke);
  silc_task_unregister_by_callback(ke->client->timeout_queue,
				   silc_client_failure_callback);
  silc_task_unregister_by_fd(ke->client->io_queue, ke->fd);
}

/* Sends key agreement request to the remote client indicated by the
   `client_entry'. If the caller provides the `hostname' and the `port'
   arguments then the library will bind the client to that hostname and
   that port for the key agreement protocol. It also sends the `hostname'
   and the `port' in the key agreement packet to the remote client. This
   would indicate that the remote client may initiate the key agreement
   protocol to the `hostname' on the `port'.

   If the `hostname' and `port' is not provided then empty key agreement
   packet is sent to the remote client. The remote client may reply with
   the same packet including its hostname and port. If the library receives
   the reply from the remote client the `key_agreement' client operation
   callback will be called to verify whether the user wants to perform the
   key agreement or not. 

   NOTE: If the application provided the `hostname' and the `port' and the 
   remote side initiates the key agreement protocol it is not verified
   from the user anymore whether the protocol should be executed or not.
   By setting the `hostname' and `port' the user gives permission to
   perform the protocol (we are responder in this case).

   NOTE: If the remote side decides not to initiate the key agreement
   or decides not to reply with the key agreement packet then we cannot
   perform the key agreement at all. If the key agreement protocol is
   performed the `completion' callback with the `context' will be called.
   If remote side decides to ignore the request the `completion' will be
   called after the specified timeout, `timeout_secs'. 

   NOTE: There can be only one active key agreement for one client entry.
   Before setting new one, the old one must be finished (it is finished
   after calling the completion callback) or the function 
   silc_client_abort_key_agreement must be called. */

void silc_client_send_key_agreement(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry,
				    char *hostname,
				    int port,
				    unsigned long timeout_secs,
				    SilcKeyAgreementCallback completion,
				    void *context)
{
  SilcSocketConnection sock = conn->sock;
  SilcClientKeyAgreement ke;
  SilcBuffer buffer;

  assert(client_entry);

  if (client_entry->ke)
    return;

  /* Create the listener if hostname and port was provided */
  if (hostname && port) {
    ke = silc_calloc(1, sizeof(*ke));
    ke->fd = silc_net_create_server(port, hostname);

    if (ke->fd < 0) {
      client->ops->say(client, conn, 
		       "Cannot create listener on %s on port %d: %s", 
		       hostname, port, strerror(errno));
      completion(client, conn, client_entry, NULL, context);
      silc_free(ke);
      return;
    }

    ke->client = client;
    ke->conn = conn;
    ke->client_entry = client_entry;
    ke->completion = completion;
    ke->context = context;

    /* Add listener task to the queue. This task receives the key 
       negotiations. */
    silc_task_register(client->io_queue, ke->fd,
		       silc_client_process_key_agreement,
		       (void *)ke, 0, 0, 
		       SILC_TASK_FD,
		       SILC_TASK_PRI_NORMAL);

    /* Register a timeout task that will be executed if the connector
       will not start the key exchange protocol within the specified 
       timeout. */
    ke->timeout = 
      silc_task_register(client->timeout_queue, 0, 
			 silc_client_key_agreement_timeout,
			 (void *)ke, timeout_secs, 0, 
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
  }

  /* Encode the key agreement payload */
  buffer = silc_key_agreement_payload_encode(hostname, port);

  /* Send the key agreement packet to the client */
  silc_client_packet_send(client, sock, SILC_PACKET_KEY_AGREEMENT,
			  client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			  buffer->data, buffer->len, FALSE);
  silc_free(buffer);
}

static int 
silc_client_connect_to_client_internal(SilcClientInternalConnectContext *ctx)
{
  int sock;

  /* Create connection to server asynchronously */
  sock = silc_net_create_connection_async(ctx->port, ctx->host);
  if (sock < 0)
    return -1;

  /* Register task that will receive the async connect and will
     read the result. */
  ctx->task = silc_task_register(ctx->client->io_queue, sock, 
				 silc_client_perform_key_agreement_start,
				 (void *)ctx, 0, 0, 
				 SILC_TASK_FD,
				 SILC_TASK_PRI_NORMAL);
  silc_task_reset_iotype(ctx->task, SILC_TASK_WRITE);
  silc_schedule_set_listen_fd(sock, ctx->task->iomask);

  ctx->sock = sock;

  return sock;
}

/* Routine used by silc_client_perform_key_agreement to create connection
   to the remote client on specified port. */

static int
silc_client_connect_to_client(SilcClient client, 
			      SilcClientConnection conn, int port,
			      char *host, void *context)
{
  SilcClientInternalConnectContext *ctx;

  /* Allocate internal context for connection process. This is
     needed as we are doing async connecting. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->client = client;
  ctx->conn = conn;
  ctx->host = strdup(host);
  ctx->port = port;
  ctx->tries = 0;
  ctx->context = context;

  /* Do the actual connecting process */
  return silc_client_connect_to_client_internal(ctx);
}

/* Callback that is called after connection has been created. This actually
   starts the key agreement protocol. This is initiator function. */

SILC_TASK_CALLBACK(silc_client_perform_key_agreement_start)
{
  SilcClientInternalConnectContext *ctx =
    (SilcClientInternalConnectContext *)context;
  SilcClient client = ctx->client;
  SilcClientConnection conn = ctx->conn;
  SilcClientKeyAgreement ke = (SilcClientKeyAgreement)ctx->context;
  int opt, opt_len = sizeof(opt);

  SILC_LOG_DEBUG(("Start"));

  /* Check the socket status as it might be in error */
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
  if (opt != 0) {
    if (ctx->tries < 2) {
      /* Connection failed but lets try again */
      client->ops->say(client, conn, "Could not connect to client %s: %s",
		       ctx->host, strerror(opt));
      client->ops->say(client, conn, 
		       "Connecting to port %d of client %s resumed", 
		       ctx->port, ctx->host);

      /* Unregister old connection try */
      silc_schedule_unset_listen_fd(fd);
      silc_net_close_connection(fd);
      silc_task_unregister(client->io_queue, ctx->task);

      /* Try again */
      silc_client_connect_to_client_internal(ctx);
      ctx->tries++;
    } else {
      /* Connection failed and we won't try anymore */
      client->ops->say(client, conn, "Could not connect to client %s: %s",
		       ctx->host, strerror(opt));
      silc_schedule_unset_listen_fd(fd);
      silc_net_close_connection(fd);
      silc_task_unregister(client->io_queue, ctx->task);
      silc_free(ctx);

      /* Call the completion callback */
      ke->completion(ke->client, ke->conn, ke->client_entry, 
		     NULL, ke->context);
      silc_free(ke);
    }
    return;
  }

  silc_schedule_unset_listen_fd(fd);
  silc_task_unregister(client->io_queue, ctx->task);
  silc_free(ctx);

  ke->fd = fd;

  /* Now actually perform the key agreement protocol */
  silc_client_perform_key_agreement_fd(ke->client, ke->conn,
				       ke->client_entry, ke->fd,
				       ke->completion, ke->context);
  silc_free(ke);
}

/* Performs the actual key agreement protocol. Application may use this
   to initiate the key agreement protocol. This can be called for example
   after the application has received the `key_agreement' client operation,
   and did not return TRUE from it.

   The `hostname' is the remote hostname (or IP address) and the `port'
   is the remote port. The `completion' callback with the `context' will
   be called after the key agreement protocol.
   
   NOTE: If the application returns TRUE in the `key_agreement' client
   operation the library will automatically start the key agreement. In this
   case the application must not call this function. However, application
   may choose to just ignore the `key_agreement' client operation (and
   merely just print information about it on the screen) and call this
   function when the user whishes to do so (by, for example, giving some
   specific command). Thus, the API provides both, automatic and manual
   initiation of the key agreement. Calling this function is the manual
   initiation and returning TRUE in the `key_agreement' client operation
   is the automatic initiation. */

void silc_client_perform_key_agreement(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry,
				       char *hostname,
				       int port,
				       SilcKeyAgreementCallback completion,
				       void *context)
{
  SilcClientKeyAgreement ke;

  assert(client_entry && hostname && port);

  ke = silc_calloc(1, sizeof(*ke));
  ke->client = client;
  ke->conn = conn;
  ke->client_entry = client_entry;
  ke->completion = completion;
  ke->context = context;

  /* Connect to the remote client */
  ke->fd = silc_client_connect_to_client(client, conn, port, hostname, ke);
  if (ke->fd < 0) {
    completion(client, conn, client_entry, NULL, context);
    silc_free(ke);
    return;
  }
}

/* Same as above but application has created already the connection to 
   the remote host. The `sock' is the socket to the remote connection. 
   Application can use this function if it does not want the client library
   to create the connection. */

void silc_client_perform_key_agreement_fd(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  int sock,
					  SilcKeyAgreementCallback completion,
					  void *context)
{
  SilcClientKeyAgreement ke;
  SilcClientKEInternalContext *proto_ctx;
  SilcProtocol protocol;

  assert(client_entry);

  ke = silc_calloc(1, sizeof(*ke));
  ke->client = client;
  ke->conn = conn;
  ke->client_entry = client_entry;
  ke->fd = sock;
  ke->completion = completion;
  ke->context = context;

  /* Allocate new socket connection object */
  silc_socket_alloc(sock, SILC_SOCKET_TYPE_UNKNOWN, (void *)conn, &ke->sock);

  /* Allocate internal context for key exchange protocol. This is
     sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = client;
  proto_ctx->sock = ke->sock;
  proto_ctx->rng = client->rng;
  proto_ctx->responder = FALSE;
  proto_ctx->context = ke;
  proto_ctx->send_packet = silc_client_key_agreement_send_packet;

  /* Perform key exchange protocol. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
		      &protocol, (void *)proto_ctx,
		      silc_client_key_agreement_final);
  ke->sock->protocol = protocol;

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it will 
     be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)client;
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(sock);

  /* Execute the protocol */
  protocol->execute(client->timeout_queue, 0, protocol, sock, 0, 0);
}

/* This function can be called to unbind the hostname and the port for
   the key agreement protocol. However, this function has effect only 
   before the key agreement protocol has been performed. After it has
   been performed the library will automatically unbind the port. The 
   `client_entry' is the client to which we sent the key agreement 
   request. */

void silc_client_abort_key_agreement(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry client_entry)
{
  assert(client_entry);

  if (client_entry->ke) {
    if (client_entry->ke->sock)
      silc_socket_free(client_entry->ke->sock);
    client_entry->ke = NULL;
    silc_task_unregister_by_fd(client->io_queue, client_entry->ke->fd);
    if (client_entry->ke->timeout)
      silc_task_unregister(client->timeout_queue, 
			   client_entry->ke->timeout);
    silc_free(client_entry->ke);
  }
}

/* Callback function that is called after we've resolved the client 
   information who sent us the key agreement packet from the server.
   We actually call the key_agreement client operation now. */

static void 
silc_client_key_agreement_resolve_cb(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry *clients,
				     unsigned int clients_count,
				     void *context)
{
  SilcPacketContext *packet = (SilcPacketContext *)context;
  SilcKeyAgreementPayload payload;
  int ret;
  SilcKeyAgreementCallback completion;
  void *completion_context;

  if (!clients)
    goto out;

  /* Parse the key agreement payload */
  payload = silc_key_agreement_payload_parse(packet->buffer);
  if (!payload)
    goto out;

  /* Call the key_agreement client operation */
  ret = client->ops->key_agreement(client, conn, clients[0], 
				   silc_key_agreement_get_hostname(payload),
				   silc_key_agreement_get_port(payload),
				   &completion, &completion_context);

  /* If the user returned TRUE then we'll start the key agreement right
     here and right now. */
  if (ret == TRUE)
    silc_client_perform_key_agreement(client, conn, clients[0],
				      silc_key_agreement_get_hostname(payload),
				      silc_key_agreement_get_port(payload),
				      completion, completion_context);

  silc_key_agreement_payload_free(payload);

 out:
  silc_packet_context_free(packet);
}

/* Received Key Agreement packet from remote client. Process the packet
   and resolve the client information from the server before actually
   letting the application know that we've received this packet.  Then 
   call the key_agreement client operation and let the user decide
   whether we perform the key agreement protocol now or not. */

void silc_client_key_agreement(SilcClient client,
			       SilcSocketConnection sock,
			       SilcPacketContext *packet)
{
  SilcClientID *remote_id;

  if (packet->src_id_type != SILC_ID_CLIENT)
    return;

  remote_id = silc_id_str2id(packet->src_id, packet->src_id_len, 
			     SILC_ID_CLIENT);
  if (!remote_id)
    return;

  silc_client_get_client_by_id_resolve(client, sock->user_data, remote_id,
				       silc_client_key_agreement_resolve_cb,
				       silc_packet_context_dup(packet));
  silc_free(remote_id);
}
