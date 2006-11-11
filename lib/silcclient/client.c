/*

  client.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************** Types and definitions ***************************/

SILC_FSM_STATE(silc_client_connection_st_run);
SILC_FSM_STATE(silc_client_new_id);


/************************ Static utility functions **************************/

/* Packet engine callback to receive a packet */

static SilcBool silc_client_packet_receive(SilcPacketEngine engine,
					   SilcPacketStream stream,
					   SilcPacket packet,
					   void *callback_context,
					   void *stream_context)
{
  SilcClientConnection conn = stream_context;

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

  /* Signal packet processor thread for a new packet */
  conn->internal->new_packet = TRUE;
  silc_fsm_set_state_context(&conn->internal->packet_thread, packet);
  silc_fsm_continue_sync(&conn->internal->packet_thread);

  return TRUE;
}

/* Packet engine callback to indicate end of stream */

static void silc_client_packet_eos(SilcPacketEngine engine,
				   SilcPacketStream stream,
				   void *callback_context,
				   void *stream_context)
{
  SILC_LOG_DEBUG(("End of stream received"));
}

/* Packet engine callback to indicate error */

static void silc_client_packet_error(SilcPacketEngine engine,
				     SilcPacketStream stream,
				     SilcPacketError error,
				     void *callback_context,
				     void *stream_context)
{

}

/* Packet stream callbacks */
static SilcPacketCallbacks silc_client_stream_cbs =
{
  silc_client_packet_receive,
  silc_client_packet_eos,
  silc_client_packet_error
};

/* FSM destructor */

void silc_client_fsm_destructor(SilcFSM fsm, void *fsm_context,
				void *destructor_context)
{
  silc_fsm_free(fsm);
}


/************************** Connection's machine ****************************/

/* Start the connection's state machine.  If threads are in use the machine
   is always executed in a real thread. */

SILC_FSM_STATE(silc_client_connection_st_start)
{
  SilcClientConnection conn = fsm_context;

  /* Take scheduler for connection */
  conn->internal->schedule = silc_fsm_get_schedule(fsm);

  /*** Run connection machine */
  silc_fsm_init(&conn->internal->fsm, conn, NULL, NULL,
		conn->internal->schedule);
  silc_fsm_sema_init(&conn->internal->wait_event, &conn->internal->fsm, 0);
  silc_fsm_start_sync(&conn->internal->fsm, silc_client_connection_st_run);

  /*** Run packet processor FSM thread */
  silc_fsm_thread_init(&conn->internal->packet_thread, &conn->internal->fsm,
		       conn, silc_client_fsm_destructor, NULL, FALSE);
  silc_fsm_start_sync(&conn->internal->packet_thread,
		      silc_client_connection_st_packet);

  /* Schedule any events set in initialization */
  if (conn->internal->connect)
    SILC_FSM_SEMA_POST(&conn->internal->wait_event);
  if (conn->internal->key_exchange)
    SILC_FSM_SEMA_POST(&conn->internal->wait_event);

  /* Wait until this thread is terminated */
  return SILC_FSM_WAIT;
}

/* Connection machine main state. */

SILC_FSM_STATE(silc_client_connection_st_run)
{
  SilcClientConnection conn = fsm_context;

  /* Wait for events */
  SILC_FSM_SEMA_WAIT(&conn->internal->wait_event);

  /* Process events */

  if (conn->internal->connect) {
    SILC_LOG_DEBUG(("Event: connect"));
    conn->internal->connect = FALSE;

    /** Connect remote host */
    silc_fsm_thread_init(&conn->internal->event_thread, &conn->internal->fsm,
			 conn, NULL, NULL, FALSE);
    silc_fsm_start_sync(&conn->internal->event_thread, silc_client_st_connect);
    return SILC_FSM_CONTINUE;
  }

  if (conn->internal->key_exchange) {
    SILC_LOG_DEBUG(("Event: key exchange"));
    conn->internal->key_exchange = FALSE;

    /** Start key exchange */
    silc_fsm_thread_init(&conn->internal->event_thread, &conn->internal->fsm,
			 conn, NULL, NULL, FALSE);
    silc_fsm_start_sync(&conn->internal->event_thread,
			silc_client_st_connect_key_exchange);
    return SILC_FSM_CONTINUE;
  }

  if (conn->internal->disconnected) {
    SILC_LOG_DEBUG(("Event: disconnected"));
    conn->internal->disconnected = FALSE;

    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
#if defined(SILC_DEBUG)
  assert(FALSE);
#endif /* SILC_DEBUG */
  return SILC_FSM_CONTINUE;
}

/* Connection's packet processor main state.  Packet processor thread waits
   here for a new packet and processes received packets. */

SILC_FSM_STATE(silc_client_connection_st_packet)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;

  /* Wait for packet to arrive */
  if (!conn->internal->new_packet) {
    SILC_LOG_DEBUG(("Wait for packet"));
    return SILC_FSM_WAIT;
  }
  conn->internal->new_packet = FALSE;

  SILC_LOG_DEBUG(("Parsing %s packet", silc_get_packet_name(packet->type)));

  switch (packet->type) {

  case SILC_PACKET_PRIVATE_MESSAGE:
    /** Private message */
    silc_fsm_next(fsm, silc_client_private_message);
    break;

  case SILC_PACKET_CHANNEL_MESSAGE:
    /* Channel message */
    //    silc_client_channel_message(client, conn, packet);
    break;

  case SILC_PACKET_FTP:
    /* File transfer packet */
    //    silc_client_ftp(client, conn, packet);
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /* Received channel key */
    //    silc_client_channel_key(client, conn, packet);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /** Command reply */
    silc_fsm_next(fsm, silc_client_command_reply);
    break;

  case SILC_PACKET_NOTIFY:
    /* Notify */
    //    silc_client_notify(client, conn, packet);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /* Private message key indicator */
    //    silc_client_private_message_key(client, conn, packet);
    break;

  case SILC_PACKET_DISCONNECT:
    /* Server disconnects */
    //    silc_client_disconnect(client, conn, packet);
    break;

  case SILC_PACKET_ERROR:
    /* Error by server */
    //    silc_client_error(client, conn, packet);
    break;

  case SILC_PACKET_KEY_AGREEMENT:
    /* Key agreement */
    //    silc_client_key_agreement(client, conn, packet);
    break;

  case SILC_PACKET_COMMAND:
    /** Command packet */
    silc_fsm_next(fsm, silc_client_command);
    break;

  case SILC_PACKET_NEW_ID:
    /** New ID */
    silc_fsm_next(fsm, silc_client_new_id);

  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /* Reply to connection authentication request to resolve authentication
       method from server. */
    //    silc_client_connection_auth_request(client, conn, packet);
    break;

  default:
    silc_packet_free(packet);
    break;
  }

  return SILC_FSM_CONTINUE;
}


/*************************** Main client machine ****************************/

/* The client's main state where we wait for various events */

SILC_FSM_STATE(silc_client_st_run)
{
  SilcClient client = fsm_context;

  /* Wait for events */
  SILC_FSM_SEMA_WAIT(&client->internal->wait_event);

  /* Process events */

  if (client->internal->run_callback && client->internal->ops->running) {
    /* Call running callbcak back to application */
    client->internal->run_callback = FALSE;
    client->internal->ops->running(client, client->application);
    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
#if defined(SILC_DEBUG)
  assert(FALSE);
#endif /* SILC_DEBUG */
  return SILC_FSM_CONTINUE;
}


/**************************** Packet Processing *****************************/

/* Received new ID from server during registering to SILC network */

SILC_FSM_STATE(silc_client_new_id)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcID id;

  if (conn->local_id)
    goto out;

  SILC_LOG_DEBUG(("New ID received from server"));

  if (!silc_id_payload_parse_id(silc_buffer_data(&packet->buffer),
				silc_buffer_len(&packet->buffer), &id))
    goto out;

  /* Create local client entry */
  conn->local_entry = silc_client_add_client(client, conn,
					     (client->nickname ?
					      client->nickname :
					      client->username),
					     client->username,
					     client->realname,
					     &id.u.client_id, 0);
  if (!conn->local_entry)
    goto out;

  /* Save the ID */
  conn->local_id = &conn->local_entry->id;
  conn->local_idp = silc_buffer_copy(&packet->buffer);

  /* Save cache entry */
  silc_idcache_find_by_id_one(conn->internal->client_cache, conn->local_id,
			      &conn->internal->local_entry);

  /* Save remote ID */
  if (packet->src_id_len) {
    conn->remote_idp = silc_id_payload_encode_data(packet->src_id,
						   packet->src_id_len,
						   packet->src_id_type);
    if (!conn->remote_idp)
      goto out;
    silc_id_payload_parse_id(silc_buffer_data(conn->remote_idp),
			     silc_buffer_len(conn->remote_idp),
			     &conn->remote_id);
  }

  /* Signal connection that new ID was received so it can continue
     with the registering. */
  if (conn->internal->registering)
    silc_fsm_continue_sync(&conn->internal->event_thread);

 out:
  /** Packet processed */
  silc_packet_free(packet);
  silc_fsm_next(fsm, silc_client_connection_st_packet);
  return SILC_FSM_CONTINUE;
}


/******************************* Public API *********************************/

/* Allocates and adds new connection to the client. This adds the allocated
   connection to the connection table and returns a pointer to it. A client
   can have multiple connections to multiple servers. Every connection must
   be added to the client using this function. User data `context' may
   be sent as argument. This function is normally used only if the
   application performed the connecting outside the library. The library
   however may use this internally. */

SilcClientConnection
silc_client_add_connection(SilcClient client,
			   SilcConnectionType conn_type,
			   SilcClientConnectionParams *params,
			   SilcPublicKey public_key,
			   SilcPrivateKey private_key,
			   char *remote_host, int port,
			   SilcClientConnectCallback callback,
			   void *context)
{
  SilcClientConnection conn;
  SilcFSMThread thread;

  if (!callback)
    return NULL;

  SILC_LOG_DEBUG(("Adding new connection to %s:%d", remote_host, port));

  conn = silc_calloc(1, sizeof(*conn));
  if (!conn)
    return NULL;
  conn->internal = silc_calloc(1, sizeof(*conn->internal));
  if (!conn->internal) {
    silc_free(conn);
    return NULL;
  }

  conn->client = client;
  conn->public_key = public_key;
  conn->private_key = private_key;
  conn->remote_host = strdup(remote_host);
  conn->remote_port = port ? port : 706;
  conn->type = conn_type;
  conn->callback = callback;
  conn->context = context;
  conn->internal->client_cache =
    silc_idcache_alloc(0, SILC_ID_CLIENT, NULL, NULL);
  conn->internal->channel_cache = silc_idcache_alloc(0, SILC_ID_CHANNEL, NULL,
						     NULL);
  conn->internal->server_cache = silc_idcache_alloc(0, SILC_ID_SERVER, NULL,
						    NULL);
  conn->internal->ftp_sessions = silc_dlist_init();
  conn->internal->verbose = TRUE;
  silc_list_init(conn->internal->pending_commands,
		 struct SilcClientCommandContextStruct, next);

  if (params) {
    if (params->detach_data)
      conn->internal->params.detach_data =
	silc_memdup(params->detach_data,
		    params->detach_data_len);
    conn->internal->params.detach_data_len = params->detach_data_len;
  }

  /* Add the connection to connections list */
  //  silc_dlist_add(client->internal->conns, conn);

  /* Run the connection state machine.  If threads are in use the machine
     is always run in a real thread. */
  thread = silc_fsm_thread_alloc(&client->internal->fsm, conn,
				 silc_client_fsm_destructor, NULL,
				 client->internal->params->threads);
  if (!thread) {
    silc_client_del_connection(client, conn);
    return NULL;
  }
  silc_fsm_start_sync(thread, silc_client_connection_st_start);

  return conn;
}

/* Removes connection from client. Frees all memory. */

void silc_client_del_connection(SilcClient client, SilcClientConnection conn)
{
#if 0
  SilcClientConnection c;
  SilcIDCacheList list;
  SilcIDCacheEntry entry;
  SilcClientCommandPending *r;
  SilcBool ret;

  silc_dlist_start(client->internal->conns);
  while ((c = silc_dlist_get(client->internal->conns)) != SILC_LIST_END) {
    if (c != conn)
      continue;

    /* Free all cache entries */
    if (silc_idcache_get_all(conn->internal->client_cache, &list)) {
      ret = silc_idcache_list_first(list, &entry);
      while (ret) {
	silc_client_del_client(client, conn, entry->context);
	ret = silc_idcache_list_next(list, &entry);
      }
      silc_idcache_list_free(list);
    }

    if (silc_idcache_get_all(conn->internal->channel_cache, &list)) {
      ret = silc_idcache_list_first(list, &entry);
      while (ret) {
	silc_client_del_channel(client, conn, entry->context);
	ret = silc_idcache_list_next(list, &entry);
      }
      silc_idcache_list_free(list);
    }

    if (silc_idcache_get_all(conn->internal->server_cache, &list)) {
      ret = silc_idcache_list_first(list, &entry);
      while (ret) {
	silc_client_del_server(client, conn, entry->context);
	ret = silc_idcache_list_next(list, &entry);
      }
      silc_idcache_list_free(list);
    }

    /* Clear ID caches */
    if (conn->internal->client_cache)
      silc_idcache_free(conn->internal->client_cache);
    if (conn->internal->channel_cache)
      silc_idcache_free(conn->internal->channel_cache);
    if (conn->internal->server_cache)
      silc_idcache_free(conn->internal->server_cache);

    /* Free data (my ID is freed in above silc_client_del_client).
       conn->nickname is freed when freeing the local_entry->nickname. */
    silc_free(conn->remote_host);
    silc_free(conn->local_id_data);
    if (conn->internal->send_key)
      silc_cipher_free(conn->internal->send_key);
    if (conn->internal->receive_key)
      silc_cipher_free(conn->internal->receive_key);
    if (conn->internal->hmac_send)
      silc_hmac_free(conn->internal->hmac_send);
    if (conn->internal->hmac_receive)
      silc_hmac_free(conn->internal->hmac_receive);
    silc_free(conn->internal->rekey);

    if (conn->internal->active_session) {
      if (conn->sock)
	conn->sock->user_data = NULL;
      silc_client_ftp_session_free(conn->internal->active_session);
      conn->internal->active_session = NULL;
    }

    silc_client_ftp_free_sessions(client, conn);

    if (conn->internal->pending_commands) {
      silc_dlist_start(conn->internal->pending_commands);
      while ((r = silc_dlist_get(conn->internal->pending_commands))
	     != SILC_LIST_END)
	silc_dlist_del(conn->internal->pending_commands, r);
      silc_dlist_uninit(conn->internal->pending_commands);
    }

    silc_free(conn->internal);
    memset(conn, 0, sizeof(*conn));
    silc_free(conn);

    silc_dlist_del(client->internal->conns, conn);
  }
#endif /* 0 */
}

/* Connects to remote server. This is the main routine used to connect
   to remote SILC server. Returns FALSE on error. */

void silc_client_connect_to_server(SilcClient client,
				   SilcClientConnectionParams *params,
				   SilcPublicKey public_key,
				   SilcPrivateKey private_key,
				   char *remote_host, int port,
				   SilcClientConnectCallback callback,
				   void *context)
{
  SilcClientConnection conn;

  if (!client || !remote_host)
    return;

  /* Add new connection */
  conn = silc_client_add_connection(client, SILC_CONN_SERVER, params,
				    public_key, private_key, remote_host,
				    port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, context);
    return;
  }

  client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT,
			     "Connecting to port %d of server %s",
			     port, remote_host);

  /* Signal connection machine to start connecting */
  conn->internal->connect = TRUE;
}

/* Start SILC Key Exchange (SKE) protocol to negotiate shared secret
   key material between client and server.  This function can be called
   directly if application is performing its own connecting and does not
   use the connecting provided by this library. This function is normally
   used only if the application performed the connecting outside the library.
   The library however may use this internally. */

void silc_client_start_key_exchange(SilcClient client,
				    SilcClientConnection conn,
				    SilcStream stream)
{
#if 0
  assert(conn && stream);
  assert(client->public_key);
  assert(client->private_key);

  conn->nickname = (client->nickname ? strdup(client->nickname) :
		    strdup(client->username));
#endif /* 0 */

  /* Start */

}

#if 0
/* Authentication method resolving callback. Application calls this function
   after we've called the client->internal->ops->get_auth_method
   client operation to resolve the authentication method. We will continue
   the executiong of the protocol in this function. */

void silc_client_resolve_auth_method(SilcBool success,
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

  if (success && auth_data && auth_data_len) {

    /* Passphrase must be UTF-8 encoded, if it isn't encode it */
    if (auth_meth == SILC_AUTH_PASSWORD &&
	!silc_utf8_valid(auth_data, auth_data_len)) {
      int payload_len = 0;
      unsigned char *autf8 = NULL;
      payload_len = silc_utf8_encoded_len(auth_data, auth_data_len,
					  SILC_STRING_ASCII);
      autf8 = silc_calloc(payload_len, sizeof(*autf8));
      auth_data_len = silc_utf8_encode(auth_data, auth_data_len,
				       SILC_STRING_ASCII, autf8, payload_len);
      auth_data = autf8;
    }

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
    ctx->status = SILC_CLIENT_CONN_ERROR_AUTH;
    goto err;
  }

  if (conn->internal->params.detach_data) {
    /* Send RESUME_CLIENT packet to the server, which is used to resume
       old detached session back. */
    SilcBuffer auth;
    SilcClientID *old_client_id;
    unsigned char *old_id;
    SilcUInt16 old_id_len;

    if (!silc_client_process_detach_data(client, conn, &old_id, &old_id_len)) {
      ctx->status = SILC_CLIENT_CONN_ERROR_RESUME;
      goto err;
    }

    old_client_id = silc_id_str2id(old_id, old_id_len, SILC_ID_CLIENT);
    if (!old_client_id) {
      silc_free(old_id);
      ctx->status = SILC_CLIENT_CONN_ERROR_RESUME;
      goto err;
    }

    /* Generate authentication data that server will verify */
    auth = silc_auth_public_key_auth_generate(client->public_key,
					      client->private_key,
					      client->rng,
					      conn->internal->hash,
					      old_client_id, SILC_ID_CLIENT);
    if (!auth) {
      silc_free(old_client_id);
      silc_free(old_id);
      ctx->status = SILC_CLIENT_CONN_ERROR_RESUME;
      goto err;
    }

    packet = silc_buffer_alloc_size(2 + old_id_len + auth->len);
    silc_buffer_format(packet,
		       SILC_STR_UI_SHORT(old_id_len),
		       SILC_STR_UI_XNSTRING(old_id, old_id_len),
		       SILC_STR_UI_XNSTRING(auth->data, auth->len),
		       SILC_STR_END);

    /* Send the packet */
    silc_client_packet_send(client, ctx->sock, SILC_PACKET_RESUME_CLIENT,
			    NULL, 0, NULL, NULL,
			    packet->data, packet->len, TRUE);
    silc_buffer_free(packet);
    silc_buffer_free(auth);
    silc_free(old_client_id);
    silc_free(old_id);
  } else {
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
  }

  /* Save remote ID. */
  conn->remote_id = ctx->dest_id;
  conn->remote_id_data = silc_id_id2str(ctx->dest_id, SILC_ID_SERVER);
  conn->remote_id_data_len = silc_id_get_len(ctx->dest_id, SILC_ID_SERVER);

  /* Register re-key timeout */
  conn->internal->rekey->timeout = client->internal->params->rekey_secs;
  conn->internal->rekey->context = (void *)client;
  silc_schedule_task_add(client->schedule, conn->sock->sock,
			 silc_client_rekey_callback,
			 (void *)conn->sock, conn->internal->rekey->timeout, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  silc_protocol_free(protocol);
  silc_free(ctx->auth_data);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  silc_socket_free(ctx->sock);
  silc_free(ctx);
  conn->sock->protocol = NULL;
  return;

 err:
  silc_protocol_free(protocol);
  silc_free(ctx->auth_data);
  silc_free(ctx->dest_id);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  conn->sock->protocol = NULL;
  silc_socket_free(ctx->sock);

  /* Notify application of failure */
  silc_schedule_task_add(client->schedule, ctx->sock->sock,
			 silc_client_connect_failure_auth, ctx,
			 0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
}

/* Packet processing callback. This is used to send and receive packets
   from network. This is generic task. */

SILC_TASK_CALLBACK_GLOBAL(silc_client_packet_process)
{
  SilcClient client = (SilcClient)context;
  SilcClientConnection conn = NULL;
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
	  client->internal->ops->disconnected(client, conn, 0, NULL);
	silc_client_close_connection_real(client, sock, conn);
	return;
      }

      SILC_LOG_DEBUG(("EOF from connection %d", sock->sock));
      if (sock == conn->sock && sock->type != SILC_SOCKET_TYPE_CLIENT)
	client->internal->ops->disconnected(client, conn, 0, NULL);
      silc_client_close_connection_real(client, sock, conn);
      return;
    }

    /* Process the packet. This will call the parser that will then
       decrypt and parse the packet. */
    if (sock->type != SILC_SOCKET_TYPE_UNKNOWN)
      silc_packet_receive_process(sock, FALSE, conn->internal->receive_key,
				  conn->internal->hmac_receive,
				  conn->internal->psn_receive,
				  silc_client_packet_parse, client);
    else
      silc_packet_receive_process(sock, FALSE, NULL, NULL, 0,
				  silc_client_packet_parse, client);
  }
}

/* Parser callback called by silc_packet_receive_process. Thie merely
   registers timeout that will handle the actual parsing when appropriate. */

static SilcBool silc_client_packet_parse(SilcPacketParserContext *parser_context,
				     void *context)
{
  SilcClient client = (SilcClient)context;
  SilcClientConnection conn = parser_context->sock;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcPacketContext *packet = parser_context->packet;
  SilcPacketType ret;

  if (conn && conn->internal->hmac_receive && conn->sock == sock)
    conn->internal->psn_receive = parser_context->packet->sequence + 1;

  /* Parse the packet immediately */
  if (parser_context->normal)
    ret = silc_packet_parse(packet, conn->internal->receive_key);
  else
    ret = silc_packet_parse_special(packet, conn->internal->receive_key);

  if (ret == SILC_PACKET_NONE) {
    silc_packet_context_free(packet);
    silc_free(parser_context);
    return FALSE;
  }

  /* If protocol for this connection is key exchange or rekey then we'll
     process all packets synchronously, since there might be packets in
     queue that we are not able to decrypt without first processing the
     packets before them. */
  if (sock->protocol && sock->protocol->protocol &&
      (sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE ||
       sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)) {

    /* Parse the incoming packet type */
    silc_client_packet_parse_type(client, sock, packet);

    /* Reprocess the buffer since we'll return FALSE. This is because
       the `conn->internal->receive_key' might have become valid by processing
       the previous packet */
    if (sock->type != SILC_SOCKET_TYPE_UNKNOWN)
      silc_packet_receive_process(sock, FALSE, conn->internal->receive_key,
				  conn->internal->hmac_receive,
				  conn->internal->psn_receive,
				  silc_client_packet_parse, client);
    else
      silc_packet_receive_process(sock, FALSE, NULL, NULL, 0,
				  silc_client_packet_parse, client);

    silc_packet_context_free(packet);
    silc_free(parser_context);

    return FALSE;
  }

  /* Parse the incoming packet type */
  silc_client_packet_parse_type(client, sock, packet);
  silc_packet_context_free(packet);
  silc_free(parser_context);
  return TRUE;
}
#endif /* 0 */

/* Closes connection to remote end. Free's all allocated data except
   for some information such as nickname etc. that are valid at all time.
   If the `sock' is NULL then the conn->sock will be used.  If `sock' is
   provided it will be checked whether the sock and `conn->sock' are the
   same (they can be different, ie. a socket can use `conn' as its
   connection but `conn->sock' might be actually a different connection
   than the `sock'). */

#if 0
void silc_client_close_connection_real(SilcClient client,
				       SilcClientConnection conn)
{
  int del = FALSE;

  SILC_LOG_DEBUG(("Start"));

  if (!sock && !conn)
    return;

  if (!sock || (sock && conn->sock == sock))
    del = TRUE;
  if (!sock)
    sock = conn->sock;

  if (!sock) {
    if (del && conn)
      silc_client_del_connection(client, conn);
    return;
  }

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(client->schedule, sock->sock);

  /* Unregister all tasks */
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
	 (the ops->connected client operation). */
      return;
    } else {
      sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
      silc_protocol_execute_final(sock->protocol, client->schedule);
      sock->protocol = NULL;
    }
  }

  /* Free everything */
  if (del && sock->user_data)
    silc_client_del_connection(client, conn);

  silc_socket_free(sock);
}

/* Closes the connection to the remote end */

void silc_client_close_connection(SilcClient client,
				  SilcClientConnection conn)
{
  //  silc_client_close_connection_real(client, NULL, conn);
}

/* Called when we receive disconnection packet from server. This
   closes our end properly and displays the reason of the disconnection
   on the screen. */

void silc_client_disconnect(SilcClient client,
			    SilcClientConnection conn,
			    SilcBuffer packet)
{
  SilcClientConnection conn;
  SilcStatus status;
  char *message = NULL;

  SILC_LOG_DEBUG(("Server disconnected us, sock %d", sock->sock));

  if (packet->len < 1)
    return;

  status = (SilcStatus)packet->data[0];

  if (packet->len > 1 &&
      silc_utf8_valid(packet->data + 1, packet->len - 1))
    message = silc_memdup(packet->data + 1, packet->len - 1);

  conn = (SilcClientConnection)sock->user_data;
  if (sock == conn->sock && sock->type != SILC_SOCKET_TYPE_CLIENT)
    client->internal->ops->disconnected(client, conn, status, message);

  silc_free(message);

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
				 SilcClientConnection conn,
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
  if (client)
    silc_client_command_send(client, conn, SILC_COMMAND_NICK,
			     ++conn->cmd_ident, 1, 1,
			     client->nickname, strlen(client->nickname));
}

/* Client session resuming callback.  If the session was resumed
   this callback is called after the resuming is completed.  This
   will call the `connect' client operation to the application
   since it has not been called yet. */

static void silc_client_resume_session_cb(SilcClient client,
					  SilcClientConnection conn,
					  SilcBool success,
					  void *context)
{
  SilcBuffer sidp;

  /* Notify application that connection is created to server */
  client->internal->ops->connected(client, conn, success ?
				   SILC_CLIENT_CONN_SUCCESS_RESUME :
				   SILC_CLIENT_CONN_ERROR_RESUME);

  if (success) {
    /* Issue INFO command to fetch the real server name and server
       information and other stuff. */
    silc_client_command_register(client, SILC_COMMAND_INFO, NULL, NULL,
				 silc_client_command_reply_info_i, 0,
				 ++conn->cmd_ident);
    sidp = silc_id_payload_encode(conn->remote_id, SILC_ID_SERVER);
    silc_client_command_send(client, conn, SILC_COMMAND_INFO,
			     conn->cmd_ident, 1, 2, sidp->data, sidp->len);
    silc_buffer_free(sidp);
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
				 SilcClientConnection conn,
				 SilcPacketContext *packet)
{
  SilcUInt32 failure = 0;

  if (sock->protocol) {
    if (packet->buffer->len >= 4)
      SILC_GET32_MSB(failure, packet->buffer->data);

    /* Notify application */
    client->internal->ops->failure(client, sock->user_data, sock->protocol,
				   SILC_32_TO_PTR(failure));
  }
}

/* A timeout callback for the re-key. We will be the initiator of the
   re-key protocol. */

SILC_TASK_CALLBACK_GLOBAL(silc_client_rekey_callback)
{
  SilcClientConnection conn = (SilcSocketConnection)context;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcClient client = (SilcClient)conn->internal->rekey->context;
  SilcProtocol protocol;
  SilcClientRekeyInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  /* If rekey protocol is active already wait for it to finish */
  if (sock->protocol && sock->protocol->protocol &&
      sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)
    return;

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = silc_socket_dup(sock);
  proto_ctx->responder = FALSE;
  proto_ctx->pfs = conn->internal->rekey->pfs;

  /* Perform rekey protocol. Will call the final callback after the
     protocol is over. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_REKEY,
		      &protocol, proto_ctx, silc_client_rekey_final);
  sock->protocol = protocol;

  /* Run the protocol */
  silc_protocol_execute(protocol, client->schedule, 0, 0);
}

/* The final callback for the REKEY protocol. This will actually take the
   new key material into use. */

SILC_TASK_CALLBACK(silc_client_rekey_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientRekeyInternalContext *ctx =
    (SilcClientRekeyInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientConnection conn = ctx->sock;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;

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

  /* Re-register re-key timeout */
  if (ctx->responder == FALSE)
    silc_schedule_task_add(client->schedule, sock->sock,
			   silc_client_rekey_callback,
			   sock, conn->internal->rekey->timeout, 0,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

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
					 SilcClientConnection conn,
					 SilcPacketContext *packet)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcUInt16 conn_type, auth_meth;
  int ret;

  /* If we haven't send our request then ignore this one. */
  if (!conn->internal->connauth)
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
  if (conn->internal->connauth->callback)
    (*conn->internal->connauth->callback)(client, conn, auth_meth,
					  conn->internal->connauth->context);

  silc_schedule_task_del(client->schedule, conn->internal->connauth->timeout);

  silc_free(conn->internal->connauth);
  conn->internal->connauth = NULL;
}

/* Timeout task callback called if the server does not reply to our
   connection authentication method request in the specified time interval. */

SILC_TASK_CALLBACK(silc_client_request_authentication_method_timeout)
{
  SilcClientConnection conn = (SilcClientConnection)context;
  SilcClient client = conn->client;

  if (!conn->internal->connauth)
    return;

  /* Call the request callback to notify application */
  if (conn->internal->connauth->callback)
    (*conn->internal->connauth->callback)(client, conn, SILC_AUTH_NONE,
					  conn->internal->connauth->context);

  silc_free(conn->internal->connauth);
  conn->internal->connauth = NULL;
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

  assert(client && conn);
  connauth = silc_calloc(1, sizeof(*connauth));
  connauth->callback = callback;
  connauth->context = context;

  if (conn->internal->connauth)
    silc_free(conn->internal->connauth);

  conn->internal->connauth = connauth;

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
#endif /* 0 */


/******************************* Client API *********************************/

/* Allocates new client object. This has to be done before client may
   work. After calling this one must call silc_client_init to initialize
   the client. The `application' is application specific user data pointer
   and caller must free it. */

SilcClient silc_client_alloc(SilcClientOperations *ops,
			     SilcClientParams *params,
			     void *application,
			     const char *version_string)
{
  SilcClient new_client;

  new_client = silc_calloc(1, sizeof(*new_client));
  new_client->application = application;

  new_client->internal = silc_calloc(1, sizeof(*new_client->internal));
  new_client->internal->ops = ops;
  new_client->internal->params =
    silc_calloc(1, sizeof(*new_client->internal->params));
  if (!version_string)
    version_string = silc_version_string;
  new_client->internal->silc_client_version = strdup(version_string);

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

    if (!client->internal->params->dont_register_crypto_library) {
      silc_cipher_unregister_all();
      silc_pkcs_unregister_all();
      silc_hash_unregister_all();
      silc_hmac_unregister_all();
    }

    silc_hash_free(client->md5hash);
    silc_hash_free(client->sha1hash);
    silc_hmac_free(client->internal->md5hmac);
    silc_hmac_free(client->internal->sha1hmac);
    silc_free(client->internal->params);
    silc_free(client->internal->silc_client_version);
    silc_free(client->internal);
    silc_free(client);
  }
}

/* Initializes the client. This makes all the necessary steps to make
   the client ready to be run. One must call silc_client_run to run the
   client. Returns FALSE if error occured, TRUE otherwise. */

SilcBool silc_client_init(SilcClient client)
{
  SILC_LOG_DEBUG(("Initializing client"));

  assert(client);
  assert(client->username);
  assert(client->hostname);
  assert(client->realname);

  /* Validate essential strings */
  if (client->nickname)
    if (!silc_identifier_verify(client->nickname, strlen(client->nickname),
				SILC_STRING_UTF8, 128)) {
      SILC_LOG_ERROR(("Malformed nickname '%s'", client->nickname));
      return FALSE;
    }
  if (!silc_identifier_verify(client->username, strlen(client->username),
			      SILC_STRING_UTF8, 128)) {
    SILC_LOG_ERROR(("Malformed username '%s'", client->username));
    return FALSE;
  }
  if (!silc_identifier_verify(client->hostname, strlen(client->hostname),
			      SILC_STRING_UTF8, 256)) {
    SILC_LOG_ERROR(("Malformed hostname '%s'", client->hostname));
    return FALSE;
  }
  if (!silc_utf8_valid(client->realname, strlen(client->realname))) {
    SILC_LOG_ERROR(("Malformed realname '%s'", client->realname));
    return FALSE;
  }

  if (!client->internal->params->dont_register_crypto_library) {
    /* Initialize the crypto library.  If application has done this already
       this has no effect.  Also, we will not be overriding something
       application might have registered earlier. */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
  }

  /* Initialize hash functions for client to use */
  silc_hash_alloc("md5", &client->md5hash);
  silc_hash_alloc("sha1", &client->sha1hash);

  /* Initialize random number generator */
  client->rng = silc_rng_alloc();
  silc_rng_init(client->rng);
  silc_rng_global_init(client->rng);

  /* Initialize the scheduler */
  client->schedule =
    silc_schedule_init(client->internal->params->task_max ?
		       client->internal->params->task_max : 200, client);
  if (!client->schedule)
    return FALSE;

  /* Start packet engine */
  client->internal->packet_engine =
    silc_packet_engine_start(client->rng, FALSE, &silc_client_stream_cbs,
			     client);
  if (!client->internal->packet_engine)
    return FALSE;

  /* Initialize FSM */
  if (!silc_fsm_init(&client->internal->fsm, client, NULL, NULL,
		     client->schedule))
    return FALSE;
  silc_fsm_sema_init(&client->internal->wait_event, &client->internal->fsm, 0);

  /* Allocate client lock */
  silc_mutex_alloc(&client->internal->lock);

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

  silc_client_commands_unregister(client);

  SILC_LOG_DEBUG(("Client stopped"));
}

/* Starts the SILC client FSM machine and blocks here.  When this returns
   the client has ended. */

void silc_client_run(SilcClient client)
{
  SILC_LOG_DEBUG(("Starting SILC client"));

  /* Start the client */
  silc_fsm_start_sync(&client->internal->fsm, silc_client_st_run);

  /* Signal the application when we are running */
  client->internal->run_callback = TRUE;
  SILC_FSM_SEMA_POST(&client->internal->wait_event);

  /* Run the scheduler */
  silc_schedule(client->schedule);
}

/* Call scheduler one iteration and return.  This cannot be called if threads
   are in use. */

void silc_client_run_one(SilcClient client)
{
  silc_schedule_one(client->schedule, -1);
}
