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


/************************ Static utility functions **************************/

/* Connection machine FSM destructor.  This will finish the thread where
   the machine was running and deletes the connection context. */

static void silc_client_connection_destructor(SilcFSM fsm,
					      void *fsm_context,
					      void *destructor_context)
{
  SilcClientConnection conn = fsm_context;
  SilcFSMThread thread = destructor_context;

  /* Delete connection */
  silc_client_del_connection(conn->client, conn);

  /* Finish the thread were this machine was running */
  silc_fsm_finish(thread);
}

/* Packet FSM thread destructor */

static void silc_client_packet_destructor(SilcFSMThread thread,
					  void *thread_context,
					  void *destructor_context)
{
  SilcClientConnection conn = thread_context;

  /* Add thread back to thread pool */
  silc_list_add(conn->internal->thread_pool, thread);
  if (silc_list_count(conn->internal->thread_pool) == 1)
    silc_list_start(conn->internal->thread_pool);
}

/* Packet engine callback to receive a packet */

static SilcBool silc_client_packet_receive(SilcPacketEngine engine,
					   SilcPacketStream stream,
					   SilcPacket packet,
					   void *callback_context,
					   void *stream_context)
{
  SilcClientConnection conn = stream_context;
  SilcFSMThread thread;

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

  /* Get packet processing thread */
  thread = silc_list_get(conn->internal->thread_pool);
  if (!thread) {
    thread = silc_fsm_thread_alloc(&conn->internal->fsm, conn,
				   silc_client_packet_destructor, NULL, FALSE);
    if (!thread)
      return FALSE;
  } else {
    silc_list_del(conn->internal->thread_pool, thread);
    silc_fsm_thread_init(thread, &conn->internal->fsm, conn,
			 silc_client_packet_destructor, NULL, FALSE);
  }

  /* Process packet in thread */
  silc_fsm_set_state_context(thread, packet);
  silc_fsm_start_sync(thread, silc_client_connection_st_packet);

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
  SilcFSM connfsm;

  /* Take scheduler for connection */
  conn->internal->schedule = silc_fsm_get_schedule(fsm);

  /*** Run connection machine */
  connfsm = &conn->internal->fsm;
  silc_fsm_init(connfsm, conn, silc_client_connection_destructor,
		fsm, conn->internal->schedule);
  silc_fsm_sema_init(&conn->internal->wait_event, connfsm, 0);
  silc_fsm_start_sync(connfsm, silc_client_connection_st_run);

  /* Schedule any events set in initialization */
  if (conn->internal->connect)
    SILC_FSM_SEMA_POST(&conn->internal->wait_event);
  if (conn->internal->key_exchange)
    SILC_FSM_SEMA_POST(&conn->internal->wait_event);

  /* Wait until this thread is terminated from the machine destructor */
  return SILC_FSM_WAIT;
}

/* Connection machine main state.  This handles various connection related
   events, but not packet processing.  It's done in dedicated packet
   processing FSM thread. */

SILC_FSM_STATE(silc_client_connection_st_run)
{
  SilcClientConnection conn = fsm_context;
  SilcFSMThread thread;

  /* Wait for events */
  SILC_FSM_SEMA_WAIT(&conn->internal->wait_event);

  /* Process events */
  thread = &conn->internal->event_thread;

  if (conn->internal->connect) {
    SILC_LOG_DEBUG(("Event: connect"));
    conn->internal->connect = FALSE;

    /*** Event: connect */
    silc_fsm_thread_init(thread, &conn->internal->fsm, conn,
			 NULL, NULL, FALSE);
    silc_fsm_start_sync(thread, silc_client_st_connect);
    return SILC_FSM_CONTINUE;
  }

  if (conn->internal->key_exchange) {
    SILC_LOG_DEBUG(("Event: key exchange"));
    conn->internal->key_exchange = FALSE;

    /*** Event: key exchange */
    silc_fsm_thread_init(thread, &conn->internal->fsm, conn,
			 NULL, NULL, FALSE);
    silc_fsm_start_sync(thread, silc_client_st_connect_set_stream);
    return SILC_FSM_CONTINUE;
  }

  if (conn->internal->disconnected) {
    /** Event: disconnected */
    SILC_LOG_DEBUG(("Event: disconnected"));
    conn->internal->disconnected = FALSE;
    silc_fsm_next(fsm, silc_client_connection_st_close);
    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
  SILC_ASSERT(FALSE);
  return SILC_FSM_CONTINUE;
}

/* Packet processor thread.  Each incoming packet is processed in FSM
   thread in this state.  The thread is run in the connection machine. */

SILC_FSM_STATE(silc_client_connection_st_packet)
{
  SilcPacket packet = state_context;

  SILC_LOG_DEBUG(("Parsing %s packet", silc_get_packet_name(packet->type)));

  switch (packet->type) {

  case SILC_PACKET_PRIVATE_MESSAGE:
    /** Private message */
    silc_fsm_next(fsm, silc_client_private_message);
    break;

  case SILC_PACKET_CHANNEL_MESSAGE:
    /** Channel message */
    silc_fsm_next(fsm, silc_client_channel_message);
    break;

  case SILC_PACKET_FTP:
    /* File transfer packet */
    //    silc_client_ftp(client, conn, packet);
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /** Channel key */
    silc_fsm_next(fsm, silc_client_channel_key);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /** Command reply */
    silc_fsm_next(fsm, silc_client_command_reply);
    break;

  case SILC_PACKET_NOTIFY:
    /** Notify */
    silc_fsm_next(fsm, silc_client_notify);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /* Private message key indicator */
    silc_fsm_next(fsm, silc_client_private_message_key);
    break;

  case SILC_PACKET_DISCONNECT:
    /** Disconnect */
    silc_fsm_next(fsm, silc_client_disconnect);
    break;

  case SILC_PACKET_ERROR:
    /* Error by server */
    silc_fsm_next(fsm, silc_client_error);
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
    break;

  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /* Reply to connection authentication request to resolve authentication
       method from server. */
    //    silc_client_connection_auth_request(client, conn, packet);
    break;

  default:
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
    break;
  }

  return SILC_FSM_CONTINUE;
}

/* Disconnection even to close remote connection.  We close the connection
   and finish the connection machine in this state.  The connection context
   is deleted in the machine destructor.  The connection callback must be
   already called back to application before getting here. */

SILC_FSM_STATE(silc_client_connection_st_close)
{
  SilcClientConnection conn = fsm_context;

  SILC_LOG_DEBUG(("Closing remote connection"));

  /* Abort ongoing events */
  if (conn->internal->op)
    silc_async_abort(conn->internal->op, NULL, NULL);

  /* Close connection */
  silc_packet_stream_destroy(conn->stream);

  SILC_LOG_DEBUG(("Finishing connection machine"));

  return SILC_FSM_FINISH;
}

/* Received error packet from server.  Send it to application. */

SILC_FSM_STATE(silc_client_error)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  char *msg;

  msg = silc_memdup(silc_buffer_data(&packet->buffer),
		    silc_buffer_len(&packet->buffer));
  if (msg)
    client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT, msg);

  silc_free(msg);
  silc_packet_free(packet);

  return SILC_FSM_FINISH;
}

/* Received disconnect packet from server.  We close the connection and
   send the disconnect message to application. */

SILC_FSM_STATE(silc_client_disconnect)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcStatus status;
  char *message = NULL;

  SILC_LOG_DEBUG(("Server disconnected"));

  if (silc_buffer_len(&packet->buffer) < 1) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  status = (SilcStatus)packet->buffer.data[0];

  silc_buffer_pull(&packet->buffer, 1);
  if (silc_buffer_len(&packet->buffer) > 1 &&
      silc_utf8_valid(silc_buffer_data(&packet->buffer),
		      silc_buffer_len(&packet->buffer)))
    message = silc_memdup(silc_buffer_data(&packet->buffer),
			  silc_buffer_len(&packet->buffer));

  /* Call connection callback */
  conn->callback(client, conn, SILC_CLIENT_CONN_DISCONNECTED, status,
		 message, conn->callback_context);

  silc_free(message);
  silc_packet_free(packet);

  /* Signal to close connection */
  conn->internal->disconnected = TRUE;
  SILC_FSM_SEMA_POST(&conn->internal->wait_event);

  return SILC_FSM_FINISH;
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
    SILC_LOG_DEBUG(("We are running, call running callback"));
    client->internal->run_callback = FALSE;
    client->internal->ops->running(client, client->application);
    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
  SILC_ASSERT(FALSE);
  return SILC_FSM_CONTINUE;
}

/******************************* Private API ********************************/

/* Adds new connection.  Creates the connection context and returns it. */

static SilcClientConnection
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

  conn->client = client;
  conn->public_key = public_key;
  conn->private_key = private_key;
  conn->remote_host = strdup(remote_host);
  conn->remote_port = port ? port : 706;
  conn->type = conn_type;
  conn->callback = callback;
  conn->callback_context = context;

  conn->internal = silc_calloc(1, sizeof(*conn->internal));
  if (!conn->internal) {
    silc_free(conn);
    return NULL;
  }
  conn->internal->retry_timer = SILC_CLIENT_RETRY_MIN;
  silc_mutex_alloc(&conn->internal->lock);
  silc_atomic_init16(&conn->internal->cmd_ident, 0);

  if (!silc_hash_alloc("sha1", &conn->internal->sha1hash)) {
    silc_free(conn);
    silc_free(conn->internal);
    return NULL;
  }
  if (params)
    conn->internal->params = *params;
  conn->internal->verbose = TRUE;
  silc_list_init(conn->internal->pending_commands,
		 struct SilcClientCommandContextStruct, next);
  silc_list_init(conn->internal->thread_pool, SilcFSMThreadStruct, next);

  conn->internal->client_cache = silc_idcache_alloc(0, SILC_ID_CLIENT,
						    NULL, NULL);
  conn->internal->channel_cache = silc_idcache_alloc(0, SILC_ID_CHANNEL,
						     NULL, NULL);
  conn->internal->server_cache = silc_idcache_alloc(0, SILC_ID_SERVER,
						    NULL, NULL);
  if (!conn->internal->client_cache || !conn->internal->channel_cache ||
      !conn->internal->server_cache) {
    silc_client_del_connection(client, conn);
    return NULL;
  }

  conn->internal->ftp_sessions = silc_dlist_init();

  /* Run the connection state machine.  If threads are in use the machine
     is always run in a real thread. */
  thread = silc_fsm_thread_alloc(&client->internal->fsm, conn,
				 silc_client_fsm_destructor, NULL,
				 client->internal->params->threads);
  if (!thread) {
    silc_client_del_connection(client, conn);
    return NULL;
  }
  silc_fsm_start(thread, silc_client_connection_st_start);

  return conn;
}

/* Deletes connection.  This is always called from the connection machine
   destructor.  Do not call this directly other places. */

void silc_client_del_connection(SilcClient client, SilcClientConnection conn)
{
  SilcList list;
  SilcIDCacheEntry entry;
  SilcFSMThread thread;
  SilcClientCommandContext cmd;

  SILC_LOG_DEBUG(("Freeing connection %p", conn));

  /* Free all cache entries */
  if (silc_idcache_get_all(conn->internal->client_cache, &list)) {
    silc_list_start(list);
    while ((entry = silc_list_get(list)))
      silc_client_del_client(client, conn, entry->context);
  }
  if (silc_idcache_get_all(conn->internal->channel_cache, &list)) {
    silc_list_start(list);
    while ((entry = silc_list_get(list)))
      silc_client_del_channel(client, conn, entry->context);
  }
  if (silc_idcache_get_all(conn->internal->server_cache, &list)) {
    silc_list_start(list);
    while ((entry = silc_list_get(list)))
      silc_client_del_server(client, conn, entry->context);
  }

  /* Free ID caches */
  if (conn->internal->client_cache)
    silc_idcache_free(conn->internal->client_cache);
  if (conn->internal->channel_cache)
    silc_idcache_free(conn->internal->channel_cache);
  if (conn->internal->server_cache)
    silc_idcache_free(conn->internal->server_cache);

  /* Free thread pool */
  silc_list_start(conn->internal->thread_pool);
  while ((thread = silc_list_get(conn->internal->thread_pool)))
    silc_fsm_free(thread);

  /* Free pending commands */
  silc_list_start(conn->internal->pending_commands);
  while ((cmd = silc_list_get(conn->internal->pending_commands)))
    silc_client_command_free(cmd);

  silc_free(conn->remote_host);
  silc_buffer_free(conn->internal->local_idp);
  silc_buffer_free(conn->internal->remote_idp);
  silc_mutex_free(conn->internal->lock);
  if (conn->internal->hash)
    silc_hash_free(conn->internal->hash);
  if (conn->internal->sha1hash)
    silc_hash_free(conn->internal->sha1hash);
  silc_atomic_uninit16(&conn->internal->cmd_ident);

  silc_free(conn->internal);
  memset(conn, 'F', sizeof(*conn));
  silc_free(conn);
}


/******************************* Client API *********************************/

/* Connects to remote server.  This is the main routine used to connect
   to remote SILC server.  Performs key exchange also.  Returns the
   connection context to the connection callback. */

SilcBool silc_client_connect_to_server(SilcClient client,
				       SilcClientConnectionParams *params,
				       SilcPublicKey public_key,
				       SilcPrivateKey private_key,
				       char *remote_host, int port,
				       SilcClientConnectCallback callback,
				       void *context)
{
  SilcClientConnection conn;

  if (!client || !remote_host)
    return FALSE;

  /* Add new connection */
  conn = silc_client_add_connection(client, SILC_CONN_SERVER, params,
				    public_key, private_key, remote_host,
				    port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return FALSE;
  }

  client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT,
			     "Connecting to port %d of server %s",
			     port, remote_host);

  /* Signal connection machine to start connecting */
  conn->internal->connect = TRUE;
  return TRUE;
}

/* Connects to remote client.  Performs key exchange also.  Returns the
   connection context to the connection callback. */

SilcBool silc_client_connect_to_client(SilcClient client,
				       SilcClientConnectionParams *params,
				       SilcPublicKey public_key,
				       SilcPrivateKey private_key,
				       char *remote_host, int port,
				       SilcClientConnectCallback callback,
				       void *context)
{
  SilcClientConnection conn;

  if (!client || !remote_host)
    return FALSE;

  /* Add new connection */
  conn = silc_client_add_connection(client, SILC_CONN_CLIENT, params,
				    public_key, private_key, remote_host,
				    port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return FALSE;
  }

  /* Signal connection machine to start connecting */
  conn->internal->connect = TRUE;
  return TRUE;
}

/* Starts key exchange in the remote stream indicated by `stream'.  This
   creates the connection context and returns it in the connection callback. */

SilcBool silc_client_key_exchange(SilcClient client,
				  SilcClientConnectionParams *params,
				  SilcPublicKey public_key,
				  SilcPrivateKey private_key,
				  SilcStream stream,
				  SilcConnectionType conn_type,
				  SilcClientConnectCallback callback,
				  void *context)
{
  SilcClientConnection conn;
  const char *host;
  SilcUInt16 port;

  if (!client || !stream)
    return FALSE;

  if (!silc_socket_stream_get_info(stream, NULL, &host, NULL, &port)) {
    SILC_LOG_ERROR(("Socket stream does not have remote host name set"));
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return FALSE;
  }

  /* Add new connection */
  conn = silc_client_add_connection(client, conn_type, params,
				    public_key, private_key,
				    (char *)host, port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return FALSE;
  }
  conn->stream = (void *)stream;

  /* Signal connection to start key exchange */
  conn->internal->key_exchange = TRUE;
  return TRUE;
}

/* Closes remote connection */

void silc_client_close_connection(SilcClient client,
				  SilcClientConnection conn)
{
  SILC_LOG_DEBUG(("Closing connection %p", conn));

  /* Signal to close connection */
  conn->internal->disconnected = TRUE;
  SILC_FSM_SEMA_POST(&conn->internal->wait_event);
}

#if 0
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
  if (!new_client)
    return NULL;
  new_client->application = application;

  new_client->internal = silc_calloc(1, sizeof(*new_client->internal));
  if (!new_client->internal) {
    silc_free(new_client);
    return NULL;
  }
  new_client->internal->ops = ops;
  new_client->internal->params =
    silc_calloc(1, sizeof(*new_client->internal->params));
  if (!version_string)
    version_string = silc_version_string;
  new_client->internal->silc_client_version = strdup(version_string);

  if (params)
    memcpy(new_client->internal->params, params, sizeof(*params));

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
  if (client->rng)
    silc_rng_free(client->rng);

  if (!client->internal->params->dont_register_crypto_library) {
    silc_cipher_unregister_all();
    silc_pkcs_unregister_all();
    silc_hash_unregister_all();
    silc_hmac_unregister_all();
  }

  silc_free(client->username);
  silc_free(client->hostname);
  silc_free(client->realname);
  silc_free(client->internal->params);
  silc_free(client->internal->silc_client_version);
  silc_free(client->internal);
  silc_free(client);
}

/* Initializes the client. This makes all the necessary steps to make
   the client ready to be run. One must call silc_client_run to run the
   client. Returns FALSE if error occured, TRUE otherwise. */

SilcBool silc_client_init(SilcClient client, const char *username,
			  const char *hostname, const char *realname)
{
  SILC_LOG_DEBUG(("Initializing client"));

  if (!client)
    return FALSE;

  if (!username || !hostname) {
    SILC_LOG_ERROR(("Username, hostname and realname must be given to "
		    "silc_client_init"));
    return FALSE;
  }
  if (!realname)
    realname = username;

  /* Validate essential strings */
  if (!silc_identifier_verify(username, strlen(username),
			      SILC_STRING_UTF8, 128)) {
    SILC_LOG_ERROR(("Malformed username '%s'. Username must be UTF-8 string",
		    client->username));
    return FALSE;
  }
  if (!silc_identifier_verify(hostname, strlen(hostname),
			      SILC_STRING_UTF8, 256)) {
    SILC_LOG_ERROR(("Malformed hostname '%s'. Hostname must be UTF-8 string",
		    client->hostname));
    return FALSE;
  }
  if (!silc_utf8_valid(realname, strlen(realname))) {
    SILC_LOG_ERROR(("Malformed realname '%s'. Realname must be UTF-8 string",
		    client->realname));
    return FALSE;
  }

  /* Take the name strings */
  client->username = strdup(username);
  client->hostname = strdup(hostname);
  client->realname = strdup(realname);
  if (!username || !hostname || !realname)
    return FALSE;

  if (!client->internal->params->dont_register_crypto_library) {
    /* Initialize the crypto library.  If application has done this already
       this has no effect.  Also, we will not be overriding something
       application might have registered earlier. */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
  }

  /* Initialize random number generator */
  client->rng = silc_rng_alloc();
  if (!client->rng)
    return FALSE;
  silc_rng_init(client->rng);
  silc_rng_global_init(client->rng);

  /* Initialize the scheduler */
  client->schedule = silc_schedule_init(0, client);
  if (!client->schedule)
    return FALSE;

  /* Start packet engine */
  client->internal->packet_engine =
    silc_packet_engine_start(client->rng, FALSE, &silc_client_stream_cbs,
			     client);
  if (!client->internal->packet_engine)
    return FALSE;

  /* Allocate client lock */
  silc_mutex_alloc(&client->internal->lock);

  /* Register commands */
  silc_client_commands_register(client);

  /* Initialize and start the client FSM */
  silc_fsm_init(&client->internal->fsm, client, NULL, NULL, client->schedule);
  silc_fsm_sema_init(&client->internal->wait_event, &client->internal->fsm, 0);
  silc_fsm_start_sync(&client->internal->fsm, silc_client_st_run);

  /* Signal the application when we are running */
  client->internal->run_callback = TRUE;
  SILC_FSM_SEMA_POST(&client->internal->wait_event);

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

  /* Run the scheduler */
  silc_schedule(client->schedule);
}

/* Call scheduler one iteration and return.  This cannot be called if threads
   are in use. */

void silc_client_run_one(SilcClient client)
{
  silc_schedule_one(client->schedule, 0);
}
