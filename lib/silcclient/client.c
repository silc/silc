/*

  client.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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

  SILC_LOG_DEBUG(("Connection %p finished", conn));

  /* Delete connection */
  silc_client_del_connection(conn->client, conn);

  /* Finish the thread were this machine was running */
  silc_fsm_finish(thread);
}

/* Connection thread FSM destructor.  This was the thread where the connection
   machine was running (may be real thread).  From here we notify client
   that the connection thread has finished. */

static void silc_client_connection_finished(SilcFSMThread fsm,
					    void *fsm_context,
					    void *destructor_context)
{
  SilcClient client = silc_fsm_get_state_context(fsm);

  /* Signal client that we have finished */
  silc_atomic_sub_int16(&client->internal->conns, 1);
  client->internal->connection_closed = TRUE;
  SILC_FSM_EVENT_SIGNAL(&client->internal->wait_event);

  silc_fsm_free(fsm);
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
  case SILC_PACKET_REKEY_DONE:
  case SILC_PACKET_CONNECTION_AUTH:
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
  SilcClientConnection conn = stream_context;

  SILC_LOG_DEBUG(("Remote disconnected connection"));

  /* Signal to close connection */
  conn->internal->status = SILC_CLIENT_CONN_DISCONNECTED;
  if (!conn->internal->disconnected) {
    conn->internal->disconnected = TRUE;
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  }
}

/* Packet engine callback to indicate error */

static void silc_client_packet_error(SilcPacketEngine engine,
				     SilcPacketStream stream,
				     SilcPacketError error,
				     void *callback_context,
				     void *stream_context)
{
  /* Nothing */
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

/* Connect abort operation */

static void silc_client_connect_abort(SilcAsyncOperation op, void *context)
{
  SilcClientConnection conn = context;

  SILC_LOG_DEBUG(("Connection %p aborted by application", conn));

  /* Connection callback will not be called after user aborted connecting */
  conn->callback = NULL;
  conn->internal->cop = NULL;

  /* Signal to close connection */
  if (!conn->internal->disconnected) {
    conn->internal->disconnected = TRUE;

    /* If user aborts before connection machine is even up yet, then don't
       send signal yet.  It will process this event when it comes up. */
    if (silc_fsm_is_started(&conn->internal->fsm))
      SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  }
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
  silc_fsm_event_init(&conn->internal->wait_event, connfsm);
  silc_fsm_start_sync(connfsm, silc_client_connection_st_run);

  /* Schedule any events possibly set in initialization */
  if (conn->internal->disconnected)
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  if (conn->internal->connect)
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  if (conn->internal->key_exchange)
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);

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
  SILC_FSM_EVENT_WAIT(&conn->internal->wait_event);

  /* Process events */
  thread = &conn->internal->event_thread;

  if (conn->internal->disconnected) {
    /** Event: disconnected */
    SILC_LOG_DEBUG(("Event: disconnected"));
    silc_fsm_next(fsm, silc_client_connection_st_close);
    return SILC_FSM_YIELD;
  }

  if (conn->internal->connect) {
    SILC_LOG_DEBUG(("Event: connect"));
    conn->internal->connect = FALSE;
    SILC_ASSERT(silc_fsm_is_started(thread) == FALSE);

    /*** Event: connect */
    silc_fsm_thread_init(thread, &conn->internal->fsm, conn,
			 NULL, NULL, FALSE);
    silc_fsm_start_sync(thread, silc_client_st_connect);
    return SILC_FSM_CONTINUE;
  }

  if (conn->internal->key_exchange) {
    SILC_LOG_DEBUG(("Event: key exchange"));
    conn->internal->key_exchange = FALSE;
    SILC_ASSERT(silc_fsm_is_started(thread) == FALSE);

    /*** Event: key exchange */
    silc_fsm_thread_init(thread, &conn->internal->fsm, conn,
			 NULL, NULL, FALSE);
    silc_fsm_start_sync(thread, silc_client_st_connect_set_stream);
    return SILC_FSM_CONTINUE;
  }

  if (conn->internal->rekeying) {
    SILC_LOG_DEBUG(("Event: rekey"));
    conn->internal->rekeying = FALSE;
    SILC_ASSERT(silc_fsm_is_started(thread) == FALSE);

    /*** Event: rekey */
    silc_fsm_thread_init(thread, &conn->internal->fsm, conn,
			 NULL, NULL, FALSE);
    silc_fsm_start_sync(thread, silc_client_st_rekey);
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
  SilcClientConnection conn = fsm_context;
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
    silc_fsm_next(fsm, silc_client_ftp);
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
    /** Key agreement */
    silc_fsm_next(fsm, silc_client_key_agreement);
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
    /** Connection auth resolve reply */
    silc_fsm_next(fsm, silc_client_connect_auth_request);
    break;

  case SILC_PACKET_REKEY:
    /* Signal to start rekey */
    conn->internal->rekey_responder = TRUE;
    conn->internal->rekeying = TRUE;
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);

    silc_packet_free(packet);
    return SILC_FSM_FINISH;
    break;

  default:
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
    break;
  }

  return SILC_FSM_CONTINUE;
}

/* Disconnection event to close remote connection.  We close the connection
   and finish the connection machine in this state.  The connection context
   is deleted in the machine destructor.  The connection callback is called
   in this state if it is set. */

SILC_FSM_STATE(silc_client_connection_st_close)
{
  SilcClientConnection conn = fsm_context;
  SilcClientCommandContext cmd;

  /* Finish running command threads.  This will also finish waiting packet
     thread, as they are always waiting for some command.  If any thread is
     waiting something else than command, they must be finished explicitly. */
  if (silc_list_count(conn->internal->pending_commands)) {
    SILC_LOG_DEBUG(("Finish pending commands"));
    silc_list_start(conn->internal->pending_commands);
    while ((cmd = silc_list_get(conn->internal->pending_commands))) {
      if (silc_fsm_is_started(&cmd->thread)) {
        cmd->verbose = FALSE;
        silc_fsm_continue_sync(&cmd->thread);
      }
    }

    /* Give threads time to finish */
    return SILC_FSM_YIELD;
  }

  /* Abort ongoing event */
  if (conn->internal->op) {
    SILC_LOG_DEBUG(("Abort event"));
    silc_async_abort(conn->internal->op, NULL, NULL);
    conn->internal->op = NULL;
  }

  /* If event thread is running, finish it. */
  if (silc_fsm_is_started(&conn->internal->event_thread)) {
    SILC_LOG_DEBUG(("Finish event thread"));
    silc_fsm_continue_sync(&conn->internal->event_thread);
    return SILC_FSM_YIELD;
  }

  /* Call the connection callback */
  if (conn->callback)
    conn->callback(conn->client, conn, conn->internal->status,
		   conn->internal->error, conn->internal->disconnect_message,
		   conn->callback_context);
  silc_free(conn->internal->disconnect_message);

  SILC_LOG_DEBUG(("Closing remote connection"));

  /* Close connection. */
  if (conn->stream)
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
  conn->internal->status = SILC_CLIENT_CONN_DISCONNECTED;
  conn->internal->error = status;
  conn->internal->disconnect_message = message;

  /* Signal to close connection */
  if (!conn->internal->disconnected) {
    conn->internal->disconnected = TRUE;
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  }

  silc_packet_free(packet);

  return SILC_FSM_FINISH;
}

/*************************** Main client machine ****************************/

/* The client's main state where we wait for various events */

SILC_FSM_STATE(silc_client_st_run)
{
  SilcClient client = fsm_context;

  /* Wait for events */
  SILC_FSM_EVENT_WAIT(&client->internal->wait_event);

  /* Process events */

  if (client->internal->run_callback && client->internal->running) {
    /* Call running callbcak back to application */
    SILC_LOG_DEBUG(("We are up, call running callback"));
    client->internal->run_callback = FALSE;
    client->internal->running(client, client->internal->running_context);
    return SILC_FSM_CONTINUE;
  }

  if (client->internal->connection_closed) {
    /* A connection finished */
    SILC_LOG_DEBUG(("Event: connection closed"));
    client->internal->connection_closed = FALSE;
    if (silc_atomic_get_int16(&client->internal->conns) == 0 &&
	client->internal->stop)
      SILC_FSM_EVENT_SIGNAL(&client->internal->wait_event);
    return SILC_FSM_CONTINUE;
  }

  if (client->internal->stop) {
    /* Stop client libarry.  If we have running connections, wait until
       they finish first. */
    SILC_LOG_DEBUG(("Event: stop"));
    if (silc_atomic_get_int16(&client->internal->conns) == 0)
      silc_fsm_next(fsm, silc_client_st_stop);
    return SILC_FSM_CONTINUE;
  }

  /* NOT REACHED */
  SILC_ASSERT(FALSE);
  return SILC_FSM_CONTINUE;
}

/* Stop event.  Stops the client library. */

SILC_FSM_STATE(silc_client_st_stop)
{
  SilcClient client = fsm_context;

  SILC_LOG_DEBUG(("Client stopped"));

  /* Stop scheduler */
  silc_schedule_stop(client->schedule);
  silc_client_commands_unregister(client);

  /* Call stopped callback to application */
  if (client->internal->running)
    client->internal->running(client, client->internal->running_context);

  return SILC_FSM_FINISH;
}

/******************************* Private API ********************************/

/* Adds new connection.  Creates the connection context and returns it. */

SilcClientConnection
silc_client_add_connection(SilcClient client,
			   SilcConnectionType conn_type,
			   SilcBool connect,
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

  /* Set parameters */
  if (params)
    conn->internal->params = *params;
  if (!conn->internal->params.rekey_secs)
    conn->internal->params.rekey_secs = 3600;
#ifndef SILC_DIST_INPLACE
  if (conn->internal->params.rekey_secs < 300)
    conn->internal->params.rekey_secs = 300;
#endif /* SILC_DIST_INPLACE */

  conn->internal->verbose = TRUE;
  silc_list_init(conn->internal->pending_commands,
		 struct SilcClientCommandContextStruct, next);
  silc_list_init(conn->internal->thread_pool, SilcFSMThreadStruct, next);

  /* Allocate client, channel and serve caches */
  if (conn_type != SILC_CONN_CLIENT) {
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
  }

  if (connect) {
    /* Initialize our async operation so that application may abort us
       while we're connecting. */
    conn->internal->cop = silc_async_alloc(silc_client_connect_abort,
					   NULL, conn);
    if (!conn->internal->cop) {
      silc_client_del_connection(client, conn);
      return NULL;
    }
  }

  /* Run the connection state machine.  If threads are in use the connection
     machine is always run in a real thread. */
  thread = silc_fsm_thread_alloc(&client->internal->fsm, conn,
				 silc_client_connection_finished, NULL,
				 client->internal->params->threads);
  if (!thread) {
    silc_client_del_connection(client, conn);
    return NULL;
  }
  silc_fsm_set_state_context(thread, client);
  silc_fsm_start(thread, silc_client_connection_st_start);

  SILC_LOG_DEBUG(("New connection %p", conn));
  silc_atomic_add_int16(&client->internal->conns, 1);

  return conn;
}

/* Deletes connection.  This is always called from the connection machine
   destructor.  Do not call this directly other places. */

void silc_client_del_connection(SilcClient client, SilcClientConnection conn)
{
  SilcList list;
  SilcIDCacheEntry entry;
  SilcFSMThread thread;

  SILC_LOG_DEBUG(("Freeing connection %p", conn));

  silc_schedule_task_del_by_context(conn->internal->schedule, conn);

  /* Free all cache entries */
  if (conn->internal->server_cache) {
    if (silc_idcache_get_all(conn->internal->server_cache, &list)) {
      silc_list_start(list);
      while ((entry = silc_list_get(list)))
	silc_client_del_server(client, conn, entry->context);
    }
  }
  if (conn->internal->channel_cache) {
    if (silc_idcache_get_all(conn->internal->channel_cache, &list)) {
      silc_list_start(list);
      while ((entry = silc_list_get(list))) {
	silc_client_empty_channel(client, conn, entry->context);
	silc_client_del_channel(client, conn, entry->context);
      }
    }
  }
  if (conn->internal->client_cache) {
    if (silc_idcache_get_all(conn->internal->client_cache, &list)) {
      silc_list_start(list);
      while ((entry = silc_list_get(list)))
	silc_client_del_client(client, conn, entry->context);
    }
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

  silc_free(conn->remote_host);
  silc_buffer_free(conn->internal->local_idp);
  silc_buffer_free(conn->internal->remote_idp);
  silc_mutex_free(conn->internal->lock);
  if (conn->internal->hash)
    silc_hash_free(conn->internal->hash);
  if (conn->internal->sha1hash)
    silc_hash_free(conn->internal->sha1hash);
  silc_atomic_uninit16(&conn->internal->cmd_ident);
  silc_free(conn->internal->away_message);
  if (conn->internal->rekey)
    silc_ske_free_rekey_material(conn->internal->rekey);
  if (conn->internal->cop)
    silc_async_free(conn->internal->cop);

  silc_free(conn->internal);
  memset(conn, 'F', sizeof(*conn));
  silc_free(conn);
}

/******************************* Client API *********************************/

/* Connects to remote server.  This is the main routine used to connect
   to remote SILC server.  Performs key exchange also.  Returns the
   connection context to the connection callback. */

SilcAsyncOperation
silc_client_connect_to_server(SilcClient client,
			      SilcClientConnectionParams *params,
			      SilcPublicKey public_key,
			      SilcPrivateKey private_key,
			      char *remote_host, int port,
			      SilcClientConnectCallback callback,
			      void *context)
{
  SilcClientConnection conn;

  SILC_LOG_DEBUG(("Connecting to server"));

  if (!client || !remote_host)
    return NULL;

  /* Add new connection */
  conn = silc_client_add_connection(client, SILC_CONN_SERVER, TRUE, params,
				    public_key, private_key, remote_host,
				    port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return NULL;
  }

  client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT,
			     "Connecting to port %d of server %s",
			     port, remote_host);

  /* Signal connection machine to start connecting */
  conn->internal->connect = TRUE;
  return conn->internal->cop;
}

/* Connects to remote client.  Performs key exchange also.  Returns the
   connection context to the connection callback. */

SilcAsyncOperation
silc_client_connect_to_client(SilcClient client,
			      SilcClientConnectionParams *params,
			      SilcPublicKey public_key,
			      SilcPrivateKey private_key,
			      char *remote_host, int port,
			      SilcClientConnectCallback callback,
			      void *context)
{
  SilcClientConnection conn;

  SILC_LOG_DEBUG(("Connecting to client"));

  if (!client || !remote_host)
    return NULL;

  if (params)
    params->no_authentication = TRUE;

  /* Add new connection */
  conn = silc_client_add_connection(client, SILC_CONN_CLIENT, TRUE, params,
				    public_key, private_key, remote_host,
				    port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return NULL;
  }

  /* Signal connection machine to start connecting */
  conn->internal->connect = TRUE;
  return conn->internal->cop;
}

/* Starts key exchange in the remote stream indicated by `stream'.  This
   creates the connection context and returns it in the connection callback. */

SilcAsyncOperation
silc_client_key_exchange(SilcClient client,
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

  SILC_LOG_DEBUG(("Performing key exchange"));

  if (!client || !stream)
    return NULL;

  if (!silc_socket_stream_get_info(stream, NULL, &host, NULL, &port)) {
    SILC_LOG_ERROR(("Socket stream does not have remote host name set"));
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return NULL;
  }

  /* Add new connection */
  conn = silc_client_add_connection(client, conn_type, TRUE, params,
				    public_key, private_key,
				    (char *)host, port, callback, context);
  if (!conn) {
    callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL, context);
    return NULL;
  }
  conn->internal->user_stream = stream;

  /* Signal connection to start key exchange */
  conn->internal->key_exchange = TRUE;
  return conn->internal->cop;
}

/* Closes remote connection */

void silc_client_close_connection(SilcClient client,
				  SilcClientConnection conn)
{
  SILC_LOG_DEBUG(("Closing connection %p", conn));

  /* Signal to close connection */
  conn->internal->status = SILC_CLIENT_CONN_DISCONNECTED;
  if (!conn->internal->disconnected) {
    conn->internal->disconnected = TRUE;
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  }
}

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

  new_client->internal->params->
    nickname_format[sizeof(new_client->internal->
			   params->nickname_format) - 1] = 0;

  silc_atomic_init16(&new_client->internal->conns, 0);

  return new_client;
}

/* Frees client object and its internals. */

void silc_client_free(SilcClient client)
{
  silc_schedule_uninit(client->schedule);

  if (client->rng)
    silc_rng_free(client->rng);

  if (!client->internal->params->dont_register_crypto_library) {
    silc_cipher_unregister_all();
    silc_pkcs_unregister_all();
    silc_hash_unregister_all();
    silc_hmac_unregister_all();
  }

  silc_packet_engine_stop(client->internal->packet_engine);
  silc_dlist_uninit(client->internal->ftp_sessions);
  silc_atomic_uninit16(&client->internal->conns);
  silc_mutex_free(client->internal->lock);
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
			  const char *hostname, const char *realname,
			  SilcClientRunning running, void *context)
{
  SILC_LOG_DEBUG(("Initializing client"));

  if (!client)
    return FALSE;

  if (!username || !hostname) {
    SILC_LOG_ERROR(("Username and hostname must be given to "
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

  client->internal->ftp_sessions = silc_dlist_init();
  if (!client->internal->ftp_sessions)
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

  /* Allocate client lock */
  silc_mutex_alloc(&client->internal->lock);

  /* Register commands */
  silc_client_commands_register(client);

  /* Start packet engine */
  client->internal->packet_engine =
    silc_packet_engine_start(client->rng, FALSE, &silc_client_stream_cbs,
			     client);
  if (!client->internal->packet_engine)
    return FALSE;

  /* Initialize and start the client FSM */
  client->internal->running = running;
  client->internal->running_context = context;
  silc_fsm_init(&client->internal->fsm, client, NULL, NULL, client->schedule);
  silc_fsm_event_init(&client->internal->wait_event, &client->internal->fsm);
  silc_fsm_start_sync(&client->internal->fsm, silc_client_st_run);

  /* Signal the application when we are running */
  client->internal->run_callback = TRUE;
  SILC_FSM_EVENT_SIGNAL(&client->internal->wait_event);

  return TRUE;
}

/* Starts the SILC client FSM machine and blocks here.  When this returns
   the client has ended. */

void silc_client_run(SilcClient client)
{
  SILC_LOG_DEBUG(("Starting SILC client"));

  /* Run the scheduler */
  silc_schedule(client->schedule);
}

/* Call scheduler one iteration and return. */

void silc_client_run_one(SilcClient client)
{
  if (silc_fsm_is_started(&client->internal->fsm))
    silc_schedule_one(client->schedule, 0);
}

/* Stops the client. This is called to stop the client and thus to stop
   the program. */

void silc_client_stop(SilcClient client, SilcClientStopped stopped,
		      void *context)
{
  SILC_LOG_DEBUG(("Stopping client"));

  client->internal->running = (SilcClientRunning)stopped;
  client->internal->running_context = context;

  /* Signal to stop */
  client->internal->stop = TRUE;
  SILC_FSM_EVENT_SIGNAL(&client->internal->wait_event);
}
