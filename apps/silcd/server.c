/*

  server.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005, 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "serverincludes.h"
#include "server_internal.h"

/************************* Types and definitions ****************************/

SILC_TASK_CALLBACK(silc_server_get_stats);
SILC_TASK_CALLBACK(silc_server_connect_router);
SILC_TASK_CALLBACK(silc_server_do_rekey);
SILC_TASK_CALLBACK(silc_server_purge_expired_clients);
static void silc_server_accept_new_connection(SilcNetStatus status,
					      SilcStream stream,
					      void *context);
static void silc_server_packet_parse_type(SilcServer server,
					  SilcPacketStream sock,
					  SilcPacket packet);
static void silc_server_rekey(SilcServer server, SilcPacketStream sock,
			      SilcPacket packet);


/************************ Static utility functions **************************/

/* SKE public key verification callback */

static void
silc_server_verify_key(SilcSKE ske,
		       SilcPublicKey public_key,
		       void *context,
		       SilcSKEVerifyCbCompletion completion,
		       void *completion_context)
{
  SilcPacketStream sock = context;
  SilcUnknownEntry entry = silc_packet_get_context(sock);

  SILC_LOG_DEBUG(("Verifying public key"));

  if (silc_pkcs_get_type(public_key) != SILC_SKE_PK_TYPE_SILC) {
    SILC_LOG_WARNING(("We don't support %s (%s) port %d public key type %d",
		      entry->hostname, entry->ip, entry->port,
		      silc_pkcs_get_type(public_key)));
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }

  /* We accept all keys without explicit verification */
  completion(ske, SILC_SKE_STATUS_OK, completion_context);
}


/************************ Packet engine callbacks ***************************/

/* Packet engine callback to receive a packet */

static SilcBool silc_server_packet_receive(SilcPacketEngine engine,
					   SilcPacketStream stream,
					   SilcPacket packet,
					   void *callback_context,
					   void *stream_context)
{
  SilcServer server = callback_context;
  SilcIDListData idata = stream_context;

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

  /* Only specific packets can come without source ID present. */
  if ((!packet->src_id ||
       !(idata->status & SILC_IDLIST_STATUS_REGISTERED)) &&
      packet->type != SILC_PACKET_NEW_CLIENT &&
      packet->type != SILC_PACKET_NEW_SERVER &&
      packet->type != SILC_PACKET_CONNECTION_AUTH_REQUEST &&
      packet->type != SILC_PACKET_DISCONNECT)
    return FALSE;

  /* NEW_CLIENT and NEW_SERVER are accepted only without source ID
     and for unregistered connection. */
  if (packet->src_id && (packet->type == SILC_PACKET_NEW_CLIENT ||
			 packet->type == SILC_PACKET_NEW_SERVER) &&
      (idata->status & SILC_IDLIST_STATUS_REGISTERED))
    return FALSE;

  /* Ignore packets from disabled connection */
  if (idata->status & SILC_IDLIST_STATUS_DISABLED &&
      packet->type != SILC_PACKET_HEARTBEAT &&
      packet->type != SILC_PACKET_RESUME_ROUTER &&
      packet->type != SILC_PACKET_REKEY)
    return FALSE;

  /* Check that the the current client ID is same as in the client's packet. */
  if (idata->conn_type == SILC_CONN_CLIENT) {
    SilcClientEntry client = (SilcClientEntry)silc_packet_get_context(stream);
    SilcClientID client_id;

    if (client->id && packet->src_id &&
	silc_id_str2id(packet->src_id, packet->src_id_len,
		       packet->src_id_type, &client_id, sizeof(client_id))) {
      if (!SILC_ID_CLIENT_COMPARE(client->id, &client_id)) {
	SILC_LOG_DEBUG(("Packet source is not same as sender"));
	return FALSE;
      }
    }
  }

  if (server->server_type == SILC_ROUTER) {
    /* Route the packet if it is not destined to us. Other ID types but
       server are handled separately after processing them. */
    if (packet->dst_id &&
	!(packet->flags & SILC_PACKET_FLAG_BROADCAST) &&
	packet->dst_id_type == SILC_ID_SERVER &&
	idata->conn_type != SILC_CONN_CLIENT &&
	memcmp(packet->dst_id, server->id_string, server->id_string_len)) {
      SilcPacketStream conn;
      SilcServerID server_id;

      silc_id_str2id(packet->dst_id, packet->dst_id_len, packet->dst_id_type,
		     &server_id, sizeof(server_id));

      conn = silc_server_route_get(server, &server_id, SILC_ID_SERVER);
      if (!conn) {
	SILC_LOG_WARNING(("Packet to unknown server ID %s, dropped (no route)",
			  silc_id_render(&server_id, SILC_ID_SERVER)));
	return FALSE;
      }

      silc_server_packet_route(server, conn, packet);
      silc_packet_free(packet);
      return TRUE;
    }
  }

  /* Broadcast packet if it is marked as broadcast packet and it is
     originated from router and we are router. */
  if (server->server_type == SILC_ROUTER &&
      idata->conn_type == SILC_CONN_ROUTER &&
      packet->flags & SILC_PACKET_FLAG_BROADCAST) {
    /* Broadcast to our primary route */
    silc_server_packet_broadcast(server, SILC_PRIMARY_ROUTE(server), packet);

    /* If we have backup routers then we need to feed all broadcast
       data to those servers. */
    silc_server_backup_broadcast(server, stream, packet);
  }

  /* Process packet */
  silc_server_packet_parse_type(server, stream, packet);

  return TRUE;
}

/* Packet engine callback to indicate end of stream */

static void silc_server_packet_eos(SilcPacketEngine engine,
				   SilcPacketStream stream,
				   void *callback_context,
				   void *stream_context)
{
  SilcServer server = callback_context;
  SilcIDListData idata = silc_packet_get_context(stream);

  SILC_LOG_DEBUG(("End of stream received"));

  if (!idata)
    return;

  if (server->router_conn && server->router_conn->sock == stream &&
      !server->router && server->standalone) {
    silc_server_create_connections(server);
  } else {
    /* If backup disconnected then mark that resuming will not be allowed */
     if (server->server_type == SILC_ROUTER && !server->backup_router &&
         idata->conn_type == SILC_CONN_SERVER) {
      SilcServerEntry server_entry = (SilcServerEntry)idata;
      if (server_entry->server_type == SILC_BACKUP_ROUTER)
        server->backup_closed = TRUE;
    }

    silc_server_free_sock_user_data(server, stream, NULL);
  }

  silc_server_close_connection(server, stream);
}

/* Packet engine callback to indicate error */

static void silc_server_packet_error(SilcPacketEngine engine,
				     SilcPacketStream stream,
				     SilcPacketError error,
				     void *callback_context,
				     void *stream_context)
{
  SilcIDListData idata = silc_packet_get_context(stream);
  SilcStream sock = silc_packet_stream_get_stream(stream);
  const char *ip;
  SilcUInt16 port;

  if (!idata || !sock)
    return;

  if (!silc_socket_stream_get_info(sock, NULL, NULL, &ip, &port))
    return;

  SILC_LOG_ERROR(("Connection %s:%d [%s]: %s",
		  SILC_CONNTYPE_STRING(idata->conn_type), ip, port,
		  silc_packet_error_string(error)));
}

/* Packet stream callbacks */
static SilcPacketCallbacks silc_server_stream_cbs =
{
  silc_server_packet_receive,
  silc_server_packet_eos,
  silc_server_packet_error
};

/* Parses the packet type and calls what ever routines the packet type
   requires. This is done for all incoming packets. */

static void silc_server_packet_parse_type(SilcServer server,
					  SilcPacketStream sock,
					  SilcPacket packet)
{
  SilcPacketType type = packet->type;
  SilcIDListData idata = silc_packet_get_context(sock);

  SILC_LOG_DEBUG(("Received %s packet [flags %d]",
		  silc_get_packet_name(type), packet->flags));

  /* Parse the packet type */
  switch (type) {
  case SILC_PACKET_NOTIFY:
    /*
     * Received notify packet. Server can receive notify packets from
     * router. Server then relays the notify messages to clients if needed.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_notify_list(server, sock, packet);
    else
      silc_server_notify(server, sock, packet);
    break;

    /*
     * Private Message packets
     */
  case SILC_PACKET_PRIVATE_MESSAGE:
    /*
     * Received private message packet. The packet is coming from either
     * client or server.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    idata->last_receive = time(NULL);
    silc_server_private_message(server, sock, packet);
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
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    idata->last_receive = time(NULL);
    silc_server_channel_message(server, sock, packet);
    break;

    /*
     * Command packets
     */
  case SILC_PACKET_COMMAND:
    /*
     * Recived command. Processes the command request and allocates the
     * command context and calls the command.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    server->stat.commands_received++;
    silc_server_command_process(server, sock, packet);
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Received command reply packet. Received command reply to command. It
     * may be reply to command sent by us or reply to command sent by client
     * that we've routed further.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    server->stat.commands_received++;
    silc_server_command_reply(server, sock, packet);
    break;

  case SILC_PACKET_DISCONNECT:
    {
      SilcStatus status;
      char *message = NULL;
      const char *hostname, *ip;

      if (packet->flags & SILC_PACKET_FLAG_LIST)
	break;
      if (silc_buffer_len(&packet->buffer) < 1)
	break;

      status = (SilcStatus)packet->buffer.data[0];
      if (silc_buffer_len(&packet->buffer) > 1 &&
	  silc_utf8_valid(packet->buffer.data + 1, silc_buffer_len(&packet->buffer) - 1))
	message = silc_memdup(packet->buffer.data + 1,
			      silc_buffer_len(&packet->buffer) - 1);

      if (!silc_socket_stream_get_info(sock, NULL, &hostname, &ip, NULL))
	break;

      SILC_LOG_INFO(("Disconnected by %s (%s): %s (%d) %s", ip, hostname,
		     silc_get_status_message(status), status,
		     message ? message : ""));

      silc_free(message);

      /* Do not switch to backup in case of error */
      server->backup_noswitch = (status == SILC_STATUS_OK ? FALSE : TRUE);

      /* If backup disconnected then mark that resuming will not be allowed */
#if 0
      if (server->server_type == SILC_ROUTER && !server->backup_router &&
	  sock->type == SILC_CONN_SERVER && sock->user_data) {
	SilcServerEntry server_entry = sock->user_data;
	if (server_entry->server_type == SILC_BACKUP_ROUTER)
	  server->backup_closed = TRUE;
      }

      /* Handle the disconnection from our end too */
      if (sock->user_data && SILC_IS_LOCAL(sock->user_data))
	silc_server_free_sock_user_data(server, sock, NULL);
      SILC_SET_DISCONNECTING(sock);
      silc_server_close_connection(server, sock);
      server->backup_noswitch = FALSE;
#endif
    }
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /*
     * Received key for channel. As channels are created by the router
     * the keys are as well. We will distribute the key to all of our
     * locally connected clients on the particular channel. Router
     * never receives this channel and thus is ignored.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_channel_key(server, sock, packet);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /*
     * Private message key packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_private_message_key(server, sock, packet);
    break;

  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /*
     * Connection authentication request packet. When we receive this packet
     * we will send to the other end information about our mandatory
     * authentication method for the connection. This packet maybe received
     * at any time.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_connection_auth_request(server, sock, packet);
    break;

  case SILC_PACKET_NEW_ID:
    /*
     * Received New ID packet. This includes some new ID that has been
     * created. It may be for client, server or channel. This is the way
     * to distribute information about new registered entities in the
     * SILC network.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_id_list(server, sock, packet);
    else
      silc_server_new_id(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CLIENT:
    /*
     * Received new client packet. This includes client information that
     * we will use to create initial client ID. After creating new
     * ID we will send it to the client.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_new_client(server, sock, packet);
    break;

  case SILC_PACKET_NEW_SERVER:
    /*
     * Received new server packet. This includes Server ID and some other
     * information that we may save. This is received after server has
     * connected to us.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_new_server(server, sock, packet);
    break;

  case SILC_PACKET_NEW_CHANNEL:
    /*
     * Received new channel packet. Information about new channel in the
     * network are distributed using this packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_channel_list(server, sock, packet);
    else
      silc_server_new_channel(server, sock, packet);
    break;

  case SILC_PACKET_HEARTBEAT:
    /*
     * Received heartbeat.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    break;

  case SILC_PACKET_KEY_AGREEMENT:
    /*
     * Received heartbeat.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_key_agreement(server, sock, packet);
    break;

  case SILC_PACKET_REKEY:
    /*
     * Received re-key packet. The sender wants to regenerate the session
     * keys.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_rekey(server, sock, packet);
    break;

  case SILC_PACKET_FTP:
    /* FTP packet */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_ftp(server, sock, packet);
    break;

  case SILC_PACKET_RESUME_CLIENT:
    /* Resume client */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_resume_client(server, sock, packet);
    break;

  case SILC_PACKET_RESUME_ROUTER:
    /* Resume router packet received. This packet is received for backup
       router resuming protocol. */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
#if 0
    silc_server_backup_resume_router(server, sock, packet);
#endif
    break;

  default:
    SILC_LOG_ERROR(("Incorrect packet type %d, packet dropped", type));
    break;
  }
}

/****************************** Server API **********************************/

/* Allocates a new SILC server object. This has to be done before the server
   can be used. After allocation one must call silc_server_init to initialize
   the server. The new allocated server object is returned to the new_server
   argument. */

SilcBool silc_server_alloc(SilcServer *new_server)
{
  SilcServer server;

  SILC_LOG_DEBUG(("Allocating new server object"));

  server = silc_calloc(1, sizeof(*server));
  if (!server)
    return FALSE;
  server->server_type = SILC_SERVER;
  server->standalone = TRUE;
  server->local_list = silc_calloc(1, sizeof(*server->local_list));
  if (!server->local_list)
    return FALSE;
  server->global_list = silc_calloc(1, sizeof(*server->global_list));
  if (!server->global_list)
    return FALSE;
  server->pending_commands = silc_dlist_init();
  if (!server->pending_commands)
    return FALSE;
  server->listeners = silc_dlist_init();
  if (!server->listeners)
    return FALSE;
  server->repository = silc_skr_alloc();
  if (!server->repository)
    return FALSE;
  server->conns = silc_dlist_init();
  if (!server->conns)
    return FALSE;
  server->expired_clients = silc_dlist_init();
  if (!server->expired_clients)
    return FALSE;

  *new_server = server;

  return TRUE;
}

/* Free's the SILC server object. This is called at the very end before
   the program ends. */

void silc_server_free(SilcServer server)
{
  SilcList list;
  SilcIDCacheEntry cache;

  if (!server)
    return;

  silc_server_backup_free(server);
  silc_server_config_unref(&server->config_ref);
  if (server->rng)
    silc_rng_free(server->rng);
  if (server->public_key)
    silc_pkcs_public_key_free(server->public_key);
  if (server->private_key)
    silc_pkcs_private_key_free(server->private_key);
  if (server->pending_commands)
    silc_dlist_uninit(server->pending_commands);
  if (server->id_entry)
    silc_idlist_del_server(server->local_list, server->id_entry);

  /* Delete all channels */
  if (silc_idcache_get_all(server->local_list->channels, &list)) {
    silc_list_start(list);
    while ((cache = silc_list_get(list)))
      silc_idlist_del_channel(server->local_list, cache->context);
  }
  if (silc_idcache_get_all(server->global_list->channels, &list)) {
    silc_list_start(list);
    while ((cache = silc_list_get(list)))
      silc_idlist_del_channel(server->global_list, cache->context);
  }

  /* Delete all clients */
  if (silc_idcache_get_all(server->local_list->clients, &list)) {
    silc_list_start(list);
    while ((cache = silc_list_get(list)))
      silc_idlist_del_client(server->local_list, cache->context);
  }
  if (silc_idcache_get_all(server->global_list->clients, &list)) {
    silc_list_start(list);
    while ((cache = silc_list_get(list)))
      silc_idlist_del_client(server->global_list, cache->context);
  }

  /* Delete all servers */
  if (silc_idcache_get_all(server->local_list->servers, &list)) {
    silc_list_start(list);
    while ((cache = silc_list_get(list)))
      silc_idlist_del_server(server->local_list, cache->context);
  }
  if (silc_idcache_get_all(server->global_list->servers, &list)) {
    while ((cache = silc_list_get(list)))
      silc_idlist_del_server(server->global_list, cache->context);
  }

  silc_idcache_free(server->local_list->clients);
  silc_idcache_free(server->local_list->servers);
  silc_idcache_free(server->local_list->channels);
  silc_idcache_free(server->global_list->clients);
  silc_idcache_free(server->global_list->servers);
  silc_idcache_free(server->global_list->channels);
  silc_hash_table_free(server->watcher_list);
  silc_hash_table_free(server->watcher_list_pk);
  silc_hash_free(server->md5hash);
  silc_hash_free(server->sha1hash);

  silc_dlist_uninit(server->listeners);
  silc_dlist_uninit(server->conns);
  silc_dlist_uninit(server->expired_clients);
  silc_skr_free(server->repository);
  silc_packet_engine_stop(server->packet_engine);

  silc_free(server->local_list);
  silc_free(server->global_list);
  silc_free(server->server_name);
  silc_free(server->purge_i);
  silc_free(server->purge_g);
  silc_free(server);

  silc_hmac_unregister_all();
  silc_hash_unregister_all();
  silc_cipher_unregister_all();
  silc_pkcs_unregister_all();
}

/* Creates a new server listener. */

static SilcNetListener
silc_server_listen(SilcServer server, const char *server_ip, SilcUInt16 port)
{
  SilcNetListener listener;

  listener =
    silc_net_tcp_create_listener(&server_ip, 1, port, TRUE,
				 server->config->require_reverse_lookup,
				 server->schedule,
				 silc_server_accept_new_connection, server);
  if (!listener) {
    SILC_SERVER_LOG_ERROR(("Could not create server listener: %s on %hu",
			   server_ip, port));
    return NULL;
  }

  return listener;
}

/* Adds a secondary listener. */

SilcBool silc_server_init_secondary(SilcServer server)
{
  return TRUE;
#if 0
  int sock = 0;
  SilcPacketStream newsocket = NULL;
  SilcServerConfigServerInfoInterface *interface;

  for (interface = server->config->server_info->secondary; interface;
       interface = interface->next, sock++) {

    if (!silc_server_listen(server,
	interface->server_ip, interface->port, &sock_list[sock]))
      goto err;

    /* Set socket to non-blocking mode */
    silc_net_set_socket_nonblock(sock_list[sock]);

    /* Add ourselves also to the socket table. The entry allocated above
       is sent as argument for fast referencing in the future. */
    silc_socket_alloc(sock_list[sock],
		      SILC_CONN_SERVER, NULL, &newsocket);
    server->sockets[sock_list[sock]] = newsocket;
    SILC_SET_LISTENER(newsocket);

    /* Perform name and address lookups to resolve the listenning address
       and port. */
    if (!silc_net_check_local_by_sock(sock_list[sock], &newsocket->hostname,
      			    &newsocket->ip)) {
      if ((server->config->require_reverse_lookup && !newsocket->hostname) ||
        !newsocket->ip) {
        SILC_LOG_ERROR(("IP/DNS lookup failed for local host %s",
        	      newsocket->hostname ? newsocket->hostname :
        	      newsocket->ip ? newsocket->ip : ""));
        server->stat.conn_failures++;
        goto err;
      }
      if (!newsocket->hostname)
        newsocket->hostname = strdup(newsocket->ip);
    }
    newsocket->port = silc_net_get_local_port(sock);

    newsocket->user_data = (void *)server->id_entry;
    silc_schedule_task_add(server->schedule, sock_list[sock],
			   silc_server_accept_new_connection,
			   (void *)server, 0, 0,
			   SILC_TASK_FD,
			   SILC_TASK_PRI_NORMAL);
  }

  return TRUE;

 err:
  do silc_net_close_server(sock_list[sock--]); while (sock >= 0);
#endif /* 0 */
  return FALSE;
}

/* Initializes the entire SILC server. This is called always before running
   the server. This is called only once at the initialization of the program.
   This binds the server to its listenning port. After this function returns
   one should call silc_server_run to start the server. This returns TRUE
   when everything is ok to run the server. Configuration file must be
   read and parsed before calling this. */

SilcBool silc_server_init(SilcServer server)
{
  SilcServerID *id;
  SilcServerEntry id_entry;
  SilcIDListPurge purge;
  SilcNetListener listener;
  SilcUInt16 *port;
  char **ip;

  SILC_LOG_DEBUG(("Initializing server"));

  server->starttime = time(NULL);

  /* Take config object for us */
  silc_server_config_ref(&server->config_ref, server->config,
			 server->config);

#ifdef SILC_DEBUG
  /* Set debugging on if configured */
  if (server->config->debug_string) {
    silc_log_debug(TRUE);
    silc_log_set_debug_string(server->config->debug_string);
  }
#endif /* SILC_DEBUG */

  /* Steal public and private key from the config object */
  server->public_key = server->config->server_info->public_key;
  server->private_key = server->config->server_info->private_key;
  server->config->server_info->public_key = NULL;
  server->config->server_info->private_key = NULL;

  /* Register all configured ciphers, PKCS and hash functions. */
  if (!silc_server_config_register_ciphers(server))
    silc_cipher_register_default();
  if (!silc_server_config_register_pkcs(server))
    silc_pkcs_register_default();
  if (!silc_server_config_register_hashfuncs(server))
    silc_hash_register_default();
  if (!silc_server_config_register_hmacs(server))
    silc_hmac_register_default();

  /* Initialize random number generator for the server. */
  server->rng = silc_rng_alloc();
  silc_rng_init(server->rng);
  silc_rng_global_init(server->rng);

  /* Initialize hash functions for server to use */
  silc_hash_alloc("md5", &server->md5hash);
  silc_hash_alloc("sha1", &server->sha1hash);

  /* Initialize the scheduler */
  server->schedule = silc_schedule_init(server->config->param.connections_max,
					server);
  if (!server->schedule)
    goto err;

  /* First, register log files configuration for error output */
  silc_server_config_setlogfiles(server);

  /* Initialize ID caches */
  server->local_list->clients =
    silc_idcache_alloc(0, SILC_ID_CLIENT, silc_idlist_client_destructor,
		       server);
  server->local_list->servers =
    silc_idcache_alloc(0, SILC_ID_SERVER, silc_idlist_server_destructor,
		       server);
  server->local_list->channels =
    silc_idcache_alloc(0, SILC_ID_CHANNEL, silc_idlist_channel_destructor,
		       NULL);

  /* These are allocated for normal server as well as these hold some
     global information that the server has fetched from its router. For
     router these are used as they are supposed to be used on router. */
  server->global_list->clients =
    silc_idcache_alloc(0, SILC_ID_CLIENT, silc_idlist_client_destructor,
		       server);
  server->global_list->servers =
    silc_idcache_alloc(0, SILC_ID_SERVER, silc_idlist_server_destructor,
		       server);
  server->global_list->channels =
    silc_idcache_alloc(0, SILC_ID_CHANNEL, silc_idlist_channel_destructor,
		       NULL);

  /* Init watcher lists */
  server->watcher_list =
    silc_hash_table_alloc(1, silc_hash_client_id_hash, NULL,
			  silc_hash_data_compare, (void *)CLIENTID_HASH_LEN,
			  NULL, NULL, TRUE);
  if (!server->watcher_list)
    goto err;
  server->watcher_list_pk =
    silc_hash_table_alloc(1, silc_hash_public_key, NULL,
			  silc_hash_public_key_compare, NULL,
			  NULL, NULL, TRUE);
  if (!server->watcher_list_pk)
    goto err;

  /* Create TCP listener */
  listener = silc_server_listen(
		   server,
		   server->config->server_info->primary == NULL ? NULL :
		   server->config->server_info->primary->server_ip,
		   server->config->server_info->primary == NULL ? 0 :
		   server->config->server_info->primary->port);
  if (!listener)
    goto err;

  silc_dlist_add(server->listeners, listener);

  /* Create a Server ID for the server. */
  port = silc_net_listener_get_port(listener, NULL);
  ip = silc_net_listener_get_ip(listener, NULL);
  silc_id_create_server_id(ip[0], port[0], server->rng, &id);
  if (!id)
    goto err;

  silc_free(port);
  silc_free(ip[0]);
  silc_free(ip);

  server->id = id;
  server->server_name = server->config->server_info->server_name;
  server->config->server_info->server_name = NULL;
  silc_id_id2str(server->id, SILC_ID_SERVER, server->id_string,
		 sizeof(server->id_string), &server->id_string_len);

  /* Add ourselves to the server list. We don't have a router yet
     beacuse we haven't established a route yet. It will be done later.
     For now, NULL is sent as router. This allocates new entry to
     the ID list. */
  id_entry =
    silc_idlist_add_server(server->local_list, strdup(server->server_name),
			   server->server_type, server->id, NULL, NULL);
  if (!id_entry) {
    SILC_LOG_ERROR(("Could not add local server to cache"));
    goto err;
  }
  id_entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;
  server->id_entry = id_entry;

  /* Create secondary TCP listeners */
  if (silc_server_init_secondary(server) == FALSE)
    goto err;

  server->listenning = TRUE;

  /* Create connections to configured routers. */
  silc_server_create_connections(server);

  /* If server connections has been configured then we must be router as
     normal server cannot have server connections, only router connections. */
  if (server->config->servers) {
    SilcServerConfigServer *ptr = server->config->servers;

    server->server_type = SILC_ROUTER;
    while (ptr) {
      if (ptr->backup_router) {
	server->server_type = SILC_BACKUP_ROUTER;
	server->backup_router = TRUE;
	server->id_entry->server_type = SILC_BACKUP_ROUTER;
	break;
      }
      ptr = ptr->next;
    }
  }

  /* Register the ID Cache purge task. This periodically purges the ID cache
     and removes the expired cache entries. */

  /* Clients local list */
  server->purge_i = purge = silc_calloc(1, sizeof(*purge));
  purge->cache = server->local_list->clients;
  purge->timeout = 600;
  silc_schedule_task_add_timeout(server->schedule, silc_idlist_purge,
				 (void *)purge, purge->timeout, 0);

  /* Clients global list */
  server->purge_g = purge = silc_calloc(1, sizeof(*purge));
  purge->cache = server->global_list->clients;
  purge->timeout = 300;
  silc_schedule_task_add_timeout(server->schedule, silc_idlist_purge,
				 (void *)purge, purge->timeout, 0);

  /* If we are normal server we'll retrieve network statisticial information
     once in a while from the router. */
  if (server->server_type != SILC_ROUTER)
    silc_schedule_task_add_timeout(server->schedule, silc_server_get_stats,
				   server, 10, 0);

  if (server->server_type == SILC_ROUTER)
    server->stat.routers++;

  /* Start packet engine */
  server->packet_engine =
    silc_packet_engine_start(server->rng, server->server_type == SILC_ROUTER,
			     &silc_server_stream_cbs, server);
  if (!server->packet_engine)
    goto err;

  /* Register client entry expiration timeout */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_purge_expired_clients, server,
				 600, 0);

  /* Initialize HTTP server */
  silc_server_http_init(server);

  SILC_LOG_DEBUG(("Server initialized"));

  /* We are done here, return succesfully */
  return TRUE;

 err:
  silc_server_config_unref(&server->config_ref);
  return FALSE;
}

#if 0
/* Task callback to close a socket connection after rehash */

SILC_TASK_CALLBACK(silc_server_rehash_close_connection)
{
  SilcServer server = context;
  SilcPacketStream sock = server->sockets[fd];

  if (!sock)
    return;

  SILC_LOG_INFO(("Connection %s:%d [%s] is unconfigured",
		 sock->hostname, sock->port,
		 (sock->type == SILC_CONN_UNKNOWN ? "Unknown" :
		  sock->type == SILC_CONN_CLIENT ? "Client" :
		  sock->type == SILC_CONN_SERVER ? "Server" :
		  "Router")));
  silc_schedule_task_del_by_context(server->schedule, sock);
  silc_server_disconnect_remote(server, sock,
				SILC_STATUS_ERR_BANNED_FROM_SERVER,
				"This connection is removed from "
				"configuration");
  if (sock->user_data)
    silc_server_free_sock_user_data(server, sock, NULL);
}
#endif /* 0 */

/* This function basically reads the config file again and switches the config
   object pointed by the server object. After that, we have to fix various
   things such as the server_name and the listening ports.
   Keep in mind that we no longer have the root privileges at this point. */

SilcBool silc_server_rehash(SilcServer server)
{
#if 0
  SilcServerConfig newconfig;

  SILC_LOG_INFO(("Rehashing server"));

  /* Reset the logging system */
  silc_log_quick(TRUE);
  silc_log_flush_all();

  /* Start the main rehash phase (read again the config file) */
  newconfig = silc_server_config_alloc(server->config_file, server);
  if (!newconfig) {
    SILC_LOG_ERROR(("Rehash FAILED."));
    return FALSE;
  }

  /* Reinit scheduler if necessary */
  if (newconfig->param.connections_max > server->config->param.connections_max)
    if (!silc_schedule_reinit(server->schedule,
			      newconfig->param.connections_max))
      return FALSE;

  /* Fix the server_name field */
  if (strcmp(server->server_name, newconfig->server_info->server_name)) {
    silc_free(server->server_name);

    /* Check server name */
    server->server_name =
      silc_identifier_check(newconfig->server_info->server_name,
			    strlen(newconfig->server_info->server_name),
			    SILC_STRING_LOCALE, 256, NULL);
    if (!server->server_name) {
      SILC_LOG_ERROR(("Malformed server name string '%s'",
		      server->config->server_info->server_name));
      return FALSE;
    }

    /* Update the idcache list with a fresh pointer */
    silc_free(server->id_entry->server_name);
    server->id_entry->server_name = strdup(server->server_name);
    if (!silc_idcache_del_by_context(server->local_list->servers,
				     server->id_entry))
      return FALSE;
    if (!silc_idcache_add(server->local_list->servers,
			  strdup(server->id_entry->server_name),
			  server->id_entry->id, server->id_entry, 0, NULL))
      return FALSE;
  }

  /* Set logging */
  silc_server_config_setlogfiles(server);

  /* Change new key pair if necessary */
  if (newconfig->server_info->public_key &&
      !silc_pkcs_public_key_compare(server->public_key,
				    newconfig->server_info->public_key)) {
    silc_pkcs_public_key_free(server->public_key);
    silc_pkcs_private_key_free(server->private_key);
    server->public_key = newconfig->server_info->public_key;
    server->private_key = newconfig->server_info->private_key;
    newconfig->server_info->public_key = NULL;
    newconfig->server_info->private_key = NULL;

    /* Allocate PKCS context for local public and private keys */
    silc_pkcs_free(server->pkcs);
    if (!silc_pkcs_alloc(server->public_key->name, &server->pkcs))
      return FALSE;
    silc_pkcs_public_key_set(server->pkcs, server->public_key);
    silc_pkcs_private_key_set(server->pkcs, server->private_key);
  }

  /* Check for unconfigured server and router connections and close
     connections that were unconfigured. */

  if (server->config->routers) {
    SilcServerConfigRouter *ptr;
    SilcServerConfigRouter *newptr;
    SilcBool found;

    for (ptr = server->config->routers; ptr; ptr = ptr->next) {
      found = FALSE;

      /* Check whether new config has this one too */
      for (newptr = newconfig->routers; newptr; newptr = newptr->next) {
	if (silc_string_compare(newptr->host, ptr->host) &&
	    newptr->port == ptr->port &&
	    newptr->initiator == ptr->initiator) {
	  found = TRUE;
	  break;
	}
      }

      if (!found && ptr->host) {
	/* Remove this connection */
	SilcPacketStream sock;
	sock = silc_server_find_socket_by_host(server, SILC_CONN_ROUTER,
					       ptr->host, ptr->port);
	if (sock && !SILC_IS_LISTENER(sock))
	  silc_schedule_task_add(server->schedule, sock->sock,
				 silc_server_rehash_close_connection,
				 server, 0, 1, SILC_TASK_TIMEOUT,
				 SILC_TASK_PRI_NORMAL);
      }
    }
  }

  if (server->config->servers) {
    SilcServerConfigServer *ptr;
    SilcServerConfigServer *newptr;
    SilcBool found;

    for (ptr = server->config->servers; ptr; ptr = ptr->next) {
      found = FALSE;

      /* Check whether new config has this one too */
      for (newptr = newconfig->servers; newptr; newptr = newptr->next) {
	if (silc_string_compare(newptr->host, ptr->host)) {
	  found = TRUE;
	  break;
	}
      }

      if (!found && ptr->host) {
	/* Remove this connection */
	SilcPacketStream sock;
	sock = silc_server_find_socket_by_host(server, SILC_CONN_SERVER,
					       ptr->host, 0);
	if (sock && !SILC_IS_LISTENER(sock))
	  silc_schedule_task_add(server->schedule, sock->sock,
				 silc_server_rehash_close_connection,
				 server, 0, 1, SILC_TASK_TIMEOUT,
				 SILC_TASK_PRI_NORMAL);
      }
    }
  }

  if (server->config->clients) {
    SilcServerConfigClient *ptr;
    SilcServerConfigClient *newptr;
    SilcBool found;

    for (ptr = server->config->clients; ptr; ptr = ptr->next) {
      found = FALSE;

      /* Check whether new config has this one too */
      for (newptr = newconfig->clients; newptr; newptr = newptr->next) {
	if (silc_string_compare(newptr->host, ptr->host)) {
	  found = TRUE;
	  break;
	}
      }

      if (!found && ptr->host) {
	/* Remove this connection */
	SilcPacketStream sock;
	sock = silc_server_find_socket_by_host(server, SILC_CONN_CLIENT,
					       ptr->host, 0);
	if (sock)
	  silc_schedule_task_add(server->schedule, sock->sock,
				 silc_server_rehash_close_connection,
				 server, 0, 1, SILC_TASK_TIMEOUT,
				 SILC_TASK_PRI_NORMAL);
      }
    }
  }

  /* Create connections after rehash */
  silc_server_create_connections(server);

  /* Check whether our router status has changed */
  if (newconfig->servers) {
    SilcServerConfigServer *ptr = newconfig->servers;

    server->server_type = SILC_ROUTER;
    while (ptr) {
      if (ptr->backup_router) {
	server->server_type = SILC_BACKUP_ROUTER;
	server->backup_router = TRUE;
	server->id_entry->server_type = SILC_BACKUP_ROUTER;
	break;
      }
      ptr = ptr->next;
    }
  }

  /* Our old config is gone now. We'll unreference our reference made in
     silc_server_init and then destroy it since we are destroying it
     underneath the application (layer which called silc_server_init). */
  silc_server_config_unref(&server->config_ref);
  silc_server_config_destroy(server->config);

  /* Take new config context */
  server->config = newconfig;
  silc_server_config_ref(&server->config_ref, server->config, server->config);

#ifdef SILC_DEBUG
  /* Set debugging on if configured */
  if (server->config->debug_string) {
    silc_log_debug(TRUE);
    silc_log_set_debug_string(server->config->debug_string);
  }
#endif /* SILC_DEBUG */

  SILC_LOG_DEBUG(("Server rehashed"));
#endif /* 0 */

  return TRUE;
}

/* The heart of the server. This runs the scheduler thus runs the server.
   When this returns the server has been stopped and the program will
   be terminated. */

void silc_server_run(SilcServer server)
{
  SILC_LOG_INFO(("SILC Server started"));

  /* Start the scheduler, the heart of the SILC server. When this returns
     the program will be terminated. */
  silc_schedule(server->schedule);
}

/* Stops the SILC server. This function is used to shutdown the server.
   This is usually called after the scheduler has returned. After stopping
   the server one should call silc_server_free. */

void silc_server_stop(SilcServer server)
{
  SilcDList list;
  SilcPacketStream ps;
  SilcNetListener listener;

  SILC_LOG_INFO(("SILC Server shutting down"));

  server->server_shutdown = TRUE;

  /* Close all connections */
  if (server->packet_engine) {
    list = silc_packet_engine_get_streams(server->packet_engine);

    silc_dlist_start(list);
    while ((ps = silc_dlist_get(list))) {
      SilcIDListData idata = silc_packet_get_context(ps);

      if (idata)
	idata->status &= ~SILC_IDLIST_STATUS_DISABLED;

      silc_server_disconnect_remote(server, ps, SILC_STATUS_OK,
				    "Server is shutting down");
      silc_server_free_sock_user_data(server, ps,
				      "Server is shutting down");
    }
    silc_dlist_uninit(list);
  }

  /* We are not connected to network anymore */
  server->standalone = TRUE;

  silc_dlist_start(server->listeners);
  while ((listener = silc_dlist_get(server->listeners)))
    silc_net_close_listener(listener);

  silc_server_http_uninit(server);

  silc_schedule_stop(server->schedule);
  silc_schedule_uninit(server->schedule);
  server->schedule = NULL;

  SILC_LOG_DEBUG(("Server stopped"));
}

/* Purge expired client entries from the server */

SILC_TASK_CALLBACK(silc_server_purge_expired_clients)
{
  SilcServer server = context;
  SilcClientEntry client;
  SilcIDList id_list;

  SILC_LOG_DEBUG(("Expire timeout"));

  silc_dlist_start(server->expired_clients);
  while ((client = silc_dlist_get(server->expired_clients))) {
    if (client->data.status & SILC_IDLIST_STATUS_REGISTERED)
      continue;

    id_list = (client->data.status & SILC_IDLIST_STATUS_LOCAL ?
	       server->local_list : server->global_list);

    silc_idlist_del_data(client);
    silc_idlist_del_client(id_list, client);
    silc_dlist_del(server->expired_clients, client);
  }

  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_purge_expired_clients, server,
				 600, 0);
}


/******************************* Connecting *********************************/

/* Free connection context */

static void silc_server_connection_free(SilcServerConnection sconn)
{
  silc_dlist_del(sconn->server->conns, sconn);
  silc_server_config_unref(&sconn->conn);
  silc_free(sconn->remote_host);
  silc_free(sconn->backup_replace_ip);
  silc_free(sconn);
}

/* Creates connection to a remote router. */

void silc_server_create_connection(SilcServer server,
				   SilcBool reconnect,
				   const char *remote_host, SilcUInt32 port,
				   SilcServerConnectCallback callback,
				   void *context)
{
  SilcServerConnection sconn;

  /* Allocate connection object for hold connection specific stuff. */
  sconn = silc_calloc(1, sizeof(*sconn));
  if (!sconn)
    return;
  sconn->remote_host = strdup(remote_host);
  sconn->remote_port = port;
  sconn->no_reconnect = reconnect == FALSE;
  sconn->callback = callback;
  sconn->callback_context = context;

  silc_schedule_task_add_timeout(server->schedule, silc_server_connect_router,
				 sconn, 0, 0);
}

/* Connection authentication completion callback */

static void
silc_server_ke_auth_compl(SilcConnAuth connauth, SilcBool success,
			  void *context)
{
  SilcServerConnection sconn = context;
  SilcUnknownEntry entry = silc_packet_get_context(sconn->sock);
  SilcServer server = entry->server;
  SilcServerConfigServer *conn;
  SilcServerConfigConnParams *param;
  SilcIDListData idata;
  SilcServerEntry id_entry;
  unsigned char id[32];
  SilcUInt32 id_len;
  SilcID remote_id;

  SILC_LOG_DEBUG(("Connection authentication completed"));

  if (success == FALSE) {
    /* Authentication failed */
    /* XXX retry connecting */

    silc_server_disconnect_remote(server, sconn->sock,
				  SILC_STATUS_ERR_AUTH_FAILED, NULL);
    return;
  }

  SILC_LOG_INFO(("Connected to %s %s",
		 SILC_CONNTYPE_STRING(entry->data.conn_type),
		 sconn->remote_host));

  /* Create the actual entry for remote entity */
  switch (entry->data.conn_type) {
  case SILC_CONN_SERVER:
    SILC_LOG_DEBUG(("Remote is SILC server"));

    /* Add new server.  The server must register itself to us before it
       becomes registered to SILC network. */
    id_entry = silc_idlist_add_server(server->local_list,
				      strdup(sconn->remote_host),
				      SILC_SERVER, NULL, NULL, sconn->sock);
    if (!id_entry) {
      silc_server_disconnect_remote(server, sconn->sock,
				    SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
      silc_server_connection_free(sconn);
      silc_free(entry);
      return;
    }

    silc_idlist_add_data(id_entry, (SilcIDListData)entry);
    break;

  case SILC_CONN_ROUTER:
    SILC_LOG_DEBUG(("Remote is SILC router"));

    /* Register to network */
    silc_id_id2str(server->id, SILC_ID_SERVER, id, sizeof(id), &id_len);
    if (!silc_packet_send_va(sconn->sock, SILC_PACKET_NEW_SERVER, 0,
			     SILC_STR_UI_SHORT(id_len),
			     SILC_STR_DATA(id, id_len),
			     SILC_STR_UI_SHORT(strlen(server->server_name)),
			     SILC_STR_DATA(server->server_name,
					   strlen(server->server_name)),
			     SILC_STR_END)) {
      silc_server_disconnect_remote(server, sconn->sock,
				    SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
      silc_server_connection_free(sconn);
      silc_free(entry);
      return;
    }

    /* Get remote ID */
    silc_packet_get_ids(sconn->sock, NULL, NULL, NULL, &remote_id);

    /* Check that we do not have this ID already */
    id_entry = silc_idlist_find_server_by_id(server->local_list,
					     &remote_id.u.server_id,
					     TRUE, NULL);
    if (id_entry) {
      silc_idcache_del_by_context(server->local_list->servers, id_entry, NULL);
    } else {
      id_entry = silc_idlist_find_server_by_id(server->global_list,
					       &remote_id.u.server_id,
					       TRUE, NULL);
      if (id_entry)
	silc_idcache_del_by_context(server->global_list->servers, id_entry,
				    NULL);
    }

    SILC_LOG_DEBUG(("New server id(%s)",
		    silc_id_render(&remote_id.u.server_id, SILC_ID_SERVER)));

    /* Add the connected router to global server list.  Router is sent
       as NULL since it's local to us. */
    id_entry = silc_idlist_add_server(server->global_list,
				      strdup(sconn->remote_host),
				      SILC_ROUTER, &remote_id.u.server_id,
				      NULL, sconn->sock);
    if (!id_entry) {
      silc_server_disconnect_remote(server, sconn->sock,
				    SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
      silc_server_connection_free(sconn);
      silc_free(entry);
      return;
    }

    /* Registered */
    silc_idlist_add_data(id_entry, (SilcIDListData)entry);
    idata = (SilcIDListData)entry;
    idata->status |= (SILC_IDLIST_STATUS_REGISTERED |
		      SILC_IDLIST_STATUS_LOCAL);

    if (!sconn->backup) {
      /* Mark this router our primary router if we're still standalone */
      if (server->standalone) {
	SILC_LOG_DEBUG(("This connection is our primary router"));
	server->id_entry->router = id_entry;
	server->router = id_entry;
	server->router->server_type = SILC_ROUTER;
	server->standalone = FALSE;
	server->backup_primary = FALSE;

	/* Announce data if we are not backup router (unless not as primary
	   currently).  Backup router announces later at the end of
	   resuming protocol. */
	if (server->backup_router && server->server_type == SILC_ROUTER) {
	  SILC_LOG_DEBUG(("Announce data after resume protocol"));
	} else {
	  /* If we are router then announce our possible servers.  Backup
	     router announces also global servers. */
	  if (server->server_type == SILC_ROUTER)
	    silc_server_announce_servers(server,
					 server->backup_router ? TRUE : FALSE,
					 0, SILC_PRIMARY_ROUTE(server));

	  /* Announce our clients and channels to the router */
	  silc_server_announce_clients(server, 0, SILC_PRIMARY_ROUTE(server));
	  silc_server_announce_channels(server, 0, SILC_PRIMARY_ROUTE(server));
	}

#if 0
	/* If we are backup router then this primary router is whom we are
	   backing up. */
	if (server->server_type == SILC_BACKUP_ROUTER)
	  silc_server_backup_add(server, server->id_entry, sock->ip,
				 sconn->remote_port, TRUE);
#endif /* 0 */
      }
    } else {
      /* Add this server to be our backup router */
      id_entry->server_type = SILC_BACKUP_ROUTER;
      silc_server_backup_add(server, id_entry, sconn->backup_replace_ip,
			     sconn->backup_replace_port, FALSE);
    }

    break;

  default:
    silc_server_disconnect_remote(server, sconn->sock,
				  SILC_STATUS_ERR_AUTH_FAILED, NULL);
    silc_server_connection_free(sconn);
    silc_free(entry);
    return;
  }

  conn = sconn->conn.ref_ptr;
  param = &server->config->param;
  if (conn && conn->param)
    param = conn->param;

  /* Register rekey timeout */
  sconn->rekey_timeout = param->key_exchange_rekey;
  silc_schedule_task_add_timeout(server->schedule, silc_server_do_rekey,
				 sconn->sock, sconn->rekey_timeout, 0);

#if 0
  /* Perform keepalive. */
  silc_socket_set_heartbeat(sock, param->keepalive_secs, server,
			    silc_server_perform_heartbeat,
			    server->schedule);

 out:
  /* Call the completion callback to indicate that we've connected to
     the router */
  if (sconn && sconn->callback)
    (*sconn->callback)(server, id_entry, sconn->callback_context);

  /* Free the temporary connection data context */
  if (sconn) {
    silc_server_config_unref(&sconn->conn);
    silc_free(sconn->remote_host);
    silc_free(sconn->backup_replace_ip);
    silc_free(sconn);
  }
  if (sconn == server->router_conn)
    server->router_conn = NULL;
#endif /* 0 */

  silc_free(entry);
}

/* SKE completion callback */

static void silc_server_ke_completed(SilcSKE ske, SilcSKEStatus status,
				     SilcSKESecurityProperties prop,
				     SilcSKEKeyMaterial keymat,
				     SilcSKERekeyMaterial rekey,
				     void *context)
{
  SilcServerConnection sconn = context;
  SilcUnknownEntry entry = silc_packet_get_context(sconn->sock);
  SilcServer server = entry->server;
  SilcServerConfigRouter *conn = sconn->conn.ref_ptr;
  SilcAuthMethod auth_meth = SILC_AUTH_NONE;
  void *auth_data = NULL;
  SilcUInt32 auth_data_len = 0;
  SilcConnAuth connauth;
  SilcCipher send_key, receive_key;
  SilcHmac hmac_send, hmac_receive;
  SilcHash hash;

  if (status != SILC_SKE_STATUS_OK) {
    /* SKE failed */
    SILC_LOG_ERROR(("Error (%s) during Key Exchange protocol with %s (%s)",
		    silc_ske_map_status(status), entry->hostname, entry->ip));

    /* XXX retry connecting */
    silc_ske_free(ske);
    silc_server_disconnect_remote(server, sconn->sock,
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    silc_server_connection_free(sconn);
    return;
  }

  SILC_LOG_DEBUG(("Setting keys into use"));

  /* Set the keys into use.  The data will be encrypted after this. */
  if (!silc_ske_set_keys(ske, keymat, prop, &send_key, &receive_key,
			 &hmac_send, &hmac_receive, &hash)) {

    /* XXX retry connecting */

    /* Error setting keys */
    silc_ske_free(ske);
    silc_server_disconnect_remote(server, sconn->sock,
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    silc_server_connection_free(sconn);
    return;
  }
  silc_packet_set_keys(sconn->sock, send_key, receive_key, hmac_send,
		       hmac_receive, FALSE);

  SILC_LOG_DEBUG(("Starting connection authentication"));

  connauth = silc_connauth_alloc(server->schedule, ske,
				 server->config->conn_auth_timeout);
  if (!connauth) {
    /* XXX retry connecting */

    /** Error allocating auth protocol */
    silc_ske_free(ske);
    silc_server_disconnect_remote(server, sconn->sock,
				  SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
    silc_server_connection_free(sconn);
    return;
  }

  /* Get authentication method */
  if (conn) {
    if (conn->passphrase) {
      if (conn->publickeys && !server->config->prefer_passphrase_auth) {
	auth_meth = SILC_AUTH_PUBLIC_KEY;
	auth_data = server->private_key;
      } else {
	auth_meth = SILC_AUTH_PASSWORD;
	auth_data = conn->passphrase;
	auth_data_len = conn->passphrase_len;
      }
    } else {
      auth_meth = SILC_AUTH_PUBLIC_KEY;
      auth_data = server->private_key;
    }
  }

  /* Start connection authentication */
  silc_connauth_initiator(connauth, server->server_type == SILC_ROUTER ?
			  SILC_CONN_ROUTER : SILC_CONN_SERVER, auth_meth,
			  auth_data, auth_data_len,
			  silc_server_ke_auth_compl, sconn);
}

/* Function that is called when the network connection to a router has
   been established.  This will continue with the key exchange protocol
   with the remote router. */

void silc_server_start_key_exchange(SilcServerConnection sconn)
{
  SilcServer server = sconn->server;
  SilcServerConfigRouter *conn = sconn->conn.ref_ptr;
  SilcUnknownEntry entry;
  SilcSKEParamsStruct params;
  SilcSKE ske;

  /* Cancel any possible retry timeouts */
  silc_schedule_task_del_by_context(server->schedule, sconn);

  /* Create packet stream */
  sconn->sock = silc_packet_stream_create(server->packet_engine,
					  server->schedule, sconn->stream);
  if (!sconn->sock) {
    SILC_LOG_ERROR(("Cannot connect: cannot create packet stream"));
    silc_stream_destroy(sconn->stream);
    silc_server_connection_free(sconn);
    return;
  }
  server->stat.conn_num++;

  /* Set source ID to packet stream */
  if (!silc_packet_set_ids(sconn->sock, SILC_ID_SERVER, server->id,
			   0, NULL)) {
    silc_packet_stream_destroy(sconn->sock);
    silc_server_connection_free(sconn);
    return;
  }

  /* Create entry for remote entity */
  entry = silc_calloc(1, sizeof(*entry));
  if (!entry) {
    silc_packet_stream_destroy(sconn->sock);
    silc_server_connection_free(sconn);
    return;
  }
  entry->server = server;
  silc_packet_set_context(sconn->sock, entry);

  /* Set Key Exchange flags from configuration, but fall back to global
     settings too. */
  memset(&params, 0, sizeof(params));
  SILC_GET_SKE_FLAGS(conn, params.flags);
  if (server->config->param.key_exchange_pfs)
    params.flags |= SILC_SKE_SP_FLAG_PFS;

  /* Start SILC Key Exchange protocol */
  SILC_LOG_DEBUG(("Starting key exchange protocol"));
  ske = silc_ske_alloc(server->rng, server->schedule, server->repository,
		       server->public_key, server->private_key, sconn->sock);
  if (!ske) {
    silc_free(entry);
    silc_packet_stream_destroy(sconn->sock);
    silc_server_connection_free(sconn);
    return;
  }
  silc_ske_set_callbacks(ske, silc_server_verify_key,
			 silc_server_ke_completed, sconn->sock);

  /* Start key exchange protocol */
  params.version = silc_version_string;
  params.timeout_secs = server->config->key_exchange_timeout;
  silc_ske_initiator(ske, sconn->sock, &params, NULL);
}

/* Timeout callback that will be called to retry connecting to remote
   router. This is used by both normal and router server. This will wait
   before retrying the connecting. The timeout is generated by exponential
   backoff algorithm. */

SILC_TASK_CALLBACK(silc_server_connect_to_router_retry)
{
  SilcServerConnection sconn = context;
  SilcServer server = sconn->server;
  SilcServerConfigRouter *conn = sconn->conn.ref_ptr;
  SilcServerConfigConnParams *param =
		(conn->param ? conn->param : &server->config->param);

  SILC_LOG_INFO(("Retrying connecting to %s:%d", sconn->remote_host,
		 sconn->remote_port));

  /* Calculate next timeout */
  if (sconn->retry_count >= 1) {
    sconn->retry_timeout = sconn->retry_timeout * SILC_SERVER_RETRY_MULTIPLIER;
    if (sconn->retry_timeout > param->reconnect_interval_max)
      sconn->retry_timeout = param->reconnect_interval_max;
  } else {
    sconn->retry_timeout = param->reconnect_interval;
  }
  sconn->retry_count++;
  sconn->retry_timeout = sconn->retry_timeout +
    (silc_rng_get_rn32(server->rng) % SILC_SERVER_RETRY_RANDOMIZER);

  /* If we've reached max retry count, give up. */
  if ((sconn->retry_count > param->reconnect_count) &&
      !param->reconnect_keep_trying) {
    SILC_LOG_ERROR(("Could not connect, giving up"));
    silc_server_connection_free(sconn);
    return;
  }

  SILC_LOG_DEBUG(("Retrying connecting %d seconds", sconn->retry_timeout));

  /* We will lookup a fresh pointer later */
  silc_server_config_unref(&sconn->conn);

  /* Wait before retrying */
  silc_schedule_task_del_by_context(server->schedule, sconn);
  silc_schedule_task_add_timeout(server->schedule, silc_server_connect_router,
				 sconn, sconn->retry_timeout, 0);
}

/* Callback for async connection to remote router */

static void silc_server_connection_established(SilcNetStatus status,
					       SilcStream stream,
					       void *context)
{
  SilcServerConnection sconn = context;
  SilcServer server = sconn->server;

  silc_schedule_task_del_by_context(server->schedule, sconn);
  sconn->op = NULL;

  switch (status) {
  case SILC_NET_OK:
    SILC_LOG_DEBUG(("Connection to %s:%d established",
		    sconn->remote_host, sconn->remote_port));

    /* Continue with key exchange protocol */
    sconn->stream = stream;
    silc_server_start_key_exchange(sconn);
    break;

  case SILC_NET_UNKNOWN_IP:
  case SILC_NET_UNKNOWN_HOST:
    SILC_LOG_ERROR(("Could not connect to %s:%d: %s",
		    sconn->remote_host, sconn->remote_port,
		    silc_net_get_error_string(status)));
    silc_server_connection_free(sconn);
    break;

  default:
    SILC_LOG_ERROR(("Could not connect to %s:%d: %s",
		    sconn->remote_host, sconn->remote_port,
		    silc_net_get_error_string(status)));
    if (!sconn->no_reconnect) {
      silc_schedule_task_add_timeout(sconn->server->schedule,
				     silc_server_connect_to_router_retry,
				     sconn, 1, 0);
    } else {
      silc_server_connection_free(sconn);
    }
    break;
  }
}

/* Generic routine to use connect to a router. */

SILC_TASK_CALLBACK(silc_server_connect_router)
{
  SilcServerConnection sconn = context;
  SilcServer server = sconn->server;
  SilcServerConfigRouter *rconn;

  silc_schedule_task_del_by_context(server->schedule, sconn);

  /* Don't connect if we are shutting down. */
  if (server->server_shutdown) {
    silc_server_connection_free(sconn);
    return;
  }

  SILC_LOG_INFO(("Connecting to the %s %s on port %d",
		 (sconn->backup ? "backup router" : "router"),
		 sconn->remote_host, sconn->remote_port));

  if (!server->no_conf) {
    /* Find connection configuration */
    rconn = silc_server_config_find_router_conn(server, sconn->remote_host,
						sconn->remote_port);
    if (!rconn) {
      SILC_LOG_INFO(("Unconfigured %s connection %s:%d, cannot connect",
		     (sconn->backup ? "backup router" : "router"),
		     sconn->remote_host, sconn->remote_port));
      silc_server_connection_free(sconn);
      return;
    }
    silc_server_config_ref(&sconn->conn, server->config, (void *)rconn);
  }

  /* Connect to remote host */
  sconn->op =
    silc_net_tcp_connect((!server->config->server_info->primary ? NULL :
			  server->config->server_info->primary->server_ip),
			 sconn->remote_host, sconn->remote_port,
			 server->schedule, silc_server_connection_established,
			 sconn);
  if (!sconn->op) {
    SILC_LOG_ERROR(("Could not connect to router %s:%d",
		    sconn->remote_host, sconn->remote_port));
    silc_server_connection_free(sconn);
    return;
  }

  /* Add to connection list */
  silc_dlist_add(server->conns, sconn);
}

/* This function connects to our primary router or if we are a router this
   establishes all our primary routes. This is called at the start of the
   server to do authentication and key exchange with our router - called
   from schedule. */

SILC_TASK_CALLBACK(silc_server_connect_to_router)
{
  SilcServer server = context;
  SilcServerConnection sconn;
  SilcServerConfigRouter *ptr;

  /* Don't connect if we are shutting down. */
  if (server->server_shutdown)
    return;

  SILC_LOG_DEBUG(("We are %s",
		  (server->server_type == SILC_SERVER ?
		   "normal server" : server->server_type == SILC_ROUTER ?
		   "router" : "backup router/normal server")));

  /* XXX */
  if (!server->config->routers) {
    /* There wasn't a configured router, we will continue but we don't
       have a connection to outside world.  We will be standalone server. */
    SILC_LOG_DEBUG(("No router(s), we are standalone"));
    server->standalone = TRUE;
    return;
  }

  /* Create the connections to all our routes */
  for (ptr = server->config->routers; ptr; ptr = ptr->next) {

    SILC_LOG_DEBUG(("%s connection [%s] %s:%d",
		    ptr->backup_router ? "Backup router" : "Router",
		    ptr->initiator ? "Initiator" : "Responder",
		    ptr->host, ptr->port));

    if (server->server_type == SILC_ROUTER && ptr->backup_router &&
	ptr->initiator == FALSE && !server->backup_router &&
	!silc_server_config_get_backup_router(server))
      server->wait_backup = TRUE;

    if (!ptr->initiator)
      continue;

    /* Check whether we are connecting or connected to this host already */
    if (silc_server_num_sockets_by_remote(server,
					  silc_net_is_ip(ptr->host) ?
					  ptr->host : NULL,
					  silc_net_is_ip(ptr->host) ?
					  NULL : ptr->host, ptr->port)) {
      SILC_LOG_DEBUG(("We are already connected to %s:%d",
		      ptr->host, ptr->port));

      /* If we don't have primary router and this connection is our
	 primary router we are in desync.  Reconnect to the primary. */
      if (server->standalone && !server->router) {
	/* XXX */
	SilcPacketStream sock;
	SilcServerConfigRouter *primary =
	  silc_server_config_get_primary_router(server);
	if (primary != ptr)
	  continue;
	sock = silc_server_find_socket_by_host(server, SILC_CONN_ROUTER,
					       ptr->host, ptr->port);
	if (!sock)
	  continue;
	server->backup_noswitch = TRUE;
#if 0
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	silc_server_disconnect_remote(server, sock, 0, NULL);
#endif /* 0 */
	server->backup_noswitch = FALSE;
	SILC_LOG_DEBUG(("Reconnecting to primary router"));
      } else {
	continue;
      }
    }

    /* Allocate connection object for hold connection specific stuff. */
    sconn = silc_calloc(1, sizeof(*sconn));
    if (!sconn)
      continue;
    sconn->remote_host = strdup(ptr->host);
    sconn->remote_port = ptr->port;
    sconn->backup = ptr->backup_router;
    if (sconn->backup) {
      sconn->backup_replace_ip = strdup(ptr->backup_replace_ip);
      sconn->backup_replace_port = ptr->backup_replace_port;
    }

    /* XXX */
    if (!server->router_conn && !sconn->backup)
      server->router_conn = sconn;

    /* Connect */
    silc_server_connect_router(server->schedule, server, SILC_TASK_EXPIRE,
			       0, sconn);
  }
}


/************************ Accepting new connection **************************/

/* After this is called, server don't wait for backup router anymore.
   This gets called automatically even after we have backup router
   connection established. */

SILC_TASK_CALLBACK(silc_server_backup_router_wait)
{
  SilcServer server = context;
  server->wait_backup = FALSE;
}

/* Authentication data callback */

static SilcBool
silc_server_accept_get_auth(SilcConnAuth connauth,
			    SilcConnectionType conn_type,
			    unsigned char **passphrase,
			    SilcUInt32 *passphrase_len,
			    SilcSKR *repository,
			    void *context)
{
  SilcPacketStream sock = context;
  SilcUnknownEntry entry = silc_packet_get_context(sock);
  SilcServer server = entry->server;

  SILC_LOG_DEBUG(("Remote connection type %d", conn_type));

  /* Remote end is client */
  if (conn_type == SILC_CONN_CLIENT) {
    SilcServerConfigClient *cconfig = entry->cconfig.ref_ptr;
    if (!cconfig)
      return FALSE;

    *passphrase = cconfig->passphrase;
    *passphrase_len = cconfig->passphrase_len;
    if (cconfig->publickeys)
      *repository = server->repository;

    entry->data.conn_type = conn_type;
    return TRUE;
  }

  /* Remote end is server */
  if (conn_type == SILC_CONN_SERVER) {
    SilcServerConfigServer *sconfig = entry->sconfig.ref_ptr;
    if (!sconfig)
      return FALSE;

    *passphrase = sconfig->passphrase;
    *passphrase_len = sconfig->passphrase_len;
    if (sconfig->publickeys)
      *repository = server->repository;

    entry->data.conn_type = conn_type;
    return TRUE;
  }

  /* Remote end is router */
  if (conn_type == SILC_CONN_ROUTER) {
    SilcServerConfigRouter *rconfig = entry->rconfig.ref_ptr;
    if (!rconfig)
      return FALSE;

    *passphrase = rconfig->passphrase;
    *passphrase_len = rconfig->passphrase_len;
    if (rconfig->publickeys)
      *repository = server->repository;

    entry->data.conn_type = conn_type;
    return TRUE;
  }

  return FALSE;
}

/* Authentication completion callback. */

static void
silc_server_accept_auth_compl(SilcConnAuth connauth, SilcBool success,
			      void *context)
{
  SilcPacketStream sock = context;
  SilcUnknownEntry entry = silc_packet_get_context(sock);
  SilcIDListData idata = (SilcIDListData)entry;
  SilcServer server = entry->server;
  SilcServerConfigConnParams *param = &server->config->param;
  SilcServerConnection sconn;
  void *id_entry;
  const char *hostname;
  SilcUInt16 port;

  silc_socket_stream_get_info(silc_packet_stream_get_stream(sock),
			      NULL, &hostname, NULL, &port);

  if (success == FALSE) {
    /* Authentication failed */
    SILC_LOG_INFO(("Authentication failed for %s (%s) [%s]", entry->hostname,
		   entry->ip, SILC_CONNTYPE_STRING(entry->data.conn_type)));
    server->stat.auth_failures++;
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    goto out;
  }

  SILC_LOG_DEBUG(("Checking whether connection is allowed"));

  switch (entry->data.conn_type) {
  case SILC_CONN_CLIENT:
    {
      SilcClientEntry client;
      SilcServerConfigClient *conn = entry->cconfig.ref_ptr;

      /* Verify whether this connection is after all allowed to connect */
      if (!silc_server_connection_allowed(server, sock, entry->data.conn_type,
					  &server->config->param,
					  conn->param,
					  silc_connauth_get_ske(connauth))) {
	server->stat.auth_failures++;
	goto out;
      }

      /* If we are primary router and we have backup router configured
	 but it has not connected to use yet, do not accept any other
	 connection. */
      if (server->wait_backup && server->server_type == SILC_ROUTER &&
	  !server->backup_router) {
	SilcServerConfigRouter *router;
	router = silc_server_config_get_backup_router(server);
	if (router && strcmp(server->config->server_info->primary->server_ip,
			     entry->ip) &&
	    silc_server_find_socket_by_host(server,
					    SILC_CONN_SERVER,
					    router->backup_replace_ip, 0)) {
	  SILC_LOG_INFO(("Will not accept connections because we do "
			 "not have backup router connection established"));
	  silc_server_disconnect_remote(server, sock,
					SILC_STATUS_ERR_PERM_DENIED,
					"We do not have connection to backup "
					"router established, try later");
	  server->stat.auth_failures++;

	  /* From here on, wait 20 seconds for the backup router to appear. */
	  silc_schedule_task_add_timeout(server->schedule,
					 silc_server_backup_router_wait,
					 (void *)server, 20, 0);
	  goto out;
	}
      }

      SILC_LOG_DEBUG(("Remote host is client"));
      SILC_LOG_INFO(("Connection %s (%s) is client", entry->hostname,
		     entry->ip));

      /* Add the client to the client ID cache. The nickname and Client ID
	 and other information is created after we have received NEW_CLIENT
	 packet from client. */
      client = silc_idlist_add_client(server->local_list,
				      NULL, NULL, NULL, NULL, NULL, sock);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to cache"));
	server->stat.auth_failures++;
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_AUTH_FAILED, NULL);
	goto out;
      }
      entry->data.status |= SILC_IDLIST_STATUS_LOCAL;

      /* Statistics */
      server->stat.my_clients++;
      server->stat.clients++;
      server->stat.cell_clients++;

      /* Get connection parameters */
      if (conn->param) {
	param = conn->param;

	if (!param->keepalive_secs)
	  param->keepalive_secs = server->config->param.keepalive_secs;

	if (!param->qos && server->config->param.qos) {
	  param->qos = server->config->param.qos;
	  param->qos_rate_limit = server->config->param.qos_rate_limit;
	  param->qos_bytes_limit = server->config->param.qos_bytes_limit;
	  param->qos_limit_sec = server->config->param.qos_limit_sec;
	  param->qos_limit_usec = server->config->param.qos_limit_usec;
	}

	/* Check if to be anonymous connection */
	if (param->anonymous)
	  client->mode |= SILC_UMODE_ANONYMOUS;
      }

      /* Add public key to repository */
      if (!silc_server_get_public_key_by_client(server, client, NULL))
	silc_skr_add_public_key_simple(server->repository,
				       entry->data.public_key,
				       SILC_SKR_USAGE_IDENTIFICATION, client,
				       NULL);

      id_entry = (void *)client;
      break;
    }

  case SILC_CONN_SERVER:
  case SILC_CONN_ROUTER:
    {
      SilcServerEntry new_server;
      SilcBool initiator = FALSE;
      SilcBool backup_local = FALSE;
      SilcBool backup_router = FALSE;
      char *backup_replace_ip = NULL;
      SilcUInt16 backup_replace_port = 0;
      SilcServerConfigServer *sconn = entry->sconfig.ref_ptr;
      SilcServerConfigRouter *rconn = entry->rconfig.ref_ptr;

      /* If we are backup router and this is incoming server connection
	 and we do not have connection to primary router, do not allow
	 the connection. */
      if (server->server_type == SILC_BACKUP_ROUTER &&
	  entry->data.conn_type == SILC_CONN_SERVER &&
	  !SILC_PRIMARY_ROUTE(server)) {
	SILC_LOG_INFO(("Will not accept server connection because we do "
		       "not have primary router connection established"));
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_PERM_DENIED,
				      "We do not have connection to primary "
				      "router established, try later");
	server->stat.auth_failures++;
	goto out;
      }

      if (entry->data.conn_type == SILC_CONN_ROUTER) {
	/* Verify whether this connection is after all allowed to connect */
	if (!silc_server_connection_allowed(server, sock,
					    entry->data.conn_type,
					    &server->config->param,
					    rconn ? rconn->param : NULL,
					    silc_connauth_get_ske(connauth))) {
	  server->stat.auth_failures++;
	  goto out;
	}

	if (rconn) {
	  if (rconn->param) {
	    param = rconn->param;

	    if (!param->keepalive_secs)
	      param->keepalive_secs = server->config->param.keepalive_secs;

	    if (!param->qos && server->config->param.qos) {
	      param->qos = server->config->param.qos;
	      param->qos_rate_limit = server->config->param.qos_rate_limit;
	      param->qos_bytes_limit = server->config->param.qos_bytes_limit;
	      param->qos_limit_sec = server->config->param.qos_limit_sec;
	      param->qos_limit_usec = server->config->param.qos_limit_usec;
	    }
	  }

	  initiator = rconn->initiator;
	  backup_local = rconn->backup_local;
	  backup_router = rconn->backup_router;
	  backup_replace_ip = rconn->backup_replace_ip;
	  backup_replace_port = rconn->backup_replace_port;
	}
      }

      if (entry->data.conn_type == SILC_CONN_SERVER) {
	/* Verify whether this connection is after all allowed to connect */
	if (!silc_server_connection_allowed(server, sock,
					    entry->data.conn_type,
					    &server->config->param,
					    sconn ? sconn->param : NULL,
					    silc_connauth_get_ske(connauth))) {
	  server->stat.auth_failures++;
	  goto out;
	}
	if (sconn) {
	  if (sconn->param) {
	    param = sconn->param;

	    if (!param->keepalive_secs)
	      param->keepalive_secs = server->config->param.keepalive_secs;

	    if (!param->qos && server->config->param.qos) {
	      param->qos = server->config->param.qos;
	      param->qos_rate_limit = server->config->param.qos_rate_limit;
	      param->qos_bytes_limit = server->config->param.qos_bytes_limit;
	      param->qos_limit_sec = server->config->param.qos_limit_sec;
	      param->qos_limit_usec = server->config->param.qos_limit_usec;
	    }
	  }

	  backup_router = sconn->backup_router;
	}
      }

      /* If we are primary router and we have backup router configured
	 but it has not connected to use yet, do not accept any other
	 connection. */
#if 0
      if (server->wait_backup && server->server_type == SILC_ROUTER &&
	  !server->backup_router && !backup_router) {
	SilcServerConfigRouter *router;
	router = silc_server_config_get_backup_router(server);
	if (router && strcmp(server->config->server_info->primary->server_ip,
			     ip) &&
	    silc_server_find_socket_by_host(server,
					    SILC_CONN_SERVER,
					    router->backup_replace_ip, 0)) {
	  SILC_LOG_INFO(("Will not accept connections because we do "
			 "not have backup router connection established"));
	  silc_server_disconnect_remote(server, sock,
					SILC_STATUS_ERR_PERM_DENIED,
					"We do not have connection to backup "
					"router established, try later");
	  server->stat.auth_failures++;

	  /* From here on, wait 20 seconds for the backup router to appear. */
	  silc_schedule_task_add_timeout(server->schedule,
					 silc_server_backup_router_wait,
					 (void *)server, 20, 0);
	  goto out;
	}
      }
#endif /* 0 */

      SILC_LOG_DEBUG(("Remote host is %s",
		      entry->data.conn_type == SILC_CONN_SERVER ?
		      "server" : (backup_router ?
				  "backup router" : "router")));
      SILC_LOG_INFO(("Connection %s (%s) is %s", entry->hostname,
		     entry->ip, entry->data.conn_type == SILC_CONN_SERVER ?
		     "server" : (backup_router ?
				 "backup router" : "router")));

      /* Add the server into server cache. The server name and Server ID
	 is updated after we have received NEW_SERVER packet from the
	 server. We mark ourselves as router for this server if we really
	 are router. */
      new_server =
	silc_idlist_add_server((entry->data.conn_type == SILC_CONN_SERVER ?
				server->local_list : (backup_router ?
						      server->local_list :
						      server->global_list)),
			       NULL,
			       (entry->data.conn_type == SILC_CONN_SERVER ?
				SILC_SERVER : SILC_ROUTER),
			       NULL,
			       (entry->data.conn_type == SILC_CONN_SERVER ?
				server->id_entry : (backup_router ?
						    server->id_entry : NULL)),
			       sock);
      if (!new_server) {
	SILC_LOG_ERROR(("Could not add new server to cache"));
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_AUTH_FAILED, NULL);
	server->stat.auth_failures++;
	goto out;
      }
      entry->data.status |= SILC_IDLIST_STATUS_LOCAL;

      id_entry = (void *)new_server;

      /* If the incoming connection is router and marked as backup router
	 then add it to be one of our backups */
      if (entry->data.conn_type == SILC_CONN_ROUTER && backup_router) {
	/* Change it back to SERVER type since that's what it really is. */
	if (backup_local)
	  entry->data.conn_type = SILC_CONN_SERVER;
	new_server->server_type = SILC_BACKUP_ROUTER;

	SILC_SERVER_SEND_OPERS(server, FALSE, TRUE, SILC_NOTIFY_TYPE_NONE,
			       ("Backup router %s is now online",
				entry->hostname));

	/* Remove the backup waiting with timeout */
	silc_schedule_task_add_timeout(server->schedule,
				       silc_server_backup_router_wait,
				       (void *)server, 10, 0);
      }

      /* Statistics */
      if (entry->data.conn_type == SILC_CONN_SERVER) {
	server->stat.my_servers++;
	server->stat.servers++;
      } else {
	server->stat.my_routers++;
	server->stat.routers++;
      }

      /* Check whether this connection is to be our primary router connection
	 if we do not already have the primary route. */
      if (!backup_router &&
	  server->standalone && entry->data.conn_type == SILC_CONN_ROUTER) {
	if (silc_server_config_is_primary_route(server) && !initiator)
	  break;

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
    goto out;
    break;
  }

  /* Add connection to server->conns so that we know we have connection
     to this peer. */
  sconn = silc_calloc(1, sizeof(*sconn));
  sconn->server = server;
  sconn->sock = sock;
  sconn->remote_host = strdup(hostname);
  sconn->remote_port = port;
  silc_dlist_add(server->conns, sconn);
  idata->sconn = sconn;
  idata->last_receive = time(NULL);

  /* Add the common data structure to the ID entry. */
  silc_idlist_add_data(id_entry, (SilcIDListData)entry);
  silc_packet_set_context(sock, id_entry);

  /* Connection has been fully established now. Everything is ok. */
  SILC_LOG_DEBUG(("New connection authenticated"));

#if 0
  /* Perform keepalive. */
  if (param->keepalive_secs)
    silc_socket_set_heartbeat(sock, param->keepalive_secs, server,
			      silc_server_perform_heartbeat,
			      server->schedule);
#endif

  /* Perform Quality of Service */
  if (param->qos)
    silc_socket_stream_set_qos(silc_packet_stream_get_stream(sock),
			       param->qos_rate_limit, param->qos_bytes_limit,
			       param->qos_limit_sec, param->qos_limit_usec);

  silc_server_config_unref(&entry->cconfig);
  silc_server_config_unref(&entry->sconfig);
  silc_server_config_unref(&entry->rconfig);
  silc_free(entry);

 out:
  silc_ske_free(silc_connauth_get_ske(connauth));
  silc_connauth_free(connauth);
}

/* SKE completion callback.  We set the new keys into use here. */

static void
silc_server_accept_completed(SilcSKE ske, SilcSKEStatus status,
			     SilcSKESecurityProperties prop,
			     SilcSKEKeyMaterial keymat,
			     SilcSKERekeyMaterial rekey,
			     void *context)
{
  SilcPacketStream sock = context;
  SilcUnknownEntry entry = silc_packet_get_context(sock);
  SilcIDListData idata = (SilcIDListData)entry;
  SilcServer server = entry->server;
  SilcConnAuth connauth;
  SilcCipher send_key, receive_key;
  SilcHmac hmac_send, hmac_receive;
  SilcHash hash;

  if (status != SILC_SKE_STATUS_OK) {
    /* SKE failed */
    SILC_LOG_ERROR(("Error (%s) during Key Exchange protocol with %s (%s)",
		    silc_ske_map_status(status), entry->hostname, entry->ip));
    silc_ske_free(ske);
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    return;
  }

  SILC_LOG_DEBUG(("Setting keys into use"));

  /* Set the keys into use.  The data will be encrypted after this. */
  if (!silc_ske_set_keys(ske, keymat, prop, &send_key, &receive_key,
			 &hmac_send, &hmac_receive, &hash)) {
    /* Error setting keys */
    silc_ske_free(ske);
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_KEY_EXCHANGE_FAILED, NULL);
    return;
  }
  silc_packet_set_keys(sock, send_key, receive_key, hmac_send,
		       hmac_receive, FALSE);

  idata->rekey = rekey;
  idata->public_key = silc_pkcs_public_key_copy(prop->public_key);

  SILC_LOG_DEBUG(("Starting connection authentication"));
  server->stat.auth_attempts++;

  connauth = silc_connauth_alloc(server->schedule, ske,
				 server->config->conn_auth_timeout);
  if (!connauth) {
    /** Error allocating auth protocol */
    silc_ske_free(ske);
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
    return;
  }

  /* Start connection authentication */
  silc_connauth_responder(connauth, silc_server_accept_get_auth,
			  silc_server_accept_auth_compl, sock);
}

/* Accept new TCP connection */

static void silc_server_accept_new_connection(SilcNetStatus status,
					      SilcStream stream,
					      void *context)
{
  SilcServer server = context;
  SilcPacketStream packet_stream;
  SilcServerConfigClient *cconfig = NULL;
  SilcServerConfigServer *sconfig = NULL;
  SilcServerConfigRouter *rconfig = NULL;
  SilcServerConfigDeny *deny;
  SilcUnknownEntry entry;
  SilcSKE ske;
  SilcSKEParamsStruct params;
  char *hostname, *ip;
  SilcUInt16 port;

  SILC_LOG_DEBUG(("Accepting new connection"));

  /* Check for maximum allowed connections */
  server->stat.conn_attempts++;
  if (silc_dlist_count(server->conns) >
      server->config->param.connections_max) {
    SILC_LOG_ERROR(("Refusing connection, server is full"));
    server->stat.conn_failures++;
    silc_stream_destroy(stream);
    return;
  }

  /* Get hostname, IP and port */
  if (!silc_socket_stream_get_info(stream, NULL, (const char **)&hostname,
				   (const char **)&ip, &port)) {
    /* Bad socket stream */
    server->stat.conn_failures++;
    silc_stream_destroy(stream);
    return;
  }

  /* Create packet stream */
  packet_stream = silc_packet_stream_create(server->packet_engine,
					    server->schedule, stream);
  if (!packet_stream) {
    SILC_LOG_ERROR(("Refusing connection, cannot create packet stream"));
    server->stat.conn_failures++;
    silc_stream_destroy(stream);
    return;
  }
  server->stat.conn_num++;

  /* Set source ID to packet stream */
  if (!silc_packet_set_ids(packet_stream, SILC_ID_SERVER, server->id,
			   0, NULL)) {
    /* Out of memory */
    server->stat.conn_failures++;
    silc_packet_stream_destroy(packet_stream);
    return;
  }

  /* Check whether this connection is denied to connect to us. */
  deny = silc_server_config_find_denied(server, ip);
  if (!deny)
    deny = silc_server_config_find_denied(server, hostname);
  if (deny) {
    /* The connection is denied */
    SILC_LOG_INFO(("Connection %s (%s) is denied", hostname, ip));
    silc_server_disconnect_remote(server, packet_stream,
				  SILC_STATUS_ERR_BANNED_FROM_SERVER,
				  deny->reason);
    return;
  }

  /* Check whether we have configured this sort of connection at all. We
     have to check all configurations since we don't know what type of
     connection this is. */
  if (!(cconfig = silc_server_config_find_client(server, ip)))
    cconfig = silc_server_config_find_client(server, hostname);
  if (!(sconfig = silc_server_config_find_server_conn(server, ip)))
    sconfig = silc_server_config_find_server_conn(server, hostname);
  if (server->server_type == SILC_ROUTER)
    if (!(rconfig = silc_server_config_find_router_conn(server, ip, port)))
      rconfig = silc_server_config_find_router_conn(server, hostname, port);
  if (!cconfig && !sconfig && !rconfig) {
    SILC_LOG_INFO(("Connection %s (%s) is not allowed", hostname, ip));
    server->stat.conn_failures++;
    silc_server_disconnect_remote(server, packet_stream,
				  SILC_STATUS_ERR_BANNED_FROM_SERVER, NULL);
    return;
  }

  /* The connection is allowed */
  entry = silc_calloc(1, sizeof(*entry));
  if (!entry) {
    server->stat.conn_failures++;
    silc_server_disconnect_remote(server, packet_stream,
				  SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
    return;
  }
  entry->hostname = hostname;
  entry->ip = ip;
  entry->port = port;
  entry->server = server;
  silc_packet_set_context(packet_stream, entry);

  silc_server_config_ref(&entry->cconfig, server->config, cconfig);
  silc_server_config_ref(&entry->sconfig, server->config, sconfig);
  silc_server_config_ref(&entry->rconfig, server->config, rconfig);

  /* Take flags for key exchange. Since we do not know what type of connection
     this is, we go through all found configurations and use the global ones
     as well. This will result always into strictest key exchange flags. */
  memset(&params, 0, sizeof(params));
  SILC_GET_SKE_FLAGS(cconfig, params.flags);
  SILC_GET_SKE_FLAGS(sconfig, params.flags);
  SILC_GET_SKE_FLAGS(rconfig, params.flags);
  if (server->config->param.key_exchange_pfs)
    params.flags |= SILC_SKE_SP_FLAG_PFS;

  SILC_LOG_INFO(("Incoming connection %s (%s)", hostname, ip));
  server->stat.conn_attempts++;

  /* Start SILC Key Exchange protocol */
  SILC_LOG_DEBUG(("Starting key exchange protocol"));
  ske = silc_ske_alloc(server->rng, server->schedule, server->repository,
		       server->public_key, server->private_key,
		       packet_stream);
  if (!ske) {
    server->stat.conn_failures++;
    silc_server_disconnect_remote(server, packet_stream,
				  SILC_STATUS_ERR_RESOURCE_LIMIT, NULL);
    return;
  }
  silc_ske_set_callbacks(ske, silc_server_verify_key,
			 silc_server_accept_completed, packet_stream);

  /* Start key exchange protocol */
  params.version = silc_version_string;
  params.timeout_secs = server->config->key_exchange_timeout;
  silc_ske_responder(ske, packet_stream, &params);
}


/********************************** Rekey ***********************************/

/* Initiator rekey completion callback */

static void silc_server_rekey_completion(SilcSKE ske,
					 SilcSKEStatus status,
					 const SilcSKESecurityProperties prop,
					 const SilcSKEKeyMaterial keymat,
					 SilcSKERekeyMaterial rekey,
					 void *context)
{
  SilcPacketStream sock = context;
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcServer server = idata->sconn->server;

  idata->sconn->op = NULL;
  if (status != SILC_SKE_STATUS_OK) {
    SILC_LOG_ERROR(("Error during rekey protocol with %s",
		    idata->sconn->remote_host));
    return;
  }

  SILC_LOG_DEBUG(("Rekey protocol completed with %s:%d [%s]",
		  idata->sconn->remote_host, idata->sconn->remote_port,
		  SILC_CONNTYPE_STRING(idata->conn_type)));

  /* Save rekey data for next rekey */
  idata->rekey = rekey;

  /* Register new rekey timeout */
  silc_schedule_task_add_timeout(server->schedule, silc_server_do_rekey,
				 sock, idata->sconn->rekey_timeout, 0);
}

/* Rekey callback.  Start rekey as initiator */

SILC_TASK_CALLBACK(silc_server_do_rekey)
{
  SilcServer server = app_context;
  SilcPacketStream sock = context;
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcSKE ske;

  /* Do not execute rekey with disabled connections */
  if (idata->status & SILC_IDLIST_STATUS_DISABLED)
    return;

  /* If another protocol is active do not start rekey */
  if (idata->sconn->op) {
    SILC_LOG_DEBUG(("Waiting for other protocol to finish before rekeying"));
    silc_schedule_task_add_timeout(server->schedule, silc_server_do_rekey,
				   sock, 60, 0);
    return;
  }

  SILC_LOG_DEBUG(("Executing rekey protocol with %s:%d [%s]",
		  idata->sconn->remote_host, idata->sconn->remote_port,
		  SILC_CONNTYPE_STRING(idata->conn_type)));

  /* Allocate SKE */
  ske = silc_ske_alloc(server->rng, server->schedule, server->repository,
		       server->public_key, server->private_key, sock);
  if (!ske)
    return;

  /* Set SKE callbacks */
  silc_ske_set_callbacks(ske, NULL, silc_server_rekey_completion, sock);

  /* Perform rekey */
  idata->sconn->op = silc_ske_rekey_initiator(ske, sock, idata->rekey);
}

/* Responder rekey completion callback */

static void
silc_server_rekey_resp_completion(SilcSKE ske,
				  SilcSKEStatus status,
				  const SilcSKESecurityProperties prop,
				  const SilcSKEKeyMaterial keymat,
				  SilcSKERekeyMaterial rekey,
				  void *context)
{
  SilcPacketStream sock = context;
  SilcIDListData idata = silc_packet_get_context(sock);

  idata->sconn->op = NULL;
  if (status != SILC_SKE_STATUS_OK) {
    SILC_LOG_ERROR(("Error during rekey protocol with %s",
		    idata->sconn->remote_host));
    return;
  }

  SILC_LOG_DEBUG(("Rekey protocol completed with %s:%d [%s]",
		  idata->sconn->remote_host, idata->sconn->remote_port,
		  SILC_CONNTYPE_STRING(idata->conn_type)));

  /* Save rekey data for next rekey */
  idata->rekey = rekey;
}

/* Start rekey as responder */

static void silc_server_rekey(SilcServer server, SilcPacketStream sock,
			      SilcPacket packet)
{
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcSKE ske;

  SILC_LOG_DEBUG(("Executing rekey protocol with %s:%d [%s]",
		  idata->sconn->remote_host, idata->sconn->remote_port,
		  SILC_CONNTYPE_STRING(idata->conn_type)));

  /* Allocate SKE */
  ske = silc_ske_alloc(server->rng, server->schedule, server->repository,
		       server->public_key, server->private_key, sock);
  if (!ske) {
    silc_packet_free(packet);
    return;
  }

  /* Set SKE callbacks */
  silc_ske_set_callbacks(ske, NULL, silc_server_rekey_resp_completion, sock);

  /* Perform rekey */
  idata->sconn->op = silc_ske_rekey_responder(ske, sock, idata->rekey,
					      packet);
}


/****************************** Disconnection *******************************/

/* Destroys packet stream. */

SILC_TASK_CALLBACK(silc_server_close_connection_final)
{
  silc_packet_stream_destroy(context);
}

/* Closes connection to socket connection */

void silc_server_close_connection(SilcServer server,
				  SilcPacketStream sock)
{
  SilcIDListData idata = silc_packet_get_context(sock);
  char tmp[128];
  const char *hostname;
  SilcUInt16 port;

#if 0
  /* If any protocol is active cancel its execution. It will call
     the final callback which will finalize the disconnection. */
  if (sock->protocol && sock->protocol->protocol &&
      sock->protocol->protocol->type != SILC_PROTOCOL_SERVER_BACKUP) {
    SILC_LOG_DEBUG(("Cancelling protocol, calling final callback"));
    silc_protocol_cancel(sock->protocol, server->schedule);
    sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
    silc_protocol_execute_final(sock->protocol, server->schedule);
    sock->protocol = NULL;
    return;
  }
#endif

  memset(tmp, 0, sizeof(tmp));
  //  silc_socket_get_error(sock, tmp, sizeof(tmp));
  silc_socket_stream_get_info(silc_packet_stream_get_stream(sock),
			      NULL, &hostname, NULL, &port);
  SILC_LOG_INFO(("Closing connection %s:%d [%s] %s", hostname, port,
		 idata ? SILC_CONNTYPE_STRING(idata->conn_type) : "",
		 tmp[0] ? tmp : ""));

  //  silc_socket_set_qos(sock, 0, 0, 0, 0, NULL);

  /* Close connection with timeout */
  server->stat.conn_num--;
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_close_connection_final,
				 sock, 0, 1);
}

/* Sends disconnect message to remote connection and disconnects the
   connection. */

void silc_server_disconnect_remote(SilcServer server,
				   SilcPacketStream sock,
				   SilcStatus status, ...)
{
  unsigned char buf[512];
  va_list ap;
  char *cp;

  if (!sock)
    return;

  SILC_LOG_DEBUG(("Disconnecting remote host"));

  va_start(ap, status);
  cp = va_arg(ap, char *);
  if (cp)
    silc_vsnprintf(buf, sizeof(buf), cp, ap);
  va_end(ap);

  /* Send SILC_PACKET_DISCONNECT */
  silc_packet_send_va(sock, SILC_PACKET_DISCONNECT, 0,
		      SILC_STR_UI_CHAR(status),
		      SILC_STR_UI8_STRING(cp ? buf : NULL),
		      SILC_STR_END);

  /* Close connection */
  silc_server_close_connection(server, sock);
}

SILC_TASK_CALLBACK(silc_server_free_client_data_timeout)
{
  SilcClientEntry client = context;

  assert(!silc_hash_table_count(client->channels));

  silc_idlist_del_data(client);
  //  silc_idcache_purge_by_context(server->local_list->clients, client);
}

/* Frees client data and notifies about client's signoff. */

void silc_server_free_client_data(SilcServer server,
				  SilcPacketStream sock,
				  SilcClientEntry client,
				  int notify,
				  const char *signoff)
{
  SILC_LOG_DEBUG(("Freeing client data"));

  if (client->id) {
    /* Check if anyone is watching this nickname */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_SIGNOFF);

    /* Send SIGNOFF notify to routers. */
    if (notify)
      silc_server_send_notify_signoff(server, SILC_PRIMARY_ROUTE(server),
				      SILC_BROADCAST(server), client->id,
				      signoff);
  }

  /* Remove client from all channels */
  if (notify)
    silc_server_remove_from_channels(server, NULL, client,
				     TRUE, (char *)signoff, TRUE, FALSE);
  else
    silc_server_remove_from_channels(server, NULL, client,
				     FALSE, NULL, FALSE, FALSE);

  /* Remove this client from watcher list if it is */
  silc_server_del_from_watcher_list(server, client);

  /* Remove client's public key from repository, this will free it too. */
  if (client->data.public_key) {
    silc_skr_del_public_key(server->repository, client->data.public_key,
			    client);
    client->data.public_key = NULL;
  }

  /* Update statistics */
  server->stat.my_clients--;
  server->stat.clients--;
  if (server->stat.cell_clients)
    server->stat.cell_clients--;
  SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
  SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);
  silc_schedule_task_del_by_context(server->schedule, client);

  /* We will not delete the client entry right away. We will take it
     into history (for WHOWAS command) for 5 minutes, unless we're
     shutting down server. */
  if (!server->server_shutdown) {
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_free_client_data_timeout,
				   client, 600, 0);
    client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
    client->data.status &= ~SILC_IDLIST_STATUS_LOCAL;
    client->mode = 0;
    client->router = NULL;
    client->connection = NULL;
  } else {
    /* Delete directly since we're shutting down server */
    silc_idlist_del_data(client);
    silc_idlist_del_client(server->local_list, client);
  }
}

/* Frees user_data pointer from socket connection object. This also sends
   appropriate notify packets to the network to inform about leaving
   entities. */

void silc_server_free_sock_user_data(SilcServer server,
				     SilcPacketStream sock,
				     const char *signoff_message)
{
  SilcIDListData idata = silc_packet_get_context(sock);

  if (!idata)
    return;

  switch (idata->conn_type) {
  case SILC_CONN_CLIENT:
    {
      SilcClientEntry client_entry = (SilcClientEntry)idata;
      silc_server_free_client_data(server, sock, client_entry, TRUE,
				   signoff_message);
      silc_packet_set_context(sock, NULL);
      break;
    }

  case SILC_CONN_SERVER:
  case SILC_CONN_ROUTER:
    {
      SilcServerEntry user_data = (SilcServerEntry)idata;
      SilcServerEntry backup_router = NULL;

      SILC_LOG_DEBUG(("Freeing server data"));

      if (user_data->id)
	backup_router = silc_server_backup_get(server, user_data->id);

      if (!server->backup_router && server->server_type == SILC_ROUTER &&
	  backup_router == server->id_entry &&
	  idata->conn_type != SILC_CONN_ROUTER)
	backup_router = NULL;

      if (server->server_shutdown || server->backup_noswitch)
      	backup_router = NULL;

      /* If this was our primary router connection then we're lost to
	 the outside world. */
      if (server->router == user_data) {
	/* Check whether we have a backup router connection */
	if (!backup_router || backup_router == user_data) {
	  if (!server->no_reconnect)
	    silc_server_create_connections(server);
	  server->id_entry->router = NULL;
	  server->router = NULL;
	  server->standalone = TRUE;
	  server->backup_primary = FALSE;
	  backup_router = NULL;
	} else {
	  if (server->id_entry != backup_router) {
	    SILC_LOG_INFO(("New primary router is backup router %s",
			   backup_router->server_name));
	    server->id_entry->router = backup_router;
	    server->router = backup_router;
	    server->router_connect = time(0);
	    server->backup_primary = TRUE;
	    backup_router->data.status &= ~SILC_IDLIST_STATUS_DISABLED;

	    /* Send START_USE to backup router to indicate we have switched */
	    silc_server_backup_send_start_use(server,
					      backup_router->connection,
					      FALSE);
	  } else {
	    SILC_LOG_INFO(("We are now new primary router in this cell"));
	    server->id_entry->router = NULL;
	    server->router = NULL;
	    server->standalone = TRUE;
	  }

	  /* We stop here to take a breath */
	  sleep(2);

#if 0
	  if (server->backup_router) {
	    server->server_type = SILC_ROUTER;

	    /* We'll need to constantly try to reconnect to the primary
	       router so that we'll see when it comes back online. */
	    silc_server_backup_reconnect(server, sock->ip, sock->port,
					 silc_server_backup_connected,
					 NULL);
	  }
#endif /* 0 */

	  /* Mark this connection as replaced */
	  silc_server_backup_replaced_add(server, user_data->id,
					  backup_router);
	}
      } else if (backup_router) {
	SILC_LOG_INFO(("Enabling the use of backup router %s",
		       backup_router->server_name));

	/* Mark this connection as replaced */
	silc_server_backup_replaced_add(server, user_data->id,
					backup_router);
      } else if (server->server_type == SILC_SERVER &&
		 idata->conn_type == SILC_CONN_ROUTER) {
	/* Reconnect to the router (backup) */
	if (!server->no_reconnect)
	  silc_server_create_connections(server);
      }

      if (user_data->server_name)
	SILC_SERVER_SEND_OPERS(server, FALSE, TRUE, SILC_NOTIFY_TYPE_NONE,
			       ("Server %s signoff", user_data->server_name));

      if (!backup_router) {
	/* Remove all servers that are originated from this server, and
	   remove the clients of those servers too. */
	silc_server_remove_servers_by_server(server, user_data, TRUE);

#if 0
	/* Remove the clients that this server owns as they will become
	   invalid now too.  For backup router the server is actually
	   coming from the primary router, so mark that as the owner
	   of this entry. */
	if (server->server_type == SILC_BACKUP_ROUTER &&
	    sock->type == SILC_CONN_SERVER)
	  silc_server_remove_clients_by_server(server, server->router,
					       user_data, TRUE);
	else
#endif
	  silc_server_remove_clients_by_server(server, user_data,
					       user_data, TRUE);

	/* Remove channels owned by this server */
	if (server->server_type == SILC_SERVER)
	  silc_server_remove_channels_by_server(server, user_data);
      } else {
	/* Enable local server connections that may be disabled */
	silc_server_local_servers_toggle_enabled(server, TRUE);

	/* Update the client entries of this server to the new backup
	   router.  If we are the backup router we also resolve the real
	   servers for the clients.  After updating is over this also
	   removes the clients that this server explicitly owns. */
	silc_server_update_clients_by_server(server, user_data,
					     backup_router, TRUE);

	/* If we are router and just lost our primary router (now standlaone)
	   we remove everything that was behind it, since we don't know
	   any better. */
	if (server->server_type == SILC_ROUTER && server->standalone)
	  /* Remove all servers that are originated from this server, and
	     remove the clients of those servers too. */
	  silc_server_remove_servers_by_server(server, user_data, TRUE);

	/* Finally remove the clients that are explicitly owned by this
	   server.  They go down with the server. */
	silc_server_remove_clients_by_server(server, user_data,
					     user_data, TRUE);

	/* Update our server cache to use the new backup router too. */
	silc_server_update_servers_by_server(server, user_data, backup_router);
	if (server->server_type == SILC_SERVER)
	  silc_server_update_channels_by_server(server, user_data,
						backup_router);

	/* Send notify about primary router going down to local operators */
	if (server->backup_router)
	  SILC_SERVER_SEND_OPERS(server, FALSE, TRUE,
				 SILC_NOTIFY_TYPE_NONE,
				 ("%s switched to backup router %s "
				  "(we are primary router now)",
				  server->server_name, server->server_name));
	else if (server->router)
	  SILC_SERVER_SEND_OPERS(server, FALSE, TRUE,
				 SILC_NOTIFY_TYPE_NONE,
				 ("%s switched to backup router %s",
				  server->server_name,
				  server->router->server_name));
      }
      server->backup_noswitch = FALSE;

      /* Free the server entry */
      silc_server_backup_del(server, user_data);
      silc_server_backup_replaced_del(server, user_data);
      silc_idlist_del_data(user_data);
      if (!silc_idlist_del_server(server->local_list, user_data))
	silc_idlist_del_server(server->global_list, user_data);
      if (idata->conn_type == SILC_CONN_SERVER) {
	server->stat.my_servers--;
	server->stat.servers--;
      } else {
	server->stat.my_routers--;
	server->stat.routers--;
      }
      if (server->server_type == SILC_ROUTER)
	server->stat.cell_servers--;

      if (backup_router && backup_router != server->id_entry) {
	/* Announce all of our stuff that was created about 5 minutes ago.
	   The backup router knows all the other stuff already. */
	if (server->server_type == SILC_ROUTER)
	  silc_server_announce_servers(server, FALSE, time(0) - 300,
				       backup_router->connection);

	/* Announce our clients and channels to the router */
	silc_server_announce_clients(server, time(0) - 300,
				     backup_router->connection);
	silc_server_announce_channels(server, time(0) - 300,
				      backup_router->connection);
      }

      silc_packet_set_context(sock, NULL);
      break;
    }

  default:
    {
      SilcUnknownEntry entry = (SilcUnknownEntry)idata;

      SILC_LOG_DEBUG(("Freeing unknown connection data"));

      silc_idlist_del_data(idata);
      silc_free(entry);
      silc_packet_set_context(sock, NULL);
      break;
    }
  }
}

/* Removes client from all channels it has joined. This is used when client
   connection is disconnected. If the client on a channel is last, the
   channel is removed as well. This sends the SIGNOFF notify types. */

void silc_server_remove_from_channels(SilcServer server,
				      SilcPacketStream sock,
				      SilcClientEntry client,
				      SilcBool notify,
				      const char *signoff_message,
				      SilcBool keygen,
				      SilcBool killed)
{
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer clidp = NULL;

  if (!client)
    return;

  if (notify && !client->id)
    notify = FALSE;

  SILC_LOG_DEBUG(("Removing client %s from joined channels",
		  notify ? silc_id_render(client->id, SILC_ID_CLIENT) : ""));

  if (notify) {
    clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    if (!clidp)
      notify = FALSE;
  }

  /* Remove the client from all channels. The client is removed from
     the channels' user list. */
  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    /* Remove channel if this is last client leaving the channel, unless
       the channel is permanent. */
    if (server->server_type != SILC_SERVER &&
	silc_hash_table_count(channel->user_list) < 2) {
      silc_server_channel_delete(server, channel);
      continue;
    }

    silc_hash_table_del(client->channels, channel);
    silc_hash_table_del(channel->user_list, client);
    channel->user_count--;

    /* If there is no global users on the channel anymore mark the channel
       as local channel. Do not check if the removed client is local client. */
    if (server->server_type == SILC_SERVER && channel->global_users &&
	chl->client->router && !silc_server_channel_has_global(channel))
      channel->global_users = FALSE;

    memset(chl, 'A', sizeof(*chl));
    silc_free(chl);

    /* Update statistics */
    if (SILC_IS_LOCAL(client))
      server->stat.my_chanclients--;
    if (server->server_type == SILC_ROUTER) {
      server->stat.cell_chanclients--;
      server->stat.chanclients--;
    }

    /* If there is not at least one local user on the channel then we don't
       need the channel entry anymore, we can remove it safely, unless the
       channel is permanent channel */
    if (server->server_type == SILC_SERVER &&
	!silc_server_channel_has_local(channel)) {
      /* Notify about leaving client if this channel has global users. */
      if (notify && channel->global_users)
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
					   SILC_NOTIFY_TYPE_SIGNOFF,
					   signoff_message ? 2 : 1,
					   clidp->data, silc_buffer_len(clidp),
					   signoff_message, signoff_message ?
					   strlen(signoff_message) : 0);

      silc_schedule_task_del_by_context(server->schedule, channel->rekey);
      silc_server_channel_delete(server, channel);
      continue;
    }

    /* Send notify to channel about client leaving SILC and channel too */
    if (notify)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
					 SILC_NOTIFY_TYPE_SIGNOFF,
					 signoff_message ? 2 : 1,
					 clidp->data, silc_buffer_len(clidp),
					 signoff_message, signoff_message ?
					 strlen(signoff_message) : 0);

    if (killed && clidp) {
      /* Remove the client from channel's invite list */
      if (channel->invite_list &&
	  silc_hash_table_count(channel->invite_list)) {
	SilcBuffer ab;
	SilcArgumentPayload iargs;
	ab = silc_argument_payload_encode_one(NULL, clidp->data,
					      silc_buffer_len(clidp), 3);
	iargs = silc_argument_payload_parse(ab->data, silc_buffer_len(ab), 1);
	silc_server_inviteban_process(server, channel->invite_list, 1, iargs);
	silc_buffer_free(ab);
	silc_argument_payload_free(iargs);
      }
    }

    /* Don't create keys if we are shutting down */
    if (server->server_shutdown)
      continue;

    /* Re-generate channel key if needed */
    if (keygen && !(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
      if (!silc_server_create_channel_key(server, channel, 0))
	continue;

      /* Send the channel key to the channel. The key of course is not sent
	 to the client who was removed from the channel. */
      silc_server_send_channel_key(server, client->connection, channel,
				   server->server_type == SILC_ROUTER ?
				   FALSE : !server->standalone);
    }
  }

  silc_hash_table_list_reset(&htl);
  if (clidp)
    silc_buffer_free(clidp);
}

/* Removes client from one channel. This is used for example when client
   calls LEAVE command to remove itself from the channel. Returns TRUE
   if channel still exists and FALSE if the channel is removed when
   last client leaves the channel. If `notify' is FALSE notify messages
   are not sent. */

SilcBool silc_server_remove_from_one_channel(SilcServer server,
					 SilcPacketStream sock,
					 SilcChannelEntry channel,
					 SilcClientEntry client,
					 SilcBool notify)
{
  SilcChannelClientEntry chl;
  SilcBuffer clidp;

  SILC_LOG_DEBUG(("Removing %s from channel %s",
		  silc_id_render(client->id, SILC_ID_CLIENT),
		  channel->channel_name));

  /* Get the entry to the channel, if this client is not on the channel
     then return Ok. */
  if (!silc_hash_table_find(client->channels, channel, NULL, (void *)&chl))
    return TRUE;

  /* Remove channel if this is last client leaving the channel, unless
     the channel is permanent. */
  if (server->server_type != SILC_SERVER &&
      silc_hash_table_count(channel->user_list) < 2) {
    silc_server_channel_delete(server, channel);
    return FALSE;
  }

  silc_hash_table_del(client->channels, channel);
  silc_hash_table_del(channel->user_list, client);
  channel->user_count--;

  /* If there is no global users on the channel anymore mark the channel
     as local channel. Do not check if the client is local client. */
  if (server->server_type == SILC_SERVER && channel->global_users &&
      chl->client->router && !silc_server_channel_has_global(channel))
    channel->global_users = FALSE;

  memset(chl, 'O', sizeof(*chl));
  silc_free(chl);

  /* Update statistics */
  if (SILC_IS_LOCAL(client))
    server->stat.my_chanclients--;
  if (server->server_type == SILC_ROUTER) {
    server->stat.cell_chanclients--;
    server->stat.chanclients--;
  }

  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  if (!clidp)
    notify = FALSE;

  /* If there is not at least one local user on the channel then we don't
     need the channel entry anymore, we can remove it safely, unless the
     channel is permanent channel */
  if (server->server_type == SILC_SERVER &&
      !silc_server_channel_has_local(channel)) {
    /* Notify about leaving client if this channel has global users. */
    if (notify && channel->global_users)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
					 SILC_NOTIFY_TYPE_LEAVE, 1,
					 clidp->data, silc_buffer_len(clidp));

    silc_schedule_task_del_by_context(server->schedule, channel->rekey);
    silc_server_channel_delete(server, channel);
    silc_buffer_free(clidp);
    return FALSE;
  }

  /* Send notify to channel about client leaving the channel */
  if (notify)
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
				       SILC_NOTIFY_TYPE_LEAVE, 1,
				       clidp->data, silc_buffer_len(clidp));

  silc_buffer_free(clidp);
  return TRUE;
}

/* Creates new channel. Sends NEW_CHANNEL packet to primary route. This
   function may be used only by router. In real SILC network all channels
   are created by routers thus this function is never used by normal
   server. */

SilcChannelEntry silc_server_create_new_channel(SilcServer server,
						SilcServerID *router_id,
						char *cipher,
						char *hmac,
						char *channel_name,
						int broadcast)
{
  SilcChannelID *channel_id;
  SilcChannelEntry entry;
  SilcCipher send_key, receive_key;
  SilcHmac newhmac;

  SILC_LOG_DEBUG(("Creating new channel %s", channel_name));

  if (!cipher)
    cipher = SILC_DEFAULT_CIPHER;
  if (!hmac)
    hmac = SILC_DEFAULT_HMAC;

  /* Allocate cipher */
  if (!silc_cipher_alloc(cipher, &send_key))
    return NULL;
  if (!silc_cipher_alloc(cipher, &receive_key)) {
    silc_cipher_free(send_key);
    return NULL;
  }

  /* Allocate hmac */
  if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
    silc_cipher_free(send_key);
    silc_cipher_free(receive_key);
    return NULL;
  }

  channel_name = strdup(channel_name);

  /* Create the channel ID */
  if (!silc_id_create_channel_id(server, router_id, server->rng,
				 &channel_id)) {
    silc_free(channel_name);
    silc_cipher_free(send_key);
    silc_cipher_free(receive_key);
    silc_hmac_free(newhmac);
    return NULL;
  }

  /* Create the channel */
  entry = silc_idlist_add_channel(server->local_list, channel_name,
				  SILC_CHANNEL_MODE_NONE, channel_id,
				  NULL, send_key, receive_key, newhmac);
  if (!entry) {
    silc_free(channel_name);
    silc_cipher_free(send_key);
    silc_cipher_free(receive_key);
    silc_hmac_free(newhmac);
    silc_free(channel_id);
    return NULL;
  }

  entry->cipher = strdup(cipher);
  entry->hmac_name = strdup(hmac);

  /* Now create the actual key material */
  if (!silc_server_create_channel_key(server, entry,
				      silc_cipher_get_key_len(send_key) / 8)) {
    silc_idlist_del_channel(server->local_list, entry);
    return NULL;
  }

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (broadcast)
    silc_server_send_new_channel(server, SILC_PRIMARY_ROUTE(server), TRUE,
				 channel_name, entry->id,
				 silc_id_get_len(entry->id, SILC_ID_CHANNEL),
				 entry->mode);

  /* Distribute to backup routers */
  if (broadcast && server->server_type == SILC_ROUTER) {
    SilcBuffer packet;
    unsigned char cid[32];
    SilcUInt32 name_len = strlen(channel_name);
    SilcUInt32 id_len;

    silc_id_id2str(entry->id, SILC_ID_CHANNEL, cid, sizeof(cid), &id_len);
    packet = silc_channel_payload_encode(channel_name, name_len,
					 cid, id_len, entry->mode);
    silc_server_backup_send(server, NULL, SILC_PACKET_NEW_CHANNEL, 0,
			    packet->data, silc_buffer_len(packet), FALSE,
			    TRUE);
    silc_buffer_free(packet);
  }

  server->stat.my_channels++;
  if (server->server_type == SILC_ROUTER) {
    server->stat.channels++;
    server->stat.cell_channels++;
    entry->users_resolved = TRUE;
  }

  return entry;
}

/* Same as above but creates the channel with Channel ID `channel_id. */

SilcChannelEntry
silc_server_create_new_channel_with_id(SilcServer server,
				       char *cipher,
				       char *hmac,
				       char *channel_name,
				       SilcChannelID *channel_id,
				       int broadcast)
{
  SilcChannelEntry entry;
  SilcCipher send_key, receive_key;
  SilcHmac newhmac;

  SILC_LOG_DEBUG(("Creating new channel %s", channel_name));

  if (!cipher)
    cipher = SILC_DEFAULT_CIPHER;
  if (!hmac)
    hmac = SILC_DEFAULT_HMAC;

  /* Allocate cipher */
  if (!silc_cipher_alloc(cipher, &send_key))
    return NULL;
  if (!silc_cipher_alloc(cipher, &receive_key)) {
    silc_cipher_free(send_key);
    return NULL;
  }

  /* Allocate hmac */
  if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
    silc_cipher_free(send_key);
    silc_cipher_free(receive_key);
    return NULL;
  }

  channel_name = strdup(channel_name);

  /* Create the channel */
  entry = silc_idlist_add_channel(server->local_list, channel_name,
				  SILC_CHANNEL_MODE_NONE, channel_id,
				  NULL, send_key, receive_key, newhmac);
  if (!entry) {
    silc_cipher_free(send_key);
    silc_cipher_free(receive_key);
    silc_hmac_free(newhmac);
    silc_free(channel_name);
    return NULL;
  }

  /* Now create the actual key material */
  if (!silc_server_create_channel_key(server, entry,
				      silc_cipher_get_key_len(send_key) / 8)) {
    silc_idlist_del_channel(server->local_list, entry);
    return NULL;
  }

  /* Notify other routers about the new channel. We send the packet
     to our primary route. */
  if (broadcast)
    silc_server_send_new_channel(server, SILC_PRIMARY_ROUTE(server), TRUE,
				 channel_name, entry->id,
				 silc_id_get_len(entry->id, SILC_ID_CHANNEL),
				 entry->mode);

  /* Distribute to backup routers */
  if (broadcast && server->server_type == SILC_ROUTER) {
    SilcBuffer packet;
    unsigned char cid[32];
    SilcUInt32 name_len = strlen(channel_name);
    SilcUInt32 id_len;

    silc_id_id2str(entry->id, SILC_ID_CHANNEL, cid, sizeof(cid), &id_len);
    packet = silc_channel_payload_encode(channel_name, name_len,
					 cid, id_len, entry->mode);
    silc_server_backup_send(server, NULL, SILC_PACKET_NEW_CHANNEL, 0,
			    packet->data, silc_buffer_len(packet), FALSE,
			    TRUE);
    silc_buffer_free(packet);
  }

  server->stat.my_channels++;
  if (server->server_type == SILC_ROUTER) {
    server->stat.channels++;
    server->stat.cell_channels++;
    entry->users_resolved = TRUE;
  }

  return entry;
}

/* Channel's key re-key timeout callback. */

SILC_TASK_CALLBACK(silc_server_channel_key_rekey)
{
  SilcServer server = app_context;
  SilcServerChannelRekey rekey = (SilcServerChannelRekey)context;

  rekey->task = NULL;

  /* Return now if we are shutting down */
  if (server->server_shutdown)
    return;

  if (!silc_server_create_channel_key(server, rekey->channel, rekey->key_len))
    return;

  silc_server_send_channel_key(server, NULL, rekey->channel, FALSE);
}

/* Generates new channel key. This is used to create the initial channel key
   but also to re-generate new key for channel. If `key_len' is provided
   it is the bytes of the key length. */

SilcBool silc_server_create_channel_key(SilcServer server,
					SilcChannelEntry channel,
					SilcUInt32 key_len)
{
  int i;
  unsigned char channel_key[32], hash[SILC_HASH_MAXLEN];
  SilcUInt32 len;

  if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
    SILC_LOG_DEBUG(("Channel has private keys, will not generate new key"));
    return TRUE;
  }

  SILC_LOG_DEBUG(("Generating channel %s key", channel->channel_name));

  if (!channel->send_key)
    if (!silc_cipher_alloc(SILC_DEFAULT_CIPHER, &channel->send_key)) {
      channel->send_key = NULL;
      return FALSE;
    }
  if (!channel->receive_key)
    if (!silc_cipher_alloc(SILC_DEFAULT_CIPHER, &channel->receive_key)) {
      silc_cipher_free(channel->send_key);
      channel->send_key = channel->receive_key = NULL;
      return FALSE;
    }

  if (key_len)
    len = key_len;
  else if (channel->key_len)
    len = channel->key_len / 8;
  else
    len = silc_cipher_get_key_len(channel->send_key) / 8;

  /* Create channel key */
  for (i = 0; i < len; i++) channel_key[i] = silc_rng_get_byte(server->rng);

  /* Set the key */
  silc_cipher_set_key(channel->send_key, channel_key, len * 8, TRUE);
  silc_cipher_set_key(channel->receive_key, channel_key, len * 8, FALSE);

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
  }

  /* Save the key */
  channel->key_len = len * 8;
  channel->key = silc_memdup(channel_key, len);
  memset(channel_key, 0, sizeof(channel_key));

  /* Generate HMAC key from the channel key data and set it */
  if (!channel->hmac)
    if (!silc_hmac_alloc(SILC_DEFAULT_HMAC, NULL, &channel->hmac)) {
      memset(channel->key, 0, channel->key_len / 8);
      silc_free(channel->key);
      silc_cipher_free(channel->send_key);
      silc_cipher_free(channel->receive_key);
      channel->send_key = channel->receive_key = NULL;
      return FALSE;
    }
  silc_hash_make(silc_hmac_get_hash(channel->hmac), channel->key, len, hash);
  silc_hmac_set_key(channel->hmac, hash,
		    silc_hash_len(silc_hmac_get_hash(channel->hmac)));
  memset(hash, 0, sizeof(hash));

  if (server->server_type == SILC_ROUTER) {
    if (!channel->rekey)
      channel->rekey = silc_calloc(1, sizeof(*channel->rekey));
    channel->rekey->channel = channel;
    channel->rekey->key_len = key_len;
    if (channel->rekey->task)
      silc_schedule_task_del(server->schedule, channel->rekey->task);

    channel->rekey->task =
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_channel_key_rekey,
				     (void *)channel->rekey,
				     server->config->channel_rekey_secs, 0);
  }

  return TRUE;
}

/* Saves the channel key found in the encoded `key_payload' buffer. This
   function is used when we receive Channel Key Payload and also when we're
   processing JOIN command reply. Returns entry to the channel. */

SilcChannelEntry silc_server_save_channel_key(SilcServer server,
					      SilcBuffer key_payload,
					      SilcChannelEntry channel)
{
  SilcChannelKeyPayload payload = NULL;
  SilcChannelID id;
  unsigned char *tmp, hash[SILC_HASH_MAXLEN];
  SilcUInt32 tmp_len;
  char *cipher;

  /* Decode channel key payload */
  payload = silc_channel_key_payload_parse(key_payload->data,
					   silc_buffer_len(key_payload));
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload received, dropped"));
    channel = NULL;
    goto out;
  }

  /* Get the channel entry */
  if (!channel) {

    /* Get channel ID */
    tmp = silc_channel_key_get_id(payload, &tmp_len);
    if (!silc_id_str2id(tmp, tmp_len, SILC_ID_CHANNEL, &id, sizeof(id))) {
      channel = NULL;
      goto out;
    }

    channel = silc_idlist_find_channel_by_id(server->local_list, &id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->global_list, &id, NULL);
      if (!channel) {
	if (server->server_type == SILC_ROUTER)
	  SILC_LOG_ERROR(("Received key for non-existent channel %s",
			  silc_id_render(&id, SILC_ID_CHANNEL)));
	goto out;
      }
    }
  }

  SILC_LOG_DEBUG(("Saving new channel %s key", channel->channel_name));

  tmp = silc_channel_key_get_key(payload, &tmp_len);
  if (!tmp) {
    channel = NULL;
    goto out;
  }

  cipher = silc_channel_key_get_cipher(payload, NULL);
  if (!cipher) {
    channel = NULL;
    goto out;
  }

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len / 8);
    silc_free(channel->key);
    silc_cipher_free(channel->send_key);
    silc_cipher_free(channel->receive_key);
  }

  /* Create new cipher */
  if (!silc_cipher_alloc(cipher, &channel->send_key)) {
    channel->send_key = NULL;
    channel = NULL;
    goto out;
  }
  if (!silc_cipher_alloc(cipher, &channel->receive_key)) {
    silc_cipher_free(channel->send_key);
    channel->send_key = channel->receive_key = NULL;
    channel = NULL;
    goto out;
  }

  if (channel->cipher)
    silc_free(channel->cipher);
  channel->cipher = strdup(cipher);

  /* Save the key */
  channel->key_len = tmp_len * 8;
  channel->key = silc_memdup(tmp, tmp_len);
  silc_cipher_set_key(channel->send_key, tmp, channel->key_len, TRUE);
  silc_cipher_set_key(channel->receive_key, tmp, channel->key_len, FALSE);

  /* Generate HMAC key from the channel key data and set it */
  if (!channel->hmac)
    if (!silc_hmac_alloc(SILC_DEFAULT_HMAC, NULL, &channel->hmac)) {
      memset(channel->key, 0, channel->key_len / 8);
      silc_free(channel->key);
      silc_cipher_free(channel->send_key);
      silc_cipher_free(channel->receive_key);
      channel->send_key = channel->receive_key = NULL;
      return FALSE;
    }
  silc_hash_make(silc_hmac_get_hash(channel->hmac), tmp, tmp_len, hash);
  silc_hmac_set_key(channel->hmac, hash,
		    silc_hash_len(silc_hmac_get_hash(channel->hmac)));

  memset(hash, 0, sizeof(hash));
  memset(tmp, 0, tmp_len);

  if (server->server_type == SILC_ROUTER) {
    if (!channel->rekey)
      channel->rekey = silc_calloc(1, sizeof(*channel->rekey));
    channel->rekey->channel = channel;
    if (channel->rekey->task)
      silc_schedule_task_del(server->schedule, channel->rekey->task);

    channel->rekey->task =
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_channel_key_rekey,
				     (void *)channel->rekey,
				     server->config->channel_rekey_secs, 0);
  }

 out:
  if (payload)
    silc_channel_key_payload_free(payload);

  return channel;
}

/* Returns assembled of all servers in the given ID list. The packet's
   form is dictated by the New ID payload. */

static void silc_server_announce_get_servers(SilcServer server,
					     SilcServerEntry remote,
					     SilcIDList id_list,
					     SilcBuffer *servers,
					     unsigned long creation_time)
{
  SilcList list;
  SilcIDCacheEntry id_cache;
  SilcServerEntry entry;
  SilcBuffer idp;

  /* Go through all clients in the list */
  if (silc_idcache_get_all(id_list->servers, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      entry = (SilcServerEntry)id_cache->context;

      /* Do not announce the one we've sending our announcements and
	 do not announce ourself. Also check the creation time if it's
	 provided. */
      if ((entry == remote) || (entry == server->id_entry) ||
	  (creation_time && entry->data.created < creation_time))
	continue;

      idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);

      *servers = silc_buffer_realloc(*servers,
				     (*servers ?
				      silc_buffer_truelen((*servers)) +
				      silc_buffer_len(idp) :
				      silc_buffer_len(idp)));
      silc_buffer_pull_tail(*servers, ((*servers)->end - (*servers)->data));
      silc_buffer_put(*servers, idp->data, silc_buffer_len(idp));
      silc_buffer_pull(*servers, silc_buffer_len(idp));
      silc_buffer_free(idp);
    }
  }
}

static SilcBuffer
silc_server_announce_encode_notify(SilcNotifyType notify, SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer p;

  va_start(ap, argc);
  p = silc_notify_payload_encode(notify, argc, ap);
  va_end(ap);

  return p;
}

/* This function is used by router to announce existing servers to our
   primary router when we've connected to it. If `creation_time' is non-zero
   then only the servers that has been created after the `creation_time'
   will be announced. */

void silc_server_announce_servers(SilcServer server, SilcBool global,
				  unsigned long creation_time,
				  SilcPacketStream remote)
{
  SilcBuffer servers = NULL;

  SILC_LOG_DEBUG(("Announcing servers"));

  /* Get servers in local list */
  silc_server_announce_get_servers(server, silc_packet_get_context(remote),
				   server->local_list, &servers,
				   creation_time);

  if (global)
    /* Get servers in global list */
    silc_server_announce_get_servers(server, silc_packet_get_context(remote),
				     server->global_list, &servers,
				     creation_time);

  if (servers) {
    silc_buffer_push(servers, servers->data - servers->head);
    SILC_LOG_HEXDUMP(("servers"), servers->data, silc_buffer_len(servers));

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NEW_ID, SILC_PACKET_FLAG_LIST,
			    servers->data, silc_buffer_len(servers));

    silc_buffer_free(servers);
  }
}

/* Returns assembled packet of all clients in the given ID list. The
   packet's form is dictated by the New ID Payload. */

static void silc_server_announce_get_clients(SilcServer server,
					     SilcIDList id_list,
					     SilcBuffer *clients,
					     SilcBuffer *umodes,
					     unsigned long creation_time)
{
  SilcList list;
  SilcIDCacheEntry id_cache;
  SilcClientEntry client;
  SilcBuffer idp;
  SilcBuffer tmp;
  unsigned char mode[4];

  /* Go through all clients in the list */
  if (silc_idcache_get_all(id_list->clients, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      client = (SilcClientEntry)id_cache->context;

      if (creation_time && client->data.created < creation_time)
	continue;
      if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED))
	continue;
      if (!client->connection && !client->router)
	continue;

      idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

      *clients = silc_buffer_realloc(*clients,
				     (*clients ?
				      silc_buffer_truelen((*clients)) +
				      silc_buffer_len(idp) :
				      silc_buffer_len(idp)));
      silc_buffer_pull_tail(*clients, ((*clients)->end - (*clients)->data));
      silc_buffer_put(*clients, idp->data, silc_buffer_len(idp));
      silc_buffer_pull(*clients, silc_buffer_len(idp));

      SILC_PUT32_MSB(client->mode, mode);
      tmp =
	silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_UMODE_CHANGE,
					   2, idp->data, silc_buffer_len(idp),
					   mode, 4);
      *umodes = silc_buffer_realloc(*umodes,
				    (*umodes ?
				     silc_buffer_truelen((*umodes)) +
				     silc_buffer_len(tmp) :
				     silc_buffer_len(tmp)));
      silc_buffer_pull_tail(*umodes, ((*umodes)->end - (*umodes)->data));
      silc_buffer_put(*umodes, tmp->data, silc_buffer_len(tmp));
      silc_buffer_pull(*umodes, silc_buffer_len(tmp));
      silc_buffer_free(tmp);

      silc_buffer_free(idp);
    }
  }
}

/* This function is used to announce our existing clients to our router
   when we've connected to it. If `creation_time' is non-zero then only
   the clients that has been created after the `creation_time' will be
   announced. */

void silc_server_announce_clients(SilcServer server,
				  unsigned long creation_time,
				  SilcPacketStream remote)
{
  SilcBuffer clients = NULL;
  SilcBuffer umodes = NULL;

  SILC_LOG_DEBUG(("Announcing clients"));

  /* Get clients in local list */
  silc_server_announce_get_clients(server, server->local_list,
				   &clients, &umodes, creation_time);

  /* As router we announce our global list as well */
  if (server->server_type == SILC_ROUTER)
    silc_server_announce_get_clients(server, server->global_list,
				     &clients, &umodes, creation_time);

  if (clients) {
    silc_buffer_push(clients, clients->data - clients->head);
    SILC_LOG_HEXDUMP(("clients"), clients->data, silc_buffer_len(clients));

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NEW_ID, SILC_PACKET_FLAG_LIST,
			    clients->data, silc_buffer_len(clients));

    silc_buffer_free(clients);
  }

  if (umodes) {
    silc_buffer_push(umodes, umodes->data - umodes->head);
    SILC_LOG_HEXDUMP(("umodes"), umodes->data, silc_buffer_len(umodes));

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
			    umodes->data, silc_buffer_len(umodes));

    silc_buffer_free(umodes);
  }
}

/* Returns channel's topic for announcing it */

void silc_server_announce_get_channel_topic(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *topic)
{
  SilcBuffer chidp;

  if (channel->topic) {
    chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
    *topic = silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_TOPIC_SET, 2,
						chidp->data,
						silc_buffer_len(chidp),
						channel->topic,
						strlen(channel->topic));
    silc_buffer_free(chidp);
  }
}

/* Returns channel's invite and ban lists */

void silc_server_announce_get_inviteban(SilcServer server,
					SilcChannelEntry channel,
					SilcBuffer *invite,
					SilcBuffer *ban)
{
  SilcBuffer list, idp, idp2, tmp2;
  SilcUInt32 type;
  SilcHashTableList htl;
  const unsigned char a[1] = { 0x03 };

  idp = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);

  /* Encode invite list */
  if (channel->invite_list && silc_hash_table_count(channel->invite_list)) {
    list = silc_buffer_alloc_size(2);
    type = silc_hash_table_count(channel->invite_list);
    SILC_PUT16_MSB(type, list->data);
    silc_hash_table_list(channel->invite_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&type, (void *)&tmp2))
      list = silc_argument_payload_encode_one(list, tmp2->data, silc_buffer_len(tmp2),
                                              type);
    silc_hash_table_list_reset(&htl);

    idp2 = silc_id_payload_encode(server->id, SILC_ID_SERVER);
    *invite =
      silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_INVITE, 5,
					 idp->data, silc_buffer_len(idp),
					 channel->channel_name,
					 strlen(channel->channel_name),
					 idp2->data, silc_buffer_len(idp2),
					 a, 1,
				         list->data, silc_buffer_len(list));
    silc_buffer_free(idp2);
    silc_buffer_free(list);
  }

  /* Encode ban list */
  if (channel->ban_list && silc_hash_table_count(channel->ban_list)) {
    list = silc_buffer_alloc_size(2);
    type = silc_hash_table_count(channel->ban_list);
    SILC_PUT16_MSB(type, list->data);
    silc_hash_table_list(channel->ban_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&type, (void *)&tmp2))
      list = silc_argument_payload_encode_one(list, tmp2->data, silc_buffer_len(tmp2),
                                              type);
    silc_hash_table_list_reset(&htl);

    *ban =
      silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_BAN, 3,
					 idp->data, silc_buffer_len(idp),
					 a, 1,
				         list->data, silc_buffer_len(list));
    silc_buffer_free(list);
  }

  silc_buffer_free(idp);
}

/* Returns assembled packets for channel users of the `channel'. */

void silc_server_announce_get_channel_users(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *channel_modes,
					    SilcBuffer *channel_users,
					    SilcBuffer *channel_users_modes)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer chidp, clidp, csidp;
  SilcBuffer tmp, fkey = NULL, chpklist;
  int len;
  unsigned char mode[4], ulimit[4];
  char *hmac;

  SILC_LOG_DEBUG(("Start"));

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  csidp = silc_id_payload_encode(server->id, SILC_ID_SERVER);
  chpklist = silc_server_get_channel_pk_list(server, channel, TRUE, FALSE);

  /* CMODE notify */
  SILC_PUT32_MSB(channel->mode, mode);
  if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
    SILC_PUT32_MSB(channel->user_limit, ulimit);
  hmac = channel->hmac ? (char *)silc_hmac_get_name(channel->hmac) : NULL;
  if (channel->founder_key)
    fkey = silc_public_key_payload_encode(channel->founder_key);
  tmp =
    silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_CMODE_CHANGE,
				       8, csidp->data,
				       silc_buffer_len(csidp),
				       mode, sizeof(mode),
				       NULL, 0,
				       hmac, hmac ? strlen(hmac) : 0,
				       channel->passphrase,
				       channel->passphrase ?
				       strlen(channel->passphrase) : 0,
				       fkey ? fkey->data : NULL,
				       fkey ? silc_buffer_len(fkey) : 0,
				       chpklist ? chpklist->data : NULL,
				       chpklist ?
				       silc_buffer_len(chpklist) : 0,
				       (channel->mode &
					SILC_CHANNEL_MODE_ULIMIT ?
					ulimit : NULL),
				       (channel->mode &
					SILC_CHANNEL_MODE_ULIMIT ?
					sizeof(ulimit) : 0));
  len = silc_buffer_len(tmp);
  *channel_modes =
    silc_buffer_realloc(*channel_modes,
			(*channel_modes ?
			 silc_buffer_truelen((*channel_modes)) + len : len));
  silc_buffer_pull_tail(*channel_modes,
			((*channel_modes)->end -
			 (*channel_modes)->data));
  silc_buffer_put(*channel_modes, tmp->data, silc_buffer_len(tmp));
  silc_buffer_pull(*channel_modes, len);
  silc_buffer_free(tmp);
  silc_buffer_free(fkey);
  fkey = NULL;

  /* Now find all users on the channel */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    clidp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);

    /* JOIN Notify */
    tmp = silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_JOIN, 2,
					     clidp->data,
					     silc_buffer_len(clidp),
					     chidp->data,
					     silc_buffer_len(chidp));
    len = silc_buffer_len(tmp);
    *channel_users =
      silc_buffer_realloc(*channel_users,
			  (*channel_users ?
			   silc_buffer_truelen((*channel_users)) + len : len));
    silc_buffer_pull_tail(*channel_users,
			  ((*channel_users)->end -
			   (*channel_users)->data));

    silc_buffer_put(*channel_users, tmp->data, silc_buffer_len(tmp));
    silc_buffer_pull(*channel_users, len);
    silc_buffer_free(tmp);

    /* CUMODE notify for mode change on the channel */
    SILC_PUT32_MSB(chl->mode, mode);
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO && channel->founder_key)
      fkey = silc_public_key_payload_encode(channel->founder_key);
    tmp = silc_server_announce_encode_notify(SILC_NOTIFY_TYPE_CUMODE_CHANGE,
					     4, csidp->data,
					     silc_buffer_len(csidp),
					     mode, sizeof(mode),
					     clidp->data,
					     silc_buffer_len(clidp),
					     fkey ? fkey->data : NULL,
					     fkey ? silc_buffer_len(fkey) : 0);
    len = silc_buffer_len(tmp);
    *channel_users_modes =
      silc_buffer_realloc(*channel_users_modes,
			  (*channel_users_modes ?
			   silc_buffer_truelen((*channel_users_modes)) +
			   len : len));
    silc_buffer_pull_tail(*channel_users_modes,
			  ((*channel_users_modes)->end -
			   (*channel_users_modes)->data));

    silc_buffer_put(*channel_users_modes, tmp->data, silc_buffer_len(tmp));
    silc_buffer_pull(*channel_users_modes, len);
    silc_buffer_free(tmp);
    silc_buffer_free(fkey);
    fkey = NULL;
    silc_buffer_free(clidp);
  }
  silc_hash_table_list_reset(&htl);
  silc_buffer_free(chidp);
  silc_buffer_free(csidp);
}

/* Returns assembled packets for all channels and users on those channels
   from the given ID List. The packets are in the form dictated by the
   New Channel and New Channel User payloads. */

void silc_server_announce_get_channels(SilcServer server,
				       SilcIDList id_list,
				       SilcBuffer *channels,
				       SilcBuffer **channel_modes,
				       SilcBuffer *channel_users,
				       SilcBuffer **channel_users_modes,
				       SilcUInt32 *channel_users_modes_c,
				       SilcBuffer **channel_topics,
				       SilcBuffer **channel_invites,
				       SilcBuffer **channel_bans,
				       SilcChannelID ***channel_ids,
				       unsigned long creation_time)
{
  SilcList list;
  SilcIDCacheEntry id_cache;
  SilcChannelEntry channel;
  unsigned char cid[32];
  SilcUInt32 id_len;
  SilcUInt16 name_len;
  int len;
  int i = *channel_users_modes_c;
  SilcBool announce;

  SILC_LOG_DEBUG(("Start"));

  /* Go through all channels in the list */
  if (silc_idcache_get_all(id_list->channels, &list)) {
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      channel = (SilcChannelEntry)id_cache->context;

      if (creation_time && channel->created < creation_time)
	announce = FALSE;
      else
	announce = TRUE;

      silc_id_id2str(channel->id, SILC_ID_CHANNEL, cid, sizeof(cid), &id_len);
      name_len = strlen(channel->channel_name);

      if (announce) {
	len = 4 + name_len + id_len + 4;
	*channels =
	  silc_buffer_realloc(*channels,
			      (*channels ?
			       silc_buffer_truelen((*channels)) +
			       len : len));
	silc_buffer_pull_tail(*channels,
			      ((*channels)->end - (*channels)->data));
	silc_buffer_format(*channels,
			   SILC_STR_UI_SHORT(name_len),
			   SILC_STR_UI_XNSTRING(channel->channel_name,
						name_len),
			   SILC_STR_UI_SHORT(id_len),
			     SILC_STR_UI_XNSTRING(cid, id_len),
			   SILC_STR_UI_INT(channel->mode),
			   SILC_STR_END);
	silc_buffer_pull(*channels, len);
      }

      if (creation_time && channel->updated < creation_time)
	announce = FALSE;
      else
	announce = TRUE;

      if (announce) {
	/* Channel user modes */
	*channel_users_modes = silc_realloc(*channel_users_modes,
					    sizeof(**channel_users_modes) *
					    (i + 1));
	(*channel_users_modes)[i] = NULL;
	*channel_modes = silc_realloc(*channel_modes,
				      sizeof(**channel_modes) * (i + 1));
	(*channel_modes)[i] = NULL;
	*channel_ids = silc_realloc(*channel_ids,
				      sizeof(**channel_ids) * (i + 1));
	(*channel_ids)[i] = NULL;
	silc_server_announce_get_channel_users(server, channel,
					       &(*channel_modes)[i],
					       channel_users,
					       &(*channel_users_modes)[i]);
	(*channel_ids)[i] = channel->id;

	/* Channel's topic */
	*channel_topics = silc_realloc(*channel_topics,
				       sizeof(**channel_topics) * (i + 1));
	(*channel_topics)[i] = NULL;
	silc_server_announce_get_channel_topic(server, channel,
					       &(*channel_topics)[i]);

	/* Channel's invite and ban list */
	*channel_invites = silc_realloc(*channel_invites,
					sizeof(**channel_invites) * (i + 1));
	(*channel_invites)[i] = NULL;
	*channel_bans = silc_realloc(*channel_bans,
				     sizeof(**channel_bans) * (i + 1));
	(*channel_bans)[i] = NULL;
	silc_server_announce_get_inviteban(server, channel,
					   &(*channel_invites)[i],
					   &(*channel_bans)[i]);

	(*channel_users_modes_c)++;

	i++;
      }
    }
  }
}

/* This function is used to announce our existing channels to our router
   when we've connected to it. This also announces the users on the
   channels to the router. If the `creation_time' is non-zero only the
   channels that was created after the `creation_time' are announced.
   Note that the channel users are still announced even if the `creation_time'
   was provided. */

void silc_server_announce_channels(SilcServer server,
				   unsigned long creation_time,
				   SilcPacketStream remote)
{
  SilcBuffer channels = NULL, *channel_modes = NULL, channel_users = NULL;
  SilcBuffer *channel_users_modes = NULL;
  SilcBuffer *channel_topics = NULL;
  SilcBuffer *channel_invites = NULL;
  SilcBuffer *channel_bans = NULL;
  SilcUInt32 channel_users_modes_c = 0;
  SilcChannelID **channel_ids = NULL;

  SILC_LOG_DEBUG(("Announcing channels and channel users"));

  /* Get channels and channel users in local list */
  silc_server_announce_get_channels(server, server->local_list,
				    &channels, &channel_modes,
				    &channel_users,
				    &channel_users_modes,
				    &channel_users_modes_c,
				    &channel_topics,
				    &channel_invites,
				    &channel_bans,
				    &channel_ids, creation_time);

  /* Get channels and channel users in global list */
  if (server->server_type != SILC_SERVER)
    silc_server_announce_get_channels(server, server->global_list,
				      &channels, &channel_modes,
				      &channel_users,
				      &channel_users_modes,
				      &channel_users_modes_c,
				      &channel_topics,
				      &channel_invites,
				      &channel_bans,
				      &channel_ids, creation_time);

  if (channels) {
    silc_buffer_push(channels, channels->data - channels->head);
    SILC_LOG_HEXDUMP(("channels"), channels->data, silc_buffer_len(channels));

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NEW_CHANNEL, SILC_PACKET_FLAG_LIST,
			    channels->data, silc_buffer_len(channels));

    silc_buffer_free(channels);
  }

  if (channel_users) {
    silc_buffer_push(channel_users, channel_users->data - channel_users->head);
    SILC_LOG_HEXDUMP(("channel users"), channel_users->data,
		     silc_buffer_len(channel_users));

    /* Send the packet */
    silc_server_packet_send(server, remote,
			    SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
			    channel_users->data, silc_buffer_len(channel_users));

    silc_buffer_free(channel_users);
  }

  if (channel_modes) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_modes[i])
        continue;
      silc_buffer_push(channel_modes[i],
		       channel_modes[i]->data -
		       channel_modes[i]->head);
      SILC_LOG_HEXDUMP(("channel modes"), channel_modes[i]->data,
		       silc_buffer_len(channel_modes[i]));
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_modes[i]->data,
				   silc_buffer_len(channel_modes[i]));
      silc_buffer_free(channel_modes[i]);
    }
    silc_free(channel_modes);
  }

  if (channel_users_modes) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_users_modes[i])
        continue;
      silc_buffer_push(channel_users_modes[i],
		       channel_users_modes[i]->data -
		       channel_users_modes[i]->head);
      SILC_LOG_HEXDUMP(("channel users modes"), channel_users_modes[i]->data,
		       silc_buffer_len(channel_users_modes[i]));
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_users_modes[i]->data,
				   silc_buffer_len(channel_users_modes[i]));
      silc_buffer_free(channel_users_modes[i]);
    }
    silc_free(channel_users_modes);
  }

  if (channel_topics) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_topics[i])
	continue;

      silc_buffer_push(channel_topics[i],
		       channel_topics[i]->data -
		       channel_topics[i]->head);
      SILC_LOG_HEXDUMP(("channel topic"), channel_topics[i]->data,
		       silc_buffer_len(channel_topics[i]));
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_topics[i]->data,
				   silc_buffer_len(channel_topics[i]));
      silc_buffer_free(channel_topics[i]);
    }
    silc_free(channel_topics);
  }

  if (channel_invites) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_invites[i])
	continue;

      silc_buffer_push(channel_invites[i],
		       channel_invites[i]->data -
		       channel_invites[i]->head);
      SILC_LOG_HEXDUMP(("channel invite list"), channel_invites[i]->data,
		       silc_buffer_len(channel_invites[i]));
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_invites[i]->data,
				   silc_buffer_len(channel_invites[i]));
      silc_buffer_free(channel_invites[i]);
    }
    silc_free(channel_invites);
  }

  if (channel_bans) {
    int i;

    for (i = 0; i < channel_users_modes_c; i++) {
      if (!channel_bans[i])
	continue;

      silc_buffer_push(channel_bans[i],
		       channel_bans[i]->data -
		       channel_bans[i]->head);
      SILC_LOG_HEXDUMP(("channel ban list"), channel_bans[i]->data,
		       silc_buffer_len(channel_bans[i]));
      silc_server_packet_send_dest(server, remote,
				   SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				   channel_ids[i], SILC_ID_CHANNEL,
				   channel_bans[i]->data,
				   silc_buffer_len(channel_bans[i]));
      silc_buffer_free(channel_bans[i]);
    }
    silc_free(channel_bans);
  }

  silc_free(channel_ids);
}

/* Announces WATCH list. */

void silc_server_announce_watches(SilcServer server,
				  SilcPacketStream remote)
{
  SilcHashTableList htl;
  SilcBuffer buffer, idp, args, pkp;
  SilcClientEntry client;
  void *key;

  SILC_LOG_DEBUG(("Announcing watch list"));

  /* XXX because way we save the nicks (hash) we cannot announce them. */

  /* XXX we should send all public keys in one command if client is
     watching more than one key */
  silc_hash_table_list(server->watcher_list_pk, &htl);
  while (silc_hash_table_get(&htl, &key, (void *)&client)) {
    if (!client || !client->id)
      continue;

    server->stat.commands_sent++;

    idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    pkp = silc_public_key_payload_encode(key);
    args = silc_argument_payload_encode_one(args, pkp->data,
					    silc_buffer_len(pkp), 0x00);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_WATCH,
					    ++server->cmd_ident, 2,
					    1, idp->data, silc_buffer_len(idp),
					    4, args->data,
					    silc_buffer_len(args));

    /* Send command */
    silc_server_packet_send(server, remote, SILC_PACKET_COMMAND, 0,
			    buffer->data, silc_buffer_len(buffer));

    silc_buffer_free(pkp);
    silc_buffer_free(args);
    silc_buffer_free(idp);
    silc_buffer_free(buffer);
  }
  silc_hash_table_list_reset(&htl);
}

/* Assembles user list and users mode list from the `channel'. */

SilcBool silc_server_get_users_on_channel(SilcServer server,
				      SilcChannelEntry channel,
				      SilcBuffer *user_list,
				      SilcBuffer *mode_list,
				      SilcUInt32 *user_count)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  SilcBuffer idp;
  SilcUInt32 list_count = 0, len = 0;

  if (!silc_hash_table_count(channel->user_list))
    return FALSE;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl))
    len += (silc_id_get_len(chl->client->id, SILC_ID_CLIENT) + 4);
  silc_hash_table_list_reset(&htl);

  client_id_list = silc_buffer_alloc(len);
  client_mode_list =
    silc_buffer_alloc(4 * silc_hash_table_count(channel->user_list));
  silc_buffer_pull_tail(client_id_list, silc_buffer_truelen(client_id_list));
  silc_buffer_pull_tail(client_mode_list,
			silc_buffer_truelen(client_mode_list));

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    /* Client ID */
    idp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
    silc_buffer_put(client_id_list, idp->data, silc_buffer_len(idp));
    silc_buffer_pull(client_id_list, silc_buffer_len(idp));
    silc_buffer_free(idp);

    /* Client's mode on channel */
    SILC_PUT32_MSB(chl->mode, client_mode_list->data);
    silc_buffer_pull(client_mode_list, 4);

    list_count++;
  }
  silc_hash_table_list_reset(&htl);
  silc_buffer_push(client_id_list,
		   client_id_list->data - client_id_list->head);
  silc_buffer_push(client_mode_list,
		   client_mode_list->data - client_mode_list->head);

  *user_list = client_id_list;
  *mode_list = client_mode_list;
  *user_count = list_count;
  return TRUE;
}

/* Saves users and their modes to the `channel'. */

void silc_server_save_users_on_channel(SilcServer server,
				       SilcPacketStream sock,
				       SilcChannelEntry channel,
				       SilcClientID *noadd,
				       SilcBuffer user_list,
				       SilcBuffer mode_list,
				       SilcUInt32 user_count)
{
  int i;
  SilcUInt16 idp_len;
  SilcUInt32 mode;
  SilcID id;
  SilcClientEntry client;
  SilcIDCacheEntry cache;
  SilcChannelClientEntry chl;

  SILC_LOG_DEBUG(("Saving %d users on %s channel", user_count,
		  channel->channel_name));

  for (i = 0; i < user_count; i++) {
    /* Client ID */
    SILC_GET16_MSB(idp_len, user_list->data + 2);
    idp_len += 4;
    if (!silc_id_payload_parse_id(user_list->data, idp_len, &id))
      continue;
    silc_buffer_pull(user_list, idp_len);

    /* Mode */
    SILC_GET32_MSB(mode, mode_list->data);
    silc_buffer_pull(mode_list, 4);

    if (noadd && SILC_ID_CLIENT_COMPARE(&id.u.client_id, noadd))
      continue;

    cache = NULL;

    /* Check if we have this client cached already. */
    client = silc_idlist_find_client_by_id(server->local_list,
					   &id.u.client_id,
					   server->server_type, &cache);
    if (!client)
      client = silc_idlist_find_client_by_id(server->global_list,
					     &id.u.client_id,
					     server->server_type, &cache);
    if (!client) {
      /* If router did not find such Client ID in its lists then this must
	 be bogus client or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER)
	continue;

      /* We don't have that client anywhere, add it. The client is added
	 to global list since server didn't have it in the lists so it must be
	 global. */
      client = silc_idlist_add_client(server->global_list, NULL, NULL, NULL,
				      silc_id_dup(&id.u.client_id,
						  SILC_ID_CLIENT),
				      silc_packet_get_context(sock),
				      NULL);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
	continue;
      }

      client->data.status |= SILC_IDLIST_STATUS_REGISTERED;
    }

    if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
      SILC_LOG_ERROR(("Attempting to add unregistered client to channel ",
		      "%s", channel->channel_name));
      continue;
    }

    if (!silc_server_client_on_channel(client, channel, &chl)) {
      /* Client was not on the channel, add it. */
      chl = silc_calloc(1, sizeof(*chl));
      chl->client = client;
      chl->mode = mode;
      chl->channel = channel;
      silc_hash_table_add(channel->user_list, chl->client, chl);
      silc_hash_table_add(client->channels, chl->channel, chl);
      channel->user_count++;
    } else {
      /* Update mode */
      chl->mode = mode;
    }
  }
}

/* Saves channels and channels user modes to the `client'.  Removes
   the client from those channels that are not sent in the list but
   it has joined. */

void silc_server_save_user_channels(SilcServer server,
				    SilcPacketStream sock,
				    SilcClientEntry client,
				    SilcBuffer channels,
				    SilcBuffer channels_user_modes)
{
  SilcDList ch;
  SilcUInt32 *chumodes;
  SilcChannelPayload entry;
  SilcChannelEntry channel;
  SilcChannelID channel_id;
  SilcChannelClientEntry chl;
  SilcHashTable ht = NULL;
  SilcHashTableList htl;
  char *name;
  int i = 0;

  if (!channels || !channels_user_modes ||
      !(client->data.status & SILC_IDLIST_STATUS_REGISTERED))
    goto out;

  ch = silc_channel_payload_parse_list(channels->data,
				       silc_buffer_len(channels));
  if (ch && silc_get_mode_list(channels_user_modes, silc_dlist_count(ch),
			       &chumodes)) {
    ht = silc_hash_table_alloc(0, silc_hash_ptr, NULL, NULL,
			       NULL, NULL, NULL, TRUE);
    silc_dlist_start(ch);
    while ((entry = silc_dlist_get(ch)) != SILC_LIST_END) {
      /* Check if we have this channel, and add it if we don't have it.
	 Also add the client on the channel unless it is there already. */
      if (!silc_channel_get_id_parse(entry, &channel_id))
	continue;
      channel = silc_idlist_find_channel_by_id(server->local_list,
					       &channel_id, NULL);
      if (!channel)
	channel = silc_idlist_find_channel_by_id(server->global_list,
						 &channel_id, NULL);
      if (!channel) {
	if (server->server_type != SILC_SERVER) {
	  i++;
	  continue;
	}

	/* We don't have that channel anywhere, add it. */
	name = silc_channel_get_name(entry, NULL);
	channel = silc_idlist_add_channel(server->global_list, strdup(name), 0,
					  silc_id_dup(&channel_id,
						      SILC_ID_CHANNEL),
					  server->router, NULL, NULL, 0);
	if (!channel) {
	  i++;
	  continue;
	}
      }

      channel->mode = silc_channel_get_mode(entry);

      /* Add the client on the channel */
      if (!silc_server_client_on_channel(client, channel, &chl)) {
	chl = silc_calloc(1, sizeof(*chl));
	chl->client = client;
	chl->mode = chumodes[i++];
	chl->channel = channel;
	silc_hash_table_add(channel->user_list, chl->client, chl);
	silc_hash_table_add(client->channels, chl->channel, chl);
	channel->user_count++;
      } else {
	/* Update mode */
	chl->mode = chumodes[i++];
      }

      silc_hash_table_add(ht, channel, channel);
    }
    silc_channel_payload_list_free(ch);
    silc_free(chumodes);
  }

 out:
  /* Go through the list again and remove client from channels that
     are no part of the list. */
  if (ht) {
    silc_hash_table_list(client->channels, &htl);
    while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
      if (!silc_hash_table_find(ht, chl->channel, NULL, NULL)) {
	silc_hash_table_del(chl->channel->user_list, chl->client);
	silc_hash_table_del(chl->client->channels, chl->channel);
	silc_free(chl);
      }
    }
    silc_hash_table_list_reset(&htl);
    silc_hash_table_free(ht);
  } else {
    silc_hash_table_list(client->channels, &htl);
    while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
      silc_hash_table_del(chl->channel->user_list, chl->client);
      silc_hash_table_del(chl->client->channels, chl->channel);
      silc_free(chl);
    }
    silc_hash_table_list_reset(&htl);
  }
}

/* Lookups route to the client indicated by the `id_data'. The connection
   object and internal data object is returned. Returns NULL if route
   could not be found to the client. If the `client_id' is specified then
   it is used and the `id_data' is ignored. */

SilcPacketStream
silc_server_get_client_route(SilcServer server,
			     unsigned char *id_data,
			     SilcUInt32 id_len,
			     SilcClientID *client_id,
			     SilcIDListData *idata,
			     SilcClientEntry *client_entry)
{
  SilcClientID *id, clid;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  if (client_entry)
    *client_entry = NULL;

  /* Decode destination Client ID */
  if (!client_id) {
    if (!silc_id_str2id(id_data, id_len, SILC_ID_CLIENT, &clid, sizeof(clid)))
      return NULL;
    id = silc_id_dup(&clid, SILC_ID_CLIENT);
  } else {
    id = silc_id_dup(client_id, SILC_ID_CLIENT);
  }

  /* If the destination belongs to our server we don't have to route
     the packet anywhere but to send it to the local destination. */
  client = silc_idlist_find_client_by_id(server->local_list, id, TRUE, NULL);
  if (client) {
    silc_free(id);

    /* If we are router and the client has router then the client is in
       our cell but not directly connected to us. */
    if (server->server_type == SILC_ROUTER && client->router) {
      /* We are of course in this case the client's router thus the route
	 to the client is the server who owns the client. So, we will send
	 the packet to that server. */
      if (idata)
	*idata = (SilcIDListData)client->router;
      return client->router->connection;
    }

    /* Seems that client really is directly connected to us */
    if (idata)
      *idata = (SilcIDListData)client;
    if (client_entry)
      *client_entry = client;
    return client->connection;
  }

  /* Destination belongs to someone not in this server. If we are normal
     server our action is to send the packet to our router. */
  if (server->server_type != SILC_ROUTER && !server->standalone) {
    silc_free(id);
    if (idata)
      *idata = (SilcIDListData)server->router;
    return SILC_PRIMARY_ROUTE(server);
  }

  /* We are router and we will perform route lookup for the destination
     and send the packet to fastest route. */
  if (server->server_type == SILC_ROUTER && !server->standalone) {
    /* Check first that the ID is valid */
    client = silc_idlist_find_client_by_id(server->global_list, id,
					   TRUE, NULL);
    if (client) {
      SilcPacketStream dst_sock;

      dst_sock = silc_server_route_get(server, id, SILC_ID_CLIENT);

      silc_free(id);
      if (idata && dst_sock)
	*idata = silc_packet_get_context(dst_sock);
      return dst_sock;
    }
  }

  silc_free(id);
  return NULL;
}

/* Encodes and returns channel list of channels the `client' has joined.
   Secret channels are not put to the list. */

SilcBuffer silc_server_get_client_channel_list(SilcServer server,
					       SilcClientEntry client,
					       SilcBool get_private,
					       SilcBool get_secret,
					       SilcBuffer *user_mode_list)
{
  SilcBuffer buffer = NULL;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  unsigned char cid[32];
  SilcUInt32 id_len;
  SilcUInt16 name_len;
  int len;

  if (user_mode_list)
    *user_mode_list = NULL;

  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    if (channel->mode & SILC_CHANNEL_MODE_SECRET && !get_secret)
      continue;
    if (channel->mode & SILC_CHANNEL_MODE_PRIVATE && !get_private)
      continue;

    silc_id_id2str(channel->id, SILC_ID_CHANNEL, cid, sizeof(cid), &id_len);
    name_len = strlen(channel->channel_name);

    len = 4 + name_len + id_len + 4;
    buffer = silc_buffer_realloc(buffer,
				 (buffer ?
				  silc_buffer_truelen(buffer) + len : len));
    silc_buffer_pull_tail(buffer, (buffer->end - buffer->data));
    silc_buffer_format(buffer,
		       SILC_STR_UI_SHORT(name_len),
		       SILC_STR_DATA(channel->channel_name, name_len),
		       SILC_STR_UI_SHORT(id_len),
		       SILC_STR_DATA(cid, id_len),
		       SILC_STR_UI_INT(chl->channel->mode),
		       SILC_STR_END);
    silc_buffer_pull(buffer, len);

    if (user_mode_list) {
      *user_mode_list =
	silc_buffer_realloc(*user_mode_list,
			    (*user_mode_list ?
			     silc_buffer_truelen((*user_mode_list)) + 4 : 4));
      silc_buffer_pull_tail(*user_mode_list, ((*user_mode_list)->end -
					      (*user_mode_list)->data));
      SILC_PUT32_MSB(chl->mode, (*user_mode_list)->data);
      silc_buffer_pull(*user_mode_list, 4);
    }
  }
  silc_hash_table_list_reset(&htl);

  if (buffer)
    silc_buffer_push(buffer, buffer->data - buffer->head);
  if (user_mode_list && *user_mode_list)
    silc_buffer_push(*user_mode_list, ((*user_mode_list)->data -
				       (*user_mode_list)->head));

  return buffer;
}

/* Task callback used to retrieve network statistical information from
   router server once in a while. */

SILC_TASK_CALLBACK(silc_server_get_stats)
{
  SilcServer server = (SilcServer)context;
  SilcBuffer idp, packet;

  if (!server->standalone) {
    SILC_LOG_DEBUG(("Retrieving stats from router"));
    server->stat.commands_sent++;
    idp = silc_id_payload_encode(server->router->id, SILC_ID_SERVER);
    packet = silc_command_payload_encode_va(SILC_COMMAND_STATS,
					    ++server->cmd_ident, 1,
					    1, idp->data,
					    silc_buffer_len(idp));
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, 0, packet->data,
			    silc_buffer_len(packet));
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

  silc_schedule_task_add_timeout(server->schedule, silc_server_get_stats,
				 server, 120, 0);
}
