/*

  server_backup.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

SILC_TASK_CALLBACK(silc_server_protocol_backup_done);
SILC_TASK_CALLBACK(silc_server_backup_connect_to_router);

static void silc_server_backup_connect_primary(SilcServer server,
					       SilcServerEntry server_entry,
					       void *context);


/************************** Types and Definitions ***************************/

/* Backup router */
typedef struct {
  SilcServerEntry server;
  SilcIDIP ip;
  SilcUInt16 port;
  bool local;
} SilcServerBackupEntry;

/* Holds IP address and port of the primary router that was replaced
   by backup router. */
typedef struct {
  SilcIDIP ip;
  SilcUInt16 port;
  SilcServerEntry server;	/* Backup router that replaced the primary */
} SilcServerBackupReplaced;

/* Backup context */
struct SilcServerBackupStruct {
  SilcServerBackupEntry *servers;
  SilcUInt32 servers_count;
  SilcServerBackupReplaced **replaced;
  SilcUInt32 replaced_count;
};

typedef struct {
  SilcUInt8 session;
  bool connected;
  SilcServerEntry server_entry;
} SilcServerBackupProtocolSession;

/* Backup resuming protocol context  */
typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  SilcUInt8 type;
  SilcUInt8 session;
  SilcServerBackupProtocolSession *sessions;
  SilcUInt32 sessions_count;
  SilcUInt32 initiator_restart;
  long start;
  unsigned int responder        : 1;
  unsigned int received_failure : 1;
  unsigned int timeout          : 1;
} *SilcServerBackupProtocolContext;


/********************* Backup Configuration Routines ************************/

/* Adds the `backup_server' to be one of our backup router. This can be
   called multiple times to set multiple backup routers. The `ip' and `port'
   is the IP and port that the `backup_router' will replace if the `ip'
   will become unresponsive. If `local' is TRUE then the `backup_server' is
   in the local cell, if FALSE it is in some other cell. */

void silc_server_backup_add(SilcServer server, SilcServerEntry backup_server,
			    const char *ip, int port, bool local)
{
  int i;

  if (!ip)
    return;

  if (!server->backup) {
    server->backup = silc_calloc(1, sizeof(*server->backup));
    if (!server->backup)
      return;
  }

  /* See if already added */
  for (i = 0; i < server->backup->servers_count; i++) {
    if (server->backup->servers[i].server == backup_server)
      return;
  }

  SILC_LOG_DEBUG(("Backup router %s will replace %s",
		  ((SilcSocketConnection)backup_server->connection)->ip,
		  ip, port));

  for (i = 0; i < server->backup->servers_count; i++) {
    if (!server->backup->servers[i].server) {
      server->backup->servers[i].server = backup_server;
      server->backup->servers[i].local = local;
      server->backup->servers[i].port = SILC_SWAB_16(port);
      memset(server->backup->servers[i].ip.data, 0,
	     sizeof(server->backup->servers[i].ip.data));
      silc_net_addr2bin(ip, server->backup->servers[i].ip.data,
			sizeof(server->backup->servers[i].ip.data));
      return;
    }
  }

  i = server->backup->servers_count;
  server->backup->servers = silc_realloc(server->backup->servers,
					 sizeof(*server->backup->servers) *
					 (i + 1));
  server->backup->servers[i].server = backup_server;
  server->backup->servers[i].local = local;
  server->backup->servers[i].port = SILC_SWAB_16(port);
  memset(server->backup->servers[i].ip.data, 0,
	 sizeof(server->backup->servers[i].ip.data));
  silc_net_addr2bin(ip, server->backup->servers[i].ip.data,
		    sizeof(server->backup->servers[i].ip.data));
  server->backup->servers_count++;
}

/* Returns backup router for IP and port in `server_id' or NULL if there
   does not exist backup router. */

SilcServerEntry silc_server_backup_get(SilcServer server,
				       SilcServerID *server_id)
{
  int i;

  if (!server->backup)
    return NULL;

  for (i = 0; i < server->backup->servers_count; i++) {
    if (server->backup->servers[i].server &&
	server->backup->servers[i].port == server_id->port &&
	!memcmp(server->backup->servers[i].ip.data, server_id->ip.data,
		sizeof(server_id->ip.data))) {
      SILC_LOG_DEBUG(("Found backup router %s for %s",
		      server->backup->servers[i].server->server_name,
		      silc_id_render(server_id, SILC_ID_SERVER)));
      return server->backup->servers[i].server;
    }
  }

  return NULL;
}

/* Deletes the backup server `server_entry'. */

void silc_server_backup_del(SilcServer server, SilcServerEntry server_entry)
{
  int i;

  if (!server->backup)
    return;

  for (i = 0; i < server->backup->servers_count; i++) {
    if (server->backup->servers[i].server == server_entry) {
      SILC_LOG_DEBUG(("Removing %s as backup router",
		      silc_id_render(server->backup->servers[i].server->id,
				     SILC_ID_SERVER)));
      server->backup->servers[i].server = NULL;
      memset(server->backup->servers[i].ip.data, 0,
	     sizeof(server->backup->servers[i].ip.data));
    }
  }
}

/* Frees all data allocated for backup routers.  Call this after deleting
   all backup routers and when new routers are added no more, for example
   when shutting down the server. */

void silc_server_backup_free(SilcServer server)
{
  int i;

  if (!server->backup)
    return;

  /* Delete existing servers if caller didn't do it */
  for (i = 0; i < server->backup->servers_count; i++) {
    if (server->backup->servers[i].server)
      silc_server_backup_del(server, server->backup->servers[i].server);
  }

  silc_free(server->backup->servers);
  silc_free(server->backup);
  server->backup = NULL;
}

/* Marks the IP address and port from the `server_id' as  being replaced
   by backup router indicated by the `server'. If the router connects at
   a later time we can check whether it has been replaced by an backup
   router. */

void silc_server_backup_replaced_add(SilcServer server,
				     SilcServerID *server_id,
				     SilcServerEntry server_entry)
{
  int i;
  SilcServerBackupReplaced *r = silc_calloc(1, sizeof(*r));;

  if (!server->backup)
    server->backup = silc_calloc(1, sizeof(*server->backup));
  if (!server->backup->replaced) {
    server->backup->replaced =
      silc_calloc(1, sizeof(*server->backup->replaced));
    server->backup->replaced_count = 1;
  }

  SILC_LOG_DEBUG(("Replacing router %s with %s",
		  silc_id_render(server_id, SILC_ID_SERVER),
		  server_entry->server_name));

  memcpy(&r->ip, &server_id->ip, sizeof(server_id->ip));
  r->server = server_entry;

  for (i = 0; i < server->backup->replaced_count; i++) {
    if (!server->backup->replaced[i]) {
      server->backup->replaced[i] = r;
      return;
    }
  }

  i = server->backup->replaced_count;
  server->backup->replaced = silc_realloc(server->backup->replaced,
					  sizeof(*server->backup->replaced) *
					  (i + 1));
  server->backup->replaced[i] = r;
  server->backup->replaced_count++;
}

/* Checks whether the IP address and port from the `server_id' has been
   replaced by an backup router. If it has been then this returns TRUE
   and the bacup router entry to the `server' pointer if non-NULL. Returns
   FALSE if the router is not replaced by backup router. */

bool silc_server_backup_replaced_get(SilcServer server,
				     SilcServerID *server_id,
				     SilcServerEntry *server_entry)
{
  int i;

  if (!server->backup || !server->backup->replaced)
    return FALSE;

  for (i = 0; i < server->backup->replaced_count; i++) {
    if (!server->backup->replaced[i])
      continue;
    if (!memcmp(server->backup->replaced[i]->ip.data, server_id->ip.data,
		sizeof(server_id->ip.data))) {
      if (server_entry)
	*server_entry = server->backup->replaced[i]->server;
      SILC_LOG_DEBUG(("Router %s is replaced by %s",
		      silc_id_render(server_id, SILC_ID_SERVER),
		      server->backup->replaced[i]->server->server_name));
      return TRUE;
    }
  }

  SILC_LOG_DEBUG(("Router %s is not replaced by backup router",
		  silc_id_render(server_id, SILC_ID_SERVER)));
  return FALSE;
}

/* Deletes a replaced host by the set `server_entry. */

void silc_server_backup_replaced_del(SilcServer server,
				     SilcServerEntry server_entry)
{
  int i;

  if (!server->backup || !server->backup->replaced)
    return;

  for (i = 0; i < server->backup->replaced_count; i++) {
    if (!server->backup->replaced[i])
      continue;
    if (server->backup->replaced[i]->server == server_entry) {
      silc_free(server->backup->replaced[i]);
      server->backup->replaced[i] = NULL;
      return;
    }
  }
}

/* Broadcast the received packet indicated by `packet' to all of our backup
   routers. All router wide information is passed using broadcast packets.
   That is why all backup routers need to get this data too. It is expected
   that the caller already knows that the `packet' is broadcast packet. */

void silc_server_backup_broadcast(SilcServer server,
				  SilcSocketConnection sender,
				  SilcPacketContext *packet)
{
  SilcServerEntry backup;
  SilcSocketConnection sock;
  SilcBuffer buffer;
  const SilcBufferStruct p;
  SilcIDListData idata;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  SILC_LOG_DEBUG(("Broadcasting received packet to backup routers"));

  buffer = packet->buffer;
  silc_buffer_push(buffer, buffer->data - buffer->head);

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;

    if (!backup || backup->connection == sender ||
	server->backup->servers[i].local == FALSE)
      continue;
    if (server->backup->servers[i].server == server->id_entry)
      continue;

    idata = (SilcIDListData)backup;
    sock = backup->connection;

    if (!silc_packet_send_prepare(sock, 0, 0, buffer->len, idata->hmac_send,
				  (const SilcBuffer)&p)) {
      SILC_LOG_ERROR(("Cannot send packet"));
      return;
    }
    silc_buffer_put((SilcBuffer)&p, buffer->data, buffer->len);
    silc_packet_encrypt(idata->send_key, idata->hmac_send, idata->psn_send++,
			(SilcBuffer)&p, p.len);

    SILC_LOG_HEXDUMP(("Broadcasted packet, len %d", p.len), p.data, p.len);

    /* Now actually send the packet */
    silc_server_packet_send_real(server, sock, FALSE);

    /* Check for mandatory rekey */
    if (idata->psn_send == SILC_SERVER_REKEY_THRESHOLD)
      silc_schedule_task_add(server->schedule, sender->sock,
			     silc_server_rekey_callback, sender, 0, 1,
			     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
  }
}

/* A generic routine to send data to all backup routers. If the `sender'
   is provided it will indicate the original sender of the packet and the
   packet won't be resent to that entity. The `data' is the data that will
   be assembled to packet context before sending. The packet will be
   encrypted this function. If the `force_send' is TRUE the data is sent
   immediately and not put to queue. If `local' is TRUE then the packet
   will be sent only to local backup routers inside the cell. If false the
   packet can go from one cell to the other. This function has no effect
   if there are no any backup routers. */

void silc_server_backup_send(SilcServer server,
			     SilcServerEntry sender,
			     SilcPacketType type,
			     SilcPacketFlags flags,
			     unsigned char *data,
			     SilcUInt32 data_len,
			     bool force_send,
			     bool local)
{
  SilcServerEntry backup;
  SilcSocketConnection sock;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;
    if (!backup || sender == backup)
      continue;
    if (local && server->backup->servers[i].local == FALSE)
      continue;
    if (server->backup->servers[i].server == server->id_entry)
      continue;

    sock = backup->connection;

    SILC_LOG_DEBUG(("Sending %s packet to backup router %s (%s)",
		    silc_get_packet_name(type), sock->hostname, sock->ip));

    silc_server_packet_send(server, backup->connection, type, flags,
			    data, data_len, force_send);
  }
}

/* Same as silc_server_backup_send but sets a specific Destination ID to
   the packet. The Destination ID is indicated by the `dst_id' and the
   ID type `dst_id_type'. For example, packets destined to channels must
   be sent using this function. */

void silc_server_backup_send_dest(SilcServer server,
				  SilcServerEntry sender,
				  SilcPacketType type,
				  SilcPacketFlags flags,
				  void *dst_id,
				  SilcIdType dst_id_type,
				  unsigned char *data,
				  SilcUInt32 data_len,
				  bool force_send,
				  bool local)
{
  SilcServerEntry backup;
  SilcSocketConnection sock;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;
    if (!backup || sender == backup)
      continue;
    if (local && server->backup->servers[i].local == FALSE)
      continue;
    if (server->backup->servers[i].server == server->id_entry)
      continue;

    sock = backup->connection;

    SILC_LOG_DEBUG(("Sending %s packet to backup router %s (%s)",
		    silc_get_packet_name(type), sock->hostname, sock->ip));

    silc_server_packet_send_dest(server, backup->connection, type, flags,
				 dst_id, dst_id_type, data, data_len,
				 force_send);
  }
}

/* Send the START_USE indication to remote connection.  If `failure' is
   TRUE then this sends SILC_PACKET_FAILURE.  Otherwise it sends
   SILC_PACKET_RESUME_ROUTER. */

void silc_server_backup_send_start_use(SilcServer server,
				       SilcSocketConnection sock,
				       bool failure)
{
  unsigned char data[4];

  SILC_LOG_DEBUG(("Sending START_USE (%s) to %s",
		  failure ? "failure" : "success", sock->ip));

  if (failure) {
    SILC_PUT32_MSB(SILC_SERVER_BACKUP_START_USE, data);
    silc_server_packet_send(server, sock, SILC_PACKET_FAILURE, 0,
			    data, 4, FALSE);
  } else {
    data[0] = SILC_SERVER_BACKUP_START_USE;
    data[1] = 0;
    silc_server_packet_send(server, sock,
			    SILC_PACKET_RESUME_ROUTER, 0,
			    data, 2, FALSE);
  }
}

/* Send the REPLACED indication to remote router.  This is send by the
   primary router (remote router) of the primary router that came back
   online.  This is not sent by backup router or any other server. */

void silc_server_backup_send_replaced(SilcServer server,
				      SilcSocketConnection sock)
{
  unsigned char data[4];

  SILC_LOG_DEBUG(("Sending REPLACED (%s) to %s", sock->ip));

  data[0] = SILC_SERVER_BACKUP_REPLACED;
  data[1] = 0;
  silc_server_packet_send(server, sock,
			  SILC_PACKET_RESUME_ROUTER, 0,
			  data, 2, FALSE);
}


/************************ Backup Resuming Protocol **************************/

/* Timeout callback for protocol */

SILC_TASK_CALLBACK(silc_server_backup_timeout)
{
  SilcProtocol protocol = context;
  SilcServerBackupProtocolContext ctx = protocol->context;
  SilcServer server = app_context;

  SILC_LOG_INFO(("Timeout occurred during backup resuming protocol"));
  ctx->timeout = TRUE;
  silc_protocol_cancel(protocol, server->schedule);
  protocol->state = SILC_PROTOCOL_STATE_ERROR;
  silc_protocol_execute_final(protocol, server->schedule);
}

/* Callback to start the protocol as responder */

SILC_TASK_CALLBACK(silc_server_backup_responder_start)
{
  SilcServerBackupProtocolContext proto_ctx = context;
  SilcSocketConnection sock = proto_ctx->sock;
  SilcServer server = app_context;

  /* If other protocol is executing at the same time, start with timeout. */
  if (sock->protocol) {
    SILC_LOG_DEBUG(("Other protocol is executing, wait for it to finish"));
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_backup_responder_start,
			   proto_ctx, 2, 0,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  /* Run the backup resuming protocol */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_BACKUP,
		      &sock->protocol, proto_ctx,
		      silc_server_protocol_backup_done);
  silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
  silc_schedule_task_add(server->schedule, sock->sock,
			 silc_server_backup_timeout,
			 sock->protocol, 30, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Callback to send START_USE to backup to check whether using backup
   is ok. */

SILC_TASK_CALLBACK(silc_server_backup_check_status)
{
  SilcSocketConnection sock = context;
  SilcServer server = app_context;

  /* Check whether we are still using backup */
  if (!server->backup_primary)
    return;

  silc_server_backup_send_start_use(server, sock, FALSE);
  silc_socket_free(sock);	/* unref */
}

typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  SilcPacketContext *packet;
} *SilcServerBackupPing;

/* PING command reply callback */

void silc_server_backup_ping_reply(void *context, void *reply)
{
  SilcServerBackupPing pc = context;
  SilcServerCommandReplyContext cmdr = reply;

  if (cmdr && !silc_command_get_status(cmdr->payload, NULL, NULL)) {
    /* Timeout error occurred, the primary is really down. */
    SilcSocketConnection primary = SILC_PRIMARY_ROUTE(pc->server);

    SILC_LOG_DEBUG(("PING timeout, primary is down"));

    if (primary) {
      if (primary->user_data)
	silc_server_free_sock_user_data(pc->server, primary, NULL);
      SILC_SET_DISCONNECTING(primary);
      silc_server_close_connection(pc->server, primary);
    }

    /* Reprocess the RESUME_ROUTER packet */
    silc_server_backup_resume_router(pc->server, pc->sock, pc->packet);
  } else {
    /* The primary is not down, refuse to serve the server as primary */
    SILC_LOG_DEBUG(("PING received, primary is up"));
    silc_server_backup_send_start_use(pc->server, pc->sock, TRUE);
  }

  silc_socket_free(pc->sock);
  silc_packet_context_free(pc->packet);
  silc_free(pc);
}

/* Processes incoming RESUME_ROUTER packet. This can give the packet
   for processing to the protocol handler or allocate new protocol if
   start command is received. */

void silc_server_backup_resume_router(SilcServer server,
				      SilcSocketConnection sock,
				      SilcPacketContext *packet)
{
  SilcUInt8 type, session;
  SilcServerBackupProtocolContext ctx;
  SilcIDListData idata;
  int i, ret;

  SILC_LOG_DEBUG(("Received RESUME_ROUTER packet"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      sock->type == SILC_SOCKET_TYPE_UNKNOWN) {
    SILC_LOG_DEBUG(("Bad packet received"));
    return;
  }

  idata = (SilcIDListData)sock->user_data;

  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI_CHAR(&type),
			     SILC_STR_UI_CHAR(&session),
			     SILC_STR_END);
  if (ret < 0) {
    SILC_LOG_ERROR(("Malformed resume router packet received"));
    return;
  }

  /* Check whether this packet is used to tell us that server will start
     using us as primary router. */
  if (type == SILC_SERVER_BACKUP_START_USE) {
    SilcBuffer idp;
    SilcServerBackupPing pc;

    /* If we are normal server then backup router has sent us back
       this reply and we use the backup as primary router now. */
    if (server->server_type == SILC_SERVER) {
      /* Nothing to do here actually, since we have switched already. */
      SILC_LOG_DEBUG(("Received successful START_USE from backup router"));
      return;
    }

    /* Backup router following. */

    /* If we are marked as router then the primary is down and we send
       success START_USE back to the server. */
    if (server->server_type == SILC_ROUTER) {
      SILC_LOG_DEBUG(("Sending success START_USE back to %s", sock->ip));
      silc_server_backup_send_start_use(server, sock, FALSE);
      return;
    }

    /* We have just lost primary, send success START_USE back */
    if (server->standalone) {
      SILC_LOG_DEBUG(("We are stanalone, sending success START_USE back to %s",
		      sock->ip));
      silc_server_backup_send_start_use(server, sock, FALSE);
      return;
    }

    /* We are backup router. This server claims that our primary is down.
       We will check this ourselves by sending PING command to the primary. */
    SILC_LOG_DEBUG(("Sending PING to detect status of primary router"));
    idp = silc_id_payload_encode(server->router->id, SILC_ID_SERVER);
    silc_server_send_command(server, SILC_PRIMARY_ROUTE(server),
			     SILC_COMMAND_PING, ++server->cmd_ident, 1,
			     1, idp->data, idp->len);
    silc_buffer_free(idp);

    /* Reprocess this packet after received reply from router */
    pc = silc_calloc(1, sizeof(*pc));
    pc->server = server;
    pc->sock = silc_socket_dup(sock);
    pc->packet = silc_packet_context_dup(packet);
    silc_server_command_pending_timed(server, SILC_COMMAND_PING,
				      server->cmd_ident,
				      silc_server_backup_ping_reply, pc, 15);
    return;
  }


  /* Start the resuming protocol if requested. */
  if (type == SILC_SERVER_BACKUP_START) {
    /* We have received a start for resuming protocol.  We are either
       primary router that came back online or normal server. */
    SilcServerBackupProtocolContext proto_ctx;

    /* If backup had closed the connection earlier we won't allow resuming
       since we (primary router) have never gone away. */
    if (server->server_type == SILC_ROUTER && !server->backup_router &&
	server->backup_closed) {
      unsigned char data[4];
      SILC_LOG_DEBUG(("Backup resuming not allowed since we are still "
		      "primary router"));
      SILC_LOG_INFO(("Backup resuming not allowed since we are still "
		     "primary router"));
      SILC_PUT32_MSB(SILC_SERVER_BACKUP_START, data);
      silc_server_packet_send(server, sock, SILC_PACKET_FAILURE, 0,
			      data, 4, FALSE);
      server->backup_closed = FALSE;
      return;
    }

    proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
    proto_ctx->server = server;
    proto_ctx->sock = silc_socket_dup(sock);
    proto_ctx->responder = TRUE;
    proto_ctx->type = type;
    proto_ctx->session = session;
    proto_ctx->start = time(0);

    SILC_LOG_DEBUG(("Starting backup resuming protocol as responder"));
    SILC_LOG_INFO(("Starting backup resuming protocol"));

    /* Start protocol immediately */
    silc_schedule_task_add(server->schedule, sock->sock,
			   silc_server_backup_responder_start,
			   proto_ctx, 0, 1,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }


  /* If we are router and the packet is coming from our primary router
     then it means we have been replaced by an backup router in our cell. */
  if (type == SILC_SERVER_BACKUP_REPLACED &&
      server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_ROUTER &&
      SILC_PRIMARY_ROUTE(server) == sock) {
    /* We have been replaced by an backup router in our cell. We must
       mark our primary router connection disabled since we are not allowed
       to use it at this moment. */
    SILC_LOG_INFO(("We are replaced by an backup router in this cell, will "
		   "wait until backup resuming protocol is executed"));
    idata->status |= SILC_IDLIST_STATUS_DISABLED;
    return;
  }


  /* Activate the shared protocol context for this socket connection
     if necessary */
  if (type == SILC_SERVER_BACKUP_RESUMED &&
      sock->type == SILC_SOCKET_TYPE_ROUTER && !sock->protocol &&
      idata->status & SILC_IDLIST_STATUS_DISABLED) {
    SilcServerEntry backup_router;

    if (silc_server_backup_replaced_get(server, ((SilcServerEntry)idata)->id,
					&backup_router)) {
      SilcSocketConnection bsock =
	(SilcSocketConnection)backup_router->connection;
      if (bsock->protocol && bsock->protocol->protocol &&
	  bsock->protocol->protocol->type == SILC_PROTOCOL_SERVER_BACKUP) {
	sock->protocol = bsock->protocol;
	ctx = sock->protocol->context;
	if (ctx->sock)
	  silc_socket_free(ctx->sock); /* unref */
	ctx->sock = silc_socket_dup(sock);
      }
    }
  }


  /* Call the resuming protocol if the protocol is active. */
  if (SILC_SERVER_IS_BACKUP(sock)) {
    ctx = sock->protocol->context;
    ctx->type = type;

    for (i = 0; i < ctx->sessions_count; i++) {
      if (session == ctx->sessions[i].session) {
	ctx->session = session;
	silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
	return;
      }
    }

    /* If RESUMED received the session ID is zero, execute the protocol. */
    if (type == SILC_SERVER_BACKUP_RESUMED) {
      silc_protocol_execute(sock->protocol, server->schedule, 0, 0);
      return;
    }

    SILC_LOG_ERROR(("Unknown backup resuming session %d", session));
    return;
  }
}

/* callback for async connection to remote router */

SILC_TASK_CALLBACK(silc_server_backup_connection_established)
{
  SilcServer server = app_context;
  SilcServerConnection sconn = (SilcServerConnection)context;
  int sock = fd;
  int opt = EINVAL, optlen = sizeof(opt);

  silc_schedule_task_del_by_fd(server->schedule, sock);
  silc_schedule_unset_listen_fd(server->schedule, sock);

  if (silc_net_get_socket_opt(sock, SOL_SOCKET, SO_ERROR, &opt, &optlen) || 
      (opt != 0)) {
    SILC_LOG_DEBUG(("Could not connect to router %s:%d: %s", sconn->remote_host,
		    sconn->remote_port, strerror(opt)));
		    
    if (server->server_type == SILC_SERVER) {
      sconn->retry_count++;
      if (sconn->retry_count > 3) {
	silc_free(sconn->remote_host);
	silc_free(sconn);
	return;
      }
    }
    silc_schedule_task_add(server->schedule, 0,
			   silc_server_backup_connect_to_router,
			   context, 10, 0, SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
    return;
  }

  SILC_LOG_DEBUG(("Connection to router %s:%d established", sconn->remote_host,
		  sconn->remote_port));

  /* Continue with key exchange protocol */
  silc_server_start_key_exchange(server, sconn, sock);
}


/* Timeout task callback to connect to remote router */

SILC_TASK_CALLBACK(silc_server_backup_connect_to_router)
{
  SilcServer server = app_context;
  SilcServerConnection sconn = (SilcServerConnection)context;
  int sock;
  const char *server_ip;

  SILC_LOG_DEBUG(("Connecting to router %s:%d", sconn->remote_host,
		  sconn->remote_port));

  /* Connect to remote host */
  server_ip = server->config->server_info->primary == NULL ? NULL :
    server->config->server_info->primary->server_ip;
  sock = silc_net_create_connection_async(server_ip, sconn->remote_port,
				          sconn->remote_host);
  if (sock < 0) {
    if (server->server_type == SILC_SERVER) {
      sconn->retry_count++;
      if (sconn->retry_count > 3) {
	silc_free(sconn->remote_host);
	silc_free(sconn);
	return;
      }
    }
    silc_schedule_task_add(server->schedule, 0,
			   silc_server_backup_connect_to_router,
			   context, 10, 0, SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
    return;
  }

  /* wait for the connection to be established */
  silc_schedule_task_add(server->schedule, sock,
  			 silc_server_backup_connection_established,
			 context, 0, 0, SILC_TASK_FD,
			 SILC_TASK_PRI_NORMAL);
  silc_schedule_set_listen_fd(server->schedule, sock,
  			      SILC_TASK_WRITE, FALSE);
}

/* Constantly tries to reconnect to a primary router indicated by the
   `ip' and `port'. The `connected' callback will be called when the
   connection is created. */

void silc_server_backup_reconnect(SilcServer server,
				  const char *ip, SilcUInt16 port,
				  SilcServerConnectRouterCallback callback,
				  void *context)
{
  SilcServerConnection sconn;

  SILC_LOG_INFO(("Attempting to reconnect to primary router"));

  sconn = silc_calloc(1, sizeof(*sconn));
  sconn->remote_host = strdup(ip);
  sconn->remote_port = port;
  sconn->callback = callback;
  sconn->callback_context = context;
  sconn->no_reconnect = TRUE;
  sconn->retry_count = 0;
  silc_schedule_task_add(server->schedule, 0,
			 silc_server_backup_connect_to_router,
			 sconn, 1, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Task that is called after backup router has connected back to
   primary router and we are starting the resuming protocol */

SILC_TASK_CALLBACK(silc_server_backup_connected_later)
{
  SilcServerBackupProtocolContext proto_ctx =
    (SilcServerBackupProtocolContext)context;
  SilcServer server = proto_ctx->server;
  SilcSocketConnection sock = proto_ctx->sock;

  /* If running other protocol already run this one a bit later. */
  if (sock->protocol) {
    SILC_LOG_DEBUG(("Other protocol is running, wait for it to finish"));
    silc_schedule_task_add(server->schedule, 0,
			   silc_server_backup_connected_later,
			   proto_ctx, 15, 0,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
    return;
  }

  SILC_LOG_DEBUG(("Starting backup resuming protocol as initiator"));
  SILC_LOG_INFO(("Starting backup resuming protocol"));

  /* Run the backup resuming protocol */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_BACKUP,
		      &sock->protocol, proto_ctx,
		      silc_server_protocol_backup_done);
  silc_protocol_execute(sock->protocol, server->schedule, 0, 0);

  silc_schedule_task_add(server->schedule, sock->sock,
			 silc_server_backup_timeout,
			 sock->protocol, 30, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Called when we've established connection back to our primary router
   when we've acting as backup router and have replaced the primary router
   in the cell. This function will start the backup resuming protocol. */

void silc_server_backup_connected(SilcServer server,
				  SilcServerEntry server_entry,
				  void *context)
{
  SilcServerBackupProtocolContext proto_ctx;
  SilcSocketConnection sock;

  if (!server_entry) {
    /* Try again */
    SilcServerConfigRouter *primary;
    primary = silc_server_config_get_primary_router(server);
    if (primary) {
      if (!silc_server_find_socket_by_host(server, SILC_SOCKET_TYPE_ROUTER,
					   primary->host, primary->port))
	silc_server_backup_reconnect(server,
				     primary->host, primary->port,
				     silc_server_backup_connected,
				     context);
    }
    return;
  }

  sock = (SilcSocketConnection)server_entry->connection;
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = server;
  proto_ctx->sock = silc_socket_dup(sock);
  proto_ctx->responder = FALSE;
  proto_ctx->type = SILC_SERVER_BACKUP_START;
  proto_ctx->start = time(0);

  /* Start through scheduler */
  silc_schedule_task_add(server->schedule, 0,
			 silc_server_backup_connected_later,
			 proto_ctx, 0, 1,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Called when normal server has connected to its primary router after
   backup router has sent the START packet in reusming protocol. We will
   move the protocol context from the backup router connection to the
   primary router. */

static void silc_server_backup_connect_primary(SilcServer server,
					       SilcServerEntry server_entry,
					       void *context)
{
  SilcSocketConnection backup_router = (SilcSocketConnection)context;
  SilcServerBackupProtocolContext ctx;
  SilcSocketConnection sock;
  SilcIDListData idata;
  unsigned char data[2];

  if (SILC_IS_DISCONNECTING(backup_router) ||
      SILC_IS_DISCONNECTED(backup_router)) {
    silc_socket_free(backup_router);
    return;
  }

  if (!server_entry) {
    /* Try again */
    SilcServerConfigRouter *primary;
    primary = silc_server_config_get_primary_router(server);
    if (primary)
      if (!silc_server_find_socket_by_host(server, SILC_SOCKET_TYPE_ROUTER,
					   primary->host, primary->port))
	silc_server_backup_reconnect(server,
				     primary->host, primary->port,
				     silc_server_backup_connect_primary,
				     context);
    return;
  }

  /* Unref */
  silc_socket_free(backup_router);

  if (!backup_router->protocol)
    return;
  if (!server_entry->connection)
    return;

  ctx = (SilcServerBackupProtocolContext)backup_router->protocol->context;
  sock = (SilcSocketConnection)server_entry->connection;
  idata = (SilcIDListData)server_entry;

  SILC_LOG_DEBUG(("Sending CONNECTED packet (session %d)", ctx->session));
  SILC_LOG_INFO(("Sending CONNECTED (session %d) to backup router",
		ctx->session));

  /* Send the CONNECTED packet back to the backup router. */
  data[0] = SILC_SERVER_BACKUP_CONNECTED;
  data[1] = ctx->session;
  silc_server_packet_send(server, backup_router,
			  SILC_PACKET_RESUME_ROUTER, 0, data, 2, FALSE);

  /* The primary connection is disabled until it sends the RESUMED packet
     to us. */
  idata->status |= SILC_IDLIST_STATUS_DISABLED;

  /* Move this protocol context from this backup router connection to
     the primary router connection since it will send the subsequent
     packets in this protocol. We don't talk with backup router
     anymore. */
  sock->protocol = backup_router->protocol;
  if (ctx->sock)
    silc_socket_free(ctx->sock); /* unref */
  ctx->sock = silc_socket_dup(server_entry->connection);
  backup_router->protocol = NULL;
}

/* Timeout callback used by the backup router to send the ENDING packet
   to primary router to indicate that it can now resume as being primary
   router. All CONNECTED packets has been received when we reach this. */

SILC_TASK_CALLBACK(silc_server_backup_send_resumed)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerBackupProtocolContext ctx = protocol->context;
  SilcServer server = ctx->server;
  unsigned char data[2];
  int i;

  SILC_LOG_DEBUG(("Start"));

  for (i = 0; i < ctx->sessions_count; i++)
    if (ctx->sessions[i].server_entry == ctx->sock->user_data)
      ctx->session = ctx->sessions[i].session;

  /* We've received all the CONNECTED packets and now we'll send the
     ENDING packet to the new primary router. */
  data[0] = SILC_SERVER_BACKUP_ENDING;
  data[1] = ctx->session;
  silc_server_packet_send(server, ctx->sock, SILC_PACKET_RESUME_ROUTER, 0,
			  data, sizeof(data), FALSE);

  /* The protocol will go to END state. */
  protocol->state = SILC_PROTOCOL_STATE_END;
}

/* Backup resuming protocol. This protocol is executed when the primary
   router wants to resume its position as being primary router. */

SILC_TASK_CALLBACK_GLOBAL(silc_server_protocol_backup)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerBackupProtocolContext ctx = protocol->context;
  SilcServer server = ctx->server;
  SilcServerEntry server_entry;
  SilcSocketConnection sock = NULL;
  unsigned char data[2];
  int i;

  if (protocol->state == SILC_PROTOCOL_STATE_UNKNOWN)
    protocol->state = SILC_PROTOCOL_STATE_START;

  switch(protocol->state) {
  case SILC_PROTOCOL_STATE_START:
    if (ctx->responder == FALSE) {
      /*
       * Initiator (backup router)
       */

      /* Send the START packet to primary router and normal servers. The
	 packet will indicate to the primary router that it has been replaced
	 by us.  For normal servers it means that we will be resigning as
	 being primary router shortly. */
      for (i = 0; i < server->config->param.connections_max; i++) {
	sock = server->sockets[i];
	if (!sock || !sock->user_data ||
	    sock->user_data == server->id_entry ||
	    (sock->type != SILC_SOCKET_TYPE_ROUTER &&
	     sock->type != SILC_SOCKET_TYPE_SERVER))
	  continue;

	server_entry = sock->user_data;
	if (server_entry->data.status & SILC_IDLIST_STATUS_DISABLED)
	  continue;

	ctx->sessions = silc_realloc(ctx->sessions,
				     sizeof(*ctx->sessions) *
				     (ctx->sessions_count + 1));
	ctx->sessions[ctx->sessions_count].session = ctx->sessions_count;
	ctx->sessions[ctx->sessions_count].connected = FALSE;
	ctx->sessions[ctx->sessions_count].server_entry = server_entry;

	SILC_LOG_DEBUG(("Sending START to %s (session %d)",
			server_entry->server_name, ctx->sessions_count));
	SILC_LOG_INFO(("Expecting CONNECTED from %s (session %d)",
		       server_entry->server_name, ctx->sessions_count));

	/* This connection is performing this protocol too now */
	sock->protocol = protocol;

	data[0] = SILC_SERVER_BACKUP_START;
	data[1] = ctx->sessions_count;
	silc_server_packet_send(server, sock, SILC_PACKET_RESUME_ROUTER, 0,
				data, sizeof(data), FALSE);
	ctx->sessions_count++;
      }

      /* Announce data to the new primary to be. */
      silc_server_announce_servers(server, TRUE, 0, ctx->sock);
      silc_server_announce_clients(server, 0, ctx->sock);
      silc_server_announce_channels(server, 0, ctx->sock);

      protocol->state++;

    } else {
      /*
       * Responder (all servers and routers)
       */
      SilcServerConfigRouter *primary;

      /* We should have received START packet */
      if (ctx->type != SILC_SERVER_BACKUP_START) {
	SILC_LOG_ERROR(("Bad resume router packet START %d", ctx->type));
	break;
      }

      /* Connect to the primary router that was down that is now supposed
	 to be back online. We send the CONNECTED packet after we've
	 established the connection to the primary router. */
      primary = silc_server_config_get_primary_router(server);
      if (primary && server->backup_primary &&
	  !silc_server_num_sockets_by_remote(server,
					     silc_net_is_ip(primary->host) ?
					     primary->host : NULL,
					     silc_net_is_ip(primary->host) ?
					     NULL : primary->host,
					     primary->port,
					     SILC_SOCKET_TYPE_ROUTER)) {
	SILC_LOG_DEBUG(("Received START (session %d), reconnect to router",
			ctx->session));
	silc_server_backup_reconnect(server,
				     primary->host, primary->port,
				     silc_server_backup_connect_primary,
				     silc_socket_dup(ctx->sock));
      } else {
	/* Nowhere to connect just return the CONNECTED packet */
	SILC_LOG_DEBUG(("Received START (session %d), send CONNECTED back",
			ctx->session));
	SILC_LOG_INFO(("Sending CONNECTED (session %d) to backup router",
		      ctx->session));

	/* Send the CONNECTED packet back to the backup router. */
	data[0] = SILC_SERVER_BACKUP_CONNECTED;
	data[1] = ctx->session;
	silc_server_packet_send(server, ctx->sock,
				SILC_PACKET_RESUME_ROUTER, 0,
				data, sizeof(data), FALSE);
      }

      /* Add this resuming session */
      ctx->sessions = silc_realloc(ctx->sessions,
				   sizeof(*ctx->sessions) *
				   (ctx->sessions_count + 1));
      ctx->sessions[ctx->sessions_count].session = ctx->session;
      ctx->sessions_count++;

      /* Normal server goes directly to the END state. */
      if (server->server_type == SILC_ROUTER &&
	  (!server->router ||
	   server->router->data.status & SILC_IDLIST_STATUS_DISABLED))
	protocol->state++;
      else
	protocol->state = SILC_PROTOCOL_STATE_END;
    }
    break;

  case 2:
    if (ctx->responder == FALSE) {
      /*
       * Initiator (backup router)
       */

      /* We should have received CONNECTED packet */
      if (ctx->type != SILC_SERVER_BACKUP_CONNECTED) {
	SILC_LOG_ERROR(("Bad resume router packet CONNECTED %d", ctx->type));
	break;
      }

      for (i = 0; i < ctx->sessions_count; i++) {
	if (ctx->sessions[i].session == ctx->session) {
	  ctx->sessions[i].connected = TRUE;
	  SILC_LOG_INFO(("Received CONNECTED from %s (session %d)",
			 ctx->sessions[i].server_entry->server_name,
			 ctx->session));
	  SILC_LOG_DEBUG(("Received CONNECTED (session %d)", ctx->session));
	  break;
	}
      }

      /* See if all returned CONNECTED, if not, then continue waiting. */
      for (i = 0; i < ctx->sessions_count; i++) {
	if (!ctx->sessions[i].connected)
	  return;
      }

      SILC_LOG_INFO(("All sessions have returned CONNECTED packets, "
		     "continuing"));
      SILC_LOG_DEBUG(("Sending ENDING packet to primary router"));

      /* The ENDING is sent with timeout, and then we continue to the
	 END state in the protocol. */
      silc_schedule_task_add(server->schedule, 0,
			     silc_server_backup_send_resumed,
			     protocol, 1, 0, SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
      return;

    } else {
      /*
       * Responder (primary router)
       */

      /* We should have been received ENDING packet */
      if (ctx->type != SILC_SERVER_BACKUP_ENDING) {
	SILC_LOG_ERROR(("Bad resume router packet ENDING %d", ctx->type));
	break;
      }

      SILC_LOG_DEBUG(("Received ENDING packet, we are going to resume now"));

      /* Switch announced informations to our primary router of using the
	 backup router. */
      silc_server_local_servers_toggle_enabled(server, TRUE);
      silc_server_update_servers_by_server(server, ctx->sock->user_data,
					   server->router);
      silc_server_update_clients_by_server(server, ctx->sock->user_data,
					   server->router, TRUE);

      /* We as primary router now must send RESUMED packets to all servers
	 and routers so that they know we are back.   For backup router we
	 send the packet last so that we give the backup as much time as
	 possible to deal with message routing at this critical moment. */
      for (i = 0; i < server->config->param.connections_max; i++) {
	sock = server->sockets[i];
	if (!sock || !sock->user_data ||
	    sock->user_data == server->id_entry ||
	    (sock->type != SILC_SOCKET_TYPE_ROUTER &&
	     sock->type != SILC_SOCKET_TYPE_SERVER))
	  continue;

	/* Send to backup last */
	if (sock == ctx->sock)
	  continue;

      send_to_backup:
	server_entry = sock->user_data;
	server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;

	SILC_LOG_DEBUG(("Sending RESUMED to %s", server_entry->server_name));
	SILC_LOG_INFO(("Sending RESUMED to %s", server_entry->server_name));

	/* This connection is performing this protocol too now */
	sock->protocol = protocol;

	data[0] = SILC_SERVER_BACKUP_RESUMED;
	data[1] = 0;
	silc_server_packet_send(server, sock, SILC_PACKET_RESUME_ROUTER, 0,
				data, sizeof(data), FALSE);
	silc_server_packet_queue_purge(server, sock);
      }

      /* Now send the same packet to backup */
      if (sock != ctx->sock) {
	sleep(1);
	sock = ctx->sock;
	goto send_to_backup;
      }

      /* We are now resumed and are back as primary router in the cell. */
      SILC_LOG_INFO(("We are now the primary router of our cell again"));
      server->wait_backup = FALSE;

      /* For us this is the end of this protocol. */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_END:
    {
      /*
       * Responder (backup router, servers, and remote router)
       */
      SilcServerEntry router, backup_router;

      /* We should have been received RESUMED from our primary router. */
      if (ctx->type != SILC_SERVER_BACKUP_RESUMED) {
	SILC_LOG_ERROR(("Bad resume router packet RESUMED %d", ctx->type));
	break;
      }

      SILC_LOG_INFO(("Received RESUMED from new primary router"));

      /* If we are the backup router, mark that we are no longer primary
	 but are back to backup router status. */
      if (server->backup_router)
	server->server_type = SILC_BACKUP_ROUTER;

      /* We have now new primary router. All traffic goes there from now on. */
      router = ctx->sock->user_data;
      if (silc_server_backup_replaced_get(server, router->id,
					  &backup_router)) {

	if (backup_router == server->router) {
	  /* We have new primary router now */
	  server->id_entry->router = router;
	  server->router = router;
	  SILC_LOG_INFO(("Switching back to primary router %s",
			 server->router->server_name));
	} else {
	  /* We are connected to new primary and now continue using it */
	  SILC_LOG_INFO(("Resuming the use of primary router %s",
			 router->server_name));
	}
	server->backup_primary = FALSE;
	sock = router->connection;

	/* Update the client entries of the backup router to the new
	   router */
	silc_server_local_servers_toggle_enabled(server, FALSE);
	router->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
	silc_server_update_servers_by_server(server, backup_router, router);
	silc_server_update_clients_by_server(
				   server, NULL, router,
				   server->server_type == SILC_BACKUP_ROUTER);
	if (server->server_type == SILC_SERVER)
	  silc_server_update_channels_by_server(server, backup_router, router);
 	silc_server_backup_replaced_del(server, backup_router);
      }

      /* Send notify about primary router going down to local operators */
      SILC_SERVER_SEND_OPERS(server, FALSE, TRUE,
			     SILC_NOTIFY_TYPE_NONE,
			     ("%s resumed the use of primary router %s",
			      server->server_name,
			      server->router->server_name));

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /* Protocol has ended, call the final callback */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /* Protocol has ended, call the final callback */
    SILC_LOG_ERROR(("Error during backup resume: received Failure"));
    ctx->received_failure = TRUE;
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }
}

/* Final resuming protocol completion callback */

SILC_TASK_CALLBACK(silc_server_protocol_backup_done)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerBackupProtocolContext ctx = protocol->context;
  SilcServer server = ctx->server;
  SilcServerEntry server_entry;
  SilcSocketConnection sock;
  bool error;
  int i;

  silc_schedule_task_del_by_context(server->schedule, protocol);

  error = (protocol->state == SILC_PROTOCOL_STATE_ERROR ||
	   protocol->state == SILC_PROTOCOL_STATE_FAILURE);

  if (error) {
    SILC_LOG_ERROR(("Error occurred during backup router resuming protcool"));
    if (server->server_type == SILC_SERVER)
      silc_schedule_task_del_by_callback(server->schedule,
					 silc_server_backup_connect_to_router);
  }

  if (server->server_shutdown)
    return;

  /* Remove this protocol from all server entries that has it */
  for (i = 0; i < server->config->param.connections_max; i++) {
    sock = server->sockets[i];
    if (!sock || !sock->user_data ||
	(sock->type != SILC_SOCKET_TYPE_ROUTER &&
	 sock->type != SILC_SOCKET_TYPE_SERVER))
      continue;

    server_entry = sock->user_data;

    /* The SilcProtocol context was shared between all connections, clear
       it from all connections. */
    if (sock->protocol == protocol) {
      silc_server_packet_queue_purge(server, sock);
      sock->protocol = NULL;

      if (error) {

	if (server->server_type == SILC_SERVER &&
	    server_entry->server_type == SILC_ROUTER)
	  continue;

	/* Backup router */
	if (SILC_PRIMARY_ROUTE(server) == sock && server->backup_router) {
	  if (ctx->sock == sock) {
	    silc_socket_free(sock); /* unref */
	    ctx->sock = NULL;
	  }

	  /* If failed after 10 attempts, it won't work, give up */
	  if (ctx->initiator_restart > 10)
	    ctx->received_failure = TRUE;

	  if (!ctx->received_failure) {
	    /* Protocol error, probably timeout. Just restart the protocol. */
	    SilcServerBackupProtocolContext proto_ctx;

	    /* Restart the protocol. */
	    proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
	    proto_ctx->server = server;
	    proto_ctx->sock = silc_socket_dup(sock);
	    proto_ctx->responder = FALSE;
	    proto_ctx->type = SILC_SERVER_BACKUP_START;
	    proto_ctx->start = time(0);
	    proto_ctx->initiator_restart = ctx->initiator_restart + 1;

	    /* Start through scheduler */
	    silc_schedule_task_add(server->schedule, 0,
				   silc_server_backup_connected_later,
				   proto_ctx, 5, 0,
				   SILC_TASK_TIMEOUT,
				   SILC_TASK_PRI_NORMAL);
	  } else {
	    /* If failure was received, switch back to normal backup router.
	       For some reason primary wouldn't accept that we were supposed
	       to perfom resuming protocol. */
	    server->server_type = SILC_BACKUP_ROUTER;
	    silc_server_local_servers_toggle_enabled(server, FALSE);
	    server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
	    silc_server_update_servers_by_server(server, server->id_entry,
						 sock->user_data);
	    silc_server_update_clients_by_server(server, NULL,
						 sock->user_data, TRUE);

	    /* Announce our clients and channels to the router */
	    silc_server_announce_clients(server, 0, sock);
	    silc_server_announce_channels(server, 0, sock);
	  }

	  continue;
	}
      }

      server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
    }
  }

  if (!error) {
    SILC_LOG_INFO(("Backup resuming protocol ended successfully"));

    if (ctx->type == SILC_SERVER_BACKUP_RESUMED && server->router) {
      /* Announce all of our information to the router. */
      if (server->server_type == SILC_ROUTER)
	silc_server_announce_servers(server, FALSE, 0,
				     server->router->connection);

      /* Announce our clients and channels to the router */
      silc_server_announce_clients(server, 0, server->router->connection);
      silc_server_announce_channels(server, 0, server->router->connection);
    }
  } else {
    /* Error */

    if (server->server_type == SILC_SERVER) {
      /* If we are still using backup router Send confirmation to backup
	 that using it is still ok and continue sending traffic there.
	 The backup will reply with error if it's not ok. */
      if (server->router && server->backup_primary) {
	/* Send START_USE just in case using backup wouldn't be ok. */
	silc_server_backup_send_start_use(server, server->router->connection,
					  FALSE);

	/* Check couple of times same START_USE just in case. */
	silc_schedule_task_add(server->schedule, 0,
			       silc_server_backup_check_status,
			       silc_socket_dup(server->router->connection),
			       5, 1, SILC_TASK_TIMEOUT,
			       SILC_TASK_PRI_NORMAL);
	silc_schedule_task_add(server->schedule, 0,
			       silc_server_backup_check_status,
			       silc_socket_dup(server->router->connection),
			       20, 1, SILC_TASK_TIMEOUT,
			       SILC_TASK_PRI_NORMAL);
	silc_schedule_task_add(server->schedule, 0,
			       silc_server_backup_check_status,
			       silc_socket_dup(server->router->connection),
			       60, 1, SILC_TASK_TIMEOUT,
			       SILC_TASK_PRI_NORMAL);
      }
    }
  }

  if (ctx->sock && ctx->sock->protocol)
    ctx->sock->protocol = NULL;
  if (ctx->sock)
    silc_socket_free(ctx->sock); /* unref */
  silc_protocol_free(protocol);
  silc_free(ctx->sessions);
  silc_free(ctx);
}
