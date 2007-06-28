/*

  server_backup.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

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
SILC_TASK_CALLBACK(silc_server_backup_announce_watches);

static void silc_server_backup_connect_primary(SilcServer server,
					       SilcServerEntry server_entry,
					       void *context);


/************************** Types and Definitions ***************************/

/* Backup router */
typedef struct {
  SilcServerEntry server;
  SilcIDIP ip;
  SilcUInt16 port;
  SilcBool local;
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
  SilcBool connected;
  SilcServerEntry server_entry;
} SilcServerBackupProtocolSession;

/* Backup resuming protocol context  */
typedef struct {
  SilcServer server;
  SilcPacketStream sock;
  SilcUInt8 type;
  SilcUInt8 session;
  SilcServerBackupProtocolSession *sessions;
  SilcUInt32 sessions_count;
  SilcUInt32 initiator_restart;
  long start;
  int state;
  unsigned int responder        : 1;
  unsigned int received_failure : 1;
  unsigned int timeout          : 1;
  unsigned int error            : 1;
} *SilcServerBackupProtocolContext;


/********************* Backup Configuration Routines ************************/

/* Adds the `backup_server' to be one of our backup router. This can be
   called multiple times to set multiple backup routers. The `ip' and `port'
   is the IP and port that the `backup_router' will replace if the `ip'
   will become unresponsive. If `local' is TRUE then the `backup_server' is
   in the local cell, if FALSE it is in some other cell. */

void silc_server_backup_add(SilcServer server, SilcServerEntry backup_server,
			    const char *ip, int port, SilcBool local)
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
		  backup_server->data.sconn->remote_host, ip, port));

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

SilcBool silc_server_backup_replaced_get(SilcServer server,
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
    }
  }
}

/* Broadcast the received packet indicated by `packet' to all of our backup
   routers. All router wide information is passed using broadcast packets.
   That is why all backup routers need to get this data too. It is expected
   that the caller already knows that the `packet' is broadcast packet. */

void silc_server_backup_broadcast(SilcServer server,
				  SilcPacketStream sender,
				  SilcPacket packet)
{
  SilcServerEntry backup;
  SilcPacketStream sock;
  int i;

  if (!server->backup || server->server_type != SILC_ROUTER)
    return;

  SILC_LOG_DEBUG(("Broadcasting received packet to backup routers"));

  for (i = 0; i < server->backup->servers_count; i++) {
    backup = server->backup->servers[i].server;

    if (!backup || backup->connection == sender ||
	server->backup->servers[i].local == FALSE)
      continue;
    if (server->backup->servers[i].server == server->id_entry)
      continue;

    sock = backup->connection;
    silc_server_packet_route(server, sock, packet);
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
			     SilcBool force_send,
			     SilcBool local)
{
  SilcServerEntry backup;
  SilcPacketStream sock;
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

    silc_server_packet_send(server, backup->connection, type, flags,
			    data, data_len);
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
				  SilcBool force_send,
				  SilcBool local)
{
  SilcServerEntry backup;
  SilcPacketStream sock;
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

    silc_server_packet_send_dest(server, backup->connection, type, flags,
				 dst_id, dst_id_type, data, data_len);
  }
}

/* Send the START_USE indication to remote connection.  If `failure' is
   TRUE then this sends SILC_PACKET_FAILURE.  Otherwise it sends
   SILC_PACKET_RESUME_ROUTER. */

void silc_server_backup_send_start_use(SilcServer server,
				       SilcPacketStream sock,
				       SilcBool failure)
{
  unsigned char data[4];

  SILC_LOG_DEBUG(("Sending START_USE (%s)",
		  failure ? "failure" : "success"));

  if (failure) {
    SILC_PUT32_MSB(SILC_SERVER_BACKUP_START_USE, data);
    silc_server_packet_send(server, sock, SILC_PACKET_FAILURE, 0,
			    data, 4);
  } else {
    data[0] = SILC_SERVER_BACKUP_START_USE;
    data[1] = 0;
    silc_server_packet_send(server, sock,
			    SILC_PACKET_RESUME_ROUTER, 0,
			    data, 2);
  }
}

/* Send the REPLACED indication to remote router.  This is send by the
   primary router (remote router) of the primary router that came back
   online.  This is not sent by backup router or any other server. */

void silc_server_backup_send_replaced(SilcServer server,
				      SilcPacketStream sock)
{
  unsigned char data[4];

  SILC_LOG_DEBUG(("Sending REPLACED"));

  data[0] = SILC_SERVER_BACKUP_REPLACED;
  data[1] = 0;
  silc_server_packet_send(server, sock,
			  SILC_PACKET_RESUME_ROUTER, 0,
			  data, 2);
}


/************************ Backup Resuming Protocol **************************/

/* Timeout callback for protocol */

SILC_TASK_CALLBACK(silc_server_backup_timeout)
{
  SilcServerBackupProtocolContext ctx = context;
  SilcServer server = app_context;

  SILC_LOG_INFO(("Timeout occurred during backup resuming protocol"));
  ctx->timeout = TRUE;
  ctx->error = TRUE;
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_protocol_backup_done, context,
				 0, 0);
}

/* Callback to start the protocol as responder */

SILC_TASK_CALLBACK(silc_server_backup_responder_start)
{
  SilcServerBackupProtocolContext proto_ctx = context;
  SilcPacketStream sock = proto_ctx->sock;
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcServer server = app_context;

  /* If other protocol is executing at the same time, start with timeout. */
  if (idata->sconn->op) {
    SILC_LOG_DEBUG(("Other protocol is executing, wait for it to finish"));
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_backup_responder_start,
				   proto_ctx, 2, 0);
    return;
  }

  /* Register protocol timeout */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_backup_timeout,
				 proto_ctx, 30, 0);

  /* Run the backup resuming protocol */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_protocol_backup,
				 proto_ctx, 0, 0);
}

/* Callback to send START_USE to backup to check whether using backup
   is ok. */

SILC_TASK_CALLBACK(silc_server_backup_check_status)
{
  SilcPacketStream sock = context;
  SilcServer server = app_context;

  /* Check whether we are still using backup */
  if (!server->backup_primary)
    return;

  silc_server_backup_send_start_use(server, sock, FALSE);
  silc_packet_stream_unref(sock);
}

typedef struct {
  SilcServer server;
  SilcPacketStream sock;
  SilcPacket packet;
} *SilcServerBackupPing;

/* PING command reply callback */

void silc_server_backup_ping_reply(void *context, void *reply)
{
  SilcServerBackupPing pc = context;
  SilcServerCommandReplyContext cmdr = reply;

  if (cmdr && !silc_command_get_status(cmdr->payload, NULL, NULL)) {
    /* Timeout error occurred, the primary is really down. */
    SilcPacketStream primary = SILC_PRIMARY_ROUTE(pc->server);

    SILC_LOG_DEBUG(("PING timeout, primary is down"));

    if (primary) {
      silc_server_free_sock_user_data(pc->server, primary, NULL);
      silc_server_close_connection(pc->server, primary);
    }

    /* Reprocess the RESUME_ROUTER packet */
    silc_server_backup_resume_router(pc->server, pc->sock, pc->packet);
  } else {
    /* The primary is not down, refuse to serve the server as primary */
    SILC_LOG_DEBUG(("PING received, primary is up"));
    silc_server_backup_send_start_use(pc->server, pc->sock, TRUE);
  }

  silc_packet_stream_unref(pc->sock);
  silc_packet_free(pc->packet);
  silc_free(pc);
}

/* Processes incoming RESUME_ROUTER packet. This can give the packet
   for processing to the protocol handler or allocate new protocol if
   start command is received. */

void silc_server_backup_resume_router(SilcServer server,
				      SilcPacketStream sock,
				      SilcPacket packet)
{
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcServerEntry router = (SilcServerEntry)idata;
  SilcUInt8 type, session;
  SilcServerBackupProtocolContext ctx;
  int i, ret;

  SILC_LOG_DEBUG(("Received RESUME_ROUTER packet"));

  if (idata->conn_type == SILC_CONN_CLIENT ||
      idata->conn_type == SILC_CONN_UNKNOWN) {
    SILC_LOG_DEBUG(("Bad packet received"));
    silc_packet_free(packet);
    return;
  }

  ret = silc_buffer_unformat(&packet->buffer,
			     SILC_STR_UI_CHAR(&type),
			     SILC_STR_UI_CHAR(&session),
			     SILC_STR_END);
  if (ret < 0) {
    SILC_LOG_ERROR(("Malformed resume router packet received"));
    silc_packet_free(packet);
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
      silc_packet_free(packet);
      return;
    }

    /* Backup router following. */

    /* If we are marked as router then the primary is down and we send
       success START_USE back to the server. */
    if (server->server_type == SILC_ROUTER) {
      SILC_LOG_DEBUG(("Sending success START_USE back"));
      silc_server_backup_send_start_use(server, sock, FALSE);
      silc_packet_free(packet);
      return;
    }

    /* We have just lost primary, send success START_USE back */
    if (server->standalone) {
      SILC_LOG_DEBUG(("We are stanalone, sending success START_USE back"));
      silc_server_backup_send_start_use(server, sock, FALSE);
      silc_packet_free(packet);
      return;
    }

    /* We are backup router. This server claims that our primary is down.
       We will check this ourselves by sending PING command to the primary. */
    SILC_LOG_DEBUG(("Sending PING to detect status of primary router"));
    idp = silc_id_payload_encode(server->router->id, SILC_ID_SERVER);
    silc_server_send_command(server, SILC_PRIMARY_ROUTE(server),
			     SILC_COMMAND_PING, ++server->cmd_ident, 1,
			     1, idp->data, silc_buffer_len(idp));
    silc_buffer_free(idp);

    /* Reprocess this packet after received reply from router */
    pc = silc_calloc(1, sizeof(*pc));
    pc->server = server;
    pc->sock = sock;
    pc->packet = packet;
    silc_packet_stream_ref(sock);
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
			      data, 4);
      server->backup_closed = FALSE;
      silc_packet_free(packet);
      return;
    }

    proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
    proto_ctx->server = server;
    proto_ctx->sock = sock;
    proto_ctx->responder = TRUE;
    proto_ctx->type = type;
    proto_ctx->session = session;
    proto_ctx->start = time(0);
    silc_packet_stream_ref(sock);
    router->backup = TRUE;
    router->backup_proto = proto_ctx;

    SILC_LOG_DEBUG(("Starting backup resuming protocol as responder"));
    SILC_LOG_INFO(("Starting backup resuming protocol"));

    /* Start protocol immediately */
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_backup_responder_start,
				   proto_ctx, 0, 1);
    return;
  }

  /* If we are router and the packet is coming from our primary router
     then it means we have been replaced by an backup router in our cell. */
  if (type == SILC_SERVER_BACKUP_REPLACED &&
      server->server_type == SILC_ROUTER &&
      idata->conn_type == SILC_CONN_ROUTER &&
      SILC_PRIMARY_ROUTE(server) == sock) {
    /* We have been replaced by an backup router in our cell. We must
       mark our primary router connection disabled since we are not allowed
       to use it at this moment. */
    SILC_LOG_INFO(("We are replaced by an backup router in this cell, will "
		   "wait until backup resuming protocol is executed"));
    idata->status |= SILC_IDLIST_STATUS_DISABLED;
    silc_packet_free(packet);
    return;
  }

  /* Activate the shared protocol context for this socket connection
     if necessary */
  if (type == SILC_SERVER_BACKUP_RESUMED &&
      idata->conn_type == SILC_CONN_ROUTER && !router->backup &&
      idata->status & SILC_IDLIST_STATUS_DISABLED) {
    SilcServerEntry backup_router;

    if (silc_server_backup_replaced_get(server, router->id, &backup_router)) {
      ctx = backup_router->backup_proto;
      if (ctx->sock)
	silc_packet_stream_unref(ctx->sock);
      router->backup = TRUE;
      router->backup_proto = ctx;
      ctx->sock = sock;
      silc_packet_stream_ref(sock);
    }
  }

  /* Call the resuming protocol if the protocol is active. */
  if (router->backup) {
    ctx = router->backup_proto;
    ctx->type = type;

    for (i = 0; i < ctx->sessions_count; i++) {
      if (session == ctx->sessions[i].session) {
	ctx->session = session;
	silc_schedule_task_add_timeout(server->schedule,
				       silc_server_protocol_backup,
				       ctx, 0, 1);
	silc_packet_free(packet);
	return;
      }
    }

    /* If RESUMED received the session ID is zero, execute the protocol. */
    if (type == SILC_SERVER_BACKUP_RESUMED) {
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_protocol_backup,
				     ctx, 0, 1);
      silc_packet_free(packet);
      return;
    }

    SILC_LOG_ERROR(("Unknown backup resuming session %d", session));
    silc_packet_free(packet);
    return;
  }

  silc_packet_free(packet);
}

/* Task that is called after backup router has connected back to
   primary router and we are starting the resuming protocol */

SILC_TASK_CALLBACK(silc_server_backup_connected_later)
{
  SilcServerBackupProtocolContext proto_ctx =
    (SilcServerBackupProtocolContext)context;
  SilcServer server = proto_ctx->server;

  SILC_LOG_DEBUG(("Starting backup resuming protocol as initiator"));
  SILC_LOG_INFO(("Starting backup resuming protocol"));

  /* Register protocol timeout */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_backup_timeout,
				 proto_ctx, 30, 0);

  /* Run the backup resuming protocol */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_protocol_backup,
				 proto_ctx, 0, 0);
}

SILC_TASK_CALLBACK(silc_server_backup_connected_again)
{
  SilcServer server = app_context;
  SilcServerConfigRouter *primary;

  primary = silc_server_config_get_primary_router(server);
  if (primary) {
    if (!silc_server_find_socket_by_host(server, SILC_CONN_ROUTER,
					 primary->host, primary->port))
      silc_server_create_connection(server, FALSE, FALSE,
				    primary->host, primary->port,
				    silc_server_backup_connected,
				    context);
  }
}

/* Called when we've established connection back to our primary router
   when we've acting as backup router and have replaced the primary router
   in the cell. This function will start the backup resuming protocol. */

void silc_server_backup_connected(SilcServer server,
				  SilcServerEntry server_entry,
				  void *context)
{
  SilcServerBackupProtocolContext proto_ctx;
  SilcPacketStream sock;

  if (!server_entry) {
    /* Try again */
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_backup_connected_again,
				   context, 0, 1);
    return;
  }

  sock = server_entry->connection;
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = server;
  proto_ctx->sock = sock;
  proto_ctx->responder = FALSE;
  proto_ctx->type = SILC_SERVER_BACKUP_START;
  proto_ctx->start = time(0);
  silc_packet_stream_ref(sock);

  /* Start through scheduler */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_backup_connected_later,
				 proto_ctx, 0, 1);
}

SILC_TASK_CALLBACK(silc_server_backup_connect_primary_again)
{
  SilcServer server = app_context;
  SilcServerConfigRouter *primary;

  primary = silc_server_config_get_primary_router(server);
  if (primary) {
    if (!silc_server_find_socket_by_host(server, SILC_CONN_ROUTER,
					 primary->host, primary->port))
      silc_server_create_connection(server, FALSE, FALSE,
				    primary->host, primary->port,
				    silc_server_backup_connect_primary,
				    context);
  }
}

/* Called when normal server has connected to its primary router after
   backup router has sent the START packet in reusming protocol. We will
   move the protocol context from the backup router connection to the
   primary router. */

static void silc_server_backup_connect_primary(SilcServer server,
					       SilcServerEntry server_entry,
					       void *context)
{
  SilcPacketStream backup_router = context;
  SilcIDListData idata = silc_packet_get_context(backup_router);
  SilcServerEntry router = (SilcServerEntry)idata;
  SilcServerBackupProtocolContext ctx;
  SilcPacketStream sock;
  unsigned char data[2];

  if (!server_entry) {
    /* Try again */
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_backup_connect_primary_again,
				   context, 0, 0);
    return;
  }

  if (!router->backup || !server_entry->connection) {
    silc_packet_stream_unref(backup_router);
    return;
  }

  ctx = router->backup_proto;
  sock = server_entry->connection;
  idata = (SilcIDListData)server_entry;

  SILC_LOG_DEBUG(("Sending CONNECTED packet (session %d)", ctx->session));
  SILC_LOG_INFO(("Sending CONNECTED (session %d) to backup router",
		ctx->session));

  /* Send the CONNECTED packet back to the backup router. */
  data[0] = SILC_SERVER_BACKUP_CONNECTED;
  data[1] = ctx->session;
  silc_server_packet_send(server, backup_router,
			  SILC_PACKET_RESUME_ROUTER, 0, data, 2);

  /* The primary connection is disabled until it sends the RESUMED packet
     to us. */
  idata->status |= SILC_IDLIST_STATUS_DISABLED;

  /* Move this protocol context from this backup router connection to
     the primary router connection since it will send the subsequent
     packets in this protocol. We don't talk with backup router
     anymore. */
  if (ctx->sock)
    silc_packet_stream_unref(ctx->sock);
  ctx->sock = sock;
  silc_packet_stream_ref(sock);
  server_entry->backup = TRUE;
  server_entry->backup_proto = ctx;
  router->backup = FALSE;
  router->backup_proto = NULL;

  /* Unref */
  silc_packet_stream_unref(backup_router);
}

/* Timeout callback used by the backup router to send the ENDING packet
   to primary router to indicate that it can now resume as being primary
   router. All CONNECTED packets has been received when we reach this. */

SILC_TASK_CALLBACK(silc_server_backup_send_resumed)
{
  SilcServerBackupProtocolContext ctx = context;
  SilcServer server = ctx->server;
  unsigned char data[2];
  int i;

  SILC_LOG_DEBUG(("Start"));

  for (i = 0; i < ctx->sessions_count; i++)
    if (ctx->sessions[i].server_entry == silc_packet_get_context(ctx->sock))
      ctx->session = ctx->sessions[i].session;

  /* We've received all the CONNECTED packets and now we'll send the
     ENDING packet to the new primary router. */
  data[0] = SILC_SERVER_BACKUP_ENDING;
  data[1] = ctx->session;
  silc_server_packet_send(server, ctx->sock, SILC_PACKET_RESUME_ROUTER, 0,
			  data, sizeof(data));

  /* The protocol will go to END state. */
  ctx->state = 250;
}

/* Backup resuming protocol. This protocol is executed when the primary
   router wants to resume its position as being primary router. */

SILC_TASK_CALLBACK(silc_server_protocol_backup)
{
  SilcServerBackupProtocolContext ctx = context;
  SilcServer server = ctx->server;
  SilcServerEntry server_entry = NULL;
  SilcPacketStream sock = NULL;
  unsigned char data[2];
  SilcDList list;
  int i;

  if (!ctx->state)
    ctx->state = 1;

  switch(ctx->state) {
  case 1:
    if (ctx->responder == FALSE) {
      /*
       * Initiator (backup router)
       */

      /* Send the START packet to primary router and normal servers. The
	 packet will indicate to the primary router that it has been replaced
	 by us.  For normal servers it means that we will be resigning as
	 being primary router shortly. */
      list = silc_packet_engine_get_streams(server->packet_engine);
      if (!list)
	return;

      silc_dlist_start(list);
      while ((sock = silc_dlist_get(list))) {
	server_entry = silc_packet_get_context(sock);

	if (!server_entry || server_entry == server->id_entry ||
	    (server_entry->data.conn_type != SILC_CONN_ROUTER &&
	     server_entry->data.conn_type != SILC_CONN_SERVER))
	  continue;

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
	server_entry->backup = TRUE;
	server_entry->backup_proto = ctx;

	data[0] = SILC_SERVER_BACKUP_START;
	data[1] = ctx->sessions_count;
	silc_server_packet_send(server, sock, SILC_PACKET_RESUME_ROUTER, 0,
				data, sizeof(data));
	ctx->sessions_count++;
      }
      silc_packet_engine_free_streams_list(list);

      /* Announce data to the new primary to be. */
      silc_server_announce_servers(server, TRUE, 0, ctx->sock);
      silc_server_announce_clients(server, 0, ctx->sock);
      silc_server_announce_channels(server, 0, ctx->sock);

      ctx->state++;

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
					     SILC_CONN_ROUTER)) {
	SILC_LOG_DEBUG(("Received START (session %d), reconnect to router",
			ctx->session));
	silc_packet_stream_ref(ctx->sock);
	silc_server_create_connection(server, FALSE, FALSE,
				      primary->host, primary->port,
				      silc_server_backup_connect_primary,
				      ctx->sock);
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
				data, sizeof(data));
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
	ctx->state++;
      else
	ctx->state = 250;
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
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_backup_send_resumed,
				     ctx, 1, 0);
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
      silc_server_update_servers_by_server(server,
					   silc_packet_get_context(ctx->sock),
 					   server->router);
      silc_server_update_clients_by_server(server,
					   silc_packet_get_context(ctx->sock),
					   server->router, TRUE);

      /* We as primary router now must send RESUMED packets to all servers
	 and routers so that they know we are back.   For backup router we
	 send the packet last so that we give the backup as much time as
	 possible to deal with message routing at this critical moment. */
      list = silc_packet_engine_get_streams(server->packet_engine);
      if (!list)
	return;

      silc_dlist_start(list);
      while ((sock = silc_dlist_get(list))) {
	server_entry = silc_packet_get_context(sock);

	if (!server_entry || server_entry == server->id_entry ||
	    (server_entry->data.conn_type != SILC_CONN_ROUTER &&
	     server_entry->data.conn_type != SILC_CONN_SERVER))
	  continue;

	/* Send to backup last */
	if (sock == ctx->sock)
	  continue;

      send_to_backup:
	server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;

	SILC_LOG_DEBUG(("Sending RESUMED to %s", server_entry->server_name));
	SILC_LOG_INFO(("Sending RESUMED to %s", server_entry->server_name));

	/* This connection is performing this protocol too now */
	server_entry->backup = TRUE;
	server_entry->backup_proto = ctx;

	data[0] = SILC_SERVER_BACKUP_RESUMED;
	data[1] = 0;
	silc_server_packet_send(server, sock, SILC_PACKET_RESUME_ROUTER, 0,
				data, sizeof(data));
      }
      silc_packet_engine_free_streams_list(list);

      /* Now send the same packet to backup */
      if (sock != ctx->sock) {
	sleep(1);
	sock = ctx->sock;
	goto send_to_backup;
      }

      /* We are now resumed and are back as primary router in the cell. */
      SILC_LOG_INFO(("We are now the primary router of our cell again"));
      server->wait_backup = FALSE;

      /* Announce WATCH list a little later */
      silc_packet_stream_ref(ctx->sock);
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_backup_announce_watches,
				     ctx->sock, 4, 0);

      /* For us this is the end of this protocol. */
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_protocol_backup_done,
				     ctx->sock, 0, 1);
    }
    break;

  case 250:
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
      router = silc_packet_get_context(ctx->sock);
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
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_protocol_backup_done,
				     ctx->sock, 0, 1);
    }
    break;

  case 251:
    /* Protocol has ended, call the final callback */
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_protocol_backup_done,
				   ctx->sock, 0, 1);
    break;

  case 252:
    /* Protocol has ended, call the final callback */
    SILC_LOG_ERROR(("Error during backup resume: received Failure"));
    ctx->received_failure = TRUE;
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_protocol_backup_done,
				   ctx->sock, 0, 1);
    break;

  default:
    break;
  }
}

/* Final resuming protocol completion callback */

SILC_TASK_CALLBACK(silc_server_protocol_backup_done)
{
  SilcServerBackupProtocolContext ctx = context;
  SilcServer server = ctx->server;
  SilcDList list;
  SilcServerEntry server_entry;
  SilcPacketStream sock;
  SilcBool error;

  silc_schedule_task_del_by_context(server->schedule, ctx);

  error = ctx->error;

  if (error)
    SILC_LOG_ERROR(("Error occurred during backup router resuming protcool"));

  if (server->server_shutdown)
    return;

  /* Remove this protocol from all server entries that has it */
  list = silc_packet_engine_get_streams(server->packet_engine);
  if (!list)
    return;

  silc_dlist_start(list);
  while ((sock = silc_dlist_get(list))) {
    server_entry = silc_packet_get_context(sock);
    if (!server_entry)
      continue;

    if (server_entry->data.conn_type != SILC_CONN_ROUTER &&
	server_entry->data.conn_type != SILC_CONN_SERVER)
      continue;

    if (server_entry->backup_proto == ctx) {
      if (error) {

	if (server->server_type == SILC_SERVER &&
	    server_entry->server_type == SILC_ROUTER)
	  continue;

	/* Backup router */
	if (SILC_PRIMARY_ROUTE(server) == sock && server->backup_router) {
	  if (ctx->sock == sock) {
	    silc_packet_stream_unref(sock);
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
	    proto_ctx->sock = sock;
	    proto_ctx->responder = FALSE;
	    proto_ctx->type = SILC_SERVER_BACKUP_START;
	    proto_ctx->start = time(0);
	    proto_ctx->initiator_restart = ctx->initiator_restart + 1;
	    silc_packet_stream_ref(sock);

	    /* Start through scheduler */
	    silc_schedule_task_add_timeout(server->schedule,
					   silc_server_backup_connected_later,
					   proto_ctx, 5, 0);
	  } else {
	    /* If failure was received, switch back to normal backup router.
	       For some reason primary wouldn't accept that we were supposed
	       to perfom resuming protocol. */
	    server->server_type = SILC_BACKUP_ROUTER;
	    silc_server_local_servers_toggle_enabled(server, FALSE);
	    server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
	    silc_server_update_servers_by_server(server, server->id_entry,
						 silc_packet_get_context(sock));
	    silc_server_update_clients_by_server(server, NULL,
						 silc_packet_get_context(sock),
						 TRUE);

	    /* Announce our clients and channels to the router */
	    silc_server_announce_clients(server, 0, sock);
	    silc_server_announce_channels(server, 0, sock);

	    /* Announce WATCH list a little later */
	    silc_packet_stream_ref(sock);
	    silc_schedule_task_add_timeout(server->schedule,
					   silc_server_backup_announce_watches,
					   sock, 5, 0);
	  }

	  continue;
	}
      }

      server_entry->data.status &= ~SILC_IDLIST_STATUS_DISABLED;
    }
  }
  silc_packet_engine_free_streams_list(list);

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

      /* Announce WATCH list a little later */
      silc_packet_stream_ref(server->router->connection);
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_backup_announce_watches,
				     server->router->connection, 4, 0);
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
	silc_packet_stream_ref(server->router->connection);
	silc_schedule_task_add_timeout(server->schedule,
				       silc_server_backup_check_status,
				       server->router->connection,
				       5, 1);
	silc_packet_stream_ref(server->router->connection);
	silc_schedule_task_add_timeout(server->schedule,
				       silc_server_backup_check_status,
				       server->router->connection,
				       20, 1);
	silc_packet_stream_ref(server->router->connection);
	silc_schedule_task_add_timeout(server->schedule,
				       silc_server_backup_check_status,
				       server->router->connection,
				       60, 1);
      }
    }
  }

  if (ctx->sock) {
    SilcServerEntry r = silc_packet_get_context(ctx->sock);
    r->backup = FALSE;
    r->backup_proto = NULL;
    silc_packet_stream_unref(ctx->sock);
  }
  silc_free(ctx->sessions);
  silc_free(ctx);
}

SILC_TASK_CALLBACK(silc_server_backup_announce_watches)
{
  SilcPacketStream sock = context;
  SilcServer server = app_context;
  if (silc_packet_stream_is_valid(sock))
    silc_server_announce_watches(server, sock);
  silc_packet_stream_unref(sock);
}
