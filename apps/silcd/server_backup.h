/*

  server_backup.h

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

#ifndef SERVER_BACKUP_H
#define SERVER_BACKUP_H

/* Backup resuming protocol types */
#define SILC_SERVER_BACKUP_START          1   /* Start protocol */
#define SILC_SERVER_BACKUP_CONNECTED      2   /* Connected to primary */
#define SILC_SERVER_BACKUP_ENDING         3   /* Giving up as primary */
#define SILC_SERVER_BACKUP_RESUMED        4   /* Primary is back online */
#define SILC_SERVER_BACKUP_REPLACED       20  /* Primary has been replaced */
#define SILC_SERVER_BACKUP_START_USE      21  /* Start use backup as primary */

/* Adds the `backup_server' to be one of our backup router. This can be
   called multiple times to set multiple backup routers. The `replacing' is
   the IP and port that the `backup_router' will replace if the `replacing'
   will become unresponsive. If `local' is TRUE then the `backup_server' is
   in the local cell, if FALSE it is in some other cell. */
void silc_server_backup_add(SilcServer server, SilcServerEntry backup_server,
			    const char *ip, int port, bool local);

/* Returns backup router for IP and port in `server_id' or NULL if there
   does not exist backup router. */
SilcServerEntry silc_server_backup_get(SilcServer server,
				       SilcServerID *server_id);

/* Deletes the backup server `server_entry'. */
void silc_server_backup_del(SilcServer server, SilcServerEntry server_entry);

/* Frees all data allocated for backup routers.  Call this after deleting
   all backup routers and when new routers are added no more, for example
   when shutting down the server. */
void silc_server_backup_free(SilcServer server);

/* Marks the IP address and port from the `server_id' as  being replaced
   by backup router indicated by the `server'. If the router connects at
   a later time we can check whether it has been replaced by an backup
   router. */
void silc_server_backup_replaced_add(SilcServer server,
				     SilcServerID *server_id,
				     SilcServerEntry server_entry);

/* Checks whether the IP address and port from the `server_id' has been
   replaced by an backup router. If it has been then this returns TRUE
   and the bacup router entry to the `server' pointer if non-NULL. Returns
   FALSE if the router is not replaced by backup router. */
bool silc_server_backup_replaced_get(SilcServer server,
				     SilcServerID *server_id,
				     SilcServerEntry *server_entry);

/* Deletes a replaced host by the set `server_entry. */
void silc_server_backup_replaced_del(SilcServer server,
				     SilcServerEntry server_entry);

/* Broadcast the received packet indicated by `packet' to all of our backup
   routers. All router wide information is passed using broadcast packets.
   That is why all backup routers need to get this data too. It is expected
   that the caller already knows that the `packet' is broadcast packet. */
void silc_server_backup_broadcast(SilcServer server,
				  SilcSocketConnection sender,
				  SilcPacketContext *packet);

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
			     bool local);

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
				  bool local);

/* Send the START_USE indication to remote connection.  If `failure' is
   TRUE then this sends SILC_PACKET_FAILURE.  Otherwise it sends
   SILC_PACKET_RESUME_ROUTER. */
void silc_server_backup_send_start_use(SilcServer server,
				       SilcSocketConnection sock,
				       bool failure);

/* Send the REPLACED indication to remote router.  This is send by the
   primary router (remote router) of the primary router that came back
   online.  This is not sent by backup router or any other server. */
void silc_server_backup_send_replaced(SilcServer server,
				      SilcSocketConnection sock);

/* Processes incoming RESUME_ROUTER packet. This can give the packet
   for processing to the protocol handler or allocate new protocol if
   start command is received. */
void silc_server_backup_resume_router(SilcServer server,
				      SilcSocketConnection sock,
				      SilcPacketContext *packet);

/* Constantly tries to reconnect to a primary router indicated by the
   `ip' and `port'. The `connected' callback will be called when the
   connection is created. */
void silc_server_backup_reconnect(SilcServer server,
				  const char *ip, SilcUInt16 port,
				  SilcServerConnectRouterCallback callback,
				  void *context);

/* Called when we've established connection back to our primary router
   when we've acting as backup router and have replaced the primary router
   in the cell. This function will start the backup resuming protocol. */
void silc_server_backup_connected(SilcServer server,
				  SilcServerEntry server_entry,
				  void *context);

/* Backup resuming protocol. This protocol is executed when the primary
   router wants to resume its position as being primary router. */
SILC_TASK_CALLBACK_GLOBAL(silc_server_protocol_backup);

#endif /* SERVER_BACKUP_H */
