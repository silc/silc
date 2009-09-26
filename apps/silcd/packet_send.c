/*

  packet_send.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2009 Pekka Riikonen

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

/* Send packet to remote connection */

SilcBool silc_server_packet_send(SilcServer server,
				 SilcPacketStream sock,
				 SilcPacketType type,
				 SilcPacketFlags flags,
				 unsigned char *data,
				 SilcUInt32 data_len)
{
  SilcIDListData idata;

  if (!sock)
    return FALSE;

  idata = silc_packet_get_context(sock);

  /* If entry is disabled do not sent anything.  Allow hearbeat though */
  if ((idata && idata->status & SILC_IDLIST_STATUS_DISABLED &&
       type != SILC_PACKET_HEARTBEAT) ||
      ((SilcServerEntry)idata == server->id_entry)) {
    SILC_LOG_DEBUG(("Connection is disabled"));
    return FALSE;
  }

  SILC_LOG_DEBUG(("Sending %s packet", silc_get_packet_name(type)));

  return silc_packet_send(sock, type, flags, (const unsigned char *)data,
			  data_len);
}

/* Send packet to remote connection with specific destination ID. */

SilcBool silc_server_packet_send_dest(SilcServer server,
				      SilcPacketStream sock,
				      SilcPacketType type,
				      SilcPacketFlags flags,
				      void *dst_id,
				      SilcIdType dst_id_type,
				      unsigned char *data,
				      SilcUInt32 data_len)
{
  SilcIDListData idata;

  if (!sock)
    return FALSE;

  idata = silc_packet_get_context(sock);

  /* If entry is disabled do not sent anything.  Allow hearbeat though */
  if ((idata && idata->status & SILC_IDLIST_STATUS_DISABLED &&
       type != SILC_PACKET_HEARTBEAT) ||
      ((SilcServerEntry)idata == server->id_entry)) {
    SILC_LOG_DEBUG(("Connection is disabled"));
    return FALSE;
  }

  SILC_LOG_DEBUG(("Sending %s packet", silc_get_packet_name(type)));

  return silc_packet_send_ext(sock, type, flags, 0, NULL, dst_id_type, dst_id,
			      (const unsigned char *)data, data_len,
			      NULL, NULL);
}

/* Send packet to remote connection with specific source and destination
   IDs. */

SilcBool silc_server_packet_send_srcdest(SilcServer server,
					 SilcPacketStream sock,
					 SilcPacketType type,
					 SilcPacketFlags flags,
					 void *src_id,
					 SilcIdType src_id_type,
					 void *dst_id,
					 SilcIdType dst_id_type,
					 unsigned char *data,
					 SilcUInt32 data_len)
{
  SilcIDListData idata;

  if (!sock)
    return FALSE;

  idata = silc_packet_get_context(sock);

  /* If entry is disabled do not sent anything.  Allow hearbeat though */
  if ((idata && idata->status & SILC_IDLIST_STATUS_DISABLED &&
       type != SILC_PACKET_HEARTBEAT) ||
      ((SilcServerEntry)idata == server->id_entry)) {
    SILC_LOG_DEBUG(("Connection is disabled"));
    return FALSE;
  }

  SILC_LOG_DEBUG(("Sending %s packet", silc_get_packet_name(type)));

  return silc_packet_send_ext(sock, type, flags, src_id_type, src_id,
			      dst_id_type, dst_id,
			      (const unsigned char *)data, data_len,
			      NULL, NULL);
}

/* Broadcast received packet to our primary route. This function is used
   by router to further route received broadcast packet. It is expected
   that the broadcast flag from the packet is checked before calling this
   function. This does not test or set the broadcast flag. */

SilcBool silc_server_packet_broadcast(SilcServer server,
				      SilcPacketStream primary_route,
				      SilcPacket packet)
{
  SilcServerID src_id, dst_id;

  if (!primary_route)
    return FALSE;

  SILC_LOG_DEBUG(("Broadcasting received broadcast packet"));

  if (!silc_id_str2id(packet->src_id, packet->src_id_len, packet->src_id_type,
		      &src_id, sizeof(src_id)))
    return FALSE;
  if (!silc_id_str2id(packet->dst_id, packet->dst_id_len, packet->dst_id_type,
		      &dst_id, sizeof(dst_id)))
    return FALSE;

  /* If the packet is originated from our primary route we are not allowed
     to send the packet. */
  if (SILC_ID_SERVER_COMPARE(&src_id, server->router->id)) {
    SILC_LOG_DEBUG(("Will not broadcast to primary route since it is the "
		    "original sender of this packet"));
    return FALSE;
  }

  /* Send the packet */
  return silc_server_packet_send_srcdest(server, primary_route, packet->type,
					 packet->flags, &src_id,
					 SILC_ID_SERVER, &dst_id,
					 SILC_ID_SERVER,
					 packet->buffer.data,
					 silc_buffer_len(&packet->buffer));
}

/* Routes received packet to `sock'. This is used to route the packets that
   router receives but are not destined to it. */

SilcBool silc_server_packet_route(SilcServer server,
				  SilcPacketStream sock,
				  SilcPacket packet)
{
  SilcID src_id, dst_id;

  if (!silc_id_str2id2(packet->src_id, packet->src_id_len, packet->src_id_type,
		       &src_id))
    return FALSE;
  if (!silc_id_str2id2(packet->dst_id, packet->dst_id_len, packet->dst_id_type,
		       &dst_id))
    return FALSE;

  return silc_server_packet_send_srcdest(server, sock, packet->type,
					 packet->flags,
					 SILC_ID_GET_ID(src_id),
					 src_id.type,
					 SILC_ID_GET_ID(dst_id),
					 dst_id.type,
					 packet->buffer.data,
					 silc_buffer_len(&packet->buffer));
}

/* This routine can be used to send a packet to table of clients provided
   in `clients'. If `route' is FALSE the packet is routed only to local
   clients (for server locally connected, and for router local cell). */

void silc_server_packet_send_clients(SilcServer server,
				     SilcHashTable clients,
				     SilcPacketType type,
				     SilcPacketFlags flags,
				     SilcBool route,
				     unsigned char *data,
				     SilcUInt32 data_len)
{
  SilcPacketStream sock = NULL;
  SilcIDListData idata;
  SilcHashTableList htl;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcUInt32 routed_count = 0;
  SilcBool gone = FALSE;
  int k;

  if (!silc_hash_table_count(clients))
    return;

  SILC_LOG_DEBUG(("Sending packet to %d clients",
		  silc_hash_table_count(clients)));

  /* Send to all clients in table */
  silc_hash_table_list(clients, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&client)) {
    /* If client has router set it is not locally connected client and
       we will route the message to the router set in the client. Though,
       send locally connected server in all cases. */
    if (server->server_type == SILC_ROUTER && client->router &&
	((!route && client->router->router == server->id_entry) || route)) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Route only once to router */
      sock = client->router->connection;
      idata = silc_packet_get_context(sock);
      if (idata->conn_type == SILC_CONN_ROUTER) {
	if (gone)
	  continue;
	gone = TRUE;
      }

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, flags,
				   client->router->id, SILC_ID_SERVER,
				   data, data_len);

      /* Mark this route routed already */
      routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
      routed[routed_count++] = client->router;
      continue;
    }

    if (client->router)
      continue;

    /* Send to locally connected client */
    sock = client->connection;
    if (!sock)
      continue;

    silc_server_packet_send_dest(server, sock, type, flags,
				 client->id, SILC_ID_CLIENT,
				 data, data_len);
  }
  silc_hash_table_list_reset(&htl);
  silc_free(routed);
}

/* This routine is used by the server to send packets to channel. The
   packet sent with this function is distributed to all clients on
   the channel. Usually this is used to send notify messages to the
   channel, things like notify about new user joining to the channel.
   If `route' is FALSE then the packet is sent only locally and will not
   be routed anywhere (for router locally means cell wide). If `sender'
   is provided then the packet is not sent to that connection since it
   originally came from it. If `send_to_clients' is FALSE then the
   packet is not sent clients, only servers. */

void silc_server_packet_send_to_channel(SilcServer server,
					SilcPacketStream sender,
					SilcChannelEntry channel,
					SilcPacketType type,
					SilcBool route,
					SilcBool send_to_clients,
					unsigned char *data,
					SilcUInt32 data_len)
{
  SilcPacketStream sock = NULL;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcIDListData idata;
  SilcUInt32 routed_count = 0;
  SilcBool gone = FALSE;
  int k;

  /* This doesn't send channel message packets */
  SILC_ASSERT(type != SILC_PACKET_CHANNEL_MESSAGE);

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (route && server->server_type != SILC_ROUTER && !server->standalone &&
      channel->global_users) {
    sock = server->router->connection;
    if (sock != sender) {
      SILC_LOG_DEBUG(("Sending packet to router for routing"));
      silc_server_packet_send_dest(server, sock, type, 0, channel->id,
				   SILC_ID_CHANNEL, data, data_len);
    }
  }

  if (!silc_hash_table_count(channel->user_list)) {
    SILC_LOG_DEBUG(("Channel %s is empty", channel->channel_name));
    goto out;
  }

  SILC_LOG_DEBUG(("Sending %s to channel %s",
		  silc_get_packet_name(type), channel->channel_name));

  routed = silc_calloc(silc_hash_table_count(channel->user_list),
		       sizeof(*routed));

  /* Send the message to clients on the channel's client list. */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    client = chl->client;
    if (!client)
      continue;

    /* If client has router set it is not locally connected client and
       we will route the message to the router set in the client. Though,
       send locally connected server in all cases. */
    if (server->server_type == SILC_ROUTER && client->router &&
	((!route && client->router->router == server->id_entry) || route)) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Get data used in packet header encryption, keys and stuff. */
      sock = client->router->connection;
      idata = (SilcIDListData)client->router;

      if (sender && sock == sender)
	continue;

      /* Route only once to router. Protocol prohibits sending channel
	 messages to more than one router. */
      if (idata->conn_type == SILC_CONN_ROUTER) {
	if (gone)
	  continue;
	gone = TRUE;
      }

      SILC_LOG_DEBUG(("Sending packet to client %s",
		      client->nickname ? client->nickname :
		      (unsigned char *)""));

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, 0, channel->id,
				   SILC_ID_CHANNEL, data, data_len);

      /* Mark this route routed already */
      routed[routed_count++] = client->router;
      continue;
    }

    if (client->router || !send_to_clients)
      continue;

    /* Send to locally connected client */

    /* Get data used in packet header encryption, keys and stuff. */
    sock = client->connection;
    if (!sock || (sender && sock == sender))
      continue;

    SILC_LOG_DEBUG(("Sending packet to client %s",
		    client->nickname ? client->nickname :
		    (unsigned char *)""));

    /* Send the packet */
    silc_server_packet_send_dest(server, sock, type, 0, channel->id,
				 SILC_ID_CHANNEL, data, data_len);
  }
  silc_hash_table_list_reset(&htl);

 out:
  silc_free(routed);
}

/* This checks whether the relayed packet came from router. If it did
   then we'll need to encrypt it with the channel key. This is called
   from the silc_server_packet_relay_to_channel. */

static SilcBool
silc_server_packet_relay_to_channel_encrypt(SilcServer server,
					    SilcPacketStream sender,
					    void *sender_id,
					    SilcIdType sender_type,
					    SilcChannelEntry channel,
					    unsigned char *data,
					    unsigned int data_len)
{
  SilcIDListData idata;
  SilcUInt32 mac_len, iv_len;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];
  SilcUInt16 totlen, len;
  SilcID src_id, dst_id;

  idata = silc_packet_get_context(sender);

  /* If we are router and the packet came from router and private key
     has not been set for the channel then we must encrypt the packet
     as it was decrypted with the session key shared between us and the
     router which sent it. This is so, because cells does not share the
     same channel key. */
  if (server->server_type == SILC_ROUTER &&
      idata->conn_type == SILC_CONN_ROUTER &&
      !(channel->mode & SILC_CHANNEL_MODE_PRIVKEY) && channel->key) {

    /* If we are backup router and remote is our primary router and
       we are currently doing backup resuming protocol we must not
       re-encrypt message with session key. */
    if (server->backup_router && idata->sconn->backup_resuming &&
	SILC_PRIMARY_ROUTE(server) == sender)
      return TRUE;

    mac_len = silc_hmac_len(channel->hmac);
    iv_len = silc_cipher_get_block_len(channel->send_key);

    if (data_len <= mac_len + iv_len) {
      SILC_LOG_WARNING(("Corrupted channel message, cannot relay it"));
      return FALSE;
    }

    totlen = 2;
    SILC_GET16_MSB(len, data + totlen);
    totlen += 2 + len;
    if (totlen + iv_len + mac_len + 2 > data_len) {
      SILC_LOG_WARNING(("Corrupted channel message, cannot relay it"));
      return FALSE;
    }
    SILC_GET16_MSB(len, data + totlen);
    totlen += 2 + len;
    if (totlen + iv_len + mac_len > data_len) {
      SILC_LOG_WARNING(("Corrupted channel message, cannot relay it"));
      return FALSE;
    }

    memcpy(iv, data + (data_len - iv_len - mac_len), iv_len);

    SILC_ASSERT(sender_type == SILC_ID_CLIENT);
    src_id.type = SILC_ID_CLIENT;
    src_id.u.client_id = *((SilcClientID *)sender_id);
    dst_id.type = SILC_ID_CHANNEL;
    dst_id.u.channel_id = *channel->id;

    return silc_message_payload_encrypt(data, totlen, data_len - mac_len,
					iv, &src_id, &dst_id,
					channel->send_key, channel->hmac);
  }

  return TRUE;
}

/* This routine is explicitly used to relay messages to some channel.
   Packets sent with this function we have received earlier and are
   totally encrypted. This just sends the packet to all clients on
   the channel. If the sender of the packet is someone on the channel
   the message will not be sent to that client. The SILC Packet header
   is encrypted with the session key shared between us and the client.
   MAC is also computed before encrypting the header. Rest of the
   packet will be untouched. */

void silc_server_packet_relay_to_channel(SilcServer server,
					 SilcPacketStream sender_sock,
					 SilcChannelEntry channel,
					 void *sender_id,
					 SilcIdType sender_type,
					 SilcClientEntry sender_entry,
					 unsigned char *data,
					 SilcUInt32 data_len)
{
  SilcPacketStream sock = NULL;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl, chl_sender;
  SilcUInt32 routed_count = 0;
  SilcIDListData idata;
  SilcHashTableList htl;
  SilcBool gone = FALSE;
  int k;

  if (!silc_server_client_on_channel(sender_entry, channel, &chl_sender))
    return;

  SILC_LOG_DEBUG(("Relaying packet to channel %s", channel->channel_name));

  /* This encrypts the message, if needed. It will be encrypted if
     it came from the router thus it needs to be encrypted with the
     channel key. If the channel key does not exist, then we know we
     don't have a single local user on the channel. */
  if (!silc_server_packet_relay_to_channel_encrypt(server, sender_sock,
						   sender_id, sender_type,
						   channel, data,
						   data_len))
    return;

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (server->server_type != SILC_ROUTER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router = server->router;

    /* Check that the sender is not our router. */
    if (sender_sock != router->connection) {
      SILC_LOG_DEBUG(("Sending message to router for routing"));
      sock = router->connection;
      silc_server_packet_send_srcdest(server, sock,
				      SILC_PACKET_CHANNEL_MESSAGE, 0,
				      sender_id, sender_type,
				      channel->id, SILC_ID_CHANNEL,
				      data, data_len);
    }
  }

  routed = silc_calloc(silc_hash_table_count(channel->user_list),
		       sizeof(*routed));

  /* Assure we won't route the message back to the sender's way. */
  if (sender_entry->router)
    routed[routed_count++] = sender_entry->router;

  /* Send the message to clients on the channel's client list. */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    client = chl->client;
    if (!client || client == sender_entry)
      continue;

    /* Check whether message sending is blocked */
    if (chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES)
      continue;
    if (chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS &&
	!(chl_sender->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	!(chl_sender->mode & SILC_CHANNEL_UMODE_CHANFO))
      continue;
    if (chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS &&
	sender_entry->mode & SILC_UMODE_ROBOT)
      continue;

    /* If the client has set router it means that it is not locally
       connected client and we will route the packet further. */
    if (server->server_type == SILC_ROUTER && client->router) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Get data used in packet header encryption, keys and stuff. */
      sock = client->router->connection;
      idata = (SilcIDListData)client->router;

      /* Check if the sender socket is the same as this client's router
	 socket. */
      if (sender_sock && sock == sender_sock)
	continue;

      SILC_LOG_DEBUG(("Relaying packet to client ID(%s)",
		      silc_id_render(client->id, SILC_ID_CLIENT)));

      /* Mark this route routed already. */
      routed[routed_count++] = client->router;

      if (idata->conn_type == SILC_CONN_ROUTER) {
	/* The remote connection is router then we'll decrypt the
	   channel message and re-encrypt it with the session key shared
	   between us and the remote router. This is done because the
	   channel keys are cell specific and we have different channel
	   key than the remote router has. */

	/* Route only once to router. Protocol prohibits sending channel
	   messages to more than one router. */
	if (gone)
	  continue;
	gone = TRUE;

	/* If we are backup router and remote is our primary router and
	   we are currently doing backup resuming protocol we must not
	   re-encrypt message with session key. */
	if (server->backup_router && idata->sconn->backup_resuming &&
	    SILC_PRIMARY_ROUTE(server) == sock) {
	  silc_server_packet_send_srcdest(server, sock,
					  SILC_PACKET_CHANNEL_MESSAGE, 0,
					  sender_id, sender_type,
					  channel->id, SILC_ID_CHANNEL,
					  data, data_len);
	  continue;
	}

	SILC_LOG_DEBUG(("Remote is router, encrypt with session key"));

	/* If private key mode is not set then decrypt the packet
	   and re-encrypt it */
	if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY) &&
	    channel->receive_key) {
	  unsigned char tmp[SILC_PACKET_MAX_LEN], sid[32], rid[32];
	  SilcUInt32 sid_len, rid_len;

	  if (data_len > SILC_PACKET_MAX_LEN)
	    data_len = SILC_PACKET_MAX_LEN;
	  memcpy(tmp, data, data_len);

	  /* Decrypt the channel message (we don't check the MAC) */
	  silc_id_id2str(sender_id, sender_type, sid, sizeof(sid), &sid_len);
	  silc_id_id2str(channel->id, SILC_ID_CHANNEL, rid, sizeof(rid),
			 &rid_len);
	  silc_message_payload_decrypt(tmp, data_len, FALSE, FALSE,
				       channel->receive_key,
				       channel->hmac, sid, sid_len,
				       rid, rid_len, FALSE);

	  /* Now re-encrypt and send it to the router */
	  silc_server_packet_send_srcdest(server, sock,
					  SILC_PACKET_CHANNEL_MESSAGE, 0,
					  sender_id, sender_type,
					  channel->id, SILC_ID_CHANNEL,
					  tmp, data_len);
	} else {
	  /* Private key mode is set, we don't have the channel key, so
	     just re-encrypt the entire packet and send it to the router. */
	  silc_server_packet_send_srcdest(server, sock,
					  SILC_PACKET_CHANNEL_MESSAGE, 0,
					  sender_id, sender_type,
					  channel->id, SILC_ID_CHANNEL,
					  data, data_len);
	}
      } else {
	/* Send the packet to normal server */
	silc_server_packet_send_srcdest(server, sock,
					SILC_PACKET_CHANNEL_MESSAGE, 0,
					sender_id, sender_type,
					channel->id, SILC_ID_CHANNEL,
					data, data_len);
      }

      continue;
    }

    if (client->router)
      continue;

    /* Get data used in packet header encryption, keys and stuff. */
    sock = client->connection;
    if (!sock || (sender_sock && sock == sender_sock))
      continue;

    SILC_LOG_DEBUG(("Sending packet to client ID(%s)",
		    silc_id_render(client->id, SILC_ID_CLIENT)));

    /* Send the packet */
    silc_server_packet_send_srcdest(server, sock,
				    SILC_PACKET_CHANNEL_MESSAGE, 0,
				    sender_id, sender_type,
				    channel->id, SILC_ID_CHANNEL,
				    data, data_len);
  }

  silc_hash_table_list_reset(&htl);
  silc_free(routed);
}

/* This function is used to send packets strictly to all local clients
   on a particular channel.  This is used for example to distribute new
   channel key to all our locally connected clients on the channel.
   The packets are always encrypted with the session key shared between
   the client, this means these are not _to the channel_ but _to the client_
   on the channel. */

void silc_server_packet_send_local_channel(SilcServer server,
					   SilcChannelEntry channel,
					   SilcPacketType type,
					   SilcPacketFlags flags,
					   unsigned char *data,
					   SilcUInt32 data_len)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcPacketStream sock = NULL;

  SILC_LOG_DEBUG(("Send packet to local clients on channel %s",
		  channel->channel_name));

  /* Send the message to clients on the channel's client list. */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    if (chl->client && SILC_IS_LOCAL(chl->client)) {
      sock = chl->client->connection;

      /* Send the packet to the client */
      silc_server_packet_send_dest(server, sock, type, flags, chl->client->id,
				   SILC_ID_CLIENT, data, data_len);
    }
  }
  silc_hash_table_list_reset(&htl);
}

/* Sends current motd to client */

void silc_server_send_motd(SilcServer server,
			   SilcPacketStream sock)
{
  char *motd, *motd_file = NULL;
  SilcUInt32 motd_len;

  if (server->config)
    motd_file = server->config->server_info->motd_file;

  if (motd_file) {
    motd = silc_file_readfile(motd_file, &motd_len);
    if (!motd)
      return;

    motd[motd_len] = 0;
    silc_server_send_notify(server, sock, FALSE, SILC_NOTIFY_TYPE_MOTD, 1,
			    motd, motd_len);
    silc_free(motd);
  }
}

/* Sends error message. Error messages may or may not have any
   implications. */

void silc_server_send_error(SilcServer server,
			    SilcPacketStream sock,
			    const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
  va_end(ap);

  silc_server_packet_send(server, sock, SILC_PACKET_ERROR, 0,
			  buf, strlen(buf));
}

/* Sends notify message. If format is TRUE the variable arguments are
   formatted and the formatted string is sent as argument payload. If it is
   FALSE then each argument is sent as separate argument and their format
   in the argument list must be { argument data, argument length }. */

void silc_server_send_notify(SilcServer server,
			     SilcPacketStream sock,
			     SilcBool broadcast,
			     SilcNotifyType type,
			     SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  if (!packet) {
    va_end(ap);
    return;
  }
  silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY,
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			  packet->data, silc_buffer_len(packet));

  /* Send to backup routers if this is being broadcasted to primary
     router.  The silc_server_backup_send checks further whether to
     actually send it or not. */
  if ((broadcast && sock && sock == SILC_PRIMARY_ROUTE(server)) ||
      (broadcast && !sock && !SILC_PRIMARY_ROUTE(server)))
    silc_server_backup_send(server, NULL, SILC_PACKET_NOTIFY, 0,
			    packet->data, silc_buffer_len(packet),
			    FALSE, TRUE);

  silc_buffer_free(packet);
  va_end(ap);
}

/* Sends notify message and gets the arguments from the `args' Argument
   Payloads. */

void silc_server_send_notify_args(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  SilcNotifyType type,
				  SilcUInt32 argc,
				  SilcBuffer args)
{
  SilcBuffer packet;

  packet = silc_notify_payload_encode_args(type, argc, args);
  if (packet)
    silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY,
			    broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			    packet->data, silc_buffer_len(packet));
  silc_buffer_free(packet);
}

/* Send CHANNEL_CHANGE notify type. This tells the receiver to replace the
   `old_id' with the `new_id'. */

void silc_server_send_notify_channel_change(SilcServer server,
					    SilcPacketStream sock,
					    SilcBool broadcast,
					    SilcChannelID *old_id,
					    SilcChannelID *new_id)
{
  SilcBuffer idp1, idp2;

  idp1 = silc_id_payload_encode((void *)old_id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode((void *)new_id, SILC_ID_CHANNEL);

  if (idp1 && idp2)
    silc_server_send_notify(server, sock, broadcast,
			    SILC_NOTIFY_TYPE_CHANNEL_CHANGE,
			    2, idp1->data, silc_buffer_len(idp1),
			    idp2->data, silc_buffer_len(idp2));
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Send NICK_CHANGE notify type. This tells the receiver to replace the
   `old_id' with the `new_id'. */

void silc_server_send_notify_nick_change(SilcServer server,
					 SilcPacketStream sock,
					 SilcBool broadcast,
					 SilcClientID *old_id,
					 SilcClientID *new_id,
					 const char *nickname)
{
  SilcBuffer idp1, idp2;

  idp1 = silc_id_payload_encode((void *)old_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode((void *)new_id, SILC_ID_CLIENT);

  if (idp1 && idp2)
    silc_server_send_notify(server, sock, broadcast,
			    SILC_NOTIFY_TYPE_NICK_CHANGE,
			    3, idp1->data, silc_buffer_len(idp1),
			    idp2->data, silc_buffer_len(idp2),
			    nickname, nickname ? strlen(nickname) : 0);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends JOIN notify type. This tells that new client by `client_id' ID
   has joined to the `channel'. */

void silc_server_send_notify_join(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  SilcChannelEntry channel,
				  SilcClientID *client_id)
{
  SilcBuffer idp1, idp2;

  idp1 = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);

  if (idp1 && idp2)
    silc_server_send_notify(server, sock, broadcast, SILC_NOTIFY_TYPE_JOIN,
			    2, idp1->data, silc_buffer_len(idp1),
			    idp2->data, silc_buffer_len(idp2));
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends LEAVE notify type. This tells that `client_id' has left the
   `channel'. The Notify packet is always destined to the channel. */

void silc_server_send_notify_leave(SilcServer server,
				   SilcPacketStream sock,
				   SilcBool broadcast,
				   SilcChannelEntry channel,
				   SilcClientID *client_id)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  if (idp)
    silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
				 SILC_ID_CHANNEL, SILC_NOTIFY_TYPE_LEAVE,
				 1, idp->data, silc_buffer_len(idp));
  silc_buffer_free(idp);
}

/* Sends CMODE_CHANGE notify type. This tells that `client_id' changed the
   `channel' mode to `mode. The Notify packet is always destined to
   the channel. */

void silc_server_send_notify_cmode(SilcServer server,
				   SilcPacketStream sock,
				   SilcBool broadcast,
				   SilcChannelEntry channel,
				   SilcUInt32 mode_mask,
				   void *id, SilcIdType id_type,
				   const char *cipher, const char *hmac,
				   const char *passphrase,
				   SilcPublicKey founder_key,
				   SilcBuffer channel_pubkeys)
{
  SilcBuffer idp, fkey = NULL;
  unsigned char mode[4], ulimit[4];

  idp = silc_id_payload_encode((void *)id, id_type);
  if (!idp)
    return;
  SILC_PUT32_MSB(mode_mask, mode);
  if (founder_key)
    fkey = silc_public_key_payload_encode(founder_key);
  if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
    SILC_PUT32_MSB(channel->user_limit, ulimit);

  silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
			       SILC_ID_CHANNEL, SILC_NOTIFY_TYPE_CMODE_CHANGE,
			       8, idp->data, silc_buffer_len(idp),
			       mode, 4,
			       cipher, cipher ? strlen(cipher) : 0,
			       hmac, hmac ? strlen(hmac) : 0,
			       passphrase, passphrase ?
			       strlen(passphrase) : 0,
			       fkey ? fkey->data : NULL,
			       fkey ? silc_buffer_len(fkey) : 0,
			       channel_pubkeys ? channel_pubkeys->data : NULL,
			       channel_pubkeys ?
			       silc_buffer_len(channel_pubkeys) : 0,
			       mode_mask & SILC_CHANNEL_MODE_ULIMIT ?
			       ulimit : NULL,
			       mode_mask & SILC_CHANNEL_MODE_ULIMIT ?
			       sizeof(ulimit) : 0);
  silc_buffer_free(fkey);
  silc_buffer_free(idp);
}

/* Sends CUMODE_CHANGE notify type. This tells that `id' changed the
   `target' client's mode on `channel'. The notify packet is always
   destined to the channel. */

void silc_server_send_notify_cumode(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcChannelEntry channel,
				    SilcUInt32 mode_mask,
				    void *id, SilcIdType id_type,
				    SilcClientID *target,
				    SilcPublicKey founder_key)
{
  SilcBuffer idp1, idp2, fkey = NULL;
  unsigned char mode[4];

  idp1 = silc_id_payload_encode((void *)id, id_type);
  idp2 = silc_id_payload_encode((void *)target, SILC_ID_CLIENT);
  if (!idp1 || !idp2)
    return;
  SILC_PUT32_MSB(mode_mask, mode);
  if (founder_key)
    fkey = silc_public_key_payload_encode(founder_key);

  silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
			       SILC_ID_CHANNEL,
			       SILC_NOTIFY_TYPE_CUMODE_CHANGE, 4,
			       idp1->data, silc_buffer_len(idp1),
			       mode, 4,
			       idp2->data, silc_buffer_len(idp2),
			       fkey ? fkey->data : NULL,
			       fkey ? silc_buffer_len(fkey) : 0);
  silc_buffer_free(fkey);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends SIGNOFF notify type. This tells that `client_id' client has
   left SILC network. This function is used only between server and router
   traffic. This is not used to send the notify to the channel for
   client. The `message may be NULL. */

void silc_server_send_notify_signoff(SilcServer server,
				     SilcPacketStream sock,
				     SilcBool broadcast,
				     SilcClientID *client_id,
				     const char *message)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  if (idp)
    silc_server_send_notify(server, sock, broadcast,
			    SILC_NOTIFY_TYPE_SIGNOFF,
			    message ? 2 : 1, idp->data, silc_buffer_len(idp),
			    message, message ? strlen(message): 0);
  silc_buffer_free(idp);
}

/* Sends TOPIC_SET notify type. This tells that `id' changed
   the `channel's topic to `topic'. The Notify packet is always destined
   to the channel. This function is used to send the topic set notifies
   between routers. */

void silc_server_send_notify_topic_set(SilcServer server,
				       SilcPacketStream sock,
				       SilcBool broadcast,
				       SilcChannelEntry channel,
				       void *id, SilcIdType id_type,
				       char *topic)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode(id, id_type);
  if (idp)
    silc_server_send_notify_dest(server, sock, broadcast,
				 (void *)channel->id, SILC_ID_CHANNEL,
				 SILC_NOTIFY_TYPE_TOPIC_SET,
				 topic ? 2 : 1,
				 idp->data, silc_buffer_len(idp),
				 topic, topic ? strlen(topic) : 0);
  silc_buffer_free(idp);
}

/* Send KICKED notify type. This tells that the `client_id' on `channel'
   was kicked off the channel.  The `comment' may indicate the reason
   for the kicking. This function is used only between server and router
   traffic. */

void silc_server_send_notify_kicked(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    SilcClientID *kicker,
				    char *comment)
{
  SilcBuffer idp1;
  SilcBuffer idp2;

  idp1 = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode((void *)kicker, SILC_ID_CLIENT);

  if (idp1 && idp2)
    silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
				 SILC_ID_CHANNEL, SILC_NOTIFY_TYPE_KICKED, 3,
				 idp1->data, silc_buffer_len(idp1),
				 comment, comment ? strlen(comment) : 0,
				 idp2->data, silc_buffer_len(idp2));
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Send KILLED notify type. This tells that the `client_id' client was
   killed from the network.  The `comment' may indicate the reason
   for the killing. */

void silc_server_send_notify_killed(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcClientID *client_id,
				    const char *comment,
				    void *killer, SilcIdType killer_type)
{
  SilcBuffer idp1;
  SilcBuffer idp2;

  idp1 = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode(killer, killer_type);

  if (idp1 && idp2)
    silc_server_send_notify_dest(server, sock, broadcast, (void *)client_id,
				 SILC_ID_CLIENT, SILC_NOTIFY_TYPE_KILLED,
				 3, idp1->data, silc_buffer_len(idp1),
				 comment, comment ? strlen(comment) : 0,
				 idp2->data, silc_buffer_len(idp2));
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends UMODE_CHANGE notify type. This tells that `client_id' client's
   user mode in the SILC Network was changed. This function is used to
   send the packet between routers as broadcast packet. */

void silc_server_send_notify_umode(SilcServer server,
				   SilcPacketStream sock,
				   SilcBool broadcast,
				   SilcClientID *client_id,
				   SilcUInt32 mode_mask)
{
  SilcBuffer idp;
  unsigned char mode[4];

  idp = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  SILC_PUT32_MSB(mode_mask, mode);

  if (idp)
    silc_server_send_notify(server, sock, broadcast,
			    SILC_NOTIFY_TYPE_UMODE_CHANGE, 2,
			    idp->data, silc_buffer_len(idp),
			    mode, 4);
  silc_buffer_free(idp);
}

/* Sends BAN notify type. This tells that ban has been either `add'ed
   or `del'eted on the `channel. This function is used to send the packet
   between routers as broadcast packet. */

void silc_server_send_notify_ban(SilcServer server,
				 SilcPacketStream sock,
				 SilcBool broadcast,
				 SilcChannelEntry channel,
				 unsigned char *action,
				 SilcBuffer list)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);

  if (idp)
    silc_server_send_notify(server, sock, broadcast,
			    SILC_NOTIFY_TYPE_BAN, 3,
			    idp->data, silc_buffer_len(idp),
			    action ? action : NULL, action ? 1 : 0,
			    list ? list->data : NULL,
			    list ? silc_buffer_len(list) : 0);
  silc_buffer_free(idp);
}

/* Sends INVITE notify type. This tells that invite has been either `add'ed
   or `del'eted on the `channel.  The sender of the invite is the `client_id'.
   This function is used to send the packet between routers as broadcast
   packet. */

void silc_server_send_notify_invite(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    unsigned char *action,
				    SilcBuffer list)
{
  SilcBuffer idp, idp2;

  idp = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);

  if (idp && idp2)
    silc_server_send_notify(server, sock, broadcast,
			    SILC_NOTIFY_TYPE_INVITE, 5,
			    idp->data, silc_buffer_len(idp),
			    channel->channel_name,
			    strlen(channel->channel_name),
			    idp2->data, silc_buffer_len(idp2),
			    action ? action : NULL, action ? 1 : 0,
			    list ? list->data : NULL,
			    list ? silc_buffer_len(list) : 0);
  silc_buffer_free(idp);
  silc_buffer_free(idp2);
}

/* Sends WATCH notify type. This tells that the `client' was watched and
   its status in the network has changed. */

void silc_server_send_notify_watch(SilcServer server,
				   SilcPacketStream sock,
				   SilcClientEntry watcher,
				   SilcClientEntry client,
				   const char *nickname,
				   SilcNotifyType type,
				   SilcPublicKey public_key)
{
  SilcBuffer idp, pkp = NULL;
  unsigned char mode[4], n[2];

  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  if (!idp)
    return;
  SILC_PUT16_MSB(type, n);
  SILC_PUT32_MSB(client->mode, mode);
  if (public_key)
    pkp = silc_public_key_payload_encode(public_key);
  silc_server_send_notify_dest(server, sock, FALSE, watcher->id,
			       SILC_ID_CLIENT, SILC_NOTIFY_TYPE_WATCH,
			       5, idp->data, silc_buffer_len(idp),
			       nickname, nickname ? strlen(nickname) : 0,
			       mode, sizeof(mode),
			       type != SILC_NOTIFY_TYPE_NONE ?
			       n : NULL, sizeof(n),
			       pkp ? pkp->data : NULL,
			       pkp ? silc_buffer_len(pkp) : 0);
  silc_buffer_free(idp);
  silc_buffer_free(pkp);
}

/* Sends notify message destined to specific entity. */

void silc_server_send_notify_dest(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  if (!packet) {
    va_end(ap);
    return;
  }
  silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY,
			       broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			       dest_id, dest_id_type,
			       packet->data, silc_buffer_len(packet));

  /* Send to backup routers if this is being broadcasted to primary
     router.  The silc_server_backup_send checks further whether to
     actually send it or not. */
  if ((broadcast && sock && sock == SILC_PRIMARY_ROUTE(server)) ||
      (broadcast && !sock && !SILC_PRIMARY_ROUTE(server)))
    silc_server_backup_send_dest(server, NULL, SILC_PACKET_NOTIFY, 0,
				 dest_id, dest_id_type,
				 packet->data, silc_buffer_len(packet),
				 FALSE, TRUE);

  silc_buffer_free(packet);
  va_end(ap);
}

/* Sends notify message to a channel. The notify message sent is
   distributed to all clients on the channel. If `route_notify' is TRUE
   then the notify may be routed to primary route or to some other routers.
   If FALSE it is assured that the notify is sent only locally. If `sender'
   is provided then the packet is not sent to that connection since it
   originally came from it. */

void silc_server_send_notify_to_channel(SilcServer server,
					SilcPacketStream sender,
					SilcChannelEntry channel,
					SilcBool route_notify,
					SilcBool send_to_clients,
					SilcNotifyType type,
					SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  if (packet)
    silc_server_packet_send_to_channel(server, sender, channel,
				       SILC_PACKET_NOTIFY, route_notify,
				       send_to_clients,
				       packet->data, silc_buffer_len(packet));
  silc_buffer_free(packet);
  va_end(ap);
}

/* Send notify message to all channels the client has joined. It is quaranteed
   that the message is sent only once to a client (ie. if a client is joined
   on two same channel it will receive only one notify message). Also, this
   sends only to local clients (locally connected if we are server, and to
   local servers if we are router). If `sender' is provided the packet is
   not sent to that client at all. */

void silc_server_send_notify_on_channels(SilcServer server,
					 SilcClientEntry sender,
					 SilcClientEntry client,
					 SilcNotifyType type,
					 SilcUInt32 argc, ...)
{
  int k;
  SilcPacketStream sock = NULL;
  SilcClientEntry c;
  SilcClientEntry *sent_clients = NULL;
  SilcUInt32 sent_clients_count = 0;
  SilcServerEntry *routed = NULL;
  SilcUInt32 routed_count = 0;
  SilcHashTableList htl, htl2;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl, chl2;
  SilcBuffer packet;
  unsigned char *data;
  SilcUInt32 data_len;
  va_list ap;

  if (!silc_hash_table_count(client->channels)) {
    SILC_LOG_DEBUG(("Client is not joined to any channels"));
    return;
  }

  SILC_LOG_DEBUG(("Sending notify to joined channels"));

  va_start(ap, argc);
  packet = silc_notify_payload_encode(type, argc, ap);
  if (!packet) {
    va_end(ap);
    return;
  }
  data = packet->data;
  data_len = silc_buffer_len(packet);

  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
    channel = chl->channel;

    /* Send the message to all clients on the channel's client list. */
    silc_hash_table_list(channel->user_list, &htl2);
    while (silc_hash_table_get(&htl2, NULL, (void *)&chl2)) {
      c = chl2->client;

      if (sender && c == sender)
	continue;

      /* Check if we have sent the packet to this client already */
      for (k = 0; k < sent_clients_count; k++)
	if (sent_clients[k] == c)
	  break;
      if (k < sent_clients_count)
	continue;

      /* If we are router and if this client has router set it is not
	 locally connected client and we will route the message to the
	 router set in the client. */
      if (c && c->router && server->server_type == SILC_ROUTER) {
	/* Check if we have sent the packet to this route already */
	for (k = 0; k < routed_count; k++)
	  if (routed[k] == c->router)
	    break;
	if (k < routed_count)
	  continue;

	sock = c->router->connection;

	/* Send the packet */
	silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY, 0,
				     c->router->id, SILC_ID_SERVER,
				     data, data_len);

	/* We want to make sure that the packet is routed to same router
	   only once. Mark this route as sent route. */
	routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
	routed[routed_count++] = c->router;
	continue;
      }

      if (c && c->router)
	continue;

      /* Send to locally connected client */
      if (c) {
	sock = c->connection;
        if (!sock)
          continue;

	/* Send the packet */
	silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY, 0,
				     c->id, SILC_ID_CLIENT, data, data_len);

	/* Make sure that we send the notify only once per client. */
	sent_clients = silc_realloc(sent_clients, sizeof(*sent_clients) *
				    (sent_clients_count + 1));
	sent_clients[sent_clients_count++] = c;
      }
    }
    silc_hash_table_list_reset(&htl2);
  }

  silc_hash_table_list_reset(&htl);
  silc_free(routed);
  silc_free(sent_clients);
  silc_buffer_free(packet);
  va_end(ap);
}

/* Sends New ID Payload to remote end. The packet is used to distribute
   information about new registered clients, servers, channel etc. usually
   to routers so that they can keep these information up to date.
   If the argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */

void silc_server_send_new_id(SilcServer server,
			     SilcPacketStream sock,
			     SilcBool broadcast,
			     void *id, SilcIdType id_type,
			     SilcUInt32 id_len)
{
  SilcBuffer idp;

  SILC_LOG_DEBUG(("Sending new ID"));

  idp = silc_id_payload_encode(id, id_type);
  if (idp)
    silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID,
			    broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			    idp->data, silc_buffer_len(idp));
  silc_buffer_free(idp);
}

/* Send New Channel Payload to notify about newly created channel in the
   SILC network. Router uses this to notify other routers in the network
   about new channel. This packet is broadcasted by router. */

void silc_server_send_new_channel(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  char *channel_name,
				  void *channel_id,
				  SilcUInt32 channel_id_len,
				  SilcUInt32 mode)
{
  SilcBuffer packet;
  unsigned char cid[32];
  SilcUInt32 name_len = strlen(channel_name);

  SILC_LOG_DEBUG(("Sending new channel"));

  if (!silc_id_id2str(channel_id, SILC_ID_CHANNEL, cid, sizeof(cid),
		      &channel_id_len))
    return;

  /* Encode the channel payload */
  packet = silc_channel_payload_encode(channel_name, name_len,
				       cid, channel_id_len, mode);
  if (packet)
    silc_server_packet_send(server, sock, SILC_PACKET_NEW_CHANNEL,
			    broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			    packet->data, silc_buffer_len(packet));

  silc_buffer_free(packet);
}

/* Send Channel Key payload to distribute the new channel key. Normal server
   sends this to router when new client joins to existing channel. Router
   sends this to the local server who sent the join command in case where
   the channel did not exist yet. Both normal and router servers uses this
   also to send this to locally connected clients on the channel. This
   must not be broadcasted packet. Routers do not send this to each other.
   If `sender is provided then the packet is not sent to that connection since
   it originally came from it. */

void silc_server_send_channel_key(SilcServer server,
				  SilcPacketStream sender,
				  SilcChannelEntry channel,
				  unsigned char route)
{
  SilcBuffer packet;
  unsigned char cid[32];
  SilcUInt32 tmp_len, cid_len;
  const char *cipher;

  SILC_LOG_DEBUG(("Sending key to channel %s", channel->channel_name));

  if (!channel->key)
    return;

  if (!silc_id_id2str(channel->id, SILC_ID_CHANNEL, cid, sizeof(cid),
		      &cid_len))
    return;

  /* Encode channel key packet */
  cipher = silc_cipher_get_name(channel->send_key);
  tmp_len = strlen(cipher);
  packet = silc_channel_key_payload_encode(cid_len, cid, tmp_len, cipher,
                                           channel->key_len / 8, channel->key);
  if (packet)
    silc_server_packet_send_to_channel(server, sender, channel,
				       SILC_PACKET_CHANNEL_KEY,
                                       route, TRUE, packet->data,
				       silc_buffer_len(packet));
  silc_buffer_free(packet);
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form in correct order. */

void silc_server_send_command(SilcServer server,
			      SilcPacketStream sock,
			      SilcCommand command,
			      SilcUInt16 ident,
			      SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  /* Statistics */
  server->stat.commands_sent++;

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, ident, argc, ap);
  if (packet)
    silc_server_packet_send(server, sock, SILC_PACKET_COMMAND, 0,
			    packet->data, silc_buffer_len(packet));
  silc_buffer_free(packet);
  va_end(ap);
}

/* Generic function to send any command reply. The arguments must be sent
   already encoded into correct form in correct order. */

void silc_server_send_command_reply(SilcServer server,
				    SilcPacketStream sock,
				    SilcCommand command,
				    SilcStatus status,
				    SilcStatus error,
				    SilcUInt16 ident,
				    SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  /* Statistics */
  server->stat.commands_sent++;

  va_start(ap, argc);

  packet = silc_command_reply_payload_encode_vap(command, status, error,
						 ident, argc, ap);
  if (packet)
    silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0,
			    packet->data, silc_buffer_len(packet));
  silc_buffer_free(packet);
  va_end(ap);
}

/* Generic function to send any command reply. The arguments must be sent
   already encoded into correct form in correct order. */

void silc_server_send_dest_command_reply(SilcServer server,
					 SilcPacketStream sock,
					 void *dst_id,
					 SilcIdType dst_id_type,
					 SilcCommand command,
					 SilcStatus status,
					 SilcStatus error,
					 SilcUInt16 ident,
					 SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  /* Statistics */
  server->stat.commands_sent++;

  va_start(ap, argc);

  packet = silc_command_reply_payload_encode_vap(command, status, error,
						 ident, argc, ap);
  if (packet)
    silc_server_packet_send_dest(server, sock, SILC_PACKET_COMMAND_REPLY, 0,
				 dst_id, dst_id_type, packet->data,
				 silc_buffer_len(packet));
  silc_buffer_free(packet);
  va_end(ap);
}

/* Send the heartbeat packet. */

void silc_server_send_heartbeat(SilcServer server,
				SilcPacketStream sock)
{
  silc_server_packet_send(server, sock, SILC_PACKET_HEARTBEAT, 0,
			  NULL, 0);
}

/* Routine used to send the connection authentication packet. */

void silc_server_send_connection_auth_request(SilcServer server,
					      SilcPacketStream sock,
					      SilcUInt16 conn_type,
					      SilcAuthMethod auth_meth)
{
  SilcBuffer packet;

  packet = silc_buffer_alloc(4);
  if (!packet)
    return;

  silc_buffer_pull_tail(packet, silc_buffer_truelen(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(conn_type),
		     SILC_STR_UI_SHORT(auth_meth),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_CONNECTION_AUTH_REQUEST,
			  0, packet->data, silc_buffer_len(packet));
  silc_buffer_free(packet);
}

/* Send packet to clients that are known to be operators.  If server
   is router and `route' is TRUE then the packet would go to all operators
   in the SILC network.  If `route' is FALSE then only local operators
   (local for server and cell wide for router).  If `local' is TRUE then
   only locally connected operators receive the packet.  If `local' is
   TRUE then `route' is ignored.  If server is normal server and `route'
   is FALSE it is equivalent to `local' being TRUE. */

void silc_server_send_opers(SilcServer server,
			    SilcPacketType type,
			    SilcPacketFlags flags,
			    SilcBool route, bool local,
			    unsigned char *data,
			    SilcUInt32 data_len)
{
  SilcList list;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  SilcIDListData idata;
  SilcPacketStream sock;
  SilcServerEntry *routed = NULL;
  SilcUInt32 routed_count = 0;
  SilcBool gone = FALSE;
  int k;

  SILC_LOG_DEBUG(("Sending %s packet to operators",
		  silc_get_packet_name(type)));

  /* If local was requested send only locally connected operators. */
  if (local || (server->server_type == SILC_SERVER && !route)) {
    if (!silc_idcache_get_all(server->local_list->clients, &list))
      return;
    silc_list_start(list);
    while ((id_cache = silc_list_get(list))) {
      client = (SilcClientEntry)id_cache->context;
      if (!client->router && SILC_IS_LOCAL(client) &&
	  (client->mode & SILC_UMODE_SERVER_OPERATOR ||
	   client->mode & SILC_UMODE_ROUTER_OPERATOR)) {

	/* Send the packet to locally connected operator */
	silc_server_packet_send_dest(server, client->connection, type, flags,
				     client->id, SILC_ID_CLIENT,
				     data, data_len);
      }
    }
    return;
  }

  if (!silc_idcache_get_all(server->local_list->clients, &list))
    return;
  silc_list_start(list);
  while ((id_cache = silc_list_get(list))) {
    client = (SilcClientEntry)id_cache->context;
    if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
	!(client->mode & SILC_UMODE_ROUTER_OPERATOR))
      continue;

    if (server->server_type != SILC_SERVER && client->router &&
	((!route && client->router->router == server->id_entry) || route)) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Route only once to router */
      sock = client->router->connection;
      idata = silc_packet_get_context(sock);
      if (idata->conn_type == SILC_CONN_ROUTER) {
	if (gone)
	  continue;
	gone = TRUE;
      }

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, flags,
				   client->id, SILC_ID_CLIENT,
				   data, data_len);

      /* Mark this route routed already */
      routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
      routed[routed_count++] = client->router;
      continue;
    }

    if (client->router || !client->connection)
      continue;

    /* Send to locally connected client */
    sock = client->connection;
    silc_server_packet_send_dest(server, sock, type, flags,
				 client->id, SILC_ID_CLIENT,
				 data, data_len);

  }

  if (!silc_idcache_get_all(server->global_list->clients, &list))
    return;
  silc_list_start(list);
  while ((id_cache = silc_list_get(list))) {
    client = (SilcClientEntry)id_cache->context;
    if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
	!(client->mode & SILC_UMODE_ROUTER_OPERATOR))
      continue;

    if (server->server_type != SILC_SERVER && client->router &&
	((!route && client->router->router == server->id_entry) || route)) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Route only once to router */
      sock = client->router->connection;
      idata = silc_packet_get_context(sock);
      if (idata->conn_type == SILC_CONN_ROUTER) {
	if (gone)
	  continue;
	gone = TRUE;
      }

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, flags,
				   client->id, SILC_ID_CLIENT,
				   data, data_len);

      /* Mark this route routed already */
      routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
      routed[routed_count++] = client->router;
      continue;
    }

    if (client->router || !client->connection)
      continue;

    /* Send to locally connected client */
    sock = client->connection;
    silc_server_packet_send_dest(server, sock, type, flags,
				 client->id, SILC_ID_CLIENT,
				 data, data_len);
  }
  silc_free(routed);
}

/* Send a notify packet to operators */

void silc_server_send_opers_notify(SilcServer server,
				   SilcBool route,
				   SilcBool local,
				   SilcNotifyType type,
				   SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);
  packet = silc_notify_payload_encode(type, argc, ap);
  if (packet)
    silc_server_send_opers(server, SILC_PACKET_NOTIFY, 0,
			   route, local, packet->data, silc_buffer_len(packet));
  silc_buffer_free(packet);
  va_end(ap);
}
