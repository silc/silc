/*

  packet_send.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Server packet routines to send packets. 
 */
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

/* Routine that sends packet or marks packet to be sent. This is used
   directly only in special cases. Normal cases should use
   silc_server_packet_send. Returns < 0 error. */

int silc_server_packet_send_real(SilcServer server,
				 SilcSocketConnection sock,
				 bool force_send)
{
  int ret;

  /* If disconnecting, ignore the data */
  if (SILC_IS_DISCONNECTING(sock))
    return -1;

  /* If rekey protocol is active we must assure that all packets are
     sent through packet queue. */
  if (SILC_SERVER_IS_REKEY(sock))
    force_send = FALSE;

  /* If outbound data is already pending do not force send */
  if (SILC_IS_OUTBUF_PENDING(sock))
    force_send = FALSE;

  /* Send the packet */
  ret = silc_packet_send(sock, force_send);
  if (ret != -2) {
    server->stat.packets_sent++;
    return ret;
  }

  /* Mark that there is some outgoing data available for this connection. 
     This call sets the connection both for input and output (the input
     is set always and this call keeps the input setting, actually). 
     Actual data sending is performed by silc_server_packet_process. */
  SILC_SET_CONNECTION_FOR_OUTPUT(server->schedule, sock->sock);

  /* Mark to socket that data is pending in outgoing buffer. This flag
     is needed if new data is added to the buffer before the earlier
     put data is sent to the network. */
  SILC_SET_OUTBUF_PENDING(sock);

  return 0;
}

/* Assembles a new packet to be sent out to network. This doesn't actually
   send the packet but creates the packet and fills the outgoing data
   buffer and marks the packet ready to be sent to network. However, If 
   argument force_send is TRUE the packet is sent immediately and not put 
   to queue. Normal case is that the packet is not sent immediately. */

void silc_server_packet_send(SilcServer server,
			     SilcSocketConnection sock, 
			     SilcPacketType type, 
			     SilcPacketFlags flags,
			     unsigned char *data, 
			     SilcUInt32 data_len,
			     bool force_send)
{
  void *dst_id = NULL;
  SilcIdType dst_id_type = SILC_ID_NONE;
  SilcIDListData idata;

  if (!sock)
    return;

  idata = (SilcIDListData)sock->user_data;

  /* If disconnecting, ignore the data */
  if (SILC_IS_DISCONNECTING(sock))
    return;

  /* If entry is disabled do not sent anything. */
  if (idata && idata->status & SILC_IDLIST_STATUS_DISABLED) {
    SILC_LOG_DEBUG(("Connection is disabled"));
    return;
  }

  /* Get data used in the packet sending, keys and stuff */
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    if (sock->user_data) {
      dst_id = ((SilcClientEntry)sock->user_data)->id;
      dst_id_type = SILC_ID_CLIENT;
    }
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    if (sock->user_data) {
      dst_id = ((SilcServerEntry)sock->user_data)->id;
      dst_id_type = SILC_ID_SERVER;
    }
    break;
  default:
    break;
  }

  silc_server_packet_send_dest(server, sock, type, flags, dst_id,
			       dst_id_type, data, data_len, force_send);
}

/* Assembles a new packet to be sent out to network. This doesn't actually
   send the packet but creates the packet and fills the outgoing data
   buffer and marks the packet ready to be sent to network. However, If 
   argument force_send is TRUE the packet is sent immediately and not put 
   to queue. Normal case is that the packet is not sent immediately. 
   Destination information is sent as argument for this function. */

void silc_server_packet_send_dest(SilcServer server,
				  SilcSocketConnection sock, 
				  SilcPacketType type, 
				  SilcPacketFlags flags,
				  void *dst_id,
				  SilcIdType dst_id_type,
				  unsigned char *data, 
				  SilcUInt32 data_len,
				  bool force_send)
{
  SilcPacketContext packetdata;
  const SilcBufferStruct packet;
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  SilcUInt32 sequence = 0;
  unsigned char *dst_id_data = NULL;
  SilcUInt32 dst_id_len = 0;
  int block_len = 0;

  /* If disconnecting, ignore the data */
  if (!sock || SILC_IS_DISCONNECTING(sock))
    return;

  idata = (SilcIDListData)sock->user_data;

  /* If entry is disabled do not sent anything. */
  if (idata && idata->status & SILC_IDLIST_STATUS_DISABLED) {
    SILC_LOG_DEBUG(("Connection is disabled"));
    return;
  }

  SILC_LOG_DEBUG(("Sending %s packet", silc_get_packet_name(type)));

  if (dst_id) {
    dst_id_data = silc_id_id2str(dst_id, dst_id_type);
    dst_id_len = silc_id_get_len(dst_id, dst_id_type);
  }

  if (idata) {
    cipher = idata->send_key;
    hmac = idata->hmac_send;
    sequence = idata->psn_send++;
    block_len = silc_cipher_get_block_len(cipher);
  }

  /* Set the packet context pointers */
  packetdata.type = type;
  packetdata.flags = flags;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = silc_id_get_len(server->id, SILC_ID_SERVER);
  packetdata.src_id_type = SILC_ID_SERVER;
  packetdata.dst_id = dst_id_data;
  packetdata.dst_id_len = dst_id_len;
  packetdata.dst_id_type = dst_id_type;
  data_len = SILC_PACKET_DATALEN(data_len, (SILC_PACKET_HEADER_LEN +
					    packetdata.src_id_len + 
					    packetdata.dst_id_len));
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen, block_len);

  /* Create the outgoing packet */
  if (!silc_packet_assemble(&packetdata, NULL, cipher, hmac, sock,
                            data, data_len, (const SilcBuffer)&packet)) {
    SILC_LOG_ERROR(("Cannot assemble packet"));
    goto out;
  }

  /* Encrypt the packet */
  silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&packet, packet.len);

  SILC_LOG_HEXDUMP(("Outgoing packet (%d), len %d", sequence, packet.len),
		   packet.data, packet.len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);

 out:
  if (packetdata.src_id)
    silc_free(packetdata.src_id);
  if (packetdata.dst_id)
    silc_free(packetdata.dst_id);
}

/* Assembles a new packet to be sent out to network. This doesn't actually
   send the packet but creates the packet and fills the outgoing data
   buffer and marks the packet ready to be sent to network. However, If 
   argument force_send is TRUE the packet is sent immediately and not put 
   to queue. Normal case is that the packet is not sent immediately. 
   The source and destination information is sent as argument for this
   function. */

void silc_server_packet_send_srcdest(SilcServer server,
				     SilcSocketConnection sock, 
				     SilcPacketType type, 
				     SilcPacketFlags flags,
				     void *src_id,
				     SilcIdType src_id_type,
				     void *dst_id,
				     SilcIdType dst_id_type,
				     unsigned char *data, 
				     SilcUInt32 data_len,
				     bool force_send)
{
  SilcPacketContext packetdata;
  const SilcBufferStruct packet;
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  SilcUInt32 sequence = 0;
  unsigned char *dst_id_data = NULL;
  SilcUInt32 dst_id_len = 0;
  unsigned char *src_id_data = NULL;
  SilcUInt32 src_id_len = 0;
  int block_len = 0;

  SILC_LOG_DEBUG(("Sending %s packet", silc_get_packet_name(type)));

  if (!sock)
    return;

  /* Get data used in the packet sending, keys and stuff */
  idata = (SilcIDListData)sock->user_data;

  if (dst_id) {
    dst_id_data = silc_id_id2str(dst_id, dst_id_type);
    dst_id_len = silc_id_get_len(dst_id, dst_id_type);
  }

  if (src_id) {
    src_id_data = silc_id_id2str(src_id, src_id_type);
    src_id_len = silc_id_get_len(src_id, src_id_type);
  }

  if (idata) {
    cipher = idata->send_key;
    hmac = idata->hmac_send;
    sequence = idata->psn_send++;
    block_len = silc_cipher_get_block_len(cipher);
  }

  /* Set the packet context pointers */
  packetdata.type = type;
  packetdata.flags = flags;
  packetdata.src_id = src_id_data;
  packetdata.src_id_len = src_id_len;
  packetdata.src_id_type = src_id_type;
  packetdata.dst_id = dst_id_data;
  packetdata.dst_id_len = dst_id_len;
  packetdata.dst_id_type = dst_id_type;
  data_len = SILC_PACKET_DATALEN(data_len, (SILC_PACKET_HEADER_LEN +
					    packetdata.src_id_len + 
					    dst_id_len));
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen, block_len);

  /* Create the outgoing packet */
  if (!silc_packet_assemble(&packetdata, NULL, cipher, hmac, sock, data,
                            data_len, (const SilcBuffer)&packet)) {
    SILC_LOG_ERROR(("Cannot assemble packe"));
    goto out;
  }

  /* Encrypt the packet */
  silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&packet, packet.len);

  SILC_LOG_HEXDUMP(("Outgoing packet (%d), len %d", sequence, packet.len),
                   packet.data, packet.len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);

 out:
  if (packetdata.src_id)
    silc_free(packetdata.src_id);
  if (packetdata.dst_id)
    silc_free(packetdata.dst_id);
}

/* Broadcast received packet to our primary route. This function is used
   by router to further route received broadcast packet. It is expected
   that the broadcast flag from the packet is checked before calling this
   function. This does not test or set the broadcast flag. */

void silc_server_packet_broadcast(SilcServer server,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcIDListData idata;
  void *id;

  if (!sock)
    return;

  SILC_LOG_DEBUG(("Broadcasting received broadcast packet"));

  /* If the packet is originated from our primary route we are
     not allowed to send the packet. */
  id = silc_id_str2id(packet->src_id, packet->src_id_len, packet->src_id_type);
  if (id && !SILC_ID_SERVER_COMPARE(id, server->router->id)) {
    const SilcBufferStruct p;

    idata = (SilcIDListData)sock->user_data;

    silc_buffer_push(buffer, buffer->data - buffer->head);
    if (!silc_packet_send_prepare(sock, 0, 0, buffer->len, idata->hmac_send,
                                  (const SilcBuffer)&p)) {
      SILC_LOG_ERROR(("Cannot send packet"));
      silc_free(id);
      return;
    }
    silc_buffer_put((SilcBuffer)&p, buffer->data, buffer->len);
    silc_packet_encrypt(idata->send_key, idata->hmac_send, idata->psn_send++,
			(SilcBuffer)&p, p.len);

    SILC_LOG_HEXDUMP(("Broadcasted packet (%d), len %d", idata->psn_send - 1,
		      p.len), p.data, p.len);

    /* Now actually send the packet */
    silc_server_packet_send_real(server, sock, TRUE);
    silc_free(id);
    return;
  }

  SILC_LOG_DEBUG(("Will not broadcast to primary route since it is the "
		  "original sender of this packet"));
  silc_free(id);
}

/* Routes received packet to `sock'. This is used to route the packets that
   router receives but are not destined to it. */

void silc_server_packet_route(SilcServer server,
			      SilcSocketConnection sock,
			      SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  const SilcBufferStruct p;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Routing received packet"));

  idata = (SilcIDListData)sock->user_data;

  silc_buffer_push(buffer, buffer->data - buffer->head);
  if (!silc_packet_send_prepare(sock, 0, 0, buffer->len, idata->hmac_send,
                                (const SilcBuffer)&p)) {
    SILC_LOG_ERROR(("Cannot send packet"));
    return;
  }
  silc_buffer_put((SilcBuffer)&p, buffer->data, buffer->len);
  silc_packet_encrypt(idata->send_key, idata->hmac_send, idata->psn_send++,
		      (SilcBuffer)&p, p.len);

  SILC_LOG_HEXDUMP(("Routed packet (%d), len %d", idata->psn_send - 1, 
		   p.len), p.data, p.len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, TRUE);
}

/* This routine can be used to send a packet to table of clients provided
   in `clients'. If `route' is FALSE the packet is routed only to local
   clients (for server locally connected, and for router local cell). */

void silc_server_packet_send_clients(SilcServer server,
				     SilcHashTable clients,
				     SilcPacketType type, 
				     SilcPacketFlags flags,
				     bool route,
				     unsigned char *data, 
				     SilcUInt32 data_len,
				     bool force_send)
{
  SilcSocketConnection sock = NULL;
  SilcHashTableList htl;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcUInt32 routed_count = 0;
  bool gone = FALSE;
  int k;

  SILC_LOG_DEBUG(("Sending packet to list of clients"));

  /* Send to all clients in table */
  silc_hash_table_list(clients, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&client)) {
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
      sock = (SilcSocketConnection)client->router->connection;
      if (sock->type == SILC_SOCKET_TYPE_ROUTER) {
	if (gone)
	  continue;
	gone = TRUE;
      }

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, flags,
				   client->router->id, SILC_ID_SERVER,
				   data, data_len, force_send);

      /* Mark this route routed already */
      routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
      routed[routed_count++] = client->router;
      continue;
    }

    if (client->router)
      continue;

    /* Send to locally connected client */
    sock = (SilcSocketConnection)client->connection;
    if (!sock)
      continue;

    silc_server_packet_send_dest(server, sock, type, flags,
				 client->id, SILC_ID_CLIENT,
				 data, data_len, force_send);
  }
  silc_hash_table_list_reset(&htl);
  silc_free(routed);
}

/* Internal routine to actually create the channel packet and send it
   to network. This is common function in channel message sending. If
   `channel_message' is TRUE this encrypts the message as it is strictly
   a channel message. If FALSE normal encryption process is used. */

static void
silc_server_packet_send_to_channel_real(SilcServer server,
					SilcSocketConnection sock,
					SilcPacketContext *packet,
					SilcCipher cipher,
					SilcHmac hmac,
					SilcUInt32 sequence,
					unsigned char *data,
					SilcUInt32 data_len,
					bool channel_message,
					bool force_send)
{
  int block_len;
  const SilcBufferStruct p;

  if (!sock)
    return;

  data_len = SILC_PACKET_DATALEN(data_len, (SILC_PACKET_HEADER_LEN +
					    packet->src_id_len + 
					    packet->dst_id_len));
  packet->truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packet->src_id_len + packet->dst_id_len;

  block_len = cipher ? silc_cipher_get_block_len(cipher) : 0;
  if (channel_message)
    packet->padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					 packet->src_id_len +
					 packet->dst_id_len), block_len);
  else
    packet->padlen = SILC_PACKET_PADLEN(packet->truelen, block_len);

  /* Put the data to buffer, assemble and encrypt the packet. The packet
     is encrypted with normal session key shared with the client, unless
     the `channel_message' is TRUE. */
  if (!silc_packet_assemble(packet, NULL, cipher, hmac, sock, data,
                            data_len, (const SilcBuffer)&p)) {
    SILC_LOG_ERROR(("Cannot assemble packet"));
    return;
  }

  if (channel_message)
    silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&p, 
			SILC_PACKET_HEADER_LEN + packet->src_id_len + 
			packet->dst_id_len + packet->padlen);
  else
    silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&p, p.len);
    
  SILC_LOG_HEXDUMP(("Channel packet (%d), len %d", sequence, p.len),
		   p.data, p.len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);
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
					SilcSocketConnection sender,
					SilcChannelEntry channel,
					SilcPacketType type,
					bool route,
					unsigned char *data,
					SilcUInt32 data_len,
					bool force_send)
{
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcIDListData idata;
  SilcUInt32 routed_count = 0;
  bool gone = FALSE;
  int k;

  /* This doesn't send channel message packets */
  assert(type != SILC_PACKET_CHANNEL_MESSAGE);
  
  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = type;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = silc_id_get_len(server->id, SILC_ID_SERVER);
  packetdata.src_id_type = SILC_ID_SERVER;
  packetdata.dst_id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_type = SILC_ID_CHANNEL;

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (route && server->server_type != SILC_ROUTER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router;

    /* Get data used in packet header encryption, keys and stuff. */
    router = server->router;
    sock = (SilcSocketConnection)router->connection;
    idata = (SilcIDListData)router;
    
    if (sock != sender) {
      SILC_LOG_DEBUG(("Sending packet to router for routing"));
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, 
					      idata->hmac_send, 
					      idata->psn_send++,
					      data, data_len, FALSE, 
					      force_send);
    }
  }

  if (!silc_hash_table_count(channel->user_list)) {
    SILC_LOG_DEBUG(("Channel %s is empty", channel->channel_name));
    goto out;
  }

  SILC_LOG_DEBUG(("Sending %s packet to channel %s",
		  silc_get_packet_name(type), channel->channel_name));

  routed = silc_calloc(silc_hash_table_count(channel->user_list), 
		       sizeof(*routed));

  /* Send the message to clients on the channel's client list. */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
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
      sock = (SilcSocketConnection)client->router->connection;
      idata = (SilcIDListData)client->router;

      if (sender && sock == sender)
	continue;

      /* Route only once to router. Protocol prohibits sending channel
	 messages to more than one router. */
      if (sock->type == SILC_SOCKET_TYPE_ROUTER) {
	if (gone)
	  continue;
	gone = TRUE;
      }

      SILC_LOG_DEBUG(("Sending packet to client %s",
		      client->nickname ? client->nickname :
		      (unsigned char *)""));

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, 
					      idata->hmac_send, 
					      idata->psn_send++,
					      data, data_len, FALSE, 
					      force_send);

      /* Mark this route routed already */
      routed[routed_count++] = client->router;
      continue;
    }

    if (client->router)
      continue;

    /* Send to locally connected client */

    /* Get data used in packet header encryption, keys and stuff. */
    sock = (SilcSocketConnection)client->connection;
    idata = (SilcIDListData)client;
    
    if (!sock || (sender && sock == sender))
      continue;

    SILC_LOG_DEBUG(("Sending packet to client %s",
		    client->nickname ? client->nickname :
		    (unsigned char *)""));

    /* Send the packet */
    silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					    idata->send_key, 
					    idata->hmac_send, 
					    idata->psn_send++, 
					    data, data_len, FALSE, 
					    force_send);
  }
  silc_hash_table_list_reset(&htl);

 out:
  silc_free(routed);
  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
}

/* This checks whether the relayed packet came from router. If it did
   then we'll need to encrypt it with the channel key. This is called
   from the silc_server_packet_relay_to_channel. */

static bool
silc_server_packet_relay_to_channel_encrypt(SilcServer server,
					    SilcSocketConnection sock,
					    SilcChannelEntry channel,
					    unsigned char *data,
					    unsigned int data_len)
{
  /* If we are router and the packet came from router and private key
     has not been set for the channel then we must encrypt the packet
     as it was decrypted with the session key shared between us and the
     router which sent it. This is so, because cells does not share the
     same channel key. */
  if (server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_ROUTER &&
      !(channel->mode & SILC_CHANNEL_MODE_PRIVKEY) &&
      channel->channel_key) {
    SilcUInt32 mac_len = silc_hmac_len(channel->hmac);
    SilcUInt32 iv_len = silc_cipher_get_block_len(channel->channel_key);
    unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];

    if (data_len <= mac_len + iv_len) {
      SILC_LOG_WARNING(("Corrupted channel message, cannot relay it"));
      return FALSE;
    }

    memcpy(iv, data + (data_len - iv_len), iv_len);
    silc_channel_message_payload_encrypt(data, data_len - iv_len - mac_len,
					 data_len, iv, iv_len,
					 channel->channel_key, channel->hmac);
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
					 SilcSocketConnection sender_sock,
					 SilcChannelEntry channel,
					 void *sender_id,
					 SilcIdType sender_type,
					 SilcClientEntry sender_entry,
					 unsigned char *data,
					 SilcUInt32 data_len,
					 bool force_send)
{
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl, chl_sender;
  SilcUInt32 routed_count = 0;
  SilcIDListData idata;
  SilcHashTableList htl;
  bool gone = FALSE;
  int k;

  if (!silc_server_client_on_channel(sender_entry, channel, &chl_sender))
    return;

  SILC_LOG_DEBUG(("Relaying packet to channel %s", channel->channel_name));

  /* This encrypts the packet, if needed. It will be encrypted if
     it came from the router thus it needs to be encrypted with the
     channel key. If the channel key does not exist, then we know we
     don't have a single local user on the channel. */
  if (!silc_server_packet_relay_to_channel_encrypt(server, sender_sock,
						   channel, data,
						   data_len))
    return;

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_CHANNEL_MESSAGE;
  packetdata.src_id = silc_id_id2str(sender_id, sender_type);
  packetdata.src_id_len = silc_id_get_len(sender_id, sender_type);
  packetdata.src_id_type = sender_type;
  packetdata.dst_id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_type = SILC_ID_CHANNEL;

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (server->server_type != SILC_ROUTER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router = server->router;

    /* Check that the sender is not our router. */
    if (sender_sock != (SilcSocketConnection)router->connection) {

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)router->connection;
      idata = (SilcIDListData)router;

      SILC_LOG_DEBUG(("Sending channel message to router for routing"));

      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, 
					      idata->hmac_send, 
					      idata->psn_send++, 
					      data, data_len, TRUE, 
					      force_send);
    }
  }

  routed = silc_calloc(silc_hash_table_count(channel->user_list), 
		       sizeof(*routed));

  /* Assure we won't route the message back to the sender's way. */
  if (sender_entry->router)
    routed[routed_count++] = sender_entry->router;

  /* Send the message to clients on the channel's client list. */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
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
      sock = (SilcSocketConnection)client->router->connection;
      idata = (SilcIDListData)client->router;

      /* Check if the sender socket is the same as this client's router
	 socket. */
      if (sender_sock && sock == sender_sock)
	continue;

      SILC_LOG_DEBUG(("Relaying packet to client ID(%s) %s (%s)", 
		      silc_id_render(client->id, SILC_ID_CLIENT),
		      sock->hostname, sock->ip));

      /* Mark this route routed already. */
      routed[routed_count++] = client->router;
	
      if (sock->type == SILC_SOCKET_TYPE_ROUTER) {
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

	SILC_LOG_DEBUG(("Remote is router, encrypt with session key"));

	/* If private key mode is not set then decrypt the packet
	   and re-encrypt it */
	if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY) && 
	    channel->channel_key) {
	  unsigned char tmp[SILC_PACKET_MAX_LEN];

	  if (data_len > SILC_PACKET_MAX_LEN)
	    data_len = SILC_PACKET_MAX_LEN;
	  memcpy(tmp, data, data_len);

	  /* Decrypt the channel message (we don't check the MAC) */
	  silc_channel_message_payload_decrypt(tmp, data_len,
					       channel->channel_key, NULL);

	  /* Now re-encrypt and send it to the router */
	  silc_server_packet_send_srcdest(server, sock,
					  SILC_PACKET_CHANNEL_MESSAGE, 0,
					  sender_id, sender_type,
					  channel->id, SILC_ID_CHANNEL,
					  tmp, data_len, force_send);
	} else {
	  /* Private key mode is set, we don't have the channel key, so
	     just re-encrypt the entire packet and send it to the router. */
	  silc_server_packet_send_srcdest(server, sock,
					  SILC_PACKET_CHANNEL_MESSAGE, 0,
					  sender_id, sender_type,
					  channel->id, SILC_ID_CHANNEL,
					  data, data_len, force_send);
	}
      } else {
	/* Send the packet to normal server */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key,
						idata->hmac_send,
						idata->psn_send++,
						data, data_len, TRUE,
						force_send);
      }

      continue;
    }

    if (client->router)
      continue;

    /* Get data used in packet header encryption, keys and stuff. */
    sock = (SilcSocketConnection)client->connection;
    idata = (SilcIDListData)client;

    if (!sock || (sender_sock && sock == sender_sock))
      continue;

    SILC_LOG_DEBUG(("Sending packet to client ID(%s) %s (%s)", 
		    silc_id_render(client->id, SILC_ID_CLIENT),
		    sock->hostname, sock->ip));

    /* Send the packet */
    silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					    idata->send_key, 
					    idata->hmac_send, 
					    idata->psn_send++, 
					    data, data_len, TRUE, 
					    force_send);
  }

  silc_hash_table_list_reset(&htl);
  silc_free(routed);
  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
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
					   SilcUInt32 data_len,
					   bool force_send)
{
  SilcChannelClientEntry chl;
  SilcHashTableList htl;
  SilcSocketConnection sock = NULL;

  SILC_LOG_DEBUG(("Send packet to local clients on channel %s",
		  channel->channel_name));

  /* Send the message to clients on the channel's client list. */
  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
    if (chl->client && !chl->client->router) {
      sock = (SilcSocketConnection)chl->client->connection;

      /* Send the packet to the client */
      silc_server_packet_send_dest(server, sock, type, flags, chl->client->id,
				   SILC_ID_CLIENT, data, data_len,
				   force_send);
    }
  }
  silc_hash_table_list_reset(&htl);
}

/* Routine used to send (relay, route) private messages to some destination.
   If the private message key does not exist then the message is re-encrypted,
   otherwise we just pass it along. This really is not used to send new
   private messages (as server does not send them) but to relay received
   private messages. */

void silc_server_send_private_message(SilcServer server,
				      SilcSocketConnection dst_sock,
				      SilcCipher cipher,
				      SilcHmac hmac,
				      SilcUInt32 sequence,
				      SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  const SilcBufferStruct p;

  silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		   + packet->dst_id_len + packet->padlen);
  if (!silc_packet_send_prepare(dst_sock, 0, 0, buffer->len, hmac,
                                (const SilcBuffer)&p)) {
    SILC_LOG_ERROR(("Cannot send packet"));
    return;
  }
  silc_buffer_put((SilcBuffer)&p, buffer->data, buffer->len);

  /* Re-encrypt and send if private messge key does not exist */
  if (!(packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY)) {
    /* Re-encrypt packet */
    silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&p, buffer->len);
  } else {
    /* Key exist so encrypt just header and send it */
    silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&p, 
			SILC_PACKET_HEADER_LEN + packet->src_id_len + 
			packet->dst_id_len + packet->padlen);
  }

  /* Send the packet */
  silc_server_packet_send_real(server, dst_sock, FALSE);
}

/* Sends current motd to client */

void silc_server_send_motd(SilcServer server,
			   SilcSocketConnection sock)
{
  char *motd, *motd_file = NULL;
  SilcUInt32 motd_len;

  if (server->config)
    motd_file = server->config->server_info->motd_file;

  if (motd_file) {
    motd = silc_file_readfile(motd_file, &motd_len);
    if (!motd)
      return;

    silc_server_send_notify(server, sock, FALSE, SILC_NOTIFY_TYPE_MOTD, 1,
			    motd, motd_len);
    silc_free(motd);
  }
}

/* Sends error message. Error messages may or may not have any 
   implications. */

void silc_server_send_error(SilcServer server,
			    SilcSocketConnection sock,
			    const char *fmt, ...)
{
  va_list ap;
  unsigned char buf[4096];

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsprintf(buf, fmt, ap);
  va_end(ap);

  silc_server_packet_send(server, sock, SILC_PACKET_ERROR, 0, 
			  buf, strlen(buf), FALSE);
}

/* Sends notify message. If format is TRUE the variable arguments are
   formatted and the formatted string is sent as argument payload. If it is
   FALSE then each argument is sent as separate argument and their format
   in the argument list must be { argument data, argument length }. */

void silc_server_send_notify(SilcServer server,
			     SilcSocketConnection sock,
			     bool broadcast,
			     SilcNotifyType type,
			     SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			  packet->data, packet->len, FALSE);

  /* Send to backup routers if this is being broadcasted to primary
     router.  The silc_server_backup_send checks further whether to
     actually send it or not. */
  if ((broadcast && sock && sock == SILC_PRIMARY_ROUTE(server)) ||
      (broadcast && !sock && !SILC_PRIMARY_ROUTE(server)))
    silc_server_backup_send(server, NULL, SILC_PACKET_NOTIFY, 0,
			    packet->data, packet->len, FALSE, TRUE);

  silc_buffer_free(packet);
  va_end(ap);
}

/* Sends notify message and gets the arguments from the `args' Argument
   Payloads. */

void silc_server_send_notify_args(SilcServer server,
				  SilcSocketConnection sock,
				  bool broadcast,
				  SilcNotifyType type,
				  SilcUInt32 argc,
				  SilcBuffer args)
{
  SilcBuffer packet;

  packet = silc_notify_payload_encode_args(type, argc, args);
  silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Send CHANNEL_CHANGE notify type. This tells the receiver to replace the
   `old_id' with the `new_id'. */

void silc_server_send_notify_channel_change(SilcServer server,
					    SilcSocketConnection sock,
					    bool broadcast,
					    SilcChannelID *old_id,
					    SilcChannelID *new_id)
{
  SilcBuffer idp1, idp2;

  idp1 = silc_id_payload_encode((void *)old_id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode((void *)new_id, SILC_ID_CHANNEL);

  silc_server_send_notify(server, sock, broadcast,
			  SILC_NOTIFY_TYPE_CHANNEL_CHANGE,
			  2, idp1->data, idp1->len, idp2->data, idp2->len);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Send NICK_CHANGE notify type. This tells the receiver to replace the
   `old_id' with the `new_id'. */

void silc_server_send_notify_nick_change(SilcServer server,
					 SilcSocketConnection sock,
					 bool broadcast,
					 SilcClientID *old_id,
					 SilcClientID *new_id,
					 const char *nickname)
{
  SilcBuffer idp1, idp2;

  idp1 = silc_id_payload_encode((void *)old_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode((void *)new_id, SILC_ID_CLIENT);

  silc_server_send_notify(server, sock, broadcast, 
			  SILC_NOTIFY_TYPE_NICK_CHANGE,
			  3, idp1->data, idp1->len, idp2->data, idp2->len,
			  nickname, nickname ? strlen(nickname) : 0);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends JOIN notify type. This tells that new client by `client_id' ID
   has joined to the `channel'. */

void silc_server_send_notify_join(SilcServer server,
				  SilcSocketConnection sock,
				  bool broadcast,
				  SilcChannelEntry channel,
				  SilcClientID *client_id)
{
  SilcBuffer idp1, idp2;

  idp1 = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);
  silc_server_send_notify(server, sock, broadcast, SILC_NOTIFY_TYPE_JOIN,
			  2, idp1->data, idp1->len,
			  idp2->data, idp2->len);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends LEAVE notify type. This tells that `client_id' has left the
   `channel'. The Notify packet is always destined to the channel. */

void silc_server_send_notify_leave(SilcServer server,
				   SilcSocketConnection sock,
				   bool broadcast,
				   SilcChannelEntry channel,
				   SilcClientID *client_id)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
			       SILC_ID_CHANNEL, SILC_NOTIFY_TYPE_LEAVE,
			       1, idp->data, idp->len);
  silc_buffer_free(idp);
}

/* Sends CMODE_CHANGE notify type. This tells that `client_id' changed the
   `channel' mode to `mode. The Notify packet is always destined to
   the channel. */

void silc_server_send_notify_cmode(SilcServer server,
				   SilcSocketConnection sock,
				   bool broadcast,
				   SilcChannelEntry channel,
				   SilcUInt32 mode_mask,
				   void *id, SilcIdType id_type,
				   const char *cipher, const char *hmac,
				   const char *passphrase,
				   SilcPublicKey founder_key)
{
  SilcBuffer idp;
  unsigned char mode[4], *key = NULL;
  SilcUInt32 key_len = 0;

  idp = silc_id_payload_encode((void *)id, id_type);
  SILC_PUT32_MSB(mode_mask, mode);
  if (founder_key)
    key = silc_pkcs_public_key_encode(founder_key, &key_len);

  silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
			       SILC_ID_CHANNEL, SILC_NOTIFY_TYPE_CMODE_CHANGE,
			       6, idp->data, idp->len,
			       mode, 4,
			       cipher, cipher ? strlen(cipher) : 0,
			       hmac, hmac ? strlen(hmac) : 0,
			       passphrase, passphrase ? 
			       strlen(passphrase) : 0,
			       key, key_len);
  silc_free(key);
  silc_buffer_free(idp);
}

/* Sends CUMODE_CHANGE notify type. This tells that `id' changed the
   `target' client's mode on `channel'. The notify packet is always
   destined to the channel. */

void silc_server_send_notify_cumode(SilcServer server,
				    SilcSocketConnection sock,
				    bool broadcast,
				    SilcChannelEntry channel,
				    SilcUInt32 mode_mask,
				    void *id, SilcIdType id_type,
				    SilcClientID *target,
				    SilcPublicKey founder_key)
{
  SilcBuffer idp1, idp2;
  unsigned char mode[4], *key = NULL;
  SilcUInt32 key_len = 0;

  idp1 = silc_id_payload_encode((void *)id, id_type);
  idp2 = silc_id_payload_encode((void *)target, SILC_ID_CLIENT);
  SILC_PUT32_MSB(mode_mask, mode);
  if (founder_key)
    key = silc_pkcs_public_key_encode(founder_key, &key_len);

  silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
			       SILC_ID_CHANNEL, 
			       SILC_NOTIFY_TYPE_CUMODE_CHANGE, 4, 
			       idp1->data, idp1->len,
			       mode, 4,
			       idp2->data, idp2->len,
			       key, key_len);
  silc_free(key);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends SIGNOFF notify type. This tells that `client_id' client has
   left SILC network. This function is used only between server and router
   traffic. This is not used to send the notify to the channel for
   client. The `message may be NULL. */

void silc_server_send_notify_signoff(SilcServer server,
				     SilcSocketConnection sock,
				     bool broadcast,
				     SilcClientID *client_id,
				     const char *message)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  silc_server_send_notify(server, sock, broadcast,
			  SILC_NOTIFY_TYPE_SIGNOFF,
			  message ? 2 : 1, idp->data, idp->len,
			  message, message ? strlen(message): 0);
  silc_buffer_free(idp);
}

/* Sends TOPIC_SET notify type. This tells that `id' changed
   the `channel's topic to `topic'. The Notify packet is always destined
   to the channel. This function is used to send the topic set notifies
   between routers. */

void silc_server_send_notify_topic_set(SilcServer server,
				       SilcSocketConnection sock,
				       bool broadcast,
				       SilcChannelEntry channel,
				       void *id, SilcIdType id_type,
				       char *topic)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode(id, id_type);
  silc_server_send_notify_dest(server, sock, broadcast,
			       (void *)channel->id, SILC_ID_CHANNEL,
			       SILC_NOTIFY_TYPE_TOPIC_SET,
			       topic ? 2 : 1, 
			       idp->data, idp->len, 
			       topic, topic ? strlen(topic) : 0);
  silc_buffer_free(idp);
}

/* Send KICKED notify type. This tells that the `client_id' on `channel'
   was kicked off the channel.  The `comment' may indicate the reason
   for the kicking. This function is used only between server and router
   traffic. */

void silc_server_send_notify_kicked(SilcServer server,
				    SilcSocketConnection sock,
				    bool broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    SilcClientID *kicker,
				    char *comment)
{
  SilcBuffer idp1;
  SilcBuffer idp2;

  idp1 = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode((void *)kicker, SILC_ID_CLIENT);
  silc_server_send_notify_dest(server, sock, broadcast, (void *)channel->id,
			       SILC_ID_CHANNEL, SILC_NOTIFY_TYPE_KICKED, 3,
			       idp1->data, idp1->len,
			       comment, comment ? strlen(comment) : 0,
			       idp2->data, idp2->len);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Send KILLED notify type. This tells that the `client_id' client was
   killed from the network.  The `comment' may indicate the reason
   for the killing. */

void silc_server_send_notify_killed(SilcServer server,
				    SilcSocketConnection sock,
				    bool broadcast,
				    SilcClientID *client_id,
				    const char *comment,
				    void *killer, SilcIdType killer_type)
{
  SilcBuffer idp1;
  SilcBuffer idp2;

  idp1 = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
  idp2 = silc_id_payload_encode(killer, killer_type);
  silc_server_send_notify_dest(server, sock, broadcast, (void *)client_id,
			       SILC_ID_CLIENT, SILC_NOTIFY_TYPE_KILLED,
			       3, idp1->data, idp1->len,
			       comment, comment ? strlen(comment) : 0,
			       idp2->data, idp2->len);
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);
}

/* Sends UMODE_CHANGE notify type. This tells that `client_id' client's
   user mode in the SILC Network was changed. This function is used to
   send the packet between routers as broadcast packet. */

void silc_server_send_notify_umode(SilcServer server,
				   SilcSocketConnection sock,
				   bool broadcast,
				   SilcClientID *client_id,
				   SilcUInt32 mode_mask)
{
  SilcBuffer idp;
  unsigned char mode[4];

  idp = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  SILC_PUT32_MSB(mode_mask, mode);

  silc_server_send_notify(server, sock, broadcast,
			  SILC_NOTIFY_TYPE_UMODE_CHANGE, 2,
			  idp->data, idp->len, 
			  mode, 4);
  silc_buffer_free(idp);
}

/* Sends BAN notify type. This tells that ban has been either `add'ed
   or `del'eted on the `channel. This function is used to send the packet
   between routers as broadcast packet. */

void silc_server_send_notify_ban(SilcServer server,
				 SilcSocketConnection sock,
				 bool broadcast,
				 SilcChannelEntry channel,
				 char *add, char *del)
{
  SilcBuffer idp;

  idp = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);
  silc_server_send_notify(server, sock, broadcast,
			  SILC_NOTIFY_TYPE_BAN, 3,
			  idp->data, idp->len,
			  add, add ? strlen(add) : 0,
			  del, del ? strlen(del) : 0);
  silc_buffer_free(idp);
}

/* Sends INVITE notify type. This tells that invite has been either `add'ed
   or `del'eted on the `channel.  The sender of the invite is the `client_id'.
   This function is used to send the packet between routers as broadcast
   packet. */

void silc_server_send_notify_invite(SilcServer server,
				    SilcSocketConnection sock,
				    bool broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    char *add, char *del)
{
  SilcBuffer idp, idp2;

  idp = silc_id_payload_encode((void *)channel->id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode((void *)client_id, SILC_ID_CLIENT);
  silc_server_send_notify(server, sock, broadcast,
			  SILC_NOTIFY_TYPE_INVITE, 5,
			  idp->data, idp->len,
			  channel->channel_name, strlen(channel->channel_name),
			  idp2->data, idp2->len,
			  add, add ? strlen(add) : 0,
			  del, del ? strlen(del) : 0);
  silc_buffer_free(idp);
  silc_buffer_free(idp2);
}

/* Sends WATCH notify type. This tells that the `client' was watched and
   its status in the network has changed. */

void silc_server_send_notify_watch(SilcServer server,
				   SilcSocketConnection sock,
				   SilcClientEntry watcher,
				   SilcClientEntry client,
				   const char *nickname,
				   SilcNotifyType type)
{
  SilcBuffer idp;
  unsigned char mode[4], n[2];

  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  SILC_PUT16_MSB(type, n);
  SILC_PUT32_MSB(client->mode, mode);
  silc_server_send_notify_dest(server, sock, FALSE, watcher->id,
			       SILC_ID_CLIENT, SILC_NOTIFY_TYPE_WATCH,
			       4, idp->data, idp->len,
			       nickname, nickname ? strlen(nickname) : 0,
			       mode, sizeof(mode), 
			       type != SILC_NOTIFY_TYPE_NONE ?
			       n : NULL, sizeof(n));
  silc_buffer_free(idp);
}

/* Sends notify message destined to specific entity. */

void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  bool broadcast,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY, 
			       broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			       dest_id, dest_id_type,
			       packet->data, packet->len, FALSE);
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
					SilcSocketConnection sender,
					SilcChannelEntry channel,
					bool route_notify,
					SilcNotifyType type,
					SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send_to_channel(server, sender, channel, 
				     SILC_PACKET_NOTIFY, route_notify,
				     packet->data, packet->len, FALSE);
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
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry c;
  SilcClientEntry *sent_clients = NULL;
  SilcUInt32 sent_clients_count = 0;
  SilcServerEntry *routed = NULL;
  SilcUInt32 routed_count = 0;
  SilcHashTableList htl, htl2;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl, chl2;
  SilcIDListData idata;
  SilcBuffer packet;
  unsigned char *data;
  SilcUInt32 data_len;
  bool force_send = FALSE;
  va_list ap;

  if (!silc_hash_table_count(client->channels)) {
    SILC_LOG_DEBUG(("Client is not joined to any channels"));
    return;
  }

  SILC_LOG_DEBUG(("Sending notify to joined channels"));

  va_start(ap, argc);
  packet = silc_notify_payload_encode(type, argc, ap);
  data = packet->data;
  data_len = packet->len;

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_NOTIFY;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = silc_id_get_len(server->id, SILC_ID_SERVER);
  packetdata.src_id_type = SILC_ID_SERVER;

  silc_hash_table_list(client->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chl)) {
    channel = chl->channel;

    /* Send the message to all clients on the channel's client list. */
    silc_hash_table_list(channel->user_list, &htl2);
    while (silc_hash_table_get(&htl2, NULL, (void **)&chl2)) {
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
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)c->router->connection;
	idata = (SilcIDListData)c->router;

	{
	  SILC_LOG_DEBUG(("*****************"));
	  SILC_LOG_DEBUG(("client->router->id %s",
			  silc_id_render(c->router->id, SILC_ID_SERVER)));
	  SILC_LOG_DEBUG(("client->router->connection->user_data->id %s",
			  silc_id_render(((SilcServerEntry)sock->user_data)->id, SILC_ID_SERVER)));
	}

	packetdata.dst_id = silc_id_id2str(c->router->id, SILC_ID_SERVER);
	packetdata.dst_id_len = silc_id_get_len(c->router->id, SILC_ID_SERVER);
	packetdata.dst_id_type = SILC_ID_SERVER;

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, 
						idata->hmac_send, 
						idata->psn_send++, 
						data, data_len, FALSE, 
						force_send);
	
	silc_free(packetdata.dst_id);

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
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)c->connection;
	idata = (SilcIDListData)c;
	
        if (!sock)
          continue;

	packetdata.dst_id = silc_id_id2str(c->id, SILC_ID_CLIENT);
	packetdata.dst_id_len = silc_id_get_len(c->id, SILC_ID_CLIENT);
	packetdata.dst_id_type = SILC_ID_CLIENT;

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, 
						idata->hmac_send, 
						idata->psn_send++, 
						data, data_len, FALSE, 
						force_send);

	silc_free(packetdata.dst_id);

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
  silc_free(packetdata.src_id);
  silc_buffer_free(packet);
  va_end(ap);
}

/* Sends New ID Payload to remote end. The packet is used to distribute
   information about new registered clients, servers, channel etc. usually
   to routers so that they can keep these information up to date. 
   If the argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */

void silc_server_send_new_id(SilcServer server,
			     SilcSocketConnection sock,
			     bool broadcast,
			     void *id, SilcIdType id_type, 
			     SilcUInt32 id_len)
{
  SilcBuffer idp;

  SILC_LOG_DEBUG(("Sending new ID"));

  idp = silc_id_payload_encode(id, id_type);
  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  idp->data, idp->len, FALSE);
  silc_buffer_free(idp);
}

/* Send New Channel Payload to notify about newly created channel in the
   SILC network. Router uses this to notify other routers in the network 
   about new channel. This packet is broadcasted by router. */

void silc_server_send_new_channel(SilcServer server,
				  SilcSocketConnection sock,
				  bool broadcast,
				  char *channel_name,
				  void *channel_id, 
				  SilcUInt32 channel_id_len,
				  SilcUInt32 mode)
{
  SilcBuffer packet;
  unsigned char *cid;
  SilcUInt32 name_len = strlen(channel_name);

  SILC_LOG_DEBUG(("Sending new channel"));

  cid = silc_id_id2str(channel_id, SILC_ID_CHANNEL);
  if (!cid)
    return;

  /* Encode the channel payload */
  packet = silc_channel_payload_encode(channel_name, name_len,
				       cid, channel_id_len, mode);

  silc_server_packet_send(server, sock, SILC_PACKET_NEW_CHANNEL, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);

  silc_free(cid);
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
				  SilcSocketConnection sender,
				  SilcChannelEntry channel,
				  unsigned char route)
{
  SilcBuffer packet;
  unsigned char *chid;
  SilcUInt32 tmp_len;
 
  SILC_LOG_DEBUG(("Sending key to channel %s", channel->channel_name));
 
  chid = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  if (!chid)
    return;
 
  /* Encode channel key packet */
  tmp_len = strlen(channel->channel_key->cipher->name);
  packet = silc_channel_key_payload_encode(silc_id_get_len(channel->id,
							   SILC_ID_CHANNEL),
					   chid, tmp_len,
                                           channel->channel_key->cipher->name,
                                           channel->key_len / 8, channel->key);
  silc_server_packet_send_to_channel(server, sender, channel, 
				     SILC_PACKET_CHANNEL_KEY,
                                     route, packet->data, packet->len, 
				     FALSE);
  silc_buffer_free(packet);
  silc_free(chid);
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form in correct order. */

void silc_server_send_command(SilcServer server, 
			      SilcSocketConnection sock,
			      SilcCommand command, 
			      SilcUInt16 ident,
			      SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, ident, argc, ap);
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND, 0,
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);
  va_end(ap);
}

/* Generic function to send any command reply. The arguments must be sent
   already encoded into correct form in correct order. */

void silc_server_send_command_reply(SilcServer server, 
				    SilcSocketConnection sock,
				    SilcCommand command, 
				    SilcStatus status,
				    SilcStatus error,
				    SilcUInt16 ident,
				    SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  va_start(ap, argc);

  packet = silc_command_reply_payload_encode_vap(command, status, error,
						 ident, argc, ap);
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0,
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);
  va_end(ap);
}

/* Generic function to send any command reply. The arguments must be sent
   already encoded into correct form in correct order. */

void silc_server_send_dest_command_reply(SilcServer server, 
					 SilcSocketConnection sock,
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

  va_start(ap, argc);

  packet = silc_command_reply_payload_encode_vap(command, status, error,
						 ident, argc, ap);
  silc_server_packet_send_dest(server, sock, SILC_PACKET_COMMAND_REPLY, 0,
			       dst_id, dst_id_type, packet->data, 
			       packet->len, TRUE);
  silc_buffer_free(packet);
  va_end(ap);
}

/* Send the heartbeat packet. */

void silc_server_send_heartbeat(SilcServer server,
				SilcSocketConnection sock)
{
  silc_server_packet_send(server, sock, SILC_PACKET_HEARTBEAT, 0,
			  NULL, 0, FALSE);
}

/* Generic function to relay packet we've received. This is used to relay
   packets to a client but generally can be used to other purposes as well. */

void silc_server_relay_packet(SilcServer server,
			      SilcSocketConnection dst_sock,
			      SilcCipher cipher,
			      SilcHmac hmac,
			      SilcUInt32 sequence,
			      SilcPacketContext *packet,
			      bool force_send)
{
  const SilcBufferStruct p;

  silc_buffer_push(packet->buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		   + packet->dst_id_len + packet->padlen);
  if (!silc_packet_send_prepare(dst_sock, 0, 0, packet->buffer->len, hmac,
                                (const SilcBuffer)&p)) {
    SILC_LOG_ERROR(("Cannot send packet"));
    return;
  }
  silc_buffer_put((SilcBuffer)&p, packet->buffer->data, packet->buffer->len);

  /* Re-encrypt packet */
  silc_packet_encrypt(cipher, hmac, sequence, (SilcBuffer)&p, p.len);
  
  /* Send the packet */
  silc_server_packet_send_real(server, dst_sock, force_send);

  silc_buffer_pull(packet->buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		   + packet->dst_id_len + packet->padlen);
}

/* Routine used to send the connection authentication packet. */

void silc_server_send_connection_auth_request(SilcServer server,
					      SilcSocketConnection sock,
					      SilcUInt16 conn_type,
					      SilcAuthMethod auth_meth)
{
  SilcBuffer packet;

  packet = silc_buffer_alloc(4);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(conn_type),
		     SILC_STR_UI_SHORT(auth_meth),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_CONNECTION_AUTH_REQUEST,
			  0, packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Purge the outgoing packet queue to the network if there is data. This
   function can be used to empty the packet queue. It is guaranteed that
   after this function returns the outgoing data queue is empty. */

void silc_server_packet_queue_purge(SilcServer server,
				    SilcSocketConnection sock)
{
  if (sock && SILC_IS_OUTBUF_PENDING(sock) && 
      (SILC_IS_DISCONNECTED(sock) == FALSE)) {
    server->stat.packets_sent++;
    silc_packet_send(sock, TRUE);
    SILC_SET_CONNECTION_FOR_INPUT(server->schedule, sock->sock);
    SILC_UNSET_OUTBUF_PENDING(sock);
    silc_buffer_clear(sock->outbuf);
  }
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
			    bool route, bool local,
			    unsigned char *data, 
			    SilcUInt32 data_len,
			    bool force_send)
{
  SilcIDCacheList list = NULL;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client = NULL;
  SilcSocketConnection sock;
  SilcServerEntry *routed = NULL;
  SilcUInt32 routed_count = 0;
  bool gone = FALSE;
  int k;

  SILC_LOG_DEBUG(("Sending %s packet to operators",
		  silc_get_packet_name(type)));

  /* If local was requested send only locally connected operators. */
  if (local || (server->server_type == SILC_SERVER && !route)) {
    if (!silc_idcache_get_all(server->local_list->clients, &list) ||
	!silc_idcache_list_first(list, &id_cache))
      return;
    while (id_cache) {
      client = (SilcClientEntry)id_cache->context;
      if (!client->router && SILC_IS_LOCAL(client) &&
	  (client->mode & SILC_UMODE_SERVER_OPERATOR ||
	   client->mode & SILC_UMODE_ROUTER_OPERATOR)) {

	/* Send the packet to locally connected operator */
	silc_server_packet_send_dest(server, client->connection, type, flags,
				     client->id, SILC_ID_CLIENT,
				     data, data_len, force_send);
      }

      if (!silc_idcache_list_next(list, &id_cache))
	break;
    }
    silc_idcache_list_free(list);
    return;
  }

  if (!silc_idcache_get_all(server->local_list->clients, &list) ||
      !silc_idcache_list_first(list, &id_cache))
    return;
  while (id_cache) {
    client = (SilcClientEntry)id_cache->context;
    if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
	!(client->mode & SILC_UMODE_ROUTER_OPERATOR))
      goto next;

    if (server->server_type != SILC_SERVER && client->router && 
	((!route && client->router->router == server->id_entry) || route)) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	goto next;

      /* Route only once to router */
      sock = (SilcSocketConnection)client->router->connection;
      if (sock->type == SILC_SOCKET_TYPE_ROUTER) {
	if (gone)
	  goto next;
	gone = TRUE;
      }

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, flags,
				   client->id, SILC_ID_CLIENT,
				   data, data_len, force_send);

      /* Mark this route routed already */
      routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
      routed[routed_count++] = client->router;
      goto next;
    }

    if (client->router || !client->connection)
      goto next;

    /* Send to locally connected client */
    sock = (SilcSocketConnection)client->connection;
    silc_server_packet_send_dest(server, sock, type, flags,
				 client->id, SILC_ID_CLIENT,
				 data, data_len, force_send);

  next:
    if (!silc_idcache_list_next(list, &id_cache))
      break;
  }
  silc_idcache_list_free(list);

  if (!silc_idcache_get_all(server->global_list->clients, &list) ||
      !silc_idcache_list_first(list, &id_cache))
    return;
  while (id_cache) {
    client = (SilcClientEntry)id_cache->context;
    if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
	!(client->mode & SILC_UMODE_ROUTER_OPERATOR))
      goto nextg;

    if (server->server_type != SILC_SERVER && client->router && 
	((!route && client->router->router == server->id_entry) || route)) {

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	goto nextg;

      /* Route only once to router */
      sock = (SilcSocketConnection)client->router->connection;
      if (sock->type == SILC_SOCKET_TYPE_ROUTER) {
	if (gone)
	  goto nextg;
	gone = TRUE;
      }

      /* Send the packet */
      silc_server_packet_send_dest(server, sock, type, flags,
				   client->id, SILC_ID_CLIENT,
				   data, data_len, force_send);

      /* Mark this route routed already */
      routed = silc_realloc(routed, sizeof(*routed) * (routed_count + 1));
      routed[routed_count++] = client->router;
      goto nextg;
    }

    if (client->router || !client->connection)
      goto nextg;

    /* Send to locally connected client */
    sock = (SilcSocketConnection)client->connection;
    silc_server_packet_send_dest(server, sock, type, flags,
				 client->id, SILC_ID_CLIENT,
				 data, data_len, force_send);

  nextg:
    if (!silc_idcache_list_next(list, &id_cache))
      break;
  }
  silc_idcache_list_free(list);
  silc_free(routed);
}

/* Send a notify packet to operators */

void silc_server_send_opers_notify(SilcServer server,
				   bool route,
				   bool local,
				   SilcNotifyType type,
				   SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);
  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_send_opers(server, SILC_PACKET_NOTIFY, 0,
			 route, local, packet->data, packet->len,
			 FALSE);
  silc_buffer_free(packet);
  va_end(ap);
}
