/*

  packet_send.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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
				 int force_send)
{
  int ret;

  /* Send the packet */
  ret = silc_packet_send(sock, force_send);
  if (ret != -2)
    return ret;

  /* Mark that there is some outgoing data available for this connection. 
     This call sets the connection both for input and output (the input
     is set always and this call keeps the input setting, actually). 
     Actual data sending is performed by silc_server_packet_process. */
  SILC_SET_CONNECTION_FOR_OUTPUT(sock->sock);

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
			     unsigned int data_len,
			     int force_send)
{
  void *dst_id = NULL;
  SilcIdType dst_id_type = SILC_ID_NONE;

  if (!sock)
    return;

  /* Get data used in the packet sending, keys and stuff */
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    dst_id = ((SilcClientEntry)sock->user_data)->id;
    dst_id_type = SILC_ID_CLIENT;
    break;
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    dst_id = ((SilcServerEntry)sock->user_data)->id;
    dst_id_type = SILC_ID_SERVER;
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
				  unsigned int data_len,
				  int force_send)
{
  SilcPacketContext packetdata;
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;
  unsigned char *dst_id_data = NULL;
  unsigned int dst_id_len = 0;

  SILC_LOG_DEBUG(("Sending packet, type %d", type));

  /* Get data used in the packet sending, keys and stuff */
  idata = (SilcIDListData)sock->user_data;

  if (dst_id) {
    dst_id_data = silc_id_id2str(dst_id, dst_id_type);
    dst_id_len = silc_id_get_len(dst_id_type);
  }

  /* Set the packet context pointers */
  packetdata.type = type;
  packetdata.flags = flags;
  packetdata.src_id = silc_id_id2str(server->id, server->id_type);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = server->id_type;
  packetdata.dst_id = dst_id_data;
  packetdata.dst_id_len = dst_id_len;
  packetdata.dst_id_type = dst_id_type;
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);
  packetdata.rng = server->rng;

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packetdata.src_id_len + 
			   packetdata.dst_id_len,
			   packetdata.padlen,
			   data_len);

  SILC_LOG_DEBUG(("Putting data to outgoing buffer, len %d", data_len));

  packetdata.buffer = sock->outbuf;

  /* Put the data to the buffer */
  if (data && data_len)
    silc_buffer_put(sock->outbuf, data, data_len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  if (idata) {
    cipher = idata->send_key;
    hmac = idata->hmac;
  }

  /* Encrypt the packet */
  silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);

  SILC_LOG_HEXDUMP(("Outgoing packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);

  if (packetdata.src_id)
    silc_free(packetdata.src_id);
  if (packetdata.dst_id)
    silc_free(packetdata.dst_id);
}

/* Forwards packet. Packets sent with this function will be marked as
   forwarded (in the SILC header flags) so that the receiver knows that
   we have forwarded the packet to it. Forwarded packets are handled
   specially by the receiver as they are not destined to the receiver
   originally. However, the receiver knows this because the forwarded
   flag has been set (and the flag is authenticated). */

void silc_server_packet_forward(SilcServer server,
				SilcSocketConnection sock,
				unsigned char *data, unsigned int data_len,
				int force_send)
{
  SilcIDListData idata;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;

  SILC_LOG_DEBUG(("Forwarding packet"));

  /* Get data used in the packet sending, keys and stuff */
  idata = (SilcIDListData)sock->user_data;

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 0, 0, data_len);

  /* Put the data to the buffer */
  if (data && data_len)
    silc_buffer_put(sock->outbuf, data, data_len);

  /* Add the FORWARDED flag to packet flags */
  sock->outbuf->data[2] |= (unsigned char)SILC_PACKET_FLAG_FORWARDED;

  if (idata) {
    cipher = idata->send_key;
    hmac = idata->hmac;
  }

  /* Encrypt the packet */
  silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);

  SILC_LOG_HEXDUMP(("Forwarded packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);
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

  SILC_LOG_DEBUG(("Broadcasting received broadcast packet"));

  /* If the packet is originated from our primary route we are
     not allowed to send the packet. */
  id = silc_id_str2id(packet->src_id, packet->src_id_type);
  if (id && SILC_ID_SERVER_COMPARE(id, server->router->id)) {
    idata = (SilcIDListData)sock->user_data;

    silc_buffer_push(buffer, buffer->data - buffer->head);
    silc_packet_send_prepare(sock, 0, 0, buffer->len); 
    silc_buffer_put(sock->outbuf, buffer->data, buffer->len);
    silc_packet_encrypt(idata->send_key, idata->hmac, 
			sock->outbuf, sock->outbuf->len);

    SILC_LOG_HEXDUMP(("Broadcasted packet, len %d", sock->outbuf->len),
		     sock->outbuf->data, sock->outbuf->len);

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
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Routing received packet"));

  idata = (SilcIDListData)sock->user_data;

  silc_buffer_push(buffer, buffer->data - buffer->head);
  silc_packet_send_prepare(sock, 0, 0, buffer->len); 
  silc_buffer_put(sock->outbuf, buffer->data, buffer->len);
  silc_packet_encrypt(idata->send_key, idata->hmac, 
		      sock->outbuf, sock->outbuf->len);

  SILC_LOG_HEXDUMP(("Routed packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, TRUE);
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
					unsigned char *data,
					unsigned int data_len,
					int channel_message,
					int force_send)
{
  packet->truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packet->src_id_len + packet->dst_id_len;

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packet->src_id_len + 
			   packet->dst_id_len,
			   packet->padlen,
			   data_len);

  packet->buffer = sock->outbuf;

  /* Put the data to buffer, assemble and encrypt the packet. The packet
     is encrypted with normal session key shared with the client. */
  silc_buffer_put(sock->outbuf, data, data_len);
  silc_packet_assemble(packet);
  if (channel_message)
    silc_packet_encrypt(cipher, hmac, sock->outbuf, SILC_PACKET_HEADER_LEN + 
			packet->src_id_len + packet->dst_id_len +
			packet->padlen);
  else
    silc_packet_encrypt(cipher, hmac, sock->outbuf, sock->outbuf->len);
    
  SILC_LOG_HEXDUMP(("Channel packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_server_packet_send_real(server, sock, force_send);
}

/* This routine is used by the server to send packets to channel. The 
   packet sent with this function is distributed to all clients on
   the channel. Usually this is used to send notify messages to the
   channel, things like notify about new user joining to the channel. 
   If `route' is FALSE then the packet is sent only locally and will not
   be routed anywhere (for router locally means cell wide). */

void silc_server_packet_send_to_channel(SilcServer server,
					SilcChannelEntry channel,
					SilcPacketType type,
					unsigned char route,
					unsigned char *data,
					unsigned int data_len,
					int force_send)
{
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl;
  SilcIDListData idata;
  unsigned int routed_count = 0;

  /* This doesn't send channel message packets */
  if (type == SILC_PACKET_CHANNEL_MESSAGE)
    return;
  
  SILC_LOG_DEBUG(("Sending packet to channel"));

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = type;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = SILC_ID_SERVER;
  packetdata.dst_id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_len = SILC_ID_CHANNEL_LEN;
  packetdata.dst_id_type = SILC_ID_CHANNEL;
  packetdata.rng = server->rng;
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (route && server->server_type == SILC_SERVER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router;

    /* Get data used in packet header encryption, keys and stuff. */
    router = server->router;
    sock = (SilcSocketConnection)router->connection;
    idata = (SilcIDListData)router;
    
    SILC_LOG_DEBUG(("Sending channel message to router for routing"));

    silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					    idata->send_key, idata->hmac, 
					    data, data_len, FALSE, force_send);
  }

  /* Send the message to clients on the channel's client list. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    client = chl->client;

    /* If client has router set it is not locally connected client and
       we will route the message to the router set in the client. Though,
       send locally connected server in all cases. */
    if (server->server_type == SILC_ROUTER && client && client->router && 
	((!route && client->router->router == server->id_entry) || route)) {
      int k;

      /* Check if we have sent the packet to this route already */
      for (k = 0; k < routed_count; k++)
	if (routed[k] == client->router)
	  break;
      if (k < routed_count)
	continue;

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->router->connection;
      idata = (SilcIDListData)client->router;

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, FALSE, 
					      force_send);

      /* We want to make sure that the packet is routed to same router
	 only once. Mark this route as sent route. */
      k = routed_count;
      routed = silc_realloc(routed, sizeof(*routed) * (k + 1));
      routed[k] = client->router;
      routed_count++;

      continue;
    }

    if (server->server_type == SILC_ROUTER && !route)
      continue;

    if (server->server_type == SILC_SERVER && client->router)
      continue;

    /* Send to locally connected client */
    if (client) {

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->connection;
      idata = (SilcIDListData)client;

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, FALSE, 
					      force_send);
    }
  }

  if (routed_count)
    silc_free(routed);
  silc_free(packetdata.src_id);
  silc_free(packetdata.dst_id);
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
					 void *sender, 
					 SilcIdType sender_type,
					 unsigned char *data,
					 unsigned int data_len,
					 int force_send)
{
  int found = FALSE;
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry client = NULL;
  SilcServerEntry *routed = NULL;
  SilcChannelClientEntry chl;
  unsigned int routed_count = 0;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Relaying packet to channel"));

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_CHANNEL_MESSAGE;
  packetdata.src_id = silc_id_id2str(sender, sender_type);
  packetdata.src_id_len = silc_id_get_len(sender_type);
  packetdata.src_id_type = sender_type;
  packetdata.dst_id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  packetdata.dst_id_len = SILC_ID_CHANNEL_LEN;
  packetdata.dst_id_type = SILC_ID_CHANNEL;
  packetdata.rng = server->rng;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* If there are global users in the channel we will send the message
     first to our router for further routing. */
  if (server->server_type == SILC_SERVER && !server->standalone &&
      channel->global_users) {
    SilcServerEntry router;

    router = server->router;

    /* Check that the sender is not our router. */
    if (sender_sock != (SilcSocketConnection)router->connection) {

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)router->connection;
      idata = (SilcIDListData)router;

      SILC_LOG_DEBUG(("Sending channel message to router for routing"));

      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, TRUE, 
					      force_send);
    }
  }

  /* Send the message to clients on the channel's client list. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    client = chl->client;

    if (client) {

      /* If sender is one on the channel do not send it the packet. */
      if (!found && !SILC_ID_CLIENT_COMPARE(client->id, sender)) {
	found = TRUE;
	continue;
      }

      /* If the client has set router it means that it is not locally
	 connected client and we will route the packet further. */
      if (server->server_type == SILC_ROUTER && client->router) {
	int k;

	/* Sender maybe server as well so we want to make sure that
	   we won't send the message to the server it came from. */
	if (!found && !SILC_ID_SERVER_COMPARE(client->router->id, sender)) {
	  found = TRUE;
	  continue;
	}

	/* Check if we have sent the packet to this route already */
	for (k = 0; k < routed_count; k++)
	  if (routed[k] == client->router)
	    break;
	if (k < routed_count)
	  continue;
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)client->router->connection;
	idata = (SilcIDListData)client->router;

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, idata->hmac, 
						data, data_len, TRUE, 
						force_send);
	
	/* We want to make sure that the packet is routed to same router
	   only once. Mark this route as sent route. */
	k = routed_count;
	routed = silc_realloc(routed, sizeof(*routed) * (k + 1));
	routed[k] = client->router;
	routed_count++;
	
	continue;
      }

      if (server->server_type == SILC_SERVER && client->router)
	continue;

      /* Get data used in packet header encryption, keys and stuff. */
      sock = (SilcSocketConnection)client->connection;
      idata = (SilcIDListData)client;

      SILC_LOG_DEBUG(("Sending packet to client %s (%s)", 
		      sock->hostname, sock->ip));

      /* Send the packet */
      silc_server_packet_send_to_channel_real(server, sock, &packetdata,
					      idata->send_key, idata->hmac, 
					      data, data_len, TRUE, 
					      force_send);
    }
  }

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
					   unsigned int data_len,
					   int force_send)
{
  SilcChannelClientEntry chl;
  SilcSocketConnection sock = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Send the message to clients on the channel's client list. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (chl->client) {
      sock = (SilcSocketConnection)chl->client->connection;

      /* Send the packet to the client */
      silc_server_packet_send_dest(server, sock, type, flags, chl->client->id,
				   SILC_ID_CLIENT, data, data_len,
				   force_send);
    }
  }
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
				      SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;

  /* Send and re-encrypt if private messge key does not exist */
  if ((packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY) == FALSE) {

    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_packet_send_prepare(dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    
    /* Re-encrypt packet */
    silc_packet_encrypt(cipher, hmac, dst_sock->outbuf, buffer->len);
    
    /* Send the packet */
    silc_server_packet_send_real(server, dst_sock, FALSE);

  } else {
    /* Key exist so just send it */
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    silc_packet_send_prepare(dst_sock, 0, 0, buffer->len);
    silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);
    silc_server_packet_send_real(server, dst_sock, FALSE);
  }
}

/* Sends current motd to client */

void silc_server_send_motd(SilcServer server,
			   SilcSocketConnection sock)
{
  char *motd;
  int motd_len;

  if (server->config && server->config->motd && 
      server->config->motd->motd_file) {

    motd = silc_file_read(server->config->motd->motd_file, &motd_len);
    if (!motd)
      return;

    silc_server_send_notify(server, sock, SILC_NOTIFY_TYPE_MOTD, 1,
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
			     SilcNotifyType type,
			     unsigned int argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send(server, sock, SILC_PACKET_NOTIFY, 0, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Sends notify message destined to specific entity. */

void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  unsigned int argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send_dest(server, sock, SILC_PACKET_NOTIFY, 0, 
			       dest_id, dest_id_type,
			       packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Sends notify message to a channel. The notify message sent is 
   distributed to all clients on the channel. If `router_notify' is TRUE
   then the notify may be routed to primary route or to some other routers.
   If FALSE it is assured that the notify is sent only locally. */

void silc_server_send_notify_to_channel(SilcServer server,
					SilcChannelEntry channel,
					unsigned char route_notify,
					SilcNotifyType type,
					unsigned int argc, ...)
{
  va_list ap;
  SilcBuffer packet;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  silc_server_packet_send_to_channel(server, channel, 
				     SILC_PACKET_NOTIFY, route_notify,
				     packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
}

/* Send notify message to all clients the client has joined. It is quaranteed
   that the message is sent only once to a client (ie. if a client is joined
   on two same channel it will receive only one notify message). Also, this
   sends only to local clients (locally connected if we are server, and to
   local servers if we are router). */

void silc_server_send_notify_on_channels(SilcServer server,
					 SilcClientEntry client,
					 SilcNotifyType type,
					 unsigned int argc, ...)
{
  int k;
  SilcSocketConnection sock = NULL;
  SilcPacketContext packetdata;
  SilcClientEntry c;
  SilcClientEntry *sent_clients = NULL;
  unsigned int sent_clients_count = 0;
  SilcServerEntry *routed = NULL;
  unsigned int routed_count = 0;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl, chl2;
  SilcIDListData idata;
  SilcBuffer packet;
  unsigned char *data;
  unsigned int data_len;
  int force_send = FALSE;
  va_list ap;

  SILC_LOG_DEBUG(("Start"));

  if (!silc_list_count(client->channels))
    return;

  va_start(ap, argc);
  packet = silc_notify_payload_encode(type, argc, ap);
  data = packet->data;
  data_len = packet->len;

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_NOTIFY;
  packetdata.src_id = silc_id_id2str(server->id, SILC_ID_SERVER);
  packetdata.src_id_len = SILC_ID_SERVER_LEN;
  packetdata.src_id_type = SILC_ID_SERVER;
  packetdata.rng = server->rng;

  silc_list_start(client->channels);
  while ((chl = silc_list_get(client->channels)) != SILC_LIST_END) {
    channel = chl->channel;

    /* Send the message to all clients on the channel's client list. */
    silc_list_start(channel->user_list);
    while ((chl2 = silc_list_get(channel->user_list)) != SILC_LIST_END) {
      c = chl2->client;
      
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
	
	packetdata.dst_id = silc_id_id2str(c->router->id, SILC_ID_SERVER);
	packetdata.dst_id_len = SILC_ID_SERVER_LEN;
	packetdata.dst_id_type = SILC_ID_SERVER;
	packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	  packetdata.src_id_len + packetdata.dst_id_len;
	packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, idata->hmac, 
						data, data_len, FALSE, 
						force_send);
	
	silc_free(packetdata.dst_id);

	/* We want to make sure that the packet is routed to same router
	   only once. Mark this route as sent route. */
	k = routed_count;
	routed = silc_realloc(routed, sizeof(*routed) * (k + 1));
	routed[k] = c->router;
	routed_count++;

	continue;
      }

      if (server->server_type == SILC_SERVER && client->router)
	continue;

      /* Send to locally connected client */
      if (c) {
	
	/* Get data used in packet header encryption, keys and stuff. */
	sock = (SilcSocketConnection)c->connection;
	idata = (SilcIDListData)c;
	
	packetdata.dst_id = silc_id_id2str(c->id, SILC_ID_CLIENT);
	packetdata.dst_id_len = SILC_ID_CLIENT_LEN;
	packetdata.dst_id_type = SILC_ID_CLIENT;
	packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
	  packetdata.src_id_len + packetdata.dst_id_len;
	packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

	/* Send the packet */
	silc_server_packet_send_to_channel_real(server, sock, &packetdata,
						idata->send_key, idata->hmac, 
						data, data_len, FALSE, 
						force_send);

	silc_free(packetdata.dst_id);

	/* Make sure that we send the notify only once per client. */
	sent_clients = silc_realloc(sent_clients, sizeof(*sent_clients) * 
				    (sent_clients_count + 1));
	sent_clients[sent_clients_count] = c;
	sent_clients_count++;
      }
    }
  }

  if (routed_count)
    silc_free(routed);
  if (sent_clients_count)
    silc_free(sent_clients);
  silc_free(packetdata.src_id);
}

/* Sends New ID Payload to remote end. The packet is used to distribute
   information about new registered clients, servers, channel etc. usually
   to routers so that they can keep these information up to date. 
   If the argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */

void silc_server_send_new_id(SilcServer server,
			     SilcSocketConnection sock,
			     int broadcast,
			     void *id, SilcIdType id_type, 
			     unsigned int id_len)
{
  SilcBuffer idp;

  SILC_LOG_DEBUG(("Start"));

  idp = silc_id_payload_encode(id, id_type);
  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  idp->data, idp->len, FALSE);
  silc_buffer_free(idp);
}

/* Sends Replace ID payload to remote end. This is used to replace old
   ID with new ID sent in the packet.  This is called for example when
   user changes nickname and we create new ID for the user.  If the 
   argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */
/* XXX It would be expected that the new id is same type as the old
   ID. :) */

void silc_server_send_replace_id(SilcServer server,
				 SilcSocketConnection sock,
				 int broadcast,
				 void *old_id, SilcIdType old_id_type,
				 unsigned int old_id_len,
				 void *new_id, SilcIdType new_id_type,
				 unsigned int new_id_len)
{
  SilcBuffer packet;
  unsigned char *oid;
  unsigned char *nid;

  SILC_LOG_DEBUG(("Start"));

  oid = silc_id_id2str(old_id, old_id_type);
  if (!oid)
    return;

  nid = silc_id_id2str(new_id, new_id_type);
  if (!nid)
    return;

  packet = silc_buffer_alloc(2 + 2 + 2 + 2 + old_id_len + new_id_len);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(old_id_type),
		     SILC_STR_UI_SHORT(old_id_len),
		     SILC_STR_UI_XNSTRING(oid, old_id_len),
		     SILC_STR_UI_SHORT(new_id_type),
		     SILC_STR_UI_SHORT(new_id_len),
		     SILC_STR_UI_XNSTRING(nid, new_id_len),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_REPLACE_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);
  silc_free(oid);
  silc_free(nid);
  silc_buffer_free(packet);
}

/* This function is used to send Remove Channel User payload. This may sent
   by server but is usually used only by router to notify other routers that
   user has left a channel. Normal server sends this packet to its router
   to notify that the router should not hold a record about this client
   on a channel anymore. Router distributes it further to other routers. */

void silc_server_send_remove_channel_user(SilcServer server,
					  SilcSocketConnection sock,
					  int broadcast,
					  void *client_id, void *channel_id)
{
  SilcBuffer packet;
  unsigned char *clid, *chid;

  SILC_LOG_DEBUG(("Start"));

  clid = silc_id_id2str(client_id, SILC_ID_CLIENT);
  if (!clid)
    return;

  chid = silc_id_id2str(channel_id, SILC_ID_CHANNEL);
  if (!chid)
    return;

  packet = silc_buffer_alloc(2 + 2 + SILC_ID_CLIENT_LEN + SILC_ID_CHANNEL_LEN);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT_LEN),
		     SILC_STR_UI_XNSTRING(clid, SILC_ID_CLIENT_LEN),
		     SILC_STR_UI_SHORT(SILC_ID_CHANNEL_LEN),
		     SILC_STR_UI_XNSTRING(chid, SILC_ID_CHANNEL_LEN),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_REMOVE_CHANNEL_USER, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);
  silc_free(clid);
  silc_free(chid);
  silc_buffer_free(packet);
}

/* Send New Channel Payload to notify about newly created channel in the
   SILC network. Normal server nevers sends this packet. Router uses this
   to notify other routers in the network about new channel. This packet
   is broadcasted. */

void silc_server_send_new_channel(SilcServer server,
				  SilcSocketConnection sock,
				  int broadcast,
				  char *channel_name,
				  void *channel_id, 
				  unsigned int channel_id_len)
{
  SilcBuffer packet;
  unsigned char *cid;
  unsigned int name_len = strlen(channel_name);

  SILC_LOG_DEBUG(("Start"));

  cid = silc_id_id2str(channel_id, SILC_ID_CHANNEL);
  if (!cid)
    return;

  packet = silc_buffer_alloc(2 + 2 + name_len + channel_id_len);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(name_len),
		     SILC_STR_UI_XNSTRING(channel_name, name_len),
		     SILC_STR_UI_SHORT(channel_id_len),
		     SILC_STR_UI_XNSTRING(cid, channel_id_len),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_NEW_CHANNEL, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);

  silc_free(cid);
  silc_buffer_free(packet);
}

/* Send New Channel User payload to notify routers in the network about new
   user on the channel. The packet is may be broadcasted. Normal server
   can send this but must not receive. Router can send and receive it. */

void silc_server_send_new_channel_user(SilcServer server,
				       SilcSocketConnection sock,
				       int broadcast,
				       void *channel_id, 
				       unsigned int channel_id_len,
				       void *client_id,
				       unsigned int client_id_len)
{
  SilcBuffer packet;
  unsigned char *clid, *chid;

  SILC_LOG_DEBUG(("Start"));

  chid = silc_id_id2str(channel_id, SILC_ID_CHANNEL);
  if (!chid)
    return;

  clid = silc_id_id2str(client_id, SILC_ID_CLIENT);
  if (!clid)
    return;

  packet = silc_buffer_alloc(2 + 2 + channel_id_len + client_id_len);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(channel_id_len),
		     SILC_STR_UI_XNSTRING(chid, channel_id_len),
		     SILC_STR_UI_SHORT(client_id_len),
		     SILC_STR_UI_XNSTRING(clid, client_id_len),
		     SILC_STR_END);

  silc_server_packet_send(server, sock, SILC_PACKET_NEW_CHANNEL_USER, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  packet->data, packet->len, FALSE);
  silc_free(clid);
  silc_free(chid);
  silc_buffer_free(packet);
}

/* Send Channel Key payload to distribute the new channel key. Normal server
   sends this to router when new client joins to existing channel. Router
   sends this to the local server who sent the join command in case where
   the channel did not exist yet. Both normal and router servers uses this
   also to send this to locally connected clients on the channel. This
   must not be broadcasted packet. Routers do not send this to each other. */

void silc_server_send_channel_key(SilcServer server,
				  SilcChannelEntry channel,
				  unsigned char route)
{
  SilcBuffer packet;
  unsigned char *chid;
  unsigned int tmp_len;
 
  SILC_LOG_DEBUG(("Start"));
 
  chid = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  if (!chid)
    return;
 
  /* Encode channel key packet */
  tmp_len = strlen(channel->channel_key->cipher->name);
  packet = silc_channel_key_payload_encode(SILC_ID_CHANNEL_LEN, chid, tmp_len,
                                           channel->channel_key->cipher->name,
                                           channel->key_len / 8, channel->key);
 
  silc_server_packet_send_to_channel(server, channel, SILC_PACKET_CHANNEL_KEY,
                                     route, packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
  silc_free(chid);
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form in correct order. */

void silc_server_send_command(SilcServer server, 
			      SilcSocketConnection sock,
			      SilcCommand command, 
			      unsigned int argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, 0, argc, ap);
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND, 0,
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);
}

/* Function used to send REMOVE_ID packet. The packet is used to notify
   routers that certain ID should be removed. After that the ID will become
   invalid.  If the argument `broadcast' is TRUE then the packet is sent as
   broadcast packet. */

void silc_server_send_remove_id(SilcServer server,
				SilcSocketConnection sock,
				int broadcast,
				void *id, unsigned int id_len,
				SilcIdType id_type)
{
  SilcBuffer idp;

  SILC_LOG_DEBUG(("Start"));

  idp = silc_id_payload_encode(id, id_type);
  silc_server_packet_send(server, sock, SILC_PACKET_REMOVE_ID, 
			  broadcast ? SILC_PACKET_FLAG_BROADCAST : 0, 
			  idp->data, idp->len, FALSE);
  silc_buffer_free(idp);
}
