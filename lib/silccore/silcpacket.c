/*

  silcpacket.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Created: Fri Jul 25 18:52:14 1997
 */
/* $Id$ */

#include "silcincludes.h"

/******************************************************************************

                          Packet Sending Routines

******************************************************************************/

/* Actually sends the packet. This flushes the connections outgoing data
   buffer. If data is sent directly to the network this returns the bytes
   written, if error occured this returns -1 and if the data could not
   be written directly to the network at this time this returns -2, in
   which case the data should be queued by the caller and sent at some
   later time. If `force_send' is TRUE this attempts to write the data
   directly to the network, if FALSE, this returns -2. */

int silc_packet_send(SilcSocketConnection sock, bool force_send)
{
  SILC_LOG_DEBUG(("Sending packet to %s:%d [%s]", sock->hostname,
		  sock->port,  
		  (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
		   sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
		   sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
		   "Router")));

  /* Send now if forced to do so */
  if (force_send == TRUE) {
    int ret;

    SILC_LOG_DEBUG(("Forcing packet send, packet sent immediately"));

    /* Write to network */
    ret = silc_socket_write(sock);

    if (ret == -1) {
      SILC_LOG_ERROR(("Error sending packet, dropped: %s", 
                      strerror(errno)));
    }
    if (ret != -2)
      return ret;

    SILC_LOG_DEBUG(("Could not force the send, packet put to queue"));
  }  

  SILC_LOG_DEBUG(("Packet in queue"));

  return -2;
}

/* Encrypts a packet. This also creates HMAC of the packet before 
   encryption and adds the HMAC at the end of the buffer. This assumes
   that there is enough free space at the end of the buffer to add the
   computed HMAC. This is the normal way of encrypting packets, if some
   other process of HMAC computing and encryption is needed this function
   cannot be used. */

void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, SilcUInt32 sequence,
			 SilcBuffer buffer, SilcUInt32 len)
{

  /* Encrypt the data area of the packet. */
  if (cipher) {
    SILC_LOG_DEBUG(("Encrypting packet (%d), cipher %s, len %d", 
		    sequence, silc_cipher_get_name(cipher), len));
    silc_cipher_encrypt(cipher, buffer->data, buffer->data, len, NULL);
  }

  /* Compute HMAC. This assumes that MAC is computed from the entire
     data area thus this uses the length found in buffer, not the length
     sent as argument. */
  if (hmac) {
    unsigned char mac[32], psn[4];
    SilcUInt32 mac_len;

    silc_hmac_init(hmac);
    SILC_PUT32_MSB(sequence, psn);
    silc_hmac_update(hmac, psn, 4);
    silc_hmac_update(hmac, buffer->data, buffer->len);
    silc_hmac_final(hmac, mac, &mac_len);

    /* Put MAC and pull the it into the visible data area in the buffer */
    silc_buffer_put_tail(buffer, mac, mac_len);
    silc_buffer_pull_tail(buffer, mac_len);
  }
}

/* Assembles a new packet to be ready for send out. */

bool silc_packet_assemble(SilcPacketContext *packet, SilcRng rng,
			  SilcCipher cipher, SilcHmac hmac,
			  SilcSocketConnection sock,
			  const unsigned char *data, SilcUInt32 data_len,
			  const SilcBuffer assembled_packet)
{ 
  unsigned char tmppad[SILC_PACKET_MAX_PADLEN];   
  int block_len = cipher ? silc_cipher_get_block_len(cipher) : 0;
  int i, ret;

  SILC_LOG_DEBUG(("Assembling outgoing packet"));

  /* Calculate the packet's length and padding length if upper layer
     didn't already do it. */

  /* Get the true length of the packet. This is saved as payload length
     into the packet header. This does not include the length of the
     padding. */
  if (!packet->truelen) {
    data_len = SILC_PACKET_DATALEN(data_len, SILC_PACKET_HEADER_LEN +
				   packet->src_id_len + packet->dst_id_len);
    packet->truelen = data_len + SILC_PACKET_HEADER_LEN + 
      packet->src_id_len + packet->dst_id_len;
  }

  /* Calculate the length of the padding. The padding is calculated from
     the data that will be encrypted. */
  if (!packet->padlen) {
    if (packet->long_pad)
      SILC_PACKET_PADLEN_MAX(packet->truelen, block_len, packet->padlen);
    else
      SILC_PACKET_PADLEN(packet->truelen, block_len, packet->padlen);
  }

  /* Now prepare the outgoing data buffer for packet sending and start
     assembling the packet. */

  /* Return pointer to the assembled packet */
  if (!silc_packet_send_prepare(sock, packet->truelen - data_len,
				packet->padlen, data_len, hmac,
				assembled_packet))
    return FALSE;

  /* Get random padding */
  if (rng)
    for (i = 0; i < packet->padlen; i++) tmppad[i] =
					   silc_rng_get_byte_fast(rng);
  else
    for (i = 0; i < packet->padlen; i++) tmppad[i] =
					   silc_rng_global_get_byte_fast();

  /* Create the packet. This creates the SILC header, adds padding, and
     the actual packet data. */
  ret =
    silc_buffer_format(assembled_packet,
		       SILC_STR_UI_SHORT(packet->truelen),
		       SILC_STR_UI_CHAR(packet->flags),
		       SILC_STR_UI_CHAR(packet->type),
		       SILC_STR_UI_CHAR(packet->padlen),
		       SILC_STR_UI_CHAR(0),
		       SILC_STR_UI_CHAR(packet->src_id_len),
		       SILC_STR_UI_CHAR(packet->dst_id_len),
		       SILC_STR_UI_CHAR(packet->src_id_type),
		       SILC_STR_UI_XNSTRING(packet->src_id,
					    packet->src_id_len),
		       SILC_STR_UI_CHAR(packet->dst_id_type),
		       SILC_STR_UI_XNSTRING(packet->dst_id,
					    packet->dst_id_len),
		       SILC_STR_UI_XNSTRING(tmppad, packet->padlen),
		       SILC_STR_UI_XNSTRING(data, data_len),
		       SILC_STR_END);
  if (ret < 0)
    return FALSE;

  SILC_LOG_HEXDUMP(("Assembled packet, len %d", assembled_packet->len),
		   assembled_packet->data, assembled_packet->len);

  return TRUE;
}

/* Prepare outgoing data buffer for packet sending. This moves the data
   area so that new packet may be added into it. If needed this allocates
   more space to the buffer. This handles directly the connection's
   outgoing buffer in SilcSocketConnection object, and returns the
   pointer to that buffer into the `packet'. */

bool silc_packet_send_prepare(SilcSocketConnection sock,
			      SilcUInt32 header_len,
			      SilcUInt32 pad_len,
			      SilcUInt32 data_len,
			      SilcHmac hmac,
			      const SilcBuffer packet)
{ 
  int totlen;
  unsigned char *oldptr;
  int mac_len = hmac ? silc_hmac_len(hmac) : 0;

  if (!packet)
    return FALSE;

  totlen = header_len + pad_len + data_len;

  /* Prepare the outgoing buffer for packet sending. */
  if (!sock->outbuf) {
    /* Allocate new buffer. This is done only once per connection. */
    SILC_LOG_DEBUG(("Allocating outgoing data buffer"));

    sock->outbuf = silc_buffer_alloc(totlen > SILC_PACKET_DEFAULT_SIZE ?
				     totlen : SILC_PACKET_DEFAULT_SIZE);
    if (!sock->outbuf)
      return FALSE;
  } else {
    if (!SILC_IS_OUTBUF_PENDING(sock)) {
      /* Buffer is free for use */
      silc_buffer_clear(sock->outbuf);
    }
  }

  /* Allocate more space if needed */
  if ((sock->outbuf->end - sock->outbuf->tail) < (totlen + mac_len)) {
    SILC_LOG_DEBUG(("Reallocating outgoing data buffer"));
    sock->outbuf = silc_buffer_realloc(sock->outbuf,
				       sock->outbuf->truelen + (totlen * 2));
    if (!sock->outbuf)
      return FALSE;
  }

  /* Pull data area for the new packet, and return pointer to the start of
     the data area and save the pointer in to the `packet'. */
  oldptr = silc_buffer_pull_tail(sock->outbuf, totlen + mac_len);
  silc_buffer_set(packet, oldptr, totlen + mac_len);
  silc_buffer_push_tail(packet, mac_len);

  return TRUE;
}

/******************************************************************************

                         Packet Reception Routines

******************************************************************************/

static int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac, 
			       SilcUInt32 sequence, SilcBuffer buffer, 
			       bool normal);
static bool silc_packet_check_mac(SilcHmac hmac,
				  const unsigned char *data,
				  SilcUInt32 data_len,
				  const unsigned char *packet_mac,
				  SilcUInt32 sequence);

/* Receives packet from network and reads the data into connection's
   incoming data buffer. If the data was read directly this returns the
   read bytes, if error occured this returns -1, if the data could not
   be read directly at this time this returns -2 in which case the data
   should be read again at some later time, or If EOF occured this returns
   0. */

int silc_packet_receive(SilcSocketConnection sock)
{
  int ret;

  SILC_LOG_DEBUG(("Receiving packet from %s:%d [%s]", sock->hostname,
		  sock->port, 
		  (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
		   sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
		   sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
		   "Router")));

  /* Read some data from connection */
  ret = silc_socket_read(sock);

  return ret;
}

/* Processes and decrypts the incmoing data, and calls parser callback
   for each received packet that will handle the actual packet parsing.
   If more than one packet was received this calls the parser multiple
   times.  The parser callback will get context SilcPacketParserContext
   that includes the packet and the `parser_context' sent to this
   function. 
   
   The `local_is_router' indicates whether the caller is router server
   in which case the receiving process of a certain packet types may
   be special.  Normal server and client must set it to FALSE.  The
   SilcPacketParserContext will indicate also whether the received
   packet was normal or special packet. */

bool silc_packet_receive_process(SilcSocketConnection sock,
				 bool local_is_router,
				 SilcCipher cipher, SilcHmac hmac,
				 SilcUInt32 sequence,
				 SilcPacketParserCallback parser,
				 void *parser_context)
{
  SilcPacketParserContext *parse_ctx;
  int packetlen, paddedlen, mac_len = 0, ret, block_len;
  bool cont = TRUE;
  unsigned char tmp[SILC_PACKET_MIN_HEADER_LEN], *header;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];

  /* Do not process for disconnected connection */
  if (SILC_IS_DISCONNECTED(sock))
    return TRUE;

  if (sock->inbuf->len < SILC_PACKET_MIN_HEADER_LEN)
    return TRUE;

  if (hmac)
    mac_len = silc_hmac_len(hmac);

  /* Parse the packets from the data */
  while (sock->inbuf->len > 0 && cont) {

    if (sock->inbuf->len < SILC_PACKET_MIN_HEADER_LEN) {
      SILC_LOG_DEBUG(("Partial packet in queue, waiting for the rest"));
      return TRUE;
    }

    /* Decrypt first block of the packet to get the length field out */
    if (cipher) {
      block_len = silc_cipher_get_block_len(cipher);
      memcpy(iv, silc_cipher_get_iv(cipher), block_len);
      silc_cipher_decrypt(cipher, sock->inbuf->data, tmp, block_len, iv);
      header = tmp;
    } else {
      block_len = SILC_PACKET_MIN_HEADER_LEN;
      header = sock->inbuf->data;
    }

    /* Get packet lenght and full packet length with padding */
    SILC_PACKET_LENGTH(header, packetlen, paddedlen);

    /* Sanity checks */
    if (packetlen < SILC_PACKET_MIN_LEN) {
      SILC_LOG_ERROR(("Received too short packet"));
      memset(header, 0, sizeof(header));
      silc_buffer_clear(sock->inbuf);
      return FALSE;
    }

    if (sock->inbuf->len < paddedlen + mac_len) {
      SILC_LOG_DEBUG(("Received partial packet, waiting for the rest "
		      "(%d bytes)", paddedlen + mac_len - sock->inbuf->len));
      SILC_SET_INBUF_PENDING(sock);
      memset(tmp, 0, sizeof(tmp));
      return TRUE;
    }

    /* Check MAC of the packet */
    if (!silc_packet_check_mac(hmac, sock->inbuf->data, paddedlen,
			       sock->inbuf->data + paddedlen, sequence)) {
      SILC_LOG_WARNING(("Packet MAC check failed %s:%d [%s] [%s]", 
			sock->hostname, sock->port,
			silc_get_packet_name(header[3]),
			(sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
			 sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
			 sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
			 "Router")));
      memset(tmp, 0, sizeof(tmp));
      silc_buffer_clear(sock->inbuf);
      return FALSE;
    }

    SILC_UNSET_INBUF_PENDING(sock);
    parse_ctx = silc_calloc(1, sizeof(*parse_ctx));
    if (!parse_ctx)
      return FALSE;
    parse_ctx->packet = silc_packet_context_alloc();
    parse_ctx->packet->buffer = silc_buffer_alloc_size(paddedlen);
    parse_ctx->packet->type = header[3];
    parse_ctx->packet->padlen = header[4];
    parse_ctx->packet->sequence = sequence++;
    parse_ctx->sock = sock;
    parse_ctx->context = parser_context;

    /* Check whether this is normal or special packet */
    if (local_is_router) {
      if (header[3] == SILC_PACKET_PRIVATE_MESSAGE &&
	  (header[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
	parse_ctx->normal = FALSE;
      else if (header[3] != SILC_PACKET_CHANNEL_MESSAGE || 
	       (header[3] == SILC_PACKET_CHANNEL_MESSAGE &&
		sock->type == SILC_SOCKET_TYPE_ROUTER))
	parse_ctx->normal = TRUE;
    } else {
      if (header[3] == SILC_PACKET_PRIVATE_MESSAGE &&
	  (header[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
	parse_ctx->normal = FALSE;
      else if (header[3] != SILC_PACKET_CHANNEL_MESSAGE)
	parse_ctx->normal = TRUE;
    }

    SILC_LOG_HEXDUMP(("Incoming packet (%d) len %d",
		      sequence - 1, paddedlen + mac_len),
		     sock->inbuf->data, paddedlen + mac_len);

    /* Put the decrypted part, and rest of the encrypted data, and decrypt */
    silc_buffer_put(parse_ctx->packet->buffer, header, block_len);
    silc_buffer_pull(parse_ctx->packet->buffer, block_len);
    silc_buffer_put(parse_ctx->packet->buffer, sock->inbuf->data + block_len,
		    paddedlen - block_len);
    if (cipher) {
      silc_cipher_set_iv(cipher, iv);
      ret = silc_packet_decrypt(cipher, hmac, parse_ctx->packet->sequence, 
				parse_ctx->packet->buffer, 
				parse_ctx->normal);
      if (ret < 0) {
	SILC_LOG_WARNING(("Packet decryption failed %s:%d [%s] [%s]", 
			  sock->hostname, sock->port,
			  silc_get_packet_name(parse_ctx->packet->type),
			  (sock->type == SILC_SOCKET_TYPE_UNKNOWN ? "Unknown" :
			   sock->type == SILC_SOCKET_TYPE_CLIENT ? "Client" :
			   sock->type == SILC_SOCKET_TYPE_SERVER ? "Server" :
			   "Router")));
	memset(tmp, 0, sizeof(tmp));
	silc_packet_context_free(parse_ctx->packet);
	silc_free(parse_ctx);
	return FALSE;
      }
    }
    silc_buffer_push(parse_ctx->packet->buffer, block_len);

    SILC_LOG_HEXDUMP(("Fully decrypted packet, len %d",
		      parse_ctx->packet->buffer->len), 
		     parse_ctx->packet->buffer->data,
		     parse_ctx->packet->buffer->len);

    /* Pull the packet from inbuf thus we'll get the next one
       in the inbuf. */
    silc_buffer_pull(sock->inbuf, paddedlen + mac_len);

    /* Call the parser */
    cont = (*parser)(parse_ctx, parser_context);
    memset(tmp, 0, sizeof(tmp));
  }

  if (cont == FALSE && sock->inbuf->len > 0)
    return TRUE;

  SILC_LOG_DEBUG(("Clearing inbound buffer"));
  silc_buffer_clear(sock->inbuf);
  return TRUE;
}

/* Checks MAC in the packet. Returns TRUE if MAC is Ok. */

static bool silc_packet_check_mac(SilcHmac hmac,
				  const unsigned char *data,
				  SilcUInt32 data_len,
				  const unsigned char *packet_mac,
				  SilcUInt32 sequence)
{
  /* Check MAC */
  if (hmac) {
    unsigned char mac[32], psn[4];
    SilcUInt32 mac_len;
    
    SILC_LOG_DEBUG(("Verifying MAC"));

    /* Compute HMAC of packet */
    silc_hmac_init(hmac);
    SILC_PUT32_MSB(sequence, psn);
    silc_hmac_update(hmac, psn, 4);
    silc_hmac_update(hmac, data, data_len);
    silc_hmac_final(hmac, mac, &mac_len);

    /* Compare the MAC's */
    if (memcmp(packet_mac, mac, mac_len)) {
      SILC_LOG_ERROR(("MAC failed"));
      return FALSE;
    }
    
    SILC_LOG_DEBUG(("MAC is Ok"));
  }
  
  return TRUE;
}

/* Decrypts SILC packet.  Handles both normal and special packet decryption.
   Return 0 when packet is normal and 1 when it it special, -1 on error. */

static int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
			       SilcUInt32 sequence, SilcBuffer buffer, 
			       bool normal)
{
  /* If the packet type is not any special type lets decrypt rest
     of the packet here. */
  if (normal == TRUE) {
    if (cipher) {
      /* Decrypt rest of the packet */
      SILC_LOG_DEBUG(("Decrypting the packet"));
      if (!silc_cipher_decrypt(cipher, buffer->data, buffer->data,
			       buffer->len, NULL)) {
	SILC_LOG_ERROR(("silc_cipher_decrypt failed"));
	return -1;
      }
    }
    return 0;

  } else {
    /* Decrypt rest of the header plus padding */
    if (cipher) {
      SilcUInt16 len;
      int block_len = silc_cipher_get_block_len(cipher);

      SILC_LOG_DEBUG(("Decrypting the header"));

      /* padding length + src id len + dst id len + header length - 16
	 bytes already decrypted, gives the rest of the encrypted packet */
      silc_buffer_push(buffer, block_len);
      len = (((SilcUInt8)buffer->data[4] + (SilcUInt8)buffer->data[6] + 
	      (SilcUInt8)buffer->data[7] + SILC_PACKET_HEADER_LEN) -
	     block_len);

      if (len > buffer->len) {
	SILC_LOG_ERROR(("Garbage in header of packet, bad packet length, "
			"packet dropped"));
	return -1;
      }
      silc_buffer_pull(buffer, block_len);
      if (!silc_cipher_decrypt(cipher, buffer->data, buffer->data,
			       len, NULL)) {
	SILC_LOG_ERROR(("silc_cipher_decrypt failed"));
	return -1;
      }
    }

    return 1;
  }
}

/* Parses the packet. This is called when a whole packet is ready to be
   parsed. The buffer sent must be already decrypted before calling this 
   function. The len argument must be the true length of the packet. This 
   function returns the type of the packet. The data section of the 
   buffer is parsed, not head or tail sections. */

SilcPacketType silc_packet_parse(SilcPacketContext *ctx, SilcCipher cipher)
{
  SilcBuffer buffer = ctx->buffer;
  SilcUInt8 tmp;
  int len, ret;
  SilcUInt8 src_id_len, src_id_type, dst_id_len, dst_id_type, padlen;

  SILC_LOG_DEBUG(("Parsing incoming packet"));

  /* Check the length of the buffer */
  if (buffer->len < SILC_PACKET_MIN_LEN) {
    SILC_LOG_ERROR(("Bad packet length: %d, packet dropped", buffer->len));
    return SILC_PACKET_NONE;
  }

  /* Parse the buffer. This parses the SILC header of the packet. */
  len = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_SHORT(&ctx->truelen),
			     SILC_STR_UI_CHAR(&ctx->flags),
			     SILC_STR_UI_CHAR(&ctx->type),
			     SILC_STR_UI_CHAR(&padlen),
			     SILC_STR_UI_CHAR(&tmp),
			     SILC_STR_UI_CHAR(&src_id_len),
			     SILC_STR_UI_CHAR(&dst_id_len),
			     SILC_STR_UI_CHAR(&src_id_type),
			     SILC_STR_END);
  if (len == -1 || tmp != 0)
    return SILC_PACKET_NONE;

  if (src_id_len > SILC_PACKET_MAX_ID_LEN ||
      dst_id_len > SILC_PACKET_MAX_ID_LEN) {
    SILC_LOG_ERROR(("Bad ID lengths in packet (%d and %d)",
		    src_id_len, dst_id_len));
    return SILC_PACKET_NONE;
  }

  silc_buffer_pull(buffer, len);
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->src_id,
							src_id_len),
			     SILC_STR_UI_CHAR(&dst_id_type),
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->dst_id,
							dst_id_len),
			     SILC_STR_UI_XNSTRING(NULL, padlen),
			     SILC_STR_END);
  if (ret == -1)
    return SILC_PACKET_NONE;

  if (src_id_type > SILC_ID_CHANNEL || dst_id_type > SILC_ID_CHANNEL) {
    SILC_LOG_ERROR(("Bad ID types in packet (%d and %d)",
		   src_id_type, dst_id_type));
    return SILC_PACKET_NONE;
  }

  ctx->src_id_len = src_id_len;
  ctx->dst_id_len = dst_id_len;
  ctx->src_id_type = src_id_type;
  ctx->dst_id_type = dst_id_type;
  ctx->padlen = padlen;

  silc_buffer_push(buffer, len);

  SILC_LOG_HEXDUMP(("parsed packet, len %d", ctx->buffer->len), 
		   ctx->buffer->data, ctx->buffer->len);

  /* Pull SILC header and padding from packet */
  silc_buffer_pull(buffer, SILC_PACKET_HEADER_LEN +
		   ctx->src_id_len + ctx->dst_id_len + ctx->padlen);

  SILC_LOG_DEBUG(("Incoming packet type: %d", ctx->type));

  return ctx->type;
}

/* Perform special SILC Packet header parsing. This is required to some
   packet types that have the data payload encrypted with different key
   than the header area plus padding of the packet. Hence, this parses
   the header in a way that it does not take the data area into account
   and parses the header and padding area only. */

SilcPacketType silc_packet_parse_special(SilcPacketContext *ctx,
					 SilcCipher cipher)
{
  SilcBuffer buffer = ctx->buffer;
  SilcUInt8 tmp;
  int len, ret;
  SilcUInt8 src_id_len, src_id_type, dst_id_len, dst_id_type, padlen;

  SILC_LOG_DEBUG(("Parsing incoming packet"));

  /* Check the length of the buffer */
  if (buffer->len < SILC_PACKET_MIN_LEN) {
    SILC_LOG_ERROR(("Bad packet length: %d, packet dropped", buffer->len));
    return SILC_PACKET_NONE;
  }

  /* Parse the buffer. This parses the SILC header of the packet. */
  len = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_SHORT(&ctx->truelen),
			     SILC_STR_UI_CHAR(&ctx->flags),
			     SILC_STR_UI_CHAR(&ctx->type),
			     SILC_STR_UI_CHAR(&padlen),
			     SILC_STR_UI_CHAR(&tmp),
			     SILC_STR_UI_CHAR(&src_id_len),
			     SILC_STR_UI_CHAR(&dst_id_len),
			     SILC_STR_UI_CHAR(&src_id_type),
			     SILC_STR_END);
  if (len == -1 || tmp != 0) {
    SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return SILC_PACKET_NONE;
  }

  if (src_id_len > SILC_PACKET_MAX_ID_LEN ||
      dst_id_len > SILC_PACKET_MAX_ID_LEN) {
    SILC_LOG_ERROR(("Bad ID lengths in packet (%d and %d)",
		    src_id_len, dst_id_len));
    return SILC_PACKET_NONE;
  }

  silc_buffer_pull(buffer, len);
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->src_id,
							src_id_len),
			     SILC_STR_UI_CHAR(&dst_id_type),
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->dst_id,
							dst_id_len),
			     SILC_STR_UI_XNSTRING(NULL, padlen),
			     SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return SILC_PACKET_NONE;
  }

  if (src_id_type > SILC_ID_CHANNEL || dst_id_type > SILC_ID_CHANNEL) {
    SILC_LOG_ERROR(("Bad ID types in packet (%d and %d)",
		   src_id_type, dst_id_type));
    return SILC_PACKET_NONE;
  }

  ctx->src_id_len = src_id_len;
  ctx->dst_id_len = dst_id_len;
  ctx->src_id_type = src_id_type;
  ctx->dst_id_type = dst_id_type;
  ctx->padlen = padlen;

  silc_buffer_push(buffer, len);

  SILC_LOG_HEXDUMP(("parsed packet, len %d", ctx->buffer->len), 
		   ctx->buffer->data, ctx->buffer->len);

  /* Pull SILC header and padding from packet */
  silc_buffer_pull(buffer, SILC_PACKET_HEADER_LEN +
		   ctx->src_id_len + ctx->dst_id_len + ctx->padlen);

  SILC_LOG_DEBUG(("Incoming packet type: %d", ctx->type));

  return ctx->type;
}

/* Allocate packet context */

SilcPacketContext *silc_packet_context_alloc(void)
{
  SilcPacketContext *ctx = silc_calloc(1, sizeof(*ctx));
  if (!ctx)
    return NULL;
  ctx->users++;
  return ctx;
}

/* Increse the reference count of the packet context. */

SilcPacketContext *silc_packet_context_dup(SilcPacketContext *ctx)
{
  ctx->users++;
  SILC_LOG_DEBUG(("Packet context %p refcnt %d->%d", ctx, ctx->users - 1,
		  ctx->users));
  return ctx;
}

/* Decrese the reference count of the packet context and free it only if
   it is zero. */

void silc_packet_context_free(SilcPacketContext *ctx)
{
  ctx->users--;
  SILC_LOG_DEBUG(("Packet context %p refcnt %d->%d", ctx, ctx->users + 1,
		  ctx->users));
  if (ctx->users < 1)
    {
      if (ctx->buffer)
	silc_buffer_free(ctx->buffer);
      if (ctx->src_id)
	silc_free(ctx->src_id);
      if (ctx->dst_id)
	silc_free(ctx->dst_id);
      silc_free(ctx);
    }
}
