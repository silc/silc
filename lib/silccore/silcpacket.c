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
      SILC_LOG_ERROR(("Error sending packet, dropped"));
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

void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, uint32 sequence,
			 SilcBuffer buffer, uint32 len)
{
  unsigned char mac[32];
  uint32 mac_len;

  /* Compute HMAC. This assumes that HMAC is created from the entire
     data area thus this uses the length found in buffer, not the length
     sent as argument. */
  if (hmac) {
    unsigned char psn[4];

    silc_hmac_init(hmac);
    SILC_PUT32_MSB(sequence, psn);
    silc_hmac_update(hmac, psn, 4);
    silc_hmac_update(hmac, buffer->data, buffer->len);
    silc_hmac_final(hmac, mac, &mac_len);
    silc_buffer_put_tail(buffer, mac, mac_len);
    memset(mac, 0, sizeof(mac));
  }

  /* Encrypt the data area of the packet. */
  if (cipher) {
    SILC_LOG_DEBUG(("Encrypting packet, cipher %s, len %d", 
		    cipher->cipher->name, len));
    silc_cipher_encrypt(cipher, buffer->data, buffer->data, len, cipher->iv);
  }

  /* Pull the HMAC into the visible data area in the buffer */
  if (hmac)
    silc_buffer_pull_tail(buffer, mac_len);
}

/* Assembles a new packet to be ready for send out. The buffer sent as
   argument must include the data to be sent and it must not be encrypted. 
   The packet also must have enough free space so that the SILC header
   and padding maybe added to the packet. The packet is encrypted after 
   this function has returned.

   The buffer sent as argument should be something like following:

   --------------------------------------------
   | head             | data           | tail |
   --------------------------------------------
   ^                  ^
   58 bytes           x bytes

   So that the SILC header and 1 - 16 bytes of padding can fit to
   the buffer. After assembly the buffer might look like this:

   --------------------------------------------
   | data                              |      |
   --------------------------------------------
   ^                                   ^
   Start of assembled packet

   Packet construct is as follows:

   n bytes       SILC Header
      2 bytes     Payload length
      1 byte      Flags
      1 byte      Packet type
      1 byte      Padding length
      1 byte      RESERVED
      1 bytes     Source ID Length
      1 bytes     Destination ID Length
      1 byte      Source ID Type
      n bytes     Source ID
      1 byte      Destination ID Type
      n bytes     Destination ID

   1 - 16 bytes    Padding

   n bytes        Data payload

   All fields in the packet will be authenticated by MAC. The MAC is
   not computed here, it must be computed separately before encrypting
   the packet.

*/

void silc_packet_assemble(SilcPacketContext *ctx, SilcCipher cipher)
{
  unsigned char tmppad[SILC_PACKET_MAX_PADLEN];
  int block_len = cipher ? silc_cipher_get_block_len(cipher) : 0;
  int i;

  SILC_LOG_DEBUG(("Assembling outgoing packet"));
  
  /* Get the true length of the packet. This is saved as payload length
     into the packet header. This does not include the length of the
     padding. */
  if (!ctx->truelen)
    ctx->truelen = ctx->buffer->len + SILC_PACKET_HEADER_LEN + 
      ctx->src_id_len + ctx->dst_id_len;

  /* Calculate the length of the padding. The padding is calculated from
     the data that will be encrypted. */
  if (!ctx->padlen) {
    if (ctx->long_pad)
      ctx->padlen = SILC_PACKET_PADLEN_MAX(ctx->truelen);
    else
      ctx->padlen = SILC_PACKET_PADLEN(ctx->truelen, block_len);
  }

  /* Put the start of the data section to the right place. */
  silc_buffer_push(ctx->buffer, SILC_PACKET_HEADER_LEN + 
		   ctx->src_id_len + ctx->dst_id_len + ctx->padlen);

  /* Get random padding */
#if 1
  for (i = 0; i < ctx->padlen; i++) tmppad[i] = silc_rng_global_get_byte();
#else
  /* XXX: For testing - to be removed */
  memset(tmppad, 65, sizeof(tmppad));
#endif

  /* Create the packet. This creates the SILC header and adds padding,
     rest of the buffer remains as it is. */
  silc_buffer_format(ctx->buffer, 
		     SILC_STR_UI_SHORT(ctx->truelen),
		     SILC_STR_UI_CHAR(ctx->flags),
		     SILC_STR_UI_CHAR(ctx->type),
		     SILC_STR_UI_CHAR(ctx->padlen),
		     SILC_STR_UI_CHAR(0),
		     SILC_STR_UI_CHAR(ctx->src_id_len),
		     SILC_STR_UI_CHAR(ctx->dst_id_len),
		     SILC_STR_UI_CHAR(ctx->src_id_type),
		     SILC_STR_UI_XNSTRING(ctx->src_id, ctx->src_id_len),
		     SILC_STR_UI_CHAR(ctx->dst_id_type),
		     SILC_STR_UI_XNSTRING(ctx->dst_id, ctx->dst_id_len),
		     SILC_STR_UI_XNSTRING(tmppad, ctx->padlen),
		     SILC_STR_END);

  SILC_LOG_HEXDUMP(("Assembled packet, len %d", ctx->buffer->len), 
		   ctx->buffer->data, ctx->buffer->len);

  SILC_LOG_DEBUG(("Outgoing packet assembled"));
}

/* Prepare outgoing data buffer for packet sending. This moves the data
   area so that new packet may be added into it. If needed this allocates
   more space to the buffer. This handles directly the connection's
   outgoing buffer in SilcSocketConnection object. */

void silc_packet_send_prepare(SilcSocketConnection sock,
			      uint32 header_len,
			      uint32 padlen,
			      uint32 data_len)
{
  int totlen, oldlen;

  totlen = header_len + padlen + data_len;

  /* Prepare the outgoing buffer for packet sending. */
  if (!sock->outbuf) {
    /* Allocate new buffer. This is done only once per connection. */
    SILC_LOG_DEBUG(("Allocating outgoing data buffer"));
    
    if (totlen > SILC_PACKET_DEFAULT_SIZE)
      sock->outbuf = silc_buffer_alloc(totlen);
    else
      sock->outbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);
    silc_buffer_pull_tail(sock->outbuf, totlen);
    silc_buffer_pull(sock->outbuf, header_len + padlen);
  } else {
    if (SILC_IS_OUTBUF_PENDING(sock)) {
      /* There is some pending data in the buffer. */

      /* Allocate more space if needed */
      if ((sock->outbuf->end - sock->outbuf->tail) < 
	  (totlen + 20)) {
	SILC_LOG_DEBUG(("Reallocating outgoing data buffer"));
	sock->outbuf = silc_buffer_realloc(sock->outbuf, 
					   sock->outbuf->truelen +
					   (totlen * 2));
      }

      oldlen = sock->outbuf->len;
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen + oldlen);
    } else {
      /* Buffer is free for use */
      silc_buffer_clear(sock->outbuf);

      /* Allocate more space if needed */
      if ((sock->outbuf->end - sock->outbuf->tail) < (totlen + 20)) {
	SILC_LOG_DEBUG(("Reallocating outgoing data buffer"));
	sock->outbuf = silc_buffer_realloc(sock->outbuf, 
					   sock->outbuf->truelen + 
					   (totlen * 2));
      }

      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen);
    }
  }
}

/******************************************************************************

                         Packet Reception Routines

******************************************************************************/

static int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac, 
			       uint32 sequence, SilcBuffer buffer, 
			       bool normal);

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

void silc_packet_receive_process(SilcSocketConnection sock,
				 bool local_is_router,
				 SilcCipher cipher, SilcHmac hmac,
				 uint32 sequence,
				 SilcPacketParserCallback parser,
				 void *parser_context)
{
  SilcPacketParserContext *parse_ctx;
  int packetlen, paddedlen, mac_len = 0;
  int block_len = cipher ? silc_cipher_get_block_len(cipher) : 0;

  if (sock->inbuf->len < SILC_PACKET_MIN_HEADER_LEN)
    return;

  if (hmac)
    mac_len = silc_hmac_len(hmac);

  /* Parse the packets from the data */
  while (sock->inbuf->len > 0) {

    /* Decrypt first 16 bytes of the packet */
    if (!SILC_IS_INBUF_PENDING(sock) && cipher)
      silc_cipher_decrypt(cipher, sock->inbuf->data, sock->inbuf->data, 
			  SILC_PACKET_MIN_HEADER_LEN, cipher->iv);

    /* Get packet lenght and full packet length with padding */
    SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);

    /* Sanity checks */
    if (packetlen < SILC_PACKET_MIN_LEN) {
      SILC_LOG_DEBUG(("Received invalid packet, dropped"));
      silc_buffer_clear(sock->inbuf);
      return;
    }

    if (sock->inbuf->len < paddedlen + mac_len) {
      SILC_LOG_DEBUG(("Received partial packet, waiting for the rest"
		      "(%d < %d)", sock->inbuf->len, paddedlen + mac_len));
      SILC_SET_INBUF_PENDING(sock);
      return;
    }

    SILC_UNSET_INBUF_PENDING(sock);
    parse_ctx = silc_calloc(1, sizeof(*parse_ctx));
    parse_ctx->packet = silc_packet_context_alloc();
    parse_ctx->packet->buffer = silc_buffer_alloc(paddedlen + mac_len);
    parse_ctx->packet->padlen = sock->inbuf->data[4];
    parse_ctx->packet->sequence = sequence++;
    parse_ctx->sock = sock;
    parse_ctx->context = parser_context;

    silc_buffer_pull_tail(parse_ctx->packet->buffer, 
			  SILC_BUFFER_END(parse_ctx->packet->buffer));
    silc_buffer_put(parse_ctx->packet->buffer, sock->inbuf->data, 
    		    paddedlen + mac_len);

    SILC_LOG_HEXDUMP(("Incoming packet (%d) (%d bytes decrypted), len %d", 
		      sequence - 1, block_len, paddedlen + mac_len),
		     sock->inbuf->data, paddedlen + mac_len);

    /* Check whether this is normal or special packet */
    if (local_is_router) {
      if (sock->inbuf->data[3] == SILC_PACKET_PRIVATE_MESSAGE &&
	  (sock->inbuf->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
	parse_ctx->normal = FALSE;
      else if (sock->inbuf->data[3] != SILC_PACKET_CHANNEL_MESSAGE || 
	       (sock->inbuf->data[3] == SILC_PACKET_CHANNEL_MESSAGE &&
		sock->type == SILC_SOCKET_TYPE_ROUTER))
	parse_ctx->normal = TRUE;
    } else {
      if (sock->inbuf->data[3] == SILC_PACKET_PRIVATE_MESSAGE &&
	  (sock->inbuf->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
	parse_ctx->normal = FALSE;
      else if (sock->inbuf->data[3] != SILC_PACKET_CHANNEL_MESSAGE)
	parse_ctx->normal = TRUE;
    }

    /* Decrypt rest of the packet */
    if (cipher)
      silc_packet_decrypt(cipher, hmac, parse_ctx->packet->sequence, 
			  parse_ctx->packet->buffer, parse_ctx->normal);

    /* Call the parser */
    if (parser)
      (*parser)(parse_ctx, parser_context);

    /* Pull the packet from inbuf thus we'll get the next one
       in the inbuf. */
    silc_buffer_pull(sock->inbuf, paddedlen + mac_len);
  }

  SILC_LOG_DEBUG(("Clearing inbound buffer"));
  silc_buffer_clear(sock->inbuf);
}

/* Checks MAC in the packet. Returns TRUE if MAC is Ok. This is called
   after packet has been totally decrypted and parsed. */

static int silc_packet_check_mac(SilcHmac hmac, SilcBuffer buffer,
				 uint32 sequence)
{
  /* Check MAC */
  if (hmac) {
    unsigned char mac[32], psn[4];
    uint32 mac_len;
    
    SILC_LOG_DEBUG(("Verifying MAC"));

    /* Compute HMAC of packet */

    memset(mac, 0, sizeof(mac));
    silc_hmac_init(hmac);
    SILC_PUT32_MSB(sequence, psn);
    silc_hmac_update(hmac, psn, 4);
    silc_hmac_update(hmac, buffer->data, buffer->len);
    silc_hmac_final(hmac, mac, &mac_len);

    /* Compare the HMAC's (buffer->tail has the packet's HMAC) */
    if (memcmp(mac, buffer->tail, mac_len)) {
      SILC_LOG_ERROR(("MAC failed"));
      assert(FALSE);
      return FALSE;
    }
    
    SILC_LOG_DEBUG(("MAC is Ok"));
    memset(mac, 0, sizeof(mac));
  }
  
  return TRUE;
}

/* Decrypts rest of the packet (after decrypting just the SILC header).
   After calling this function the packet is ready to be parsed by calling 
   silc_packet_parse. If everything goes without errors this returns TRUE,
   if packet is malformed this returns FALSE. */

static int silc_packet_decrypt_rest(SilcCipher cipher, SilcHmac hmac,
				    SilcBuffer buffer)
{
  if (cipher) {

    /* Pull MAC from packet before decryption */
    if (hmac) {
      if ((buffer->len - silc_hmac_len(hmac)) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, silc_hmac_len(hmac));
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }

    SILC_LOG_DEBUG(("Decrypting rest of the packet"));

    /* Decrypt rest of the packet */
    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN);
    silc_cipher_decrypt(cipher, buffer->data, buffer->data, buffer->len, 
			cipher->iv);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN);

    SILC_LOG_HEXDUMP(("Fully decrypted packet, len %d", buffer->len),
		     buffer->data, buffer->len);
  }

  return TRUE;
}

/* Decrypts rest of the SILC Packet header that has been decrypted partly
   already. This decrypts the padding of the packet also. After calling 
   this function the packet is ready to be parsed by calling function 
   silc_packet_parse. This is used in special packet reception (protocol
   defines the way of decrypting special packets). */

static int silc_packet_decrypt_rest_special(SilcCipher cipher,
					    SilcHmac hmac,
					    SilcBuffer buffer)
{
  /* Decrypt rest of the header plus padding */
  if (cipher) {
    uint16 len;

    /* Pull MAC from packet before decryption */
    if (hmac) {
      if ((buffer->len - silc_hmac_len(hmac)) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, silc_hmac_len(hmac));
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }
  
    SILC_LOG_DEBUG(("Decrypting rest of the header"));

    /* padding length + src id len + dst id len + header length - 16
       bytes already decrypted, gives the rest of the encrypted packet */
    len = (((uint8)buffer->data[4] + (uint8)buffer->data[6] + 
	   (uint8)buffer->data[7] + SILC_PACKET_HEADER_LEN) -
	   SILC_PACKET_MIN_HEADER_LEN);

    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN);
    if (len > buffer->len) {
      SILC_LOG_DEBUG(("Garbage in header of packet, bad packet length, "
		      "packet dropped"));
      return FALSE;
    }
    silc_cipher_decrypt(cipher, buffer->data, buffer->data, len, cipher->iv);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN);
    SILC_LOG_HEXDUMP(("packet, len %d", buffer->len), 
		     buffer->data, buffer->len);
  }

  return TRUE;
}

/* Decrypts a packet. This assumes that typical SILC packet is the
   packet to be decrypted and thus checks for normal and special SILC
   packets and can handle both of them. This also computes and checks
   the HMAC of the packet. If any other special or customized decryption
   processing is required this function cannot be used. This returns
   -1 on error, 0 when packet is normal packet and 1 when the packet
   is special and requires special processing. 

   The `check_packet' is a callback funtion that this function will 
   call.  The callback relates to the checking whether the packet is
   normal packet or special packet and how it should be processed.  If
   the callback return TRUE the packet is normal and FALSE if the packet
   is special and requires special procesing. */

static int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
			       uint32 sequence, SilcBuffer buffer, 
			       bool normal)
{
  /* If the packet type is not any special type lets decrypt rest
     of the packet here. */
  if (normal == TRUE) {
    /* Normal packet, decrypt rest of the packet */
    if (!silc_packet_decrypt_rest(cipher, hmac, buffer))
      return -1;

    /* Check MAC */
    if (!silc_packet_check_mac(hmac, buffer, sequence))
      return -1;

    return 0;
  } else {
    /* Packet requires special handling, decrypt rest of the header.
       This only decrypts. */
    if (!silc_packet_decrypt_rest_special(cipher, hmac, buffer))
      return -1;

    /* Check MAC */
    if (!silc_packet_check_mac(hmac, buffer, sequence))
      return -1;

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
  uint8 tmp;
  int len, ret;

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
			     SILC_STR_UI_CHAR(&ctx->padlen),
			     SILC_STR_UI_CHAR(&tmp),
			     SILC_STR_UI_CHAR(&ctx->src_id_len),
			     SILC_STR_UI_CHAR(&ctx->dst_id_len),
			     SILC_STR_UI_CHAR(&ctx->src_id_type),
			     SILC_STR_END);
  if (len == -1 || tmp != 0)
    return SILC_PACKET_NONE;

  if (ctx->src_id_len > SILC_PACKET_MAX_ID_LEN ||
      ctx->dst_id_len > SILC_PACKET_MAX_ID_LEN) {
    SILC_LOG_ERROR(("Bad ID lengths in packet (%d and %d)",
		    ctx->src_id_len, ctx->dst_id_len));
    return SILC_PACKET_NONE;
  }

  silc_buffer_pull(buffer, len);
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->src_id,
							ctx->src_id_len),
			     SILC_STR_UI_CHAR(&ctx->dst_id_type),
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->dst_id,
							ctx->dst_id_len),
			     SILC_STR_UI_XNSTRING(NULL, ctx->padlen),
			     SILC_STR_END);
  if (ret == -1)
    return SILC_PACKET_NONE;

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
  uint8 tmp;
  int len, ret;

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
			     SILC_STR_UI_CHAR(&ctx->padlen),
			     SILC_STR_UI_CHAR(&tmp),
			     SILC_STR_UI_CHAR(&ctx->src_id_len),
			     SILC_STR_UI_CHAR(&ctx->dst_id_len),
			     SILC_STR_UI_CHAR(&ctx->src_id_type),
			     SILC_STR_END);
  if (len == -1 || tmp != 0) {
    SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return SILC_PACKET_NONE;
  }

  if (ctx->src_id_len > SILC_PACKET_MAX_ID_LEN ||
      ctx->dst_id_len > SILC_PACKET_MAX_ID_LEN) {
    SILC_LOG_ERROR(("Bad ID lengths in packet (%d and %d)",
		    ctx->src_id_len, ctx->dst_id_len));
    return SILC_PACKET_NONE;
  }

  silc_buffer_pull(buffer, len);
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->src_id,
							ctx->src_id_len),
			     SILC_STR_UI_CHAR(&ctx->dst_id_type),
			     SILC_STR_UI_XNSTRING_ALLOC(&ctx->dst_id,
							ctx->dst_id_len),
			     SILC_STR_UI_XNSTRING(NULL, ctx->padlen),
			     SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_ERROR(("Malformed packet header, packet dropped"));
    return SILC_PACKET_NONE;
  }

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
