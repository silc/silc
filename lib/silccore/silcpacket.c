/*

  silcpacket.c

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
 * Created: Fri Jul 25 18:52:14 1997
 */
/* $Id$ */

#include "silcincludes.h"

/******************************************************************************

                          Packet Sending Routines

******************************************************************************/

/* Writes data from encrypted buffer to the socket connection. If the
   data cannot be written at once, it will be written later with a timeout. 
   The data is written from the data section of the buffer, not from head
   or tail section. This automatically pulls the data section towards end
   after writing the data. */

int silc_packet_write(int sock, SilcBuffer src)
{
  int ret = 0;

  SILC_LOG_DEBUG(("Writing data to socket %d", sock));

  if (src->len > 0) {
    ret = write(sock, src->data, src->len);
    if (ret < 0) {
      if (errno == EAGAIN) {
	SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
	return -2;
      }
      SILC_LOG_ERROR(("Cannot write to socket: %s", strerror(errno)));
      return -1;
    }

    silc_buffer_pull(src, ret);
  }

  SILC_LOG_DEBUG(("Wrote data %d bytes", ret));

  return ret;
}

/* Actually sends the packet. This flushes the connections outgoing data
   buffer. If data is sent directly to the network this returns the bytes
   written, if error occured this returns -1 and if the data could not
   be written directly to the network at this time this returns -2, in
   which case the data should be queued by the caller and sent at some
   later time. If `force_send' is TRUE this attempts to write the data
   directly to the network, if FALSE, this returns -2. */

int silc_packet_send(SilcSocketConnection sock, int force_send)
{
  /* Send now if forced to do so */
  if (force_send == TRUE) {
    int ret;

    SILC_LOG_DEBUG(("Forcing packet send, packet sent immediately"));

    /* Write to network */
    ret = silc_packet_write(sock->sock, sock->outbuf);

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

void silc_packet_encrypt(SilcCipher cipher, SilcHmac hmac, 
			 SilcBuffer buffer, unsigned int len)
{
  unsigned char mac[32];

  if (cipher) {
    SILC_LOG_DEBUG(("Encrypting packet, cipher %s, len %d (%d)", 
		    cipher->cipher->name, len, len - 2));
  }

  /* Compute HMAC. This assumes that HMAC is created from the entire
     data area thus this uses the length found in buffer, not the length
     sent as argument. */
  if (hmac) {
    silc_hmac_make(hmac, buffer->data, buffer->len, mac);
    silc_buffer_put_tail(buffer, mac, hmac->hash->hash->hash_len);
    memset(mac, 0, sizeof(mac));
  }

  /* Encrypt the data area of the packet. 2 bytes of the packet
     are not encrypted. */
  if (cipher)
    cipher->cipher->encrypt(cipher->context, buffer->data + 2, 
			    buffer->data + 2, len - 2, cipher->iv);

  /* Pull the HMAC into the visible data area in the buffer */
  if (hmac)
    silc_buffer_pull_tail(buffer, hmac->hash->hash->hash_len);
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

   Packet construct is as follows (* = won't be encrypted):

   x bytes       SILC Header
      2 bytes     Payload length  (*)
      1 byte      Flags
      1 byte      Packet type
      1 byte      Source ID Type
      2 bytes     Source ID Length
      x bytes     Source ID
      1 byte      Destination ID Type
      2 bytes     Destination ID Length
      x bytes     Destination ID

   1 - 16 bytes    Padding

   x bytes        Data payload

   All fields in the packet will be authenticated by MAC. The MAC is
   not computed here, it must be computed differently before encrypting
   the packet.

*/

void silc_packet_assemble(SilcPacketContext *ctx)
{
  unsigned char tmppad[SILC_PACKET_MAX_PADLEN];
  int i;

  SILC_LOG_DEBUG(("Assembling outgoing packet"));
  
  /* Get the true length of the packet. This is saved as payload length
     into the packet header. This does not include the length of the
     padding. */
  if (!ctx->truelen)
    ctx->truelen = ctx->buffer->len + SILC_PACKET_HEADER_LEN + 
      ctx->src_id_len + ctx->dst_id_len;

  /* Calculate the length of the padding. The padding is calculated from
     the data that will be encrypted. As protocol states 3 first bytes
     of the packet are not encrypted they are not included in the
     padding calculation. */
  if (!ctx->padlen)
    ctx->padlen = SILC_PACKET_PADLEN(ctx->truelen);

  /* Put the start of the data section to the right place. */
  silc_buffer_push(ctx->buffer, SILC_PACKET_HEADER_LEN + 
		   ctx->src_id_len + ctx->dst_id_len + ctx->padlen);

  /* Get random padding */
#if 1
  for (i = 0; i < ctx->padlen; i++)
    tmppad[i] = silc_rng_get_byte(ctx->rng);
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
		     SILC_STR_UI_SHORT(ctx->src_id_len),
		     SILC_STR_UI_SHORT(ctx->dst_id_len),
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
			      unsigned int header_len,
			      unsigned int padlen,
			      unsigned int data_len)
{
  int totlen, oldlen;

  totlen = header_len + padlen + data_len;

  /* Prepare the outgoing buffer for packet sending. */
  if (!sock->outbuf) {
    /* Allocate new buffer. This is done only once per connection. */
    SILC_LOG_DEBUG(("Allocating outgoing data buffer"));
    
    sock->outbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);
    silc_buffer_pull_tail(sock->outbuf, totlen);
    silc_buffer_pull(sock->outbuf, header_len + padlen);
  } else {
    if (SILC_IS_OUTBUF_PENDING(sock)) {
      /* There is some pending data in the buffer. */

      /* Allocate more space if needed */
      if ((sock->outbuf->end - sock->outbuf->tail) < data_len) {
	SILC_LOG_DEBUG(("Reallocating outgoing data buffer"));
	sock->outbuf = silc_buffer_realloc(sock->outbuf, 
					   sock->outbuf->truelen + totlen);
      }

      oldlen = sock->outbuf->len;
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen + oldlen);
    } else {
      /* Buffer is free for use */
      silc_buffer_clear(sock->outbuf);
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen);
    }
  }
}

/******************************************************************************

                         Packet Reception Routines

******************************************************************************/

/* Reads data from the socket connection into the incoming data buffer.
   However, this does not parse the packet, it only reads some amount from
   the network. If there are more data available that can be read at a time
   the rest of the data will be read later with a timeout and only after
   that the packet is ready to be parsed. 

   The destination buffer sent as argument must be initialized before 
   calling this function, and, the data section and the start of the tail
   section must be same. Ie. we add the read data to the tail section of
   the buffer hence the data section is the start of the buffer.

   This returns amount of bytes read or -1 on error or -2 on case where
   all of the data could not be read at once. */

int silc_packet_read(int sock, SilcBuffer dest)
{
  int len = 0;
  unsigned char buf[SILC_PACKET_READ_SIZE];

  SILC_LOG_DEBUG(("Reading data from socket %d", sock));

  /* Read the data from the socket. */
  len = read(sock, buf, sizeof(buf));
  if (len < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      return -2;
    }
    SILC_LOG_ERROR(("Cannot read from socket: %d", strerror(errno)));
    return -1;
  }

  if (!len)
    return 0;

  /* Insert the data to the buffer. If the data doesn't fit to the 
     buffer space is allocated for the buffer. */
  /* XXX: This may actually be bad thing as if there is pending data in
     the buffer they will be lost! */
  if (dest) {

    /* If the data doesn't fit we just have to allocate a whole new 
       data area */
    if (dest->truelen <= len) {

      /* Free the old buffer */
      memset(dest->head, 'F', dest->truelen);
      silc_free(dest->head);

      /* Allocate new data area */
      len += SILC_PACKET_DEFAULT_SIZE;
      dest->data = silc_calloc(len, sizeof(char));
      dest->truelen = len;
      dest->len = 0;
      dest->head = dest->data;
      dest->data = dest->data;
      dest->tail = dest->data;
      dest->end = dest->data + dest->truelen;
      len -= SILC_PACKET_DEFAULT_SIZE;
    }

    silc_buffer_put_tail(dest, buf, len);
    silc_buffer_pull_tail(dest, len);
  }

  SILC_LOG_DEBUG(("Read %d bytes", len));

  return len;
}

/* Processes the received data. This checks the received data and 
   calls parser callback that handles the actual packet decryption
   and parsing. If more than one packet was received this calls the
   parser multiple times. The parser callback will get context
   SilcPacketParserContext that includes the packet and the `context'
   sent to this function. */

void silc_packet_receive_process(SilcSocketConnection sock,
				 SilcCipher cipher, SilcHmac hmac,
				 SilcPacketParserCallback parser,
				 void *context)
{
  SilcPacketParserContext *parse_ctx;
  int packetlen, paddedlen, count, mac_len = 0;

  /* We need at least 2 bytes of data to be able to start processing
     the packet. */
  if (sock->inbuf->len < 2)
    return;

  if (hmac)
    mac_len = hmac->hash->hash->hash_len;

  /* Parse the packets from the data */
  count = 0;
  while (sock->inbuf->len > 0) {
    SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);
    paddedlen += 2;
    count++;

    if (packetlen < SILC_PACKET_MIN_LEN) {
      SILC_LOG_DEBUG(("Received invalid packet, dropped"));
      return;
    }

    if (sock->inbuf->len < paddedlen + mac_len) {
      SILC_LOG_DEBUG(("Received partial packet, waiting for the rest"));
      return;
    }

    parse_ctx = silc_calloc(1, sizeof(*parse_ctx));
    parse_ctx->packet = silc_calloc(1, sizeof(*parse_ctx->packet));
    parse_ctx->packet->buffer = silc_buffer_alloc(paddedlen + mac_len);
    parse_ctx->sock = sock;
    parse_ctx->cipher = cipher;
    parse_ctx->hmac = hmac;
    parse_ctx->context = context;

    silc_buffer_pull_tail(parse_ctx->packet->buffer, 
			  SILC_BUFFER_END(parse_ctx->packet->buffer));
    silc_buffer_put(parse_ctx->packet->buffer, sock->inbuf->data, 
		    paddedlen + mac_len);

    SILC_LOG_HEXDUMP(("Incoming packet, len %d", 
		      parse_ctx->packet->buffer->len),
		     parse_ctx->packet->buffer->data, 
		     parse_ctx->packet->buffer->len);

    /* Call the parser */
    if (parser)
      (*parser)(parse_ctx);

    /* Pull the packet from inbuf thus we'll get the next one
       in the inbuf. */
    silc_buffer_pull(sock->inbuf, paddedlen);
    if (hmac)
      silc_buffer_pull(sock->inbuf, mac_len);
  }

  silc_buffer_clear(sock->inbuf);
}

/* Receives packet from network and reads the data into connection's
   incoming data buffer. If the data was read directly this returns the
   read bytes, if error occured this returns -1, if the data could not
   be read directly at this time this returns -2 in which case the data
   should be read again at some later time, or If EOF occured this returns
   0. */

int silc_packet_receive(SilcSocketConnection sock)
{
  int ret;

  /* Allocate the incoming data buffer if not done already. */
  if (!sock->inbuf)
    sock->inbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);
  
  /* Read some data from connection */
  ret = silc_packet_read(sock->sock, sock->inbuf);

  /* Error */
  if (ret == -1) {
    SILC_LOG_ERROR(("Error reading packet, dropped"));
  }

  return ret;
}

/* Checks MAC in the packet. Returns TRUE if MAC is Ok. This is called
   after packet has been totally decrypted and parsed. */

static int silc_packet_check_mac(SilcHmac hmac, SilcBuffer buffer)
{
  /* Check MAC */
  if (hmac) {
    unsigned char mac[32];
    
    SILC_LOG_DEBUG(("Verifying MAC"));

    /* Compute HMAC of packet */
    memset(mac, 0, sizeof(mac));
    silc_hmac_make(hmac, buffer->data, buffer->len, mac);

    /* Compare the HMAC's (buffer->tail has the packet's HMAC) */
    if (memcmp(mac, buffer->tail, hmac->hash->hash->hash_len)) {
      SILC_LOG_DEBUG(("MAC failed"));
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
      if ((buffer->len - hmac->hash->hash->hash_len) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, hmac->hash->hash->hash_len);
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }

    SILC_LOG_DEBUG(("Decrypting rest of the packet"));

    /* Decrypt rest of the packet */
    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    cipher->cipher->decrypt(cipher->context, buffer->data + 2,
			    buffer->data + 2, buffer->len - 2,
			    cipher->iv);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);

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
    unsigned short truelen, len1, len2, padlen;

    /* Pull MAC from packet before decryption */
    if (hmac) {
      if ((buffer->len - hmac->hash->hash->hash_len) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, hmac->hash->hash->hash_len);
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }
  
    SILC_LOG_DEBUG(("Decrypting rest of the header"));

    SILC_GET16_MSB(len1, &buffer->data[4]);
    SILC_GET16_MSB(len2, &buffer->data[6]);

    truelen = SILC_PACKET_HEADER_LEN + len1 + len2;
    padlen = SILC_PACKET_PADLEN(truelen);
    len1 = (truelen + padlen) - (SILC_PACKET_MIN_HEADER_LEN - 2);

    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    cipher->cipher->decrypt(cipher->context, buffer->data + 2,
			    buffer->data + 2, len1 - 2,
			    cipher->iv);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
  }

  return TRUE;
}

/* Decrypts a packet. This assumes that typical SILC packet is the
   packet to be decrypted and thus checks for normal and special SILC
   packets and can handle both of them. This also computes and checks
   the HMAC of the packet. If any other special or customized decryption
   processing is required this function cannot be used. This returns
   -1 on error, 0 when packet is normal packet and 1 when the packet
   is special and requires special processing. */

int silc_packet_decrypt(SilcCipher cipher, SilcHmac hmac,
			SilcBuffer buffer, SilcPacketContext *packet)
{
#if 0
  SILC_LOG_DEBUG(("Decrypting packet, cipher %s, len %d (%d)", 
		  cipher->cipher->name, len, len - 2));
#endif

  /* Decrypt start of the packet header */
  if (cipher)
    cipher->cipher->decrypt(cipher->context, buffer->data + 2,
			    buffer->data + 2, SILC_PACKET_MIN_HEADER_LEN - 2,
			    cipher->iv);

  /* If the packet type is not any special type lets decrypt rest
     of the packet here. */
  if ((buffer->data[3] == SILC_PACKET_PRIVATE_MESSAGE &&
      !(buffer->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY)) ||
      buffer->data[3] != SILC_PACKET_CHANNEL_MESSAGE) {

    /* Normal packet, decrypt rest of the packet */
    if (!silc_packet_decrypt_rest(cipher, hmac, buffer))
      return -1;

    /* Check MAC */
    if (!silc_packet_check_mac(hmac, buffer))
      return FALSE;

    return 0;
  } else {
    /* Packet requires special handling, decrypt rest of the header.
       This only decrypts. */
    silc_packet_decrypt_rest_special(cipher, hmac, buffer);

    /* Check MAC */
    if (!silc_packet_check_mac(hmac, buffer))
      return FALSE;

    return 1;
  }
}

/* Parses the packet. This is called when a whole packet is ready to be
   parsed. The buffer sent must be already decrypted before calling this 
   function. The len argument must be the true length of the packet. This 
   function returns the type of the packet. The data section of the 
   buffer is parsed, not head or tail sections. */

SilcPacketType silc_packet_parse(SilcPacketContext *ctx)
{
  SilcBuffer buffer = ctx->buffer;
  int len;

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
			     SILC_STR_UI_SHORT(&ctx->src_id_len),
			     SILC_STR_UI_SHORT(&ctx->dst_id_len),
			     SILC_STR_UI_CHAR(&ctx->src_id_type),
			     SILC_STR_END);

  if (ctx->src_id_len > SILC_PACKET_MAX_ID_LEN ||
      ctx->dst_id_len > SILC_PACKET_MAX_ID_LEN) {
    SILC_LOG_ERROR(("Bad ID lengths in packet"));
    return SILC_PACKET_NONE;
  }

  /* Calculate length of padding in packet */
  ctx->padlen = SILC_PACKET_PADLEN(ctx->truelen);

  silc_buffer_pull(buffer, len);
  silc_buffer_unformat(buffer, 
		       SILC_STR_UI_XNSTRING_ALLOC(&ctx->src_id,
						  ctx->src_id_len),
		       SILC_STR_UI_CHAR(&ctx->dst_id_type),
		       SILC_STR_UI_XNSTRING_ALLOC(&ctx->dst_id,
						  ctx->dst_id_len),
		       SILC_STR_UI_XNSTRING(NULL, ctx->padlen),
		       SILC_STR_END);
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

SilcPacketType silc_packet_parse_special(SilcPacketContext *ctx)
{
  SilcBuffer buffer = ctx->buffer;
  int len, tmplen;

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
			     SILC_STR_UI_SHORT(&ctx->src_id_len),
			     SILC_STR_UI_SHORT(&ctx->dst_id_len),
			     SILC_STR_UI_CHAR(&ctx->src_id_type),
			     SILC_STR_END);

  if (ctx->src_id_len > SILC_PACKET_MAX_ID_LEN ||
      ctx->dst_id_len > SILC_PACKET_MAX_ID_LEN) {
    SILC_LOG_ERROR(("Bad ID lengths in packet"));
    return SILC_PACKET_NONE;
  }

  /* Calculate length of padding in packet. As this is special packet
     the data area is not used in the padding calculation as it won't
     be decrypted by the caller. */
  tmplen = SILC_PACKET_HEADER_LEN + ctx->src_id_len + ctx->dst_id_len;
  ctx->padlen = SILC_PACKET_PADLEN(tmplen);

  silc_buffer_pull(buffer, len);
  silc_buffer_unformat(buffer, 
		       SILC_STR_UI_XNSTRING_ALLOC(&ctx->src_id,
						  ctx->src_id_len),
		       SILC_STR_UI_CHAR(&ctx->dst_id_type),
		       SILC_STR_UI_XNSTRING_ALLOC(&ctx->dst_id,
						  ctx->dst_id_len),
		       SILC_STR_UI_XNSTRING(NULL, ctx->padlen),
		       SILC_STR_END);
  silc_buffer_push(buffer, len);

  SILC_LOG_HEXDUMP(("parsed packet, len %d", ctx->buffer->len), 
		   ctx->buffer->data, ctx->buffer->len);

  /* Pull SILC header and padding from packet */
  silc_buffer_pull(buffer, SILC_PACKET_HEADER_LEN +
		   ctx->src_id_len + ctx->dst_id_len + ctx->padlen);

  SILC_LOG_DEBUG(("Incoming packet type: %d", ctx->type));

  return ctx->type;
}

/* Duplicates packet context. Duplicates the entire context and its
   contents. */

SilcPacketContext *silc_packet_context_dup(SilcPacketContext *ctx)
{
  SilcPacketContext *new;

  new = silc_calloc(1, sizeof(*new));
  new->buffer = silc_buffer_copy(ctx->buffer);
  new->type = ctx->type;
  new->flags = ctx->flags;

  new->src_id = silc_calloc(ctx->src_id_len, sizeof(*new->src_id));
  memcpy(new->src_id, ctx->src_id, ctx->src_id_len);
  new->src_id_len = ctx->src_id_len;
  new->src_id_type = ctx->src_id_type;

  new->dst_id = silc_calloc(ctx->dst_id_len, sizeof(*new->dst_id));
  memcpy(new->dst_id, ctx->dst_id, ctx->dst_id_len);
  new->dst_id_len = ctx->dst_id_len;
  new->dst_id_type = ctx->dst_id_type;

  new->truelen = ctx->truelen;
  new->padlen = ctx->padlen;

  new->rng = ctx->rng;
  new->context = ctx->context;
  new->sock = ctx->sock;

  return new;
}
