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
/*
 * $Id$
 * $Log$
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

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
    if (errno == EAGAIN) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      return -2;
    }
    SILC_LOG_ERROR(("Cannot read from socket: %d", strerror(errno)));
    return -1;
  }

  if (!len)
    return 0;

  /* Insert the data to the buffer. If the data doesn't fit to the 
     buffer space is allocated for the buffer.  
     XXX: I don't like this. -Pekka */
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

/* Encrypts a packet. */

void silc_packet_encrypt(SilcCipher cipher, SilcBuffer buffer,
			 unsigned int len)
{
  SILC_LOG_DEBUG(("Encrypting packet, cipher %s, len %d (%d)", 
		  cipher->cipher->name, len, len - 2));

  /* Encrypt the data area of the packet. 3 bytes of the packet
     are not encrypted. */
  cipher->cipher->encrypt(cipher->context, buffer->data + 2, 
			  buffer->data + 2, len - 2, cipher->iv);

}

/* Decrypts a packet. */

void silc_packet_decrypt(SilcCipher cipher, SilcBuffer buffer, 
			 unsigned int len)
{
  SILC_LOG_DEBUG(("Decrypting packet, cipher %s, len %d (%d)", 
		  cipher->cipher->name, len, len - 2));

  /* Decrypt the data area of the packet. 2 bytes of the packet
     are not decrypted (they are not encrypted). */
  cipher->cipher->decrypt(cipher->context, buffer->data + 2, 
			  buffer->data + 2, len - 2, cipher->iv);

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
      1 byte      Flags           (*)
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
