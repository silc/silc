/*

  silcprivate.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* Includes the Private Message Payload implementation */
/* $Id$ */

#include "silcincludes.h"
#include "silcprivate.h"

/******************************************************************************

                           Private Message Payload

******************************************************************************/

/* Private Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcPrivateMessagePayloadStruct {
  uint16 flags;
  uint16 nickname_len;
  unsigned char *nickname;
  uint16 message_len;
  unsigned char *message;
};

/* Parses private message payload returning new private mesage payload 
   structure. This also decrypts the message if the `cipher' is provided. */

SilcPrivateMessagePayload 
silc_private_message_payload_parse(SilcBuffer buffer, SilcCipher cipher)
{
  SilcPrivateMessagePayload new;
  int ret;

  SILC_LOG_DEBUG(("Parsing private message payload"));

  /* Decrypt the payload */
  if (cipher)
    silc_cipher_decrypt(cipher, buffer->data, buffer->data, 
			buffer->len, cipher->iv);

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Private Message Payload. Ignore the padding. */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&new->flags),
			     SILC_STR_UI16_NSTRING_ALLOC(&new->nickname, 
							 &new->nickname_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&new->message, 
							 &new->message_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if ((new->message_len < 1 || new->message_len > buffer->len) ||
      (new->nickname_len < 1 || new->nickname_len > buffer->len)) {
    SILC_LOG_ERROR(("Incorrect private message payload in packet, "
		    "packet dropped"));
    goto err;
  }

  return new;

 err:
  silc_private_message_payload_free(new);
  return NULL;
}

/* Encodes private message payload into a buffer and returns it.  If
   the cipher is provided the packet is also encrypted here.  It is provided
   if the private message private keys are used. */

SilcBuffer silc_private_message_payload_encode(uint16 flags,
					       uint32 nickname_len,
					       unsigned char *nickname,
					       uint16 data_len,
					       unsigned char *data,
					       SilcCipher cipher)
{
  int i;
  SilcBuffer buffer;
  uint32 len, pad_len = 0;
  unsigned char pad[SILC_PACKET_MAX_PADLEN];

  SILC_LOG_DEBUG(("Encoding private message payload"));

  len = 4 + nickname_len + 2 + data_len;

  if (cipher) {
    /* Calculate length of padding. */
    pad_len = SILC_PACKET_PADLEN((len + 2));
    len += pad_len;

    /* Generate padding */
    for (i = 0; i < pad_len; i++) pad[i] = silc_rng_global_get_byte();
  }

  /* Allocate private message payload buffer */
  buffer = silc_buffer_alloc(len);

  /* Encode the Channel Message Payload */
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(flags),
		     SILC_STR_UI_SHORT(nickname_len),
		     SILC_STR_UI_XNSTRING(nickname, nickname_len),
		     SILC_STR_UI_SHORT(data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI_XNSTRING(pad, pad_len),
		     SILC_STR_END);

  if (cipher) {
    /* Encrypt payload of the packet. */
    silc_cipher_encrypt(cipher, buffer->data, buffer->data, 
			buffer->len, cipher->iv);
    memset(pad, 0, sizeof(pad));
  }

  return buffer;
}

/* Free's Private Message Payload */

void silc_private_message_payload_free(SilcPrivateMessagePayload payload)
{
  silc_free(payload->nickname);
  if (payload->message) {
    memset(payload->message, 0, payload->message_len);
    silc_free(payload->message);
  }
  silc_free(payload);
}

/* Return flags */

uint16 
silc_private_message_get_flags(SilcPrivateMessagePayload payload)
{
  return payload->flags;
}

/* Return nickname */

unsigned char *
silc_private_message_get_nickname(SilcPrivateMessagePayload payload,
				  uint32 *nickname_len)
{
  if (nickname_len)
    *nickname_len = payload->nickname_len;

  return payload->nickname;
}

/* Return message */

unsigned char *
silc_private_message_get_message(SilcPrivateMessagePayload payload,
				 uint32 *message_len)
{
  if (message_len)
    *message_len = payload->message_len;

  return payload->message;
}
