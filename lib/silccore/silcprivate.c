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

/* Calculates padding length for message payload */
#define SILC_PRIVATE_MESSAGE_PAD(__payloadlen) (16 - ((__payloadlen) % 16))

/* Header length plus maximum padding length */
#define SILC_PRIVATE_MESSAGE_HLEN 4 + 16

/* Returns the data length that fits to the packet.  If data length is too
   big it will be truncated to fit to the payload. */
#define SILC_PRIVATE_MESSAGE_DATALEN(data_len)				\
  ((data_len + SILC_PRIVATE_MESSAGE_HLEN) > SILC_PACKET_MAX_LEN ?	\
   data_len - ((data_len + SILC_PRIVATE_MESSAGE_HLEN) - 		\
	       SILC_PACKET_MAX_LEN) : data_len)

/* Private Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcPrivateMessagePayloadStruct {
  SilcUInt16 flags;
  SilcUInt16 message_len;
  unsigned char *message;
};

/* Parses private message payload returning new private mesage payload 
   structure. This also decrypts the message if the `cipher' is provided. */

SilcPrivateMessagePayload 
silc_private_message_payload_parse(unsigned char *payload,
				   SilcUInt32 payload_len,
				   SilcCipher cipher)
{
  SilcBufferStruct buffer;
  SilcPrivateMessagePayload newp;
  int ret;

  SILC_LOG_DEBUG(("Parsing private message payload"));

  silc_buffer_set(&buffer, payload, payload_len);

  /* Decrypt the payload */
  if (cipher)
    silc_cipher_decrypt(cipher, buffer.data, buffer.data, 
			buffer.len, cipher->iv);

  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the Private Message Payload. Ignore the padding. */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&newp->flags),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->message, 
							 &newp->message_len),
			     SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_DEBUG(("Incorrect private message payload"));
    goto err;
  }

  if ((newp->message_len < 1 || newp->message_len > buffer.len - 4)) {
    SILC_LOG_DEBUG(("Incorrect private message payload in packet, "
		    "packet dropped"));
    goto err;
  }

  return newp;

 err:
  silc_private_message_payload_free(newp);
  return NULL;
}

/* Encodes private message payload into a buffer and returns it.  If
   the cipher is provided the packet is also encrypted here.  It is provided
   if the private message private keys are used. */

SilcBuffer silc_private_message_payload_encode(SilcUInt16 flags,
					       SilcUInt16 data_len,
					       const unsigned char *data,
					       SilcCipher cipher,
					       SilcRng rng)
{
  int i;
  SilcBuffer buffer;
  SilcUInt32 len, pad_len = 0;
  unsigned char pad[16];

  SILC_LOG_DEBUG(("Encoding private message payload"));

  data_len = SILC_PRIVATE_MESSAGE_DATALEN(data_len);
  len = 4 + data_len;

  if (cipher) {
    /* Calculate length of padding. */
    pad_len = SILC_PRIVATE_MESSAGE_PAD(len);
    len += pad_len;

    /* Generate padding */
    for (i = 0; i < pad_len; i++) pad[i] = silc_rng_global_get_byte();
  }

  /* Allocate private message payload buffer */
  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;

  /* Encode the Channel Message Payload */
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(flags),
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

/* Frees Private Message Payload */

void silc_private_message_payload_free(SilcPrivateMessagePayload payload)
{
  if (payload->message) {
    memset(payload->message, 0, payload->message_len);
    silc_free(payload->message);
  }
  silc_free(payload);
}

/* Return flags */

SilcUInt16 
silc_private_message_get_flags(SilcPrivateMessagePayload payload)
{
  return payload->flags;
}

/* Return message */

unsigned char *
silc_private_message_get_message(SilcPrivateMessagePayload payload,
				 SilcUInt32 *message_len)
{
  if (message_len)
    *message_len = payload->message_len;

  return payload->message;
}
