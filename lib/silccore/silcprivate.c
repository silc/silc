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
#include "silcprivate_i.h"

/******************************************************************************

                           Private Message Payload

******************************************************************************/

/* Parses private message payload returning new private mesage payload 
   structure. This also decrypts the message if the `cipher' is provided. */

SilcPrivateMessagePayload 
silc_private_message_payload_parse(unsigned char *payload,
				   SilcUInt32 payload_len,
				   SilcCipher cipher,
				   SilcHmac hmac)
{
  SilcBufferStruct buffer;
  SilcPrivateMessagePayload newp;
  SilcUInt32 mac_len = 0, block_len, pad_len = 0;
  unsigned char data[16], mac[32];
  int len, totlen;

  SILC_LOG_DEBUG(("Parsing private message payload"));

  silc_buffer_set(&buffer, payload, payload_len);

  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Decrypt the payload */
  if (cipher) {
    /* Decrypt first block. This is to get the true length of the data in
       payload.  It is possible there is additional data after the message
       payload with private messages. */
    block_len = silc_cipher_get_block_len(cipher);
    if (block_len > buffer.len)
      goto err;
    silc_cipher_decrypt(cipher, buffer.data, data, block_len,
			silc_cipher_get_iv(cipher));

    /* Length of encrypted area */
    SILC_GET16_MSB(newp->message_len, data + 2);
    totlen = 4 + newp->message_len;
    pad_len = SILC_PRIVATE_MESSAGE_PAD(4 + newp->message_len);
    totlen += pad_len;

    /* Sanity checks */
    if (totlen > buffer.len || newp->message_len < 1 ||
	newp->message_len > buffer.len - 4) {
      SILC_LOG_DEBUG(("Incorrect private message payload in packet"));
      goto err;
    }

    /* Compute MAC for integrity check from the cipher text */
    if (hmac) {
      SILC_LOG_DEBUG(("Checking private message MAC"));
      silc_hmac_init(hmac);
      silc_hmac_update(hmac, buffer.data, totlen);
      silc_hmac_final(hmac, mac, &mac_len);
      if (memcmp(mac, buffer.data + totlen, mac_len)) {
	SILC_LOG_DEBUG(("Private message MAC does not match"));
	goto err;
      }
      SILC_LOG_DEBUG(("MAC is Ok"));
    }

    /* Now decrypt rest of the data */
    memcpy(buffer.data, data, block_len);
    if (totlen - block_len > 0)
      silc_cipher_decrypt(cipher, buffer.data + block_len,
			  buffer.data + block_len, totlen - block_len,
			  silc_cipher_get_iv(cipher));
    memset(data, 0, sizeof(data));
  }

  /* Parse the Private Message Payload. */
  len = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&newp->flags),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->message, 
							 &newp->message_len),
			     SILC_STR_END);
  if (len == -1 || newp->message_len < 1 ||
      newp->message_len > buffer.len - 4) {
    SILC_LOG_DEBUG(("Incorrect private message payload in packet"));
    goto err;
  }

  /* Parse also padding and MAC */
  if (cipher) {
    silc_buffer_pull(&buffer, 4 + newp->message_len);
    len = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_XNSTRING_ALLOC(&newp->pad,
							  pad_len),
			       SILC_STR_UI_XNSTRING_ALLOC(&newp->mac,
							  mac_len),
			       SILC_STR_END);
    silc_buffer_push(&buffer, 4 + newp->message_len);
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
					       SilcHmac hmac,
					       SilcRng rng)
{
  int i;
  SilcBuffer buffer;
  SilcUInt32 len, pad_len = 0, mac_len = 0;
  unsigned char pad[16], mac[32];

  SILC_LOG_DEBUG(("Encoding private message payload"));

  data_len = SILC_PRIVATE_MESSAGE_DATALEN(data_len);
  len = 4 + data_len;

  if (cipher) {
    /* Calculate length of padding. */
    pad_len = SILC_PRIVATE_MESSAGE_PAD(len);
    len += pad_len;
    mac_len = hmac ? silc_hmac_len(hmac) : 0;
    len += mac_len;

    /* Generate padding */
    if (rng) {
      for (i = 0; i < pad_len; i++) pad[i] = silc_rng_get_byte_fast(rng);
    } else {
      for (i = 0; i < pad_len; i++) pad[i] = silc_rng_global_get_byte_fast();
    }
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
			buffer->len - mac_len, silc_cipher_get_iv(cipher));
    memset(pad, 0, sizeof(pad));

    /* Compute MAC from the ciphertext */
    if (hmac) {
      silc_hmac_init(hmac);
      silc_hmac_update(hmac, buffer->data, buffer->len - mac_len);
      silc_hmac_final(hmac, mac, &mac_len);
      memcpy(buffer->data + (buffer->len - mac_len), mac, mac_len);
      memset(mac, 0, sizeof(mac));
    }
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

/* Return MAC.  Caller knows its length */

unsigned char *
silc_private_message_get_mac(SilcPrivateMessagePayload payload)
{
  return payload->mac;
}
