/*

  silcchannel.c

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
/* Channel Payload and Channel Key Payload implementations. */
/* $Id$ */

#include "silcincludes.h"
#include "silcchannel.h"

/******************************************************************************

                          Channel Message Payload

******************************************************************************/

/* Channel Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelPayloadStruct {
  unsigned short data_len;
  unsigned char *data;
  unsigned char *mac;
  unsigned char *iv;
};

/* Parses channel payload returning new channel payload structure. This
   also decrypts it and checks the MAC. */

SilcChannelPayload silc_channel_payload_parse(SilcBuffer buffer,
					      SilcCipher cipher,
					      SilcHmac hmac)
{
  SilcChannelPayload new;
  int ret;
  unsigned int iv_len, mac_len;
  unsigned char *mac, mac2[32];

  SILC_LOG_DEBUG(("Parsing channel payload"));

  /* Decrypt the channel message. First push the IV out of the packet.
     The IV is used in the decryption process. Then decrypt the message.
     After decyprtion, take the MAC from the decrypted packet, compute MAC
     and compare the MACs.  If they match, the decryption was successfull
     and we have the channel message ready to be displayed. */

  /* Push the IV out of the packet (it will be in buffer->tail) */
  iv_len = silc_cipher_get_block_len(cipher);
  silc_buffer_push_tail(buffer, iv_len);

  /* Decrypt the channel message */
  silc_cipher_decrypt(cipher, buffer->data, buffer->data,
		      buffer->len, buffer->tail);

  /* Take the MAC */
  mac_len = silc_hmac_len(hmac);
  silc_buffer_push_tail(buffer, mac_len);
  mac = buffer->tail;

  /* Check the MAC of the message */
  SILC_LOG_DEBUG(("Checking channel message MACs"));
  silc_hmac_make(hmac, buffer->data, buffer->len, mac2, &mac_len);
  if (memcmp(mac, mac2, mac_len)) {
    SILC_LOG_DEBUG(("Channel message MACs does not match"));
    return NULL;
  }
  SILC_LOG_DEBUG(("MAC is Ok"));
  silc_buffer_pull_tail(buffer, iv_len + mac_len);

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Channel Payload. Ignore the padding. */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&new->data, 
							 &new->data_len),
			     SILC_STR_UI16_NSTRING(NULL, NULL),
			     SILC_STR_UI_XNSTRING(&new->mac, mac_len),
			     SILC_STR_UI_XNSTRING(&new->iv, iv_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if (new->data_len < 1 || new->data_len > buffer->len) {
    SILC_LOG_ERROR(("Incorrect channel payload in packet, packet dropped"));
    goto err;
  }

  return new;

 err:
  silc_channel_payload_free(new);
  return NULL;
}

/* Encodes channel payload into a buffer and returns it. This is used 
   to add channel payload into a packet. As the channel payload is
   encrypted separately from other parts of the packet padding must
   be applied to the payload. */

SilcBuffer silc_channel_payload_encode(unsigned short data_len,
				       unsigned char *data,
				       unsigned short iv_len,
				       unsigned char *iv,
				       SilcCipher cipher,
				       SilcHmac hmac,
				       SilcRng rng)
{
  int i;
  SilcBuffer buffer;
  unsigned int len, pad_len, mac_len;
  unsigned char pad[SILC_PACKET_MAX_PADLEN];
  unsigned char mac[32];

  SILC_LOG_DEBUG(("Encoding channel payload"));

  /* Calculate length of padding. IV is not included into the calculation
     since it is not encrypted. */
  mac_len = silc_hmac_len(hmac);
  len = 4 + data_len + mac_len;
  pad_len = SILC_PACKET_PADLEN((len + 2));

  /* Allocate channel payload buffer */
  len += pad_len + iv_len;
  buffer = silc_buffer_alloc(len);

  /* Generate padding */
  for (i = 0; i < pad_len; i++) pad[i] = silc_rng_get_byte(rng);

  /* Encode the Channel Payload */
  silc_buffer_pull_tail(buffer, 4 + data_len + pad_len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI_SHORT(pad_len),
		     SILC_STR_UI_XNSTRING(pad, pad_len),
		     SILC_STR_END);

  /* Compute the MAC of the channel message data */
  silc_hmac_make(hmac, buffer->data, buffer->len, mac, &mac_len);

  /* Put rest of the data to the payload */
  silc_buffer_pull_tail(buffer, mac_len + iv_len);
  silc_buffer_pull(buffer, 4 + data_len + pad_len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_XNSTRING(mac, mac_len),
		     SILC_STR_UI_XNSTRING(iv, iv_len),
		     SILC_STR_END);
  silc_buffer_push(buffer, 4 + data_len + pad_len);

  /* Encrypt payload of the packet. This is encrypted with the channel key. */
  silc_cipher_encrypt(cipher, buffer->data, buffer->data, 
		      buffer->len - iv_len, iv);

  memset(pad, 0, sizeof(pad));
  memset(mac, 0, sizeof(mac));

  return buffer;
}

/* Free's Channel Payload */

void silc_channel_payload_free(SilcChannelPayload payload)
{
  if (payload) {
    if (payload->data)
      silc_free(payload->data);
    silc_free(payload);
  }
}

/* Return data */

unsigned char *silc_channel_get_data(SilcChannelPayload payload,
				     unsigned int *data_len)
{
  if (data_len)
    *data_len = payload->data_len;

  return payload->data;
}

/* Return MAC. The caller knows the length of the MAC */

unsigned char *silc_channel_get_mac(SilcChannelPayload payload)
{
  return payload->mac;
}

/* Return IV. The caller knows the length of the IV */

unsigned char *silc_channel_get_iv(SilcChannelPayload payload)
{
  return payload->iv;
}

/******************************************************************************

                             Channel Key Payload

******************************************************************************/

/* Channel Key Payload structrue. Channel keys are parsed from SILC
   packets into this structure. */
struct SilcChannelKeyPayloadStruct {
  unsigned short id_len;
  unsigned char *id;
  unsigned short cipher_len;
  unsigned char *cipher;
  unsigned short key_len;
  unsigned char *key;
};

/* Parses channel key payload returning new channel key payload structure */

SilcChannelKeyPayload silc_channel_key_payload_parse(SilcBuffer buffer)
{
  SilcChannelKeyPayload new;
  int ret;

  SILC_LOG_DEBUG(("Parsing channel key payload"));

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Channel Key Payload */
  ret =
    silc_buffer_unformat(buffer,
			 SILC_STR_UI16_NSTRING_ALLOC(&new->id, &new->id_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&new->cipher, 
						     &new->cipher_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&new->key, &new->key_len),
			 SILC_STR_END);
  if (ret == -1)
    goto err;

  if (new->id_len < 1 || new->key_len < 1 || new->cipher_len < 1) {
    SILC_LOG_ERROR(("Incorrect channel key payload in packet"));
    goto err;
  }

  return new;

 err:
  if (new->id)
    silc_free(new->id);
  if (new->cipher)
    silc_free(new->cipher);
  if (new->key)
    silc_free(new->key);
  silc_free(new);
  return NULL;
}

/* Encodes channel key payload into a buffer and returns it. This is used 
   to add channel key payload into a packet. */

SilcBuffer silc_channel_key_payload_encode(unsigned short id_len,
					   unsigned char *id,
					   unsigned short cipher_len,
					   unsigned char *cipher,
					   unsigned short key_len,
					   unsigned char *key)
{
  SilcBuffer buffer;
  unsigned int len;

  SILC_LOG_DEBUG(("Encoding channel key payload"));

  /* Allocate channel payload buffer. Length is 2 + id + 2 + key + 
     2 + cipher */
  len = 2 + id_len + 2 + key_len + 2 + cipher_len;
  buffer = silc_buffer_alloc(len);

  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Encode the Channel Payload */
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(id_len),
		     SILC_STR_UI_XNSTRING(id, id_len),
		     SILC_STR_UI_SHORT(cipher_len),
		     SILC_STR_UI_XNSTRING(cipher, cipher_len),
		     SILC_STR_UI_SHORT(key_len),
		     SILC_STR_UI_XNSTRING(key, key_len),
		     SILC_STR_END);

  return buffer;
}

/* Free's Channel Key Payload */

void silc_channel_key_payload_free(SilcChannelKeyPayload payload)
{
  if (payload) {
    if (payload->id)
      silc_free(payload->id);
    if (payload->cipher)
      silc_free(payload->cipher);
    if (payload->key) {
      memset(payload->key, 0, payload->key_len);
      silc_free(payload->key);
    }
    silc_free(payload);
  }
}

/* Return ID */

unsigned char *silc_channel_key_get_id(SilcChannelKeyPayload payload, 
				       unsigned int *id_len)
{
  if (id_len)
    *id_len = payload->id_len;

  return payload->id;
}

/* Return cipher name */

unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
					   unsigned int *cipher_len)
{
  if (cipher_len)
    *cipher_len = payload->cipher_len;

  return payload->cipher;
}

/* Return key */

unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
					unsigned int *key_len)
{
  if (key_len)
    *key_len = payload->key_len;

  return payload->key;
}
