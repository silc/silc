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

                              Channel Payload

******************************************************************************/

/* Channel Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelPayloadStruct {
  unsigned short data_len;
  unsigned char *data;
  unsigned short iv_len;
  unsigned char *iv;
};

/* Parses channel payload returning new channel payload structure */

SilcChannelPayload silc_channel_payload_parse(SilcBuffer buffer)
{
  SilcChannelPayload new;

  SILC_LOG_DEBUG(("Parsing channel payload"));

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Channel Payload. Ignore padding and IV, we don't need
     them. */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_NSTRING_ALLOC(&new->data, &new->data_len),
		       SILC_STR_UI16_NSTRING_ALLOC(NULL, NULL),
		       SILC_STR_END);

  if (new->data_len < 1 || new->data_len > buffer->len) {
    SILC_LOG_ERROR(("Incorrect channel payload in packet, packet dropped"));
    goto err;
  }

  return new;

 err:
  if (new->data)
    silc_free(new->data);
  if (new->iv)
    silc_free(new->iv);
  silc_free(new);
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
				       SilcRng rng)
{
  int i;
  SilcBuffer buffer;
  unsigned int len, pad_len;
  unsigned char pad[SILC_PACKET_MAX_PADLEN];

  SILC_LOG_DEBUG(("Encoding channel payload"));

  /* Calculate length of padding. IV is not included into the calculation
     since it is not encrypted. */
  len = 2 + data_len + 2;
  pad_len = SILC_PACKET_PADLEN((len + 2));

  /* Allocate channel payload buffer */
  len += pad_len;
  buffer = silc_buffer_alloc(len + iv_len);

  /* Generate padding */
  for (i = 0; i < pad_len; i++) pad[i] = silc_rng_get_byte(rng);

  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Encode the Channel Payload */
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI_SHORT(pad_len),
		     SILC_STR_UI_XNSTRING(pad, pad_len),
		     SILC_STR_UI_XNSTRING(iv, iv_len),
		     SILC_STR_END);

  memset(pad, 0, pad_len);
  return buffer;
}

/* Free's Channel Payload */

void silc_channel_payload_free(SilcChannelPayload payload)
{
  if (payload) {
    if (payload->data)
      silc_free(payload->data);
    if (payload->iv)
      silc_free(payload->iv);
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

/* Return initial vector */

unsigned char *silc_channel_get_iv(SilcChannelPayload payload,
				   unsigned int *iv_len)
{
  if (iv_len)
    *iv_len = payload->iv_len;

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

  SILC_LOG_DEBUG(("Parsing channel key payload"));

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Channel Key Payload */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_NSTRING_ALLOC(&new->id, &new->id_len),
		       SILC_STR_UI16_NSTRING_ALLOC(&new->cipher, 
						   &new->cipher_len),
		       SILC_STR_UI16_NSTRING_ALLOC(&new->key, &new->key_len),
		       SILC_STR_END);

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

  /* Sanity checks */
  if (!id_len || !key_len || !id || !key || !cipher_len || !cipher)
    return NULL;

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
