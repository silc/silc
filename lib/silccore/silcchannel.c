/*

  silcchannel.c

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
/* Channel Payload, Channel Message Payload and Channel Key Payload 
   implementations. */
/* $Id$ */

#include "silcincludes.h"
#include "silcchannel.h"

/******************************************************************************

                              Channel Payload

******************************************************************************/

/* Channel Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelPayloadStruct {
  uint16 name_len;
  unsigned char *channel_name;
  uint16 id_len;
  unsigned char *channel_id;
  uint32 mode;
};

/* Parses channel payload returning new channel payload structure. */

SilcChannelPayload silc_channel_payload_parse(SilcBuffer buffer)
{
  SilcChannelPayload new;
  int ret;

  SILC_LOG_DEBUG(("Parsing channel payload"));

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Channel Payload. Ignore the padding. */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&new->channel_name, 
							 &new->name_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&new->channel_id, 
							 &new->id_len),
			     SILC_STR_UI_INT(&new->mode),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if ((new->name_len < 1 || new->name_len > buffer->len) ||
      (new->id_len < 1 || new->id_len > buffer->len)) {
    SILC_LOG_ERROR(("Incorrect channel payload in packet, packet dropped"));
    goto err;
  }

  return new;

 err:
  silc_channel_payload_free(new);
  return NULL;
}

/* Parses list of channel payloads returning list of payloads. */

SilcDList silc_channel_payload_parse_list(SilcBuffer buffer)
{
  SilcDList list;
  SilcChannelPayload new;
  int len, ret;

  SILC_LOG_DEBUG(("Parsing channel payload list"));

  list = silc_dlist_init();

  while (buffer->len) {
    new = silc_calloc(1, sizeof(*new));
    ret = silc_buffer_unformat(buffer,
			       SILC_STR_UI16_NSTRING_ALLOC(&new->channel_name, 
							   &new->name_len),
			       SILC_STR_UI16_NSTRING_ALLOC(&new->channel_id, 
							   &new->id_len),
			       SILC_STR_UI_INT(&new->mode),
			       SILC_STR_END);
    if (ret == -1)
      goto err;

    if ((new->name_len < 1 || new->name_len > buffer->len) ||
	(new->id_len < 1 || new->id_len > buffer->len)) {
      SILC_LOG_ERROR(("Incorrect channel payload in packet, packet dropped"));
      goto err;
    }

    len = 2 + new->name_len + 2 + new->id_len + 4;
    if (buffer->len < len)
      break;
    silc_buffer_pull(buffer, len);

    silc_dlist_add(list, new);
  }
  
  return list;

 err:
  silc_channel_payload_list_free(list);
  return NULL;
}

/* Encode new channel payload and returns it as buffer. */

SilcBuffer silc_channel_payload_encode(unsigned char *channel_name,
				       uint16 channel_name_len,
				       unsigned char *channel_id,
				       uint32 channel_id_len,
				       uint32 mode)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Encoding message payload"));

  buffer = silc_buffer_alloc(2 + channel_name_len + 2 + channel_id_len + 4);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Encode the Channel Payload */
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(channel_name_len),
		     SILC_STR_UI_XNSTRING(channel_name, channel_name_len),
		     SILC_STR_UI_SHORT(channel_id_len),
		     SILC_STR_UI_XNSTRING(channel_id, channel_id_len),
		     SILC_STR_UI_INT(mode),
		     SILC_STR_END);

  return buffer;
}

/* Free's Channel Payload */

void silc_channel_payload_free(SilcChannelPayload payload)
{
  silc_free(payload->channel_name);
  silc_free(payload->channel_id);
  silc_free(payload);
}

/* Free's list of Channel Payloads */

void silc_channel_payload_list_free(SilcDList list)
{
  SilcChannelPayload entry;

  silc_dlist_start(list);
  while ((entry = silc_dlist_get(list)) != SILC_LIST_END) {
    silc_free(entry->channel_name);
    silc_free(entry->channel_id);
    silc_free(entry);
    silc_dlist_del(list, entry);
  }

  silc_dlist_uninit(list);
}

/* Return the channel name */

unsigned char *silc_channel_get_name(SilcChannelPayload payload,
				     uint32 *channel_name_len)
{
  if (channel_name_len)
    *channel_name_len = payload->name_len;

  return payload->channel_name;
}

/* Return the channel ID */

unsigned char *silc_channel_get_id(SilcChannelPayload payload,
				   uint32 *channel_id_len)
{
  if (channel_id_len)
    *channel_id_len = payload->id_len;

  return payload->channel_id;
}

/* Return the channel ID as parsed ID. */

SilcChannelID *silc_channel_get_id_parse(SilcChannelPayload payload)
{
  return silc_id_str2id(payload->channel_id, payload->id_len,
			SILC_ID_CHANNEL);
}

/* Return the mode. The mode is arbitrary. It can be the mode of the
   channel or perhaps the mode of the client on the channel.  The protocol
   dictates what the usage of the mode is in different circumstances. */

uint32 silc_channel_get_mode(SilcChannelPayload payload)
{
  return payload->mode;
}

/******************************************************************************

                          Channel Message Payload

******************************************************************************/

/* Channel Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelMessagePayloadStruct {
  uint16 flags;
  uint16 data_len;
  unsigned char *data;
  unsigned char *mac;
  unsigned char *iv;
};

/* Decrypts the channel message payload. */

int silc_channel_message_payload_decrypt(unsigned char *data,
					 size_t data_len,
					 SilcCipher cipher,
					 SilcHmac hmac)
{
  uint32 iv_len, mac_len;
  unsigned char *end, *mac, mac2[32];

  /* Decrypt the channel message. First push the IV out of the packet.
     The IV is used in the decryption process. Then decrypt the message.
     After decyprtion, take the MAC from the decrypted packet, compute MAC
     and compare the MACs.  If they match, the decryption was successfull
     and we have the channel message ready to be displayed. */
  end = data + data_len;

  /* Push the IV out of the packet */
  iv_len = silc_cipher_get_block_len(cipher);

  /* Decrypt the channel message */
  silc_cipher_decrypt(cipher, data, data, data_len - iv_len, (end - iv_len));

  /* Take the MAC */
  if (hmac) {
    mac_len = silc_hmac_len(hmac);
    mac = (end - iv_len - mac_len);

    /* Check the MAC of the message */
    SILC_LOG_DEBUG(("Checking channel message MACs"));
    silc_hmac_make(hmac, data, (data_len - iv_len - mac_len), mac2, &mac_len);
    if (memcmp(mac, mac2, mac_len)) {
      SILC_LOG_DEBUG(("Channel message MACs does not match"));
      return FALSE;
    }
    SILC_LOG_DEBUG(("MAC is Ok"));
  }

  return TRUE;
}

/* Parses channel message payload returning new channel payload structure.
   This also decrypts it and checks the MAC. */

SilcChannelMessagePayload 
silc_channel_message_payload_parse(SilcBuffer buffer,
				   SilcCipher cipher,
				   SilcHmac hmac)
{
  SilcChannelMessagePayload new;
  int ret;
  uint32 iv_len, mac_len;

  SILC_LOG_DEBUG(("Parsing channel message payload"));

  /* Decrypt the payload */
  ret = silc_channel_message_payload_decrypt(buffer->data, buffer->len,
				     cipher, hmac);
  if (ret == FALSE)
    return NULL;

  iv_len = silc_cipher_get_block_len(cipher);
  mac_len = silc_hmac_len(hmac);

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Channel Message Payload. Ignore the padding. */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&new->flags),
			     SILC_STR_UI16_NSTRING_ALLOC(&new->data, 
							 &new->data_len),
			     SILC_STR_UI16_NSTRING(NULL, NULL),
			     SILC_STR_UI_XNSTRING(&new->mac, mac_len),
			     SILC_STR_UI_XNSTRING(&new->iv, iv_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if (new->data_len < 1 || new->data_len > buffer->len) {
    SILC_LOG_ERROR(("Incorrect channel messaeg payload in packet, "
		    "packet dropped"));
    goto err;
  }

  return new;

 err:
  silc_channel_message_payload_free(new);
  return NULL;
}

/* Encodes channel message payload into a buffer and returns it. This is used 
   to add channel message payload into a packet. As the channel payload is
   encrypted separately from other parts of the packet padding must
   be applied to the payload. */

SilcBuffer silc_channel_message_payload_encode(uint16 flags,
					       uint16 data_len,
					       unsigned char *data,
					       uint16 iv_len,
					       unsigned char *iv,
					       SilcCipher cipher,
					       SilcHmac hmac)
{
  int i;
  SilcBuffer buffer;
  uint32 len, pad_len, mac_len;
  unsigned char pad[SILC_PACKET_MAX_PADLEN];
  unsigned char mac[32];

  SILC_LOG_DEBUG(("Encoding channel message payload"));

  /* Calculate length of padding. IV is not included into the calculation
     since it is not encrypted. */
  mac_len = silc_hmac_len(hmac);
  len = 6 + data_len + mac_len;
  pad_len = SILC_PACKET_PADLEN((len + 2));

  /* Allocate channel payload buffer */
  len += pad_len + iv_len;
  buffer = silc_buffer_alloc(len);

  /* Generate padding */
  for (i = 0; i < pad_len; i++) pad[i] = silc_rng_global_get_byte();

  /* Encode the Channel Message Payload */
  silc_buffer_pull_tail(buffer, 6 + data_len + pad_len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(flags),
		     SILC_STR_UI_SHORT(data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI_SHORT(pad_len),
		     SILC_STR_UI_XNSTRING(pad, pad_len),
		     SILC_STR_END);

  /* Compute the MAC of the channel message data */
  silc_hmac_make(hmac, buffer->data, buffer->len, mac, &mac_len);

  /* Put rest of the data to the payload */
  silc_buffer_pull_tail(buffer, mac_len + iv_len);
  silc_buffer_pull(buffer, 6 + data_len + pad_len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_XNSTRING(mac, mac_len),
		     SILC_STR_UI_XNSTRING(iv, iv_len),
		     SILC_STR_END);
  silc_buffer_push(buffer, 6 + data_len + pad_len);

  /* Encrypt payload of the packet. This is encrypted with the channel key. */
  silc_cipher_encrypt(cipher, buffer->data, buffer->data, 
		      buffer->len - iv_len, iv);

  memset(pad, 0, sizeof(pad));
  memset(mac, 0, sizeof(mac));

  return buffer;
}

/* Free's Channel Message Payload */

void silc_channel_message_payload_free(SilcChannelMessagePayload payload)
{
  if (payload->data) {
    memset(payload->data, 0, payload->data_len);
    silc_free(payload->data);
  }
  silc_free(payload);
}

/* Return flags */

uint16 
silc_channel_message_get_flags(SilcChannelMessagePayload payload)
{
  return payload->flags;
}

/* Return data */

unsigned char *silc_channel_message_get_data(SilcChannelMessagePayload payload,
					     uint32 *data_len)
{
  if (data_len)
    *data_len = payload->data_len;

  return payload->data;
}

/* Return MAC. The caller knows the length of the MAC */

unsigned char *silc_channel_mesage_get_mac(SilcChannelMessagePayload payload)
{
  return payload->mac;
}

/* Return IV. The caller knows the length of the IV */

unsigned char *silc_channel_message_get_iv(SilcChannelMessagePayload payload)
{
  return payload->iv;
}

/******************************************************************************

                             Channel Key Payload

******************************************************************************/

/* Channel Key Payload structrue. Channel keys are parsed from SILC
   packets into this structure. */
struct SilcChannelKeyPayloadStruct {
  uint16 id_len;
  unsigned char *id;
  uint16 cipher_len;
  unsigned char *cipher;
  uint16 key_len;
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

SilcBuffer silc_channel_key_payload_encode(uint16 id_len,
					   unsigned char *id,
					   uint16 cipher_len,
					   unsigned char *cipher,
					   uint16 key_len,
					   unsigned char *key)
{
  SilcBuffer buffer;
  uint32 len;

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
    silc_free(payload->id);
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
				       uint32 *id_len)
{
  if (id_len)
    *id_len = payload->id_len;

  return payload->id;
}

/* Return cipher name */

unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
					   uint32 *cipher_len)
{
  if (cipher_len)
    *cipher_len = payload->cipher_len;

  return payload->cipher;
}

/* Return key */

unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
					uint32 *key_len)
{
  if (key_len)
    *key_len = payload->key_len;

  return payload->key;
}
