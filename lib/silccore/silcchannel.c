/*

  silcchannel.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

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

/* Channel Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelPayloadStruct {
  unsigned char *channel_name;
  unsigned char *channel_id;
  SilcUInt32 mode;
  SilcUInt16 name_len;
  SilcUInt16 id_len;
};

/* Parses channel payload returning new channel payload structure. */

SilcChannelPayload silc_channel_payload_parse(const unsigned char *payload,
					      SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcChannelPayload newp;
  int ret;

  SILC_LOG_DEBUG(("Parsing channel payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the Channel Payload. Ignore the padding. */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->channel_name, 
							 &newp->name_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->channel_id, 
							 &newp->id_len),
			     SILC_STR_UI_INT(&newp->mode),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if ((newp->name_len < 1 || newp->name_len > buffer.len - 8) ||
      (newp->id_len < 1 || newp->id_len > buffer.len - 8) ||
      (newp->id_len + newp->name_len > buffer.len - 8)) {
    SILC_LOG_ERROR(("Incorrect channel payload in packet, packet dropped"));
    goto err;
  }

  return newp;

 err:
  silc_channel_payload_free(newp);
  return NULL;
}

/* Parses list of channel payloads returning list of payloads. */

SilcDList silc_channel_payload_parse_list(const unsigned char *payload,
					  SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcDList list;
  SilcChannelPayload newp;
  SilcUInt32 len;
  int ret;

  SILC_LOG_DEBUG(("Parsing channel payload list"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  list = silc_dlist_init();

  while (buffer.len) {
    newp = silc_calloc(1, sizeof(*newp));
    if (!newp)
      goto err;
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI16_NSTRING_ALLOC(&newp->channel_name, 
							   &newp->name_len),
			       SILC_STR_UI16_NSTRING_ALLOC(&newp->channel_id, 
							   &newp->id_len),
			       SILC_STR_UI_INT(&newp->mode),
			       SILC_STR_END);
    if (ret == -1)
      goto err;

    if ((newp->name_len < 1 || newp->name_len > buffer.len - 8) ||
	(newp->id_len < 1 || newp->id_len > buffer.len - 8) ||
	(newp->id_len + newp->name_len > buffer.len - 8)) {
      SILC_LOG_ERROR(("Incorrect channel payload in packet, packet dropped"));
      goto err;
    }

    len = 2 + newp->name_len + 2 + newp->id_len + 4;
    if (buffer.len < len)
      break;
    silc_buffer_pull(&buffer, len);

    silc_dlist_add(list, newp);
  }
  
  return list;

 err:
  silc_channel_payload_list_free(list);
  return NULL;
}

/* Encode new channel payload and returns it as buffer. */

SilcBuffer silc_channel_payload_encode(const unsigned char *channel_name,
				       SilcUInt16 channel_name_len,
				       const unsigned char *channel_id,
				       SilcUInt32 channel_id_len,
				       SilcUInt32 mode)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Encoding message payload"));

  buffer = silc_buffer_alloc_size(2 + channel_name_len + 2 + 
				  channel_id_len + 4);
  if (!buffer)
    return NULL;

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

/* Frees Channel Payload */

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
    silc_dlist_del(list, entry);
    silc_free(entry);
  }

  silc_dlist_uninit(list);
}

/* Return the channel name */

unsigned char *silc_channel_get_name(SilcChannelPayload payload,
				     SilcUInt32 *channel_name_len)
{
  if (channel_name_len)
    *channel_name_len = payload->name_len;

  return payload->channel_name;
}

/* Return the channel ID */

unsigned char *silc_channel_get_id(SilcChannelPayload payload,
				   SilcUInt32 *channel_id_len)
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

SilcUInt32 silc_channel_get_mode(SilcChannelPayload payload)
{
  return payload->mode;
}


/******************************************************************************

                             Channel Key Payload

******************************************************************************/

/* Channel Key Payload structrue. Channel keys are parsed from SILC
   packets into this structure. */
struct SilcChannelKeyPayloadStruct {
  unsigned char *id;
  unsigned char *cipher;
  unsigned char *key;
  SilcUInt16 id_len;
  SilcUInt16 cipher_len;
  SilcUInt16 key_len;
};

/* Parses channel key payload returning new channel key payload structure */

SilcChannelKeyPayload 
silc_channel_key_payload_parse(const unsigned char *payload,
			       SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcChannelKeyPayload newp;
  int ret;

  SILC_LOG_DEBUG(("Parsing channel key payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the Channel Key Payload */
  ret =
    silc_buffer_unformat(&buffer,
			 SILC_STR_UI16_NSTRING_ALLOC(&newp->id, &newp->id_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&newp->cipher, 
						     &newp->cipher_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&newp->key, 
						     &newp->key_len),
			 SILC_STR_END);
  if (ret == -1)
    goto err;

  if (newp->id_len < 1 || newp->key_len < 1 || newp->cipher_len < 1 ||
      newp->id_len + newp->cipher_len + newp->key_len > buffer.len - 6) {
    SILC_LOG_ERROR(("Incorrect channel key payload in packet"));
    goto err;
  }

  return newp;

 err:
  if (newp->id)
    silc_free(newp->id);
  if (newp->cipher)
    silc_free(newp->cipher);
  if (newp->key)
    silc_free(newp->key);
  silc_free(newp);
  return NULL;
}

/* Encodes channel key payload into a buffer and returns it. This is used 
   to add channel key payload into a packet. */

SilcBuffer silc_channel_key_payload_encode(SilcUInt16 id_len,
					   const unsigned char *id,
					   SilcUInt16 cipher_len,
					   const unsigned char *cipher,
					   SilcUInt16 key_len,
					   const unsigned char *key)
{
  SilcBuffer buffer;
  SilcUInt32 len;

  SILC_LOG_DEBUG(("Encoding channel key payload"));

  /* Allocate channel payload buffer. Length is 2 + id + 2 + key + 
     2 + cipher */
  len = 2 + id_len + 2 + key_len + 2 + cipher_len;
  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;

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

/* Frees Channel Key Payload */

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
				       SilcUInt32 *id_len)
{
  if (id_len)
    *id_len = payload->id_len;

  return payload->id;
}

/* Return cipher name */

unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
					   SilcUInt32 *cipher_len)
{
  if (cipher_len)
    *cipher_len = payload->cipher_len;

  return payload->cipher;
}

/* Return key */

unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
					SilcUInt32 *key_len)
{
  if (key_len)
    *key_len = payload->key_len;

  return payload->key;
}
