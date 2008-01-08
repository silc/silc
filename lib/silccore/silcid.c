/*

  id.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcid.h"

/* ID lengths (in bytes) without the IP address part */
#define ID_SERVER_LEN_PART      4
#define ID_CLIENT_LEN_PART      CLIENTID_HASH_LEN + 1
#define ID_CHANNEL_LEN_PART     4

/******************************************************************************

                                ID Payload

******************************************************************************/

struct SilcIDPayloadStruct {
  SilcIdType type;
  SilcUInt16 len;
  unsigned char *id;
};

/* Parses buffer and return ID payload into payload structure */

SilcIDPayload silc_id_payload_parse(const unsigned char *payload,
				    SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcIDPayload newp;
  int ret;

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&newp->type),
			     SILC_STR_UI_SHORT(&newp->len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if (newp->type > SILC_ID_CHANNEL)
    goto err;

  silc_buffer_pull(&buffer, 4);

  if (newp->len > silc_buffer_len(&buffer) ||
      newp->len > SILC_PACKET_MAX_ID_LEN)
    goto err;

  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_DATA_ALLOC(&newp->id, newp->len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  return newp;

 err:
  SILC_LOG_DEBUG(("Error parsing ID payload"));
  silc_free(newp);
  return NULL;
}

/* Return the ID directly from the raw payload data. */

SilcBool silc_id_payload_parse_id(const unsigned char *data, SilcUInt32 len,
				  SilcID *ret_id)
{
  SilcBufferStruct buffer;
  SilcIdType type;
  SilcUInt16 idlen;
  unsigned char *id_data;
  int ret;

  if (!ret_id)
    return FALSE;

  silc_buffer_set(&buffer, (unsigned char *)data, len);
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&type),
			     SILC_STR_UI_SHORT(&idlen),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if (type > SILC_ID_CHANNEL)
    goto err;

  silc_buffer_pull(&buffer, 4);

  if (idlen > silc_buffer_len(&buffer) || idlen > SILC_PACKET_MAX_ID_LEN)
    goto err;

  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_DATA(&id_data, idlen),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  ret_id->type = type;

  if (type == SILC_ID_CLIENT) {
    if (!silc_id_str2id(id_data, idlen, type, &ret_id->u.client_id,
			sizeof(SilcClientID)))
      goto err;
  } else if (type == SILC_ID_SERVER) {
    if (!silc_id_str2id(id_data, idlen, type, &ret_id->u.server_id,
			sizeof(SilcServerID)))
      goto err;
  } else {
    if (!silc_id_str2id(id_data, idlen, type, &ret_id->u.channel_id,
			sizeof(SilcChannelID)))
      goto err;
  }

  return TRUE;

 err:
  SILC_LOG_DEBUG(("Error parsing ID payload"));
  return FALSE;
}

/* Encodes ID Payload */

SilcBuffer silc_id_payload_encode(const void *id, SilcIdType type)
{
  SilcBuffer buffer;
  unsigned char id_data[32];
  SilcUInt32 len;

  if (!silc_id_id2str(id, type, id_data, sizeof(id_data), &len))
    return NULL;
  buffer = silc_id_payload_encode_data((const unsigned char *)id_data,
				       len, type);
  return buffer;
}

SilcBuffer silc_id_payload_encode_data(const unsigned char *id,
				       SilcUInt32 id_len, SilcIdType type)
{
  SilcBuffer buffer;

  buffer = silc_buffer_alloc_size(4 + id_len);
  if (!buffer)
    return NULL;
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(type),
		     SILC_STR_UI_SHORT(id_len),
		     SILC_STR_DATA(id, id_len),
		     SILC_STR_END);
  return buffer;
}

/* Free ID Payload */

void silc_id_payload_free(SilcIDPayload payload)
{
  if (payload) {
    silc_free(payload->id);
    silc_free(payload);
  }
}

/* Get ID type */

SilcIdType silc_id_payload_get_type(SilcIDPayload payload)
{
  return payload ? payload->type : 0;
}

/* Get ID */

SilcBool silc_id_payload_get_id(SilcIDPayload payload, void *ret_id,
				SilcUInt32 ret_id_len)
{
  if (!payload)
    return FALSE;
  return silc_id_str2id(payload->id, payload->len, payload->type,
			ret_id, ret_id_len);
}

/* Get raw ID data. Data is duplicated. */

unsigned char *silc_id_payload_get_data(SilcIDPayload payload)
{
  if (!payload)
    return NULL;

  return silc_memdup(payload->id, payload->len);
}

/* Get length of ID */

SilcUInt32 silc_id_payload_get_len(SilcIDPayload payload)
{
  return payload ? payload->len : 0;
}

/* Converts ID to string. */

SilcBool silc_id_id2str(const void *id, SilcIdType type,
			unsigned char *ret_id, SilcUInt32 ret_id_size,
			SilcUInt32 *ret_id_len)
{
  SilcServerID *server_id;
  SilcClientID *client_id;
  SilcChannelID *channel_id;
  SilcUInt32 id_len = silc_id_get_len(id, type);

  if (id_len > ret_id_size)
    return FALSE;

  if (ret_id_len)
    *ret_id_len = id_len;

  if (id_len > SILC_PACKET_MAX_ID_LEN)
    return FALSE;

  switch(type) {
  case SILC_ID_SERVER:
    server_id = (SilcServerID *)id;
    memcpy(ret_id, server_id->ip.data, server_id->ip.data_len);
    SILC_PUT16_MSB(server_id->port, &ret_id[server_id->ip.data_len]);
    SILC_PUT16_MSB(server_id->rnd, &ret_id[server_id->ip.data_len + 2]);
    return TRUE;
    break;
  case SILC_ID_CLIENT:
    client_id = (SilcClientID *)id;
    memcpy(ret_id, client_id->ip.data, client_id->ip.data_len);
    ret_id[client_id->ip.data_len] = client_id->rnd;
    memcpy(&ret_id[client_id->ip.data_len + 1], client_id->hash,
	   CLIENTID_HASH_LEN);
    return TRUE;
    break;
  case SILC_ID_CHANNEL:
    channel_id = (SilcChannelID *)id;
    memcpy(ret_id, channel_id->ip.data, channel_id->ip.data_len);
    SILC_PUT16_MSB(channel_id->port, &ret_id[channel_id->ip.data_len]);
    SILC_PUT16_MSB(channel_id->rnd, &ret_id[channel_id->ip.data_len + 2]);
    return TRUE;
    break;
  }

  return FALSE;
}

/* Converts string to a ID */

SilcBool silc_id_str2id(const unsigned char *id, SilcUInt32 id_len,
			SilcIdType type, void *ret_id, SilcUInt32 ret_id_size)
{
  if (id_len > SILC_PACKET_MAX_ID_LEN)
    return FALSE;

  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id = ret_id;

      if (id_len != ID_SERVER_LEN_PART + 4 &&
	  id_len != ID_SERVER_LEN_PART + 16)
	return FALSE;

      if (ret_id_size < sizeof(SilcServerID))
	return FALSE;

      memset(ret_id, 0, ret_id_size);
      memcpy(server_id->ip.data, id, (id_len > ID_SERVER_LEN_PART + 4 ?
				      16 : 4));
      server_id->ip.data_len = (id_len > ID_SERVER_LEN_PART + 4 ? 16 : 4);
      SILC_GET16_MSB(server_id->port, &id[server_id->ip.data_len]);
      SILC_GET16_MSB(server_id->rnd, &id[server_id->ip.data_len + 2]);
      return TRUE;
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = ret_id;

      if (id_len != ID_CLIENT_LEN_PART + 4 &&
	  id_len != ID_CLIENT_LEN_PART + 16)
	return FALSE;

      if (ret_id_size < sizeof(SilcClientID))
	return FALSE;

      memset(ret_id, 0, ret_id_size);
      memcpy(client_id->ip.data, id, (id_len > ID_CLIENT_LEN_PART + 4 ?
				      16 : 4));
      client_id->ip.data_len = (id_len > ID_CLIENT_LEN_PART + 4 ? 16 : 4);
      client_id->rnd = id[client_id->ip.data_len];
      memcpy(client_id->hash, &id[client_id->ip.data_len + 1],
	     CLIENTID_HASH_LEN);
      return TRUE;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = ret_id;

      if (id_len != ID_CHANNEL_LEN_PART + 4 &&
	  id_len != ID_CHANNEL_LEN_PART + 16)
	return FALSE;

      if (ret_id_size < sizeof(SilcChannelID))
	return FALSE;

      memset(ret_id, 0, ret_id_size);
      memcpy(channel_id->ip.data, id, (id_len > ID_CHANNEL_LEN_PART + 4 ?
				       16 : 4));
      channel_id->ip.data_len = (id_len > ID_CHANNEL_LEN_PART + 4 ? 16 : 4);
      SILC_GET16_MSB(channel_id->port, &id[channel_id->ip.data_len]);
      SILC_GET16_MSB(channel_id->rnd, &id[channel_id->ip.data_len + 2]);
      return TRUE;
    }
    break;
  }

  return FALSE;
}

/* Converts string to ID */

SilcBool silc_id_str2id2(const unsigned char *id, SilcUInt32 id_len,
			 SilcIdType type, SilcID *ret_id)
{
  if (!ret_id)
    return FALSE;

  ret_id->type = type;

  switch (type) {
  case SILC_ID_CLIENT:
    return silc_id_str2id(id, id_len, type, &ret_id->u.client_id,
			  sizeof(ret_id->u.client_id));
    break;

  case SILC_ID_SERVER:
    return silc_id_str2id(id, id_len, type, &ret_id->u.server_id,
			  sizeof(ret_id->u.server_id));
    break;

  case SILC_ID_CHANNEL:
    return silc_id_str2id(id, id_len, type, &ret_id->u.channel_id,
			  sizeof(ret_id->u.channel_id));
    break;
  }

  return FALSE;
}

/* Returns length of the ID */

SilcUInt32 silc_id_get_len(const void *id, SilcIdType type)
{
  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id = (SilcServerID *)id;
      return ID_SERVER_LEN_PART + server_id->ip.data_len;
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = (SilcClientID *)id;
      return ID_CLIENT_LEN_PART + client_id->ip.data_len;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = (SilcChannelID *)id;
      return ID_CHANNEL_LEN_PART + channel_id->ip.data_len;
    }
    break;
  }

  return 0;
}

/* Duplicate ID data */

void *silc_id_dup(const void *id, SilcIdType type)
{
  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id = (SilcServerID *)id;
      return silc_memdup(server_id, sizeof(*server_id));
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = (SilcClientID *)id;
      return silc_memdup(client_id, sizeof(*client_id));
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = (SilcChannelID *)id;
      return silc_memdup(channel_id, sizeof(*channel_id));
    }
    break;
  }

  return NULL;
}

/**************************** Utility functions *****************************/

/* Hash a ID. The `user_context' is the ID type. */

SilcUInt32 silc_hash_id(void *key, void *user_context)
{
  SilcIdType id_type = (SilcIdType)SILC_PTR_TO_32(user_context);
  SilcUInt32 h = 0;
  int i;

  switch (id_type) {
  case SILC_ID_CLIENT:
    {
      SilcClientID *id = (SilcClientID *)key;

      /* The client ID is hashed by hashing the hash of the ID
	 (which is a truncated MD5 hash of the nickname) so that we
	 can access the entry from the cache with both Client ID but
	 with just a hash from the ID as well. */
      return silc_hash_client_id_hash(id->hash, NULL);
    }
    break;
  case SILC_ID_SERVER:
    {
      SilcServerID *id = (SilcServerID *)key;

      h = id->port * id->rnd;
      for (i = 0; i < id->ip.data_len; i++)
	h ^= id->ip.data[i];

      return h;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *id = (SilcChannelID *)key;

      h = id->port * id->rnd;
      for (i = 0; i < id->ip.data_len; i++)
	h ^= id->ip.data[i];

      return h;
    }
    break;
  default:
    break;
  }

  return h;
}

/* Hash Client ID's hash. */

SilcUInt32 silc_hash_client_id_hash(void *key, void *user_context)
{
  int i;
  unsigned char *hash = key;
  SilcUInt32 h = 0, g;

  for (i = 0; i < CLIENTID_HASH_LEN; i++) {
    h = (h << 4) + hash[i];
    if ((g = h & 0xf0000000)) {
      h = h ^ (g >> 24);
      h = h ^ g;
    }
  }

  return h;
}

/* Compares two ID's. May be used as SilcHashTable comparison function.
   The Client ID's compares only the hash of the Client ID not any other
   part of the Client ID. Other ID's are fully compared. */

SilcBool silc_hash_id_compare(void *key1, void *key2, void *user_context)
{
  SilcIdType id_type = (SilcIdType)SILC_PTR_TO_32(user_context);
  return (id_type == SILC_ID_CLIENT ?
	  SILC_ID_COMPARE_HASH((SilcClientID *)key1, (SilcClientID *)key2) :
	  SILC_ID_COMPARE_TYPE(key1, key2, id_type));
}

/* Compares two ID's. Compares full IDs. */

SilcBool silc_hash_id_compare_full(void *key1, void *key2, void *user_context)
{
  SilcIdType id_type = (SilcIdType)SILC_PTR_TO_32(user_context);
  return SILC_ID_COMPARE_TYPE(key1, key2, id_type);
}

/* Compare two Client ID's entirely and not just the hash from the ID. */

SilcBool silc_hash_client_id_compare(void *key1, void *key2,
				     void *user_context)
{
  return SILC_ID_COMPARE_TYPE(key1, key2, SILC_ID_CLIENT);
}
