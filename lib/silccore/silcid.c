/*

  id.c

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
/* $Id$ */

#include "silcincludes.h"
#include "silcid.h"

/* ID lengths (in bytes) without the IP address part */
#define ID_SERVER_LEN_PART      4
#define ID_CLIENT_LEN_PART      CLIENTID_HASH_LEN + 1
#define ID_CHANNEL_LEN_PART     4

/* Converts ID to string. */

unsigned char *silc_id_id2str(const void *id, SilcIdType type)
{
  unsigned char *ret_id;
  SilcServerID *server_id;
  SilcClientID *client_id;
  SilcChannelID *channel_id;
  uint32 id_len = silc_id_get_len(id, type);

  switch(type) {
  case SILC_ID_SERVER:
    server_id = (SilcServerID *)id;
    ret_id = silc_calloc(id_len, sizeof(unsigned char));
    memcpy(ret_id, server_id->ip.data, server_id->ip.data_len);
    SILC_PUT16_MSB(server_id->port, &ret_id[4]);
    SILC_PUT16_MSB(server_id->rnd, &ret_id[6]);
    return ret_id;
    break;
  case SILC_ID_CLIENT:
    client_id = (SilcClientID *)id;
    ret_id = silc_calloc(id_len, sizeof(unsigned char));
    memcpy(ret_id, client_id->ip.data, client_id->ip.data_len);
    ret_id[4] = client_id->rnd;
    memcpy(&ret_id[5], client_id->hash, CLIENTID_HASH_LEN);
    return ret_id;
    break;
  case SILC_ID_CHANNEL:
    channel_id = (SilcChannelID *)id;
    ret_id = silc_calloc(id_len, sizeof(unsigned char));
    memcpy(ret_id, channel_id->ip.data, channel_id->ip.data_len);
    SILC_PUT16_MSB(channel_id->port, &ret_id[4]);
    SILC_PUT16_MSB(channel_id->rnd, &ret_id[6]);
    return ret_id;
    break;
  }

  return NULL;
}

/* Converts string to a ID */

void *silc_id_str2id(const unsigned char *id, uint32 id_len, SilcIdType type)
{

  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id;

      if (id_len != ID_SERVER_LEN_PART + 4 &&
	  id_len != ID_SERVER_LEN_PART + 16)
	return NULL;

      server_id = silc_calloc(1, sizeof(*server_id));
      memcpy(server_id->ip.data, id, (id_len > ID_SERVER_LEN_PART + 4 ?
				      16 : 4));
      server_id->ip.data_len = (id_len > ID_SERVER_LEN_PART + 4 ? 16 : 4);
      SILC_GET16_MSB(server_id->port, &id[4]);
      SILC_GET16_MSB(server_id->rnd, &id[6]);
      return server_id;
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id;

      if (id_len != ID_CLIENT_LEN_PART + 4 &&
	  id_len != ID_CLIENT_LEN_PART + 16)
	return NULL;

      client_id = silc_calloc(1, sizeof(*client_id));
      memcpy(client_id->ip.data, id, (id_len > ID_CLIENT_LEN_PART + 4 ?
				      16 : 4));
      client_id->ip.data_len = (id_len > ID_CLIENT_LEN_PART + 4 ? 16 : 4);
      client_id->rnd = id[4];
      memcpy(client_id->hash, &id[5], CLIENTID_HASH_LEN);
      return client_id;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id;

      if (id_len != ID_CHANNEL_LEN_PART + 4 &&
	  id_len != ID_CHANNEL_LEN_PART + 16)
	return NULL;

      channel_id = silc_calloc(1, sizeof(*channel_id));
      memcpy(channel_id->ip.data, id, (id_len > ID_CHANNEL_LEN_PART + 4 ?
				       16 : 4));
      channel_id->ip.data_len = (id_len > ID_CHANNEL_LEN_PART + 4 ? 16 : 4);
      SILC_GET16_MSB(channel_id->port, &id[4]);
      SILC_GET16_MSB(channel_id->rnd, &id[6]);
      return channel_id;
    }
    break;
  }

  return NULL;
}

/* Returns length of the ID */

uint32 silc_id_get_len(const void *id, SilcIdType type)
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
      SilcServerID *server_id = (SilcServerID *)id, *new;
      new = silc_calloc(1, sizeof(*server_id));
      memcpy(new, server_id, sizeof(*server_id));
      return new;
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = (SilcClientID *)id, *new;
      new = silc_calloc(1, sizeof(*client_id));
      memcpy(new, client_id, sizeof(*client_id));
      return new;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = (SilcChannelID *)id, *new;
      new = silc_calloc(1, sizeof(*channel_id));
      memcpy(new, channel_id, sizeof(*channel_id));
      return new;
    }
    break;
  }

  return NULL;
}
