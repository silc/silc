/*

  id.c

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
/* $Id$ */

#include "silcincludes.h"

/* Converts ID to string. */

unsigned char *silc_id_id2str(void *id, SilcIdType type)
{
  unsigned char *ret_id;
  SilcServerID *server_id;
  SilcClientID *client_id;
  SilcChannelID *channel_id;

  switch(type) {
  case SILC_ID_SERVER:
    server_id = (SilcServerID *)id;
    ret_id = silc_calloc(8, sizeof(unsigned char));
    SILC_PUT32_MSB(server_id->ip.s_addr, ret_id);
    SILC_PUT16_MSB(server_id->port, &ret_id[4]);
    SILC_PUT16_MSB(server_id->rnd, &ret_id[6]);
    return ret_id;
    break;
  case SILC_ID_CLIENT:
    client_id = (SilcClientID *)id;
    ret_id = silc_calloc(16, sizeof(unsigned char));
    SILC_PUT32_MSB(client_id->ip.s_addr, ret_id);
    ret_id[4] = client_id->rnd;
    memcpy(&ret_id[5], client_id->hash, CLIENTID_HASH_LEN);
    return ret_id;
    break;
  case SILC_ID_CHANNEL:
    channel_id = (SilcChannelID *)id;
    ret_id = silc_calloc(8, sizeof(unsigned char));
    SILC_PUT32_MSB(channel_id->ip.s_addr, ret_id);
    SILC_PUT16_MSB(channel_id->port, &ret_id[4]);
    SILC_PUT16_MSB(channel_id->rnd, &ret_id[6]);
    return ret_id;
    break;
  }

  return NULL;
}

/* Converts string to a ID */

void *silc_id_str2id(unsigned char *id, unsigned int id_len, SilcIdType type)
{

  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id;

      if (id_len != SILC_ID_SERVER_LEN)
	return NULL;

      server_id = silc_calloc(1, sizeof(*server_id));
      SILC_GET32_MSB(server_id->ip.s_addr, id);
      SILC_GET16_MSB(server_id->port, &id[4]);
      SILC_GET16_MSB(server_id->rnd, &id[6]);
      return server_id;
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id;

      if (id_len != SILC_ID_CLIENT_LEN)
	return NULL;

      client_id = silc_calloc(1, sizeof(*client_id));
      SILC_GET32_MSB(client_id->ip.s_addr, id);
      client_id->rnd = id[4];
      memcpy(client_id->hash, &id[5], CLIENTID_HASH_LEN);
      return client_id;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id;

      if (id_len != SILC_ID_CHANNEL_LEN)
	return NULL;

      channel_id = silc_calloc(1, sizeof(*channel_id));
      SILC_GET32_MSB(channel_id->ip.s_addr, id);
      SILC_GET16_MSB(channel_id->port, &id[4]);
      SILC_GET16_MSB(channel_id->rnd, &id[6]);
      return channel_id;
    }
    break;
  }

  return NULL;
}

/* Returns length of the ID */

unsigned int silc_id_get_len(SilcIdType type)
{
  switch(type) {
  case SILC_ID_SERVER:
    return SILC_ID_SERVER_LEN;
    break;
  case SILC_ID_CLIENT:
    return SILC_ID_CLIENT_LEN;
    break;
  case SILC_ID_CHANNEL:
    return SILC_ID_CHANNEL_LEN;
    break;
  }

  return 0;
}
