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

#include "serverincludes.h"
#include "server_internal.h"

/* Creates a Server ID. Newly created Server ID is returned to the
   new_id argument. */

void silc_id_create_server_id(int sock, SilcRng rng, SilcServerID **new_id)
{
  struct sockaddr_in server;
  int rval, len;

  SILC_LOG_DEBUG(("Creating new Server ID"));

  *new_id = silc_calloc(1, sizeof(**new_id));

  /* Get IP address */
  len = sizeof(server);
  rval = getsockname(sock, (struct sockaddr *)&server, &len);
  if (rval < 0) {
    SILC_LOG_ERROR(("Could not get IP address: %s", strerror(errno)));
    silc_free(*new_id);
    *new_id = NULL;
    return;
  }

  /* Create the ID */
  /* XXX Does not support IPv6 */
  SILC_PUT32_MSB(server.sin_addr.s_addr, (*new_id)->ip.data);
  (*new_id)->ip.data_len = 4;
  (*new_id)->port = server.sin_port;
  (*new_id)->rnd = silc_rng_get_rn16(rng);

  SILC_LOG_DEBUG(("New ID (%s)", silc_id_render(*new_id, SILC_ID_SERVER)));
}

/* Creates Client ID. This assures that there are no collisions in the
   created Client IDs.  If the collision would occur (meaning that there
   are 2^8 occurences of the `nickname' this will return FALSE, and the
   caller must recall the function with different nickname. If this returns
   TRUE the new ID was created successfully. */

bool silc_id_create_client_id(SilcServer server,
			      SilcServerID *server_id, SilcRng rng,
			      SilcHash md5hash, char *nickname, 
			      SilcClientID **new_id)
{
  unsigned char hash[16];
  bool finding = FALSE;

  SILC_LOG_DEBUG(("Creating new Client ID"));

  *new_id = silc_calloc(1, sizeof(**new_id));

  /* Create hash of the nickanem */
  silc_hash_make(md5hash, nickname, strlen(nickname), hash);

  /* Create the ID */
  memcpy((*new_id)->ip.data, server_id->ip.data, server_id->ip.data_len);
  (*new_id)->ip.data_len = server_id->ip.data_len;
  (*new_id)->rnd = silc_rng_get_byte(rng);
  memcpy((*new_id)->hash, hash, CLIENTID_HASH_LEN);

  /* Assure that the ID does not exist already */
  while (1) {
    if (!silc_idlist_find_client_by_id(server->local_list, 
				       *new_id, FALSE, NULL))
      if (!silc_idlist_find_client_by_id(server->global_list, 
					 *new_id, FALSE, NULL))
	break;

    /* The ID exists, start increasing the rnd from 0 until we find a
       ID that does not exist. If we wrap and it still exists then we
       will return FALSE and the caller must send some other nickname
       since this cannot be used anymore. */
    (*new_id)->rnd++;

    if (finding && (*new_id)->rnd == 0)
      return FALSE;

    if (!finding) {
      (*new_id)->rnd = 0;
      finding = TRUE;
    }
  }

  SILC_LOG_DEBUG(("New ID (%s)", silc_id_render(*new_id, SILC_ID_CLIENT)));

  return TRUE;
}

/* Creates Channel ID */

bool silc_id_create_channel_id(SilcServer server,
			       SilcServerID *router_id, SilcRng rng,
			       SilcChannelID **new_id)
{
  bool finding = TRUE;

  SILC_LOG_DEBUG(("Creating new Channel ID"));

  *new_id = silc_calloc(1, sizeof(**new_id));

  /* Create the ID */
  memcpy((*new_id)->ip.data, router_id->ip.data, router_id->ip.data_len);
  (*new_id)->ip.data_len = router_id->ip.data_len;
  (*new_id)->port = router_id->port;
  (*new_id)->rnd = silc_rng_get_rn16(rng);

  /* Assure that the ID does not exist already */
  while (1) {
    if (!silc_idlist_find_channel_by_id(server->local_list, 
					*new_id, NULL))
      break;

    (*new_id)->rnd++;
    
    if (finding && (*new_id)->rnd == 0)
      return FALSE;
    
    if (!finding) {
      (*new_id)->rnd = 0;
      finding = TRUE;
    }
  }

  SILC_LOG_DEBUG(("New ID (%s)", silc_id_render(*new_id, SILC_ID_CHANNEL)));

  return TRUE;
}
