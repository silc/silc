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
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "serverincludes.h"

/* Creates a Server ID. Newly created Server ID is returned to the
   new_id argument. */

void silc_id_create_server_id(int sock, SilcRng rng, SilcServerID **new_id)
{
  struct sockaddr_in server;
  int rval, len;

  SILC_LOG_DEBUG(("Creating new Server ID"));

  *new_id = silc_calloc(1, sizeof(**new_id));
  if (*new_id == NULL) {
    SILC_LOG_ERROR(("Could not allocate new Server ID"));
    return;
  }

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
  (*new_id)->ip = server.sin_addr;
  (*new_id)->port = server.sin_port;
  (*new_id)->rnd = silc_rng_get_rn16(rng);
}

/* Creates Client ID */

void silc_id_create_client_id(SilcServerID *server_id, SilcRng rng,
			      SilcHash md5hash, char *nickname, 
			      SilcClientID **new_id)
{
  unsigned char hash[16];

  SILC_LOG_DEBUG(("Creating new Client ID"));

  *new_id = silc_calloc(1, sizeof(**new_id));
  if (*new_id == NULL) {
    SILC_LOG_ERROR(("Could not allocate new Client ID"));
    return;
  }

  /* Create hash of the nickanem */
  silc_hash_make(md5hash, nickname, strlen(nickname), hash);

  /* Create the ID */
  (*new_id)->ip.s_addr = server_id->ip.s_addr;
  (*new_id)->rnd = silc_rng_get_byte(rng);
  memcpy((*new_id)->hash, hash, CLIENTID_HASH_LEN);
}

/* Creates Channel ID */

void silc_id_create_channel_id(SilcServerID *router_id, SilcRng rng,
			       SilcChannelID **new_id)
{
  SILC_LOG_DEBUG(("Creating new Channel ID"));

  *new_id = silc_calloc(1, sizeof(**new_id));
  if (*new_id == NULL) {
    SILC_LOG_ERROR(("Could not allocate new Channel ID"));
    return;
  }

  /* Create the ID */
  (*new_id)->ip.s_addr = router_id->ip.s_addr;
  (*new_id)->port = router_id->port;
  (*new_id)->rnd = silc_rng_get_rn16(rng);
}
