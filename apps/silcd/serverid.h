/*

  serverid.h

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

#ifndef SERVERID_H
#define SERVERID_H

/* Prototypes */
void silc_id_create_server_id(const char *ip, SilcUInt16 port, SilcRng rng, 
			      SilcServerID **new_id);
bool silc_id_create_client_id(SilcServer server,
			      SilcServerID *server_id, SilcRng rng,
			      SilcHash md5hash, char *nickname, 
			      SilcClientID **new_id);
bool silc_id_create_channel_id(SilcServer server,
			       SilcServerID *router_id, SilcRng rng,
			       SilcChannelID **new_id);
bool silc_id_is_valid_server_id(SilcServer server,
				SilcServerID *server_id,
				SilcSocketConnection remote);

#endif
