/*

  packet_receive.h

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

#ifndef PACKET_RECEIVE_H
#define PACKET_RECEIVE_H

/* Prototypes */

void silc_server_private_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
void silc_server_command_reply(SilcServer server,
			       SilcSocketConnection sock,
			       SilcPacketContext *packet);
void silc_server_channel_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
void silc_server_channel_key(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet);
void silc_server_replace_id(SilcServer server,
			    SilcSocketConnection sock,
			    SilcPacketContext *packet);
SilcClientEntry silc_server_new_client(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet);
SilcServerEntry silc_server_new_server(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet);
void silc_server_new_id(SilcServer server, SilcSocketConnection sock,
			SilcPacketContext *packet);
void silc_server_remove_channel_user(SilcServer server,
				     SilcSocketConnection sock,
				     SilcPacketContext *packet);
void silc_server_new_channel(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet);
void silc_server_notify(SilcServer server,
			SilcSocketConnection sock,
			SilcPacketContext *packet);
void silc_server_new_channel_user(SilcServer server,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet);
void silc_server_remove_id(SilcServer server,
			   SilcSocketConnection sock,
			   SilcPacketContext *packet);

#endif
