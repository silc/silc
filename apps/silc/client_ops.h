/*

  client_ops.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_OPS_H
#define CLIENT_OPS_H

void silc_say(SilcClient client, SilcClientConnection conn, char *msg, ...);
void silc_channel_message(SilcClient client, SilcClientConnection conn,
			  char *sender, char *channel_name, char *msg);
void silc_private_message(SilcClient client, SilcClientConnection conn,
			  char *sender, char *msg);
void silc_command(SilcClient client, SilcClientConnection conn, 
		  SilcClientCommandContext cmd_context, int success,
		  SilcCommand command);
void silc_command_reply(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, int success,
			SilcCommand command, ...);
void silc_connect(SilcClient client, SilcClientConnection conn, int success);
void silc_disconnect(SilcClient client, SilcClientConnection conn);
unsigned char *silc_ask_passphrase(SilcClient client, 
				   SilcClientConnection conn);
int silc_verify_server_key(SilcClient client, SilcClientConnection conn, 
			   unsigned char *pk, unsigned int pk_len,
			   SilcSKEPKType pk_type);
int silc_get_auth_method(SilcClient client, SilcClientConnection conn,
			 char *hostname, unsigned short port,
			 SilcProtocolAuthMeth *auth_meth,
			 unsigned char **auth_data,
			 unsigned int *auth_data_len);

#endif
