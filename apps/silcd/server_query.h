/*

  server_query.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVER_QUERY_H
#define SERVER_QUERY_H

/* Processes query as command.  The `query' is the command that is
   being processed indicated by the `cmd'.  The `query' can be one of
   the following: SILC_COMMAND_WHOIS, SILC_COMMAND_WHOWAS or
   SILC_COMMAND_IDENTIFY.  This function handles the reply sending
   to the entity who sent this query to us automatically.  Returns
   TRUE if the query is being processed or FALSE on error. */
bool silc_server_query_command(SilcServer server, SilcCommand querycmd,
			       SilcServerCommandContext cmd);

/* Find client by the Client ID indicated by the `client_id', and if not
   found then query it by using WHOIS command.  The client information
   is also resolved if the cached information is incomplete or if the
   `always_resolve' is set to TRUE.  The indication whether requested
   client was being resolved is saved into `resolved'.  If the client
   is not being resolved its entry is returned by this function.  NULL
   is returned if client is resolved.  If the client was resovled the
   caller may attach to the query by using silc_server_command_pending
   function.  The server->cmd_ident includes the query identifier. */
SilcClientEntry silc_server_query_client(SilcServer server,
					 const SilcClientID *client_id,
					 bool always_resolve,
					 bool *resolved);

#endif /* SERVER_QUERY_H */
