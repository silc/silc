/*

  idlist.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef IDLIST_H
#define IDLIST_H

/* Prototypes. These are used only by the library. Application should not
   call these directly. */

SilcClientEntry
silc_client_add_client(SilcClient client, SilcClientConnection conn,
		       char *nickname, char *username, 
		       char *userinfo, SilcClientID *id, SilcUInt32 mode);
void silc_client_update_client(SilcClient client,
			       SilcClientConnection conn,
			       SilcClientEntry client_entry,
			       const char *nickname,
			       const char *username,
			       const char *userinfo,
			       SilcUInt32 mode);
void silc_client_del_client_entry(SilcClient client, 
				  SilcClientConnection conn,
				  SilcClientEntry client_entry);
SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       const char *nickname,
				       const char *format,
				       bool query);
SilcChannelEntry silc_client_add_channel(SilcClient client,
					 SilcClientConnection conn,
					 const char *channel_name,
					 SilcUInt32 mode, 
					 SilcChannelID *channel_id);
SilcServerEntry silc_client_add_server(SilcClient client,
				       SilcClientConnection conn,
				       const char *server_name,
				       const char *server_info,
				       SilcServerID *server_id);
void silc_client_update_server(SilcClient client,
			       SilcClientConnection conn,
			       SilcServerEntry server_entry,
			       const char *server_name,
			       const char *server_info);
bool silc_client_replace_channel_id(SilcClient client,
				    SilcClientConnection conn,
				    SilcChannelEntry channel,
				    SilcChannelID *new_id);
void silc_client_nickname_format(SilcClient client, 
				 SilcClientConnection conn,
				 SilcClientEntry client_entry);

#endif
