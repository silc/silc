/*

  silc-queries.h 

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

#ifndef SILC_QUERIES_H
#define SILC_QUERIES_H

#include "chat-protocols.h"
#include "queries.h"
#include "silc-servers.h"

/* Returns SILC_QUERY_REC if it's SILC query, NULL if it isn't. */
#define SILC_QUERY(query) \
	PROTO_CHECK_CAST(QUERY(query), QUERY_REC, chat_type, "SILC")
#define IS_SILC_QUERY(query) \
	(SILC_QUERY(query) ? TRUE : FALSE)
#define silc_query_find(server, name) \
	query_find(SERVER(server), name)

QUERY_REC *silc_query_create(const char *server_tag,
			     const char *nick, int automatic);
void silc_queries_init(void);
void silc_queries_deinit(void);
void command_attr(const char *data, SILC_SERVER_REC *server,
		  WI_ITEM_REC *item);
void silc_query_attributes_default(SilcClient client,
				   SilcClientConnection conn);
void silc_query_attributes_print(SILC_SERVER_REC *server,
				 SilcClient client,
				 SilcClientConnection conn,
				 SilcDList attrs);

#endif /* SILC_QUERIES_H */
