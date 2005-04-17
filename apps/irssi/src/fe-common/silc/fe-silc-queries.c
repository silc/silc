/*

  fe-silc-queries.c

  Author: Jochen Eisinger <c0ffee@penguin-breeder.org>

  Copyright (C) 2003 Jochen Eisinger

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "module.h"
#include "modules.h"
#include "signals.h"
#include "themes.h"
#include "levels.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "servers.h"
#include "channels.h"
#include "nicklist.h"
#include "ignore.h"

#include "window-items.h"
#include "fe-queries.h"
#include "fe-messages.h"
#include "hilight-text.h"
#include "printtext.h"
#include "module-formats.h"

static void sig_signed_message_query(SERVER_REC *server, const char *msg,
				const char *nick, const char *address,
				int verified)
{
	QUERY_REC *query;

	/* create query window if needed */
	query = privmsg_get_query(server, nick, FALSE, MSGLEVEL_MSGS);

	/* reset the query's last_unread_msg timestamp */
        if (query != NULL)
		query->last_unread_msg = time(NULL);
}

void fe_silc_queries_init(void)
{
  signal_add_first("message signed_private",
  		   (SIGNAL_FUNC) sig_signed_message_query);
}

void fe_silc_queries_deinit(void)
{
  signal_remove("message signed_private",
  		(SIGNAL_FUNC) sig_signed_message_query);
}
