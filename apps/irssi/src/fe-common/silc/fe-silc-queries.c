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

#define VERIFIED_MSG(v,msg) (v == SILC_MSG_SIGNED_VERIFIED ? \
				msg##_SIGNED : (v == SILC_MSG_SIGNED_UNKNOWN ? \
				msg##_UNKNOWN : msg##_FAILED))

static void sig_signed_message_private(SERVER_REC * server,
				       const char *msg, const char *nick,
				       const char *address, int verified)
{
  QUERY_REC *query;
  char *freemsg = NULL;

  query = query_find(server, nick);

  if (settings_get_bool("emphasis"))
    msg = freemsg = expand_emphasis((WI_ITEM_REC *) query, msg);

  printformat_module("fe-common/silc", server, nick, MSGLEVEL_MSGS,
		     query == NULL ? VERIFIED_MSG(verified, SILCTXT_MSG_PRIVATE) :
		     VERIFIED_MSG(verified, SILCTXT_MSG_PRIVATE_QUERY), nick, address, msg);

  g_free_not_null(freemsg);
}

static void sig_signed_message_own_private(SERVER_REC * server,
					   const char *msg,
					   const char *target,
					   const char *origtarget)
{
  QUERY_REC *query;
  char *freemsg = NULL;

  g_return_if_fail(server != NULL);
  g_return_if_fail(msg != NULL);

  if (target == NULL) {
    /* this should only happen if some special target failed and
       we should display some error message. currently the special
       targets are only ',' and '.'. */
    g_return_if_fail(strcmp(origtarget, ",") == 0 ||
		     strcmp(origtarget, ".") == 0);

    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CLIENTNOTICE,
		       *origtarget == ',' ? SILCTXT_NO_MSGS_GOT :
		       SILCTXT_NO_MSGS_SENT);
    signal_stop();
    return;
  }

  query = privmsg_get_query(server, target, TRUE, MSGLEVEL_MSGS);

  if (settings_get_bool("emphasis"))
    msg = freemsg = expand_emphasis((WI_ITEM_REC *) query, msg);

  printformat_module("fe-common/silc", server, target,
		     MSGLEVEL_MSGS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
		     query == NULL ? SILCTXT_OWN_MSG_PRIVATE_SIGNED :
		     SILCTXT_OWN_MSG_PRIVATE_QUERY_SIGNED, target, msg,
		     server->nick);

  g_free_not_null(freemsg);
}

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
  signal_add_last("message signed_private",
		  (SIGNAL_FUNC) sig_signed_message_private);
  signal_add_last("message signed_own_private",
		  (SIGNAL_FUNC) sig_signed_message_own_private);

  signal_add_first("message signed_private",
  		   (SIGNAL_FUNC) sig_signed_message_query);
}

void fe_silc_queries_deinit(void)
{
  signal_remove("message signed_private",
		(SIGNAL_FUNC) sig_signed_message_private);
  signal_remove("message signed_own_private",
		(SIGNAL_FUNC) sig_signed_message_own_private);

  signal_remove("message signed_private",
  		(SIGNAL_FUNC) sig_signed_message_query);
}
