/*

  fe-silc-messages.c

  Author: Jochen Eisinger <c0ffee@penguin-breeder.org>

  Copyright (C) 2002 Jochen Eisinger

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

static void sig_signed_message_public(SERVER_REC * server, const char *msg,
				      const char *nick,
				      const char *address,
				      const char *target,
				      int verified)
{
  CHANNEL_REC *chanrec;
  NICK_REC *nickrec = NULL; /* we cheat here a little to keep the limit of 
			       6 parameters to a signal handler ... */
  const char *nickmode, *printnick;
  int for_me, print_channel, level;
  char *color, *freemsg = NULL;

  /* NOTE: this may return NULL if some channel is just closed with
     /WINDOW CLOSE and server still sends the few last messages */
  chanrec = channel_find(server, target);
  if (nickrec == NULL && chanrec != NULL)
    nickrec = nicklist_find(chanrec, nick);

  for_me = !settings_get_bool("hilight_nick_matches") ? FALSE :
      nick_match_msg(chanrec, msg, server->nick);
  color = for_me ? NULL :
      hilight_match_nick(server, target, nick, address, MSGLEVEL_PUBLIC,
			 msg);

  print_channel = chanrec == NULL ||
      !window_item_is_active((WI_ITEM_REC *) chanrec);
  if (!print_channel && settings_get_bool("print_active_channel") &&
      window_item_window((WI_ITEM_REC *) chanrec)->items->next != NULL)
    print_channel = TRUE;

  level = MSGLEVEL_PUBLIC;
  if (for_me || color != NULL)
    level |= MSGLEVEL_HILIGHT;

  if (settings_get_bool("emphasis"))
    msg = freemsg = expand_emphasis((WI_ITEM_REC *) chanrec, msg);

  /* get nick mode & nick what to print the msg with
     (in case there's multiple identical nicks) */
  nickmode = channel_get_nickmode(chanrec, nick);
  printnick = nickrec == NULL ? nick :
      g_hash_table_lookup(printnicks, nickrec);
  if (printnick == NULL)
    printnick = nick;

  if (!print_channel) {
    /* message to active channel in window */
    if (color != NULL) {
      /* highlighted nick */
      printformat_module("fe-common/silc", server, target,
			 level, VERIFIED_MSG(verified, SILCTXT_PUBMSG_HILIGHT),
			 color, printnick, msg, nickmode);
    } else {
      printformat_module("fe-common/silc", server, target, level,
			 for_me ? VERIFIED_MSG(verified, SILCTXT_PUBMSG_ME) :
			 	  VERIFIED_MSG(verified,SILCTXT_PUBMSG),
			 printnick, msg, nickmode);
    }
  } else {
    /* message to not existing/active channel */
    if (color != NULL) {
      /* highlighted nick */
      printformat_module("fe-common/silc", server, target, level,
			 VERIFIED_MSG(verified, SILCTXT_PUBMSG_HILIGHT_CHANNEL),
			 color, printnick, target, msg, nickmode);
    } else {
      printformat_module("fe-common/silc", server, target, level,
			 for_me ? VERIFIED_MSG(verified, SILCTXT_PUBMSG_ME_CHANNEL) :
			 VERIFIED_MSG(verified, SILCTXT_PUBMSG_CHANNEL),
			 printnick, target, msg, nickmode);
    }
  }

  g_free_not_null(freemsg);
  g_free_not_null(color);
}

static void sig_signed_message_own_public(SERVER_REC * server,
					  const char *msg,
					  const char *target)
{
  WINDOW_REC *window;
  CHANNEL_REC *channel;
  const char *nickmode;
  char *freemsg = NULL;
  int print_channel;

  channel = channel_find(server, target);
  if (channel != NULL)
    target = channel->visible_name;

  nickmode = channel_get_nickmode(channel, server->nick);

  window = channel == NULL ? NULL :
      window_item_window((WI_ITEM_REC *) channel);

  print_channel = window == NULL ||
      window->active != (WI_ITEM_REC *) channel;

  if (!print_channel && settings_get_bool("print_active_channel") &&
      window != NULL && g_slist_length(window->items) > 1)
    print_channel = TRUE;

  if (settings_get_bool("emphasis"))
    msg = freemsg = expand_emphasis((WI_ITEM_REC *) channel, msg);

  if (!print_channel) {
    printformat_module("fe-common/silc", server, target,
		       MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT |
		       MSGLEVEL_NO_ACT, SILCTXT_OWN_MSG_SIGNED, server->nick, msg,
		       nickmode);
  } else {
    printformat_module("fe-common/silc", server, target,
		       MSGLEVEL_PUBLIC | MSGLEVEL_NOHILIGHT |
		       MSGLEVEL_NO_ACT, SILCTXT_OWN_MSG_CHANNEL_SIGNED,
		       server->nick, target, msg, nickmode);
  }

  g_free_not_null(freemsg);
}


void fe_silc_messages_init(void)
{
  signal_add_last("message signed_public",
		  (SIGNAL_FUNC) sig_signed_message_public);
  signal_add_last("message signed_own_public",
		  (SIGNAL_FUNC) sig_signed_message_own_public);
}

void fe_silc_messages_deinit(void)
{
  signal_remove("message signed_public",
		(SIGNAL_FUNC) sig_signed_message_public);
  signal_remove("message signed_own_public",
		(SIGNAL_FUNC) sig_signed_message_own_public);
}
