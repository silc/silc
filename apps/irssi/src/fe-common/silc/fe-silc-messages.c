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

#define VERIFIED_MSG2(v,msg) (v >= 0 ? VERIFIED_MSG(v,msg) : msg)

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
    (char *)hilight_match_nick(server, target, nick, address, MSGLEVEL_PUBLIC,
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

static void sig_message_own_action_all(SERVER_REC *server,
					const char *msg, const char *target,
					bool is_channel, bool is_signed)
{
  void *item;
  char *freemsg = NULL;

  if (is_channel)
    item = channel_find(server, target);
  else
    item = query_find(server, target);

  if (settings_get_bool("emphasis"))
    msg = freemsg = expand_emphasis(item, msg);

  printformat(server, target,
	      MSGLEVEL_ACTIONS | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT |
	      (is_channel ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS),
	      item != NULL ?
	      (is_signed ? SILCTXT_OWN_ACTION_SIGNED : SILCTXT_OWN_ACTION) :
	      (is_signed ? SILCTXT_OWN_ACTION_TARGET_SIGNED :
	                   SILCTXT_OWN_ACTION_TARGET),
	      server->nick, msg, target);

  g_free_not_null(freemsg);
}

static void sig_message_own_action(SERVER_REC *server, const char *msg,
				   const char *target)
{
  sig_message_own_action_all(server, msg, target, TRUE, FALSE);
}

static void sig_message_own_private_action(SERVER_REC *server,
					   const char *msg, const char *target)
{
  sig_message_own_action_all(server, msg, target, FALSE, FALSE);
}

static void sig_message_own_action_signed(SERVER_REC *server,
					  const char *msg, const char *target)
{
  sig_message_own_action_all(server, msg, target, TRUE, TRUE);
}

static void sig_message_own_private_action_signed(SERVER_REC *server,
					  const char *msg, const char *target)
{
  sig_message_own_action_all(server, msg, target, FALSE, TRUE);
}

static void sig_message_action_all(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target, int is_channel,
				   int verified)
{
  void *item;
  char *freemsg = NULL;
  int level;

  level = MSGLEVEL_ACTIONS |
	  (is_channel ? MSGLEVEL_PUBLIC : MSGLEVEL_MSGS);

  if (ignore_check(server, nick, address, target, msg, level))
    return;

  if (is_channel)
    item = channel_find(server, target);
  else
    item = privmsg_get_query(server, nick, FALSE, level);

  if (settings_get_bool("emphasis"))
    msg = freemsg = expand_emphasis(item, msg);

  if (is_channel) {
    /* channel action */
    if (window_item_is_active(item)) {
      /* message to active channel in window */
      printformat(server, target, level,
		  VERIFIED_MSG2(verified, SILCTXT_ACTION_PUBLIC),
		  nick, target, msg);
    } else {
      /* message to not existing/active channel */
      printformat(server, target, level,
		  VERIFIED_MSG2(verified, SILCTXT_ACTION_PUBLIC_CHANNEL),
		  nick, target, msg);
    }
  } else {
    /* private action */
    printformat(server, nick, MSGLEVEL_ACTIONS | MSGLEVEL_MSGS,
		item == NULL ? VERIFIED_MSG2(verified, SILCTXT_ACTION_PRIVATE) :
		VERIFIED_MSG2(verified, SILCTXT_ACTION_PRIVATE_QUERY),
		nick, address == NULL ? "" : address, msg);
  }

  g_free_not_null(freemsg);
}

static void sig_message_action(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
  sig_message_action_all(server, msg, nick, address, target, TRUE, -1);
}

static void sig_message_private_action(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
  sig_message_action_all(server, msg, nick, address, target, FALSE, -1);
}

static void sig_message_action_signed(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target, int verified)
{
  sig_message_action_all(server, msg, nick, address, target, TRUE, verified);
}

static void sig_message_private_action_signed(SERVER_REC *server,
				   const char *msg, const char *nick,
				   const char *address, const char *target,
				   int verified)
{
  sig_message_action_all(server, msg, nick, address, target, FALSE, verified);
}

static void sig_message_own_notice_all(SERVER_REC *server,
					const char *msg, const char *target,
					bool is_signed)
{
  printformat(server, target,
	      MSGLEVEL_NOTICES | MSGLEVEL_NOHILIGHT | MSGLEVEL_NO_ACT,
	      (is_signed ? SILCTXT_OWN_NOTICE_SIGNED : SILCTXT_OWN_NOTICE),
	      target, msg);
}

static void sig_message_own_notice(SERVER_REC *server, const char *msg,
				   const char *target)
{
  sig_message_own_notice_all(server, msg, target, FALSE);
}

static void sig_message_own_notice_signed(SERVER_REC *server,
					  const char *msg, const char *target)
{
  sig_message_own_notice_all(server, msg, target, TRUE);
}

static void sig_message_notice_all(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target, int is_channel,
				   int verified)
{
  if (ignore_check(server, nick, address, target, msg, MSGLEVEL_NOTICES))
    return;

  if (is_channel) {
    /* channel notice */
      printformat(server, target, MSGLEVEL_NOTICES,
		  VERIFIED_MSG2(verified, SILCTXT_NOTICE_PUBLIC),
		  nick, target, msg);
  } else {
    /* private notice */
    printformat(server, nick, MSGLEVEL_NOTICES,
		VERIFIED_MSG2(verified, SILCTXT_NOTICE_PRIVATE),
		nick, address == NULL ? "" : address, msg);
  }

}

static void sig_message_notice(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
  sig_message_notice_all(server, msg, nick, address, target, TRUE, -1);
}

static void sig_message_private_notice(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target)
{
  sig_message_notice_all(server, msg, nick, address, target, FALSE, -1);
}

static void sig_message_notice_signed(SERVER_REC *server, const char *msg,
				   const char *nick, const char *address,
				   const char *target, int verified)
{
  sig_message_notice_all(server, msg, nick, address, target, TRUE, verified);
}

static void sig_message_private_notice_signed(SERVER_REC *server,
				   const char *msg, const char *nick,
				   const char *address, const char *target,
				   int verified)
{
  sig_message_notice_all(server, msg, nick, address, target, FALSE, verified);
}

void fe_silc_messages_init(void)
{
  signal_add_last("message signed_public",
		  (SIGNAL_FUNC) sig_signed_message_public);
  signal_add_last("message signed_own_public",
		  (SIGNAL_FUNC) sig_signed_message_own_public);
  signal_add_last("message signed_private",
		  (SIGNAL_FUNC) sig_signed_message_private);
  signal_add_last("message signed_own_private",
		  (SIGNAL_FUNC) sig_signed_message_own_private);

  signal_add_last("message silc own_action",
		  (SIGNAL_FUNC) sig_message_own_action);
  signal_add_last("message silc action",
		  (SIGNAL_FUNC) sig_message_action);
  signal_add_last("message silc signed_own_action",
		  (SIGNAL_FUNC) sig_message_own_action_signed);
  signal_add_last("message silc signed_action",
		  (SIGNAL_FUNC) sig_message_action_signed);
  signal_add_last("message silc own_private_action",
		  (SIGNAL_FUNC) sig_message_own_private_action);
  signal_add_last("message silc private_action",
		  (SIGNAL_FUNC) sig_message_private_action);
  signal_add_last("message silc signed_own_private_action",
		  (SIGNAL_FUNC) sig_message_own_private_action_signed);
  signal_add_last("message silc signed_private_action",
		  (SIGNAL_FUNC) sig_message_private_action_signed);

  signal_add_last("message silc own_notice",
		  (SIGNAL_FUNC) sig_message_own_notice);
  signal_add_last("message silc notice",
		  (SIGNAL_FUNC) sig_message_notice);
  signal_add_last("message silc signed_own_notice",
		  (SIGNAL_FUNC) sig_message_own_notice_signed);
  signal_add_last("message silc signed_notice",
		  (SIGNAL_FUNC) sig_message_notice_signed);
  signal_add_last("message silc own_private_notice",
		  (SIGNAL_FUNC) sig_message_own_notice);
  signal_add_last("message silc private_notice",
		  (SIGNAL_FUNC) sig_message_private_notice);
  signal_add_last("message silc signed_own_private_notice",
		  (SIGNAL_FUNC) sig_message_own_notice_signed);
  signal_add_last("message silc signed_private_notice",
		  (SIGNAL_FUNC) sig_message_private_notice_signed);
}

void fe_silc_messages_deinit(void)
{
  signal_remove("message signed_public",
		(SIGNAL_FUNC) sig_signed_message_public);
  signal_remove("message signed_own_public",
		(SIGNAL_FUNC) sig_signed_message_own_public);
  signal_remove("message signed_private",
		(SIGNAL_FUNC) sig_signed_message_private);
  signal_remove("message signed_own_private",
		(SIGNAL_FUNC) sig_signed_message_own_private);

  signal_remove("message silc own_action",
		(SIGNAL_FUNC) sig_message_own_action);
  signal_remove("message silc action",
		(SIGNAL_FUNC) sig_message_action);
  signal_remove("message silc signed_own_action",
		(SIGNAL_FUNC) sig_message_own_action_signed);
  signal_remove("message silc signed_action",
		(SIGNAL_FUNC) sig_message_action_signed);
  signal_remove("message silc own_private_action",
		(SIGNAL_FUNC) sig_message_own_private_action);
  signal_remove("message silc private_action",
		(SIGNAL_FUNC) sig_message_private_action);
  signal_remove("message silc signed_own_private_action",
		(SIGNAL_FUNC) sig_message_own_private_action_signed);
  signal_remove("message silc signed_private_action",
		(SIGNAL_FUNC) sig_message_private_action_signed);

  signal_remove("message silc own_notice",
		(SIGNAL_FUNC) sig_message_own_notice);
  signal_remove("message silc notice",
		(SIGNAL_FUNC) sig_message_notice);
  signal_remove("message silc signed_own_notice",
		(SIGNAL_FUNC) sig_message_own_notice_signed);
  signal_remove("message silc signed_notice",
		(SIGNAL_FUNC) sig_message_notice_signed);
  signal_remove("message silc own_private_notice",
		(SIGNAL_FUNC) sig_message_own_notice);
  signal_remove("message silc private_notice",
		(SIGNAL_FUNC) sig_message_private_notice);
  signal_remove("message silc signed_own_private_notice",
		(SIGNAL_FUNC) sig_message_own_notice_signed);
  signal_remove("message silc signed_private_notice",
		(SIGNAL_FUNC) sig_message_private_notice_signed);
}
