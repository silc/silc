/*
  silc-channels.c : irssi

  Copyright (C) 2000 - 2001 Timo Sirainen
                            Pekka Riikonen <priikone@poseidon.pspt.fi>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"

#include "net-nonblock.h"
#include "net-sendbuffer.h"
#include "signals.h"
#include "servers.h"
#include "commands.h"
#include "levels.h"
#include "modules.h"
#include "rawlog.h"
#include "misc.h"
#include "settings.h"

#include "channels-setup.h"

#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"
#include "window-item-def.h"

#include "fe-common/core/printtext.h"
#include "fe-common/silc/module-formats.h"

SILC_CHANNEL_REC *silc_channel_create(SILC_SERVER_REC *server,
				      const char *name, int automatic)
{
  SILC_CHANNEL_REC *rec;

  g_return_val_if_fail(server == NULL || IS_SILC_SERVER(server), NULL);
  g_return_val_if_fail(name != NULL, NULL);

  rec = g_new0(SILC_CHANNEL_REC, 1);
  rec->chat_type = SILC_PROTOCOL;
  rec->name = g_strdup(name);
  rec->server = server;

  channel_init((CHANNEL_REC *) rec, automatic);
  return rec;
}

static void sig_channel_destroyed(SILC_CHANNEL_REC *channel)
{
  if (!IS_SILC_CHANNEL(channel))
    return;

  if (channel->server != NULL && !channel->left && !channel->kicked) {
    /* destroying channel record without actually
       having left the channel yet */
    silc_command_exec(channel->server, "PART", channel->name);
  }
}

static void silc_channels_join(SILC_SERVER_REC *server,
			       const char *channels, int automatic)
{
  char **list, **tmp, *channel;

  list = g_strsplit(channels, ",", -1);
  for (tmp = list; *tmp != NULL; tmp++) {
    channel = **tmp == '#' ? g_strdup(*tmp) :
      g_strconcat("#", *tmp, NULL);
    silc_channel_create(server, channel, FALSE);
    silc_command_exec(server, "JOIN", channel);
    g_free(channel);
  }
  g_strfreev(list);
}

static void sig_connected(SILC_SERVER_REC *server)
{
  if (IS_SILC_SERVER(server))
    server->channels_join = (void *) silc_channels_join;
}

/* "server quit" signal from the core to indicate that QUIT command
   was called. */

static void sig_server_quit(SILC_SERVER_REC *server, const char *msg)
{
  if (IS_SILC_SERVER(server))
    silc_command_exec(server, "QUIT", msg);
}

/*
 * "event join". Joined to a channel.
 */

SILC_CHANNEL_REC *silc_channel_find_entry(SILC_SERVER_REC *server,
					  SilcChannelEntry entry)
{
  GSList *tmp;

  g_return_val_if_fail(IS_SILC_SERVER(server), NULL);

  for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
    SILC_CHANNEL_REC *rec = tmp->data;

    if (rec->entry == entry)
      return rec;
  }

  return NULL;
}

static void event_join(SILC_SERVER_REC *server, va_list va)
{
  SILC_CHANNEL_REC *chanrec;
  SILC_NICK_REC *nickrec;
  SilcClientEntry client;
  SilcChannelEntry channel;

  client = va_arg(va, SilcClientEntry);
  channel = va_arg(va, SilcChannelEntry);

  if (client == server->conn->local_entry) {
    /* You joined to channel */
    chanrec = silc_channel_find(server, channel->channel_name);
    if (chanrec != NULL && !chanrec->joined)
      chanrec->entry = channel;
  } else {
    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      SilcChannelUser user;

      silc_list_start(chanrec->entry->clients);
      while ((user = silc_list_get(chanrec->entry->clients)) != NULL)
	if (user->client == client) {
	  nickrec = silc_nicklist_insert(chanrec, user, TRUE);
	  break;
	}
    }
  }

  signal_emit("message join", 4, server, channel->channel_name,
	      client->nickname,
	      client->username == NULL ? "" : client->username);
}

/*
 * "event leave". Left a channel.
 */

static void event_leave(SILC_SERVER_REC *server, va_list va)
{
  SILC_CHANNEL_REC *chanrec;
  SILC_NICK_REC *nickrec;
  SilcClientEntry client;
  SilcChannelEntry channel;

  client = va_arg(va, SilcClientEntry);
  channel = va_arg(va, SilcChannelEntry);

  signal_emit("message part", 5, server, channel->channel_name,
	      client->nickname,  client->username ?  client->username : "", 
	      client->nickname);

  chanrec = silc_channel_find_entry(server, channel);
  if (chanrec != NULL) {
    nickrec = silc_nicklist_find(chanrec, client);
    if (nickrec != NULL)
      nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
  }
}

/*
 * "event signoff". Left the network.
 */

static void event_signoff(SILC_SERVER_REC *server, va_list va)
{
  SilcClientEntry client;
  GSList *nicks, *tmp;
  char *message;

  client = va_arg(va, SilcClientEntry);
  message = va_arg(va, char *);

  signal_emit("message quit", 4, server, client->nickname,
	      client->username ? client->username : "", 
	      message ? message : "");

  nicks = nicklist_get_same_unique(SERVER(server), client);
  for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
    CHANNEL_REC *channel = tmp->data;
    NICK_REC *nickrec = tmp->next->data;
    
    nicklist_remove(channel, nickrec);
  }
}

/*
 * "event topic". Changed topic.
 */

static void event_topic(SILC_SERVER_REC *server, va_list va)
{
  SILC_CHANNEL_REC *chanrec;
  SilcClientEntry client;
  SilcChannelEntry channel;
  char *topic;

  client = va_arg(va, SilcClientEntry);
  topic = va_arg(va, char *);
  channel = va_arg(va, SilcChannelEntry);

  chanrec = silc_channel_find_entry(server, channel);
  if (chanrec != NULL) {
    g_free_not_null(chanrec->topic);
    chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
    signal_emit("channel topic changed", 1, chanrec);
  }

  signal_emit("message topic", 5, server, channel->channel_name,
	      topic, client->nickname, client->username);
}

/*
 * "event invite". Invited or modified invite list.
 */

static void event_invite(SILC_SERVER_REC *server, va_list va)
{
  SilcClientEntry client;
  SilcChannelEntry channel;
  
  client = va_arg(va, SilcClientEntry);
  channel = va_arg(va, SilcChannelEntry);

  signal_emit("message invite", 4, server, channel->channel_name,
	      client->nickname, client->username);
}

/*
 * "event nick". Changed nickname.
 */

static void event_nick(SILC_SERVER_REC *server, va_list va)
{
  SilcClientEntry oldclient, newclient;

  oldclient = va_arg(va, SilcClientEntry);
  newclient = va_arg(va, SilcClientEntry);

  nicklist_rename_unique(SERVER(server),
			 oldclient, oldclient->nickname,
			 newclient, newclient->nickname);

  signal_emit("message nick", 4, server, newclient->nickname, 
	      oldclient->nickname, newclient->username);
}

/*
 * "event cmode". Changed channel mode.
 */

static void event_cmode(SILC_SERVER_REC *server, va_list va)
{
  SILC_CHANNEL_REC *chanrec;
  SilcClientEntry client;
  SilcChannelEntry channel;
  char *mode;
  uint32 modei;

  client = va_arg(va, SilcClientEntry);
  modei = va_arg(va, uint32);
  (void)va_arg(va, char *);
  (void)va_arg(va, char *);
  channel = va_arg(va, SilcChannelEntry);

  mode = silc_client_chmode(modei, channel);
  
  chanrec = silc_channel_find_entry(server, channel);
  if (chanrec != NULL) {
    g_free_not_null(chanrec->mode);
    chanrec->mode = g_strdup(mode == NULL ? "" : mode);
    signal_emit("channel mode changed", 1, chanrec);
  }
  
  printformat_module("fe-common/silc", server, channel->channel_name,
		     MSGLEVEL_MODES, SILCTXT_CHANNEL_CMODE,
		     channel->channel_name, mode ? mode : "removed all",
		     client->nickname);
  
  g_free(mode);
}

/*
 * "event cumode". Changed user's mode on channel.
 */

static void event_cumode(SILC_SERVER_REC *server, va_list va)
{
  SILC_CHANNEL_REC *chanrec;
  SilcClientEntry client, destclient;
  SilcChannelEntry channel;
  int mode;
  char *modestr;
  
  client = va_arg(va, SilcClientEntry);
  mode = va_arg(va, uint32);
  destclient = va_arg(va, SilcClientEntry);
  channel = va_arg(va, SilcChannelEntry);
  
  modestr = silc_client_chumode(mode);
  chanrec = silc_channel_find_entry(server, channel);
  if (chanrec != NULL) {
    SILC_NICK_REC *nick;
    
    if (destclient == server->conn->local_entry) {
      chanrec->chanop =
	(mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
    }

    nick = silc_nicklist_find(chanrec, destclient);
    if (nick != NULL) {
      nick->op = (mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
      signal_emit("nick mode changed", 2, chanrec, nick);
    }
  }
  
  printformat_module("fe-common/silc", server, channel->channel_name,
		     MSGLEVEL_MODES, SILCTXT_CHANNEL_CUMODE,
		     channel->channel_name, destclient->nickname, 
		     modestr ? modestr : "removed all",
		     client->nickname);

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    printformat_module("fe-common/silc", 
		       server, channel->channel_name, MSGLEVEL_CRAP,
		       SILCTXT_CHANNEL_FOUNDER,
		       channel->channel_name, destclient->nickname);

  g_free(modestr);
}

/*
 * "event motd". Received MOTD.
 */

static void event_motd(SILC_SERVER_REC *server, va_list va)
{
  char *text = va_arg(va, char *);

  if (!settings_get_bool("skip_motd"))
    printtext_multiline(server, NULL, MSGLEVEL_CRAP, "%s", text);
}

/*
 * "event channel_change". Channel ID has changed.
 */

static void event_channel_change(SILC_SERVER_REC *server, va_list va)
{

}

/*
 * "event server_signoff". Server has quit the network.
 */

static void event_server_signoff(SILC_SERVER_REC *server, va_list va)
{

}

/*
 * "event kick". Someone was kicked from channel.
 */

static void event_kick(SILC_SERVER_REC *server, va_list va)
{

}

/*
 * "event kill". Someone was killed from the network.
 */

static void event_kill(SILC_SERVER_REC *server, va_list va)
{

}

/*
 * "event ban". Someone was banned or ban list was modified.
 */

static void event_ban(SILC_SERVER_REC *server, va_list va)
{

}

/* PART (LEAVE) command. */

static void command_part(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  
  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  if (*data == '\0') {
    if (!IS_SILC_CHANNEL(item))
      cmd_return_error(CMDERR_NOT_JOINED);
    data = item->name;
  }

  chanrec = silc_channel_find(server, data);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  signal_emit("message part", 5, server, chanrec->name,
	      server->nick, server->conn->local_entry->username, "");
  
  silc_command_exec(server, "LEAVE", chanrec->name);
  signal_stop();
  
  channel_destroy(CHANNEL(chanrec));
}

/* ME local command. */

static void command_me(const char *data, SILC_SERVER_REC *server,
		       WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  char *tmpcmd = "ME", *tmp;
  uint32 argc = 0;
  unsigned char **argv;
  uint32 *argv_lens, *argv_types;
  int i;
 
  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  if (!IS_SILC_CHANNEL(item))
    cmd_return_error(CMDERR_NOT_JOINED);

  /* Now parse all arguments */
  tmp = g_strconcat(tmpcmd, " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens,
			  &argv_types, &argc, 2);
  g_free(tmp);

  if (argc < 2)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  chanrec = silc_channel_find(server, item->name);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  /* Send the action message */
  silc_client_send_channel_message(silc_client, server->conn, 
				   chanrec->entry, NULL,
				   SILC_MESSAGE_FLAG_ACTION, 
				   argv[1], argv_lens[1], TRUE);

  printformat_module("fe-common/silc", server, chanrec->entry->channel_name,
		     MSGLEVEL_ACTIONS, SILCTXT_CHANNEL_OWNACTION, argv[1]);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv_lens);
  silc_free(argv_types);
}

/* NOTICE local command. */

static void command_notice(const char *data, SILC_SERVER_REC *server,
			   WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  char *tmpcmd = "ME", *tmp;
  uint32 argc = 0;
  unsigned char **argv;
  uint32 *argv_lens, *argv_types;
  int i;
 
  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  if (!IS_SILC_CHANNEL(item))
    cmd_return_error(CMDERR_NOT_JOINED);

  /* Now parse all arguments */
  tmp = g_strconcat(tmpcmd, " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens,
			  &argv_types, &argc, 2);
  g_free(tmp);

  if (argc < 2)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  chanrec = silc_channel_find(server, item->name);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  /* Send the action message */
  silc_client_send_channel_message(silc_client, server->conn, 
				   chanrec->entry, NULL,
				   SILC_MESSAGE_FLAG_NOTICE, 
				   argv[1], argv_lens[1], TRUE);

  printformat_module("fe-common/silc", server, chanrec->entry->channel_name,
		     MSGLEVEL_NOTICES, SILCTXT_CHANNEL_OWNNOTICE, argv[1]);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv_lens);
  silc_free(argv_types);
}

/* AWAY local command.  Sends UMODE command that sets the SILC_UMODE_GONE
   flag. */

static void command_away(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  /* XXX TODO */
}

void silc_channels_init(void)
{
  signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
  signal_add("server connected", (SIGNAL_FUNC) sig_connected);
  signal_add("server quit", (SIGNAL_FUNC) sig_server_quit);

  signal_add("silc event join", (SIGNAL_FUNC) event_join);
  signal_add("silc event leave", (SIGNAL_FUNC) event_leave);
  signal_add("silc event signoff", (SIGNAL_FUNC) event_signoff);
  signal_add("silc event topic", (SIGNAL_FUNC) event_topic);
  signal_add("silc event invite", (SIGNAL_FUNC) event_invite);
  signal_add("silc event nick", (SIGNAL_FUNC) event_nick);
  signal_add("silc event cmode", (SIGNAL_FUNC) event_cmode);
  signal_add("silc event cumode", (SIGNAL_FUNC) event_cumode);
  signal_add("silc event motd", (SIGNAL_FUNC) event_motd);
  signal_add("silc event channel_change", (SIGNAL_FUNC) event_channel_change);
  signal_add("silc event server_signoff", (SIGNAL_FUNC) event_server_signoff);
  signal_add("silc event kick", (SIGNAL_FUNC) event_kick);
  signal_add("silc event kill", (SIGNAL_FUNC) event_kill);
  signal_add("silc event ban", (SIGNAL_FUNC) event_ban);
  
  command_bind("part", MODULE_NAME, (SIGNAL_FUNC) command_part);
  command_bind("me", MODULE_NAME, (SIGNAL_FUNC) command_me);
  command_bind("notice", MODULE_NAME, (SIGNAL_FUNC) command_notice);
  command_bind("away", MODULE_NAME, (SIGNAL_FUNC) command_away);

  silc_nicklist_init();
}

void silc_channels_deinit(void)
{
  signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
  signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
  signal_remove("server quit", (SIGNAL_FUNC) sig_server_quit);

  signal_remove("silc event join", (SIGNAL_FUNC) event_join);
  signal_remove("silc event leave", (SIGNAL_FUNC) event_leave);
  signal_remove("silc event signoff", (SIGNAL_FUNC) event_signoff);
  signal_remove("silc event topic", (SIGNAL_FUNC) event_topic);
  signal_remove("silc event invite", (SIGNAL_FUNC) event_invite);
  signal_remove("silc event nick", (SIGNAL_FUNC) event_nick);
  signal_remove("silc event cmode", (SIGNAL_FUNC) event_cmode);
  signal_remove("silc event cumode", (SIGNAL_FUNC) event_cumode);
  signal_remove("silc event motd", (SIGNAL_FUNC) event_motd);
  signal_remove("silc event channel_change", 
		(SIGNAL_FUNC) event_channel_change);
  signal_remove("silc event server_signoff", 
		(SIGNAL_FUNC) event_server_signoff);
  signal_remove("silc event kick", (SIGNAL_FUNC) event_kick);
  signal_remove("silc event kill", (SIGNAL_FUNC) event_kill);
  signal_remove("silc event ban", (SIGNAL_FUNC) event_ban);
  
  command_unbind("part", (SIGNAL_FUNC) command_part);
  command_unbind("me", (SIGNAL_FUNC) command_me);
  command_unbind("notice", (SIGNAL_FUNC) command_notice);
  command_unbind("away", (SIGNAL_FUNC) command_away);

  silc_nicklist_deinit();
}
