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
  SILC_CHANNEL_REC *chanrec;

  list = g_strsplit(channels, ",", -1);
  for (tmp = list; *tmp != NULL; tmp++) {
    channel = **tmp == '#' ? g_strdup(*tmp) :
      g_strconcat("#", *tmp, NULL);

    chanrec = silc_channel_find(server, channel);
    if (chanrec) {
      g_free(channel);
      continue;
    }

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
  if (IS_SILC_SERVER(server) && server->conn && server->conn->sock)
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
  char *channel_name;
  
  channel = va_arg(va, SilcChannelEntry);
  channel_name = va_arg(va, char *);
  client = va_arg(va, SilcClientEntry);

  signal_emit("message invite", 4, server, channel ? channel->channel_name :
	      channel_name, client->nickname, client->username);
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

  mode = silc_client_chmode(modei, 
			    channel->channel_key->cipher->name,
			    channel->hmac->hmac->name);
  
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
      nick->founder = (mode & SILC_CHANNEL_UMODE_CHANFO) != 0;
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
  /* Nothing interesting to do */
}

/*
 * "event server_signoff". Server has quit the network.
 */

static void event_server_signoff(SILC_SERVER_REC *server, va_list va)
{
  SilcClientEntry *clients;
  uint32 clients_count;
  int i;
  
  (void)va_arg(va, void *);
  clients = va_arg(va, SilcClientEntry *);
  clients_count = va_arg(va, uint32);
  
  for (i = 0; i < clients_count; i++)
    signal_emit("message quit", 4, server, clients[i]->nickname,
		clients[i]->username ? clients[i]->username : "", 
		"server signoff");
}

/*
 * "event kick". Someone was kicked from channel.
 */

static void event_kick(SILC_SERVER_REC *server, va_list va)
{
  SilcClientConnection conn = server->conn;
  SilcClientEntry client_entry;
  SilcChannelEntry channel_entry;
  char *tmp;
  SILC_CHANNEL_REC *chanrec;

  client_entry = va_arg(va, SilcClientEntry);
  tmp = va_arg(va, char *);
  channel_entry = va_arg(va, SilcChannelEntry);

  chanrec = silc_channel_find_entry(server, channel_entry);
  
  if (client_entry == conn->local_entry) {
    printformat_module("fe-common/silc", server, channel_entry->channel_name,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_KICKED_YOU, 
		       channel_entry->channel_name, tmp ? tmp : "");
    if (chanrec) {
      chanrec->kicked = TRUE;
      channel_destroy((CHANNEL_REC *)chanrec);
    }
  } else {
    printformat_module("fe-common/silc", server, channel_entry->channel_name,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_KICKED, 
		       client_entry->nickname,
		       channel_entry->channel_name, tmp ? tmp : "");

    if (chanrec) {
      SILC_NICK_REC *nickrec = silc_nicklist_find(chanrec, client_entry);
      if (nickrec != NULL)
	nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
    }
  }
}

/*
 * "event kill". Someone was killed from the network.
 */

static void event_kill(SILC_SERVER_REC *server, va_list va)
{
  SilcClientConnection conn = server->conn;
  SilcClientEntry client_entry;
  char *tmp;

  client_entry = va_arg(va, SilcClientEntry);
  tmp = va_arg(va, char *);
  
  if (client_entry == conn->local_entry) {
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED_YOU, 
		       tmp ? tmp : "");
  } else {
    GSList *nicks, *tmpn;
    nicks = nicklist_get_same_unique(SERVER(server), client_entry);
    for (tmpn = nicks; tmpn != NULL; tmpn = tmpn->next->next) {
      CHANNEL_REC *channel = tmpn->data;
      NICK_REC *nickrec = tmpn->next->data;
      nicklist_remove(channel, nickrec);
    }

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED, 
		       client_entry->nickname,
		       tmp ? tmp : "");
  }
}

/* PART (LEAVE) command. */

static void command_part(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  
  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  if (!strcmp(data, "*") || *data == '\0') {
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
		     MSGLEVEL_ACTIONS, SILCTXT_CHANNEL_OWNACTION, 
                     server->conn->local_entry->nickname, argv[1]);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv_lens);
  silc_free(argv_types);
}

/* ACTION local command. Same as ME but takes the channel as mandatory
   argument. */

static void command_action(const char *data, SILC_SERVER_REC *server,
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
			  &argv_types, &argc, 3);
  g_free(tmp);

  if (argc < 3)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  chanrec = silc_channel_find(server, argv[1]);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  /* Send the action message */
  silc_client_send_channel_message(silc_client, server->conn, 
				   chanrec->entry, NULL,
				   SILC_MESSAGE_FLAG_ACTION, 
				   argv[2], argv_lens[2], TRUE);

  printformat_module("fe-common/silc", server, chanrec->entry->channel_name,
		     MSGLEVEL_ACTIONS, SILCTXT_CHANNEL_OWNACTION, 
                     server->conn->local_entry->nickname, argv[2]);

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
		     MSGLEVEL_NOTICES, SILCTXT_CHANNEL_OWNNOTICE, 
                     server->conn->local_entry->nickname, argv[1]);

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
  bool set;

  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  if (*data == '\0') {
    /* Remove any possible away message */
    silc_client_set_away_message(silc_client, server->conn, NULL);
    set = FALSE;

    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_UNSET_AWAY);
  } else {
    /* Set the away message */
    silc_client_set_away_message(silc_client, server->conn, (char *)data);
    set = TRUE;

    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_SET_AWAY, data);
  }

  signal_emit("away mode changed", 1, server);

  silc_command_exec(server, "UMODE", set ? "+g" : "-g");
}

typedef struct {
  int type;			/* 1 = msg, 2 = channel */
  SILC_SERVER_REC *server;
} *KeyInternal;

/* Key agreement callback that is called after the key agreement protocol
   has been performed. This is called also if error occured during the
   key agreement protocol. The `key' is the allocated key material and
   the caller is responsible of freeing it. The `key' is NULL if error
   has occured. The application can freely use the `key' to whatever
   purpose it needs. See lib/silcske/silcske.h for the definition of
   the SilcSKEKeyMaterial structure. */

static void keyagr_completion(SilcClient client,
			      SilcClientConnection conn,
			      SilcClientEntry client_entry,
			      SilcKeyAgreementStatus status,
			      SilcSKEKeyMaterial *key,
			      void *context)
{
  KeyInternal i = (KeyInternal)context;

  switch(status) {
  case SILC_KEY_AGREEMENT_OK:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_OK, client_entry->nickname);

    if (i->type == 1) {
      /* Set the private key for this client */
      silc_client_del_private_message_key(client, conn, client_entry);
      silc_client_add_private_message_key_ske(client, conn, client_entry,
					      NULL, key);
      printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_NOTICES,
			 SILCTXT_KEY_AGREEMENT_PRIVMSG, 
			 client_entry->nickname);
      silc_ske_free_key_material(key);
    }
    
    break;
    
  case SILC_KEY_AGREEMENT_ERROR:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_ERROR, client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_FAILURE:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_FAILURE, client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_TIMEOUT:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_TIMEOUT, client_entry->nickname);
    break;
    
  default:
    break;
  } 

  if (i)
    silc_free(i);
}

/* Local command KEY. This command is used to set and unset private
   keys for channels, set and unset private keys for private messages
   with remote clients and to send key agreement requests and
   negotiate the key agreement protocol with remote client.  The
   key agreement is supported only to negotiate private message keys,
   it currently cannot be used to negotiate private keys for channels,
   as it is not convenient for that purpose. */

typedef struct {
  SILC_SERVER_REC *server;
  char *data;
  WI_ITEM_REC *item;
} *KeyGetClients;

/* Callback to be called after client information is resolved from the
   server. */

SILC_CLIENT_CMD_FUNC(key_get_clients)
{
  KeyGetClients internal = (KeyGetClients)context;
  signal_emit("command key", 3, internal->data, internal->server,
	      internal->item);
  silc_free(internal->data);
  silc_free(internal);
}

static void command_key(const char *data, SILC_SERVER_REC *server,
			WI_ITEM_REC *item)
{
  SilcClientConnection conn = server->conn;
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel_entry = NULL;
  uint32 num = 0;
  char *nickname = NULL, *serv = NULL, *tmp;
  int command = 0, port = 0, type = 0;
  char *hostname = NULL;
  KeyInternal internal = NULL;
  uint32 argc = 0;
  unsigned char **argv;
  uint32 *argv_lens, *argv_types;
 
  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  /* Now parse all arguments */
  tmp = g_strconcat("KEY", " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens, &argv_types, &argc, 7);
  g_free(tmp);

  if (argc < 4) {
    silc_say(silc_client, conn, "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    return;
  }

  /* Get type */
  if (!strcasecmp(argv[1], "msg"))
    type = 1;
  if (!strcasecmp(argv[1], "channel"))
    type = 2;

  if (type == 0) {
    silc_say(silc_client, conn, "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    return;
  }

  if (type == 1) {
    if (argv[2][0] == '*') {
      nickname = "*";
    } else {
      /* Parse the typed nickname. */
      if (!silc_parse_nickname(argv[2], &nickname, &serv, &num)) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_BAD_NICK, argv[2]);
	return;
      }
      
      /* Find client entry */
      client_entry = silc_idlist_get_client(silc_client, conn, nickname, 
					    serv, num, TRUE);
      if (!client_entry) {
	KeyGetClients inter = silc_calloc(1, sizeof(*inter));
	inter->server = server;
	inter->data = strdup(data);
	inter->item = item;

	/* Client entry not found, it was requested thus mark this to be
	   pending command. */
	silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				    conn->cmd_ident, 
				    NULL, silc_client_command_key_get_clients, 
				    inter);
	goto out;
      }
    }
  }

  if (type == 2) {
    /* Get channel entry */
    char *name;

    if (argv[2][0] == '*') {
      if (!conn->current_channel) {
	if (nickname)
	  silc_free(nickname);
	if (serv)
	  silc_free(serv);
	cmd_return_error(CMDERR_NOT_JOINED);
      }
      name = conn->current_channel->channel_name;
    } else {
      name = argv[2];
    }

    channel_entry = silc_client_get_channel(silc_client, conn, name);
    if (!channel_entry) {
      if (nickname)
	silc_free(nickname);
      if (serv)
	silc_free(serv);
      cmd_return_error(CMDERR_NOT_JOINED);
    }
  }

  /* Set command */
  if (!strcasecmp(argv[3], "set")) {
    command = 1;

    if (argc >= 5) {
      if (type == 1 && client_entry) {
	/* Set private message key */
	
	silc_client_del_private_message_key(silc_client, conn, client_entry);

	if (argc >= 6)
	  silc_client_add_private_message_key(silc_client, conn, client_entry,
					      argv[5], argv[4],
					      argv_lens[4],
					      (argv[4][0] == '*' ?
					       TRUE : FALSE));
	else
	  silc_client_add_private_message_key(silc_client, conn, client_entry,
					      NULL, argv[4],
					      argv_lens[4],
					      (argv[4][0] == '*' ?
					       TRUE : FALSE));

	/* Send the key to the remote client so that it starts using it
	   too. */
	silc_client_send_private_message_key(silc_client, conn, 
					     client_entry, TRUE);
      } else if (type == 2) {
	/* Set private channel key */
	char *cipher = NULL, *hmac = NULL;

	if (!(channel_entry->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
	  printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			     SILCTXT_CH_PRIVATE_KEY_NOMODE, 
			     channel_entry->channel_name);
	  goto out;
	}

	if (argc >= 6)
	  cipher = argv[5];
	if (argc >= 7)
	  hmac = argv[6];

	if (!silc_client_add_channel_private_key(silc_client, conn, 
						 channel_entry,
						 cipher, hmac,
						 argv[4],
						 argv_lens[4])) {
	  printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			     SILCTXT_CH_PRIVATE_KEY_ERROR, 
			     channel_entry->channel_name);
	  goto out;
	}

	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CH_PRIVATE_KEY_ADD, 
			   channel_entry->channel_name);
      }
    }

    goto out;
  }
  
  /* Unset command */
  if (!strcasecmp(argv[3], "unset")) {
    command = 2;

    if (type == 1 && client_entry) {
      /* Unset private message key */
      silc_client_del_private_message_key(silc_client, conn, client_entry);
    } else if (type == 2) {
      /* Unset channel key(s) */
      SilcChannelPrivateKey *keys;
      uint32 keys_count;
      int number;

      if (argc == 4)
	silc_client_del_channel_private_keys(silc_client, conn, 
					     channel_entry);

      if (argc > 4) {
	number = atoi(argv[4]);
	keys = silc_client_list_channel_private_keys(silc_client, conn, 
						     channel_entry,
						     &keys_count);
	if (!keys)
	  goto out;

	if (!number || number > keys_count) {
	  silc_client_free_channel_private_keys(keys, keys_count);
	  goto out;
	}

	silc_client_del_channel_private_key(silc_client, conn, channel_entry,
					    keys[number - 1]);
	silc_client_free_channel_private_keys(keys, keys_count);
      }

      goto out;
    }
  }

  /* List command */
  if (!strcasecmp(argv[3], "list")) {
    command = 3;

    if (type == 1) {
      SilcPrivateMessageKeys keys;
      uint32 keys_count;
      int k, i, len;
      char buf[1024];

      keys = silc_client_list_private_message_keys(silc_client, conn, 
						   &keys_count);
      if (!keys)
	goto out;

      /* list the private message key(s) */
      if (nickname[0] == '*') {
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_PRIVATE_KEY_LIST);
	for (k = 0; k < keys_count; k++) {
	  memset(buf, 0, sizeof(buf));
	  strncat(buf, "  ", 2);
	  len = strlen(keys[k].client_entry->nickname);
	  strncat(buf, keys[k].client_entry->nickname, len > 30 ? 30 : len);
	  if (len < 30)
	    for (i = 0; i < 30 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");
	  
	  len = strlen(keys[k].cipher);
	  strncat(buf, keys[k].cipher, len > 14 ? 14 : len);
	  if (len < 14)
	    for (i = 0; i < 14 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");

	  if (keys[k].key)
	    strcat(buf, "<hidden>");
	  else
	    strcat(buf, "*generated*");

	  silc_say(silc_client, conn, "%s", buf);
	}
      } else {
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_PRIVATE_KEY_LIST_NICK,
			   client_entry->nickname);
	for (k = 0; k < keys_count; k++) {
	  if (keys[k].client_entry != client_entry)
	    continue;

	  memset(buf, 0, sizeof(buf));
	  strncat(buf, "  ", 2);
	  len = strlen(keys[k].client_entry->nickname);
	  strncat(buf, keys[k].client_entry->nickname, len > 30 ? 30 : len);
	  if (len < 30)
	    for (i = 0; i < 30 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");
	  
	  len = strlen(keys[k].cipher);
	  strncat(buf, keys[k].cipher, len > 14 ? 14 : len);
	  if (len < 14)
	    for (i = 0; i < 14 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");

	  if (keys[k].key)
	    strcat(buf, "<hidden>");
	  else
	    strcat(buf, "*generated*");

	  silc_say(silc_client, conn, "%s", buf);
	}
      }

      silc_client_free_private_message_keys(keys, keys_count);
    } else if (type == 2) {
      SilcChannelPrivateKey *keys;
      uint32 keys_count;
      int k, i, len;
      char buf[1024];

      keys = silc_client_list_channel_private_keys(silc_client, conn, 
						   channel_entry,
						   &keys_count);
      if (!keys)
	goto out;
      
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_CH_PRIVATE_KEY_LIST,
			 channel_entry->channel_name);
      for (k = 0; k < keys_count; k++) {
	memset(buf, 0, sizeof(buf));
	strncat(buf, "  ", 2);

	len = strlen(keys[k]->cipher->cipher->name);
	strncat(buf, keys[k]->cipher->cipher->name, len > 16 ? 16 : len);
	if (len < 16)
	  for (i = 0; i < 16 - len; i++)
	    strcat(buf, " ");
	strcat(buf, " ");
	
	len = strlen(keys[k]->hmac->hmac->name);
	strncat(buf, keys[k]->hmac->hmac->name, len > 16 ? 16 : len);
	if (len < 16)
	  for (i = 0; i < 16 - len; i++)
	    strcat(buf, " ");
	strcat(buf, " ");
	
	strcat(buf, "<hidden>");

	silc_say(silc_client, conn, "%s", buf);
      }
      
      silc_client_free_channel_private_keys(keys, keys_count);
    }

    goto out;
  }

  /* Send command is used to send key agreement */
  if (!strcasecmp(argv[3], "agreement")) {
    command = 4;

    if (argc >= 5)
      hostname = argv[4];
    if (argc >= 6)
      port = atoi(argv[5]);

    internal = silc_calloc(1, sizeof(*internal));
    internal->type = type;
    internal->server = server;
  }

  /* Start command is used to start key agreement (after receiving the
     key_agreement client operation). */
  if (!strcasecmp(argv[3], "negotiate")) {
    command = 5;

    if (argc >= 5)
      hostname = argv[4];
    if (argc >= 6)
      port = atoi(argv[5]);

    internal = silc_calloc(1, sizeof(*internal));
    internal->type = type;
    internal->server = server;
  }

  if (command == 0) {
    silc_say(silc_client, conn, "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    goto out;
  }

  if (command == 4 && client_entry) {
    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT, argv[2]);
    silc_client_send_key_agreement(silc_client, conn, client_entry, hostname, 
				   port, 120, keyagr_completion, internal);
    goto out;
  }

  if (command == 5 && client_entry && hostname) {
    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_NEGOTIATE, argv[2]);
    silc_client_perform_key_agreement(silc_client, conn, client_entry, 
				      hostname, port, keyagr_completion, 
				      internal);
    goto out;
  }

 out:
  if (nickname)
    silc_free(nickname);
  if (serv)
    silc_free(serv);
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
  
  command_bind("part", MODULE_NAME, (SIGNAL_FUNC) command_part);
  command_bind("me", MODULE_NAME, (SIGNAL_FUNC) command_me);
  command_bind("action", MODULE_NAME, (SIGNAL_FUNC) command_action);
  command_bind("notice", MODULE_NAME, (SIGNAL_FUNC) command_notice);
  command_bind("away", MODULE_NAME, (SIGNAL_FUNC) command_away);
  command_bind("key", MODULE_NAME, (SIGNAL_FUNC) command_key);

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
  
  command_unbind("part", (SIGNAL_FUNC) command_part);
  command_unbind("me", (SIGNAL_FUNC) command_me);
  command_unbind("action", (SIGNAL_FUNC) command_action);
  command_unbind("notice", (SIGNAL_FUNC) command_notice);
  command_unbind("away", (SIGNAL_FUNC) command_away);
  command_unbind("key", (SIGNAL_FUNC) command_key);

  silc_nicklist_deinit();
}
