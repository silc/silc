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

#include "silc-commands.h"

void sig_mime(SILC_SERVER_REC *server, SILC_CHANNEL_REC *channel,
               const char *blob, const char *enc, const char *type,
               const char *nick)
{

  if (!(IS_SILC_SERVER(server)))
    return;
  
  printformat_module("fe-common/silc", server, 
                        channel == NULL ? NULL : channel->name,
                        MSGLEVEL_CRAP, SILCTXT_MESSAGE_DATA,
                        nick == NULL ? "[<unknown>]" : nick, type);

}

SILC_CHANNEL_REC *silc_channel_create(SILC_SERVER_REC *server,
				      const char *name,
				      const char *visible_name,
				      int automatic)
{
  SILC_CHANNEL_REC *rec;

  g_return_val_if_fail(server == NULL || IS_SILC_SERVER(server), NULL);
  g_return_val_if_fail(name != NULL, NULL);

  rec = g_new0(SILC_CHANNEL_REC, 1);
  rec->chat_type = SILC_PROTOCOL;
  channel_init((CHANNEL_REC *)rec, (SERVER_REC *)server, name, name,
	       automatic);
  return rec;
}

static void sig_channel_destroyed(SILC_CHANNEL_REC *channel)
{
  if (!IS_SILC_CHANNEL(channel))
    return;
  if (channel->server && channel->server->disconnected)
    return;

  if (channel->server != NULL && !channel->left && !channel->kicked) {
    /* destroying channel record without actually
       having left the channel yet */
    silc_command_exec(channel->server, "LEAVE", channel->name);
  }
}

static void silc_channels_join(SILC_SERVER_REC *server,
			       const char *channels, int automatic)
{
  char **list, **tmp;
  SILC_CHANNEL_REC *chanrec;

  list = g_strsplit(channels, ",", -1);
  for (tmp = list; *tmp != NULL; tmp++) {
    chanrec = silc_channel_find(server, *tmp);
    if (chanrec)
      continue;

    silc_command_exec(server, "JOIN", *tmp);
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

static void sig_gui_quit(SILC_SERVER_REC *server, const char *msg)
{
  silc_client_stop(silc_client);
}

/* Find Irssi channel entry by SILC channel entry */

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

/* PART (LEAVE) command. */

static void command_part(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  char userhost[256];
  
  CMD_SILC_SERVER(server);

  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  if (!strcmp(data, "*") || *data == '\0') {
    if (!IS_SILC_CHANNEL(item))
      cmd_return_error(CMDERR_NOT_JOINED);
    data = item->visible_name;
  }

  chanrec = silc_channel_find(server, data);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  memset(userhost, 0, sizeof(userhost));
  snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	   server->conn->local_entry->username, 
	   server->conn->local_entry->hostname);
  signal_emit("message part", 5, server, chanrec->name,
	      server->nick, userhost, "");
  
  chanrec->left = TRUE;
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
  SilcUInt32 argc = 0;
  unsigned char *message = NULL;
  unsigned char **argv;
  SilcUInt32 *argv_lens, *argv_types;
  int i;
 
  CMD_SILC_SERVER(server);

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

  chanrec = silc_channel_find(server, item->visible_name);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  if (!silc_term_utf8()) {
    int len = silc_utf8_encoded_len(argv[1], argv_lens[1],
				    SILC_STRING_LANGUAGE);
    message = silc_calloc(len + 1, sizeof(*message));
    g_return_if_fail(message != NULL);
    silc_utf8_encode(argv[1], argv_lens[1], SILC_STRING_LANGUAGE,
		     message, len);
  }

  /* Send the action message */
  silc_client_send_channel_message(silc_client, server->conn, 
				   chanrec->entry, NULL,
				   SILC_MESSAGE_FLAG_ACTION |
				   SILC_MESSAGE_FLAG_UTF8,
				   message ? message : argv[1],
				   message ? strlen(message) : argv_lens[1],
				   TRUE);

  printformat_module("fe-common/silc", server, chanrec->entry->channel_name,
		     MSGLEVEL_ACTIONS, SILCTXT_CHANNEL_OWNACTION, 
                     server->conn->local_entry->nickname, argv[1]);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv_lens);
  silc_free(argv_types);
  silc_free(message);
}

/* ACTION local command. Same as ME but takes the channel as mandatory
   argument. */

static void command_action(const char *data, SILC_SERVER_REC *server,
			   WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  char *tmpcmd = "ME", *tmp;
  SilcUInt32 argc = 0;
  unsigned char *message = NULL;
  unsigned char **argv;
  SilcUInt32 *argv_lens, *argv_types;
  int i;
 
  CMD_SILC_SERVER(server);
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

  if (!silc_term_utf8()) {
    int len = silc_utf8_encoded_len(argv[2], argv_lens[2],
				    SILC_STRING_LANGUAGE);
    message = silc_calloc(len + 1, sizeof(*message));
    g_return_if_fail(message != NULL);
    silc_utf8_encode(argv[2], argv_lens[2], SILC_STRING_LANGUAGE,
		     message, len);
  }

  /* Send the action message */
  silc_client_send_channel_message(silc_client, server->conn, 
				   chanrec->entry, NULL,
				   SILC_MESSAGE_FLAG_ACTION |
				   SILC_MESSAGE_FLAG_UTF8,
				   message ? message : argv[2],
				   message ? strlen(message) : argv_lens[2],
				   TRUE);

  printformat_module("fe-common/silc", server, chanrec->entry->channel_name,
		     MSGLEVEL_ACTIONS, SILCTXT_CHANNEL_OWNACTION, 
                     server->conn->local_entry->nickname, argv[2]);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv_lens);
  silc_free(argv_types);
  silc_free(message);
}

/* NOTICE local command. */

static void command_notice(const char *data, SILC_SERVER_REC *server,
			   WI_ITEM_REC *item)
{
  SILC_CHANNEL_REC *chanrec;
  char *tmpcmd = "ME", *tmp;
  SilcUInt32 argc = 0;
  unsigned char *message = NULL;
  unsigned char **argv;
  SilcUInt32 *argv_lens, *argv_types;
  int i;
 
  CMD_SILC_SERVER(server);
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

  chanrec = silc_channel_find(server, item->visible_name);
  if (chanrec == NULL) 
    cmd_return_error(CMDERR_CHAN_NOT_FOUND);

  if (!silc_term_utf8()) {
    int len = silc_utf8_encoded_len(argv[1], argv_lens[1],
				    SILC_STRING_LANGUAGE);
    message = silc_calloc(len + 1, sizeof(*message));
    g_return_if_fail(message != NULL);
    silc_utf8_encode(argv[1], argv_lens[1], SILC_STRING_LANGUAGE,
		     message, len);
  }

  /* Send the action message */
  silc_client_send_channel_message(silc_client, server->conn, 
				   chanrec->entry, NULL,
				   SILC_MESSAGE_FLAG_NOTICE |
				   SILC_MESSAGE_FLAG_UTF8,
				   message ? message : argv[1],
				   message ? strlen(message) : argv_lens[1],
				   TRUE);

  printformat_module("fe-common/silc", server, chanrec->entry->channel_name,
		     MSGLEVEL_NOTICES, SILCTXT_CHANNEL_OWNNOTICE, 
                     server->conn->local_entry->nickname, argv[1]);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv_lens);
  silc_free(argv_types);
  silc_free(message);
}

/* AWAY local command.  Sends UMODE command that sets the SILC_UMODE_GONE
   flag. */

bool silc_set_away(const char *reason, SILC_SERVER_REC *server)
{
  bool set;
  
  if (!IS_SILC_SERVER(server) || !server->connected)
    return FALSE;
  
  if (*reason == '\0') {
    /* Remove any possible away message */
    silc_client_set_away_message(silc_client, server->conn, NULL);
    set = FALSE;

    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_UNSET_AWAY);
  } else {
    /* Set the away message */
    silc_client_set_away_message(silc_client, server->conn, (char *)reason);
    set = TRUE;

    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_SET_AWAY, reason);
  }

  server->usermode_away = set;
  g_free_and_null(server->away_reason);
  if (set)
    server->away_reason = g_strdup((char *)reason);

  signal_emit("away mode changed", 1, server);

  return set;
}

static void command_away(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  CMD_SILC_SERVER(server);

  if (!IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  g_free_and_null(server->away_reason);
  if ((data) && (*data != '\0'))
    server->away_reason = g_strdup(data);
  
  silc_command_exec(server, "UMODE", 
		    (server->away_reason != NULL) ? "+g" : "-g");
}

typedef struct {
  int type;			/* 1 = msg, 2 = channel */
  bool responder;
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
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_OK, client_entry->nickname);

    if (i->type == 1) {
      /* Set the private key for this client */
      silc_client_del_private_message_key(client, conn, client_entry);
      silc_client_add_private_message_key_ske(client, conn, client_entry,
					      NULL, NULL, key, i->responder);
      printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_KEY_AGREEMENT_PRIVMSG, 
			 client_entry->nickname);
      silc_ske_free_key_material(key);
    }
    
    break;
    
  case SILC_KEY_AGREEMENT_ERROR:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_ERROR, client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_FAILURE:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_FAILURE, client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_TIMEOUT:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_TIMEOUT, client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_ABORTED:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_ABORTED, client_entry->nickname);
    break;

  case SILC_KEY_AGREEMENT_ALREADY_STARTED:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_ALREADY_STARTED,
		       client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_SELF_DENIED:
    printformat_module("fe-common/silc", i->server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_SELF_DENIED);
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
  char *nick;
  WI_ITEM_REC *item;
} *KeyGetClients;

/* Callback to be called after client information is resolved from the
   server. */

static void silc_client_command_key_get_clients(SilcClient client,
						SilcClientConnection conn,
						SilcClientEntry *clients,
						SilcUInt32 clients_count,
						void *context)
{
  KeyGetClients internal = (KeyGetClients)context;

  if (!clients) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Unknown nick: %s", 
	      internal->nick);
    silc_free(internal->data);
    silc_free(internal->nick);
    silc_free(internal);
    return;
  }

  signal_emit("command key", 3, internal->data, internal->server,
	      internal->item);

  silc_free(internal->data);
  silc_free(internal->nick);
  silc_free(internal);
}

static void command_key(const char *data, SILC_SERVER_REC *server,
			WI_ITEM_REC *item)
{
  SilcClientConnection conn;
  SilcClientEntry *entrys, client_entry = NULL;
  SilcUInt32 entry_count;
  SILC_CHANNEL_REC *chanrec = NULL;
  SilcChannelEntry channel_entry = NULL;
  char *nickname = NULL, *tmp;
  int command = 0, port = 0, type = 0;
  char *hostname = NULL;
  KeyInternal internal = NULL;
  SilcUInt32 argc = 0;
  unsigned char **argv;
  SilcUInt32 *argv_lens, *argv_types;
  char *bindhost = NULL;
 
  CMD_SILC_SERVER(server);

  if (!server || !IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  conn = server->conn;

  /* Now parse all arguments */
  tmp = g_strconcat("KEY", " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens, &argv_types, &argc, 7);
  g_free(tmp);

  if (argc < 4)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  /* Get type */
  if (!strcasecmp(argv[1], "msg"))
    type = 1;
  if (!strcasecmp(argv[1], "channel"))
    type = 2;

  if (type == 0)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  if (type == 1) {
    if (argv[2][0] == '*') {
      nickname = strdup("*");
    } else {
      /* Parse the typed nickname. */
      if (!silc_parse_userfqdn(argv[2], &nickname, NULL)) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_BAD_NICK, argv[2]);
	return;
      }
      
      /* Find client entry */
      entrys = silc_client_get_clients_local(silc_client, conn, nickname,
					     argv[2], &entry_count);
      if (!entrys) {
	KeyGetClients inter = silc_calloc(1, sizeof(*inter));
	inter->server = server;
	inter->data = strdup(data);
	inter->nick = strdup(nickname);
	inter->item = item;
	silc_client_get_clients(silc_client, conn, nickname, argv[2],
				silc_client_command_key_get_clients, inter);
	goto out;
      }
      client_entry = entrys[0];
      silc_free(entrys);
    }
  }

  if (type == 2) {
    /* Get channel entry */
    char *name;

    if (argv[2][0] == '*') {
      if (!conn->current_channel) {
	silc_free(nickname);
	cmd_return_error(CMDERR_NOT_JOINED);
      }
      name = conn->current_channel->channel_name;
    } else {
      name = argv[2];
    }

    chanrec = silc_channel_find(server, name);
    if (chanrec == NULL) {
      silc_free(nickname);
      cmd_return_error(CMDERR_CHAN_NOT_FOUND);
    }
    channel_entry = chanrec->entry;
  }

  /* Set command */
  if (!strcasecmp(argv[3], "set")) {
    command = 1;

    if (argc >= 5) {
      char *cipher = NULL, *hmac = NULL;

      if (type == 1 && client_entry) {
	/* Set private message key */
	bool responder = FALSE;
	
	silc_client_del_private_message_key(silc_client, conn, client_entry);

	if (argc >= 6) {
	  if (!strcasecmp(argv[5], "-responder"))
	    responder = TRUE;
	  else
	    cipher = argv[5];
	}
	if (argc >= 7) {
	  if (!strcasecmp(argv[6], "-responder"))
	    responder = TRUE;
	  else
	    hmac = argv[6];
	}
	if (argc >= 8) {
	  if (!strcasecmp(argv[7], "-responder"))
	    responder = TRUE;
	}

	silc_client_add_private_message_key(silc_client, conn, client_entry,
					    cipher, hmac,
					    argv[4], argv_lens[4],
					    (argv[4][0] == '*' ?
					     TRUE : FALSE), responder);

	/* Send the key to the remote client so that it starts using it
	   too. */
	/* XXX for now we don't do this.  This feature is pretty stupid
	   and should perhaps be removed altogether from SILC.
	silc_client_send_private_message_key(silc_client, conn, 
					     client_entry, TRUE);
	*/
      } else if (type == 2) {
	/* Set private channel key */
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
						 channel_entry, NULL,
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
      SilcUInt32 keys_count;
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
      SilcUInt32 keys_count;
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

	  silc_say(silc_client, conn, SILC_CLIENT_MESSAGE_INFO, "%s", buf);
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

	  silc_say(silc_client, conn, SILC_CLIENT_MESSAGE_INFO, "%s", buf);
	}
      }

      silc_client_free_private_message_keys(keys, keys_count);

    } else if (type == 2) {
      SilcChannelPrivateKey *keys;
      SilcUInt32 keys_count;
      int k, i, len;
      char buf[1024];

      keys = silc_client_list_channel_private_keys(silc_client, conn, 
						   channel_entry,
						   &keys_count);

      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_CH_PRIVATE_KEY_LIST,
			 channel_entry->channel_name);

      if (!keys)
	goto out;
      
      for (k = 0; k < keys_count; k++) {
	memset(buf, 0, sizeof(buf));
	strncat(buf, "  ", 2);

	len = strlen(silc_cipher_get_name(keys[k]->cipher));
	strncat(buf, silc_cipher_get_name(keys[k]->cipher),
		len > 16 ? 16 : len);
	if (len < 16)
	  for (i = 0; i < 16 - len; i++)
	    strcat(buf, " ");
	strcat(buf, " ");
	
	len = strlen(silc_hmac_get_name(keys[k]->hmac));
	strncat(buf, silc_hmac_get_name(keys[k]->hmac), len > 16 ? 16 : len);
	if (len < 16)
	  for (i = 0; i < 16 - len; i++)
	    strcat(buf, " ");
	strcat(buf, " ");
	
	strcat(buf, "<hidden>");

	silc_say(silc_client, conn, SILC_CLIENT_MESSAGE_INFO, "%s", buf);
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
    
    if (!hostname) {
      if (settings_get_bool("use_auto_addr")) {
       
        hostname = (char *)settings_get_str("auto_public_ip");

	/* If the hostname isn't set, treat this case as if auto_public_ip 
	   wasn't set. */
        if ((hostname) && (*hostname == '\0')) {
           hostname = NULL;
        } else {
          bindhost = (char *)settings_get_str("auto_bind_ip");
            
	  /* if the bind_ip isn't set, but the public_ip IS, then assume then
	     public_ip is the same value as the bind_ip. */
          if ((bindhost) && (*bindhost == '\0'))
            bindhost = hostname;
	  port = settings_get_int("auto_bind_port");
        }
      }  /* if use_auto_addr */
    }
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

  /* Change current channel private key */
  if (!strcasecmp(argv[3], "change")) {
    command = 6;
    if (type == 2) {
      /* Unset channel key(s) */
      SilcChannelPrivateKey *keys;
      SilcUInt32 keys_count;
      int number;

      keys = silc_client_list_channel_private_keys(silc_client, conn, 
						   channel_entry,
						   &keys_count);
      if (!keys)
	goto out;

      if (argc == 4) {
	chanrec->cur_key++;
	if (chanrec->cur_key >= keys_count)
	  chanrec->cur_key = 0;
      }

      if (argc > 4) {
	number = atoi(argv[4]);
	if (!number || number > keys_count)
	  chanrec->cur_key = 0;
	else
	  chanrec->cur_key = number - 1;
      }

      /* Set the current channel private key */
      silc_client_current_channel_private_key(silc_client, conn, 
					      channel_entry, 
					      keys[chanrec->cur_key]);
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_CH_PRIVATE_KEY_CHANGE, chanrec->cur_key + 1,
			 channel_entry->channel_name);

      silc_client_free_channel_private_keys(keys, keys_count);
      goto out;
    }
  }

  if (command == 0) {
    silc_say(silc_client, conn, SILC_CLIENT_MESSAGE_INFO,
	     "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    goto out;
  }

  if (command == 4 && client_entry) {
    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT, argv[2]);
    internal->responder = TRUE;
    silc_client_send_key_agreement(
			   silc_client, conn, client_entry, hostname, 
			   bindhost, port, 
			   settings_get_int("key_exchange_timeout_secs"), 
			   keyagr_completion, internal);
    if (!hostname)
      silc_free(internal);
    goto out;
  }

  if (command == 5 && client_entry && hostname) {
    printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_NEGOTIATE, argv[2]);
    internal->responder = FALSE;
    silc_client_perform_key_agreement(silc_client, conn, client_entry, 
				      hostname, port, keyagr_completion, 
				      internal);
    goto out;
  }

 out:
  silc_free(nickname);
}

/* Lists locally saved client and server public keys. */

static void command_listkeys(const char *data, SILC_SERVER_REC *server,
			     WI_ITEM_REC *item)
{

}

void silc_channels_init(void)
{
  signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
  signal_add("server connected", (SIGNAL_FUNC) sig_connected);
  signal_add("server quit", (SIGNAL_FUNC) sig_server_quit);
  signal_add("gui exit", (SIGNAL_FUNC) sig_gui_quit);
  signal_add("mime", (SIGNAL_FUNC) sig_mime);

  command_bind_silc("part", MODULE_NAME, (SIGNAL_FUNC) command_part);
  command_bind_silc("me", MODULE_NAME, (SIGNAL_FUNC) command_me);
  command_bind_silc("action", MODULE_NAME, (SIGNAL_FUNC) command_action);
  command_bind_silc("notice", MODULE_NAME, (SIGNAL_FUNC) command_notice);
  command_bind_silc("away", MODULE_NAME, (SIGNAL_FUNC) command_away);
  command_bind_silc("key", MODULE_NAME, (SIGNAL_FUNC) command_key);
/*  command_bind_silc("listkeys", MODULE_NAME, (SIGNAL_FUNC) command_listkeys); */

  silc_nicklist_init();
}

void silc_channels_deinit(void)
{
  signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
  signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
  signal_remove("server quit", (SIGNAL_FUNC) sig_server_quit);
  signal_remove("gui exit", (SIGNAL_FUNC) sig_gui_quit);
  signal_remove("mime", (SIGNAL_FUNC) sig_mime);

  command_unbind("part", (SIGNAL_FUNC) command_part);
  command_unbind("me", (SIGNAL_FUNC) command_me);
  command_unbind("action", (SIGNAL_FUNC) command_action);
  command_unbind("notice", (SIGNAL_FUNC) command_notice);
  command_unbind("away", (SIGNAL_FUNC) command_away);
  command_unbind("key", (SIGNAL_FUNC) command_key);
/*  command_unbind("listkeys", (SIGNAL_FUNC) command_listkeys); */

  silc_nicklist_deinit();
}
