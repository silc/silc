/*

  client_ops.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

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
#include "chat-protocols.h"
#include "args.h"

#include "chatnets.h"
#include "servers-setup.h"
#include "channels-setup.h"
#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"

#include "signals.h"
#include "levels.h"
#include "settings.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

static void 
silc_verify_public_key_internal(SilcClient client, SilcClientConnection conn,
				const char *name, SilcSocketType conn_type, 
				unsigned char *pk, SilcUInt32 pk_len, 
				SilcSKEPKType pk_type,
				SilcVerifyPublicKey completion, void *context);

void silc_say(SilcClient client, SilcClientConnection conn,
	      SilcClientMessageType type, char *msg, ...)
{
  SILC_SERVER_REC *server;
  va_list va;
  char *str;

  server = conn == NULL ? NULL : conn->context;
  
  va_start(va, msg);
  str = g_strdup_vprintf(msg, va);
  printtext(server, NULL, MSGLEVEL_CRAP, "%s", str);
  g_free(str);
  va_end(va);
}

void silc_say_error(char *msg, ...)
{
  va_list va;
  char *str;

  va_start(va, msg);
  str = g_strdup_vprintf(msg, va);
  printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", str);

  g_free(str);
  va_end(va);
}

/* Message for a channel. The `sender' is the nickname of the sender 
   received in the packet. The `channel_name' is the name of the channel. */

void silc_channel_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcChannelEntry channel,
			  SilcMessageFlags flags, char *msg)
{
  SILC_SERVER_REC *server;
  SILC_NICK_REC *nick;
  SILC_CHANNEL_REC *chanrec;
  
  SILC_LOG_DEBUG(("Start"));

  if (!msg)
    return;

  server = conn == NULL ? NULL : conn->context;
  chanrec = silc_channel_find_entry(server, channel);
  if (!chanrec)
    return;
  
  nick = silc_nicklist_find(chanrec, sender);
  if (!nick) {
    /* We didn't find client but it clearly exists, add it. */
    SilcChannelUser chu = silc_client_on_channel(channel, sender);
    if (chu)
      nick = silc_nicklist_insert(chanrec, chu, FALSE);
  }

  if (flags & SILC_MESSAGE_FLAG_ACTION)
    printformat_module("fe-common/silc", server, channel->channel_name,
		       MSGLEVEL_ACTIONS, SILCTXT_CHANNEL_ACTION, 
                       nick == NULL ? "[<unknown>]" : nick->nick, msg);
  else if (flags & SILC_MESSAGE_FLAG_NOTICE)
    printformat_module("fe-common/silc", server, channel->channel_name,
		       MSGLEVEL_NOTICES, SILCTXT_CHANNEL_NOTICE, 
                       nick == NULL ? "[<unknown>]" : nick->nick, msg);
  else
    signal_emit("message public", 6, server, msg,
		nick == NULL ? "[<unknown>]" : nick->nick,
		nick == NULL ? "" : nick->host == NULL ? "" : nick->host,
		chanrec->name, nick);
}

/* Private message to the client. The `sender' is the nickname of the
   sender received in the packet. */

void silc_private_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessageFlags flags,
			  char *msg)
{
  SILC_SERVER_REC *server;
  char userhost[256];
  
  SILC_LOG_DEBUG(("Start"));

  server = conn == NULL ? NULL : conn->context;
  memset(userhost, 0, sizeof(userhost));
  if (sender->username)
    snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	     sender->username, sender->hostname);
  signal_emit("message private", 4, server, msg,
	      sender->nickname ? sender->nickname : "[<unknown>]",
	      sender->username ? userhost : NULL);
}

/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it). */

void silc_notify(SilcClient client, SilcClientConnection conn,
		 SilcNotifyType type, ...)
{
  va_list va;
  SILC_SERVER_REC *server;
  SILC_CHANNEL_REC *chanrec;
  SILC_NICK_REC *nickrec;
  SilcClientEntry client_entry, client_entry2;
  SilcChannelEntry channel;
  SilcServerEntry server_entry;
  SilcIdType idtype;
  void *entry;
  SilcUInt32 mode;
  char userhost[512];
  char *name, *tmp;
  GSList *list1, *list_tmp;

  SILC_LOG_DEBUG(("Start"));

  va_start(va, type);

  server = conn == NULL ? NULL : conn->context;
  
  switch(type) {
  case SILC_NOTIFY_TYPE_NONE:
    /* Some generic notice from server */
    printtext(server, NULL, MSGLEVEL_CRAP, "%s", (char *)va_arg(va, char *));
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    /*
     * Invited or modified invite list.
     */

    SILC_LOG_DEBUG(("Notify: INVITE"));

    channel = va_arg(va, SilcChannelEntry);
    name = va_arg(va, char *);
    client_entry = va_arg(va, SilcClientEntry);

    memset(userhost, 0, sizeof(userhost));
    snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	     client_entry->username, client_entry->hostname);
    signal_emit("message invite", 4, server, channel ? channel->channel_name :
		name, client_entry->nickname, userhost);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    /*
     * Joined channel.
     */
 
    SILC_LOG_DEBUG(("Notify: JOIN"));

    client_entry = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    if (client_entry == server->conn->local_entry) {
      /* You joined to channel */
      chanrec = silc_channel_find(server, channel->channel_name);
      if (chanrec != NULL && !chanrec->joined)
	chanrec->entry = channel;
    } else {
      chanrec = silc_channel_find_entry(server, channel);
      if (chanrec != NULL) {
	SilcChannelUser chu = silc_client_on_channel(channel, client_entry);
	if (chu)
	  nickrec = silc_nicklist_insert(chanrec, chu, TRUE);
      }
    }
    
    memset(userhost, 0, sizeof(userhost));
    if (client_entry->username)
    snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	     client_entry->username, client_entry->hostname);
    signal_emit("message join", 4, server, channel->channel_name,
		client_entry->nickname,
		client_entry->username == NULL ? "" : userhost);
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /*
     * Left a channel.
     */

    SILC_LOG_DEBUG(("Notify: LEAVE"));

    client_entry = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);
    
    memset(userhost, 0, sizeof(userhost));
    if (client_entry->username)
      snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
    signal_emit("message part", 5, server, channel->channel_name,
		client_entry->nickname,  client_entry->username ? 
		userhost : "", client_entry->nickname);
    
    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      nickrec = silc_nicklist_find(chanrec, client_entry);
      if (nickrec != NULL)
	nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
    }
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /*
     * Left the network.
     */

    SILC_LOG_DEBUG(("Notify: SIGNOFF"));

    client_entry = va_arg(va, SilcClientEntry);
    tmp = va_arg(va, char *);
    
    silc_server_free_ftp(server, client_entry);
    
    memset(userhost, 0, sizeof(userhost));
    if (client_entry->username)
      snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
    signal_emit("message quit", 4, server, client_entry->nickname,
		client_entry->username ? userhost : "", 
		tmp ? tmp : "");
    
    list1 = nicklist_get_same_unique(SERVER(server), client_entry);
    for (list_tmp = list1; list_tmp != NULL; list_tmp = 
	   list_tmp->next->next) {
      CHANNEL_REC *channel = list_tmp->data;
      NICK_REC *nickrec = list_tmp->next->data;
      
      nicklist_remove(channel, nickrec);
    }
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /*
     * Changed topic.
     */

    SILC_LOG_DEBUG(("Notify: TOPIC_SET"));

    idtype = va_arg(va, int);
    entry = va_arg(va, void *);
    tmp = va_arg(va, char *);
    channel = va_arg(va, SilcChannelEntry);
    
    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      g_free_not_null(chanrec->topic);
      chanrec->topic = *tmp == '\0' ? NULL : g_strdup(tmp);
      signal_emit("channel topic changed", 1, chanrec);
    }
    
    if (idtype == SILC_ID_CLIENT) {
      client_entry = (SilcClientEntry)entry;
      memset(userhost, 0, sizeof(userhost));
      snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
      signal_emit("message topic", 5, server, channel->channel_name,
		  tmp, client_entry->nickname, userhost);
    } else if (idtype == SILC_ID_SERVER) {
      server_entry = (SilcServerEntry)entry;
      signal_emit("message topic", 5, server, channel->channel_name,
		  tmp, server_entry->server_name, 
		  server_entry->server_name);
    } else {
      channel = (SilcChannelEntry)entry;
      signal_emit("message topic", 5, server, channel->channel_name,
		  tmp, channel->channel_name, channel->channel_name);
    }
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    /*
     * Changed nickname.
     */

    SILC_LOG_DEBUG(("Notify: NICK_CHANGE"));

    client_entry = va_arg(va, SilcClientEntry);
    client_entry2 = va_arg(va, SilcClientEntry);
    
    memset(userhost, 0, sizeof(userhost));
    snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	     client_entry2->username, client_entry2->hostname);
    nicklist_rename_unique(SERVER(server),
			   client_entry, client_entry->nickname,
			   client_entry2, client_entry2->nickname);
    signal_emit("message nick", 4, server, client_entry2->nickname, 
		client_entry->nickname, userhost);
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /*
     * Changed channel mode.
     */

    SILC_LOG_DEBUG(("Notify: CMODE_CHANGE"));

    idtype = va_arg(va, int);
    entry = va_arg(va, void *);
    mode = va_arg(va, SilcUInt32);
    (void)va_arg(va, char *);
    (void)va_arg(va, char *);
    channel = va_arg(va, SilcChannelEntry);

    tmp = silc_client_chmode(mode,
			     channel->channel_key ? 
			     channel->channel_key->cipher->name : "",
			     channel->hmac ? 
			     silc_hmac_get_name(channel->hmac) : "");
    
    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      g_free_not_null(chanrec->mode);
      chanrec->mode = g_strdup(tmp == NULL ? "" : tmp);
      signal_emit("channel mode changed", 1, chanrec);
    }
    
    if (idtype == SILC_ID_CLIENT) {
      client_entry = (SilcClientEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CMODE,
			 channel->channel_name, tmp ? tmp : "removed all",
			 client_entry->nickname);
    } else if (idtype == SILC_ID_SERVER) {
      server_entry = (SilcServerEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CMODE,
			 channel->channel_name, tmp ? tmp : "removed all",
			 server_entry->server_name);
    }

    silc_free(tmp);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    /*
     * Changed user's mode on channel.
     */

    SILC_LOG_DEBUG(("Notify: CUMODE_CHANGE"));

    client_entry = va_arg(va, SilcClientEntry);
    mode = va_arg(va, SilcUInt32);
    client_entry2 = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    tmp = silc_client_chumode(mode);
    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      SILC_NICK_REC *nick;

      if (client_entry2 == server->conn->local_entry)
	chanrec->chanop = (mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
      
      nick = silc_nicklist_find(chanrec, client_entry2);
      if (nick != NULL) {
	nick->op = (mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
	nick->founder = (mode & SILC_CHANNEL_UMODE_CHANFO) != 0;
	signal_emit("nick mode changed", 2, chanrec, nick);
      }
    }

    printformat_module("fe-common/silc", server, channel->channel_name,
		       MSGLEVEL_MODES, SILCTXT_CHANNEL_CUMODE,
		       channel->channel_name, client_entry2->nickname, 
		       tmp ? tmp : "removed all",
		       client_entry->nickname);

    if (mode & SILC_CHANNEL_UMODE_CHANFO)
      printformat_module("fe-common/silc", 
			 server, channel->channel_name, MSGLEVEL_CRAP,
			 SILCTXT_CHANNEL_FOUNDER,
			 channel->channel_name, client_entry2->nickname);

    silc_free(tmp);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /*
     * Received MOTD.
     */

    SILC_LOG_DEBUG(("Notify: MOTD"));

    tmp = va_arg(va, char *);

    if (!settings_get_bool("skip_motd"))
      printtext_multiline(server, NULL, MSGLEVEL_CRAP, "%s", tmp);
    break;

  case SILC_NOTIFY_TYPE_KICKED:
    /*
     * Someone was kicked from channel.
     */

    SILC_LOG_DEBUG(("Notify: KICKED"));

    client_entry = va_arg(va, SilcClientEntry);
    tmp = va_arg(va, char *);
    client_entry2 = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    chanrec = silc_channel_find_entry(server, channel);
  
    if (client_entry == conn->local_entry) {
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_KICKED_YOU, 
			 channel->channel_name, client_entry2->nickname,
			 tmp ? tmp : "");
      if (chanrec) {
	chanrec->kicked = TRUE;
	channel_destroy((CHANNEL_REC *)chanrec);
      }
    } else {
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_KICKED, 
			 client_entry->nickname, channel->channel_name, 
			 client_entry2->nickname, tmp ? tmp : "");

      if (chanrec) {
	SILC_NICK_REC *nickrec = silc_nicklist_find(chanrec, client_entry);
	if (nickrec != NULL)
	  nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
      }
    }
    break;

  case SILC_NOTIFY_TYPE_KILLED:
    /*
     * Someone was killed from the network.
     */

    SILC_LOG_DEBUG(("Notify: KILLED"));

    client_entry = va_arg(va, SilcClientEntry);
    tmp = va_arg(va, char *);
  
    if (client_entry == conn->local_entry) {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED_YOU, 
			 tmp ? tmp : "");
    } else {
      list1 = nicklist_get_same_unique(SERVER(server), client_entry);
      for (list_tmp = list1; list_tmp != NULL; list_tmp = 
	     list_tmp->next->next) {
	CHANNEL_REC *channel = list_tmp->data;
	NICK_REC *nickrec = list_tmp->next->data;
	nicklist_remove(channel, nickrec);
      }

      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED, 
			 client_entry->nickname,
			 tmp ? tmp : "");
    }
    break;

  case SILC_NOTIFY_TYPE_SERVER_SIGNOFF:
    {
      /*
       * Server has quit the network.
       */
      int i;
      SilcClientEntry *clients;
      SilcUInt32 clients_count;

      SILC_LOG_DEBUG(("Notify: SIGNOFF"));
      
      (void)va_arg(va, void *);
      clients = va_arg(va, SilcClientEntry *);
      clients_count = va_arg(va, SilcUInt32);
  
      for (i = 0; i < clients_count; i++) {
	memset(userhost, 0, sizeof(userhost));
	if (clients[i]->username)
	  snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
		   clients[i]->username, clients[i]->hostname);
	signal_emit("message quit", 4, server, clients[i]->nickname,
		    clients[i]->username ? userhost : "", 
		    "server signoff");

	silc_server_free_ftp(server, clients[i]);
	
	list1 = nicklist_get_same_unique(SERVER(server), clients[i]);
	for (list_tmp = list1; list_tmp != NULL; list_tmp = 
	       list_tmp->next->next) {
	  CHANNEL_REC *channel = list_tmp->data;
	  NICK_REC *nickrec = list_tmp->next->data;
	  nicklist_remove(channel, nickrec);
	}
      }
    }
    break;

  default:
    /* Unknown notify */
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_UNKNOWN_NOTIFY, type);
    break;
  }

  va_end(va);
}

/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection object which it should save somewhere. */

void silc_connect(SilcClient client, SilcClientConnection conn, int success)
{
  SILC_SERVER_REC *server = conn->context;

  if (!server && !success) {
    silc_client_close_connection(client, NULL, conn);
    return;
  }

  if (success) {
    server->connected = TRUE;
    signal_emit("event connected", 1, server);
  } else {
    server->connection_lost = TRUE;
    if (server->conn)
      server->conn->context = NULL;
    server_disconnect(SERVER(server));
  }
}

/* Called to indicate that connection was disconnected to the server. */

void silc_disconnect(SilcClient client, SilcClientConnection conn)
{
  SILC_SERVER_REC *server = conn->context;

  SILC_LOG_DEBUG(("Start"));

  if (server->conn && server->conn->local_entry) {
    nicklist_rename_unique(SERVER(server),
			   server->conn->local_entry, server->nick,
			   server->conn->local_entry, 
			   silc_client->username);
    silc_change_nick(server, silc_client->username);
  }

  server->conn->context = NULL;
  server->conn = NULL;
  server->connection_lost = TRUE;
  server_disconnect(SERVER(server));
}

/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occured
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

void silc_command(SilcClient client, SilcClientConnection conn, 
		  SilcClientCommandContext cmd_context, int success,
		  SilcCommand command)
{
  SILC_SERVER_REC *server = conn->context;

  SILC_LOG_DEBUG(("Start"));

  if (!success)
    return;

  switch(command) {
  case SILC_COMMAND_INVITE:
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITING,
		       cmd_context->argv[2], 
		       (cmd_context->argv[1][0] == '*' ?
			(char *)conn->current_channel->channel_name :
			(char *)cmd_context->argv[1]));
    break;
  default:
    break;
  }
}

/* Client info resolving callback when JOIN command reply is received.
   This will cache all users on the channel. */

static void silc_client_join_get_users(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry *clients,
				       SilcUInt32 clients_count,
				       void *context)
{
  SilcChannelEntry channel = (SilcChannelEntry)context;
  SilcHashTableList htl;
  SilcChannelUser chu;
  SILC_SERVER_REC *server = conn->context;
  SILC_CHANNEL_REC *chanrec;
  SilcClientEntry founder = NULL;
  NICK_REC *ownnick;

  if (!clients)
    return;

  chanrec = silc_channel_find(server, channel->channel_name);
  if (chanrec == NULL)
    return;

  silc_hash_table_list(channel->user_list, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
    if (!chu->client->nickname)
      continue;
    if (chu->mode & SILC_CHANNEL_UMODE_CHANFO)
      founder = chu->client;
    silc_nicklist_insert(chanrec, chu, FALSE);
  }
  silc_hash_table_list_reset(&htl);

  ownnick = NICK(silc_nicklist_find(chanrec, conn->local_entry));
  nicklist_set_own(CHANNEL(chanrec), ownnick);
  signal_emit("channel joined", 1, chanrec);

  if (chanrec->topic)
    printformat_module("fe-common/silc", server, channel->channel_name,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_TOPIC,
		       channel->channel_name, chanrec->topic);

  fe_channels_nicklist(CHANNEL(chanrec), CHANNEL_NICKLIST_FLAG_ALL);

  if (founder) {
    if (founder == conn->local_entry)
      printformat_module("fe-common/silc", 
			 server, channel->channel_name, MSGLEVEL_CRAP,
			 SILCTXT_CHANNEL_FOUNDER_YOU,
			 channel->channel_name);
    else
      printformat_module("fe-common/silc", 
			 server, channel->channel_name, MSGLEVEL_CRAP,
			 SILCTXT_CHANNEL_FOUNDER,
			 channel->channel_name, founder->nickname);
  }
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  void *entry;
  SilcIdType id_type;
  char *fingerprint;
} *GetkeyContext;

void silc_getkey_cb(bool success, void *context)
{
  GetkeyContext getkey = (GetkeyContext)context;
  char *entity = (getkey->id_type == SILC_ID_CLIENT ? "user" : "server");
  char *name = (getkey->id_type == SILC_ID_CLIENT ? 
		((SilcClientEntry)getkey->entry)->nickname :
		((SilcServerEntry)getkey->entry)->server_name);

  if (success) {
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_GETKEY_VERIFIED, entity, name);
  } else {
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_GETKEY_DISCARD, entity, name);
  }

  silc_free(getkey->fingerprint);
  silc_free(getkey);
}

/* Command reply handler. This function is called always in the command reply
   function. If error occurs it will be called as well. Normal scenario
   is that it will be called after the received command data has been parsed
   and processed. The function is used to pass the received command data to
   the application. 

   `conn' is the associated client connection. `cmd_payload' is the command
   payload data received from server and it can be ignored. It is provided
   if the application would like to re-parse the received command data,
   however, it must be noted that the data is parsed already by the library
   thus the payload can be ignored. `success' is FALSE if error occured.
   In this case arguments are not sent to the application. `command' is the
   command reply being processed. The function has variable argument list
   and each command defines the number and type of arguments it passes to the
   application (on error they are not sent). */

void 
silc_command_reply(SilcClient client, SilcClientConnection conn,
		   SilcCommandPayload cmd_payload, int success,
		   SilcCommand command, SilcCommandStatus status, ...)

{
  SILC_SERVER_REC *server = conn->context;
  SILC_CHANNEL_REC *chanrec;
  va_list vp;

  va_start(vp, status);

  SILC_LOG_DEBUG(("Start"));

  switch(command) {
  case SILC_COMMAND_WHOIS:
    {
      char buf[1024], *nickname, *username, *realname, *nick;
      unsigned char *fingerprint;
      SilcUInt32 idle, mode;
      SilcBuffer channels;
      SilcClientEntry client_entry;
      
      if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
	/* Print the unknown nick for user */
	unsigned char *tmp =
	  silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
				     3, NULL);
	if (tmp)
	  silc_say_error("%s: %s", tmp, 
			 silc_client_command_status_message(status));
	break;
      } else if (status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
	/* Try to find the entry for the unknown client ID, since we
	   might have, and print the nickname of it for user. */
	SilcUInt32 tmp_len;
	unsigned char *tmp =
	  silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
				     2, &tmp_len);
	if (tmp) {
	  SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len);
	  if (client_id) {
	    client_entry = silc_client_get_client_by_id(client, conn,
							client_id);
	    if (client_entry && client_entry->nickname)
	      silc_say_error("%s: %s", client_entry->nickname,
			     silc_client_command_status_message(status));
	    silc_free(client_id);
	  }
	}
	break;
      }
      
      if (!success)
	return;
      
      client_entry = va_arg(vp, SilcClientEntry);
      nickname = va_arg(vp, char *);
      username = va_arg(vp, char *);
      realname = va_arg(vp, char *);
      channels = va_arg(vp, SilcBuffer);
      mode = va_arg(vp, SilcUInt32);
      idle = va_arg(vp, SilcUInt32);
      fingerprint = va_arg(vp, unsigned char *);
      
      silc_parse_userfqdn(nickname, &nick, NULL);
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOIS_USERINFO, nickname, 
			 client_entry->username, client_entry->hostname,
			 nick, client_entry->nickname);
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOIS_REALNAME, realname);
      silc_free(nick);

      if (channels) {
	SilcDList list = silc_channel_payload_parse_list(channels->data,
							 channels->len);
	if (list) {
	  SilcChannelPayload entry;
	  memset(buf, 0, sizeof(buf));
	  silc_dlist_start(list);
	  while ((entry = silc_dlist_get(list)) != SILC_LIST_END) {
	    char *m = silc_client_chumode_char(silc_channel_get_mode(entry));
	    SilcUInt32 name_len;
	    char *name = silc_channel_get_name(entry, &name_len);
	    
	    if (m)
	      strncat(buf, m, strlen(m));
	    strncat(buf, name, name_len);
	    strncat(buf, " ", 1);
	    silc_free(m);
	  }

	  printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			     SILCTXT_WHOIS_CHANNELS, buf);
	  silc_channel_payload_list_free(list);
	}
      }
      
      if (mode) {
	memset(buf, 0, sizeof(buf));

	if ((mode & SILC_UMODE_SERVER_OPERATOR) ||
	    (mode & SILC_UMODE_ROUTER_OPERATOR)) {
	  strcat(buf, (mode & SILC_UMODE_SERVER_OPERATOR) ?
		 "Server Operator " :
		 (mode & SILC_UMODE_ROUTER_OPERATOR) ?
		 "SILC Operator " : "[Unknown mode] ");
	}
	if (mode & SILC_UMODE_GONE)
	  strcat(buf, "away");

	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_MODES, buf);
      }
      
      if (idle && nickname) {
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%lu %s",
		 idle > 60 ? (idle / 60) : idle,
		 idle > 60 ? "minutes" : "seconds");

	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_IDLE, buf);
      }

      if (fingerprint) {
	fingerprint = silc_fingerprint(fingerprint, 20);
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_FINGERPRINT, fingerprint);
	silc_free(fingerprint);
      }
    }
    break;
    
  case SILC_COMMAND_IDENTIFY:
    {
      SilcClientEntry client_entry;
      
      if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
	/* Print the unknown nick for user */
	unsigned char *tmp =
	  silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
				     3, NULL);
	if (tmp)
	  silc_say_error("%s: %s", tmp, 
			 silc_client_command_status_message(status));
	break;
      } else if (status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
	/* Try to find the entry for the unknown client ID, since we
	   might have, and print the nickname of it for user. */
	SilcUInt32 tmp_len;
	unsigned char *tmp =
	  silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
				     2, &tmp_len);
	if (tmp) {
	  SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len);
	  if (client_id) {
	    client_entry = silc_client_get_client_by_id(client, conn,
							client_id);
	    if (client_entry && client_entry->nickname)
	      silc_say_error("%s: %s", client_entry->nickname,
			     silc_client_command_status_message(status));
	    silc_free(client_id);
	  }
	}
	break;
      }

      break;
    }

  case SILC_COMMAND_WHOWAS:
    {
      char *nickname, *username, *realname;
      
      if (status == SILC_STATUS_ERR_NO_SUCH_NICK ||
	  status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
	char *tmp;
	tmp = silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
					 3, NULL);
	if (tmp)
	  silc_say_error("%s: %s", tmp, 
			 silc_client_command_status_message(status));
	break;
      }
      
      if (!success)
	return;
      
      (void)va_arg(vp, SilcClientEntry);
      nickname = va_arg(vp, char *);
      username = va_arg(vp, char *);
      realname = va_arg(vp, char *);
      
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOWAS_USERINFO, nickname, username, 
			 realname ? realname : "");
    }
    break;
    
  case SILC_COMMAND_INVITE:
    {
      SilcChannelEntry channel;
      char *invite_list;
      SilcArgumentPayload args;
      int argc = 0;
      
      if (!success)
	return;
      
      channel = va_arg(vp, SilcChannelEntry);
      invite_list = va_arg(vp, char *);

      args = silc_command_get_args(cmd_payload);
      if (args)
	argc = silc_argument_get_arg_num(args);

      if (invite_list)
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CHANNEL_INVITE_LIST, channel->channel_name,
			   invite_list);
      else if (argc == 3)
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CHANNEL_NO_INVITE_LIST, 
			   channel->channel_name);
    }
    break;

  case SILC_COMMAND_JOIN: 
    {
      char *channel, *mode, *topic;
      SilcUInt32 modei;
      SilcChannelEntry channel_entry;
      SilcBuffer client_id_list;
      SilcUInt32 list_count;

      if (!success)
	return;

      channel = va_arg(vp, char *);
      channel_entry = va_arg(vp, SilcChannelEntry);
      modei = va_arg(vp, SilcUInt32);
      (void)va_arg(vp, SilcUInt32);
      (void)va_arg(vp, unsigned char *);
      (void)va_arg(vp, unsigned char *);
      (void)va_arg(vp, unsigned char *);
      topic = va_arg(vp, char *);
      (void)va_arg(vp, unsigned char *);
      list_count = va_arg(vp, SilcUInt32);
      client_id_list = va_arg(vp, SilcBuffer);

      chanrec = silc_channel_find(server, channel);
      if (!chanrec)
	chanrec = silc_channel_create(server, channel, TRUE);

      if (topic) {
	g_free_not_null(chanrec->topic);
	chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
	signal_emit("channel topic changed", 1, chanrec);
      }

      mode = silc_client_chmode(modei, 
				channel_entry->channel_key ? 
				channel_entry->channel_key->cipher->name : "",
				channel_entry->hmac ? 
				silc_hmac_get_name(channel_entry->hmac) : "");
      g_free_not_null(chanrec->mode);
      chanrec->mode = g_strdup(mode == NULL ? "" : mode);
      signal_emit("channel mode changed", 1, chanrec);

      /* Resolve the client information */
      silc_client_get_clients_by_list(client, conn, list_count, client_id_list,
				      silc_client_join_get_users, 
				      channel_entry);

      break;
    }

  case SILC_COMMAND_NICK: 
    {
      SilcClientEntry client = va_arg(vp, SilcClientEntry);
      char *old;
      
      if (!success)
	return;

      old = g_strdup(server->nick);
      server_change_nick(SERVER(server), client->nickname);
      nicklist_rename_unique(SERVER(server),
			     server->conn->local_entry, server->nick,
			     client, client->nickname);
      signal_emit("message own_nick", 4, server, server->nick, old, "");
      g_free(old);
      break;
    }
    
  case SILC_COMMAND_LIST:
    {
      char *topic, *name;
      int usercount;
      char users[20];
      
      if (!success)
	return;
      
      (void)va_arg(vp, SilcChannelEntry);
      name = va_arg(vp, char *);
      topic = va_arg(vp, char *);
      usercount = va_arg(vp, int);
      
      if (status == SILC_STATUS_LIST_START ||
	  status == SILC_STATUS_OK)
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_LIST_HEADER);

      if (!usercount)
	snprintf(users, sizeof(users) - 1, "N/A");
      else
	snprintf(users, sizeof(users) - 1, "%d", usercount);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_LIST,
			 name, users, topic ? topic : "");
    }
    break;
    
  case SILC_COMMAND_UMODE:
    {
      SilcUInt32 mode;
      
      if (!success)
	return;
      
      mode = va_arg(vp, SilcUInt32);
      
      if (mode & SILC_UMODE_SERVER_OPERATOR &&
	  !(server->umode & SILC_UMODE_SERVER_OPERATOR))
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_SERVER_OPER);

      if (mode & SILC_UMODE_ROUTER_OPERATOR &&
	  !(server->umode & SILC_UMODE_ROUTER_OPERATOR))
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ROUTER_OPER);

      server->umode = mode;
    }
    break;
    
  case SILC_COMMAND_OPER:
    if (!success)
      return;

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_SERVER_OPER);
    break;
    
  case SILC_COMMAND_SILCOPER:
    if (!success)
      return;

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ROUTER_OPER);
    break;
    
  case SILC_COMMAND_USERS: 
    {
      SilcHashTableList htl;
      SilcChannelEntry channel;
      SilcChannelUser chu;
      
      if (!success)
	return;
      
      channel = va_arg(vp, SilcChannelEntry);
      
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_USERS_HEADER,
			 channel->channel_name);

      silc_hash_table_list(channel->user_list, &htl);
      while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
	SilcClientEntry e = chu->client;
	char stat[5], *mode;

	if (!e->nickname)
	  continue;
	
	memset(stat, 0, sizeof(stat));
	mode = silc_client_chumode_char(chu->mode);
	if (e->mode & SILC_UMODE_GONE)
	  strcat(stat, "G");
	else
	  strcat(stat, "H");
	if (mode)
	  strcat(stat, mode);

	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_USERS,
			   e->nickname, stat, 
			   e->username ? e->username : "",
			   e->hostname ? e->hostname : "",
			   e->realname ? e->realname : "");
	if (mode)
	  silc_free(mode);
      }
      silc_hash_table_list_reset(&htl);
    }
    break;

  case SILC_COMMAND_BAN:
    {
      SilcChannelEntry channel;
      char *ban_list;
      
      if (!success)
	return;
      
      channel = va_arg(vp, SilcChannelEntry);
      ban_list = va_arg(vp, char *);
      
      if (ban_list)
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CHANNEL_BAN_LIST, channel->channel_name,
			   ban_list);
      else
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CHANNEL_NO_BAN_LIST, 
			   channel->channel_name);
    }
    break;
    
  case SILC_COMMAND_GETKEY:
    {
      SilcIdType id_type;
      void *entry;
      SilcPublicKey public_key;
      unsigned char *pk;
      SilcUInt32 pk_len;
      GetkeyContext getkey;
      char *name;
      
      if (!success)
	return;
      
      id_type = va_arg(vp, SilcUInt32);
      entry = va_arg(vp, void *);
      public_key = va_arg(vp, SilcPublicKey);

      if (public_key) {
	pk = silc_pkcs_public_key_encode(public_key, &pk_len);

	getkey = silc_calloc(1, sizeof(*getkey));
	getkey->entry = entry;
	getkey->id_type = id_type;
	getkey->client = client;
	getkey->conn = conn;
	getkey->fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);

	name = (id_type == SILC_ID_CLIENT ? 
		((SilcClientEntry)entry)->nickname :
		((SilcServerEntry)entry)->server_name);

	silc_verify_public_key_internal(client, conn, name,
					(id_type == SILC_ID_CLIENT ?
					 SILC_SOCKET_TYPE_CLIENT :
					 SILC_SOCKET_TYPE_SERVER),
					pk, pk_len, SILC_SKE_PK_TYPE_SILC,
					silc_getkey_cb, getkey);
	silc_free(pk);
      } else {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_GETKEY_NOKEY);
      }
    }
    break;

  case SILC_COMMAND_INFO:
    {
      SilcServerEntry server_entry;
      char *server_name;
      char *server_info;

      if (!success)
	return;
      
      server_entry = va_arg(vp, SilcServerEntry);
      server_name = va_arg(vp, char *);
      server_info = va_arg(vp, char *);

      if (server_name && server_info )
	{
	  printtext(server, NULL, MSGLEVEL_CRAP, "Server: %s", server_name);
	  printtext(server, NULL, MSGLEVEL_CRAP, "%s", server_info);
	}
    }
    break;
    
  case SILC_COMMAND_TOPIC:
    {
      SilcChannelEntry channel;
      char *topic;
      
      if (!success)
	return;
      
      channel = va_arg(vp, SilcChannelEntry);
      topic = va_arg(vp, char *);
      
      if (topic) {
	chanrec = silc_channel_find_entry(server, channel);
	if (chanrec) {
	  g_free_not_null(chanrec->topic);
	  chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
	  signal_emit("channel topic changed", 1, chanrec);
	}
	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_TOPIC,
			   channel->channel_name, topic);
      } else {
	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_TOPIC_NOT_SET,
			   channel->channel_name);
      }
    }
    break;

  }

  va_end(vp);
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  char *filename;
  char *entity;
  char *entity_name;
  unsigned char *pk;
  SilcUInt32 pk_len;
  SilcSKEPKType pk_type;
  SilcVerifyPublicKey completion;
  void *context;
} *PublicKeyVerify;

static void verify_public_key_completion(const char *line, void *context)
{
  PublicKeyVerify verify = (PublicKeyVerify)context;

  if (line[0] == 'Y' || line[0] == 'y') {
    /* Call the completion */
    if (verify->completion)
      verify->completion(TRUE, verify->context);

    /* Save the key for future checking */
    silc_pkcs_save_public_key_data(verify->filename, verify->pk, 
				   verify->pk_len, SILC_PKCS_FILE_PEM);
  } else {
    /* Call the completion */
    if (verify->completion)
      verify->completion(FALSE, verify->context);

    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_PUBKEY_DISCARD, 
		       verify->entity_name ? verify->entity_name :
		       verify->entity);
  }

  silc_free(verify->filename);
  silc_free(verify->entity);
  silc_free(verify->entity_name);
  silc_free(verify->pk);
  silc_free(verify);
}

/* Internal routine to verify public key. If the `completion' is provided
   it will be called to indicate whether public was verified or not. For
   server/router public key this will check for filename that includes the
   remote host's IP address and remote host's hostname. */

static void 
silc_verify_public_key_internal(SilcClient client, SilcClientConnection conn,
				const char *name, SilcSocketType conn_type, 
				unsigned char *pk, SilcUInt32 pk_len, 
				SilcSKEPKType pk_type,
				SilcVerifyPublicKey completion, void *context)
{
  int i;
  char file[256], filename[256], filename2[256], *ipf, *hostf = NULL;
  char *fingerprint, *babbleprint, *format;
  struct passwd *pw;
  struct stat st;
  char *entity = ((conn_type == SILC_SOCKET_TYPE_SERVER ||
		   conn_type == SILC_SOCKET_TYPE_ROUTER) ? 
		  "server" : "client");
  PublicKeyVerify verify;

  if (pk_type != SILC_SKE_PK_TYPE_SILC) {
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_PUBKEY_UNSUPPORTED, 
		       entity, pk_type);
    if (completion)
      completion(FALSE, context);
    return;
  }

  pw = getpwuid(getuid());
  if (!pw) {
    if (completion)
      completion(FALSE, context);
    return;
  }

  memset(filename, 0, sizeof(filename));
  memset(filename2, 0, sizeof(filename2));
  memset(file, 0, sizeof(file));

  if (conn_type == SILC_SOCKET_TYPE_SERVER ||
      conn_type == SILC_SOCKET_TYPE_ROUTER) {
    if (!name) {
      snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity, 
	       conn->sock->ip, conn->sock->port);
      snprintf(filename, sizeof(filename) - 1, "%s/.silc/%skeys/%s", 
	       pw->pw_dir, entity, file);
      
      snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity, 
	       conn->sock->hostname, conn->sock->port);
      snprintf(filename2, sizeof(filename2) - 1, "%s/.silc/%skeys/%s", 
	       pw->pw_dir, entity, file);
      
      ipf = filename;
      hostf = filename2;
    } else {
      snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity, 
	       name, conn->sock->port);
      snprintf(filename, sizeof(filename) - 1, "%s/.silc/%skeys/%s", 
	       pw->pw_dir, entity, file);
      
      ipf = filename;
    }
  } else {
    /* Replace all whitespaces with `_'. */
    fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
    for (i = 0; i < strlen(fingerprint); i++)
      if (fingerprint[i] == ' ')
	fingerprint[i] = '_';
    
    snprintf(file, sizeof(file) - 1, "%skey_%s.pub", entity, fingerprint);
    snprintf(filename, sizeof(filename) - 1, "%s/.silc/%skeys/%s", 
	     pw->pw_dir, entity, file);
    silc_free(fingerprint);

    ipf = filename;
  }

  /* Take fingerprint of the public key */
  fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
  babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);

  verify = silc_calloc(1, sizeof(*verify));
  verify->client = client;
  verify->conn = conn;
  verify->filename = strdup(ipf);
  verify->entity = strdup(entity);
  verify->entity_name = (conn_type != SILC_SOCKET_TYPE_CLIENT ?
			 (name ? strdup(name) : strdup(conn->sock->hostname))
			 : NULL);
  verify->pk = silc_calloc(pk_len, sizeof(*verify->pk));
  memcpy(verify->pk, pk, pk_len);
  verify->pk_len = pk_len;
  verify->pk_type = pk_type;
  verify->completion = completion;
  verify->context = context;

  /* Check whether this key already exists */
  if (stat(ipf, &st) < 0 && (!hostf || stat(hostf, &st) < 0)) {
    /* Key does not exist, ask user to verify the key and save it */

    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_PUBKEY_RECEIVED,verify->entity_name ? 
		       verify->entity_name : entity);
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
    format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			     SILCTXT_PUBKEY_ACCEPT);
    keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			    format, 0, verify);
    g_free(format);
    silc_free(fingerprint);
    return;
  } else {
    /* The key already exists, verify it. */
    SilcPublicKey public_key;
    unsigned char *encpk;
    SilcUInt32 encpk_len;

    /* Load the key file, try for both IP filename and hostname filename */
    if (!silc_pkcs_load_public_key(ipf, &public_key, 
				   SILC_PKCS_FILE_PEM) &&
	!silc_pkcs_load_public_key(ipf, &public_key, 
				   SILC_PKCS_FILE_BIN) &&
	(!hostf || (!silc_pkcs_load_public_key(hostf, &public_key, 
					       SILC_PKCS_FILE_PEM) &&
		    !silc_pkcs_load_public_key(hostf, &public_key, 
					       SILC_PKCS_FILE_BIN)))) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_RECEIVED,verify->entity_name ? 
			 verify->entity_name : entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_COULD_NOT_LOAD, entity);
      format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			       SILCTXT_PUBKEY_ACCEPT_ANYWAY);
      keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			      format, 0, verify);
      g_free(format);
      silc_free(fingerprint);
      return;
    }

    /* Encode the key data */
    encpk = silc_pkcs_public_key_encode(public_key, &encpk_len);
    if (!encpk) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_RECEIVED,verify->entity_name ? 
			 verify->entity_name : entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_MALFORMED, entity);
      format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			       SILCTXT_PUBKEY_ACCEPT_ANYWAY);
      keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			      format, 0, verify);
      g_free(format);
      silc_free(fingerprint);
      return;
    }

    /* Compare the keys */
    if (memcmp(encpk, pk, encpk_len)) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_RECEIVED,verify->entity_name ? 
			 verify->entity_name : entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_NO_MATCH, entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_MAYBE_EXPIRED, entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_MITM_ATTACK, entity);

      /* Ask user to verify the key and save it */
      format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			       SILCTXT_PUBKEY_ACCEPT_ANYWAY);
      keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			      format, 0, verify);
      g_free(format);
      silc_free(fingerprint);
      return;
    }

    /* Local copy matched */
    if (completion)
      completion(TRUE, context);
    silc_free(fingerprint);
  }
}

/* Verifies received public key. The `conn_type' indicates which entity
   (server, client etc.) has sent the public key. If user decides to trust
   the key may be saved as trusted public key for later use. The 
   `completion' must be called after the public key has been verified. */

void 
silc_verify_public_key(SilcClient client, SilcClientConnection conn,
		       SilcSocketType conn_type, unsigned char *pk, 
		       SilcUInt32 pk_len, SilcSKEPKType pk_type,
		       SilcVerifyPublicKey completion, void *context)
{
  silc_verify_public_key_internal(client, conn, NULL, conn_type, pk,
				  pk_len, pk_type,
				  completion, context);
}

/* Asks passphrase from user on the input line. */

typedef struct {
  SilcAskPassphrase completion;
  void *context;
} *AskPassphrase;

void ask_passphrase_completion(const char *passphrase, void *context)
{
  AskPassphrase p = (AskPassphrase)context;
  p->completion((unsigned char *)passphrase, 
		passphrase ? strlen(passphrase) : 0, p->context);
  silc_free(p);
}

void silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
			 SilcAskPassphrase completion, void *context)
{
  AskPassphrase p = silc_calloc(1, sizeof(*p));
  p->completion = completion;
  p->context = context;

  keyboard_entry_redirect((SIGNAL_FUNC)ask_passphrase_completion,
			  "Passphrase: ", ENTRY_REDIRECT_FLAG_HIDDEN, p);
}

typedef struct {
  SilcGetAuthMeth completion;
  void *context;
} *InternalGetAuthMethod;

/* Callback called when we've received the authentication method information
   from the server after we've requested it. This will get the authentication
   data from the user if needed. */

static void silc_get_auth_method_callback(SilcClient client,
					  SilcClientConnection conn,
					  SilcAuthMethod auth_meth,
					  void *context)
{
  InternalGetAuthMethod internal = (InternalGetAuthMethod)context;

  SILC_LOG_DEBUG(("Start"));

  switch (auth_meth) {
  case SILC_AUTH_NONE:
    /* No authentication required. */
    (*internal->completion)(TRUE, auth_meth, NULL, 0, internal->context);
    break;
  case SILC_AUTH_PASSWORD:
    /* Do not ask the passphrase from user, the library will ask it if
       we do not provide it here. */
    (*internal->completion)(TRUE, auth_meth, NULL, 0, internal->context);
    break;
  case SILC_AUTH_PUBLIC_KEY:
    /* Do not get the authentication data now, the library will generate
       it using our default key, if we do not provide it here. */
    /* XXX In the future when we support multiple local keys and multiple
       local certificates we will need to ask from user which one to use. */
    (*internal->completion)(TRUE, auth_meth, NULL, 0, internal->context);
    break;
  }

  silc_free(internal);
}

/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. The found authentication
   method and authentication data is returned to `auth_meth', `auth_data'
   and `auth_data_len'. The function returns TRUE if authentication method
   is found and FALSE if not. `conn' may be NULL. */

void silc_get_auth_method(SilcClient client, SilcClientConnection conn,
			  char *hostname, SilcUInt16 port,
			  SilcGetAuthMeth completion, void *context)
{
  InternalGetAuthMethod internal;

  SILC_LOG_DEBUG(("Start"));

  /* XXX must resolve from configuration whether this connection has
     any specific authentication data */

  /* If we do not have this connection configured by the user in a
     configuration file then resolve the authentication method from the
     server for this session. */
  internal = silc_calloc(1, sizeof(*internal));
  internal->completion = completion;
  internal->context = context;

  silc_client_request_authentication_method(client, conn, 
					    silc_get_auth_method_callback,
					    internal);
}

/* Notifies application that failure packet was received.  This is called
   if there is some protocol active in the client.  The `protocol' is the
   protocol context.  The `failure' is opaque pointer to the failure
   indication.  Note, that the `failure' is protocol dependant and application
   must explicitly cast it to correct type.  Usually `failure' is 32 bit
   failure type (see protocol specs for all protocol failure types). */

void silc_failure(SilcClient client, SilcClientConnection conn, 
		  SilcProtocol protocol, void *failure)
{
  SILC_LOG_DEBUG(("Start"));

  if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE) {
    SilcSKEStatus status = (SilcSKEStatus)failure;
    
    if (status == SILC_SKE_STATUS_BAD_VERSION)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_BAD_VERSION);
    if (status == SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_UNSUPPORTED_PUBLIC_KEY);
    if (status == SILC_SKE_STATUS_UNKNOWN_GROUP)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_UNKNOWN_GROUP);
    if (status == SILC_SKE_STATUS_UNKNOWN_CIPHER)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_UNKNOWN_CIPHER);
    if (status == SILC_SKE_STATUS_UNKNOWN_PKCS)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_UNKNOWN_PKCS);
    if (status == SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_UNKNOWN_HASH_FUNCTION);
    if (status == SILC_SKE_STATUS_UNKNOWN_HMAC)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_UNKNOWN_HMAC);
    if (status == SILC_SKE_STATUS_INCORRECT_SIGNATURE)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_INCORRECT_SIGNATURE);
    if (status == SILC_SKE_STATUS_INVALID_COOKIE)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_KE_INVALID_COOKIE);
  }

  if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_CONNECTION_AUTH) {
    SilcUInt32 err = (SilcUInt32)failure;

    if (err == SILC_AUTH_FAILED)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_AUTH_FAILED);
  }
}

/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). */

int silc_key_agreement(SilcClient client, SilcClientConnection conn,
		       SilcClientEntry client_entry, const char *hostname,
		       SilcUInt16 port, SilcKeyAgreementCallback *completion,
		       void **context)
{
  char portstr[12];

  SILC_LOG_DEBUG(("Start"));

  /* We will just display the info on the screen and return FALSE and user
     will have to start the key agreement with a command. */

  if (hostname) 
    snprintf(portstr, sizeof(portstr) - 1, "%d", port);

  if (!hostname)
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_REQUEST, client_entry->nickname);
  else
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_REQUEST_HOST, 
		       client_entry->nickname, hostname, portstr);

  *completion = NULL;
  *context = NULL;

  return FALSE;
}

void silc_ftp(SilcClient client, SilcClientConnection conn,
	      SilcClientEntry client_entry, SilcUInt32 session_id,
	      const char *hostname, SilcUInt16 port)
{
  SILC_SERVER_REC *server;
  char portstr[12];
  FtpSession ftp = silc_calloc(1, sizeof(*ftp));

  SILC_LOG_DEBUG(("Start"));

  server = conn->context;

  ftp->client_entry = client_entry;
  ftp->session_id = session_id;
  ftp->send = FALSE;
  ftp->conn = conn;
  silc_dlist_add(server->ftp_sessions, ftp);
  server->current_session = ftp;

  if (hostname) 
    snprintf(portstr, sizeof(portstr) - 1, "%d", port);

  if (!hostname)
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_FILE_REQUEST, client_entry->nickname);
  else
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_FILE_REQUEST_HOST, 
		       client_entry->nickname, hostname, portstr);
}

/* SILC client operations */
SilcClientOperations ops = {
  silc_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_connect,
  silc_disconnect,
  silc_get_auth_method,
  silc_verify_public_key,
  silc_ask_passphrase,
  silc_failure,
  silc_key_agreement,
  silc_ftp,
};
