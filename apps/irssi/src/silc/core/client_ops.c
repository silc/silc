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
				SilcSocketType conn_type, unsigned char *pk, 
				uint32 pk_len, SilcSKEPKType pk_type,
				SilcVerifyPublicKey completion, void *context);

void silc_say(SilcClient client, SilcClientConnection conn,
		     char *msg, ...)
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
  
  server = conn == NULL ? NULL : conn->context;
  chanrec = silc_channel_find_entry(server, channel);
  if (!chanrec)
    return;
  
  nick = silc_nicklist_find(chanrec, sender);

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
  
  server = conn == NULL ? NULL : conn->context;
  signal_emit("message private", 4, server, msg,
	      sender->nickname ? sender->nickname : "[<unknown>]",
	      sender->username ? sender->username : NULL);
}

/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it). */

typedef struct {
  int type;
  const char *name;
} NOTIFY_REC;

#define MAX_NOTIFY (sizeof(notifies)/sizeof(notifies[0]))
static NOTIFY_REC notifies[] = {
  { SILC_NOTIFY_TYPE_NONE,		NULL },
  { SILC_NOTIFY_TYPE_INVITE,		"invite" },
  { SILC_NOTIFY_TYPE_JOIN,		"join" },
  { SILC_NOTIFY_TYPE_LEAVE,		"leave" },
  { SILC_NOTIFY_TYPE_SIGNOFF,		"signoff" },
  { SILC_NOTIFY_TYPE_TOPIC_SET,		"topic" },
  { SILC_NOTIFY_TYPE_NICK_CHANGE,	"nick" },
  { SILC_NOTIFY_TYPE_CMODE_CHANGE,	"cmode" },
  { SILC_NOTIFY_TYPE_CUMODE_CHANGE,	"cumode" },
  { SILC_NOTIFY_TYPE_MOTD,		"motd" },
  { SILC_NOTIFY_TYPE_CHANNEL_CHANGE,	"channel_change" },
  { SILC_NOTIFY_TYPE_SERVER_SIGNOFF,	"server_signoff" },
  { SILC_NOTIFY_TYPE_KICKED,	        "kick" },
  { SILC_NOTIFY_TYPE_KILLED,	        "kill" },
  { SILC_NOTIFY_TYPE_UMODE_CHANGE,      "umode" },
  { SILC_NOTIFY_TYPE_BAN,               "ban" },
};

void silc_notify(SilcClient client, SilcClientConnection conn,
		 SilcNotifyType type, ...)
{
  SILC_SERVER_REC *server;
  va_list va;
  
  server = conn == NULL ? NULL : conn->context;
  va_start(va, type);
  
  if (type == SILC_NOTIFY_TYPE_NONE) {
    /* Some generic notice from server */
    printtext(server, NULL, MSGLEVEL_CRAP, "%s", (char *)va_arg(va, char *));
  } else if (type < MAX_NOTIFY) {
    /* Send signal about the notify event */
    char signal[50];
    g_snprintf(signal, sizeof(signal), "silc event %s", notifies[type].name);
    signal_emit(signal, 2, server, va);
  } else {
    /* Unknown notify */
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_UNKNOWN_NOTIFY, type);
  }

  va_end(va);
}

/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection objecet which it should save somewhere. */

void  silc_connect(SilcClient client, SilcClientConnection conn, int success)
{
  SILC_SERVER_REC *server = conn->context;

  if (success) {
    server->connected = TRUE;
    signal_emit("event connected", 1, server);
  } else {
    server->connection_lost = TRUE;
    server->conn->context = NULL;
    server_disconnect(SERVER(server));
  }
}

/* Called to indicate that connection was disconnected to the server. */

void silc_disconnect(SilcClient client, SilcClientConnection conn)
{
  SILC_SERVER_REC *server = conn->context;

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
}

/* Client info resolving callback when JOIN command reply is received.
   This will cache all users on the channel. */

static void silc_client_join_get_users(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry *clients,
				       uint32 clients_count,
				       void *context)
{
  SilcChannelEntry channel = (SilcChannelEntry)context;
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

  silc_list_start(channel->clients);
  while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
    if (chu->mode & SILC_CHANNEL_UMODE_CHANFO)
      founder = chu->client;
    silc_nicklist_insert(chanrec, chu, FALSE);
  }

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

  switch(command) {
  case SILC_COMMAND_WHOIS:
    {
      char buf[1024], *nickname, *username, *realname;
      uint32 idle, mode;
      SilcBuffer channels;
      
      if (status == SILC_STATUS_ERR_NO_SUCH_NICK ||
	  status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
	char *tmp;
	tmp = silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
					 3, NULL);
	if (tmp)
	  silc_say_error("%s: %s", tmp, 
			 silc_client_command_status_message(status));
	else
	  silc_say_error("%s", silc_client_command_status_message(status));
	break;
      }
      
      if (!success)
	return;
      
      (void)va_arg(vp, SilcClientEntry);
      nickname = va_arg(vp, char *);
      username = va_arg(vp, char *);
      realname = va_arg(vp, char *);
      channels = va_arg(vp, SilcBuffer);
      mode = va_arg(vp, uint32);
      idle = va_arg(vp, uint32);
      
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOIS_USERINFO, nickname, username, 
			 realname);

      if (channels) {
	SilcDList list = silc_channel_payload_parse_list(channels);
	if (list) {
	  SilcChannelPayload entry;
	  memset(buf, 0, sizeof(buf));
	  silc_dlist_start(list);
	  while ((entry = silc_dlist_get(list)) != SILC_LIST_END) {
	    char *m = silc_client_chumode_char(silc_channel_get_mode(entry));
	    uint32 name_len;
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
    }
    break;
    
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
	else
	  silc_say_error("%s", silc_client_command_status_message(status));
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
      
      if (!success)
	return;
      
      channel = va_arg(vp, SilcChannelEntry);
      invite_list = va_arg(vp, char *);
      
      if (invite_list)
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CHANNEL_INVITE_LIST, channel->channel_name,
			   invite_list);
      else
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_CHANNEL_NO_INVITE_LIST, 
			   channel->channel_name);
    }
    break;

  case SILC_COMMAND_JOIN: 
    {
      char *channel, *mode, *topic;
      uint32 modei;
      SilcChannelEntry channel_entry;
      SilcBuffer client_id_list;
      uint32 list_count;

      if (!success)
	return;

      channel = va_arg(vp, char *);
      channel_entry = va_arg(vp, SilcChannelEntry);
      modei = va_arg(vp, uint32);
      (void)va_arg(vp, uint32);
      (void)va_arg(vp, unsigned char *);
      (void)va_arg(vp, unsigned char *);
      (void)va_arg(vp, unsigned char *);
      topic = va_arg(vp, char *);
      (void)va_arg(vp, unsigned char *);
      list_count = va_arg(vp, uint32);
      client_id_list = va_arg(vp, SilcBuffer);

      chanrec = silc_channel_find(server, channel);
      if (chanrec != NULL && !success)
	channel_destroy(CHANNEL(chanrec));
      else if (chanrec == NULL && success)
	chanrec = silc_channel_create(server, channel, TRUE);
      
      if (topic) {
	g_free_not_null(chanrec->topic);
	chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
	signal_emit("channel topic changed", 1, chanrec);
      }

      mode = silc_client_chmode(modei, 
				channel_entry->channel_key->cipher->name,
				channel_entry->hmac->hmac->name);
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

      snprintf(users, sizeof(users) - 1, "%d", usercount);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_LIST,
			 name, users, topic ? topic : "");
    }
    break;
    
  case SILC_COMMAND_UMODE:
    {
      uint32 mode;
      
      if (!success)
	return;
      
      mode = va_arg(vp, uint32);
      
      if (mode & SILC_UMODE_SERVER_OPERATOR)
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_SERVER_OPER);

      if (mode & SILC_UMODE_ROUTER_OPERATOR)
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ROUTER_OPER);
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
      SilcChannelEntry channel;
      SilcChannelUser chu;
      
      if (!success)
	return;
      
      channel = va_arg(vp, SilcChannelEntry);
      
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_USERS_HEADER,
			 channel->channel_name);

      silc_list_start(channel->clients);
      while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
	SilcClientEntry e = chu->client;
	char stat[5], *mode;
	
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
			   e->nickname, stat, e->username, 
			   e->realname ? e->realname : "");
	if (mode)
	  silc_free(mode);
      }
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
      uint32 pk_len;
      
      if (!success)
	return;
      
      id_type = va_arg(vp, uint32);
      entry = va_arg(vp, void *);
      public_key = va_arg(vp, SilcPublicKey);
      
      pk = silc_pkcs_public_key_encode(public_key, &pk_len);
      
      if (id_type == SILC_ID_CLIENT)
	silc_verify_public_key_internal(client, conn, SILC_SOCKET_TYPE_CLIENT,
					pk, pk_len, SILC_SKE_PK_TYPE_SILC,
					NULL, NULL);
      silc_free(pk);
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

/* Internal routine to verify public key. If the `completion' is provided
   it will be called to indicate whether public was verified or not. */

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  char *filename;
  char *entity;
  unsigned char *pk;
  uint32 pk_len;
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
		       MSGLEVEL_CRAP, SILCTXT_PUBKEY_DISCARD, verify->entity);
  }

  silc_free(verify->filename);
  silc_free(verify->entity);
  silc_free(verify->pk);
  silc_free(verify);
}

static void 
silc_verify_public_key_internal(SilcClient client, SilcClientConnection conn,
				SilcSocketType conn_type, unsigned char *pk, 
				uint32 pk_len, SilcSKEPKType pk_type,
				SilcVerifyPublicKey completion, void *context)
{
  int i;
  char file[256], filename[256], *fingerprint, *format;
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
  memset(file, 0, sizeof(file));

  if (conn_type == SILC_SOCKET_TYPE_SERVER ||
      conn_type == SILC_SOCKET_TYPE_ROUTER) {
    snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity, 
	     conn->sock->hostname, conn->sock->port);
    snprintf(filename, sizeof(filename) - 1, "%s/.silc/%skeys/%s", 
	     pw->pw_dir, entity, file);
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
  }

  /* Take fingerprint of the public key */
  fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);

  verify = silc_calloc(1, sizeof(*verify));
  verify->client = client;
  verify->conn = conn;
  verify->filename = strdup(filename);
  verify->entity = strdup(entity);
  verify->pk = silc_calloc(pk_len, sizeof(*verify->pk));
  memcpy(verify->pk, pk, pk_len);
  verify->pk_len = pk_len;
  verify->pk_type = pk_type;
  verify->completion = completion;
  verify->context = context;

  /* Check whether this key already exists */
  if (stat(filename, &st) < 0) {
    /* Key does not exist, ask user to verify the key and save it */

    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_PUBKEY_RECEIVED, entity);
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
		       SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
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
    uint32 encpk_len;

    /* Load the key file */
    if (!silc_pkcs_load_public_key(filename, &public_key, 
				   SILC_PKCS_FILE_PEM))
      if (!silc_pkcs_load_public_key(filename, &public_key, 
				     SILC_PKCS_FILE_BIN)) {
	printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			   SILCTXT_PUBKEY_RECEIVED, entity);
	printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			   SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
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
			 SILCTXT_PUBKEY_RECEIVED, entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
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
			 SILCTXT_PUBKEY_RECEIVED, entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP, 
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
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
		       uint32 pk_len, SilcSKEPKType pk_type,
		       SilcVerifyPublicKey completion, void *context)
{
  silc_verify_public_key_internal(client, conn, conn_type, pk,
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

/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. The found authentication
   method and authentication data is returned to `auth_meth', `auth_data'
   and `auth_data_len'. The function returns TRUE if authentication method
   is found and FALSE if not. `conn' may be NULL. */

int silc_get_auth_method(SilcClient client, SilcClientConnection conn,
			 char *hostname, uint16 port,
			 SilcProtocolAuthMeth *auth_meth,
			 unsigned char **auth_data,
			 uint32 *auth_data_len)
{
  bool ret = TRUE;
  SILC_SERVER_REC *server = conn ? conn->context : NULL;

  /* XXX must resolve from configuration whether this connection has
     any specific authentication data */

  *auth_meth = SILC_AUTH_NONE;
  *auth_data = NULL;
  *auth_data_len = 0;

  if (ret == FALSE) {
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_MODES, SILCTXT_AUTH_METH_UNRESOLVED);
  }

  return ret;
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
  }

  if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_CONNECTION_AUTH) {
    uint32 err = (uint32)failure;

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
		       SilcClientEntry client_entry, char *hostname,
		       int port,
		       SilcKeyAgreementCallback *completion,
		       void **context)
{
  char portstr[6];

  /* We will just display the info on the screen and return FALSE and user
     will have to start the key agreement with a command. */

  if (hostname) 
    snprintf(portstr, sizeof(portstr) - 1, "%d", port);

  if (!hostname)
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_REQUEST, client_entry->nickname);
  else
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_NOTICES,
		       SILCTXT_KEY_AGREEMENT_REQUEST_HOST, 
		       client_entry->nickname, hostname, portstr);

  *completion = NULL;
  *context = NULL;

  return FALSE;
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
};
