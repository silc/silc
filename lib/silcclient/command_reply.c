/*

  command_reply.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Command reply functions are "the otherside" of the command functions.
 * Reply to a command sent by server is handled by these functions.
 */
/* $Id$ */

#include "clientlibincludes.h"

/* Client command reply list. */
SilcClientCommandReply silc_command_reply_list[] =
{
  SILC_CLIENT_CMD_REPLY(whois, WHOIS),
  SILC_CLIENT_CMD_REPLY(whowas, WHOWAS),
  SILC_CLIENT_CMD_REPLY(identify, IDENTIFY),
  SILC_CLIENT_CMD_REPLY(nick, NICK),
  SILC_CLIENT_CMD_REPLY(list, LIST),
  SILC_CLIENT_CMD_REPLY(topic, TOPIC),
  SILC_CLIENT_CMD_REPLY(invite, INVITE),
  SILC_CLIENT_CMD_REPLY(quit, QUIT),
  SILC_CLIENT_CMD_REPLY(kill, KILL),
  SILC_CLIENT_CMD_REPLY(info, INFO),
  SILC_CLIENT_CMD_REPLY(connect, CONNECT),
  SILC_CLIENT_CMD_REPLY(ping, PING),
  SILC_CLIENT_CMD_REPLY(oper, OPER),
  SILC_CLIENT_CMD_REPLY(join, JOIN),
  SILC_CLIENT_CMD_REPLY(motd, MOTD),
  SILC_CLIENT_CMD_REPLY(umode, UMODE),
  SILC_CLIENT_CMD_REPLY(cmode, CMODE),
  SILC_CLIENT_CMD_REPLY(kick, KICK),
  SILC_CLIENT_CMD_REPLY(restart, RESTART),
  SILC_CLIENT_CMD_REPLY(close, CLOSE),
  SILC_CLIENT_CMD_REPLY(die, DIE),
  SILC_CLIENT_CMD_REPLY(silcoper, SILCOPER),
  SILC_CLIENT_CMD_REPLY(leave, LEAVE),
  SILC_CLIENT_CMD_REPLY(names, NAMES),

  { NULL, 0 },
};

/* Status message structure. Messages are defined below. */
typedef struct {
  SilcCommandStatus status;
  char *message;
} SilcCommandStatusMessage;

/* Status messages returned by the server */
#define STAT(x) SILC_STATUS_ERR_##x
const SilcCommandStatusMessage silc_command_status_messages[] = {

  { STAT(NO_SUCH_NICK),      "No such nickname" },
  { STAT(NO_SUCH_CHANNEL),   "No such channel" },
  { STAT(NO_SUCH_SERVER),    "No such server" },
  { STAT(TOO_MANY_TARGETS),  "Duplicate recipients. No message delivered" },
  { STAT(NO_RECIPIENT),      "No recipient given" },
  { STAT(UNKNOWN_COMMAND),   "Unknown command" },
  { STAT(WILDCARDS),         "Unknown command" },
  { STAT(NO_CLIENT_ID),      "No Client ID given" },
  { STAT(NO_CHANNEL_ID),     "No Channel ID given" },
  { STAT(NO_SERVER_ID),      "No Server ID given" },
  { STAT(BAD_CLIENT_ID),     "Bad Client ID" },
  { STAT(BAD_CHANNEL_ID),    "Bad Channel ID" },
  { STAT(NO_SUCH_CLIENT_ID), "No such Client ID" },
  { STAT(NO_SUCH_CHANNEL_ID),"No such Channel ID" },
  { STAT(NICKNAME_IN_USE),   "Nickname already exists" },
  { STAT(NOT_ON_CHANNEL),    "You are not on that channel" },
  { STAT(USER_ON_CHANNEL),   "User already on channel" },
  { STAT(NOT_REGISTERED),    "You have not registered" },
  { STAT(NOT_ENOUGH_PARAMS), "Not enough parameters" },
  { STAT(TOO_MANY_PARAMS),   "Too many parameters" },
  { STAT(PERM_DENIED),       "Your host is not among the privileged" },
  { STAT(BANNED_FROM_SERVER),"You are banned from this server" },
  { STAT(BAD_PASSWORD),      "Cannot join channel. Incorrect password" },
  { STAT(CHANNEL_IS_FULL),   "Cannot join channel. Channel is full" },
  { STAT(NOT_INVITED),     "Cannot join channel. You have not been invited" },
  { STAT(BANNED_FROM_CHANNEL), "Cannot join channel. You have been banned" },
  { STAT(UNKNOWN_MODE),    "Unknown mode" },
  { STAT(NOT_YOU),         "Cannot change mode for other users" },
  { STAT(NO_CHANNEL_PRIV), "Permission denied. You are not channel operator" },
  { STAT(NO_SERVER_PRIV),  "Permission denied. You are not server operator" },
  { STAT(NO_ROUTER_PRIV),  "Permission denied. You are not SILC operator" },
  { STAT(BAD_NICKNAME),    "Bad nickname" },
  { STAT(BAD_CHANNEL),     "Bad channel name" },
  { STAT(AUTH_FAILED),     "Authentication failed" },

  { 0, NULL }
};

/* Command reply operation that is called at the end of all command replys. 
   Usage: COMMAND_REPLY((ARGS, argument1, argument2, etc...)), */
#define COMMAND_REPLY(args) cmd->client->ops->command_reply args
#define ARGS cmd->client, cmd->sock->user_data, \
             cmd->payload, TRUE, status, silc_command_get(cmd->payload)

/* Error reply to application. Usage: COMMAND_REPLY_ERROR; */
#define COMMAND_REPLY_ERROR cmd->client->ops->command_reply(cmd->client, \
  cmd->sock->user_data, cmd->payload, FALSE, status, \
  silc_command_get(cmd->payload))

/* Process received command reply. */

void silc_client_command_reply_process(SilcClient client,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientCommandReplyContext ctx;
  SilcCommandPayload payload;

  /* Get command reply payload from packet */
  payload = silc_command_parse_payload(buffer);
  if (!payload) {
    /* Silently ignore bad reply packet */
    SILC_LOG_DEBUG(("Bad command reply packet"));
    return;
  }
  
  /* Allocate command reply context. This must be free'd by the
     command reply routine receiving it. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->client = client;
  ctx->sock = sock;
  ctx->payload = payload;
  ctx->packet = packet;
      
  /* Check for pending commands and mark to be exeucted */
  SILC_CLIENT_COMMAND_CHECK_PENDING(ctx);
  
  /* Execute command reply */
  SILC_CLIENT_COMMAND_REPLY_EXEC(ctx);
}

/* Returns status message string */

static char *
silc_client_command_status_message(SilcCommandStatus status)
{
  int i;

  for (i = 0; silc_command_status_messages[i].message; i++) {
    if (silc_command_status_messages[i].status == status)
      break;
  }

  if (silc_command_status_messages[i].message == NULL)
    return NULL;

  return silc_command_status_messages[i].message;
}

/* Free command reply context and its internals. */

void silc_client_command_reply_free(SilcClientCommandReplyContext cmd)
{
  if (cmd) {
    silc_command_free_payload(cmd->payload);
    silc_free(cmd);
  }
}

/* Received reply for WHOIS command. This maybe called several times
   for one WHOIS command as server may reply with list of results. */
/* Sends to application: (no arguments) */

SILC_CLIENT_CMD_REPLY_FUNC(whois)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
      /* Take nickname which may be provided */
      tmp = silc_command_get_arg_type(cmd->payload, 3, NULL);
      if (tmp)
	cmd->client->ops->say(cmd->client, conn, "%s: %s", tmp,
		 silc_client_command_status_message(status));
      else
	cmd->client->ops->say(cmd->client, conn, "%s",
		 silc_client_command_status_message(status));
      COMMAND_REPLY_ERROR;
      goto out;
    } else {
      cmd->client->ops->say(cmd->client, conn,
	       "%s", silc_client_command_status_message(status));
      COMMAND_REPLY_ERROR;
      goto out;
    }
  }

  /* Display one whois reply */
  if (status == SILC_STATUS_OK) {
    char buf[256];
    int argc, len;
    unsigned char *id_data;
    char *nickname = NULL, *username = NULL;
    char *realname = NULL;

    memset(buf, 0, sizeof(buf));

    argc = silc_command_get_arg_num(cmd->payload);
    id_data = silc_command_get_arg_type(cmd->payload, 2, NULL);

    nickname = silc_command_get_arg_type(cmd->payload, 3, &len);
    if (nickname) {
      strncat(buf, nickname, len);
      strncat(buf, " is ", 4);
    }

    username = silc_command_get_arg_type(cmd->payload, 4, &len);
    if (username) {
      strncat(buf, username, len);
    }

    realname = silc_command_get_arg_type(cmd->payload, 5, &len);
    if (realname) {
      strncat(buf, " (", 2);
      strncat(buf, realname, len);
      strncat(buf, ")", 1);
    }

#if 0
    /* Save received Client ID to ID cache */
    /* XXX Maybe should not be saved as /MSG will get confused */
    id = silc_id_str2id(id_data, SILC_ID_CLIENT);
    client->current_conn->client_id_cache_count[(int)nickname[0] - 32] =
    silc_idcache_add(&client->current_conn->
		     client_id_cache[(int)nickname[0] - 32],
		     client->current_conn->
		     client_id_cache_count[(int)nickname[0] - 32],
		     strdup(nickname), SILC_ID_CLIENT, id, NULL);
#endif

    cmd->client->ops->say(cmd->client, conn, "%s", buf);

    /* Notify application */
    COMMAND_REPLY((ARGS));
  }

  if (status == SILC_STATUS_LIST_START) {

  }

  if (status == SILC_STATUS_LIST_END) {

  }

  SILC_CLIENT_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_WHOIS);

 out:
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(whowas)
{
}

/* Received reply for IDENTIFY command. This maybe called several times
   for one IDENTIFY command as server may reply with list of results. 
   This is totally silent and does not print anything on screen. */

SILC_CLIENT_CMD_REPLY_FUNC(identify)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientEntry client_entry;
  SilcCommandStatus status;
  unsigned char *tmp;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
      /* Take nickname which may be provided */
      tmp = silc_command_get_arg_type(cmd->payload, 3, NULL);
      if (tmp)
	cmd->client->ops->say(cmd->client, conn, "%s: %s", tmp,
		 silc_client_command_status_message(status));
      else
	cmd->client->ops->say(cmd->client, conn, "%s",
		 silc_client_command_status_message(status));
      COMMAND_REPLY_ERROR;
      goto out;
    } else {
      cmd->client->ops->say(cmd->client, conn,
	       "%s", silc_client_command_status_message(status));
      COMMAND_REPLY_ERROR;
      goto out;
    }
  }

  /* Display one whois reply */
  if (status == SILC_STATUS_OK) {
    unsigned char *id_data;
    char *nickname;

    id_data = silc_command_get_arg_type(cmd->payload, 2, NULL);
    nickname = silc_command_get_arg_type(cmd->payload, 3, NULL);

    /* Allocate client entry */
    client_entry = silc_calloc(1, sizeof(*client_entry));
    client_entry->id = silc_id_str2id(id_data, SILC_ID_CLIENT);
    client_entry->nickname = strdup(nickname);

    /* Save received Client ID to ID cache */
    silc_idcache_add(conn->client_cache, client_entry->nickname,
		     SILC_ID_CLIENT, client_entry->id, client_entry, TRUE);
  }

  if (status == SILC_STATUS_LIST_START) {

  }

  if (status == SILC_STATUS_LIST_END) {

  }

  SILC_CLIENT_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_IDENTIFY);

 out:
  silc_client_command_reply_free(cmd);
}

/* Received reply for command NICK. If everything went without errors
   we just received our new Client ID. */
/* Sends to application: char * (nickname). */

SILC_CLIENT_CMD_REPLY_FUNC(nick)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp, *id_string;
  int argc;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn, "Cannot set nickname: %s", 
	     silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_command_get_arg_num(cmd->payload);
  if (argc < 2 || argc > 2) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot set nickname: bad reply to command");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take received Client ID */
  id_string = silc_command_get_arg_type(cmd->payload, 2, NULL);
  silc_client_receive_new_id(cmd->client, cmd->sock, id_string);

  /* Notify application */
  COMMAND_REPLY((ARGS, conn->nickname));

 out:
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(list)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(topic)
{
}

/* Received reply to invite command. */
/* Sends to application: (no arguments) */

SILC_CLIENT_CMD_REPLY_FUNC(invite)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    silc_client_command_reply_free(cmd);
    COMMAND_REPLY_ERROR;
    return;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  silc_client_command_reply_free(cmd);
}
 
SILC_CLIENT_CMD_REPLY_FUNC(quit)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(kill)
{
}

/* Received reply to INFO command. We receive the server ID and some
   information about the server user requested. */
/* Sends to application: char * (server information) */

SILC_CLIENT_CMD_REPLY_FUNC(info)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClient client = cmd->client;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    silc_client_command_reply_free(cmd);
    COMMAND_REPLY_ERROR;
    return;
  }

  /* Get server ID */
  tmp = silc_command_get_arg_type(cmd->payload, 2, NULL);
  if (!tmp)
    goto out;

  /* XXX save server id */

  /* Get server info */
  tmp = silc_command_get_arg_type(cmd->payload, 3, NULL);
  if (!tmp)
    goto out;

  client->ops->say(cmd->client, conn, "Info: %s", tmp);

  /* Notify application */
  COMMAND_REPLY((ARGS, (char *)tmp));

 out:
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(connect)
{
}

/* Received reply to PING command. The reply time is shown to user. */
/* Sends to application: (no arguments) */

SILC_CLIENT_CMD_REPLY_FUNC(ping)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  void *id;
  char *tmp;
  int i;
  time_t diff, curtime;

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  curtime = time(NULL);
  id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_type);

  for (i = 0; i < conn->ping_count; i++) {
    if (!SILC_ID_SERVER_COMPARE(conn->ping[i].dest_id, id)) {
      diff = curtime - conn->ping[i].start_time;
      cmd->client->ops->say(cmd->client, conn, 
			    "Ping reply from %s: %d second%s", 
			    conn->ping[i].dest_name, diff, 
			    diff == 1 ? "" : "s");

      conn->ping[i].start_time = 0;
      silc_free(conn->ping[i].dest_id);
      conn->ping[i].dest_id = NULL;
      silc_free(conn->ping[i].dest_name);
      conn->ping[i].dest_name = NULL;

      /* Notify application */
      COMMAND_REPLY((ARGS));
      goto out;
    }
  }

 out:
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(oper)
{
}

/* Received reply for JOIN command. */

SILC_CLIENT_CMD_REPLY_FUNC(join)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClient client = cmd->client;
  SilcCommandStatus status;
  unsigned int argc, mode;
  unsigned char *id_string;
  char *topic, *tmp, *channel_name;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_command_get_arg_num(cmd->payload);
  if (argc < 3 || argc > 4) {
    cmd->client->ops->say(cmd->client, conn,
	     "Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel name */
  tmp = silc_command_get_arg_type(cmd->payload, 2, NULL);
  if (!tmp) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel_name = strdup(tmp);

  /* Get Channel ID */
  id_string = silc_command_get_arg_type(cmd->payload, 3, NULL);
  if (!id_string) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel mode */
  tmp = silc_command_get_arg_type(cmd->payload, 4, NULL);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);
  else
    mode = 0;

  /* Get topic */
  topic = silc_command_get_arg_type(cmd->payload, 5, NULL);

  /* Save received Channel ID */
  silc_client_new_channel_id(cmd->client, cmd->sock, channel_name, 
			     mode, id_string);

  if (topic)
    client->ops->say(cmd->client, conn, 
		     "Topic for %s: %s", channel_name, topic);

  /* Notify application */
  COMMAND_REPLY((ARGS, channel_name, topic));

 out:
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(motd)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(umode)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(cmode)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(kick)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(restart)
{
}
 
SILC_CLIENT_CMD_REPLY_FUNC(close)
{
}
 
SILC_CLIENT_CMD_REPLY_FUNC(die)
{
}
 
SILC_CLIENT_CMD_REPLY_FUNC(silcoper)
{
}

/* Reply to LEAVE command. */
/* Sends to application: (no arguments) */

SILC_CLIENT_CMD_REPLY_FUNC(leave)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    return;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  silc_client_command_reply_free(cmd);
}

/* Reply to NAMES command. Received list of client names on the channel 
   we requested. */

SILC_CLIENT_CMD_REPLY_FUNC(names)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcChannelID *channel_id = NULL;
  SilcBuffer client_id_list;
  unsigned char *tmp;
  char *name_list;
  int i, len1, len2, list_count = 0;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel ID */
  tmp = silc_command_get_arg_type(cmd->payload, 2, NULL);
  if (!tmp) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot get user list: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel_id = silc_id_str2id(tmp, SILC_ID_CHANNEL);

  /* Get the name list of the channel */
  name_list = silc_command_get_arg_type(cmd->payload, 3, &len1);
  if (!name_list) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot get user list: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get Client ID list */
  tmp = silc_command_get_arg_type(cmd->payload, 4, &len2);
  if (!tmp) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot get user list: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  client_id_list = silc_buffer_alloc(len2);
  silc_buffer_pull_tail(client_id_list, len2);
  silc_buffer_put(client_id_list, tmp, len2);

  /* Get the channel name */
  if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				   SILC_ID_CHANNEL, &id_cache)) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  
  channel = (SilcChannelEntry)id_cache->context;

  /* If there is pending command we know that user has called this command
     and we will handle the name list differently. */
  if (cmd->callback) {
    /* We will resolve all the necessary information about the people
       on the channel. Only after that will we display the user list. */
    for (i = 0; i < len1; i++) {
      /* XXX */

    }
    silc_client_command_pending_del(SILC_COMMAND_NAMES);
  } else {
    /* there is no pending callback it means that this command reply
       has been received without calling the command, ie. server has sent
       the reply without getting the command from us first. This happens
       with SILC servers that sends NAMES reply after joining to a channel. */

    /* Remove commas from list */
    for (i = 0; i < len1; i++)
      if (name_list[i] == ',') {
	name_list[i] = ' ';
	list_count++;
      }

    cmd->client->ops->say(cmd->client, conn,
			  "Users on %s: %s", channel->channel_name, name_list);
  }

  /* Cache the received name list and client ID's. This cache expires
     whenever server sends notify message to channel. It means two things;
     some user has joined or leaved the channel. */
  for (i = 0; i < list_count; i++) {
    int nick_len = strcspn(name_list, " ");
    char *nickname = silc_calloc(nick_len, sizeof(*nickname));
    SilcClientID *client_id;
    SilcClientEntry client;

    memcpy(nickname, name_list, nick_len);
    client_id = silc_id_str2id(client_id_list->data, SILC_ID_CLIENT);
    silc_buffer_pull(client_id_list, SILC_ID_CLIENT_LEN);

    client = silc_calloc(1, sizeof(*client));
    client->id = client_id;
    client->nickname = nickname;

    silc_idcache_add(conn->client_cache, nickname, SILC_ID_CLIENT,
		     client_id, (void *)client, TRUE);
    name_list = name_list + nick_len + 1;
  }

  silc_buffer_free(client_id_list);

 out:
  if (channel_id)
    silc_free(channel_id);
  silc_client_command_reply_free(cmd);
}
