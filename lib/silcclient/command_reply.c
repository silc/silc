/*

  command_reply.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
 *
 * The arguments received from server are also passed to the calling
 * application through command_reply client operation.  The arguments are
 * exactly same and in same order as the server sent it.  However, ID's are
 * not sent to the application.  Instead, corresponding ID entry is sent
 * to the application.  For example, instead of sending Client ID the 
 * corresponding SilcClientEntry is sent to the application.  The case is
 * same with for example Channel ID's.  This way application has all the
 * necessary data already in hand without redundant searching.  If ID is
 * received but ID entry does not exist, NULL is sent.
 */
/* $Id$ */

#include "clientlibincludes.h"
#include "client_internal.h"

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
  SILC_CLIENT_CMD_REPLY(kill, KILL),
  SILC_CLIENT_CMD_REPLY(info, INFO),
  SILC_CLIENT_CMD_REPLY(connect, CONNECT),
  SILC_CLIENT_CMD_REPLY(ping, PING),
  SILC_CLIENT_CMD_REPLY(oper, OPER),
  SILC_CLIENT_CMD_REPLY(join, JOIN),
  SILC_CLIENT_CMD_REPLY(motd, MOTD),
  SILC_CLIENT_CMD_REPLY(umode, UMODE),
  SILC_CLIENT_CMD_REPLY(cmode, CMODE),
  SILC_CLIENT_CMD_REPLY(cumode, CUMODE),
  SILC_CLIENT_CMD_REPLY(kick, KICK),
  SILC_CLIENT_CMD_REPLY(restart, RESTART),
  SILC_CLIENT_CMD_REPLY(close, CLOSE),
  SILC_CLIENT_CMD_REPLY(shutdown, SHUTDOWN),
  SILC_CLIENT_CMD_REPLY(silcoper, SILCOPER),
  SILC_CLIENT_CMD_REPLY(leave, LEAVE),
  SILC_CLIENT_CMD_REPLY(users, USERS),

  { NULL, 0 },
};

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
  { STAT(USER_NOT_ON_CHANNEL),"They are not on the channel" },
  { STAT(USER_ON_CHANNEL),   "User already on the channel" },
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
  { STAT(NO_CHANNEL_FOPRIV),"Permission denied. You are not channel founder" },
  { STAT(NO_SERVER_PRIV),  "Permission denied. You are not server operator" },
  { STAT(NO_ROUTER_PRIV),  "Permission denied. You are not SILC operator" },
  { STAT(BAD_NICKNAME),    "Bad nickname" },
  { STAT(BAD_CHANNEL),     "Bad channel name" },
  { STAT(AUTH_FAILED),     "Authentication failed" },
  { STAT(UNKNOWN_ALGORITHM), "Unsupported algorithm" },

  { 0, NULL }
};
/* Command reply operation that is called at the end of all command replys. 
   Usage: COMMAND_REPLY((ARGS, argument1, argument2, etc...)), */
#define COMMAND_REPLY(args) cmd->client->ops->command_reply args
#define ARGS cmd->client, cmd->sock->user_data, \
             cmd->payload, TRUE, silc_command_get(cmd->payload), status

/* Error reply to application. Usage: COMMAND_REPLY_ERROR; */
#define COMMAND_REPLY_ERROR cmd->client->ops->command_reply(cmd->client, \
  cmd->sock->user_data, cmd->payload, FALSE, \
  silc_command_get(cmd->payload), status)

/* Process received command reply. */

void silc_client_command_reply_process(SilcClient client,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientCommandReply *cmd;
  SilcClientCommandReplyContext ctx;
  SilcCommandPayload payload;
  SilcCommand command;
  unsigned short ident;

  /* Get command reply payload from packet */
  payload = silc_command_payload_parse(buffer);
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
  ctx->args = silc_command_get_args(ctx->payload);
  ctx->packet = packet;
  ident = silc_command_get_ident(ctx->payload);
      
  /* Check for pending commands and mark to be exeucted */
  silc_client_command_pending_check(sock->user_data, ctx, 
				    silc_command_get(ctx->payload), ident);

  /* Execute command reply */
  command = silc_command_get(ctx->payload);
  for (cmd = silc_command_reply_list; cmd->cb; cmd++)
    if (cmd->cmd == command)
      break;

  if (cmd == NULL || !cmd->cb) {
    silc_free(ctx);
    return;
  }

  cmd->cb(ctx);
}

/* Returns status message string */

char *silc_client_command_status_message(SilcCommandStatus status)
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

static void 
silc_client_command_reply_whois_save(SilcClientCommandReplyContext cmd,
				     SilcCommandStatus status)
{
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client_entry = NULL;
  int argc, len;
  unsigned char *id_data, *tmp;
  char *nickname = NULL, *username = NULL;
  char *realname = NULL;
  unsigned int idle = 0;
  
  argc = silc_argument_get_arg_num(cmd->args);

  id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!id_data) {
    COMMAND_REPLY_ERROR;
    return;
  }
  
  client_id = silc_id_payload_parse_id(id_data, len);
  if (!client_id) {
    COMMAND_REPLY_ERROR;
    return;
  }
  
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!nickname || !username || !realname) {
    COMMAND_REPLY_ERROR;
    return;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (tmp)
    SILC_GET32_MSB(idle, tmp);

  /* Check if we have this client cached already. */
  if (!silc_idcache_find_by_id_one(conn->client_cache, (void *)client_id,
				   SILC_ID_CLIENT, &id_cache)) {
    SILC_LOG_DEBUG(("Adding new client entry"));

    client_entry = silc_calloc(1, sizeof(*client_entry));
    client_entry->id = client_id;
    silc_parse_nickname(nickname, &client_entry->nickname, 
			&client_entry->server, &client_entry->num);
    client_entry->username = strdup(username);
    if (realname)
      client_entry->realname = strdup(realname);
    
    /* Add client to cache */
    silc_idcache_add(conn->client_cache, client_entry->nickname,
		     SILC_ID_CLIENT, client_id, (void *)client_entry, 
		     TRUE, FALSE);
  } else {
    client_entry = (SilcClientEntry)id_cache->context;
    if (client_entry->nickname)
      silc_free(client_entry->nickname);
    if (client_entry->server)
      silc_free(client_entry->server);
    if (client_entry->username)
      silc_free(client_entry->username);
    if (client_entry->realname)
      silc_free(client_entry->realname);

    SILC_LOG_DEBUG(("Updating client entry"));

    silc_parse_nickname(nickname, &client_entry->nickname, 
			&client_entry->server, &client_entry->num);
    client_entry->username = strdup(username);
    if (realname)
      client_entry->realname = strdup(realname);

    id_cache->data = client_entry->nickname;
    silc_idcache_sort_by_data(conn->client_cache);

    silc_free(client_id);
  }

  /* Notify application */
  if (!cmd->callback)
    COMMAND_REPLY((ARGS, client_entry, nickname, username, realname, 
		   NULL, idle));
}

/* Received reply for WHOIS command. This maybe called several times
   for one WHOIS command as server may reply with list of results. */

SILC_CLIENT_CMD_REPLY_FUNC(whois)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcCommandStatus status;
  unsigned char *tmp;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK && 
      status != SILC_STATUS_LIST_START &&
      status != SILC_STATUS_LIST_ITEM &&
      status != SILC_STATUS_LIST_END) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Display one whois reply */
  if (status == SILC_STATUS_OK)
    silc_client_command_reply_whois_save(cmd, status);

  /* List */
  if (status == SILC_STATUS_LIST_START ||
      status == SILC_STATUS_LIST_ITEM ||
      status == SILC_STATUS_LIST_END)
    silc_client_command_reply_whois_save(cmd, status);

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_WHOIS);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_WHOIS);
  silc_client_command_reply_free(cmd);
}

/* Received reply for WHOWAS command. */

SILC_CLIENT_CMD_REPLY_FUNC(whowas)
{

}

static void 
silc_client_command_reply_identify_save(SilcClientCommandReplyContext cmd,
					SilcCommandStatus status)
{
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry client_entry = NULL;
  int argc, len;
  unsigned char *id_data;
  char *nickname = NULL, *username = NULL;
  
  argc = silc_argument_get_arg_num(cmd->args);

  id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!id_data) {
    COMMAND_REPLY_ERROR;
    return;
  }
  
  client_id = silc_id_payload_parse_id(id_data, len);
  if (!client_id) {
    COMMAND_REPLY_ERROR;
    return;
  }
  
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);

  /* Check if we have this client cached already. */
  if (!silc_idcache_find_by_id_one(conn->client_cache, (void *)client_id,
				   SILC_ID_CLIENT, &id_cache)) {
    SILC_LOG_DEBUG(("Adding new client entry"));

    client_entry = silc_calloc(1, sizeof(*client_entry));
    client_entry->id = client_id;
    silc_parse_nickname(nickname, &client_entry->nickname, 
			&client_entry->server, &client_entry->num);
    if (username)
      client_entry->username = strdup(username);
    
    /* Add client to cache */
    silc_idcache_add(conn->client_cache, client_entry->nickname,
		     SILC_ID_CLIENT, client_id, (void *)client_entry, 
		     TRUE, FALSE);
  } else {
    client_entry = (SilcClientEntry)id_cache->context;
    if (client_entry->nickname)
      silc_free(client_entry->nickname);
    if (client_entry->server)
      silc_free(client_entry->server);
    if (username && client_entry->username)
      silc_free(client_entry->username);
    
    SILC_LOG_DEBUG(("Updating client entry"));

    silc_parse_nickname(nickname, &client_entry->nickname, 
			&client_entry->server, &client_entry->num);
    
    if (username)
      client_entry->username = strdup(username);
    
    id_cache->data = client_entry->nickname;
    silc_idcache_sort_by_data(conn->client_cache);
    
    silc_free(client_id);
  }

  /* Notify application */
  COMMAND_REPLY((ARGS, client_entry, nickname, username));
}

/* Received reply for IDENTIFY command. This maybe called several times
   for one IDENTIFY command as server may reply with list of results. 
   This is totally silent and does not print anything on screen. */

SILC_CLIENT_CMD_REPLY_FUNC(identify)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcCommandStatus status;
  unsigned char *tmp;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK && 
      status != SILC_STATUS_LIST_START &&
      status != SILC_STATUS_LIST_ITEM &&
      status != SILC_STATUS_LIST_END) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Save one IDENTIFY entry */
  if (status == SILC_STATUS_OK)
    silc_client_command_reply_identify_save(cmd, status);

  /* List */
  if (status == SILC_STATUS_LIST_START ||
      status == SILC_STATUS_LIST_ITEM ||
      status == SILC_STATUS_LIST_END)
    silc_client_command_reply_identify_save(cmd, status);

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_IDENTIFY);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_IDENTIFY);
  silc_client_command_reply_free(cmd);
}

/* Received reply for command NICK. If everything went without errors
   we just received our new Client ID. */

SILC_CLIENT_CMD_REPLY_FUNC(nick)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  SilcIDPayload idp;
  unsigned char *tmp;
  unsigned int argc, len;

  SILC_LOG_DEBUG(("Start"));

  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL));
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn, "Cannot set nickname: %s", 
	     silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 2 || argc > 2) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot set nickname: bad reply to command");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take received Client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  idp = silc_id_payload_parse_data(tmp, len);
  if (!idp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  silc_client_receive_new_id(cmd->client, cmd->sock, idp);
    
  /* Notify application */
  COMMAND_REPLY((ARGS, conn->local_entry));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_NICK);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_NICK);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(list)
{
}

/* Received reply to topic command. */

SILC_CLIENT_CMD_REPLY_FUNC(topic)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  SilcChannelEntry channel;
  SilcChannelID *channel_id = NULL;
  SilcIDCacheEntry id_cache = NULL;
  unsigned char *tmp;
  char *topic;
  unsigned int argc, len;

  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL));
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_TOPIC);
    silc_client_command_reply_free(cmd);
    return;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1 || argc > 3) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  /* Take topic */
  topic = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!topic)
    goto out;

  channel_id = silc_id_payload_parse_id(tmp, len);
  if (!channel_id)
    goto out;

  /* Get the channel name */
  if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				   SILC_ID_CHANNEL, &id_cache)) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }
  
  channel = (SilcChannelEntry)id_cache->context;

  cmd->client->ops->say(cmd->client, conn, 
			"Topic on channel %s: %s", channel->channel_name,
			topic);

  /* Notify application */
  COMMAND_REPLY((ARGS, channel, topic));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_TOPIC);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_TOPIC);
  silc_client_command_reply_free(cmd);
}

/* Received reply to invite command. */

SILC_CLIENT_CMD_REPLY_FUNC(invite)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_INVITE);
    silc_client_command_reply_free(cmd);
    return;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_INVITE);

  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_INVITE);
  silc_client_command_reply_free(cmd);
}
 
SILC_CLIENT_CMD_REPLY_FUNC(kill)
{
}

/* Received reply to INFO command. We receive the server ID and some
   information about the server user requested. */

SILC_CLIENT_CMD_REPLY_FUNC(info)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClient client = cmd->client;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_INFO);
    silc_client_command_reply_free(cmd);
    return;
  }

  /* Get server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp)
    goto out;

  /* XXX save server id */

  /* Get server info */
  tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!tmp)
    goto out;

  client->ops->say(cmd->client, conn, "Info: %s", tmp);

  /* Notify application */
  COMMAND_REPLY((ARGS, NULL, (char *)tmp));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_INFO);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_INFO);
  silc_client_command_reply_free(cmd);
}

/* Received reply to PING command. The reply time is shown to user. */

SILC_CLIENT_CMD_REPLY_FUNC(ping)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  void *id;
  int i;
  time_t diff, curtime;

  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL));
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  curtime = time(NULL);
  id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_len,
		      cmd->packet->src_id_type);
  if (!id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

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
      break;
    }
  }

  silc_free(id);

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_PING);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_PING);
  silc_client_command_reply_free(cmd);
}

/* Received reply for JOIN command. */

SILC_CLIENT_CMD_REPLY_FUNC(join)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  SilcIDPayload idp = NULL;
  SilcChannelEntry channel;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelUser chu;
  unsigned int argc, mode, len, list_count;
  char *topic, *tmp, *channel_name = NULL, *hmac;
  SilcBuffer keyp, client_id_list, client_mode_list;
  int i;

  SILC_LOG_DEBUG(("Start"));

  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL));
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 7 || argc > 14) {
    cmd->client->ops->say(cmd->client, conn,
	     "Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel_name = strdup(tmp);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!tmp) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    silc_free(channel_name);
    goto out;
  }
  idp = silc_id_payload_parse_data(tmp, len);
  if (!idp) {
    COMMAND_REPLY_ERROR;
    silc_free(channel_name);
    goto out;
  }

  /* Get channel mode */
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);
  else
    mode = 0;

  /* Get channel key */
  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (!tmp) {
    silc_id_payload_free(idp);
    silc_free(channel_name);
    goto out;
  }
  keyp = silc_buffer_alloc(len);
  silc_buffer_pull_tail(keyp, SILC_BUFFER_END(keyp));
  silc_buffer_put(keyp, tmp, len);

  /* Get topic */
  topic = silc_argument_get_arg_type(cmd->args, 10, NULL);

  /* Save received Channel ID. This actually creates the channel */
  channel = silc_client_new_channel_id(cmd->client, cmd->sock, channel_name, 
				       mode, idp);
  silc_id_payload_free(idp);

  /* Get hmac */
  hmac = silc_argument_get_arg_type(cmd->args, 11, NULL);
  if (hmac) {
    if (!silc_hmac_alloc(hmac, NULL, &channel->hmac)) {
      cmd->client->ops->say(cmd->client, conn, 
			    "Cannot join channel: Unsupported HMAC `%s'",
			    hmac);
      COMMAND_REPLY_ERROR;
      silc_free(channel_name);
      goto out;
    }
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 12, &len);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 13, &len);
  if (!tmp)
    goto out;

  client_id_list = silc_buffer_alloc(len);
  silc_buffer_pull_tail(client_id_list, len);
  silc_buffer_put(client_id_list, tmp, len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 14, &len);
  if (!tmp)
    goto out;

  client_mode_list = silc_buffer_alloc(len);
  silc_buffer_pull_tail(client_mode_list, len);
  silc_buffer_put(client_mode_list, tmp, len);

  /* Add clients we received in the reply to the channel */
  for (i = 0; i < list_count; i++) {
    unsigned short idp_len;
    unsigned int mode;
    SilcClientID *client_id;
    SilcClientEntry client_entry;

    /* Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list->data, idp_len);
    if (!client_id)
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list->data);

    /* Check if we have this client cached already. */
    if (!silc_idcache_find_by_id_one(conn->client_cache, (void *)client_id,
				     SILC_ID_CLIENT, &id_cache)) {
      /* No, we don't have it, add entry for it. */
      client_entry = silc_calloc(1, sizeof(*client_entry));
      client_entry->id = silc_id_dup(client_id, SILC_ID_CLIENT);
      silc_idcache_add(conn->client_cache, NULL, SILC_ID_CLIENT, 
		       client_entry->id, (void *)client_entry, FALSE, FALSE);
    } else {
      /* Yes, we have it already */
      client_entry = (SilcClientEntry)id_cache->context;
    }

    /* Join the client to the channel */
    chu = silc_calloc(1, sizeof(*chu));
    chu->client = client_entry;
    chu->mode = mode;
    silc_list_add(channel->clients, chu);
    silc_free(client_id);

    silc_buffer_pull(client_id_list, idp_len);
    silc_buffer_pull(client_mode_list, 4);
  }
  silc_buffer_push(client_id_list, client_id_list->data - 
		   client_id_list->head);
  silc_buffer_push(client_mode_list, client_mode_list->data - 
		   client_mode_list->head);

  /* Save channel key */
  silc_client_save_channel_key(conn, keyp, channel);

  /* Notify application */
  COMMAND_REPLY((ARGS, channel_name, channel, mode, 0, keyp->head, NULL,
		 NULL, topic, hmac, list_count, client_id_list, 
		 client_mode_list));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_JOIN);

  silc_buffer_free(keyp);
  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_JOIN);
  silc_client_command_reply_free(cmd);
}

/* Received reply for MOTD command */

SILC_CLIENT_CMD_REPLY_FUNC(motd)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned int argc, i;
  unsigned char *tmp;
  char *motd = NULL, *cp, line[256];

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    return;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc > 2) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  if (argc == 2) {
    motd = silc_argument_get_arg_type(cmd->args, 2, NULL);
    if (!motd) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    i = 0;
    cp = motd;
    while(cp[i] != 0) {
      if (cp[i++] == '\n') {
	memset(line, 0, sizeof(line));
	strncat(line, cp, i - 1);
	cp += i;
	
	if (i == 2)
	  line[0] = ' ';
	
	cmd->client->ops->say(cmd->client, conn, "%s", line);
	
	if (!strlen(cp))
	  break;
	i = 0;
      }
    }
  }

  /* Notify application */
  COMMAND_REPLY((ARGS, motd));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_MOTD);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_MOTD);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(umode)
{
}

/* Received reply for CMODE command. */

SILC_CLIENT_CMD_REPLY_FUNC(cmode)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL));
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel mode */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS, tmp));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_CMODE);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_CMODE);
  silc_client_command_reply_free(cmd);
}

/* Received reply for CUMODE command */

SILC_CLIENT_CMD_REPLY_FUNC(cumode)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientID *client_id;
  unsigned char *tmp, *id;
  unsigned int len;
  
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL));
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }
  
  /* Get channel mode */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get Client ID */
  id = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  client_id = silc_id_payload_parse_id(id, len);
  if (!client_id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  
  /* Get client entry */
  if (!silc_idcache_find_by_id_one(conn->client_cache, (void *)client_id,
				   SILC_ID_CLIENT, &id_cache)) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS, tmp, (SilcClientEntry)id_cache->context));
  silc_free(client_id);
  
  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_CUMODE);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_CUMODE);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(kick)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_KICK);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_KICK);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(silcoper)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(oper)
{
}

SILC_CLIENT_CMD_REPLY_FUNC(connect)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_CONNECT);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_CONNECT);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(restart)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_RESTART);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_RESTART);
  silc_client_command_reply_free(cmd);
}
 
SILC_CLIENT_CMD_REPLY_FUNC(close)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_CLOSE);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_CLOSE);
  silc_client_command_reply_free(cmd);
}
 
SILC_CLIENT_CMD_REPLY_FUNC(shutdown)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_SHUTDOWN);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_SHUTDOWN);
  silc_client_command_reply_free(cmd);
}
 
/* Reply to LEAVE command. */

SILC_CLIENT_CMD_REPLY_FUNC(leave)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  unsigned char *tmp;

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_LEAVE);

 out:
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_LEAVE);
  silc_client_command_reply_free(cmd);
}

/* Reply to USERS command. Received list of client ID's and theirs modes
   on the channel we requested. */

SILC_CLIENT_CMD_REPLY_FUNC(users)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcCommandStatus status;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcChannelID *channel_id = NULL;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  unsigned char *tmp;
  unsigned int tmp_len, list_count;
  int i;
  unsigned char **res_argv = NULL;
  unsigned int *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK) {
    cmd->client->ops->say(cmd->client, conn,
	     "%s", silc_client_command_status_message(status));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp)
    goto out;
  channel_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!channel_id)
    goto out;

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
  if (!tmp)
    goto out;

  client_id_list = silc_buffer_alloc(tmp_len);
  silc_buffer_pull_tail(client_id_list, tmp_len);
  silc_buffer_put(client_id_list, tmp, tmp_len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &tmp_len);
  if (!tmp)
    goto out;

  client_mode_list = silc_buffer_alloc(tmp_len);
  silc_buffer_pull_tail(client_mode_list, tmp_len);
  silc_buffer_put(client_mode_list, tmp, tmp_len);

  /* Get channel entry */
  if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
                                   SILC_ID_CHANNEL, &id_cache)) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel = (SilcChannelEntry)id_cache->context;

  /* Remove old client list from channel. */
  silc_list_start(channel->clients);
  while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
    silc_list_del(channel->clients, chu);
    silc_free(chu);
  }

  /* Cache the received Client ID's and modes. This cache expires
     whenever server sends notify message to channel. It means two things;
     some user has joined or leaved the channel. XXX! */
  for (i = 0; i < list_count; i++) {
    unsigned short idp_len;
    unsigned int mode;
    SilcClientID *client_id;
    SilcClientEntry client;

    /* Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list->data, idp_len);
    if (!client_id)
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list->data);

    /* Check if we have this client cached already. */
    if (!silc_idcache_find_by_id_one(conn->client_cache, (void *)client_id,
				     SILC_ID_CLIENT, &id_cache)) {
      /* No we don't have it, query it from the server. Assemble argument
	 table that will be sent fr the IDENTIFY command later. */
      res_argv = silc_realloc(res_argv, sizeof(*res_argv) *
			      (res_argc + 1));
      res_argv_lens = silc_realloc(res_argv_lens, sizeof(*res_argv_lens) *
				   (res_argc + 1));
      res_argv_types = silc_realloc(res_argv_types, sizeof(*res_argv_types) *
				    (res_argc + 1));
      res_argv[res_argc] = client_id_list->data;
      res_argv_lens[res_argc] = idp_len;
      res_argv_types[res_argc] = res_argc + 3;
      res_argc++;
    } else {
      /* Found the client, join it to the channel */
      client = (SilcClientEntry)id_cache->context;
      chu = silc_calloc(1, sizeof(*chu));
      chu->client = client;
      chu->mode = mode;
      silc_list_add(channel->clients, chu);

      silc_free(client_id);
      id_cache = NULL;
    }

    silc_buffer_pull(client_id_list, idp_len);
    silc_buffer_pull(client_mode_list, 4);
  }

  /* Query the client information from server if the list included clients
     that we don't know about. */
  if (res_argc) {
    SilcBuffer res_cmd;

    /* Send the IDENTIFY command to server */
    res_cmd = silc_command_payload_encode(SILC_COMMAND_IDENTIFY,
					  res_argc, res_argv, res_argv_lens,
					  res_argv_types, ++conn->cmd_ident);
    silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, 
			    NULL, 0, NULL, NULL, res_cmd->data, res_cmd->len,
			    TRUE);

    /* Register pending command callback. After we've received the IDENTIFY
       command reply we will reprocess this command reply by re-calling this
       USERS command reply callback. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, conn->cmd_ident,
				NULL, silc_client_command_reply_users, cmd);

    silc_buffer_free(res_cmd);
    if (channel_id)
      silc_free(channel_id);

    silc_free(res_argv);
    silc_free(res_argv_lens);
    silc_free(res_argv_types);
    return;
  }

  /* Notify application */
  COMMAND_REPLY((ARGS, channel, list_count, client_id_list, client_mode_list));

  /* Execute any pending command callbacks */
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_USERS);

  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);

 out:
  if (channel_id)
    silc_free(channel_id);
  SILC_CLIENT_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_USERS);
  silc_client_command_reply_free(cmd);
}
