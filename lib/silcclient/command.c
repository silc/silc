/*

  command.c

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
/* $Id$ */

#include "clientlibincludes.h"
#include "client_internal.h"

/* Client command list. */
SilcClientCommand silc_command_list[] =
{
  SILC_CLIENT_CMD(whois, WHOIS, "WHOIS", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(whowas, WHOWAS, "WHOWAS", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(identify, IDENTIFY, "IDENTIFY", 
		  SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(nick, NICK, "NICK", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(list, LIST, "LIST", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(topic, TOPIC, "TOPIC", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(invite, INVITE, "INVITE", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(quit, QUIT, "QUIT", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(kill, KILL, "KILL", 
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 3),
  SILC_CLIENT_CMD(info, INFO, "INFO", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(connect, CONNECT, "CONNECT",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 3),
  SILC_CLIENT_CMD(ping, PING, "PING", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(oper, OPER, "OPER",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(join, JOIN, "JOIN", SILC_CF_LAG | SILC_CF_REG, 5),
  SILC_CLIENT_CMD(motd, MOTD, "MOTD", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(umode, UMODE, "UMODE", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(cmode, CMODE, "CMODE", SILC_CF_LAG | SILC_CF_REG, 4),
  SILC_CLIENT_CMD(cumode, CUMODE, "CUMODE", SILC_CF_LAG | SILC_CF_REG, 5),
  SILC_CLIENT_CMD(kick, KICK, "KICK", SILC_CF_LAG | SILC_CF_REG, 4),
  SILC_CLIENT_CMD(ban, BAN, "BAN", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(close, CLOSE, "CLOSE",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 3),
  SILC_CLIENT_CMD(shutdown, SHUTDOWN, "SHUTDOWN",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 1),
  SILC_CLIENT_CMD(silcoper, SILCOPER, "SILCOPER",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER, 3),
  SILC_CLIENT_CMD(leave, LEAVE, "LEAVE", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(users, USERS, "USERS", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(getkey, GETKEY, "GETKEY", SILC_CF_LAG | SILC_CF_REG, 2),

  { NULL, 0, NULL, 0, 0 },
};

#define SILC_NOT_CONNECTED(x, c) \
  x->ops->say((x), (c), SILC_CLIENT_MESSAGE_ERROR, \
	   "You are not connected to a server, use /SERVER to connect");

/* Command operation that is called at the end of all commands. 
   Usage: COMMAND; */
#define COMMAND cmd->client->ops->command(cmd->client, cmd->conn, \
  cmd, TRUE, cmd->command->cmd)

/* Error to application. Usage: COMMAND_ERROR; */
#define COMMAND_ERROR cmd->client->ops->command(cmd->client, cmd->conn, \
  cmd, FALSE, cmd->command->cmd)

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form and in correct order. */

void silc_client_send_command(SilcClient client, SilcClientConnection conn,
			      SilcCommand command, uint16 ident,
			      uint32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, ident, argc, ap);
  silc_client_packet_send(client, conn->sock, SILC_PACKET_COMMAND, 
			  NULL, 0, NULL, NULL, packet->data, 
			  packet->len, TRUE);
  silc_buffer_free(packet);
}

/* Finds and returns a pointer to the command list. Return NULL if the
   command is not found. */

SilcClientCommand *silc_client_command_find(const char *name)
{
  SilcClientCommand *cmd;

  for (cmd = silc_command_list; cmd->name; cmd++) {
    if (!strcmp(cmd->name, name))
      return cmd;
  }

  return NULL;
}

/* Add new pending command to be executed when reply to a command has been
   received.  The `reply_cmd' is the command that will call the `callback'
   with `context' when reply has been received.  If `ident is non-zero
   the `callback' will be executed when received reply with command 
   identifier `ident'. */

void silc_client_command_pending(SilcClientConnection conn,
				 SilcCommand reply_cmd,
				 uint16 ident,
				 SilcClientPendingDestructor destructor,
				 SilcCommandCb callback,
				 void *context)
{
  SilcClientCommandPending *reply;

  reply = silc_calloc(1, sizeof(*reply));
  reply->reply_cmd = reply_cmd;
  reply->ident = ident;
  reply->context = context;
  reply->callback = callback;
  reply->destructor = destructor;
  silc_dlist_add(conn->pending_commands, reply);
}

/* Deletes pending command by reply command type. */

void silc_client_command_pending_del(SilcClientConnection conn,
				     SilcCommand reply_cmd,
				     uint16 ident)
{
  SilcClientCommandPending *r;

  silc_dlist_start(conn->pending_commands);
  while ((r = silc_dlist_get(conn->pending_commands)) != SILC_LIST_END) {
    if (r->reply_cmd == reply_cmd && r->ident == ident) {
      silc_dlist_del(conn->pending_commands, r);
      break;
    }
  }
}

/* Checks for pending commands and marks callbacks to be called from
   the command reply function. Returns TRUE if there were pending command. */

int silc_client_command_pending_check(SilcClientConnection conn,
				      SilcClientCommandReplyContext ctx,
				      SilcCommand command, 
				      uint16 ident)
{
  SilcClientCommandPending *r;

  silc_dlist_start(conn->pending_commands);
  while ((r = silc_dlist_get(conn->pending_commands)) != SILC_LIST_END) {
    if (r->reply_cmd == command && r->ident == ident) {
      ctx->context = r->context;
      ctx->callback = r->callback;
      ctx->destructor = r->destructor;
      ctx->ident = ident;
      return TRUE;
    }
  }

  return FALSE;
}

/* Allocate Command Context */

SilcClientCommandContext silc_client_command_alloc()
{
  SilcClientCommandContext ctx = silc_calloc(1, sizeof(*ctx));
  ctx->users++;
  return ctx;
}

/* Free command context and its internals */

void silc_client_command_free(SilcClientCommandContext ctx)
{
  ctx->users--;
  SILC_LOG_DEBUG(("Command context %p refcnt %d->%d", ctx, ctx->users + 1,
		  ctx->users));
  if (ctx->users < 1) {
    int i;

    for (i = 0; i < ctx->argc; i++)
      silc_free(ctx->argv[i]);
    silc_free(ctx->argv_lens);
    silc_free(ctx->argv_types);
    silc_free(ctx);
  }
}

/* Duplicate Command Context by adding reference counter. The context won't
   be free'd untill it hits zero. */

SilcClientCommandContext silc_client_command_dup(SilcClientCommandContext ctx)
{
  ctx->users++;
  SILC_LOG_DEBUG(("Command context %p refcnt %d->%d", ctx, ctx->users - 1,
		  ctx->users));
  return ctx;
}

/* Pending command destructor. */

static void silc_client_command_destructor(void *context)
{
  silc_client_command_free((SilcClientCommandContext)context);
}

/* Command WHOIS. This command is used to query information about 
   specific user. */

SILC_CLIENT_CMD_FUNC(whois)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  /* Given without arguments fetches client's own information */
  if (cmd->argc < 2) {
    buffer = silc_id_payload_encode(cmd->conn->local_id, SILC_ID_CLIENT);
    silc_client_send_command(cmd->client, cmd->conn, SILC_COMMAND_WHOIS, 
			     ++conn->cmd_ident,
			     1, 3, buffer->data, buffer->len);
    silc_buffer_free(buffer);
    goto out;
  }

  buffer = silc_command_payload_encode(SILC_COMMAND_WHOIS,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types,
				       0);
  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command WHOWAS. This command is used to query history information about
   specific user that used to exist in the network. */

SILC_CLIENT_CMD_FUNC(whowas)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2 || cmd->argc > 3) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	     "Usage: /WHOWAS <nickname>[@<server>] [<count>]");
    COMMAND_ERROR;
    goto out;
  }

  buffer = silc_command_payload_encode(SILC_COMMAND_WHOWAS,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types,
				       0);
  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command IDENTIFY. This command is used to query information about 
   specific user, especially ID's. */

SILC_CLIENT_CMD_FUNC(identify)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2 || cmd->argc > 3) {
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc == 2)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_IDENTIFY, 
					    ++conn->cmd_ident, 1,
					    1, cmd->argv[1],
					    cmd->argv_lens[1]);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_IDENTIFY, 
					    ++conn->cmd_ident, 2,
					    1, cmd->argv[1],
					    cmd->argv_lens[1],
					    4, cmd->argv[2],
					    cmd->argv_lens[2]);

  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command NICK. Shows current nickname/sets new nickname on current
   window. */

SILC_CLIENT_CMD_FUNC(nick)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /NICK <nickname>");
    COMMAND_ERROR;
    goto out;
  }

  if (!strcmp(conn->nickname, cmd->argv[1]))
    goto out;

  /* Show current nickname */
  if (cmd->argc < 2) {
    if (cmd->conn) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "Your nickname is %s on server %s", 
			    conn->nickname, conn->remote_host);
    } else {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "Your nickname is %s", conn->nickname);
    }

    COMMAND;
    goto out;
  }

  /* Set new nickname */
  buffer = silc_command_payload_encode(SILC_COMMAND_NICK,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types,
				       ++cmd->conn->cmd_ident);
  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;
  if (conn->nickname)
    silc_free(conn->nickname);
  conn->nickname = strdup(cmd->argv[1]);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command LIST. Lists channels on the current server. */

SILC_CLIENT_CMD_FUNC(list)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp = NULL;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc == 2) {
    name = cmd->argv[1];

    /* Get the Channel ID of the channel */
    if (silc_idcache_find_by_name_one(conn->channel_cache, name, &id_cache)) {
      channel = (SilcChannelEntry)id_cache->context;
      idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
    }
  }

  if (!idp)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_LIST, 
					    ++conn->cmd_ident, 0);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_LIST, 
					    ++conn->cmd_ident, 1,
					    1, idp->data, idp->len);

  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  if (idp)
    silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command TOPIC. Sets/shows topic on a channel. */

SILC_CLIENT_CMD_FUNC(topic)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2 || cmd->argc > 3) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
			  "Usage: /TOPIC <channel> [<topic>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_name_one(conn->channel_cache, name, &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Send TOPIC command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  if (cmd->argc > 2)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_TOPIC, 
					    ++conn->cmd_ident, 2, 
					    1, idp->data, idp->len,
					    2, cmd->argv[2], 
					    strlen(cmd->argv[2]));
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_TOPIC, 
					    ++conn->cmd_ident, 1,
					    1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command INVITE. Invites specific client to join a channel. This is
   also used to mange the invite list of the channel. */

SILC_CLIENT_CMD_FUNC(invite)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, clidp, chidp;
  uint32 type = 0;
  char *nickname = NULL, *name;
  char *invite = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
		   "Usage: /INVITE <channel> [<nickname>[@server>]"
		   "[+|-[<nickname>[@<server>[!<username>[@hostname>]]]]]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are on that channel");
      COMMAND_ERROR;
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (cmd->argc == 3) {
    if (cmd->argv[2][0] != '+' && cmd->argv[2][0] != '-') {
      if (client->params->nickname_parse)
	client->params->nickname_parse(cmd->argv[2], &nickname);
      else
	nickname = strdup(cmd->argv[2]);

      /* Find client entry */
      client_entry = silc_idlist_get_client(client, conn, nickname, 
					    cmd->argv[2], TRUE);
      if (!client_entry) {
	if (cmd->pending) {
	  COMMAND_ERROR;
	  goto out;
	}
	silc_free(nickname);
      
	/* Client entry not found, it was requested thus mark this to be
	   pending command. */
	silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				    conn->cmd_ident,
				    silc_client_command_destructor,
				    silc_client_command_invite, 
				    silc_client_command_dup(cmd));
	cmd->pending = 1;
	return;
      }
    } else {
      invite = cmd->argv[2];
      invite++;
      if (cmd->argv[2][0] == '+')
	type = 3;
      else
	type = 4;
    }
  }

  /* Send the command */
  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  if (client_entry) {
    clidp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_INVITE, 
					    ++conn->cmd_ident, 3,
					    1, chidp->data, chidp->len,
					    2, clidp->data, clidp->len,
					    type, invite, invite ?
					    strlen(invite) : 0);
    silc_buffer_free(clidp);
  } else {
    buffer = silc_command_payload_encode_va(SILC_COMMAND_INVITE, 
					    ++conn->cmd_ident, 2,
					    1, chidp->data, chidp->len,
					    type, invite, invite ?
					    strlen(invite) : 0);
  }

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);

  /* Notify application */
  COMMAND;

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
} *QuitInternal;

SILC_TASK_CALLBACK(silc_client_command_quit_cb)
{
  QuitInternal q = (QuitInternal)context;

  /* Close connection */
  q->client->ops->disconnect(q->client, q->conn);
  silc_client_close_connection(q->client, NULL, q->conn->sock->user_data);

  silc_free(q);
}

/* Command QUIT. Closes connection with current server. */
 
SILC_CLIENT_CMD_FUNC(quit)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcBuffer buffer;
  QuitInternal q;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc > 1)
    buffer = silc_command_payload_encode(SILC_COMMAND_QUIT, cmd->argc - 1, 
					 &cmd->argv[1], &cmd->argv_lens[1],
					 &cmd->argv_types[1], 0);
  else
    buffer = silc_command_payload_encode(SILC_COMMAND_QUIT, 0,
					 NULL, NULL, NULL, 0);
  silc_client_packet_send(cmd->client, cmd->conn->sock, SILC_PACKET_COMMAND, 
			  NULL, 0, NULL, NULL, 
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  q = silc_calloc(1, sizeof(*q));
  q->client = cmd->client;
  q->conn = cmd->conn;

  /* We quit the connection with little timeout */
  silc_schedule_task_add(cmd->client->schedule, cmd->conn->sock->sock,
			 silc_client_command_quit_cb, (void *)q,
			 1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Timeout callback to remove the killed client from cache */

SILC_TASK_CALLBACK(silc_client_command_kill_remove_later)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcClientEntry target;
  char *nickname = NULL;
  
  /* Parse the typed nickname. */
  if (client->params->nickname_parse)
    client->params->nickname_parse(cmd->argv[1], &nickname);
  else
    nickname = strdup(cmd->argv[1]);

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname, 
				  cmd->argv[1], FALSE);
  if (target) {
    silc_client_remove_from_channels(client, conn, target);
    silc_client_del_client(client, conn, target);
  }

  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* Kill command's pending command callback to actually remove the killed
   client from our local cache. */

SILC_CLIENT_CMD_FUNC(kill_remove)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientCommandReplyContext reply = 
    (SilcClientCommandReplyContext)context2;
  SilcCommandStatus status;

  SILC_GET16_MSB(status, silc_argument_get_arg_type(reply->args, 1, NULL));
  if (status == SILC_STATUS_OK) {
    /* Remove with timeout */
    silc_schedule_task_add(cmd->client->schedule, cmd->conn->sock->sock,
			   silc_client_command_kill_remove_later, context,
			   1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  silc_client_command_free(cmd);
}

/* Command KILL. Router operator can use this command to remove an client
   fromthe SILC Network. */

SILC_CLIENT_CMD_FUNC(kill)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp;
  SilcClientEntry target;
  char *nickname = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /KILL <nickname> [<comment>]");
    COMMAND_ERROR;
    goto out;
  }

  /* Parse the typed nickname. */
  if (client->params->nickname_parse)
    client->params->nickname_parse(cmd->argv[1], &nickname);
  else
    nickname = strdup(cmd->argv[1]);

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname, 
				  cmd->argv[1], TRUE);
  if (!target) {
    if (cmd->pending) {
      COMMAND_ERROR;
      goto out;
    }

    silc_free(nickname);

    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				conn->cmd_ident,  
				silc_client_command_destructor,
				silc_client_command_kill, 
				silc_client_command_dup(cmd));
    cmd->pending = 1;
    return;
  }

  /* Send the KILL command to the server */
  idp = silc_id_payload_encode(target->id, SILC_ID_CLIENT);
  if (cmd->argc == 2)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_KILL, 
					    ++conn->cmd_ident, 1, 
					    1, idp->data, idp->len);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_KILL, 
					    ++conn->cmd_ident, 2, 
					    1, idp->data, idp->len,
					    2, cmd->argv[2], 
					    strlen(cmd->argv[2]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

  /* Register a pending callback that will actually remove the killed
     client from our cache. */
  silc_client_command_pending(conn, SILC_COMMAND_KILL, conn->cmd_ident,
			      NULL, silc_client_command_kill_remove,
			      silc_client_command_dup(cmd));

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* Command INFO. Request information about specific server. If specific
   server is not provided the current server is used. */

SILC_CLIENT_CMD_FUNC(info)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  char *name = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc == 2)
    name = strdup(cmd->argv[1]);

  /* Send the command */
  if (name)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_INFO, 0, 1, 
					    1, name, strlen(name));
  else
    buffer = silc_command_payload_encode(SILC_COMMAND_INFO, 0,
					 NULL, NULL, NULL, 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  if (name)
    silc_free(name);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command PING. Sends ping to server. This is used to test the 
   communication channel. */

SILC_CLIENT_CMD_FUNC(ping)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  void *id;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  /* Send the command */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_PING, 0, 1, 
					  1, conn->remote_id_data, 
					  silc_id_get_len(conn->remote_id,
							  SILC_ID_SERVER));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  id = silc_id_str2id(conn->remote_id_data, conn->remote_id_data_len,
		      SILC_ID_SERVER);
  if (!id) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  /* Start counting time */
  for (i = 0; i < conn->ping_count; i++) {
    if (conn->ping[i].dest_id == NULL) {
      conn->ping[i].start_time = time(NULL);
      conn->ping[i].dest_id = id;
      conn->ping[i].dest_name = strdup(conn->remote_host);
      conn->ping_count++;
      break;
    }
  }
  if (i >= conn->ping_count) {
    i = conn->ping_count;
    conn->ping = silc_realloc(conn->ping, sizeof(*conn->ping) * (i + 1));
    conn->ping[i].start_time = time(NULL);
    conn->ping[i].dest_id = id;
    conn->ping[i].dest_name = strdup(conn->remote_host);
    conn->ping_count++;
  }
  
  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command JOIN. Joins to a channel. */

SILC_CLIENT_CMD_FUNC(join)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcBuffer buffer, idp;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  /* See if we have joined to the requested channel already */
  if (silc_idcache_find_by_name_one(conn->channel_cache, cmd->argv[1],
				    &id_cache))
    goto out;

  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);

  /* Send JOIN command to the server */
  if (cmd->argc == 2)
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_JOIN, 0, 2,
				     1, cmd->argv[1], cmd->argv_lens[1],
				     2, idp->data, idp->len);
  else if (cmd->argc == 3)
    /* XXX Buggy */
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_JOIN, 0, 3,
				     1, cmd->argv[1], cmd->argv_lens[1],
				     2, idp->data, idp->len,
				     3, cmd->argv[2], cmd->argv_lens[2]);
  else
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_JOIN, 0, 4,
				     1, cmd->argv[1], cmd->argv_lens[1],
				     2, idp->data, idp->len,
				     3, cmd->argv[2], cmd->argv_lens[2],
				     4, cmd->argv[3], cmd->argv_lens[3]);

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* MOTD command. Requests motd from server. */

SILC_CLIENT_CMD_FUNC(motd)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 1 || cmd->argc > 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
			  "Usage: /MOTD [<server>]");
    COMMAND_ERROR;
    goto out;
  }

  /* Send TOPIC command to the server */
  if (cmd->argc == 1)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_MOTD, 0, 1, 
					    1, conn->remote_host, 
					    strlen(conn->remote_host));
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_MOTD, 0, 1, 
					    1, cmd->argv[1], 
					    cmd->argv_lens[1]);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* UMODE. Set/unset user mode in SILC. This is used mainly to unset the
   modes as client cannot set itself server/router operator privileges. */

SILC_CLIENT_CMD_FUNC(umode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp;
  unsigned char *cp, modebuf[4];
  uint32 mode, add, len;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       	  "Usage: /UMODE +|-<modes>");
    COMMAND_ERROR;
    goto out;
  }

  mode = conn->local_entry->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[1][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Parse mode */
  cp = cmd->argv[1] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'a':
      if (add) {
	mode = 0;
	mode |= SILC_UMODE_SERVER_OPERATOR;
	mode |= SILC_UMODE_ROUTER_OPERATOR;
      } else {
	mode = SILC_UMODE_NONE;
      }
      break;
    case 's':
      if (add)
	mode |= SILC_UMODE_SERVER_OPERATOR;
      else
	mode &= ~SILC_UMODE_SERVER_OPERATOR;
      break;
    case 'r':
      if (add)
	mode |= SILC_UMODE_ROUTER_OPERATOR;
      else
	mode &= ~SILC_UMODE_ROUTER_OPERATOR;
      break;
    case 'g':
      if (add)
	mode |= SILC_UMODE_GONE;
      else
	mode &= ~SILC_UMODE_GONE;
      break;
    default:
      COMMAND_ERROR;
      goto out;
      break;
    }
  }

  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);
  SILC_PUT32_MSB(mode, modebuf);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  buffer = 
    silc_command_payload_encode_va(SILC_COMMAND_UMODE, ++conn->cmd_ident, 2, 
				   1, idp->data, idp->len, 
				   2, modebuf, sizeof(modebuf));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* CMODE command. Sets channel mode. Modes that does not require any arguments
   can be set several at once. Those modes that require argument must be set
   separately (unless set with modes that does not require arguments). */

SILC_CLIENT_CMD_FUNC(cmode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, chidp, auth = NULL;
  unsigned char *name, *cp, modebuf[4], tmp[4], *arg = NULL;
  uint32 mode, add, type, len, arg_len = 0;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 3) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       	  "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are on that channel");
      COMMAND_ERROR;
      goto out;
    }
  }

  mode = channel->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[2][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Argument type to be sent to server */
  type = 0;

  /* Parse mode */
  cp = cmd->argv[2] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'p':
      if (add)
	mode |= SILC_CHANNEL_MODE_PRIVATE;
      else
	mode &= ~SILC_CHANNEL_MODE_PRIVATE;
      break;
    case 's':
      if (add)
	mode |= SILC_CHANNEL_MODE_SECRET;
      else
	mode &= ~SILC_CHANNEL_MODE_SECRET;
      break;
    case 'k':
      if (add)
	mode |= SILC_CHANNEL_MODE_PRIVKEY;
      else
	mode &= ~SILC_CHANNEL_MODE_PRIVKEY;
      break;
    case 'i':
      if (add)
	mode |= SILC_CHANNEL_MODE_INVITE;
      else
	mode &= ~SILC_CHANNEL_MODE_INVITE;
      break;
    case 't':
      if (add)
	mode |= SILC_CHANNEL_MODE_TOPIC;
      else
	mode &= ~SILC_CHANNEL_MODE_TOPIC;
      break;
    case 'l':
      if (add) {
	int ll;
	mode |= SILC_CHANNEL_MODE_ULIMIT;
	type = 3;
	if (cmd->argc < 4) {
	  cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR;
	  goto out;
	}
	ll = atoi(cmd->argv[3]);
	SILC_PUT32_MSB(ll, tmp);
	arg = tmp;
	arg_len = 4;
      } else {
	mode &= ~SILC_CHANNEL_MODE_ULIMIT;
      }
      break;
    case 'a':
      if (add) {
	mode |= SILC_CHANNEL_MODE_PASSPHRASE;
	type = 4;
	if (cmd->argc < 4) {
	  cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR;
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_PASSPHRASE;
      }
      break;
    case 'c':
      if (add) {
	mode |= SILC_CHANNEL_MODE_CIPHER;
	type = 5;
	if (cmd->argc < 4) {
	  cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR;
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_CIPHER;
      }
      break;
    case 'h':
      if (add) {
	mode |= SILC_CHANNEL_MODE_HMAC;
	type = 6;
	if (cmd->argc < 4) {
	  cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR;
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_HMAC;
      }
      break;
    case 'f':
      if (add) {
	mode |= SILC_CHANNEL_MODE_FOUNDER_AUTH;
	type = 7;

	if (cmd->argc < 4) {
	  cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR;
	  goto out;
	}

	if (!strcasecmp(cmd->argv[3], "-pubkey")) {
	  auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
						    cmd->client->private_key,
						    conn->hash,
						    conn->local_id,
						    SILC_ID_CLIENT);
	} else {
	  auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
					  cmd->argv[3], cmd->argv_lens[3]);
	}

	arg = auth->data;
	arg_len = auth->len;
      } else {
	mode &= ~SILC_CHANNEL_MODE_FOUNDER_AUTH;
      }
      break;
    default:
      COMMAND_ERROR;
      goto out;
      break;
    }
  }

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(mode, modebuf);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  if (type && arg) {
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_CMODE, 0, 3, 
				     1, chidp->data, chidp->len, 
				     2, modebuf, sizeof(modebuf),
				     type, arg, arg_len);
  } else {
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_CMODE, 0, 2, 
				     1, chidp->data, chidp->len, 
				     2, modebuf, sizeof(modebuf));
  }

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  if (auth)
    silc_buffer_free(auth);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* CUMODE command. Changes client's mode on a channel. */

SILC_CLIENT_CMD_FUNC(cumode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcClientEntry client_entry;
  SilcBuffer buffer, clidp, chidp, auth = NULL;
  unsigned char *name, *cp, modebuf[4];
  uint32 mode = 0, add, len;
  char *nickname = NULL;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 4) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
	       	  "Usage: /CUMODE <channel> +|-<modes> <nickname>[@<server>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are on that channel");
      COMMAND_ERROR;
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (client->params->nickname_parse)
    client->params->nickname_parse(cmd->argv[3], &nickname);
  else
    nickname = strdup(cmd->argv[3]);

  /* Find client entry */
  client_entry = silc_idlist_get_client(cmd->client, conn, nickname,
					cmd->argv[3], TRUE);
  if (!client_entry) {
    if (cmd->pending) {
      COMMAND_ERROR;
      goto out;
    }

    silc_free(nickname);

    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				conn->cmd_ident,  
				silc_client_command_destructor,
				silc_client_command_cumode, 
				silc_client_command_dup(cmd));
    cmd->pending = 1;
    return;
  }
  
  /* Get the current mode */
  while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
    if (chu->client == client_entry) {
      mode = chu->mode;
      break;
    }
  }

  /* Are we adding or removing mode */
  if (cmd->argv[2][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Parse mode */
  cp = cmd->argv[2] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'a':
      if (add) {
	mode |= SILC_CHANNEL_UMODE_CHANFO;
	mode |= SILC_CHANNEL_UMODE_CHANOP;
      } else {
	mode = SILC_CHANNEL_UMODE_NONE;
      }
      break;
    case 'f':
      if (add) {
	if (cmd->argc == 5) {
	  if (!strcasecmp(cmd->argv[4], "-pubkey")) {
	  auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
						    cmd->client->private_key,
						    conn->hash,
						    conn->local_id,
						    SILC_ID_CLIENT);
	  } else {
	    auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
					    cmd->argv[4], cmd->argv_lens[4]);
	  }
	}
	mode |= SILC_CHANNEL_UMODE_CHANFO;
      } else {
	mode &= ~SILC_CHANNEL_UMODE_CHANFO;
      }
      break;
    case 'o':
      if (add)
	mode |= SILC_CHANNEL_UMODE_CHANOP;
      else
	mode &= ~SILC_CHANNEL_UMODE_CHANOP;
      break;
    default:
      COMMAND_ERROR;
      goto out;
      break;
    }
  }

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(mode, modebuf);
  clidp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_CUMODE, 0, 4, 
					  1, chidp->data, chidp->len, 
					  2, modebuf, 4,
					  3, clidp->data, clidp->len,
					  4, auth ? auth->data : NULL, 
					  auth ? auth->len : 0);
  
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  silc_buffer_free(clidp);
  if (auth)
    silc_buffer_free(auth);
  
  /* Notify application */
  COMMAND;

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* KICK command. Kicks a client out of channel. */

SILC_CLIENT_CMD_FUNC(kick)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp, idp2;
  SilcClientEntry target;
  char *name;
  char *nickname = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 3) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /KICK <channel> <nickname> [<comment>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_name_one(conn->channel_cache, name, &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Parse the typed nickname. */
  if (client->params->nickname_parse)
    client->params->nickname_parse(cmd->argv[2], &nickname);
  else
    nickname = strdup(cmd->argv[2]);

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname, 
				  cmd->argv[2], FALSE);
  if (!target) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "No such client: %s",
			  cmd->argv[2]);
    COMMAND_ERROR;
    goto out;
  }

  /* Send KICK command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode(target->id, SILC_ID_CLIENT);
  if (cmd->argc == 3)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_KICK, 0, 2, 
					    1, idp->data, idp->len,
					    2, idp2->data, idp2->len);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_KICK, 0, 3, 
					    1, idp->data, idp->len,
					    2, idp2->data, idp2->len,
					    3, cmd->argv[3], 
					    strlen(cmd->argv[3]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);
  silc_buffer_free(idp2);

  /* Notify application */
  COMMAND;

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

static void silc_client_command_oper_send(unsigned char *data,
					  uint32 data_len, void *context)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, auth;

  if (cmd->argc >= 3) {
    /* Encode the public key authentication payload */
    auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
					      cmd->client->private_key,
					      conn->hash,
					      conn->local_id,
					      SILC_ID_CLIENT);
  } else {
    /* Encode the password authentication payload */
    auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
				    data, data_len);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_OPER, 0, 2, 
					  1, cmd->argv[1], 
					  strlen(cmd->argv[1]),
					  2, auth->data, auth->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);

  silc_buffer_free(buffer);
  silc_buffer_free(auth);

  /* Notify application */
  COMMAND;
}

/* OPER command. Used to obtain server operator privileges. */

SILC_CLIENT_CMD_FUNC(oper)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /OPER <username> [-pubkey]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 3) {
    /* Get passphrase */
    cmd->client->ops->ask_passphrase(cmd->client, conn,
				     silc_client_command_oper_send,
				     context);
    return;
  }

  silc_client_command_oper_send(NULL, 0, context);

 out:
  silc_client_command_free(cmd);
}

static void silc_client_command_silcoper_send(unsigned char *data,
					      uint32 data_len, void *context)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, auth;

  if (cmd->argc >= 3) {
    /* Encode the public key authentication payload */
    auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
					      cmd->client->private_key,
					      conn->hash,
					      conn->local_id,
					      SILC_ID_CLIENT);
  } else {
    /* Encode the password authentication payload */
    auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
				    data, data_len);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_SILCOPER, 0, 2, 
					  1, cmd->argv[1], 
					  strlen(cmd->argv[1]),
					  2, auth->data, auth->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);

  silc_buffer_free(buffer);
  silc_buffer_free(auth);

  /* Notify application */
  COMMAND;
}

/* SILCOPER command. Used to obtain router operator privileges. */

SILC_CLIENT_CMD_FUNC(silcoper)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /SILCOPER <username> [-pubkey]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 3) {
    /* Get passphrase */
    cmd->client->ops->ask_passphrase(cmd->client, conn,
				     silc_client_command_silcoper_send,
				     context);
    return;
  }

  silc_client_command_silcoper_send(NULL, 0, context);

 out:
  silc_client_command_free(cmd);
}

/* CONNECT command. Connects the server to another server. */

SILC_CLIENT_CMD_FUNC(connect)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  unsigned char port[4];
  uint32 tmp;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /CONNECT <server> [<port>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc == 3) {
    tmp = atoi(cmd->argv[2]);
    SILC_PUT32_MSB(tmp, port);
  }

  if (cmd->argc == 3)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_CONNECT, 0, 2, 
					    1, cmd->argv[1], 
					    strlen(cmd->argv[1]),
					    2, port, 4);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_CONNECT, 0, 1,
					    1, cmd->argv[1], 
					    strlen(cmd->argv[1]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command BAN. This is used to manage the ban list of the channel. */

SILC_CLIENT_CMD_FUNC(ban)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, chidp;
  int type = 0;
  char *name, *ban = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
		   "Usage: /BAN <channel> "
		   "[+|-[<nickname>[@<server>[!<username>[@hostname>]]]]]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are on that channel");
      COMMAND_ERROR;
      goto out;
    }
  }

  if (cmd->argc == 3) {
    if (cmd->argv[2][0] == '+')
      type = 2;
    else
      type = 3;

    ban = cmd->argv[2];
    ban++;
  }

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);

  /* Send the command */
  if (ban)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_BAN, 0, 2, 
					    1, chidp->data, chidp->len,
					    type, ban, strlen(ban));
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_BAN, 0, 1, 
					    1, chidp->data, chidp->len);

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* CLOSE command. Close server connection to the remote server */
 
SILC_CLIENT_CMD_FUNC(close)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  unsigned char port[4];
  uint32 tmp;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /CLOSE <server> [<port>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc == 3) {
    tmp = atoi(cmd->argv[2]);
    SILC_PUT32_MSB(tmp, port);
  }

  if (cmd->argc == 3)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_CLOSE, 0, 2, 
					    1, cmd->argv[1], 
					    strlen(cmd->argv[1]),
					    2, port, 4);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_CLOSE, 0, 1,
					    1, cmd->argv[1], 
					    strlen(cmd->argv[1]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}
 
/* SHUTDOWN command. Shutdowns the server. */

SILC_CLIENT_CMD_FUNC(shutdown)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  /* Send the command */
  silc_client_send_command(cmd->client, cmd->conn, 
			   SILC_COMMAND_SHUTDOWN, 0, 0);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* LEAVE command. Leaves a channel. Client removes itself from a channel. */

SILC_CLIENT_CMD_FUNC(leave)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc != 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /LEAVE <channel>");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_name_one(conn->channel_cache, name, &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Send LEAVE command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_LEAVE, 0, 1, 
					  1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

  if (conn->current_channel == channel)
    conn->current_channel = NULL;

  silc_client_del_channel(cmd->client, cmd->conn, channel);

 out:
  silc_client_command_free(cmd);
}

/* Command USERS. Requests the USERS of the clients joined on requested
   channel. */

SILC_CLIENT_CMD_FUNC(users)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc != 2) {
    cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			  "Usage: /USERS <channel>");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, 
			    "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  /* Send USERS command to the server */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_USERS, 
					  ++conn->cmd_ident, 1, 
					  2, name, strlen(name));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, 
			  NULL, 0, NULL, NULL, buffer->data, 
			  buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command GETKEY. Used to fetch remote client's public key. */

SILC_CLIENT_CMD_FUNC(getkey)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientEntry client_entry = NULL;
  SilcServerEntry server_entry = NULL;
  char *nickname = NULL;
  SilcBuffer idp, buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 2) {
    client->ops->say(client, conn, SILC_CLIENT_MESSAGE_INFO, 
		     "Usage: /GETKEY <nickname or server name>");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->pending) {
    SilcClientCommandReplyContext reply = 
      (SilcClientCommandReplyContext)context2;
    SilcCommandStatus status;
    unsigned char *tmp = silc_argument_get_arg_type(reply->args, 1, NULL);
    SILC_GET16_MSB(status, tmp);
    
    if (status == SILC_STATUS_ERR_NO_SUCH_NICK ||
	status == SILC_STATUS_ERR_NO_SUCH_SERVER) {
      cmd->client->ops->say(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
			    "%s", 
			    silc_client_command_status_message(status));
      COMMAND_ERROR;
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (client->params->nickname_parse)
    client->params->nickname_parse(cmd->argv[1], &nickname);
  else
    nickname = strdup(cmd->argv[1]);

  /* Find client entry */
  client_entry = silc_idlist_get_client(client, conn, nickname, cmd->argv[1],
					FALSE);
  if (!client_entry) {
    /* Check whether user requested server actually */
    server_entry = silc_client_get_server(client, conn, cmd->argv[1]);

    if (!server_entry && !cmd->pending) {
      /* No. what ever user wants we don't have it, so resolve it. We
	 will try to resolve both client and server, one of them is
	 bound to be wrong. */

      /* This will send the IDENTIFY command */
      silc_idlist_get_client(client, conn, nickname, cmd->argv[1], TRUE);
      silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				  conn->cmd_ident,  
				  silc_client_command_destructor,
				  silc_client_command_getkey, 
				  silc_client_command_dup(cmd));

      /* This sends the IDENTIFY command to resolve the server. */
      silc_client_send_command(client, conn, SILC_COMMAND_IDENTIFY,
			       ++conn->cmd_ident, 1, 
			       2, cmd->argv[1], cmd->argv_lens[1]);
      silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				  conn->cmd_ident, NULL,
				  silc_client_command_getkey, 
				  silc_client_command_dup(cmd));

      cmd->pending = 1;
      silc_free(nickname);
      return;
    }

    idp = silc_id_payload_encode(server_entry->server_id, SILC_ID_SERVER);
  } else {
    idp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_GETKEY, 0, 1, 
					  1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}
