/*

  command.c

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
/* $Id$ */

#include "clientlibincludes.h"

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
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(info, INFO, "INFO", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(connect, CONNECT, "CONNECT",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(ping, PING, "PING", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(oper, OPER, "OPER",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(join, JOIN, "JOIN", SILC_CF_LAG | SILC_CF_REG, 4),
  SILC_CLIENT_CMD(motd, MOTD, "MOTD", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(umode, UMODE, "UMODE", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(cmode, CMODE, "CMODE", SILC_CF_LAG | SILC_CF_REG, 4),
  SILC_CLIENT_CMD(cumode, CUMODE, "CUMODE", SILC_CF_LAG | SILC_CF_REG, 5),
  SILC_CLIENT_CMD(kick, KICK, "KICK", SILC_CF_LAG | SILC_CF_REG, 4),
  SILC_CLIENT_CMD(restart, RESTART, "RESTART",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(close, CLOSE, "CLOSE",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(shutdown, SHUTDOWN, "SHUTDOWN",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(silcoper, SILCOPER, "SILOPER",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER, 2),
  SILC_CLIENT_CMD(leave, LEAVE, "LEAVE", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(users, USERS, "USERS", SILC_CF_LAG | SILC_CF_REG, 2),

  { NULL, 0, NULL, 0, 0 },
};

#define SILC_NOT_CONNECTED(x, c) \
  x->ops->say((x), (c), \
	   "You are not connected to a server, use /SERVER to connect");

/* Command operation that is called at the end of all commands. 
   Usage: COMMAND; */
#define COMMAND cmd->client->ops->command(cmd->client, cmd->conn, \
  cmd, TRUE, cmd->command->cmd)

/* Error to application. Usage: COMMAND_ERROR; */
#define COMMAND_ERROR cmd->client->ops->command(cmd->client, cmd->conn, \
  cmd, FALSE, cmd->command->cmd)

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form in correct order. */

void silc_client_send_command(SilcClient client, SilcClientConnection conn,
			      SilcCommand command, unsigned short ident,
			      unsigned int argc, ...)
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
				 unsigned short ident,
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
				     unsigned short ident)
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
				      unsigned short ident)
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
    silc_free(ctx);
  }
}

/* Duplicate Command Context by adding reference counter. The context won't
   be free'd untill it hits zero. */

SilcClientCommandContext 
silc_client_command_dup(SilcClientCommandContext ctx)
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

  if (cmd->argc < 2 || cmd->argc > 3) {
    cmd->client->ops->say(cmd->client, conn, 
	     "Usage: /WHOIS <nickname>[@<server>] [<count>]");
    COMMAND_ERROR;
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

SILC_CLIENT_CMD_FUNC(whowas)
{
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
    cmd->client->ops->say(cmd->client, conn,
	     "Usage: /IDENTIFY <nickname>[@<server>] [<count>]");
    COMMAND_ERROR;
    goto out;
  }

  buffer = silc_command_payload_encode(SILC_COMMAND_IDENTIFY,
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

  if (!strcmp(conn->nickname, cmd->argv[1]))
    goto out;

  /* Show current nickname */
  if (cmd->argc < 2) {
    if (cmd->conn) {
      cmd->client->ops->say(cmd->client, conn, 
			    "Your nickname is %s on server %s", 
			    conn->nickname, conn->remote_host);
    } else {
      cmd->client->ops->say(cmd->client, conn, 
			    "Your nickname is %s", conn->nickname);
    }

    /* XXX Notify application */
    COMMAND;
    goto out;
  }

  /* Set new nickname */
  buffer = silc_command_payload_encode(SILC_COMMAND_NICK,
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
  if (conn->nickname)
    silc_free(conn->nickname);
  conn->nickname = strdup(cmd->argv[1]);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(list)
{
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
    cmd->client->ops->say(cmd->client, conn,
			  "Usage: /TOPIC <channel> [<topic>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_data_one(conn->channel_cache, name, &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Send TOPIC command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  if (cmd->argc > 2)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_TOPIC, 0, 2, 
					    1, idp->data, idp->len,
					    2, cmd->argv[2], 
					    strlen(cmd->argv[2]));
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_TOPIC, 1, 
					    1, idp->data, idp->len,
					    0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command INVITE. Invites specific client to join a channel. */

SILC_CLIENT_CMD_FUNC(invite)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcClientEntry client_entry;
  SilcChannelEntry channel_entry;
  SilcBuffer buffer, clidp, chidp;
  unsigned int num = 0;
  char *nickname = NULL, *server = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc != 3) {
    cmd->client->ops->say(cmd->client, conn,
			  "Usage: /INVITE <nickname>[@<server>] <channel>");
    COMMAND_ERROR;
    goto out;
  }

  /* Parse the typed nickname. */
  if (!silc_parse_nickname(cmd->argv[1], &nickname, &server, &num)) {
    cmd->client->ops->say(cmd->client, conn, "Bad nickname");
    COMMAND_ERROR;
    goto out;
  }

  /* Find client entry */
  client_entry = silc_idlist_get_client(client, conn, nickname, server, num,
					TRUE);
  if (!client_entry) {
    if (nickname)
      silc_free(nickname);
    if (server)
      silc_free(server);

    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 0,
				silc_client_command_destructor,
				silc_client_command_invite, 
				silc_client_command_dup(cmd));
    cmd->pending = 1;
    return;
  }

  /* Find channel entry */
  channel_entry = silc_idlist_get_channel(client, conn, cmd->argv[2]);
  if (!channel_entry) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Send command */
  clidp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);
  chidp = silc_id_payload_encode(channel_entry->id, SILC_ID_CHANNEL);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_INVITE, 0, 2,
					  1, clidp->data, clidp->len,
					  2, chidp->data, chidp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(clidp);
  silc_buffer_free(chidp);

  cmd->client->ops->say(cmd->client, conn, 
			"Inviting %s to channel %s", cmd->argv[1], 
			cmd->argv[2]);

  /* Notify application */
  COMMAND;

 out:
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
  silc_client_close_connection(q->client, q->conn->sock);

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
  silc_task_register(cmd->client->timeout_queue, cmd->conn->sock->sock,
		     silc_client_command_quit_cb, (void *)q,
		     1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(kill)
{
}

/* Command INFO. Request information about specific server. If specific
   server is not provided the current server is used. */

SILC_CLIENT_CMD_FUNC(info)
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

  if (cmd->argc < 2)
    name = strdup(conn->remote_host);
  else
    name = strdup(cmd->argv[1]);

  /* Send the command */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_INFO, 0, 1, 
					  1, name, strlen(name));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(connect)
{
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
  char *name = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc == 1 || !strcmp(cmd->argv[1], conn->remote_host))
    name = strdup(conn->remote_host);

  /* Send the command */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_PING, 0, 1, 
					  1, conn->remote_id_data, 
					  SILC_ID_SERVER_LEN);
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
      conn->ping[i].dest_name = name;
      conn->ping_count++;
      break;
    }
  }
  if (i >= conn->ping_count) {
    i = conn->ping_count;
    conn->ping = silc_realloc(conn->ping, sizeof(*conn->ping) * (i + 1));
    conn->ping[i].start_time = time(NULL);
    conn->ping[i].dest_id = id;
    conn->ping[i].dest_name = name;
    conn->ping_count++;
  }
  
  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(oper)
{
}

SILC_CLIENT_CMD_FUNC(trace)
{
}

SILC_CLIENT_CMD_FUNC(notice)
{
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

  if (cmd->argc < 2) {
    /* Show channels currently joined to */

    goto out;
  }

  /* See if we have joined to the requested channel already */
  if (silc_idcache_find_by_data_one(conn->channel_cache, cmd->argv[1],
				    &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, 
			  "You are talking to channel %s", cmd->argv[1]);
    conn->current_channel = (SilcChannelEntry)id_cache->context;
#if 0
    cmd->client->screen->bottom_line->channel = cmd->argv[1];
    silc_screen_print_bottom_line(cmd->client->screen, 0);
#endif
    goto out;
  }

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

  if (cmd->argc < 1 || cmd->argc > 1) {
    cmd->client->ops->say(cmd->client, conn,
			  "Usage: /MOTD");
    COMMAND_ERROR;
    goto out;
  }

  /* Send TOPIC command to the server */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_MOTD, 0, 1, 
					  2, conn->remote_host, 
					  strlen(conn->remote_host));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* UMODE. Set user mode in SILC. */

SILC_CLIENT_CMD_FUNC(umode)
{

}

/* CMODE command. Sets channel mode. Modes that does not require any arguments
   can be set several at once. Those modes that require argument must be set
   separately (unless set with modes that does not require arguments). */

SILC_CLIENT_CMD_FUNC(cmode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, chidp;
  unsigned char *name, *cp, modebuf[4], tmp[4], *arg = NULL;
  unsigned int mode, add, type, len, arg_len = 0;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 3) {
    cmd->client->ops->say(cmd->client, conn, 
	       	  "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_idlist_get_channel(cmd->client, conn, name);
    if (!channel) {
      cmd->client->ops->say(cmd->client, conn, "You are on that channel");
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
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_PASSPHRASE;
      }
      break;
    case 'b':
      if (add) {
	mode |= SILC_CHANNEL_MODE_BAN;
	type = 5;
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_BAN;
      }
      break;
    case 'I':
      if (add) {
	mode |= SILC_CHANNEL_MODE_INVITE_LIST;
	type = 6;
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_INVITE_LIST;
      }
      break;
    case 'c':
      if (add) {
	mode |= SILC_CHANNEL_MODE_CIPHER;
	type = 8;
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_CIPHER;
      }
      break;
    default:
      COMMAND_ERROR;
      goto out;
      break;
    }
  }

  if (type && cmd->argc < 3) {
    COMMAND_ERROR;
    goto out;
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

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* CUMODE command. Changes client's mode on a channel. */

SILC_CLIENT_CMD_FUNC(cumode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcClientEntry client_entry;
  SilcBuffer buffer, clidp, chidp;
  unsigned char *name, *cp, modebuf[4];
  unsigned int mode = 0, add, len;
  char *nickname = NULL, *server = NULL;
  unsigned int num = 0;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 4) {
    cmd->client->ops->say(cmd->client, conn, 
	       	  "Usage: /CUMODE <channel> +|-<modes> <nickname>[@<server>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_idlist_get_channel(cmd->client, conn, name);
    if (!channel) {
      cmd->client->ops->say(cmd->client, conn, "You are on that channel");
      COMMAND_ERROR;
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (!silc_parse_nickname(cmd->argv[3], &nickname, &server, &num)) {
    cmd->client->ops->say(cmd->client, conn, "Bad nickname");
    COMMAND_ERROR;
    goto out;
  }

  /* Find client entry */
  client_entry = silc_idlist_get_client(cmd->client, conn, 
					nickname, server, num, TRUE);
  if (!client_entry) {
    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_CUMODE, 0,  
				silc_client_command_destructor,
				silc_client_command_cumode, 
				silc_client_command_dup(cmd));
    cmd->pending = 1;
    return;
  }
  
  while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
    if (chu->client == client_entry) {
      chu->mode = mode;
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
      if (add)
	mode |= SILC_CHANNEL_UMODE_CHANFO;
      else
	mode &= ~SILC_CHANNEL_UMODE_CHANFO;
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
  buffer = silc_command_payload_encode_va(SILC_COMMAND_CUMODE, 0, 3, 
					  1, chidp->data, chidp->len, 
					  2, modebuf, 4,
					  3, clidp->data, clidp->len);

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  silc_buffer_free(clidp);
  
  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* KICK command. Kicks a client out of channel. */

SILC_CLIENT_CMD_FUNC(kick)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp, idp2;
  SilcClientEntry target;
  char *name;
  unsigned int num = 0;
  char *nickname = NULL, *server = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc < 3) {
    cmd->client->ops->say(cmd->client, conn, 
			  "Usage: /KICK <channel> <client> [<comment>]");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_data_one(conn->channel_cache, name, &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Parse the typed nickname. */
  if (!silc_parse_nickname(cmd->argv[2], &nickname, &server, &num)) {
    cmd->client->ops->say(cmd->client, conn, "Bad nickname");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname, 
				  server, num, FALSE);
  if (!target) {
    cmd->client->ops->say(cmd->client, conn, "No such client: %s",
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
  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(restart)
{
}
 
SILC_CLIENT_CMD_FUNC(close)
{
}
 
SILC_CLIENT_CMD_FUNC(shutdown)
{
}
 
SILC_CLIENT_CMD_FUNC(silcoper)
{
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
    cmd->client->ops->say(cmd->client, conn, "Usage: /LEAVE <channel>");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_data_one(conn->channel_cache, name, &id_cache)) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
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

  /* We won't talk anymore on this channel */
  cmd->client->ops->say(cmd->client, conn, "You have left channel %s", name);

  conn->current_channel = NULL;

  silc_idcache_del_by_id(conn->channel_cache, SILC_ID_CHANNEL, channel->id);
  silc_free(channel->channel_name);
  silc_free(channel->id);
  silc_free(channel->key);
  silc_cipher_free(channel->channel_key);
  silc_free(channel);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}

/* Command USERS. Requests the USERS of the clients joined on requested
   channel. */

SILC_CLIENT_CMD_FUNC(users)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp;
  char *name, *line = NULL;
  unsigned int line_len = 0;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc != 2) {
    cmd->client->ops->say(cmd->client, conn, "Usage: /USERS <channel>");
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      COMMAND_ERROR;
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    cmd->client->ops->say(cmd->client, conn, "You are not on that channel");
    COMMAND_ERROR;
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_data_one(conn->channel_cache, name, &id_cache)) {
    /* XXX should resolve the channel ID; LIST command */
    cmd->client->ops->say(cmd->client, conn, 
			  "You are not on that channel", name);
    COMMAND_ERROR;
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  if (!cmd->pending) {
    /* Send USERS command to the server */
    idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_USERS, 0, 1, 
					    1, idp->data, idp->len);
    silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, 
			    NULL, 0, NULL, NULL, buffer->data, 
			    buffer->len, TRUE);
    silc_buffer_free(buffer);
    silc_buffer_free(idp);

    /* Register pending callback which will recall this command callback with
       same context and reprocesses the command. When reprocessing we actually
       display the information on the screen. */
    silc_client_command_pending(conn, SILC_COMMAND_USERS, 0, 
				silc_client_command_destructor,
				silc_client_command_users, 
				silc_client_command_dup(cmd));
    cmd->pending = TRUE;
    return;
  }

  if (cmd->pending) {
    /* Pending command. Now we've resolved the information from server and
       we are ready to display the information on screen. */
    int i;
    SilcChannelUser chu;

    cmd->client->ops->say(cmd->client, conn, "Users on %s", 
			  channel->channel_name);

    line = silc_calloc(4096, sizeof(*line));
    line_len = 4096;
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      SilcClientEntry e = chu->client;
      char *m, tmp[80], len1;

      memset(line, 0, sizeof(line_len));

      if (strlen(e->nickname) + strlen(e->server) + 100 > line_len) {
	silc_free(line);
	line_len += strlen(e->nickname) + strlen(e->server) + 100;
	line = silc_calloc(line_len, sizeof(*line));
      }

      memset(tmp, 0, sizeof(tmp));
      m = silc_client_chumode_char(chu->mode);

      strncat(line, " ", 1);
      strncat(line, e->nickname, strlen(e->nickname));
      strncat(line, e->server ? "@" : "", 1);

      len1 = 0;
      if (e->server)
	len1 = strlen(e->server);
      strncat(line, e->server ? e->server : "", len1 > 30 ? 30 : len1);

      len1 = strlen(line);
      if (len1 >= 30) {
	memset(&line[29], 0, len1 - 29);
      } else {
	for (i = 0; i < 30 - len1 - 1; i++)
	  strcat(line, " ");
      }

      strncat(line, "  H", 3);
      strcat(tmp, m ? m : "");
      strncat(line, tmp, strlen(tmp));

      if (strlen(tmp) < 5)
	for (i = 0; i < 5 - strlen(tmp); i++)
	  strcat(line, " ");

      strcat(line, e->username ? e->username : "");

      cmd->client->ops->say(cmd->client, conn, "%s", line);

      if (m)
	silc_free(m);
    }
  }

  if (line)
    silc_free(line);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}
