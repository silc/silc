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
  SILC_CLIENT_CMD(quit, QUIT, "QUIT", SILC_CF_LAG | SILC_CF_REG, 1),
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
  SILC_CLIENT_CMD(kick, KICK, "KICK", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(restart, RESTART, "RESTART",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(close, CLOSE, "CLOSE",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(die, DIE, "DIE",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER, 2),
  SILC_CLIENT_CMD(silcoper, SILCOPER, "SILOPER",
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER, 2),
  SILC_CLIENT_CMD(leave, LEAVE, "LEAVE", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(names, NAMES, "NAMES", SILC_CF_LAG | SILC_CF_REG, 2),

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

/* List of pending commands. */
SilcClientCommandPending *silc_command_pending = NULL;

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form in correct order. */

void silc_client_send_command(SilcClient client, SilcClientConnection conn,
			      SilcCommand command, unsigned int argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, 0, argc, ap);
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

/* Add new pending command to the list of pending commands. Currently
   pending commands are executed from command replies, thus we can
   execute any command after receiving some specific command reply.

   The argument `reply_cmd' is the command reply from where the callback
   function is to be called, thus, it IS NOT the command to be executed.

   XXX: If needed in the future this support may be extended for
   commands as well, when any command could be executed after executing
   some specific command. */

void silc_client_command_pending(SilcCommand reply_cmd,
				 SilcClientCommandCallback callback,
				 void *context)
{
  SilcClientCommandPending *reply, *r;

  reply = silc_calloc(1, sizeof(*reply));
  reply->reply_cmd = reply_cmd;
  reply->context = context;
  reply->callback = callback;

  if (silc_command_pending == NULL) {
    silc_command_pending = reply;
    return;
  }

  for (r = silc_command_pending; r; r = r->next) {
    if (r->next == NULL) {
      r->next = reply;
      break;
    }
  }
}

/* Deletes pending command by reply command type. */

void silc_client_command_pending_del(SilcCommand reply_cmd)
{
  SilcClientCommandPending *r, *tmp;
  
  if (silc_command_pending) {
    if (silc_command_pending->reply_cmd == reply_cmd) {
      silc_free(silc_command_pending);
      silc_command_pending = NULL;
      return;
    }

    for (r = silc_command_pending; r; r = r->next) {
      if (r->next && r->next->reply_cmd == reply_cmd) {
	tmp = r->next;
	r->next = r->next->next;
	silc_free(tmp);
	break;
      }
    }
  }
}

/* Free command context and its internals */

void silc_client_command_free(SilcClientCommandContext cmd)
{
  int i;

  if (cmd) {
    for (i = 0; i < cmd->argc; i++)
      silc_free(cmd->argv[i]);
    silc_free(cmd);
  }
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
  client_entry = silc_idlist_get_client(client, conn, nickname, server, num);
  if (!client_entry) {
    if (nickname)
      silc_free(nickname);
    if (server)
      silc_free(server);

    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(SILC_COMMAND_IDENTIFY, 
				silc_client_command_invite, context);
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

/* Command QUIT. Closes connection with current server. */
 
SILC_CLIENT_CMD_FUNC(quit)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  buffer = silc_command_payload_encode(SILC_COMMAND_QUIT, cmd->argc - 1, 
				       ++cmd->argv, ++cmd->argv_lens,
				       ++cmd->argv_types, 0);
  silc_client_packet_send(cmd->client, cmd->conn->sock, SILC_PACKET_COMMAND, 
			  NULL, 0, NULL, NULL, 
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

  /* Close connection */
  silc_client_close_connection(cmd->client, cmd->conn->sock);
  cmd->client->ops->disconnect(cmd->client, cmd->conn);

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

  id = silc_id_str2id(conn->remote_id_data, SILC_ID_SERVER);

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
  SilcBuffer buffer;

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

  /* Send JOIN command to the server */
  if (cmd->argc == 2)
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_JOIN, 0, 1,
				     1, cmd->argv[1], cmd->argv_lens[1]);
  else if (cmd->argc == 3)
    /* XXX Buggy */
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_JOIN, 0, 2,
				     1, cmd->argv[1], cmd->argv_lens[1],
				     2, cmd->argv[2], cmd->argv_lens[2]);
  else
    buffer = 
      silc_command_payload_encode_va(SILC_COMMAND_JOIN, 0, 3,
				     1, cmd->argv[1], cmd->argv_lens[1],
				     2, cmd->argv[2], cmd->argv_lens[2],
				     3, cmd->argv[3], cmd->argv_lens[3]);

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

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
					nickname, server, num);
  if (!client_entry) {
    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(SILC_COMMAND_CUMODE, 
				silc_client_command_cumode, context);
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

}

SILC_CLIENT_CMD_FUNC(restart)
{
}
 
SILC_CLIENT_CMD_FUNC(close)
{
}
 
SILC_CLIENT_CMD_FUNC(die)
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

/* Command NAMES. Requests the names of the clients joined on requested
   channel. */

SILC_CLIENT_CMD_FUNC(names)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcBuffer buffer, idp;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR;
    goto out;
  }

  if (cmd->argc != 2) {
    cmd->client->ops->say(cmd->client, conn, "Usage: /NAMES <channel>");
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

  /* Send NAMES command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_NAMES, 0, 1, 
					  1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Register dummy pending command that will tell the reply command
     that user called this command. Server may send reply to this command
     even if user did not send this command thus we want to handle things
     differently when user sent the command. This is dummy and won't be
     executed. */
  /* XXX this is kludge and should be removed after pending command reply 
     support is added. Currently only commands may be pending not command
     replies. */
  silc_client_command_pending(SILC_COMMAND_NAMES, 
			      silc_client_command_names, NULL);

  /* Notify application */
  COMMAND;

 out:
  silc_client_command_free(cmd);
}
