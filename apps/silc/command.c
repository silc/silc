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
/*
 * $Id$
 * $Log$
 * Revision 1.8  2000/07/10 05:39:11  priikone
 * 	Added INFO and VERSION commands. Minor changes to SERVER command
 * 	to show current servers when giving without arguments.
 *
 * Revision 1.7  2000/07/07 06:54:44  priikone
 * 	Fixed channel joining bug, do not allow joining twice on the
 * 	same channel.
 *
 * Revision 1.6  2000/07/06 07:14:36  priikone
 * 	Fixes to NAMES command handling.
 * 	Fixes when leaving from channel.
 *
 * Revision 1.5  2000/07/05 06:12:05  priikone
 * 	Global cosmetic changes.
 *
 * Revision 1.4  2000/07/04 08:28:03  priikone
 * 	Added INVITE, PING and NAMES command.
 *
 * Revision 1.3  2000/07/03 05:49:49  priikone
 * 	Implemented LEAVE command.  Minor bug fixes.
 *
 * Revision 1.2  2000/06/27 19:38:40  priikone
 * 	Added missing goto flag.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "clientincludes.h"

/* Client command list. */
SilcClientCommand silc_command_list[] =
{
  SILC_CLIENT_CMD(whois, WHOIS, "WHOIS", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(whowas, WHOWAS, "WHOWAS", SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(identify, IDENTIFY, "IDENTIFY", 
		  SILC_CF_LAG | SILC_CF_REG, 3),
  SILC_CLIENT_CMD(nick, NICK, "NICK", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(list, LIST, "LIST", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(topic, TOPIC, "TOPIC", SILC_CF_LAG | SILC_CF_REG, 2),
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
  SILC_CLIENT_CMD(join, JOIN, "JOIN", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(motd, MOTD, "MOTD", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(umode, UMODE, "UMODE", SILC_CF_LAG | SILC_CF_REG, 2),
  SILC_CLIENT_CMD(cmode, CMODE, "CMODE", SILC_CF_LAG | SILC_CF_REG, 2),
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

  /*
   * Local. Client specific commands
   */
  SILC_CLIENT_CMD(help, HELP, "HELP", SILC_CF_NONE, 2),
  SILC_CLIENT_CMD(clear, CLEAR, "CLEAR", SILC_CF_NONE, 1),
  SILC_CLIENT_CMD(version, VERSION, "VERSION", SILC_CF_NONE, 1),
  SILC_CLIENT_CMD(server, SERVER, "SERVER", SILC_CF_NONE, 2),
  SILC_CLIENT_CMD(msg, MSG, "MSG", SILC_CF_NONE, 3),
  SILC_CLIENT_CMD(away, AWAY, "AWAY", SILC_CF_NONE, 2),

  { NULL, 0, NULL, 0},
};

#define SILC_NOT_CONNECTED(x) \
  silc_say((x), "You are not connected to a server, use /SERVER to connect");

/* List of pending commands. */
SilcClientCommandPending *silc_command_pending = NULL;

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

static void silc_client_command_free(SilcClientCommandContext cmd)
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
  SilcBuffer buffer;

  if (cmd->argc < 2 || cmd->argc > 3) {
    silc_say(cmd->client, "Usage: /WHOIS <nickname>[@<server>] [<count>]");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  buffer = silc_command_encode_payload(SILC_COMMAND_WHOIS,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types);
  silc_client_packet_send(cmd->client, cmd->client->current_win->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

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
  SilcBuffer buffer;

  if (cmd->argc < 2 || cmd->argc > 3) {
    silc_say(cmd->client, "Usage: /IDENTIFY <nickname>[@<server>] [<count>]");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  buffer = silc_command_encode_payload(SILC_COMMAND_IDENTIFY,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types);
  silc_client_packet_send(cmd->client, cmd->client->current_win->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

 out:
  silc_client_command_free(cmd);
}

/* Command NICK. Shows current nickname/sets new nickname on current
   window. */

SILC_CLIENT_CMD_FUNC(nick)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientWindow win = NULL;
  SilcBuffer buffer;

  if (!cmd->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  /* Show current nickname */
  if (cmd->argc < 2) {
    if (cmd->sock) {
      silc_say(cmd->client, "Your nickname is %s on server %s", 
	       win->nickname, win->remote_host);
    } else {
      silc_say(cmd->client, "Your nickname is %s", win->nickname);
    }
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  /* Set new nickname */
  buffer = silc_command_encode_payload(SILC_COMMAND_NICK,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types);
  silc_client_packet_send(cmd->client, cmd->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;
  if (win->nickname)
    silc_free(win->nickname);
  win->nickname = strdup(cmd->argv[1]);

 out:
  silc_client_command_free(cmd);
}

/* Command SERVER. Connects to remote SILC server. This is local command. */

SILC_CLIENT_CMD_FUNC(server)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  int i = 0, len, port;
  char *hostname;

  if (cmd->argc < 2) {
    /* Show current servers */

    if (!cmd->client->current_win->sock) {
      silc_say(cmd->client, "You are not connected to any server");
      silc_say(cmd->client, "Usage: /SERVER [<server>[:<port>]]");
      goto out;
    }

    silc_say(client, "Current server: %s on %d %s", 
	     client->current_win->remote_host,
	     client->current_win->remote_port,
	     client->windows[i]->remote_info ?
	     client->windows[i]->remote_info : "");
    
    silc_say(client, "Server list:");
    for (i = 0; i < client->windows_count; i++) {
      silc_say(client, " [%d] %s on %d %s", i + 1,
	       client->windows[i]->remote_host,
	       client->windows[i]->remote_port,
	       client->windows[i]->remote_info ?
	       client->windows[i]->remote_info : "");
    }

    goto out;
  }

  /* See if port is included and then extract it */
  if (strchr(cmd->argv[1], ':')) {
    len = strcspn(cmd->argv[1], ":");
    hostname = silc_calloc(len + 1, sizeof(char));
    memcpy(hostname, cmd->argv[1], len);
    port = atoi(cmd->argv[1] + 1 + len);
  } else {
    hostname = cmd->argv[1];
    port = 706;
  }

  /* Connect asynchronously to not to block user interface */
  silc_client_connect_to_server(cmd->client, port, hostname);

 out:
  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(list)
{
}

SILC_CLIENT_CMD_FUNC(topic)
{
}

/* Command INVITE. Invites specific client to join a channel. */

SILC_CLIENT_CMD_FUNC(invite)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientWindow win = NULL;
  SilcBuffer buffer;
  SilcIDCache *id_cache;
  unsigned char *client_id, *channel_id;

#define CIDC(x) win->client_id_cache[(x) - 32], \
                win->client_id_cache_count[(x) - 32]
#define CHIDC(x) win->channel_id_cache[(x) - 32], \
                 win->channel_id_cache_count[(x) - 32]

  if (cmd->argc != 3) {
    silc_say(cmd->client, "Usage: /INVITE <nickname>[@<server>] <channel>");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  /* Get client ID of the client to be invited. If we don't have it
     we will request it and cache it. This same command will be called
     again after we have received the reply (ie. pending). */
  if (!silc_idcache_find_by_data(CIDC(cmd->argv[1][0]), cmd->argv[1], 
				&id_cache)) {
    SilcClientCommandContext ctx;
    char ident[512];

    ctx = silc_calloc(1, sizeof(*ctx));
    ctx->client = cmd->client;
    ctx->sock = cmd->sock;
    memset(ident, 0, sizeof(ident));
    snprintf(ident, sizeof(ident), "/IDENTIFY %s", cmd->argv[1]);
    silc_client_parse_command_line(ident, &ctx->argv, &ctx->argv_lens, 
				   &ctx->argv_types, &ctx->argc, 2);
    silc_client_command_identify(ctx);
    silc_client_command_pending(SILC_COMMAND_IDENTIFY, 
				silc_client_command_invite, context);
    return;
  }

  client_id = silc_id_id2str(id_cache->id, SILC_ID_CLIENT);

  /* Get Channel ID of the channel. */
  if (!silc_idcache_find_by_data(CHIDC(cmd->argv[2][0]), cmd->argv[2],
				 &id_cache)) {
    silc_say(cmd->client, "You are not on that channel");
    silc_free(client_id);
    goto out;
  }

  channel_id = silc_id_id2str(id_cache->id, SILC_ID_CHANNEL);

  buffer = silc_command_encode_payload_va(SILC_COMMAND_INVITE, 2,
					  1, client_id, SILC_ID_CLIENT_LEN,
					  2, channel_id, SILC_ID_CHANNEL_LEN);
  silc_client_packet_send(cmd->client, win->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  silc_say(cmd->client, "Inviting %s to channel %s", cmd->argv[1], 
	   cmd->argv[2]);

 out:
  silc_client_command_free(cmd);
#undef CIDC
#undef CHIDC
}

/* Command QUIT. Closes connection with current server. */
 
SILC_CLIENT_CMD_FUNC(quit)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcBuffer buffer;

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  buffer = silc_command_encode_payload(SILC_COMMAND_QUIT, cmd->argc - 1, 
				       ++cmd->argv, ++cmd->argv_lens,
				       ++cmd->argv_types);
  silc_client_packet_send(cmd->client, cmd->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

  /* Close connection */
  silc_client_close_connection(cmd->client, cmd->sock);
  cmd->client->screen->bottom_line->connection = NULL;
  silc_screen_print_bottom_line(cmd->client->screen, 0);

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
  SilcClientWindow win = NULL;
  SilcBuffer buffer;
  char *name;

  if (!cmd->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  if (cmd->argc < 2)
    name = strdup(win->remote_host);
  else
    name = strdup(cmd->argv[1]);

  /* Send the command */
  buffer = silc_command_encode_payload_va(SILC_COMMAND_INFO, 1, 
					  1, name, strlen(name));
  silc_client_packet_send(cmd->client, win->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

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
  SilcClientWindow win = NULL;
  SilcBuffer buffer;
  void *id;
  int i;
  char *name = NULL;

  if (!cmd->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  if (cmd->argc == 1 || !strcmp(cmd->argv[1], win->remote_host))
    name = strdup(win->remote_host);

  id = silc_id_str2id(win->remote_id_data, SILC_ID_SERVER);

  /* Send the command */
  buffer = silc_command_encode_payload_va(SILC_COMMAND_PING, 1, 
					  1, win->remote_id_data, 
					  SILC_ID_SERVER_LEN);
  silc_client_packet_send(cmd->client, win->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Start counting time */
  for (i = 0; i < win->ping_count; i++) {
    if (win->ping[i].dest_id == NULL) {
      win->ping[i].start_time = time(NULL);
      win->ping[i].dest_id = id;
      win->ping[i].dest_name = name;
      win->ping_count++;
      break;
    }
  }
  if (i >= win->ping_count) {
    i = win->ping_count;
    win->ping = silc_realloc(win->ping, sizeof(*win->ping) * (i + 1));
    win->ping[i].start_time = time(NULL);
    win->ping[i].dest_id = id;
    win->ping[i].dest_name = name;
    win->ping_count++;
  }
  
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
  SilcClientWindow win = NULL;
  SilcIDCache *id_cache = NULL;
  SilcBuffer buffer;

#define CIDC(x) win->channel_id_cache[(x) - 32]
#define CIDCC(x) win->channel_id_cache_count[(x) - 32]

  if (cmd->argc < 2) {
    /* Show channels currently joined to */
    if (!cmd->client->current_win->sock) {
      silc_say(cmd->client, "No current channel for this window");
      SILC_NOT_CONNECTED(cmd->client);
      goto out;

    }

    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  /* See if we have joined to the requested channel already */
  silc_idcache_find_by_data(CIDC(cmd->argv[1][0]), CIDCC(cmd->argv[1][0]), 
			    cmd->argv[1], &id_cache);

  if (id_cache) {
    silc_say(cmd->client, "You are talking to channel %s", cmd->argv[1]);
    win->current_channel = (SilcChannelEntry)id_cache->context;
    cmd->client->screen->bottom_line->channel = cmd->argv[1];
    silc_screen_print_bottom_line(cmd->client->screen, 0);
    goto out;
  }

  /* Send JOIN command to the server */
  buffer = silc_command_encode_payload(SILC_COMMAND_JOIN,
				       cmd->argc - 1, ++cmd->argv,
				       ++cmd->argv_lens, ++cmd->argv_types);
  silc_client_packet_send(cmd->client, win->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

 out:
  silc_client_command_free(cmd);
#undef CIDC
#undef CIDCC
}

SILC_CLIENT_CMD_FUNC(motd)
{
}

SILC_CLIENT_CMD_FUNC(umode)
{
}

SILC_CLIENT_CMD_FUNC(cmode)
{
}

SILC_CLIENT_CMD_FUNC(kick)
{
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
  SilcClientWindow win = NULL;
  SilcIDCache *id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer;
  unsigned char *id_string;
  char *name;

#define CIDC(x) win->channel_id_cache[(x) - 32]
#define CIDCC(x) win->channel_id_cache_count[(x) - 32]

  if (cmd->argc != 2) {
    silc_say(cmd->client, "Usage: /LEAVE <channel>");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  if (cmd->argv[1][0] == '*') {
    if (!win->current_channel) {
      silc_say(cmd->client, "You are not on any chanenl");
      goto out;
    }
    name = win->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!win->current_channel) {
    silc_say(cmd->client, "You are not on that channel");
    goto out;
  }

  /* Get the Channel ID of the channel */
  silc_idcache_find_by_data(CIDC(name[0]), CIDCC(name[0]), name, &id_cache);
  if (!id_cache) {
    silc_say(cmd->client, "You are not on that channel");
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Send LEAVE command to the server */
  id_string = silc_id_id2str(id_cache->id, SILC_ID_CHANNEL);
  buffer = silc_command_encode_payload_va(SILC_COMMAND_LEAVE, 1, 
					  1, id_string, SILC_ID_CHANNEL_LEN);
  silc_client_packet_send(cmd->client, win->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* We won't talk anymore on this channel */
  silc_say(cmd->client, "You have left channel %s", name);

  if (!strncmp(win->current_channel->channel_name, name, strlen(name))) {
    cmd->client->screen->bottom_line->channel = NULL;
    silc_screen_print_bottom_line(cmd->client->screen, 0);
    win->current_channel = NULL;
  }

  silc_idcache_del_by_id(CIDC(name[0]), CIDCC(name[0]),
			 SILC_ID_CHANNEL, channel->id);
  silc_free(channel->channel_name);
  silc_free(channel->id);
  silc_free(channel->key);
  silc_cipher_free(channel->channel_key);
  silc_free(channel);
  silc_free(id_string);

 out:
  silc_client_command_free(cmd);
#undef CIDC
#undef CIDCC
}

/* Command NAMES. Requests the names of the clients joined on requested
   channel. */

SILC_CLIENT_CMD_FUNC(names)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientWindow win = NULL;
  SilcIDCache *id_cache = NULL;
  SilcBuffer buffer;
  char *name;
  unsigned char *id_string;

#define CIDC(x) win->channel_id_cache[(x) - 32]
#define CIDCC(x) win->channel_id_cache_count[(x) - 32]

  if (cmd->argc != 2) {
    silc_say(cmd->client, "Usage: /NAMES <channel>");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  if (cmd->argv[1][0] == '*')
    name = win->current_channel->channel_name;
  else
    name = cmd->argv[1];

  /* Get the Channel ID of the channel */
  silc_idcache_find_by_data(CIDC(name[0]), CIDCC(name[0]), name, &id_cache);
  if (!id_cache) {
    /* XXX should resolve the channel ID; LIST command */
    silc_say(cmd->client, "You are not on that channel", name);
    goto out;
  }

  /* Send NAMES command to the server */
  id_string = silc_id_id2str(id_cache->id, SILC_ID_CHANNEL);
  buffer = silc_command_encode_payload_va(SILC_COMMAND_NAMES, 1, 
					  1, id_string, SILC_ID_CHANNEL_LEN);
  silc_client_packet_send(cmd->client, win->sock, SILC_PACKET_COMMAND, NULL, 
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_free(id_string);

  /* Register dummy pending command that will tell the reply command
     that user called this command. Server may send reply to this command
     even if user did not send this command thus we want to handle things
     differently when user sent the command. This is dummy and won't be
     execute. */
  /* XXX this is kludge and should be removed after pending command reply 
     support is added. Currently only commands may be pending not command
     replies. */
  silc_client_command_pending(SILC_COMMAND_NAMES, silc_client_command_names,
			      NULL);

 out:
  silc_client_command_free(cmd);
#undef CIDC
#undef CIDCC
}

/*
 * Local commands
 */

/* HELP command. This is local command and shows help on SILC */

SILC_CLIENT_CMD_FUNC(help)
{

}

/* CLEAR command. This is local command and clears current output window */

SILC_CLIENT_CMD_FUNC(clear)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;

  assert(client->current_win != NULL);
  wclear((WINDOW *)client->current_win->screen);
  wrefresh((WINDOW *)client->current_win->screen);

  silc_client_command_free(cmd);
}

/* VERSION command. This is local command and shows version of the client */

SILC_CLIENT_CMD_FUNC(version)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  extern char *silc_version;
  extern char *silc_name;
  extern char *silc_fullname;

  silc_say(client, "%s (%s) version %s", silc_name, silc_fullname,
	   silc_version);

  silc_client_command_free(cmd);
}

/* Command MSG. Sends private message to user or list of users. */
/* XXX supports only one destination */

SILC_CLIENT_CMD_FUNC(msg)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientWindow win = NULL;
  SilcClient client = cmd->client;
  SilcIDCache *id_cache;

#define CIDC(x) win->client_id_cache[(x) - 32], \
                win->client_id_cache_count[(x) - 32]

  if (cmd->argc < 3) {
    silc_say(cmd->client, "Usage: /MSG <nickname> <message>");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    SILC_NOT_CONNECTED(cmd->client);
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

  /* Find ID from cache */
  if (silc_idcache_find_by_data(CIDC(cmd->argv[1][0]), cmd->argv[1], 
				&id_cache) == FALSE) {
    SilcClientCommandContext ctx;
    char ident[512];

    SILC_LOG_DEBUG(("Requesting Client ID from server"));

    /* No ID found. Do query from the server. The query is done by 
       sending simple IDENTIFY command to the server. */
    ctx = silc_calloc(1, sizeof(*ctx));
    ctx->client = client;
    ctx->sock = cmd->sock;
    memset(ident, 0, sizeof(ident));
    snprintf(ident, sizeof(ident), "/IDENTIFY %s", cmd->argv[1]);
    silc_client_parse_command_line(ident, &ctx->argv, &ctx->argv_lens, 
				   &ctx->argv_types, &ctx->argc, 2);
    silc_client_command_identify(ctx);

    /* Mark this command to be pending command and to be executed after
       we have received the IDENTIFY reply from server. */
    silc_client_command_pending(SILC_COMMAND_IDENTIFY, 
				silc_client_command_msg, context);
    return;
  }

  /* Display the message for our eyes. */
  silc_print(client, "-> *%s* %s", cmd->argv[1], cmd->argv[2]);

  /* Send the private message */
  silc_client_packet_send_private_message(client, cmd->sock, id_cache->context,
					  cmd->argv[2], cmd->argv_lens[2],
					  TRUE);

 out:
  silc_client_command_free(cmd);
#undef CIDC
}

SILC_CLIENT_CMD_FUNC(away)
{
}
