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
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Importet from internal CVS/Added Log headers.
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
  SILC_CLIENT_CMD(invite, INVITE, "INVITE", SILC_CF_LAG | SILC_CF_REG, 2),
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
   * Local. client specific commands
   */
  SILC_CLIENT_CMD(help, HELP, "HELP", SILC_CF_NONE, 2),
  SILC_CLIENT_CMD(clear, CLEAR, "CLEAR", SILC_CF_NONE, 1),
  SILC_CLIENT_CMD(version, VERSION, "VERSION", SILC_CF_NONE, 1),
  SILC_CLIENT_CMD(server, SERVER, "SERVER", SILC_CF_NONE, 2),
  SILC_CLIENT_CMD(msg, MSG, "MSG", SILC_CF_NONE, 3),
  SILC_CLIENT_CMD(away, AWAY, "AWAY", SILC_CF_NONE, 2),

  { NULL, 0, NULL, 0},
};

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
    silc_say(cmd->client, 
	     "You are not connected to a server, use /SERVER to connect");
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
    silc_say(cmd->client, 
	     "You are not connected to a server, use /SERVER to connect");
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
    silc_say(cmd->client, 
	     "You are not connected to a server, use /SERVER to connect");
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
  int len, port;
  char *hostname;

  if (cmd->argc < 2) {
    /* Show current servers */
    if (!cmd->client->current_win->sock) {
      silc_say(cmd->client, "You are not connected to any server");
      silc_say(cmd->client, "Usage: /SERVER [<server>[:<port>]]");
      goto out;
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
    /* XXX */
    port = 334;
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

SILC_CLIENT_CMD_FUNC(invite)
{
}

/* Command QUIT. Closes connection with current server. */
 
SILC_CLIENT_CMD_FUNC(quit)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcBuffer buffer;

  if (!cmd->client->current_win->sock) {
    silc_say(cmd->client, 
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  buffer = silc_command_encode_payload(SILC_COMMAND_QUIT, cmd->argc - 1, 
				       ++cmd->argv, ++cmd->argv_lens,
				       ++cmd->argv_types);
  silc_client_packet_send(cmd->client, cmd->client->current_win->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  cmd->argv--;
  cmd->argv_lens--;
  cmd->argv_types--;

  /* Close connection */
  silc_client_close_connection(cmd->client, cmd->sock);
  cmd->client->screen->bottom_line->connection = NULL;
  silc_screen_print_bottom_line(cmd->client->screen, 0);

  silc_client_command_free(cmd);
}

SILC_CLIENT_CMD_FUNC(kill)
{
}

SILC_CLIENT_CMD_FUNC(info)
{
}

SILC_CLIENT_CMD_FUNC(connect)
{
}

SILC_CLIENT_CMD_FUNC(ping)
{
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
      silc_say(cmd->client, 
	       "You are not connected to a server, use /SERVER to connect");
      goto out;

    }

    goto out;
  }

  if (!cmd->client->current_win->sock) {
    silc_say(cmd->client, 
	     "You are not connected to a server, use /SERVER to connect");
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
  silc_client_packet_send(cmd->client, cmd->client->current_win->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
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

SILC_CLIENT_CMD_FUNC(leave)
{
}

SILC_CLIENT_CMD_FUNC(names)
{
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
  SilcClient client = (SilcClient)context;

  assert(client->current_win != NULL);
  wclear((WINDOW *)client->current_win->screen);
  wrefresh((WINDOW *)client->current_win->screen);
}

/* VERSION command. This is local command and shows version of the client */

SILC_CLIENT_CMD_FUNC(version)
{

}

/* Command MSG. Sends private message to user or list of users. */
/* XXX supports only one destination */

SILC_CLIENT_CMD_FUNC(msg)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientWindow win = NULL;
  SilcClient client = cmd->client;
  SilcBuffer buffer;
  SilcIDCache *id_cache;
  unsigned int nick_len;

  if (cmd->argc < 3) {
    silc_say(cmd->client, "Usage: /MSG <nickname> <message>");
    goto out;
  }

  if (!cmd->client->current_win->sock) {
    silc_say(cmd->client, 
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  win = (SilcClientWindow)cmd->sock->user_data;

#define CIDC(x) win->client_id_cache[(x) - 32], \
                win->client_id_cache_count[(x) - 32]

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
