/*

  local_command.c

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

#include "clientincludes.h"

/* Local commands. */
SilcClientCommand silc_local_command_list[] =
{
  SILC_CLIENT_LCMD(help, HELP, "HELP", 0, 2),
  SILC_CLIENT_LCMD(clear, CLEAR, "CLEAR", 0, 1),
  SILC_CLIENT_LCMD(version, VERSION, "VERSION", 0, 1),
  SILC_CLIENT_LCMD(server, SERVER, "SERVER", 0, 2),
  SILC_CLIENT_LCMD(msg, MSG, "MSG", 0, 3),
  SILC_CLIENT_LCMD(away, AWAY, "AWAY", 0, 2),

  { NULL, 0, NULL, 0, 0 },
};

/* Finds and returns a pointer to the command list. Return NULL if the
   command is not found. */

SilcClientCommand *silc_client_local_command_find(const char *name)
{
  SilcClientCommand *cmd;

  for (cmd = silc_local_command_list; cmd->name; cmd++) {
    if (!strcmp(cmd->name, name))
      return cmd;
  }

  return NULL;
}

/* HELP command. This is local command and shows help on SILC */

SILC_CLIENT_LCMD_FUNC(help)
{

}

/* CLEAR command. This is local command and clears current output window */

SILC_CLIENT_LCMD_FUNC(clear)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientInternal app = (SilcClientInternal)client->application;

#if 0
  wclear((WINDOW *)app->screen);
  wrefresh((WINDOW *)app->screen);
#endif

  silc_client_command_free(cmd);
}

/* VERSION command. This is local command and shows version of the client */

SILC_CLIENT_LCMD_FUNC(version)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  extern char *silc_version;
  extern char *silc_name;
  extern char *silc_fullname;

  silc_say(client, cmd->conn,
	   "%s (%s) version %s", silc_name, silc_fullname,
	   silc_version);

  silc_client_command_free(cmd);
}

/* Command MSG. Sends private message to user or list of users. Note that
   private messages are not really commands, they are message packets,
   however, on user interface it is convenient to show them as commands
   as that is the common way of sending private messages (like in IRC). */
/* XXX supports only one destination */

SILC_CLIENT_LCMD_FUNC(msg)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientEntry client_entry = NULL;
  unsigned int num = 0;
  char *nickname = NULL, *server = NULL;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc < 3) {
    silc_say(client, conn, "Usage: /MSG <nickname> <message>");
    goto out;
  }

  /* Parse the typed nickname. */
  if (!silc_parse_nickname(cmd->argv[1], &nickname, &server, &num)) {
    silc_say(client, conn, "Bad nickname");
    goto out;
  }

  /* Find client entry */
  client_entry = silc_idlist_get_client(client, conn, nickname, server, num,
					TRUE);
  if (!client_entry) {
    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 0, NULL,
				silc_client_local_command_msg, context);
    return;
  }

  /* Display the message for our eyes. */
  silc_print(client, "-> *%s* %s", cmd->argv[1], cmd->argv[2]);

  /* Send the private message */
  silc_client_send_private_message(client, conn, client_entry,
				   cmd->argv[2], cmd->argv_lens[2],
				   TRUE);

 out:
  silc_client_command_free(cmd);
}


/* Command SERVER. Connects to remote SILC server. This is local command. */

SILC_CLIENT_LCMD_FUNC(server)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  int i = 0, len, port;
  char *hostname;

  if (cmd->argc < 2) {
    /* Show current servers */

    if (!cmd->conn) {
      silc_say(client, conn, "You are not connected to any server");
      silc_say(client, conn, "Usage: /SERVER [<server>[:<port>]]");
      goto out;
    }

    silc_say(client, conn, "Current server: %s on %d %s", 
	     conn->remote_host, conn->remote_port,
	     conn->remote_info ? conn->remote_info : "");
    
    silc_say(client, conn, "Server list:");
    for (i = 0; i < client->conns_count; i++) {
      silc_say(client, conn, " [%d] %s on %d %s", i + 1,
	       client->conns[i]->remote_host, 
	       client->conns[i]->remote_port,
	       client->conns[i]->remote_info ? 
	       client->conns[i]->remote_info : "");
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

#if 0
  if (conn && conn->remote_host) {
    if (!strcmp(hostname, conn->remote_host) && port == conn->remote_port) {
      silc_say(client, conn, "You are already connected to that server");
      goto out;
    }

    /* Close connection */
    cmd->client->ops->disconnect(cmd->client, cmd->conn);
    silc_client_close_connection(cmd->client, cmd->conn->sock);
  }
#endif

  /* Connect asynchronously to not to block user interface */
  silc_client_connect_to_server(cmd->client, port, hostname, NULL);

 out:
  silc_client_command_free(cmd);
}

/* Local command AWAY. Client replies with away message to whomever sends
   private message to the client if the away message is set. If this is
   given without arguments the away message is removed. */

SILC_CLIENT_LCMD_FUNC(away)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientInternal app = (SilcClientInternal)client->application;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc == 1) {
    if (conn->away) {
      silc_free(conn->away->away);
      silc_free(conn->away);
      conn->away = NULL;
      app->screen->bottom_line->away = FALSE;

      silc_say(client, conn, "Away message removed");
      silc_screen_print_bottom_line(app->screen, 0);
    }
  } else {

    if (conn->away)
      silc_free(conn->away->away);
    else
      conn->away = silc_calloc(1, sizeof(*conn->away));
    
    app->screen->bottom_line->away = TRUE;
    conn->away->away = strdup(cmd->argv[1]);

    silc_say(client, conn, "Away message set: %s", conn->away->away);
    silc_screen_print_bottom_line(app->screen, 0);
  }

 out:
  silc_client_command_free(cmd);
}
