/*
  silc-server.c : irssi

  Copyright (C) 2000 - 2001 Timo Sirainen
                            Pekka Riikonen <priikone@poseidon.pspt.fi>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"

#include "net-nonblock.h"
#include "net-sendbuffer.h"
#include "signals.h"
#include "servers.h"
#include "commands.h"
#include "levels.h"
#include "modules.h"
#include "rawlog.h"
#include "misc.h"
#include "settings.h"

#include "servers-setup.h"

#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "window-item-def.h"

#include "fe-common/core/printtext.h"
#include "fe-common/silc/module-formats.h"

void silc_servers_reconnect_init(void);
void silc_servers_reconnect_deinit(void);

static void silc_send_channel(SILC_SERVER_REC *server,
			      char *channel, char *msg)
{
  SILC_CHANNEL_REC *rec;
  
  rec = silc_channel_find(server, channel);
  if (rec == NULL || rec->entry == NULL)
    return;
  
  silc_client_send_channel_message(silc_client, server->conn, rec->entry, 
				   NULL, 0, msg, strlen(msg), TRUE);
}

typedef struct {
  char *nick;
  char *msg;
} PRIVMSG_REC;

/* Callback function that sends the private message if the client was
   resolved from the server. */

static void silc_send_msg_clients(SilcClient client,
				  SilcClientConnection conn,
				  SilcClientEntry *clients,
				  uint32 clients_count,
				  void *context)
{
  PRIVMSG_REC *rec = context;
  SilcClientEntry target;
  
  if (clients_count == 0) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Unknown nick: %s", rec->nick);
  } else {
    target = clients[0]; /* FIXME: not a good idea :) */
    
    silc_client_send_private_message(client, conn, target, 0,
				     rec->msg, strlen(rec->msg),
				     TRUE);
  }
  
  g_free(rec->nick);
  g_free(rec->msg);
  g_free(rec);
}

static void silc_send_msg(SILC_SERVER_REC *server, char *nick, char *msg)
{
  PRIVMSG_REC *rec;
  SilcClientEntry client_entry;
  uint32 num = 0;
  char *nickname = NULL, *serv = NULL;
  
  if (!silc_parse_nickname(nick, &nickname, &serv, &num)) {
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_BAD_NICK, nick);
    return;
  }

  /* Find client entry */
  client_entry = silc_idlist_get_client(silc_client, server->conn, 
					nickname, serv, num, FALSE);
  if (!client_entry) {
    rec = g_new0(PRIVMSG_REC, 1);
    rec->nick = g_strdup(nick);
    rec->msg = g_strdup(msg);

    /* Could not find client with that nick, resolve it from server. */
    silc_client_get_clients(silc_client, server->conn,
			    nickname, serv, silc_send_msg_clients, rec);
    return;
  }

  /* Send the private message directly */
  silc_client_send_private_message(silc_client, server->conn, client_entry, 0,
				   msg, strlen(msg), TRUE);
}

static int isnickflag_func(char flag)
{
  return flag == '@' || flag == '+';
}

static int ischannel_func(const char *data)
{
  return *data == '#';
}

const char *get_nick_flags(void)
{
  return "@\0\0";
}

static void send_message(SILC_SERVER_REC *server, char *target, char *msg)
{
  g_return_if_fail(server != NULL);
  g_return_if_fail(target != NULL);
  g_return_if_fail(msg != NULL);

  if (*target == '#')
    silc_send_channel(server, target, msg);
  else
    silc_send_msg(server, target, msg);
}

static void sig_connected(SILC_SERVER_REC *server)
{
  SilcClientConnection conn;
  int fd;

  if (!IS_SILC_SERVER(server))
    return;

  conn = silc_client_add_connection(silc_client,
				    server->connrec->address,
				    server->connrec->port,
				    server);
  server->conn = conn;
	
  fd = g_io_channel_unix_get_fd(net_sendbuffer_handle(server->handle));
  if (!silc_client_start_key_exchange(silc_client, conn, fd)) {
    /* some internal error occured */
    server_disconnect(SERVER(server));
    signal_stop();
    return;
  }

  server->isnickflag = isnickflag_func;
  server->ischannel = ischannel_func;
  server->get_nick_flags = get_nick_flags;
  server->send_message = (void *) send_message;
}

static void sig_disconnected(SILC_SERVER_REC *server)
{
  if (!IS_SILC_SERVER(server) || server->conn == NULL)
    return;
  
  if (server->conn->sock != NULL) {
    silc_client_close_connection(silc_client, NULL, server->conn);
    
    /* SILC closes the handle */
    g_io_channel_unref(net_sendbuffer_handle(server->handle));
    net_sendbuffer_destroy(server->handle, FALSE);
    server->handle = NULL;
  }
}

SILC_SERVER_REC *silc_server_connect(SILC_SERVER_CONNECT_REC *conn)
{
  SILC_SERVER_REC *server;

  g_return_val_if_fail(IS_SILC_SERVER_CONNECT(conn), NULL);
  if (conn->address == NULL || *conn->address == '\0') 
    return NULL;
  if (conn->nick == NULL || *conn->nick == '\0') {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, 
	      "Cannot connect: nickname is not set");
    return NULL;
  }

  server = g_new0(SILC_SERVER_REC, 1);
  server->chat_type = SILC_PROTOCOL;
  server->connrec = conn;
  if (server->connrec->port <= 0) 
    server->connrec->port = 706;

  if (!server_start_connect((SERVER_REC *) server)) {
    server_connect_free(SERVER_CONNECT(conn));
    g_free(server);
    return NULL;
  }

  return server;
}

/* Return a string of all channels in server in server->channels_join() 
   format */

char *silc_server_get_channels(SILC_SERVER_REC *server)
{
  GSList *tmp;
  GString *chans;
  char *ret;

  g_return_val_if_fail(server != NULL, FALSE);

  chans = g_string_new(NULL);
  for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
    CHANNEL_REC *channel = tmp->data;
    
    g_string_sprintfa(chans, "%s,", channel->name);
  }

  if (chans->len > 0)
    g_string_truncate(chans, chans->len-1);

  ret = chans->str;
  g_string_free(chans, FALSE);
  
  return ret;
}

/* Syntaxes of all SILC commands for HELP files (the help file generation
   will snoop these from here). */

/* SYNTAX: BAN <channel> [+|-[<nickname>[@<server>[!<username>[@hostname>]]]]] */
/* SYNTAX: CMODE <channel> +|-<modes> [{ <arguments>}] */
/* SYNTAX: CUMODE <channel> +|-<modes> <nickname>[@<server>] [-pubkey|<passwd>] */
/* SYNTAX: GETKEY <nickname> */
/* SYNTAX: INVITE <channel> [<nickname>[@server>] */
/* SYNTAX: INVITE <channel> [+|-[<nickname>[@<server>[!<username>[@hostname>]]]]] */
/* SYNTAX: KEY MSG <nickname> set|unset|list|agreement|negotiate [<arguments>] */
/* SYNTAX: KEY CHANNEL <channel> set|unset|list|agreement|negotiate [<arguments>] */
/* SYNTAX: KICK <channel> <nickname>[@<server>] [<comment>] */
/* SYNTAX: KILL <channel> <nickname>[@<server>] [<comment>] */
/* SYNTAX: OPER <username> [<public key>] */
/* SYNTAX: SILCOPER <username> [<public key>] */
/* SYNTAX: TOPIC <channel> [<topic> */
/* SYNTAX: UMODE +|-<modes> */
/* SYNTAX: WHOIS <nickname>[@<server>] [<count>] */
/* SYNTAX: WHOWAS <nickname>[@<server>] [<count>] */
/* SYNTAX: CLOSE <server> [<port>] */
/* SYNTAX: SHUTDOWN */
/* SYNTAX: MOTD [<server>] */
/* SYNTAX: LIST [<channel>] */
/* SYNTAX: ME <message> */
/* SYNTAX: ACTION <channel> <message> */
/* SYNTAX: AWAY [<message>] */
/* SYNTAX: INFO [<server>] */
/* SYNTAX: NICK <nickname> */
/* SYNTAX: NOTICE <message> */
/* SYNTAX: PART [<channel>] */
/* SYNTAX: PING */
/* SYNTAX: SCONNECT <server> [<port>] */
/* SYNTAX: USERS <channel> */

void silc_command_exec(SILC_SERVER_REC *server,
		       const char *command, const char *args)
{
  uint32 argc = 0;
  unsigned char **argv;
  uint32 *argv_lens, *argv_types;
  char *data, *tmpcmd;
  SilcClientCommand *cmd;
  SilcClientCommandContext ctx;

  g_return_if_fail(server != NULL);

  tmpcmd = g_strdup(command); 
  g_strup(tmpcmd);
  cmd = silc_client_command_find(tmpcmd);
  g_free(tmpcmd);
  if (cmd == NULL)
    return;

  /* Now parse all arguments */
  data = g_strconcat(command, " ", args, NULL);
  silc_parse_command_line(data, &argv, &argv_lens,
			  &argv_types, &argc, cmd->max_args);
  g_free(data);

  /* Allocate command context. This and its internals must be free'd
     by the command routine receiving it. */
  ctx = silc_client_command_alloc();
  ctx->client = silc_client;
  ctx->conn = server->conn;
  ctx->command = cmd;
  ctx->argc = argc;
  ctx->argv = argv;
  ctx->argv_lens = argv_lens;
  ctx->argv_types = argv_types;
  
  /* Execute command */
  (*cmd->cb)(ctx);
}

/* Generic command function to call any SILC command directly. */

static void command_self(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  if (!IS_SILC_SERVER(server) || !server->connected) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Not connected to server");
    return;
  }

  if (IS_SILC_CHANNEL(item)) {
    SILC_CHANNEL_REC *chanrec;
    chanrec = silc_channel_find(server, item->name);
    if (chanrec)
      server->conn->current_channel = chanrec->entry;
  }

  silc_command_exec(server, current_command, data);
  signal_stop();
}

/* SCONNECT command.  Calls actually SILC's CONNECT command since Irssi
   has CONNECT command for other purposes. */

static void command_sconnect(const char *data, SILC_SERVER_REC *server)
{
  if (!IS_SILC_SERVER(server) || !server->connected) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Not connected to server");
    return;
  }

  silc_command_exec(server, "CONNECT", data);
  signal_stop();
}

static void event_text(const char *line, SILC_SERVER_REC *server,
		       WI_ITEM_REC *item)
{
  char *str;

  g_return_if_fail(line != NULL);

  if (!IS_SILC_ITEM(item))
    return;

  str = g_strdup_printf("%s %s", item->name, line);
  signal_emit("command msg", 3, str, server, item);
  g_free(str);

  signal_stop();
}

void silc_server_init(void)
{
  silc_servers_reconnect_init();

  signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
  signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
  signal_add("send text", (SIGNAL_FUNC) event_text);
  command_bind("whois", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("whowas", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("nick", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("topic", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("cmode", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("cumode", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("users", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("list", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("ban", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("oper", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("silcoper", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("umode", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("invite", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("kill", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("kick", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("info", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("ping", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("motd", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("close", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("shutdown", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("getkey", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind("sconnect", MODULE_NAME, (SIGNAL_FUNC) command_sconnect);

  command_set_options("connect", "+silcnet");
}

void silc_server_deinit(void)
{
  silc_servers_reconnect_deinit();

  signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
  signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
  signal_remove("send text", (SIGNAL_FUNC) event_text);
  command_unbind("whois", (SIGNAL_FUNC) command_self);
  command_unbind("whowas", (SIGNAL_FUNC) command_self);
  command_unbind("nick", (SIGNAL_FUNC) command_self);
  command_unbind("topic", (SIGNAL_FUNC) command_self);
  command_unbind("cmode", (SIGNAL_FUNC) command_self);
  command_unbind("cumode", (SIGNAL_FUNC) command_self);
  command_unbind("users", (SIGNAL_FUNC) command_self);
  command_unbind("list", (SIGNAL_FUNC) command_self);
  command_unbind("oper", (SIGNAL_FUNC) command_self);
  command_unbind("silcoper", (SIGNAL_FUNC) command_self);
  command_unbind("umode", (SIGNAL_FUNC) command_self);
  command_unbind("invite", (SIGNAL_FUNC) command_self);
  command_unbind("kill", (SIGNAL_FUNC) command_self);
  command_unbind("kick", (SIGNAL_FUNC) command_self);
  command_unbind("info", (SIGNAL_FUNC) command_self);
  command_unbind("ping", (SIGNAL_FUNC) command_self);
  command_unbind("motd", (SIGNAL_FUNC) command_self);
  command_unbind("ban", (SIGNAL_FUNC) command_self);
  command_unbind("close", (SIGNAL_FUNC) command_self);
  command_unbind("shutdown", (SIGNAL_FUNC) command_self);
  command_unbind("getkey", (SIGNAL_FUNC) command_self);
  command_unbind("sconnect", (SIGNAL_FUNC) command_sconnect);
}
