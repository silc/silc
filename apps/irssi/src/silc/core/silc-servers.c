/*
  silc-server.c : irssi

  Copyright (C) 2000 - 2003 Timo Sirainen
                            Pekka Riikonen <priikone@silcnet.org>

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
#include "silc-nicklist.h"
#include "window-item-def.h"

#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

#include "silc-commands.h"

void silc_servers_reconnect_init(void);
void silc_servers_reconnect_deinit(void);

static int silc_send_channel(SILC_SERVER_REC *server,
			      char *channel, char *msg,
			      SilcMessageFlags flags)
{
  SILC_CHANNEL_REC *rec;

  rec = silc_channel_find(server, channel);
  if (rec == NULL || rec->entry == NULL) {
    cmd_return_error_value(CMDERR_NOT_JOINED, FALSE);
  }

  silc_client_send_channel_message(silc_client, server->conn, rec->entry,
				   NULL, flags, msg, strlen(msg), TRUE);
  return TRUE;
}

typedef struct {
  char *nick;
  char *msg;
  int len;
  SilcMessageFlags flags;
  SILC_SERVER_REC *server;
} PRIVMSG_REC;

/* Callback function that sends the private message if the client was
   resolved from the server. */

static void silc_send_msg_clients(SilcClient client,
				  SilcClientConnection conn,
				  SilcClientEntry *clients,
				  SilcUInt32 clients_count,
				  void *context)
{
  PRIVMSG_REC *rec = context;
  SILC_SERVER_REC *server = rec->server;
  SilcClientEntry target;
  char *nickname = NULL;

  if (!clients_count) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
	      "%s: There is no such client", rec->nick);
  } else {
    if (clients_count > 1) {
      silc_parse_userfqdn(rec->nick, &nickname, NULL);

      /* Find the correct one. The rec->nick might be a formatted nick
	 so this will find the correct one. */
      clients = silc_client_get_clients_local(silc_client, server->conn,
					      nickname, rec->nick,
					      &clients_count);
      if (!clients) {
	printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
		  "%s: There is no such client", rec->nick);
	silc_free(nickname);
	goto out;
      }
      silc_free(nickname);
    }

    target = clients[0];

    /* Still check for exact math for nickname, this compares the
       real (formatted) nickname and the nick (maybe formatted) that
       use gave. This is to assure that `nick' does not match
       `nick@host'. */
    if (strcasecmp(rec->nick, clients[0]->nickname)) {
      printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
		"%s: There is no such client", rec->nick);
      goto out;
    }

    /* Send the private message */
    silc_client_send_private_message(client, conn, target,
				     rec->flags,
				     rec->msg, rec->len,
				     TRUE);
  }

 out:
  g_free(rec->nick);
  g_free(rec->msg);
  g_free(rec);
}

static int silc_send_msg(SILC_SERVER_REC *server, char *nick, char *msg,
			  int msg_len, SilcMessageFlags flags)
{
  PRIVMSG_REC *rec;
  SilcClientEntry *clients;
  SilcUInt32 clients_count;
  char *nickname = NULL;

  if (!silc_parse_userfqdn(nick, &nickname, NULL)) {
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_BAD_NICK, nick);
    return FALSE;
  }

  /* Find client entry */
  clients = silc_client_get_clients_local(silc_client, server->conn,
					  nickname, nick, &clients_count);
  if (!clients) {
    rec = g_new0(PRIVMSG_REC, 1);
    rec->nick = g_strdup(nick);
    rec->msg = g_strdup(msg);
    rec->server = server;
    rec->flags = flags;
    rec->len = msg_len;

    /* Could not find client with that nick, resolve it from server. */
    silc_client_get_clients(silc_client, server->conn,
			    nickname, NULL, silc_send_msg_clients, rec);
    silc_free(nickname);
    return FALSE;
  }

  /* Send the private message directly */
  silc_free(nickname);
  silc_client_send_private_message(silc_client, server->conn,
				   clients[0], flags,
				   msg, msg_len, TRUE);
  return TRUE;
}

void silc_send_mime(SILC_SERVER_REC *server, int channel, const char *to,
		    const char *data, int sign)
{
  char *unescaped_data;
  SilcUInt32 unescaped_data_len;
  int target_type;

  if (!(IS_SILC_SERVER(server)) || (data == NULL) || (to == NULL))
    return;

  if (channel) {
    target_type = SEND_TARGET_CHANNEL;
  } else {
    target_type = server_ischannel(SERVER(server), to) ?
      SEND_TARGET_CHANNEL : SEND_TARGET_NICK;
  }

  unescaped_data = silc_unescape_data(data, &unescaped_data_len);

  if (target_type == SEND_TARGET_CHANNEL) {
    SILC_CHANNEL_REC *rec;

    rec = silc_channel_find(server, to);
    if (rec == NULL || rec->entry == NULL) {
      cmd_return_error(CMDERR_NOT_JOINED);
    }

    silc_client_send_channel_message(silc_client, server->conn, rec->entry,
				     NULL, SILC_MESSAGE_FLAG_DATA |
				     (sign ? SILC_MESSAGE_FLAG_SIGNED : 0),
				     unescaped_data, unescaped_data_len, TRUE);
  } else {
    silc_send_msg(server, (char *)to, unescaped_data, unescaped_data_len,
		  SILC_MESSAGE_FLAG_DATA | 
		  (sign ? SILC_MESSAGE_FLAG_SIGNED : 0));

  }

  signal_stop();

  silc_free(unescaped_data);
}

static int isnickflag_func(char flag)
{
  return flag == '@' || flag == '+';
}

static int ischannel_func(SERVER_REC *server, const char *data)
{
  return FALSE;
}

const char *get_nick_flags(void)
{
  return "@\0\0";
}

static void send_message(SILC_SERVER_REC *server, char *target,
			 char *msg, int target_type)
{
  char *message = NULL;
  int len;

  g_return_if_fail(server != NULL);
  g_return_if_fail(target != NULL);
  g_return_if_fail(msg != NULL);

  if (!silc_term_utf8()) {
    len = silc_utf8_encoded_len(msg, strlen(msg), SILC_STRING_LANGUAGE);
    message = silc_calloc(len + 1, sizeof(*message));
    g_return_if_fail(message != NULL);
    silc_utf8_encode(msg, strlen(msg), SILC_STRING_LANGUAGE, message, len);
  }

  if (target_type == SEND_TARGET_CHANNEL)
    silc_send_channel(server, target, message ? message : msg,
		      SILC_MESSAGE_FLAG_UTF8);
  else
    silc_send_msg(server, target, message ? message : msg,
		  message ? strlen(message) : strlen(msg),
		  SILC_MESSAGE_FLAG_UTF8);

  silc_free(message);
}

void silc_send_heartbeat(SilcSocketConnection sock,
		         void *hb_context)
{
  SILC_SERVER_REC *server = SILC_SERVER(hb_context);

  if (server == NULL)
    return;

  silc_client_send_packet(silc_client, server->conn, SILC_PACKET_HEARTBEAT,
			  NULL, 0);
}

static void sig_connected(SILC_SERVER_REC *server)
{
  SilcClientConnection conn;
  SilcClientConnectionParams params;
  char file[256];
  int fd;

  if (!IS_SILC_SERVER(server))
    return;

  /* Try to read detached session data and use it if found. */
  memset(&params, 0, sizeof(params));
  memset(file, 0, sizeof(file));
  snprintf(file, sizeof(file) - 1, "%s/session", get_irssi_dir());
  params.detach_data = silc_file_readfile(file, &params.detach_data_len);
  if (params.detach_data)
    params.detach_data[params.detach_data_len] = 0;

  /* Add connection to the client library */
  conn = silc_client_add_connection(silc_client, &params,
				    server->connrec->address,
				    server->connrec->port,
				    server);
  server->conn = conn;

  if (params.detach_data)
    keyboard_entry_redirect(NULL,
			    "-- Resuming old session, may take a while ...",
			    ENTRY_REDIRECT_FLAG_HIDDEN, server);

  silc_free(params.detach_data);
  unlink(file);

  fd = g_io_channel_unix_get_fd(net_sendbuffer_handle(server->handle));

  /* Start key exchange with the server */
  silc_client_start_key_exchange(silc_client, conn, fd);

  /* Put default attributes */
  silc_query_attributes_default(silc_client, conn);

  /* initialize heartbeat sending */
  if (settings_get_int("heartbeat") > 0)
    silc_socket_set_heartbeat(conn->sock, settings_get_int("heartbeat"),
		  		(void *)server,
				(SilcSocketConnectionHBCb)silc_send_heartbeat,
				silc_client->schedule);

  server->ftp_sessions = silc_dlist_init();
  server->isnickflag = isnickflag_func;
  server->ischannel = ischannel_func;
  server->get_nick_flags = get_nick_flags;
  server->send_message = (void *) send_message;
}

static void sig_disconnected(SILC_SERVER_REC *server)
{
  if (!IS_SILC_SERVER(server))
    return;

  silc_dlist_uninit(server->ftp_sessions);

  if (server->conn && server->conn->sock != NULL) {
    silc_client_close_connection(silc_client, server->conn);

    /* SILC closes the handle */
    g_io_channel_unref(net_sendbuffer_handle(server->handle));
    net_sendbuffer_destroy(server->handle, FALSE);
    server->handle = NULL;
  }
}

SERVER_REC *silc_server_init_connect(SERVER_CONNECT_REC *conn)
{
  SILC_SERVER_REC *server;

  g_return_val_if_fail(IS_SILC_SERVER_CONNECT(conn), NULL);
  if (conn->address == NULL || *conn->address == '\0')
    return NULL;
  if (conn->nick == NULL || *conn->nick == '\0') {
    silc_say_error("Cannot connect: nickname is not set");
    return NULL;
  }

  server = g_new0(SILC_SERVER_REC, 1);
  server->chat_type = SILC_PROTOCOL;
  server->connrec = (SILC_SERVER_CONNECT_REC *)conn;
  server_connect_ref(conn);

  if (server->connrec->port <= 0)
    server->connrec->port = 706;

  server_connect_init((SERVER_REC *)server);
  return (SERVER_REC *)server;
}

void silc_server_connect(SERVER_REC *server)
{
  if (!server_start_connect(server)) {
    server_connect_unref(server->connrec);
    g_free(server);
    return;
  }
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
/* SYNTAX: CUMODE <channel> +|-<modes> <nickname>[@<hostname>] */
/* SYNTAX: GETKEY <nickname or server name> */
/* SYNTAX: INVITE <channel> [<nickname>[@hostname>] */
/* SYNTAX: INVITE <channel> [+|-[<nickname>[@<server>[!<username>[@hostname>]]]]] */
/* SYNTAX: KEY MSG <nickname> set|unset|list|agreement|negotiate [<arguments>] */
/* SYNTAX: KEY CHANNEL <channel> set|unset|list|change [<arguments>] */
/* SYNTAX: KICK <channel> <nickname>[@<hostname>] [<comment>] */
/* SYNTAX: KILL <nickname>[@<hostname>] [<comment>] [-pubkey] */
/* SYNTAX: OPER <username> [-pubkey] */
/* SYNTAX: SILCOPER <username> [-pubkey] */
/* SYNTAX: TOPIC <channel> [<topic>] */
/* SYNTAX: UMODE +|-<modes> */
/* SYNTAX: WHOIS <nickname>[@<hostname>] [-details] [<count>] */
/* SYNTAX: WHOWAS <nickname>[@<hostname>] [<count>] */
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
/* SYNTAX: FILE SEND <filepath> <nickname> [<local IP> [<local port>]] [-no-listener]*/
/* SYNTAX: FILE ACCEPT [<nickname>] */
/* SYNTAX: FILE CLOSE [<nickname>] */
/* SYNTAX: FILE */
/* SYNTAX: JOIN <channel> [<passphrase>] [-cipher <cipher>] [-hmac <hmac>] [-founder] [-auth [<pubkeyfile> <privkeyfile> [<privkey passphrase>]]]*/
/* SYNTAX: DETACH */
/* SYNTAX: WATCH [<-add | -del> <nickname>] */
/* SYNTAX: STATS */
/* SYNTAX: ATTR [<-del> <option> [{ <value>}]] */
/* SYNTAX: SMSG [<-channel>] <target> <message> */
/* SYNTAX: LISTKEYS [-servers] [-clients] [<public key file>] */

void silc_command_exec(SILC_SERVER_REC *server,
		       const char *command, const char *args)
{
  char *data;
  g_return_if_fail(server != NULL);

  /* Call the command */
  data = g_strconcat(command, " ", args, NULL);
  silc_client_command_call(silc_client, server->conn, data);
  g_free(data);
}

/* Generic command function to call any SILC command directly. */

static void command_self(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  CMD_SILC_SERVER(server);

  if (!IS_SILC_SERVER(server) || !server->connected) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Not connected to server");
    return;
  }

  if (IS_SILC_CHANNEL(item)) {
    SILC_CHANNEL_REC *chanrec;
    chanrec = silc_channel_find(server, item->visible_name);
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
  CMD_SILC_SERVER(server);
  if (!IS_SILC_SERVER(server) || !server->connected) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Not connected to server");
    return;
  }

  silc_command_exec(server, "CONNECT", data);
  signal_stop();
}

/* SMSG command, to send digitally signed messages */

static void command_smsg(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  GHashTable *optlist;
  char *target, *origtarget, *msg;
  void *free_arg;
  int free_ret, target_type;

  g_return_if_fail(data != NULL);
  if (server == NULL || !server->connected)
    cmd_param_error(CMDERR_NOT_CONNECTED);

  if (!cmd_get_params(data, &free_arg, 2 | PARAM_FLAG_OPTIONS |
		      PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
		      "msg", &optlist, &target, &msg))
    return;
  if (*target == '\0' || *msg == '\0')
    cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

  origtarget = target;
  free_ret = FALSE;

  if (strcmp(target, "*") == 0) {
    if (item == NULL)
      cmd_param_error(CMDERR_NOT_JOINED);

    target_type = IS_CHANNEL(item) ?
      SEND_TARGET_CHANNEL : SEND_TARGET_NICK;
    target = (char *) window_item_get_target(item);
  } else if (g_hash_table_lookup(optlist, "channel") != NULL) {
    target_type = SEND_TARGET_CHANNEL;
  } else {
    target_type = server_ischannel(SERVER(server), target) ?
      SEND_TARGET_CHANNEL : SEND_TARGET_NICK;
  }

  if (target != NULL) {
    char *message = NULL;
    int len, result;

    if (!silc_term_utf8()) {
      len = silc_utf8_encoded_len(msg, strlen(msg), SILC_STRING_LANGUAGE);
      message = silc_calloc(len + 1, sizeof(*message));
      g_return_if_fail(message != NULL);
      silc_utf8_encode(msg, strlen(msg), SILC_STRING_LANGUAGE, message, len);
    }

    if (target_type == SEND_TARGET_CHANNEL)
      result = silc_send_channel(server, target, message ? message : msg,
				 SILC_MESSAGE_FLAG_UTF8 |
				 SILC_MESSAGE_FLAG_SIGNED);
    else
      result = silc_send_msg(server, target, message ? message : msg,
			     message ? strlen(message) : strlen(msg),
			     SILC_MESSAGE_FLAG_UTF8 |
			     SILC_MESSAGE_FLAG_SIGNED);
    silc_free(message);
    if (!result)
      goto out;
  }

  signal_emit(target != NULL && target_type == SEND_TARGET_CHANNEL ?
	      "message signed_own_public" : "message signed_own_private", 4,
	      server, msg, target, origtarget);
out:
  if (free_ret && target != NULL) g_free(target);
  cmd_params_free(free_arg);
}

/* FILE command */

SILC_TASK_CALLBACK(silc_client_file_close_later)
{
  FtpSession ftp = (FtpSession)context;

  SILC_LOG_DEBUG(("Start"));

  silc_client_file_close(silc_client, ftp->conn, ftp->session_id);
  silc_free(ftp->filepath);
  silc_free(ftp);
}

static void silc_client_file_monitor(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientMonitorStatus status,
				     SilcClientFileError error,
				     SilcUInt64 offset,
				     SilcUInt64 filesize,
				     SilcClientEntry client_entry,
				     SilcUInt32 session_id,
				     const char *filepath,
				     void *context)
{
  SILC_SERVER_REC *server = (SILC_SERVER_REC *)context;
  FtpSession ftp;
  char fsize[32];

  snprintf(fsize, sizeof(fsize) - 1, "%llu", ((filesize + 1023) / 1024));

  silc_dlist_start(server->ftp_sessions);
  while ((ftp = silc_dlist_get(server->ftp_sessions)) != SILC_LIST_END) {
    if (ftp->session_id == session_id) {
      if (!ftp->filepath && filepath)
	ftp->filepath = strdup(filepath);
      break;
    }
  }

  if (ftp == SILC_LIST_END)
    return;

  if (status == SILC_CLIENT_FILE_MONITOR_ERROR) {
    if (error == SILC_CLIENT_FILE_NO_SUCH_FILE)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_ERROR_NO_SUCH_FILE,
			 client_entry->nickname,
			 filepath ? filepath : "[N/A]");
    else if (error == SILC_CLIENT_FILE_PERMISSION_DENIED)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_ERROR_PERMISSION_DENIED,
			 client_entry->nickname);
    else
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_ERROR, client_entry->nickname);
    silc_schedule_task_add(silc_client->schedule, 0,
			   silc_client_file_close_later, ftp,
			   1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    if (ftp == server->current_session)
      server->current_session = NULL;
    silc_dlist_del(server->ftp_sessions, ftp);
  }

  if (status == SILC_CLIENT_FILE_MONITOR_KEY_AGREEMENT) {
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_FILE_KEY_EXCHANGE, client_entry->nickname);
  }

  /* Save some transmission data */
  if (offset && filesize) {
    unsigned long delta = time(NULL) - ftp->starttime;

    ftp->percent = ((double)offset / (double)filesize) * (double)100.0;
    if (delta)
      ftp->kps = (double)((offset / (double)delta) + 1023) / (double)1024;
    else
      ftp->kps = (double)(offset + 1023) / (double)1024;
    ftp->offset = offset;
    ftp->filesize = filesize;
  }

  if (status == SILC_CLIENT_FILE_MONITOR_SEND) {
    if (offset == 0) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_TRANSMIT, filepath, fsize,
			 client_entry->nickname);
      ftp->starttime = time(NULL);
    }
    if (offset == filesize) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_TRANSMITTED, filepath, fsize,
			 client_entry->nickname, ftp->kps);
      silc_schedule_task_add(silc_client->schedule, 0,
			     silc_client_file_close_later, ftp,
			     1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
      if (ftp == server->current_session)
	server->current_session = NULL;
      silc_dlist_del(server->ftp_sessions, ftp);
    }
  }

  if (status == SILC_CLIENT_FILE_MONITOR_RECEIVE) {
    if (offset == 0) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_RECEIVE, filepath, fsize,
			 client_entry->nickname);
      ftp->starttime = time(NULL);
    }

    if (offset == filesize) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_RECEIVED, filepath, fsize,
			 client_entry->nickname, ftp->kps);
      silc_schedule_task_add(silc_client->schedule, 0,
			     silc_client_file_close_later, ftp,
			     1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
      if (ftp == server->current_session)
	server->current_session = NULL;
      silc_dlist_del(server->ftp_sessions, ftp);
    }
  }
}

typedef struct {
  SILC_SERVER_REC *server;
  char *data;
  char *nick;
  WI_ITEM_REC *item;
} *FileGetClients;

static void silc_client_command_file_get_clients(SilcClient client,
						 SilcClientConnection conn,
						 SilcClientEntry *clients,
						 SilcUInt32 clients_count,
						 void *context)
{
  FileGetClients internal = (FileGetClients)context;

  if (!clients) {
    printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "Unknown nick: %s",
	      internal->nick);
    silc_free(internal->data);
    silc_free(internal->nick);
    silc_free(internal);
    return;
  }

  signal_emit("command file", 3, internal->data, internal->server,
	      internal->item);

  silc_free(internal->data);
  silc_free(internal->nick);
  silc_free(internal);
}

static void command_file(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
  SilcClientConnection conn;
  SilcClientEntry *entrys, client_entry;
  SilcClientFileError ret;
  SilcUInt32 entry_count;
  char *nickname = NULL, *tmp;
  unsigned char **argv;
  SilcUInt32 argc;
  SilcUInt32 *argv_lens, *argv_types;
  int type = 0;
  FtpSession ftp;
  char *local_ip = NULL;
  SilcUInt32 local_port = 0;
  SilcUInt32 session_id;
  bool do_not_bind = FALSE;

  CMD_SILC_SERVER(server);
  if (!server || !IS_SILC_SERVER(server) || !server->connected)
    cmd_return_error(CMDERR_NOT_CONNECTED);

  conn = server->conn;

  /* Now parse all arguments */
  tmp = g_strconcat("FILE", " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens, &argv_types, &argc, 7);
  g_free(tmp);

  if (argc == 1)
    type = 4;

  if (argc >= 2) {
    if (!strcasecmp(argv[1], "send"))
      type = 1;
    if (!strcasecmp(argv[1], "accept"))
      type = 2;
    if (!strcasecmp(argv[1], "close"))
      type = 3;
  }

  if (type == 0)
    cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

  switch (type) {
  case 1:
    if (argc < 4)
      cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

    /* Parse the typed nickname. */
    if (!silc_parse_userfqdn(argv[3], &nickname, NULL)) {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_BAD_NICK, argv[3]);
      goto out;
    }

    /* Find client entry */
    entrys = silc_client_get_clients_local(silc_client, conn, nickname,
					   argv[3], &entry_count);
    if (!entrys) {
      FileGetClients inter = silc_calloc(1, sizeof(*inter));
      inter->server = server;
      inter->data = strdup(data);
      inter->nick = strdup(nickname);
      inter->item = item;
      silc_client_get_clients(silc_client, conn, nickname, argv[3],
			      silc_client_command_file_get_clients, inter);
      goto out;
    }
    client_entry = entrys[0];
    silc_free(entrys);

    if (argc >= 5) {
      if (!strcasecmp(argv[4], "-no-listener"))
	do_not_bind = TRUE;
      else
	local_ip = argv[4];
    }
    if (argc >= 6) {
      if (!strcasecmp(argv[5], "-no-listener"))
	do_not_bind = TRUE;
      else
	local_port = atoi(argv[5]);
    }
    if (argc >= 7) {
      if (!strcasecmp(argv[6], "-no-listener"))
	do_not_bind = TRUE;
    }

    ret =
      silc_client_file_send(silc_client, conn, silc_client_file_monitor,
			    server, local_ip, local_port, do_not_bind,
			    client_entry, argv[2], &session_id);
    if (ret == SILC_CLIENT_FILE_OK) {
      ftp = silc_calloc(1, sizeof(*ftp));
      ftp->session_id = session_id;

      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_FILE_SEND, client_entry->nickname,
			 argv[2]);

      ftp->client_entry = client_entry;
      ftp->filepath = strdup(argv[2]);
      ftp->conn = conn;
      ftp->send = TRUE;
      silc_dlist_add(server->ftp_sessions, ftp);
      server->current_session = ftp;
    } else {
      if (ret == SILC_CLIENT_FILE_ALREADY_STARTED)
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_FILE_ALREADY_STARTED,
			   client_entry->nickname);
      if (ret == SILC_CLIENT_FILE_NO_SUCH_FILE)
	printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			   SILCTXT_FILE_ERROR_NO_SUCH_FILE,
			   client_entry->nickname, argv[2]);
    }

    break;

  case 2:
    /* Parse the typed nickname. */
    if (argc >= 3) {
      if (!silc_parse_userfqdn(argv[2], &nickname, NULL)) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_BAD_NICK, argv[2]);
	goto out;
      }

      /* Find client entry */
      entrys = silc_client_get_clients_local(silc_client, conn, nickname,
					     argv[2], &entry_count);
      if (!entrys) {
	FileGetClients inter = silc_calloc(1, sizeof(*inter));
	inter->server = server;
	inter->data = strdup(data);
	inter->nick = strdup(nickname);
	inter->item = item;
	silc_client_get_clients(silc_client, conn, nickname, argv[2],
				silc_client_command_file_get_clients, inter);
	goto out;
      }
      client_entry = entrys[0];
      silc_free(entrys);
    } else {
      if (!server->current_session) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_FILE_NA);
	goto out;
      }

      ret = silc_client_file_receive(silc_client, conn,
				     silc_client_file_monitor, server, NULL,
				     server->current_session->session_id);
      if (ret != SILC_CLIENT_FILE_OK) {
	if (ret == SILC_CLIENT_FILE_ALREADY_STARTED)
	  printformat_module("fe-common/silc", server, NULL,
			     MSGLEVEL_CRAP, SILCTXT_FILE_ALREADY_STARTED,
			     server->current_session->client_entry->nickname);
	else
	  printformat_module("fe-common/silc", server, NULL,
			     MSGLEVEL_CRAP, SILCTXT_FILE_CLIENT_NA,
			     server->current_session->client_entry->nickname);
      }

      goto out;
    }

    silc_dlist_start(server->ftp_sessions);
    while ((ftp = silc_dlist_get(server->ftp_sessions)) != SILC_LIST_END) {
      if (ftp->client_entry == client_entry && !ftp->filepath) {
	ret = silc_client_file_receive(silc_client, conn,
				       silc_client_file_monitor, server,
				       NULL, ftp->session_id);
	if (ret != SILC_CLIENT_FILE_OK) {
	  if (ret == SILC_CLIENT_FILE_ALREADY_STARTED)
	    printformat_module("fe-common/silc", server, NULL,
			       MSGLEVEL_CRAP, SILCTXT_FILE_ALREADY_STARTED,
			       client_entry->nickname);
	  else
	    printformat_module("fe-common/silc", server, NULL,
			       MSGLEVEL_CRAP, SILCTXT_FILE_CLIENT_NA,
			       client_entry->nickname);
	}
	break;
      }
    }

    if (ftp == SILC_LIST_END) {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_FILE_CLIENT_NA,
			 client_entry->nickname);
      goto out;
    }
    break;

  case 3:
    /* Parse the typed nickname. */
    if (argc >= 3) {
      if (!silc_parse_userfqdn(argv[2], &nickname, NULL)) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_BAD_NICK, argv[2]);
	goto out;
      }

      /* Find client entry */
      entrys = silc_client_get_clients_local(silc_client, conn, nickname,
					     argv[2], &entry_count);
      if (!entrys) {
	FileGetClients inter = silc_calloc(1, sizeof(*inter));
	inter->server = server;
	inter->data = strdup(data);
	inter->nick = strdup(nickname);
	inter->item = item;
	silc_client_get_clients(silc_client, conn, nickname, argv[2],
				silc_client_command_file_get_clients, inter);
	goto out;
      }
      client_entry = entrys[0];
      silc_free(entrys);
    } else {
      if (!server->current_session) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_FILE_NA);
	goto out;
      }

      silc_client_file_close(silc_client, conn,
			     server->current_session->session_id);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_FILE_CLOSED,
			 server->current_session->client_entry->nickname,
			 server->current_session->filepath ?
			 server->current_session->filepath : "[N/A]");
      silc_dlist_del(server->ftp_sessions, server->current_session);
      silc_free(server->current_session->filepath);
      silc_free(server->current_session);
      server->current_session = NULL;
      goto out;
    }

    silc_dlist_start(server->ftp_sessions);
    while ((ftp = silc_dlist_get(server->ftp_sessions)) != SILC_LIST_END) {
      if (ftp->client_entry == client_entry) {
	silc_client_file_close(silc_client, conn, ftp->session_id);
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_FILE_CLOSED,
			   client_entry->nickname,
			   ftp->filepath ? ftp->filepath : "[N/A]");
	if (ftp == server->current_session)
	  server->current_session = NULL;
	silc_dlist_del(server->ftp_sessions, ftp);
	silc_free(ftp->filepath);
	silc_free(ftp);
	break;
      }
    }

    if (ftp == SILC_LIST_END) {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_FILE_CLIENT_NA,
			 client_entry->nickname);
      goto out;
    }
    break;

  case 4:

    if (!silc_dlist_count(server->ftp_sessions)) {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_FILE_NA);
      goto out;
    }

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_FILE_SHOW_HEADER);

    silc_dlist_start(server->ftp_sessions);
    while ((ftp = silc_dlist_get(server->ftp_sessions)) != SILC_LIST_END) {
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_FILE_SHOW_LINE,
			 ftp->client_entry->nickname,
			 ftp->send ? "send" : "receive",
			 (SilcUInt32)(ftp->offset + 1023) / 1024,
			 (SilcUInt32)(ftp->filesize + 1023) / 1024,
			 ftp->percent, ftp->kps,
			 ftp->filepath ? ftp->filepath : "[N/A]");
    }

    break;

  default:
    break;
  }

 out:
  silc_free(nickname);
}

void silc_server_init(void)
{
  silc_servers_reconnect_init();

  signal_add_first("server connected", (SIGNAL_FUNC) sig_connected);
  signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
  signal_add("mime-send", (SIGNAL_FUNC)silc_send_mime);
  command_bind_silc("whois", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("whowas", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("nick", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("topic", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("cmode", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("cumode", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("users", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("list", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("ban", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("oper", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("silcoper", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("umode", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("invite", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("kill", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("kick", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("info", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("ping", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("motd", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("close", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("shutdown", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("getkey", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("sconnect", MODULE_NAME, (SIGNAL_FUNC) command_sconnect);
  command_bind_silc("file", MODULE_NAME, (SIGNAL_FUNC) command_file);
  command_bind_silc("detach", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("watch", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("stats", MODULE_NAME, (SIGNAL_FUNC) command_self);
  command_bind_silc("attr", MODULE_NAME, (SIGNAL_FUNC) command_attr);
  command_bind_silc("smsg", MODULE_NAME, (SIGNAL_FUNC) command_smsg);

  command_set_options("connect", "+silcnet");
}

void silc_server_deinit(void)
{
  silc_servers_reconnect_deinit();

  signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
  signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
  signal_remove("mime-send", (SIGNAL_FUNC)silc_send_mime);
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
  command_unbind("file", (SIGNAL_FUNC) command_file);
  command_unbind("detach", (SIGNAL_FUNC) command_self);
  command_unbind("watch", (SIGNAL_FUNC) command_self);
  command_unbind("stats", (SIGNAL_FUNC) command_self);
  command_unbind("attr", (SIGNAL_FUNC) command_attr);
  command_unbind("smsg", (SIGNAL_FUNC) command_smsg);
}

void silc_server_free_ftp(SILC_SERVER_REC *server,
			  SilcClientEntry client_entry)
{
  FtpSession ftp;

  silc_dlist_start(server->ftp_sessions);
  while ((ftp = silc_dlist_get(server->ftp_sessions)) != SILC_LIST_END) {
    if (ftp->client_entry == client_entry) {
      silc_dlist_del(server->ftp_sessions, ftp);
      silc_free(ftp->filepath);
      silc_free(ftp);
    }
  }
}

bool silc_term_utf8(void)
{
  const char *str;
  str = settings_get_str("term_type");
  if (str)
    if (g_strcasecmp(str, "utf-8") == 0)
      return TRUE;
  return FALSE;
}
