/*

  command.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2009 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

static int silc_server_is_registered(SilcServer server,
				     SilcPacketStream sock,
				     SilcServerCommandContext cmd,
				     SilcCommand command);
static void
silc_server_command_send_status_reply(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcStatus status,
				      SilcStatus error);
static void
silc_server_command_send_status_data(SilcServerCommandContext cmd,
				     SilcCommand command,
				     SilcStatus status,
				     SilcStatus error,
				     SilcUInt32 arg_type,
				     const unsigned char *arg,
				     SilcUInt32 arg_len);
static bool
silc_server_command_pending_error_check(SilcServerCommandContext cmd,
					SilcServerCommandReplyContext cmdr,
					SilcCommand command);
SILC_TASK_CALLBACK(silc_server_command_process_timeout);

/* Server command list. */
SilcServerCommand silc_command_list[] =
{
  SILC_SERVER_CMD(whois, WHOIS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(whowas, WHOWAS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(identify, IDENTIFY, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(nick, NICK, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(list, LIST, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(topic, TOPIC, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(invite, INVITE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(quit, QUIT, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(kill, KILL, SILC_CF_LAG_STRICT | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(info, INFO, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(stats, STATS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(ping, PING, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(oper, OPER, SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(join, JOIN, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(motd, MOTD, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(umode, UMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(cmode, CMODE, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(cumode, CUMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(kick, KICK, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(ban, BAN, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(detach, DETACH, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(watch, WATCH, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(silcoper, SILCOPER,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER),
  SILC_SERVER_CMD(leave, LEAVE, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(users, USERS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(getkey, GETKEY, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(service, SERVICE, SILC_CF_LAG_STRICT | SILC_CF_REG),

  SILC_SERVER_CMD(connect, PRIV_CONNECT,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(close, PRIV_CLOSE,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(shutdown, PRIV_SHUTDOWN, SILC_CF_LAG | SILC_CF_REG |
		  SILC_CF_OPER),

  { NULL, 0 },
};

/* Performs several checks to the command. It first checks whether this
   command was called as pending command callback. If it was then it checks
   whether error occurred in the command reply where the pending command
   callback was called.

   It also checks that the requested command includes correct amount
   of arguments. */
#define SILC_SERVER_COMMAND_CHECK(command, context, min, max)		     \
do {									     \
  SilcUInt32 _argc;							     \
									     \
  if (silc_server_command_pending_error_check(cmd, context2, command)) {     \
    SILC_LOG_DEBUG(("Error occurred in command reply, command not called")); \
    silc_server_command_free(cmd);					     \
    return;								     \
  }									     \
									     \
  _argc = silc_argument_get_arg_num(cmd->args);				     \
  if (_argc < min) {							     \
    SILC_LOG_DEBUG(("Not enough parameters in command"));		     \
    silc_server_command_send_status_reply(cmd, command,			     \
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, \
					  0);				     \
    silc_server_command_free(cmd);					     \
    return;								     \
  }									     \
  if (_argc > max) {							     \
    SILC_LOG_DEBUG(("Too many parameters in command"));			     \
    silc_server_command_send_status_reply(cmd, command,			     \
					  SILC_STATUS_ERR_TOO_MANY_PARAMS,   \
					  0);				     \
    silc_server_command_free(cmd);					     \
    return;								     \
  }									     \
} while(0)

/* Returns TRUE if the connection is registered. Unregistered connections
   usually cannot send commands hence the check. */

static int silc_server_is_registered(SilcServer server,
				     SilcPacketStream sock,
				     SilcServerCommandContext cmd,
				     SilcCommand command)
{
  SilcIDListData idata = silc_packet_get_context(sock);

  if (!idata)
    return FALSE;

  if (idata->status & SILC_IDLIST_STATUS_REGISTERED)
    return TRUE;

  silc_server_command_send_status_reply(cmd, command,
					SILC_STATUS_ERR_NOT_REGISTERED, 0);
  return FALSE;
}

/* Internal context to hold data when executed command with timeout. */
typedef struct {
  SilcServerCommandContext ctx;
  SilcServerCommand *cmd;
} *SilcServerCommandTimeout;

/* Timeout callback to process commands with timeout for client. Client's
   commands are always executed with timeout. */

SILC_TASK_CALLBACK(silc_server_command_process_timeout)
{
  SilcServerCommandTimeout timeout = (SilcServerCommandTimeout)context;
  SilcClientEntry client = silc_packet_get_context(timeout->ctx->sock);

  if (!client) {
    SILC_LOG_DEBUG(("Client entry is invalid"));
    silc_server_command_free(timeout->ctx);
    silc_free(timeout);
    return;
  }

  /* Update access time */
  client->last_command = time(NULL);

  if (!(timeout->cmd->flags & SILC_CF_REG)) {
    SILC_LOG_DEBUG(("Calling %s command",
		    silc_get_command_name(timeout->cmd->cmd)));
    timeout->cmd->cb(timeout->ctx, NULL);
  } else if (silc_server_is_registered(timeout->ctx->server,
				       timeout->ctx->sock,
				       timeout->ctx,
				       timeout->cmd->cmd)) {
    SILC_LOG_DEBUG(("Calling %s command",
		    silc_get_command_name(timeout->cmd->cmd)));
    timeout->cmd->cb(timeout->ctx, NULL);
  } else {
    SILC_LOG_DEBUG(("Client is not registered"));
    silc_server_command_free(timeout->ctx);
  }

  silc_free(timeout);
}

/* Processes received command packet. */

void silc_server_command_process(SilcServer server,
				 SilcPacketStream sock,
				 SilcPacket packet)
{
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcServerCommandContext ctx;
  SilcServerCommand *cmd;
  SilcCommand command;

  if (!idata)
    return;

  /* Allocate command context. This must be free'd by the
     command routine receiving it. */
  ctx = silc_server_command_alloc();
  ctx->server = server;
  ctx->sock = sock;
  ctx->packet = packet; /* Save original packet */
  silc_packet_stream_ref(sock);

  /* Parse the command payload in the packet */
  ctx->payload = silc_command_payload_parse(packet->buffer.data,
					    silc_buffer_len(&packet->buffer));
  if (!ctx->payload) {
    SILC_LOG_ERROR(("Bad command payload"));
    silc_packet_free(packet);
    silc_packet_stream_unref(ctx->sock);
    silc_free(ctx);
    return;
  }
  ctx->args = silc_command_get_args(ctx->payload);

  /* Get the command */
  command = silc_command_get(ctx->payload);
  for (cmd = silc_command_list; cmd->cb; cmd++)
    if (cmd->cmd == command)
      break;

  if (!cmd || !cmd->cb) {
    SILC_LOG_DEBUG(("Unknown command %d", command));
    silc_server_command_send_status_reply(ctx, command,
					  SILC_STATUS_ERR_UNKNOWN_COMMAND, 0);
    silc_packet_free(packet);
    silc_packet_stream_unref(ctx->sock);
    silc_free(ctx);
    return;
  }

  /* Execute client's commands always with timeout.  Normally they are
     executed with zero (0) timeout but if client is sending command more
     frequently than once in 2 seconds, then the timeout may be 0 to 2
     seconds. */
  if (idata->conn_type == SILC_CONN_CLIENT) {
    SilcClientEntry client = silc_packet_get_context(sock);
    SilcServerCommandTimeout timeout;
    int fast;

    timeout = silc_calloc(1, sizeof(*timeout));
    timeout->ctx = ctx;
    timeout->cmd = cmd;

    if (client->last_command && (time(NULL) - client->last_command) < 2) {
      client->fast_command++;
      fast = FALSE;
    } else {
      if (client->fast_command - 2 <= 0)
	client->fast_command = 0;
      else
	client->fast_command -= 2;
      fast = TRUE;
    }

    if (!fast && ((cmd->flags & SILC_CF_LAG_STRICT) ||
		  (client->fast_command > 5 && cmd->flags & SILC_CF_LAG)))
      silc_schedule_task_add_timeout(
			    server->schedule,
			    silc_server_command_process_timeout, timeout,
			    (client->fast_command < 3 ? 0 :
			     2 - (time(NULL) - client->last_command)),
			    (client->fast_command < 3 ? 200000 : 0));
    else
      silc_schedule_task_add_timeout(server->schedule,
				     silc_server_command_process_timeout,
				     timeout, 0, 0);
    return;
  }

  /* Execute for server */

  if (!(cmd->flags & SILC_CF_REG)) {
    SILC_LOG_DEBUG(("Calling %s command", silc_get_command_name(cmd->cmd)));
    cmd->cb(ctx, NULL);
  } else if (silc_server_is_registered(server, sock, ctx, cmd->cmd)) {
    SILC_LOG_DEBUG(("Calling %s command", silc_get_command_name(cmd->cmd)));
    cmd->cb(ctx, NULL);
  } else {
    SILC_LOG_DEBUG(("Server is not registered"));
    silc_server_command_free(ctx);
  }
}

/* Allocate Command Context */

SilcServerCommandContext silc_server_command_alloc()
{
  SilcServerCommandContext ctx = silc_calloc(1, sizeof(*ctx));
  ctx->users++;
  return ctx;
}

/* Free's the command context allocated before executing the command */

void silc_server_command_free(SilcServerCommandContext ctx)
{
  ctx->users--;
  SILC_LOG_DEBUG(("Command context %p refcnt %d->%d", ctx, ctx->users + 1,
		  ctx->users));
  if (ctx->users < 1) {
    if (ctx->payload)
      silc_command_payload_free(ctx->payload);
    if (ctx->packet)
      silc_packet_free(ctx->packet);
    if (ctx->sock)
      silc_packet_stream_unref(ctx->sock);
    silc_free(ctx);
  }
}

/* Duplicate Command Context by adding reference counter. The context won't
   be free'd untill it hits zero. */

SilcServerCommandContext
silc_server_command_dup(SilcServerCommandContext ctx)
{
  ctx->users++;
  SILC_LOG_DEBUG(("Command context %p refcnt %d->%d", ctx, ctx->users - 1,
		  ctx->users));
  return ctx;
}

/* Timeout for pending command.  If reply to pending command never arrives
   this is called to free resources. */

SILC_TASK_CALLBACK(silc_server_command_pending_timeout)
{
  SilcServer server = app_context;
  SilcServerCommandPending *reply = context;
  SilcServerCommandReplyContext cmdr;
  SilcBuffer tmpreply;
  int i;

  SILC_LOG_DEBUG(("Timeout pending command %p", reply));

  /* Allocate temporary and bogus command reply context */
  cmdr = silc_calloc(1, sizeof(*cmdr));
  cmdr->server = server;
  cmdr->ident = reply->ident;

  /* Check for pending commands and mark to be exeucted */
  cmdr->callbacks =
    silc_server_command_pending_check(server, reply->reply_cmd,
				      reply->ident, &cmdr->callbacks_count);

  /* Create bogus command reply with an error inside */
  tmpreply =
    silc_command_reply_payload_encode_va(reply->reply_cmd ? reply->reply_cmd :
					 SILC_COMMAND_RESERVED,
					 SILC_STATUS_ERR_TIMEDOUT, 0,
					 reply->ident, 0);
  cmdr->payload = silc_command_payload_parse(tmpreply->data,
					     silc_buffer_len(tmpreply));
  silc_buffer_free(tmpreply);

  /* Call all callbacks. Same as SILC_SERVER_PENDING_EXEC macro. */
  for (i = 0; i < cmdr->callbacks_count; i++)
    if (cmdr->callbacks[i].callback)
      (*cmdr->callbacks[i].callback)(cmdr->callbacks[i].context, cmdr);

  silc_server_command_pending_del(server, reply->reply_cmd, reply->ident);
  silc_server_command_reply_free(cmdr);
}

/* Add new pending command to be executed when reply to a command has been
   received. The `reply_cmd' is the command that will call the `callback'
   with `context' when reply has been received.  It can be SILC_COMMAND_NONE
   to match any command with the `ident'.  If `ident' is non-zero
   the `callback' will be executed when received reply with command
   identifier `ident'. If there already exists pending command for the
   specified command, ident, callback and context this function has no
   effect. */

SilcBool silc_server_command_pending(SilcServer server,
				 SilcCommand reply_cmd,
				 SilcUInt16 ident,
				 SilcCommandCb callback,
				 void *context)
{
  return silc_server_command_pending_timed(server, reply_cmd, ident, callback,
					   context, 0);
}

/* Same as silc_server_command_pending with specific timeout for pending
   commands.  If the `timeout' is zero default timeout is used. */

SilcBool silc_server_command_pending_timed(SilcServer server,
				       SilcCommand reply_cmd,
				       SilcUInt16 ident,
				       SilcCommandCb callback,
				       void *context,
				       SilcUInt16 timeout)
{
  SilcServerCommandPending *reply;

  /* Check whether identical pending already exists for same command,
     ident, callback and callback context. If it does then it would be
     error to register it again. */
  silc_dlist_start(server->pending_commands);
  while ((reply = silc_dlist_get(server->pending_commands)) != SILC_LIST_END) {
    if (reply->reply_cmd == reply_cmd && reply->ident == ident &&
	reply->callback == callback && reply->context == context)
      return FALSE;
  }

  reply = silc_calloc(1, sizeof(*reply));
  reply->reply_cmd = reply_cmd;
  reply->ident = ident;
  reply->context = context;
  reply->callback = callback;
  reply->timeout =
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_command_pending_timeout, reply,
				   timeout ? timeout : 12, 0);
  silc_dlist_add(server->pending_commands, reply);

  return TRUE;
}

/* Deletes pending command by reply command type. */

void silc_server_command_pending_del(SilcServer server,
				     SilcCommand reply_cmd,
				     SilcUInt16 ident)
{
  SilcServerCommandPending *r;

  silc_dlist_start(server->pending_commands);
  while ((r = silc_dlist_get(server->pending_commands)) != SILC_LIST_END) {
    if ((r->reply_cmd == reply_cmd || (r->reply_cmd == SILC_COMMAND_NONE &&
                                       r->reply_check))
        && r->ident == ident) {
      silc_dlist_del(server->pending_commands, r);
      if (r->timeout)
	silc_schedule_task_del(server->schedule, r->timeout);
      silc_free(r);
    }
  }
}

/* Checks for pending commands and marks callbacks to be called from
   the command reply function. Returns TRUE if there were pending command. */

SilcServerCommandPendingCallbacks
silc_server_command_pending_check(SilcServer server,
				  SilcCommand command,
				  SilcUInt16 ident,
				  SilcUInt32 *callbacks_count)
{
  SilcServerCommandPending *r;
  SilcServerCommandPendingCallbacks callbacks = NULL;
  int i = 0;

  silc_dlist_start(server->pending_commands);
  while ((r = silc_dlist_get(server->pending_commands)) != SILC_LIST_END) {
    if ((r->reply_cmd == command || r->reply_cmd == SILC_COMMAND_NONE)
	&& r->ident == ident) {
      callbacks = silc_realloc(callbacks, sizeof(*callbacks) * (i + 1));
      callbacks[i].context = r->context;
      callbacks[i].callback = r->callback;
      r->reply_check = TRUE;
      i++;
    }
  }

  *callbacks_count = i;
  return callbacks;
}

/* Sends simple status message as command reply packet */

static void
silc_server_command_send_status_reply(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcStatus status,
				      SilcStatus error)
{
  SilcBuffer buffer;

  /* Statistics */
  cmd->server->stat.commands_sent++;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer =
    silc_command_reply_payload_encode_va(command, status, error,
					 silc_command_get_ident(cmd->payload),
					 0);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0,
			  buffer->data, silc_buffer_len(buffer));
  silc_buffer_free(buffer);
}

/* Sends command status reply with one extra argument. The argument
   type must be sent as argument. */

static void
silc_server_command_send_status_data(SilcServerCommandContext cmd,
				     SilcCommand command,
				     SilcStatus status,
				     SilcStatus error,
				     SilcUInt32 arg_type,
				     const unsigned char *arg,
				     SilcUInt32 arg_len)
{
  SilcBuffer buffer;

  /* Statistics */
  cmd->server->stat.commands_sent++;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer =
    silc_command_reply_payload_encode_va(command, status, 0,
					 silc_command_get_ident(cmd->payload),
					 1, arg_type, arg, arg_len);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0,
			  buffer->data, silc_buffer_len(buffer));
  silc_buffer_free(buffer);
}

static void
silc_server_command_send_status_data2(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcStatus status,
				      SilcStatus error,
				      SilcUInt32 arg_type1,
				      const unsigned char *arg1,
				      SilcUInt32 arg_len1,
				      SilcUInt32 arg_type2,
				      const unsigned char *arg2,
				      SilcUInt32 arg_len2)
{
  SilcBuffer buffer;

  /* Statistics */
  cmd->server->stat.commands_sent++;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer =
    silc_command_reply_payload_encode_va(command, status, 0,
					 silc_command_get_ident(cmd->payload),
					 2, arg_type1, arg1, arg_len1,
					 arg_type2, arg2, arg_len2);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0,
			  buffer->data, silc_buffer_len(buffer));
  silc_buffer_free(buffer);
}

/* This function can be called to check whether in the command reply
   an error occurred. This function has no effect if this is called
   when the command function was not called as pending command callback.
   This returns TRUE if error had occurred. */

static bool
silc_server_command_pending_error_check(SilcServerCommandContext cmd,
					SilcServerCommandReplyContext cmdr,
					SilcCommand command)
{
  if (!cmd->pending || !cmdr)
    return FALSE;

  if (!silc_command_get_status(cmdr->payload, NULL, NULL)) {
    SilcBuffer buffer;

    /* Statistics */
    cmd->server->stat.commands_sent++;

    /* Send the same command reply payload */
    silc_command_set_command(cmdr->payload, silc_command_get(cmd->payload));
    silc_command_set_ident(cmdr->payload,
			   silc_command_get_ident(cmd->payload));
    buffer = silc_command_payload_encode_payload(cmdr->payload);
    silc_server_packet_send(cmd->server, cmd->sock,
			    SILC_PACKET_COMMAND_REPLY, 0,
			    buffer->data, silc_buffer_len(buffer));
    silc_buffer_free(buffer);
    return TRUE;
  }

  return FALSE;
}

/* Server side of command WHOIS. */

SILC_SERVER_CMD_FUNC(whois)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WHOIS, cmd, 1, 256);
  silc_server_query_command(cmd->server, SILC_COMMAND_WHOIS, cmd, NULL);
  silc_server_command_free(cmd);
}

/* Server side of command WHOWAS. */

SILC_SERVER_CMD_FUNC(whowas)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WHOWAS, cmd, 1, 2);
  silc_server_query_command(cmd->server, SILC_COMMAND_WHOWAS, cmd, NULL);
  silc_server_command_free(cmd);
}

/* Server side of command IDENTIFY. */

SILC_SERVER_CMD_FUNC(identify)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_IDENTIFY, cmd, 1, 256);
  silc_server_query_command(cmd->server, SILC_COMMAND_IDENTIFY, cmd, NULL);
  silc_server_command_free(cmd);
}

/* Server side of command NICK. Sets nickname for user. Setting
   nickname causes generation of a new client ID for the client. The
   new client ID is sent to the client after changing the nickname. */

SILC_SERVER_CMD_FUNC(nick)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcServer server = cmd->server;
  SilcBuffer nidp, oidp = NULL;
  SilcClientID *new_id;
  SilcUInt32 nick_len;
  unsigned char *nick, *nickc = NULL;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_NICK, cmd, 1, 1);

  /* Get nickname */
  nick = silc_argument_get_arg_type(cmd->args, 1, &nick_len);
  if (!nick) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_BAD_NICKNAME, 0);
    goto out;
  }

  /* Truncate over long nicks */
  if (nick_len > 128) {
    nick_len = 128;
    nick[nick_len - 1] = '\0';
  }

  /* Check for valid nickname string.  This is cached, original is saved
     in the client context. */
  nickc = silc_identifier_check(nick, nick_len, SILC_STRING_UTF8, 128, NULL);
  if (!nickc) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_BAD_NICKNAME, 0);
    goto out;
  }

  /* Check for same nickname */
  if (strlen(client->nickname) == nick_len &&
      !memcmp(client->nickname, nick, nick_len)) {
    nidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    silc_free(nickc);
    goto send_reply;
  }

  /* Create new Client ID */
  if (!silc_id_create_client_id(cmd->server, cmd->server->id,
				cmd->server->rng,
				cmd->server->md5hash,
				nickc, strlen(nickc), &new_id)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_BAD_NICKNAME, 0);
    silc_free(nickc);
    goto out;
  }

  /* Send notify about nickname change to our router. We send the new
     ID and ask to replace it with the old one. If we are router the
     packet is broadcasted. Send NICK_CHANGE notify. */
  silc_server_send_notify_nick_change(server, SILC_PRIMARY_ROUTE(server),
				      SILC_BROADCAST(server), client->id,
				      new_id, nick);

  /* Check if anyone is watching the old nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, nick,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

  oidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Update client entry */
  silc_idcache_update_by_context(server->local_list->clients, client,
				 new_id, nickc, TRUE);
  silc_free(new_id);
  silc_free(client->nickname);
  client->nickname = strdup(nick);

  nidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Send NICK_CHANGE notify to the client's channels */
  silc_server_send_notify_on_channels(server, NULL, client,
				      SILC_NOTIFY_TYPE_NICK_CHANGE, 3,
				      oidp->data, silc_buffer_len(oidp),
				      nidp->data, silc_buffer_len(nidp),
				      client->nickname,
				      strlen(client->nickname));

  /* Check if anyone is watching the new nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

 send_reply:
  /* Send the new Client ID as reply command back to client */
  silc_server_send_command_reply(cmd->server, cmd->sock,
				 SILC_COMMAND_NICK,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, nidp->data, silc_buffer_len(nidp),
				 3, nick, nick_len);
  silc_buffer_free(nidp);
  if (oidp)
    silc_buffer_free(oidp);

 out:
  silc_server_command_free(cmd);
}

/* Sends the LIST command reply */

static void
silc_server_command_list_send_reply(SilcServerCommandContext cmd,
				    SilcChannelEntry *lch,
				    SilcUInt32 lch_count,
				    SilcChannelEntry *gch,
				    SilcUInt32 gch_count)
{
  int i, k;
  SilcBuffer idp;
  SilcChannelEntry entry;
  SilcStatus status;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  char *topic;
  unsigned char usercount[4];
  SilcUInt32 users;
  int valid_lcount = 0, valid_rcount = 0;

  for (i = 0; i < lch_count; i++) {
    if (lch[i]->mode & SILC_CHANNEL_MODE_SECRET)
      lch[i] = NULL;
    else
      valid_lcount++;
  }
  for (i = 0; i < gch_count; i++) {
    if (gch[i]->mode & SILC_CHANNEL_MODE_SECRET)
      gch[i] = NULL;
    else
      valid_rcount++;
  }

  if (!lch_count && !gch_count) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LIST,
					  SILC_STATUS_OK, 0);
    return;
  }

  status = SILC_STATUS_OK;
  if ((lch_count + gch_count) > 1)
    status = SILC_STATUS_LIST_START;

  /* Local list */
  for (i = 0, k = 0; i < lch_count; i++) {
    entry = lch[i];
    if (!entry)
      continue;

    if (k >= 1)
      status = SILC_STATUS_LIST_ITEM;
    if (valid_lcount > 1 && k == valid_lcount - 1 && !valid_rcount)
      status = SILC_STATUS_LIST_END;

    idp = silc_id_payload_encode(entry->id, SILC_ID_CHANNEL);

    if (entry->mode & SILC_CHANNEL_MODE_PRIVATE) {
      topic = "*private*";
      memset(usercount, 0, sizeof(usercount));
    } else {
      topic = entry->topic;
      users = silc_hash_table_count(entry->user_list);
      SILC_PUT32_MSB(users, usercount);
    }

    /* Send the reply */
    silc_server_send_command_reply(cmd->server, cmd->sock, SILC_COMMAND_LIST,
				   status, 0, ident, 4,
				   2, idp->data, silc_buffer_len(idp),
				   3, entry->channel_name,
				   strlen(entry->channel_name),
				   4, topic, topic ? strlen(topic) : 0,
				   5, usercount, 4);
    silc_buffer_free(idp);
    k++;
  }

  /* Global list */
  for (i = 0, k = 0; i < gch_count; i++) {
    entry = gch[i];
    if (!entry)
      continue;

    if (k >= 1)
      status = SILC_STATUS_LIST_ITEM;
    if (valid_rcount > 1 && k == valid_rcount - 1)
      status = SILC_STATUS_LIST_END;

    idp = silc_id_payload_encode(entry->id, SILC_ID_CHANNEL);

    if (entry->mode & SILC_CHANNEL_MODE_PRIVATE) {
      topic = "*private*";
      memset(usercount, 0, sizeof(usercount));
    } else {
      topic = entry->topic;
      users = entry->user_count;
      SILC_PUT32_MSB(users, usercount);
    }

    /* Send the reply */
    silc_server_send_command_reply(cmd->server, cmd->sock, SILC_COMMAND_LIST,
				   status, 0, ident, 4,
				   2, idp->data, silc_buffer_len(idp),
				   3, entry->channel_name,
				   strlen(entry->channel_name),
				   4, topic, topic ? strlen(topic) : 0,
				   5, usercount, 4);
    silc_buffer_free(idp);
    k++;
  }
}

/* Server side of LIST command. This lists the channel of the requested
   server. Secret channels are not listed. */

SILC_SERVER_CMD_FUNC(list)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcID id;
  SilcChannelID *channel_id = NULL;
  SilcChannelEntry *lchannels = NULL, *gchannels = NULL;
  SilcUInt32 lch_count = 0, gch_count = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LIST, cmd, 0, 1);

  /* If we are normal server, send the command to router, since we
     want to know all channels in the network. */
  if (!cmd->pending && server->server_type != SILC_ROUTER &&
      !server->standalone) {
    SilcBuffer tmpbuf;
    SilcUInt16 old_ident;

    /* Statistics */
    cmd->server->stat.commands_sent++;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    tmpbuf->data, silc_buffer_len(tmpbuf));

    /* Reprocess this packet after received reply from router */
    silc_server_command_pending(server, SILC_COMMAND_LIST,
				silc_command_get_ident(cmd->payload),
				silc_server_command_list,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;
    silc_command_set_ident(cmd->payload, old_ident);
    silc_buffer_free(tmpbuf);
    goto out;
  }

  /* Get Channel ID */
  if (silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL))
    channel_id = SILC_ID_GET_ID(id);

  /* Get the channels from local list */
  lchannels = silc_idlist_get_channels(server->local_list, channel_id,
				       &lch_count);

  /* Get the channels from global list */
  gchannels = silc_idlist_get_channels(server->global_list, channel_id,
				       &gch_count);

  /* Send the reply */
  silc_server_command_list_send_reply(cmd, lchannels, lch_count,
				      gchannels, gch_count);

  silc_free(lchannels);
  silc_free(gchannels);

 out:
  silc_server_command_free(cmd);
}

/* Server side of TOPIC command. Sets topic for channel and/or returns
   current topic to client. */

SILC_SERVER_CMD_FUNC(topic)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcID id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer idp;
  unsigned char *tmp;
  SilcUInt32 argc, tmp_len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_TOPIC, cmd, 1, 2);

  argc = silc_argument_get_arg_num(cmd->args);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Check whether the channel exists */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_TOPIC,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp, tmp_len);
      goto out;
    }
  }

  if (argc > 1) {
    /* Get the topic */
    tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
    if (!tmp) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }
    if (tmp_len > 256) {
      tmp_len = 256;
      tmp[tmp_len - 1] = '\0';
    }

    if (!silc_utf8_valid(tmp, tmp_len)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    /* See whether the client is on channel and has rights to change topic */
    if (!silc_server_client_on_channel(client, channel, &chl)) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_TOPIC,
					   SILC_STATUS_ERR_NOT_ON_CHANNEL,
					   0, 2, tmp, tmp_len);
      goto out;
    }

    if (channel->mode & SILC_CHANNEL_MODE_TOPIC &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_TOPIC,
					   SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					   0, 2, tmp, tmp_len);
      goto out;
    }

    if (!channel->topic || strcmp(channel->topic, tmp)) {
      /* Set the topic for channel */
      silc_free(channel->topic);
      channel->topic = strdup(tmp);

      /* Send TOPIC_SET notify type to the network */
      silc_server_send_notify_topic_set(server, SILC_PRIMARY_ROUTE(server),
					SILC_BROADCAST(server), channel,
					client->id, SILC_ID_CLIENT,
					channel->topic);

      /* Send notify about topic change to all clients on the channel */
      idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
					 SILC_NOTIFY_TYPE_TOPIC_SET, 2,
					 idp->data, silc_buffer_len(idp),
					 channel->topic,
					 strlen(channel->topic));
      silc_buffer_free(idp);
    }
  }

  /* Send the topic to client as reply packet */
  idp = silc_id_payload_encode(SILC_ID_GET_ID(id), SILC_ID_CHANNEL);
  silc_server_send_command_reply(cmd->server, cmd->sock, SILC_COMMAND_TOPIC,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, idp->data, silc_buffer_len(idp),
				 3, channel->topic,
				 channel->topic ?
				 strlen(channel->topic) : 0);
  silc_buffer_free(idp);

 out:
  silc_server_command_free(cmd);
}

/* Server side of INVITE command. Invites some client to join some channel.
   This command is also used to manage the invite list of the channel. */

SILC_SERVER_CMD_FUNC(invite)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcPacketStream sock = cmd->sock, dest_sock;
  SilcChannelClientEntry chl;
  SilcClientEntry sender, dest;
  SilcChannelEntry channel;
  SilcID id, id2;
  SilcIDListData idata;
  SilcArgumentPayload args;
  SilcHashTableList htl;
  SilcBuffer list, tmp2;
  SilcBufferStruct alist;
  unsigned char *tmp, *atype = NULL;
  SilcUInt32 len, len2, ttype;
  void *type;
  SilcUInt16 argc = 0, ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INVITE, cmd, 1, 4);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_INVITE,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp, len);
      goto out;
    }
  }

  /* Check whether the sender of this command is on the channel. */
  sender = silc_packet_get_context(sock);
  if (!sender || !silc_server_client_on_channel(sender, channel, &chl)) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_INVITE,
					 SILC_STATUS_ERR_NOT_ON_CHANNEL, 0,
					 2, tmp, len);
    goto out;
  }

  /* Check whether the channel is invite-only channel. If yes then the
     sender of this command must be at least channel operator. */
  if (channel->mode & SILC_CHANNEL_MODE_INVITE &&
      !(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
      !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_INVITE,
					 SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					 0, 2, tmp, len);
    goto out;
  }

  /* Get destination client ID */
  if (silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id2, NULL)) {
    SilcBool resolve;

    /* Get the client entry */
    dest = silc_server_query_client(server, SILC_ID_GET_ID(id2),
				    FALSE, &resolve);
    if (!dest) {
      if (server->server_type != SILC_SERVER || !resolve || cmd->pending) {
	tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
	silc_server_command_send_status_data(
					cmd, SILC_COMMAND_INVITE,
					SILC_STATUS_ERR_NO_SUCH_CLIENT_ID, 0,
					2, tmp, len);
	goto out;
      }

      /* The client info is being resolved. Reprocess this packet after
	 receiving the reply to the query. */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS,
				  server->cmd_ident,
				  silc_server_command_invite,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      goto out;
    }

    /* Check whether the requested client is already on the channel. */
    if (silc_server_client_on_channel(dest, channel, NULL)) {
      tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
      atype = silc_argument_get_arg_type(cmd->args, 1, &len2);
      silc_server_command_send_status_data2(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_USER_ON_CHANNEL,
					    0, 2, tmp, len,
					    3, atype, len2);
      goto out;
    }

    /* Get route to the client */
    dest_sock = silc_server_get_client_route(server, NULL, 0,
					     SILC_ID_GET_ID(id2),
					     &idata, NULL);
    if (!dest_sock) {
      tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_INVITE,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   0, 2, tmp, len);
      goto out;
    }

    /* Add the client to the invite list */

    /* Allocate hash table for invite list if it doesn't exist yet */
    if (!channel->invite_list)
      channel->invite_list =
	silc_hash_table_alloc(0, silc_hash_ptr,
			      NULL, NULL, NULL,
			      silc_server_inviteban_destruct, channel, TRUE);

    /* Check if the ID is in the list already */
    tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
    silc_hash_table_list(channel->invite_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&type, (void *)&tmp2)) {
      if (SILC_PTR_TO_32(type) == 3 && !memcmp(tmp2->data, tmp, len)) {
	tmp = NULL;
	break;
      }
    }
    silc_hash_table_list_reset(&htl);

    /* Add new Client ID to invite list */
    if (tmp) {
      list = silc_buffer_alloc_size(len);
      silc_buffer_put(list, tmp, len);
      silc_hash_table_add(channel->invite_list, (void *)3, list);
    }

    if (!(dest->mode & SILC_UMODE_BLOCK_INVITE)) {
      /* Send notify to the client that is invited to the channel */
      SilcBuffer idp, idp2;
      idp = silc_id_payload_encode(SILC_ID_GET_ID(id), SILC_ID_CHANNEL);
      idp2 = silc_id_payload_encode(sender->id, SILC_ID_CLIENT);
      silc_server_send_notify_dest(server, dest_sock, FALSE,
				   SILC_ID_GET_ID(id2), SILC_ID_CLIENT,
				   SILC_NOTIFY_TYPE_INVITE, 3,
				   idp->data, silc_buffer_len(idp),
				   channel->channel_name,
				   strlen(channel->channel_name),
				   idp2->data, silc_buffer_len(idp2));
      silc_buffer_free(idp);
      silc_buffer_free(idp2);
    }
  }

  /* Get the invite information */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &len2);
  if (tmp && len2 > 2) {
    /* Parse the arguments to see they are constructed correctly */
    SILC_GET16_MSB(argc, tmp);
    args = silc_argument_payload_parse(tmp + 2, len2 - 2, argc);
    if (!args) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    /* Get the type of action */
    atype = silc_argument_get_arg_type(cmd->args, 3, &len);
    if (atype && len == 1) {
      if (atype[0] == 0x00) {
	/* Allocate hash table for invite list if it doesn't exist yet */
	if (!channel->invite_list)
	  channel->invite_list =
	    silc_hash_table_alloc(0, silc_hash_ptr,
				  NULL, NULL, NULL,
				  silc_server_inviteban_destruct, channel,
				  TRUE);

	/* Check for resource limit */
	if (silc_hash_table_count(channel->invite_list) > 64) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
						SILC_STATUS_ERR_RESOURCE_LIMIT,
						0);
	  goto out;
	}
      }

      /* Now add or delete the information. */
      if (!silc_server_inviteban_process(server, channel->invite_list,
					 (SilcUInt8)atype[0], args)) {
	silc_server_command_send_status_reply(
				    cmd, SILC_COMMAND_INVITE,
				    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
				    0);
	goto out;
      }
    }
    silc_argument_payload_free(args);
  }

  /* Encode invite list */
  list = NULL;
  if (channel->invite_list && silc_hash_table_count(channel->invite_list)) {
    list = silc_buffer_alloc_size(2);
    silc_buffer_format(list,
		       SILC_STR_UI_SHORT(silc_hash_table_count(
					  channel->invite_list)),
		       SILC_STR_END);
    silc_hash_table_list(channel->invite_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&type, (void *)&tmp2))
      list = silc_argument_payload_encode_one(list, tmp2->data,
					      silc_buffer_len(tmp2),
					      SILC_PTR_TO_32(type));
    silc_hash_table_list_reset(&htl);
  }

  /* The notify is sent to local servers (not clients), and to network. */
  if (atype && tmp && len2) {
    silc_buffer_set(&alist, tmp, len2);

    /* Send to local servers if we are router */
    if (server->server_type == SILC_ROUTER) {
      SilcBuffer idp, idp2;
      idp = silc_id_payload_encode(SILC_ID_GET_ID(id), SILC_ID_CHANNEL);
      idp2 = silc_id_payload_encode(sender->id, SILC_ID_CLIENT);
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, FALSE,
                                         SILC_NOTIFY_TYPE_INVITE, 5,
					 idp->data, silc_buffer_len(idp),
					 channel->channel_name,
					 strlen(channel->channel_name),
					 idp2->data, silc_buffer_len(idp2),
					 atype, 1,
					 tmp ? alist.data : NULL,
					 tmp ? silc_buffer_len(&alist) : 0);
      silc_buffer_free(idp);
      silc_buffer_free(idp2);
    }

    /* Send to network */
    silc_server_send_notify_invite(server, SILC_PRIMARY_ROUTE(server),
				   SILC_BROADCAST(server), channel,
				   sender->id, atype,
				   tmp ? &alist : NULL);
  }

  /* Send invite list back only if the list was modified, or no arguments
     was given. */
  ttype = 0;
  argc = silc_argument_get_arg_num(cmd->args);
  if (argc == 1)
    ttype = 1;
  if (silc_argument_get_arg_type(cmd->args, 3, &len))
    ttype = 1;

  /* Send command reply */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_INVITE,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, tmp, len,
				 3, ttype && list ?
				 list->data : NULL,
				 ttype && list ? silc_buffer_len(list) : 0);
  silc_buffer_free(list);

 out:
  silc_server_command_free(cmd);
}

typedef struct {
  SilcPacketStream sock;
  char *signoff;
} *QuitInternal;

/* Quits connection to client. This gets called if client won't
   close the connection even when it has issued QUIT command. */

SILC_TASK_CALLBACK(silc_server_command_quit_cb)
{
  SilcServer server = app_context;
  QuitInternal q = (QuitInternal)context;
  SilcClientEntry client = silc_packet_get_context(q->sock);

  if (client) {
    /* Free all client specific data, such as client entry and entires
       on channels this client may be on. */
    silc_server_free_sock_user_data(server, q->sock, q->signoff);
    silc_server_close_connection(server, q->sock);
  }

  silc_packet_stream_unref(q->sock);
  silc_free(q->signoff);
  silc_free(q);
}

/* Quits SILC session. This is the normal way to disconnect client. */

SILC_SERVER_CMD_FUNC(quit)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcPacketStream sock = cmd->sock;
  SilcClientEntry client = silc_packet_get_context(sock);
  QuitInternal q;
  unsigned char *tmp = NULL;
  SilcUInt32 len = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_QUIT, cmd, 0, 1);

  if (client->data.conn_type != SILC_CONN_CLIENT)
    goto out;

  /* Get message */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (len > 128)
    tmp = NULL;

  q = silc_calloc(1, sizeof(*q));
  q->sock = sock;
  q->signoff = tmp ? strdup(tmp) : NULL;
  silc_packet_stream_ref(q->sock);

  /* We quit the connection with little timeout */
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_command_quit_cb, (void *)q,
				 0, 200000);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command KILL. This command is used by router operator
   to remove an client from the SILC Network temporarily. */

SILC_SERVER_CMD_FUNC(kill)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcClientEntry remote_client;
  SilcID id;
  unsigned char *tmp, *comment, *auth;
  SilcUInt32 tmp_len, tmp_len2, auth_len;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_KILL, cmd, 1, 3);

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  /* Get authentication payload if present */
  auth = silc_argument_get_arg_type(cmd->args, 3, &auth_len);

  if (!auth) {
    /* Router operator killing */

    /* KILL command works only on router */
    if (server->server_type != SILC_ROUTER) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					    SILC_STATUS_ERR_NO_ROUTER_PRIV, 0);
      goto out;
    }

    /* Check whether client has the permissions. */
    if (!(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					    SILC_STATUS_ERR_NO_ROUTER_PRIV, 0);
      goto out;
    }
  }

  /* Get the client ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }

  /* Get the client entry */
  remote_client = silc_idlist_find_client_by_id(server->local_list,
						SILC_ID_GET_ID(id),
						TRUE, NULL);
  if (!remote_client) {
    remote_client = silc_idlist_find_client_by_id(server->global_list,
						  SILC_ID_GET_ID(id),
						  TRUE, NULL);
    if (!remote_client) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_KILL,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   0, 2, tmp, tmp_len);
      goto out;
    }
  }

  /* Get comment */
  comment = silc_argument_get_arg_type(cmd->args, 2, &tmp_len2);
  if (comment && tmp_len2 > 128) {
    tmp_len2 = 128;
    comment[tmp_len2 - 1] = '\0';
  }

  /* If authentication data is provided then verify that killing is
     actually allowed */
  if (auth && auth_len) {
    SilcPacketStream sock;

    if (!SILC_IS_LOCAL(remote_client) || !remote_client->data.public_key) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					    SILC_STATUS_ERR_OPERATION_ALLOWED,
					    0);
      goto out;
    }

    /* Verify the signature */
    if (!silc_auth_verify_data(auth, auth_len, SILC_AUTH_PUBLIC_KEY,
			       remote_client->data.public_key, 0,
			       server->sha1hash, remote_client->id,
			       SILC_ID_CLIENT)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					    SILC_STATUS_ERR_AUTH_FAILED, 0);
      goto out;
    }

    /* Send reply to the sender */
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_KILL,
					 SILC_STATUS_OK, 0,
					 2, tmp, tmp_len);

    /* Do normal signoff for the destination client */
    sock = remote_client->connection;

    if (sock)
      silc_packet_stream_ref(sock);

    silc_server_remove_from_channels(server, NULL, remote_client,
				     TRUE, (char *)"Killed", TRUE, TRUE);
    silc_server_free_sock_user_data(server, sock, comment ? comment :
				    (unsigned char *)"Killed");
    if (sock) {
      silc_packet_set_context(sock, NULL);
      silc_server_close_connection(server, sock);
      silc_packet_stream_unref(sock);
    }
  } else {
    /* Router operator killing */

    /* Send reply to the sender */
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_KILL,
					 SILC_STATUS_OK, 0,
					 2, tmp, tmp_len);

    /* Check if anyone is watching this nickname */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_KILLED);

    /* Now do the killing */
    silc_server_kill_client(server, remote_client, comment, client->id,
			    SILC_ID_CLIENT);
  }

 out:
  silc_server_command_free(cmd);
}

/* Server side of command INFO. This sends information about us to
   the client. If client requested specific server we will send the
   command to that server. */

SILC_SERVER_CMD_FUNC(info)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcBuffer idp;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  char *dest_server = NULL, *server_info = NULL, *server_name;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcServerEntry entry = NULL;
  SilcID id;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INFO, cmd, 0, 2);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (dest_server) {
    /* Check server name. */
    dest_server = silc_identifier_check(dest_server, strlen(dest_server),
					SILC_STRING_UTF8, 256, &tmp_len);
    if (!dest_server) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					    SILC_STATUS_ERR_BAD_SERVER, 0);
      goto out;
    }
  }

  /* Get Server ID */
  if (silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    /* Check whether we have this server cached */
    entry = silc_idlist_find_server_by_id(server->local_list,
					  SILC_ID_GET_ID(id), TRUE, NULL);
    if (!entry) {
      entry = silc_idlist_find_server_by_id(server->global_list,
					    SILC_ID_GET_ID(id), TRUE, NULL);
      if (!entry && server->server_type != SILC_SERVER) {
	tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
	silc_server_command_send_status_data(cmd, SILC_COMMAND_INFO,
					     SILC_STATUS_ERR_NO_SUCH_SERVER_ID,
					     0, 2, tmp, tmp_len);
	goto out;
      }
    }
  }

  if ((!dest_server && !entry) || (entry && entry == server->id_entry) ||
      (dest_server && !cmd->pending &&
       !memcmp(dest_server, server->server_name, strlen(dest_server)))) {
    /* Send our reply */
    char info_string[256];

    memset(info_string, 0, sizeof(info_string));
    silc_snprintf(info_string, sizeof(info_string),
		  "location: %s server: %s admin: %s <%s> version: %s",
		  server->config->server_info->location,
		  server->config->server_info->server_type,
		  server->config->server_info->admin,
		  server->config->server_info->email,
		  silc_dist_version);

    server_info = info_string;
    entry = server->id_entry;
  } else {
    /* Check whether we have this server cached */
    if (!entry && dest_server) {
      entry = silc_idlist_find_server_by_name(server->global_list,
					      dest_server, TRUE, NULL);
      if (!entry) {
	entry = silc_idlist_find_server_by_name(server->local_list,
						dest_server, TRUE, NULL);
      }
    }

    if (!cmd->pending &&
	server->server_type != SILC_SERVER && entry && !entry->server_info) {
      /* Send to the server */
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, entry->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_INFO,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_info,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }

    if (!entry && !cmd->pending && !server->standalone) {
      /* Send to the primary router */
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_INFO,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_info,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }
  }

  if (!entry) {
    if (dest_server) {
      silc_free(dest_server);
      dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_INFO,
					   SILC_STATUS_ERR_NO_SUCH_SERVER, 0,
					   2, dest_server,
					   strlen(dest_server));
      dest_server = NULL;
    }
    goto out;
  }

  idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
  if (!server_info)
    server_info = entry->server_info;
  server_name = entry->server_name;

  /* Send the reply */
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_INFO,
				 SILC_STATUS_OK, 0, ident, 3,
				 2, idp->data, silc_buffer_len(idp),
				 3, server_name,
				 strlen(server_name),
				 4, server_info,
				 server_info ?
				 strlen(server_info) : 0);
  silc_buffer_free(idp);

 out:
  silc_free(dest_server);
  silc_server_command_free(cmd);
}

/* Server side of command PING. This just replies to the ping. */

SILC_SERVER_CMD_FUNC(ping)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcUInt32 tmp_len;
  unsigned char *tmp;
  SilcID id;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_PING, cmd, 1, 1);

  /* Get Server ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  if (SILC_ID_SERVER_COMPARE(SILC_ID_GET_ID(id), server->id)) {
    /* Send our reply */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_OK, 0);
  } else {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_PING,
					 SILC_STATUS_ERR_NO_SUCH_SERVER_ID, 0,
					 2, tmp, tmp_len);
    goto out;
  }

 out:
  silc_server_command_free(cmd);
}

/* Server side of command STATS. */

SILC_SERVER_CMD_FUNC(stats)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcID id;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBuffer packet, stats;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcUInt32 uptime;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_STATS, cmd, 1, 1);

  /* Get Server ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_STATS,
					  SILC_STATUS_ERR_NO_SERVER_ID, 0);
    goto out;
  }

  SILC_LOG_DEBUG(("id %s", silc_id_render(SILC_ID_GET_ID(id),
					  id.type)));

  /* The ID must be ours */
  if (!SILC_ID_SERVER_COMPARE(server->id, SILC_ID_GET_ID(id))) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_STATS,
					 SILC_STATUS_ERR_NO_SUCH_SERVER_ID, 0,
					 2, tmp, tmp_len);
    goto out;
  }

  /* If we are router then just send everything we got. If we are normal
     server then we'll send this to our router to get all the latest
     statistical information. */
  if (!cmd->pending && server->server_type != SILC_ROUTER &&
      !server->standalone) {
    SilcBuffer idp;

    /* Statistics */
    cmd->server->stat.commands_sent++;

    /* Send request to our router */
    idp = silc_id_payload_encode(server->router->id,
				 SILC_ID_SERVER);
    packet = silc_command_payload_encode_va(SILC_COMMAND_STATS,
					    ++server->cmd_ident, 1,
					    1, idp->data,
					    silc_buffer_len(idp));
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, 0, packet->data,
			    silc_buffer_len(packet));

    /* Reprocess this packet after received reply from router */
    silc_server_command_pending(server, SILC_COMMAND_STATS,
				server->cmd_ident,
				silc_server_command_stats,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;
    silc_buffer_free(packet);
    silc_buffer_free(idp);
    goto out;
  }

  /* Send our reply to sender */
  uptime = time(NULL) - server->starttime;

  stats = silc_buffer_alloc_size(60);
  silc_buffer_format(stats,
		     SILC_STR_UI_INT(server->starttime),
		     SILC_STR_UI_INT(uptime),
		     SILC_STR_UI_INT(server->stat.my_clients),
		     SILC_STR_UI_INT(server->stat.my_channels),
		     SILC_STR_UI_INT(server->stat.my_server_ops),
		     SILC_STR_UI_INT(server->stat.my_router_ops),
		     SILC_STR_UI_INT(server->stat.cell_clients),
		     SILC_STR_UI_INT(server->stat.cell_channels),
		     SILC_STR_UI_INT(server->stat.cell_servers),
		     SILC_STR_UI_INT(server->stat.clients),
		     SILC_STR_UI_INT(server->stat.channels),
		     SILC_STR_UI_INT(server->stat.servers),
		     SILC_STR_UI_INT(server->stat.routers),
		     SILC_STR_UI_INT(server->stat.server_ops),
		     SILC_STR_UI_INT(server->stat.router_ops),
		     SILC_STR_END);

  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_STATS,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, tmp, tmp_len,
				 3, stats->data, silc_buffer_len(stats));
  silc_buffer_free(stats);

 out:
  silc_server_command_free(cmd);
}

/* Internal routine to join channel. The channel sent to this function
   has been either created or resolved from ID lists. This joins the sent
   client to the channel. */

static void silc_server_command_join_channel(SilcServer server,
					     SilcServerCommandContext cmd,
					     SilcChannelEntry channel,
					     SilcClientID *client_id,
					     SilcBool created,
					     SilcBool create_key,
					     SilcUInt32 umode,
					     const unsigned char *auth,
					     SilcUInt32 auth_len,
					     const unsigned char *cauth,
					     SilcUInt32 cauth_len)
{
  SilcPacketStream sock = cmd->sock;
  SilcIDListData idata = silc_packet_get_context(sock);
  unsigned char *tmp;
  SilcUInt32 tmp_len, user_count;
  unsigned char *passphrase = NULL, mode[4], tmp2[4], tmp3[4], ulimit[4];
  SilcClientEntry client;
  SilcChannelClientEntry chl;
  SilcBuffer reply, chidp, clidp, keyp = NULL;
  SilcBuffer user_list, mode_list, invite_list, ban_list;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  char check[512], check2[512];
  void *plen;
  SilcBool founder = FALSE;
  SilcBool resolve;
  SilcBuffer fkey = NULL, chpklist = NULL;
  const char *cipher, *hostname, *ip;

  SILC_LOG_DEBUG(("Joining client to channel"));

  if (!channel)
    return;

  silc_socket_stream_get_info(silc_packet_stream_get_stream(sock),
			      NULL, &hostname, &ip, NULL);

  /* Get the client entry */
  if (idata->conn_type == SILC_CONN_CLIENT) {
    client = (SilcClientEntry)idata;
    if (!client)
      return;
  } else {
    client = silc_server_query_client(server, client_id, FALSE,
				      &resolve);
    if (!client) {
      if (!resolve || cmd->pending) {
	tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
	silc_server_command_send_status_data(
					 cmd, SILC_COMMAND_JOIN,
					 SILC_STATUS_ERR_NO_SUCH_CLIENT_ID, 0,
					 2, tmp, tmp_len);
	goto out;
      }

      /* The client info is being resolved. Reprocess this packet after
	 receiving the reply to the query. */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS,
				  server->cmd_ident,
				  silc_server_command_join,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      goto out;
    }

    if (!client->data.public_key &&
	(auth || cauth || channel->ban_list ||
	 (channel->mode & SILC_CHANNEL_MODE_INVITE))) {
      if (cmd->pending == 2)
	goto out;

      /* We must retrieve the client's public key by sending
	 GETKEY command. Reprocess this packet after receiving the key */
      clidp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
      silc_server_send_command(server, cmd->sock,
			       SILC_COMMAND_GETKEY, ++server->cmd_ident,
			       1, 1, clidp->data, silc_buffer_len(clidp));
      silc_buffer_free(clidp);
      silc_server_command_pending(server, SILC_COMMAND_GETKEY,
				  server->cmd_ident,
				  silc_server_command_join,
				  silc_server_command_dup(cmd));
      cmd->pending = 2;
      goto out;
    }

    cmd->pending = FALSE;
  }

  /*
   * Check founder auth payload if provided.  If client can gain founder
   * privileges it can override various conditions on joining the channel,
   * and can have directly the founder mode set on the channel.
   */
  if (auth && auth_len && channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
    SilcIDListData idata = (SilcIDListData)client;
    SilcChannelClientEntry chl2;
    SilcHashTableList htl;

    if (channel->founder_key && idata->public_key &&
	silc_pkcs_public_key_compare(channel->founder_key,
				     idata->public_key)) {
      /* Check whether the client is to become founder */
      if (silc_auth_verify_data(auth, auth_len, SILC_AUTH_PUBLIC_KEY,
				channel->founder_key, 0, server->sha1hash,
				client->id, SILC_ID_CLIENT)) {

	/* There cannot be anyone else as founder on the channel now.  This
	   client is definitely the founder due to this authentication */
	silc_hash_table_list(channel->user_list, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chl2))
	  if (chl2->mode & SILC_CHANNEL_UMODE_CHANFO) {
	    chl2->mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	    silc_server_force_cumode_change(server, NULL, channel, chl2,
					    chl2->mode);
	    break;
	  }
	silc_hash_table_list_reset(&htl);

	umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	founder = TRUE;
      }
    }
  }

  /*
   * Check channel modes
   */

  if (!umode) {
    memset(check, 0, sizeof(check));
    memset(check2, 0, sizeof(check2));
    silc_strncat(check, sizeof(check),
		 client->nickname, strlen(client->nickname));
    silc_strncat(check, sizeof(check), "!", 1);
    silc_strncat(check, sizeof(check),
		 client->username, strlen(client->username));
    if (!strchr(client->username, '@')) {
      silc_strncat(check, sizeof(check), "@", 1);
      silc_strncat(check, sizeof(check),
		   hostname, strlen(hostname));
    }

    silc_strncat(check2, sizeof(check2),
		 client->nickname, strlen(client->nickname));
    if (!strchr(client->nickname, '@')) {
      silc_strncat(check2, sizeof(check2), "@", 1);
      silc_strncat(check2, sizeof(check2),
		   SILC_IS_LOCAL(client) ? server->server_name :
		   client->router->server_name,
		   SILC_IS_LOCAL(client) ? strlen(server->server_name) :
		   strlen(client->router->server_name));
    }
    silc_strncat(check2, sizeof(check2), "!", 1);
    silc_strncat(check2, sizeof(check2),
		 client->username, strlen(client->username));
    if (!strchr(client->username, '@')) {
      silc_strncat(check2, sizeof(check2), "@", 1);
      silc_strncat(check2, sizeof(check2),
		   hostname, strlen(hostname));
    }

    /* Check invite list if channel is invite-only channel */
    if (channel->mode & SILC_CHANNEL_MODE_INVITE) {
      if (!channel->invite_list ||
	  !silc_hash_table_count(channel->invite_list) ||
	  (!silc_server_inviteban_match(server, channel->invite_list,
					3, client->id) &&
	   !silc_server_inviteban_match(server, channel->invite_list,
					2, client->data.public_key) &&
	   !silc_server_inviteban_match(server, channel->invite_list,
					1, client->nickname) &&
	   !silc_server_inviteban_match(server, channel->invite_list,
					1, check) &&
	   !silc_server_inviteban_match(server, channel->invite_list,
					1, check2))) {
	chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
	silc_server_command_send_status_data(cmd, SILC_COMMAND_JOIN,
					     SILC_STATUS_ERR_NOT_INVITED, 0,
					     2, chidp->data,
					     silc_buffer_len(chidp));
	silc_buffer_free(chidp);
	goto out;
      }
    }

    /* Check ban list if it exists. If the client's nickname, server,
       username and/or hostname is in the ban list the access to the
       channel is denied. */
    if (channel->ban_list && silc_hash_table_count(channel->ban_list)) {
      if (silc_server_inviteban_match(server, channel->ban_list,
				      3, client->id) ||
	  silc_server_inviteban_match(server, channel->ban_list,
				      2, client->data.public_key) ||
	  silc_server_inviteban_match(server, channel->ban_list,
				      1, client->nickname) ||
	  silc_server_inviteban_match(server, channel->ban_list,
				      1, check) ||
	  silc_server_inviteban_match(server, channel->ban_list,
				      1, check2)) {
	chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
	silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_BANNED_FROM_CHANNEL, 0,
				      2, chidp->data,
				      silc_buffer_len(chidp));
	silc_buffer_free(chidp);
	goto out;
      }
    }

    /* Check user count limit if set. */
    if (channel->mode & SILC_CHANNEL_MODE_ULIMIT) {
      if (silc_hash_table_count(channel->user_list) + 1 >
	  channel->user_limit) {
	chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
	silc_server_command_send_status_data(cmd, SILC_COMMAND_JOIN,
					     SILC_STATUS_ERR_CHANNEL_IS_FULL,
					     0, 2, chidp->data,
					     silc_buffer_len(chidp));
	silc_buffer_free(chidp);
	goto out;
      }
    }
  }

  /* Check the channel passphrase if set. */
  if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
    /* Get passphrase */
    tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
    if (tmp)
      passphrase = silc_memdup(tmp, tmp_len);

    if (!passphrase || !channel->passphrase ||
	strlen(channel->passphrase) != strlen(passphrase) ||
        memcmp(passphrase, channel->passphrase, strlen(channel->passphrase))) {
      chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_JOIN,
					   SILC_STATUS_ERR_BAD_PASSWORD, 0,
					   2, chidp->data,
					   silc_buffer_len(chidp));
      silc_buffer_free(chidp);
      goto out;
    }
  }

  /* Verify channel authentication with channel public keys if set. */
  if (channel->mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
    if (!silc_server_verify_channel_auth(server, channel, client->id,
					 cauth, cauth_len)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_PERM_DENIED, 0);
      goto out;
    }
  }

  /*
   * Client is allowed to join to the channel. Make it happen.
   */

  /* Check whether the client already is on the channel */
  if (silc_server_client_on_channel(client, channel, NULL)) {
    clidp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
    chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
    silc_server_command_send_status_data2(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_USER_ON_CHANNEL, 0,
					  2, clidp->data,
					  silc_buffer_len(clidp),
					  3, chidp->data,
					  silc_buffer_len(chidp));
    silc_buffer_free(clidp);
    silc_buffer_free(chidp);
    goto out;
  }

  /* Generate new channel key as protocol dictates */
  if (create_key) {
    if (!silc_server_create_channel_key(server, channel, 0))
      goto out;

    /* Send the channel key. This is broadcasted to the channel but is not
       sent to the client who is joining to the channel. */
    if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY))
      silc_server_send_channel_key(server, NULL, channel,
				   server->server_type == SILC_ROUTER ?
				   FALSE : !server->standalone);
  }

  /* Join the client to the channel by adding it to channel's user list.
     Add also the channel to client entry's channels list for fast cross-
     referencing. */
  chl = silc_calloc(1, sizeof(*chl));
  chl->mode = umode;
  chl->client = client;
  chl->channel = channel;
  silc_hash_table_add(channel->user_list, client, chl);
  silc_hash_table_add(client->channels, channel, chl);
  channel->user_count++;
  channel->disabled = FALSE;

  /* Get users on the channel */
  silc_server_get_users_on_channel(server, channel, &user_list, &mode_list,
				   &user_count);

  /* Encode Client ID Payload of the original client who wants to join */
  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Encode command reply packet */
  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(channel->mode, mode);
  SILC_PUT32_MSB(created, tmp2);
  SILC_PUT32_MSB(user_count, tmp3);
  if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
    SILC_PUT32_MSB(channel->user_limit, ulimit);

  if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
    unsigned char cid[32];
    SilcUInt32 cid_len;
    silc_id_id2str(channel->id, SILC_ID_CHANNEL, cid, sizeof(cid), &cid_len);
    cipher = silc_cipher_get_name(channel->send_key);
    keyp = silc_channel_key_payload_encode(cid_len, cid,
					   strlen(cipher), cipher,
					   channel->key_len / 8, channel->key);
  }

  if (channel->founder_key)
    fkey = silc_public_key_payload_encode(channel->founder_key);

  /* Encode invite list */
  invite_list = NULL;
  if (channel->invite_list && silc_hash_table_count(channel->invite_list)) {
    SilcHashTableList htl;

    invite_list = silc_buffer_alloc_size(2);
    silc_buffer_format(invite_list,
		       SILC_STR_UI_SHORT(silc_hash_table_count(
					  channel->invite_list)),
		       SILC_STR_END);

    silc_hash_table_list(channel->invite_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&plen, (void *)&reply))
      invite_list = silc_argument_payload_encode_one(invite_list,
						     reply->data,
						     silc_buffer_len(reply),
						     SILC_PTR_TO_32(plen));
    silc_hash_table_list_reset(&htl);
  }

  /* Encode ban list */
  ban_list = NULL;
  if (channel->ban_list && silc_hash_table_count(channel->ban_list)) {
    SilcHashTableList htl;

    ban_list = silc_buffer_alloc_size(2);
    silc_buffer_format(ban_list,
		       SILC_STR_UI_SHORT(silc_hash_table_count(
					  channel->ban_list)),
		       SILC_STR_END);

    silc_hash_table_list(channel->ban_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&plen, (void *)&reply))
      ban_list = silc_argument_payload_encode_one(ban_list,
						  reply->data,
						  silc_buffer_len(reply),
						  SILC_PTR_TO_32(plen));
    silc_hash_table_list_reset(&htl);
  }

  if (channel->channel_pubkeys)
    chpklist = silc_server_get_channel_pk_list(server, channel, FALSE, FALSE);

  reply =
    silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					 SILC_STATUS_OK, 0, ident, 16,
					 2, channel->channel_name,
					 strlen(channel->channel_name),
					 3, chidp->data,
					 silc_buffer_len(chidp),
					 4, clidp->data,
					 silc_buffer_len(clidp),
					 5, mode, 4,
					 6, tmp2, 4,
					 7, keyp ? keyp->data : NULL,
					 keyp ? silc_buffer_len(keyp) : 0,
					 8, ban_list ? ban_list->data : NULL,
					 ban_list ?
					 silc_buffer_len(ban_list): 0,
					 9, invite_list ? invite_list->data :
					 NULL,
					 invite_list ?
					 silc_buffer_len(invite_list) : 0,
					 10, channel->topic,
					 channel->topic ?
					 strlen(channel->topic) : 0,
					 11, silc_hmac_get_name(channel->hmac),
					 strlen(silc_hmac_get_name(channel->
								   hmac)),
					 12, tmp3, 4,
					 13, user_list->data,
					 silc_buffer_len(user_list),
					 14, mode_list->data,
					 silc_buffer_len(mode_list),
					 15, fkey ? fkey->data : NULL,
					 fkey ? silc_buffer_len(fkey) : 0,
					 16, chpklist ? chpklist->data : NULL,
					 chpklist ? silc_buffer_len(chpklist) : 0,
					 17, (channel->mode &
					      SILC_CHANNEL_MODE_ULIMIT ?
					      ulimit : NULL),
					 (channel->mode &
					  SILC_CHANNEL_MODE_ULIMIT ?
					  sizeof(ulimit) : 0));

  /* Send command reply */
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0,
			  reply->data, silc_buffer_len(reply));

  /* Statistics */
  cmd->server->stat.commands_sent++;

  /* Send JOIN notify to locally connected clients on the channel. If
     we are normal server then router will send or have sent JOIN notify
     already. However since we've added the client already to our channel
     we'll ignore it (in packet_receive.c) so we must send it here. If
     we are router then this will send it to local clients and local
     servers. */
  SILC_LOG_DEBUG(("Send JOIN notify to channel"));
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
				     SILC_NOTIFY_TYPE_JOIN, 2,
				     clidp->data, silc_buffer_len(clidp),
				     chidp->data, silc_buffer_len(chidp));

  /* Update statistics */
  server->stat.my_chanclients++;
  if (server->server_type == SILC_ROUTER) {
    server->stat.cell_chanclients++;
    server->stat.chanclients++;
  }

  if (!cmd->pending) {
    /* Send JOIN notify packet to our primary router */
    silc_server_send_notify_join(server, SILC_PRIMARY_ROUTE(server),
				 SILC_BROADCAST(server), channel, client->id);

    if (keyp)
      /* Distribute the channel key to all backup routers. */
      silc_server_backup_send(server, NULL, SILC_PACKET_CHANNEL_KEY, 0,
			      keyp->data, silc_buffer_len(keyp), FALSE, TRUE);

    /* If client became founder by providing correct founder auth data
       notify the mode change to the channel. */
    if (founder) {
      SILC_PUT32_MSB(chl->mode, mode);
      SILC_LOG_DEBUG(("Send CUMODE_CHANGE notify to channel"));
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
					 SILC_NOTIFY_TYPE_CUMODE_CHANGE, 4,
					 clidp->data,
					 silc_buffer_len(clidp),
					 mode, 4, clidp->data,
					 silc_buffer_len(clidp),
					 fkey ? fkey->data : NULL,
					 fkey ? silc_buffer_len(fkey) : 0);
    }
  }

  /* Set CUMODE notify type to network */
  if (founder)
    silc_server_send_notify_cumode(server, SILC_PRIMARY_ROUTE(server),
				   SILC_BROADCAST(server), channel,
				   chl->mode, client->id, SILC_ID_CLIENT,
				   client->id, channel->founder_key);

  silc_buffer_free(reply);
  silc_buffer_free(clidp);
  silc_buffer_free(chidp);
  silc_buffer_free(keyp);
  silc_buffer_free(user_list);
  silc_buffer_free(mode_list);
  silc_buffer_free(fkey);
  silc_buffer_free(chpklist);
  silc_buffer_free(invite_list);
  silc_buffer_free(ban_list);

 out:
  if (passphrase)
    memset(passphrase, 0, strlen(passphrase));
  silc_free(passphrase);
}

/* Server side of command JOIN. Joins client into requested channel. If
   the channel does not exist it will be created. */

void silc_server_command_join_connected(SilcServer server,
					SilcServerEntry server_entry,
					void *context)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;

  if (!server_entry) {
    SilcUInt32 tmp_len;
    unsigned char *tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    char serv[256 + 1];

    SILC_LOG_DEBUG(("Connecting to router failed"));
    silc_parse_userfqdn(tmp, NULL, 0, serv, sizeof(serv));

    if (serv[0]) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_JOIN,
					   SILC_STATUS_ERR_NO_SUCH_SERVER, 0,
					   2, serv, strlen(serv));
    } else {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_JOIN,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL, 0,
					   2, tmp, tmp_len);
    }
    silc_server_command_free(cmd);
    return;
  }

  /* Reprocess command */
  SILC_LOG_DEBUG(("Reprocess JOIN after connecting to router"));
  silc_server_command_join(cmd, NULL);
}

SILC_SERVER_CMD_FUNC(join)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcIDListData idata = silc_packet_get_context(cmd->sock);
  unsigned char *auth, *cauth;
  SilcUInt32 tmp_len, auth_len, cauth_len;
  char *tmp, *channel_name, *channel_namec = NULL, *cipher, *hmac;
  char parsed[256 + 1], serv[256 + 1];
  SilcChannelEntry channel;
  SilcUInt32 umode = 0;
  SilcBool created = FALSE, create_key = TRUE;
  SilcID id;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_JOIN, cmd, 2, 7);

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Truncate over long channel names */
  if (tmp_len > 256) {
    tmp_len = 256;
    tmp[tmp_len - 1] = '\0';
  }

  /* Parse server name from the channel name */
  silc_parse_userfqdn(tmp, parsed, sizeof(parsed), serv,
		      sizeof(serv));
  channel_name = parsed;

  if (server->config->dynamic_server) {
    /* If server name is not specified but local channels is FALSE then the
       channel will be global, based on our router name. */
    if (!serv[0] && !server->config->local_channels) {
      if (!server->standalone) {
	silc_snprintf(serv, sizeof(serv), server->router->server_name);
      } else {
	SilcServerConfigRouter *router;
	router = silc_server_config_get_primary_router(server);
	if (router) {
	  /* Create connection to primary router */
	  SILC_LOG_DEBUG(("Create dynamic connection to primary router %s:%d",
			  router->host, router->port));
	  silc_server_create_connection(server, FALSE, TRUE,
				        router->host, router->port,
				        silc_server_command_join_connected,
					cmd);
	  return;
      	}
      }
    }

    /* If server name is ours, ignore it. */
    if (serv[0] && silc_utf8_strcasecmp(serv, server->server_name))
      memset(serv, 0, sizeof(serv));

    /* Create connection */
    if (serv[0] && server->standalone) {
      SilcServerConfigRouter *router;
      router = silc_server_config_get_primary_router(server);
      if (router) {
	/* Create connection to primary router */
	SILC_LOG_DEBUG(("Create dynamic connection to primary router %s:%d",
			router->host, router->port));
	silc_server_create_connection(server, FALSE, TRUE,
				      router->host, router->port,
				      silc_server_command_join_connected, cmd);
	return;
      }
    }
  }

  /* Check for valid channel name.  This is cached, the original is saved
     in the channel context. */
  channel_namec = silc_channel_name_check(channel_name, strlen(channel_name),
					  SILC_STRING_UTF8, 256, NULL);
  if (!channel_namec) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_BAD_CHANNEL, 0);
    goto out;
  }

  /* Get Client ID of the client who is joining to the channel */
  if (!silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NO_CLIENT_ID,
					  0);
    goto out;
  }
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);

  /* Get cipher, hmac name and auth payload */
  cipher = silc_argument_get_arg_type(cmd->args, 4, NULL);
  hmac = silc_argument_get_arg_type(cmd->args, 5, NULL);
  auth = silc_argument_get_arg_type(cmd->args, 6, &auth_len);
  cauth = silc_argument_get_arg_type(cmd->args, 7, &cauth_len);

  /* See if the channel exists */
  channel = silc_idlist_find_channel_by_name(server->local_list,
					     channel_namec, NULL);

  if (idata->conn_type == SILC_CONN_CLIENT) {
    SilcClientEntry entry = (SilcClientEntry)idata;
    if (!entry) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

#ifndef SILC_DIST_INPLACE
    /* Limit how many channels client can join */
    if (!cmd->pending && entry->channels &&
	silc_hash_table_count(entry->channels) >=
	server->config->param.chlimit) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_RESOURCE_LIMIT,
					    0);
      goto out;
    }
#endif /* SILC_DIST_INPLACE */

    if (!channel ||
	(channel->disabled && server->server_type != SILC_ROUTER)) {
      /* Channel not found or not valid */

      /* If we are standalone server we don't have a router, we just create
	 the channel by ourselves (unless it existed). */
      if (server->standalone) {
	if (!channel) {
	  channel = silc_server_create_new_channel(server, server->id, cipher,
						   hmac, channel_name, TRUE);
	  if (!channel) {
	    if (cipher) {
	      silc_server_command_send_status_data(
				cmd, SILC_COMMAND_JOIN,
				SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				0, 2, cipher, strlen(cipher));
	    } else if (hmac) {
	      silc_server_command_send_status_data(
				cmd, SILC_COMMAND_JOIN,
				SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				0, 2, hmac, strlen(hmac));
	    } else {
	      silc_server_command_send_status_reply(
				cmd, SILC_COMMAND_JOIN,
				SILC_STATUS_ERR_RESOURCE_LIMIT,
				0);
	    }
	    goto out;
	  }

	  umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	  created = TRUE;
	  create_key = FALSE;
	}
      } else {

	/* The channel does not exist on our server. If we are normal server
	   we will send JOIN command to our router which will handle the
	   joining procedure (either creates the channel if it doesn't exist
	   or joins the client to it). */
	if (server->server_type != SILC_ROUTER) {
	  SilcBuffer tmpbuf;
	  SilcUInt16 old_ident;

	  /* If this is pending command callback then we've resolved
	     it and it didn't work, return since we've notified the
	     client already in the command reply callback. */
	  if (cmd->pending)
	    goto out;

	  /* Statistics */
	  cmd->server->stat.commands_sent++;

	  old_ident = silc_command_get_ident(cmd->payload);
	  silc_command_set_ident(cmd->payload, ++server->cmd_ident);
	  tmpbuf = silc_command_payload_encode_payload(cmd->payload);

	  /* Send JOIN command to our router */
	  silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
				  SILC_PACKET_COMMAND, cmd->packet->flags,
				  tmpbuf->data, silc_buffer_len(tmpbuf));

	  /* Reprocess this packet after received reply from router */
	  silc_server_command_pending(server, SILC_COMMAND_JOIN,
				      silc_command_get_ident(cmd->payload),
				      silc_server_command_join,
				      silc_server_command_dup(cmd));
	  cmd->pending = TRUE;
          silc_command_set_ident(cmd->payload, old_ident);
	  silc_buffer_free(tmpbuf);
	  goto out;
	}

	/* We are router and the channel does not seem exist so we will check
	   our global list as well for the channel. */
	channel = silc_idlist_find_channel_by_name(server->global_list,
						   channel_namec, NULL);
	if (!channel) {
	  /* Channel really does not exist, create it */
	  channel = silc_server_create_new_channel(server, server->id, cipher,
						   hmac, channel_name, TRUE);
	  if (!channel) {
	    if (cipher) {
	      silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				      0, 2, cipher, strlen(cipher));
	    } else if (hmac) {
	      silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				      0, 2, hmac, strlen(hmac));
	    } else {
	      silc_server_command_send_status_reply(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_RESOURCE_LIMIT,
				      0);
	    }
	    goto out;
	  }

	  umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	  created = TRUE;
	  create_key = FALSE;
	}
      }
    }
  } else {
    if (!channel) {
      /* Channel not found */

      /* If the command came from router and we are normal server then
	 something went wrong with the joining as the channel was not found.
	 We can't do anything else but ignore this. */
      if (idata->conn_type == SILC_CONN_ROUTER ||
	  server->server_type != SILC_ROUTER)
	goto out;

      /* We are router and the channel does not seem exist so we will check
	 our global list as well for the channel. */
      channel = silc_idlist_find_channel_by_name(server->global_list,
						 channel_namec, NULL);
      if (!channel) {
	/* Channel really does not exist, create it */
	channel = silc_server_create_new_channel(server, server->id, cipher,
						 hmac, channel_name, TRUE);
	if (!channel) {
	  if (cipher) {
	    silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				      0, 2, cipher, strlen(cipher));
	  } else if (hmac) {
	    silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				      0, 2, hmac, strlen(hmac));
	  } else {
	    silc_server_command_send_status_reply(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_RESOURCE_LIMIT,
				      0);
	  }
	  goto out;
	}

	umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	created = TRUE;
	create_key = FALSE;
      }
    }
  }

  /* Check whether the channel was created by our router */
  if (cmd->pending && context2) {
    SilcServerCommandReplyContext reply = context2;

    if (silc_command_get(reply->payload) == SILC_COMMAND_JOIN) {
      tmp = silc_argument_get_arg_type(reply->args, 6, NULL);
      SILC_GET32_MSB(created, tmp);
      if (silc_argument_get_arg_type(reply->args, 7, NULL))
	create_key = FALSE;	/* Router returned the key already */

      if (silc_command_get_status(reply->payload, NULL, NULL) &&
	  channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
	/* Save channel passphrase, if user provided it successfully */
	unsigned char *pa;
	SilcUInt32 pa_len;
	pa = silc_argument_get_arg_type(cmd->args, 3, &pa_len);
	if (pa) {
	  silc_free(channel->passphrase);
	  channel->passphrase = silc_memdup(pa, pa_len);
	}
      }
    }

    if (silc_command_get(reply->payload) == SILC_COMMAND_WHOIS &&
	!channel->disabled && !silc_hash_table_count(channel->user_list))
      created = TRUE;
  }

  /* If the channel does not have global users and is also empty the client
     will be the channel founder and operator. */
  if (!channel->disabled &&
      !channel->global_users && !silc_hash_table_count(channel->user_list))
    umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);

  /* Join to the channel */
  silc_server_command_join_channel(server, cmd, channel, SILC_ID_GET_ID(id),
				   created, create_key, umode,
				   auth, auth_len, cauth, cauth_len);

 out:
  silc_free(channel_namec);
  silc_server_command_free(cmd);
}

/* Server side of command MOTD. Sends server's current "message of the
   day" to the client. */

SILC_SERVER_CMD_FUNC(motd)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcBuffer idp;
  char *motd, *dest_server = NULL;
  SilcUInt32 motd_len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_MOTD, cmd, 1, 1);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (!dest_server) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_MOTD,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Check server name */
  dest_server = silc_identifier_check(dest_server, strlen(dest_server),
				      SILC_STRING_UTF8, 256, NULL);
  if (!dest_server) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_MOTD,
					  SILC_STATUS_ERR_BAD_SERVER,
					  0);
    goto out;
  }

  if (!memcmp(dest_server, server->server_name, strlen(dest_server))) {
    /* Send our MOTD */

    idp = silc_id_payload_encode(server->id_entry->id, SILC_ID_SERVER);

    if (server->config && server->config->server_info &&
	server->config->server_info->motd_file) {
      /* Send motd */
      motd = silc_file_readfile(server->config->server_info->motd_file,
				&motd_len);
      if (!motd) {
	/* No motd */
	silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_MOTD,
				       SILC_STATUS_OK, 0, ident, 1,
				       2, idp->data, silc_buffer_len(idp));
	goto out;
      }

      motd[motd_len] = 0;
      silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_MOTD,
				     SILC_STATUS_OK, 0, ident, 2,
				     2, idp->data, silc_buffer_len(idp),
				     3, motd, motd_len);
    } else {
      /* No motd */
      silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_MOTD,
				     SILC_STATUS_OK, 0, ident, 1,
				     2, idp->data, silc_buffer_len(idp));
    }
    silc_buffer_free(idp);
  } else {
    SilcServerEntry entry;

    /* Check whether we have this server cached */
    entry = silc_idlist_find_server_by_name(server->global_list,
					    dest_server, TRUE, NULL);
    if (!entry) {
      entry = silc_idlist_find_server_by_name(server->local_list,
					      dest_server, TRUE, NULL);
    }

    if (server->server_type != SILC_SERVER && !cmd->pending &&
	entry && !entry->motd) {
      /* Send to the server */
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, entry->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_MOTD,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_motd,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }

    /* Send to primary router only if we don't know the server
     * the client requested or if the server is not locally connected */
    if ((!entry || !(entry->data.status & SILC_IDLIST_STATUS_LOCAL))
	&& !cmd->pending && !server->standalone) {
      /* Send to the primary router */
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_MOTD,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_motd,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }

    if (!entry) {
      silc_free(dest_server);
      dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_MOTD,
					   SILC_STATUS_ERR_NO_SUCH_SERVER, 0,
					   2, dest_server,
					   strlen(dest_server));
      dest_server = NULL;
      goto out;
    }

    idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
    silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_MOTD,
				   SILC_STATUS_OK, 0, ident, 2,
				   2, idp->data, silc_buffer_len(idp),
				   3, entry->motd,
				   entry->motd ?
				   strlen(entry->motd) : 0);
    silc_buffer_free(idp);
  }

 out:
  silc_free(dest_server);
  silc_server_command_free(cmd);
}

/* Server side of command UMODE. Client can use this command to set/unset
   user mode. Client actually cannot set itself to be as server/router
   operator so this can be used only to unset the modes. */

SILC_SERVER_CMD_FUNC(umode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  unsigned char *tmp_mask, m[4];
  SilcUInt32 mask = 0, tmp_len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcBool set_mask = FALSE;

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_UMODE, cmd, 1, 2);

  /* Get the client's mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp_mask && tmp_len == 4) {
    SILC_GET32_MSB(mask, tmp_mask);
    set_mask = TRUE;
  }

  if (set_mask) {
    /* Check that mode changing is allowed. */
    if (!silc_server_check_umode_rights(server, client, mask)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					    SILC_STATUS_ERR_PERM_DENIED, 0);
      goto out;
    }

    /* Anonymous mode cannot be set by client */
    if (mask & SILC_UMODE_ANONYMOUS &&
	!(client->mode & SILC_UMODE_ANONYMOUS)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					    SILC_STATUS_ERR_PERM_DENIED, 0);
      goto out;
    }

    /* Update statistics */
    if (mask & SILC_UMODE_GONE) {
      if (!(client->mode & SILC_UMODE_GONE))
	server->stat.my_aways++;
    } else {
      if (client->mode & SILC_UMODE_GONE)
	server->stat.my_aways--;
    }

    /* If the client has anonymous mode set, preserve it. */
    if (client->mode & SILC_UMODE_ANONYMOUS)
      mask |= SILC_UMODE_ANONYMOUS;

    /* Change the mode */
    client->mode = mask;

    /* Send UMODE change to primary router */
    silc_server_send_notify_umode(server, SILC_PRIMARY_ROUTE(server),
				  SILC_BROADCAST(server), client->id,
				  client->mode);

    /* Check if anyone is watching this nickname */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_UMODE_CHANGE);
  }

  /* Send command reply to sender */
  SILC_PUT32_MSB(client->mode, m);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_UMODE,
				 SILC_STATUS_OK, 0, ident, 1,
				 2, m, sizeof(m));

 out:
  silc_server_command_free(cmd);
}

/* Server side command of CMODE. Changes channel mode */

SILC_SERVER_CMD_FUNC(cmode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcIDListData idata = (SilcIDListData)client;
  SilcID id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer cidp;
  unsigned char *tmp, *tmp_id, *tmp_mask, *chpkdata = NULL;
  char *cipher = NULL, *hmac = NULL, *passphrase = NULL, ulimit[4];
  SilcUInt32 mode_mask = 0, old_mask = 0, tmp_len, tmp_len2, chpklen;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcBool set_mask = FALSE, set_chpk = FALSE;
  SilcPublicKey founder_key = NULL;
  SilcBuffer fkey = NULL, chpklist = NULL;
  SilcBufferStruct chpk;

  if (!client) {
    silc_server_command_free(cmd);
    return;
  }

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CMODE, cmd, 1, 9);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    silc_server_command_free(cmd);
    return;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_CMODE,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp_id, tmp_len2);
      silc_server_command_free(cmd);
      return;
    }
  }
  old_mask = channel->mode;

  /* Get the channel mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp_mask && tmp_len == 4) {
    SILC_GET32_MSB(mode_mask, tmp_mask);
    set_mask = TRUE;
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_CMODE,
					 SILC_STATUS_ERR_NOT_ON_CHANNEL, 0,
					 2, tmp_id, tmp_len2);
    goto out;
  }

  /* Check that client has rights to change any requested channel modes */
  if (set_mask && !silc_server_check_cmode_rights(server, channel, chl,
						  mode_mask)) {
    SILC_LOG_DEBUG(("Client does not have rights to change mode"));
    tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
    silc_server_command_send_status_data(
			     cmd, SILC_COMMAND_CMODE,
			     (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) ?
			      SILC_STATUS_ERR_NO_CHANNEL_PRIV :
			      SILC_STATUS_ERR_NO_CHANNEL_FOPRIV), 0,
			     2, tmp_id, tmp_len2);
    goto out;
  }

  /* If mode mask was not sent as argument then merely return the current
     mode mask, founder key and channel public key list to the sender. */
  if (!set_mask) {
    unsigned char m[4];
    SILC_PUT32_MSB(channel->mode, m);
    if (channel->founder_key)
      fkey = silc_public_key_payload_encode(channel->founder_key);
    if (channel->channel_pubkeys)
      chpklist = silc_server_get_channel_pk_list(server, channel,
						 FALSE, FALSE);
    tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
    silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_CMODE,
				   SILC_STATUS_OK, 0, ident, 4,
				   2, tmp_id, tmp_len2,
				   3, m, sizeof(m),
				   4, fkey ? fkey->data : NULL,
				   fkey ? silc_buffer_len(fkey) : 0,
				   5, chpklist ? chpklist->data : NULL,
				   chpklist ? silc_buffer_len(chpklist) : 0);
    goto out;
  }

  /*
   * Check the modes. Modes that requires nothing special operation are
   * not checked here.
   */

  if (mode_mask & SILC_CHANNEL_MODE_PRIVKEY) {
    /* Channel uses private keys to protect traffic. Client(s) has set the
       key locally they want to use, server does not know that key. */
    /* Nothing interesting to do here */
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
      /* The mode is removed and we need to generate and distribute
	 new channel key. Clients are not using private channel keys
	 anymore after this. */

      /* if we don't remove the flag from the mode
       * silc_server_create_channel_key won't create a new key */
      channel->mode &= ~SILC_CHANNEL_MODE_PRIVKEY;

      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0))
	goto out;

      /* Send the channel key. This sends it to our local clients and if
	 we are normal server to our router as well. */
      silc_server_send_channel_key(server, NULL, channel,
				   server->server_type == SILC_ROUTER ?
				   FALSE : !server->standalone);

      cipher = (char *)silc_cipher_get_name(channel->send_key);
      hmac = (char *)silc_hmac_get_name(channel->hmac);
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_ULIMIT) {
    /* User limit is set on channel */
    SilcUInt32 user_limit;

    /* Get user limit */
    tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (!tmp) {
      if (!(channel->mode & SILC_CHANNEL_MODE_ULIMIT)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	goto out;
      }
    } else {
      SILC_GET32_MSB(user_limit, tmp);
      channel->user_limit = user_limit;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
      /* User limit mode is unset. Remove user limit */
      channel->user_limit = 0;
  }

  if (mode_mask & SILC_CHANNEL_MODE_PASSPHRASE) {
    if (!(channel->mode & SILC_CHANNEL_MODE_PASSPHRASE)) {
      /* Passphrase has been set to channel */

      /* Get the passphrase */
      tmp = silc_argument_get_arg_type(cmd->args, 4, NULL);
      if (!tmp) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	goto out;
      }

      /* Save the passphrase */
      passphrase = channel->passphrase = silc_memdup(tmp, strlen(tmp));
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
      /* Passphrase mode is unset. remove the passphrase */
      silc_free(channel->passphrase);
      channel->passphrase = NULL;
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_CIPHER) {
    if (!(channel->mode & SILC_CHANNEL_MODE_CIPHER)) {
      /* Cipher to use protect the traffic */
      SilcCipher send_key, receive_key, olds, oldr;

      /* Get cipher */
      cipher = silc_argument_get_arg_type(cmd->args, 5, NULL);
      if (!cipher) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	goto out;
      }

      /* Delete old cipher and allocate the new one */
      if (!silc_cipher_alloc(cipher, &send_key)) {
	silc_server_command_send_status_data(
					 cmd, SILC_COMMAND_CMODE,
					 SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0,
					 2, cipher, strlen(cipher));
	goto out;
      }
      if (!silc_cipher_alloc(cipher, &receive_key)) {
	silc_server_command_send_status_data(
					 cmd, SILC_COMMAND_CMODE,
					 SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0,
					 2, cipher, strlen(cipher));
	goto out;
      }

      olds = channel->send_key;
      oldr = channel->receive_key;
      channel->send_key = send_key;
      channel->receive_key = receive_key;

      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0)) {
	/* We don't have new key, revert to old one */
	channel->send_key = olds;
	channel->receive_key = oldr;
	goto out;
      }

      /* Remove old channel key for good */
      silc_cipher_free(olds);
      silc_cipher_free(oldr);

      /* Send the channel key. This sends it to our local clients and if
	 we are normal server to our router as well. */
      silc_server_send_channel_key(server, NULL, channel,
				   server->server_type == SILC_ROUTER ?
				   FALSE : !server->standalone);
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_CIPHER) {
      /* Cipher mode is unset. Remove the cipher and revert back to
	 default cipher */
      SilcCipher send_key, receive_key, olds, oldr;
      cipher = channel->cipher;

      /* Delete old cipher and allocate default one */
      if (!silc_cipher_alloc(cipher ? cipher : SILC_DEFAULT_CIPHER,
			     &send_key)) {
	silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_CMODE,
				      SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0,
				      2, cipher, strlen(cipher));
	goto out;
      }
      if (!silc_cipher_alloc(cipher ? cipher : SILC_DEFAULT_CIPHER,
			     &receive_key)) {
	silc_server_command_send_status_data(
				      cmd, SILC_COMMAND_CMODE,
				      SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0,
				      2, cipher, strlen(cipher));
	goto out;
      }

      olds = channel->send_key;
      oldr = channel->receive_key;
      channel->send_key = send_key;
      channel->receive_key = receive_key;

      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0)) {
	/* We don't have new key, revert to old one */
	channel->send_key = olds;
	channel->receive_key = oldr;
	goto out;
      }

      /* Remove old channel key for good */
      silc_cipher_free(olds);
      silc_cipher_free(oldr);

      /* Send the channel key. This sends it to our local clients and if
	 we are normal server to our router as well. */
      silc_server_send_channel_key(server, NULL, channel,
				   server->server_type == SILC_ROUTER ?
				   FALSE : !server->standalone);
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_HMAC) {
    if (!(channel->mode & SILC_CHANNEL_MODE_HMAC)) {
      /* HMAC to use protect the traffic */
      unsigned char hash[SILC_HASH_MAXLEN];
      SilcHmac newhmac;

      /* Get hmac */
      hmac = silc_argument_get_arg_type(cmd->args, 6, NULL);
      if (!hmac) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	goto out;
      }

      /* Delete old hmac and allocate the new one */
      if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
	silc_server_command_send_status_data(
					cmd, SILC_COMMAND_CMODE,
					SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0,
					2, hmac, strlen(hmac));
	goto out;
      }

      silc_hmac_free(channel->hmac);
      channel->hmac = newhmac;

      /* Set the HMAC key out of current channel key. The client must do
	 this locally. */
      silc_hash_make(silc_hmac_get_hash(channel->hmac), channel->key,
		     channel->key_len / 8, hash);
      silc_hmac_set_key(channel->hmac, hash,
			silc_hash_len(silc_hmac_get_hash(channel->hmac)));
      memset(hash, 0, sizeof(hash));
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_HMAC) {
      /* Hmac mode is unset. Remove the hmac and revert back to
	 default hmac */
      SilcHmac newhmac;
      unsigned char hash[SILC_HASH_MAXLEN];
      hmac = channel->hmac_name;

      /* Delete old hmac and allocate default one */
      if (!silc_hmac_alloc(hmac ? hmac : SILC_DEFAULT_HMAC, NULL, &newhmac)) {
	silc_server_command_send_status_data(
					cmd, SILC_COMMAND_CMODE,
					SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0,
					2, hmac, strlen(hmac));
	goto out;
      }

      silc_hmac_free(channel->hmac);
      channel->hmac = newhmac;

      /* Set the HMAC key out of current channel key. The client must do
	 this locally. */
      silc_hash_make(silc_hmac_get_hash(channel->hmac), channel->key,
		     channel->key_len / 8,
		     hash);
      silc_hmac_set_key(channel->hmac, hash,
			silc_hash_len(silc_hmac_get_hash(channel->hmac)));
      memset(hash, 0, sizeof(hash));
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      /* Check if the founder public key was received */
      founder_key = idata->public_key;
      tmp = silc_argument_get_arg_type(cmd->args, 8, &tmp_len);
      if (tmp) {
	if (!silc_public_key_payload_decode(tmp, tmp_len, &founder_key)) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
						SILC_STATUS_ERR_AUTH_FAILED,
						0);
	  goto out;
	}
      } else {
	/* If key was not sent and the channel mode has already founder
	   then the key was not to be changed. */
	if (channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)
	  goto has_founder;
      }

      /* Set the founder authentication */
      tmp = silc_argument_get_arg_type(cmd->args, 7, &tmp_len);
      if (!tmp) {
	silc_server_command_send_status_reply(
				     cmd, SILC_COMMAND_CMODE,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	goto out;
      }

      /* Verify the payload before setting the mode */
      if (!silc_auth_verify_data(tmp, tmp_len, SILC_AUTH_PUBLIC_KEY,
				 founder_key, 0, server->sha1hash,
				 client->id, SILC_ID_CLIENT)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					      SILC_STATUS_ERR_AUTH_FAILED,
					      0);
	goto out;
      }

      /* Save the public key */
      if (channel->founder_key)
	silc_pkcs_public_key_free(channel->founder_key);
      if (silc_argument_get_arg_type(cmd->args, 8, NULL))
	channel->founder_key = founder_key;
      else
	channel->founder_key = silc_pkcs_public_key_copy(founder_key);
      if (!channel->founder_key) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					      SILC_STATUS_ERR_AUTH_FAILED,
					      0);
	goto out;
      }

      fkey = silc_public_key_payload_encode(channel->founder_key);
      if (!fkey) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					      SILC_STATUS_ERR_AUTH_FAILED,
					      0);
	silc_pkcs_public_key_free(channel->founder_key);
	channel->founder_key = NULL;
	goto out;
      }
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      if (channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
	if (channel->founder_key)
	  silc_pkcs_public_key_free(channel->founder_key);
	channel->founder_key = NULL;
      }
    }
  }
 has_founder:

  if (mode_mask & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      SilcStatus st;

      chpkdata = silc_argument_get_arg_type(cmd->args, 9, &chpklen);

      if (!chpkdata && channel->mode & SILC_CHANNEL_MODE_CHANNEL_AUTH)
	goto has_pk_list;

      set_chpk = TRUE;

      /* Process the channel public key(s) */
      st = silc_server_set_channel_pk_list(server, NULL, channel,
					   chpkdata, chpklen);
      if (st != SILC_STATUS_OK) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE, st, 0);
	goto out;
      }
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      if (channel->mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
	if (channel->channel_pubkeys)
	  silc_hash_table_free(channel->channel_pubkeys);
	channel->channel_pubkeys = NULL;
	set_chpk = TRUE;
      }
    }
  }
 has_pk_list:

  /* Finally, set the mode */
  old_mask = channel->mode = mode_mask;

  /* Send CMODE_CHANGE notify. */
  cidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  if (mode_mask & SILC_CHANNEL_MODE_ULIMIT)
    SILC_PUT32_MSB(channel->user_limit, ulimit);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
				     SILC_NOTIFY_TYPE_CMODE_CHANGE, 8,
				     cidp->data, silc_buffer_len(cidp),
				     tmp_mask, 4,
				     cipher, cipher ? strlen(cipher) : 0,
				     hmac, hmac ? strlen(hmac) : 0,
				     passphrase, passphrase ?
				     strlen(passphrase) : 0,
				     fkey ? fkey->data : NULL,
				     fkey ? silc_buffer_len(fkey) : 0,
				     chpkdata ? chpkdata : NULL,
				     chpkdata ? chpklen : 0,
				     mode_mask & SILC_CHANNEL_MODE_ULIMIT ?
				     ulimit : NULL,
				     mode_mask & SILC_CHANNEL_MODE_ULIMIT ?
				     sizeof(ulimit) : 0);

  /* Set CMODE notify type to network */
  if (chpkdata && chpklen)
    silc_buffer_set(&chpk, chpkdata, chpklen);
  silc_server_send_notify_cmode(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), channel,
				mode_mask, client->id, SILC_ID_CLIENT,
				cipher, hmac, passphrase, founder_key,
				chpkdata ? &chpk : NULL);

  if (set_chpk)
    chpklist = silc_server_get_channel_pk_list(server, channel, FALSE, FALSE);

  /* Send command reply to sender */
  tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_CMODE,
				 SILC_STATUS_OK, 0, ident, 5,
				 2, tmp_id, tmp_len2,
				 3, tmp_mask, 4,
				 4, fkey ? fkey->data : NULL,
				 fkey ? silc_buffer_len(fkey) : 0,
				 5, chpklist ? chpklist->data :
				 NULL, chpklist ? silc_buffer_len(chpklist)
				 : 0,
				 6, (mode_mask &
				     SILC_CHANNEL_MODE_ULIMIT ?
				     ulimit : NULL),
				 (mode_mask &
				  SILC_CHANNEL_MODE_ULIMIT ?
				  sizeof(ulimit) : 0));
  silc_buffer_free(cidp);

 out:
  channel->mode = old_mask;
  silc_buffer_free(chpklist);
  silc_buffer_free(fkey);
  silc_server_command_free(cmd);
}

/* Server side of CUMODE command. Changes client's mode on a channel. */

SILC_SERVER_CMD_FUNC(cumode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcID id, id2;
  SilcChannelEntry channel;
  SilcClientEntry target_client;
  SilcChannelClientEntry chl;
  SilcBuffer idp;
  unsigned char *tmp_id, *tmp_ch_id, *tmp_mask;
  SilcUInt32 target_mask, sender_mask = 0, tmp_len, tmp_ch_len;
  int notify = FALSE;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcPublicKey founder_key = NULL;
  SilcBuffer fkey = NULL;

  if (!client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CUMODE, cmd, 3, 4);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_CUMODE,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp_ch_id, tmp_ch_len);
      goto out;
    }
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_CUMODE,
					 SILC_STATUS_ERR_NOT_ON_CHANNEL, 0,
					 2, tmp_ch_id, tmp_ch_len);
    goto out;
  }
  sender_mask = chl->mode;

  /* Get the target client's channel mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp_mask) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }
  SILC_GET32_MSB(target_mask, tmp_mask);

  /* Get target Client ID */
  if (!silc_argument_get_decoded(cmd->args, 3, SILC_ARGUMENT_ID, &id2, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }

  /* Get target client's entry */
  target_client = silc_idlist_find_client_by_id(server->local_list,
						SILC_ID_GET_ID(id2),
						TRUE, NULL);
  if (!target_client)
    target_client = silc_idlist_find_client_by_id(server->global_list,
						  SILC_ID_GET_ID(id2),
						  TRUE, NULL);

  if (target_client != client &&
      !(sender_mask & SILC_CHANNEL_UMODE_CHANFO) &&
      !(sender_mask & SILC_CHANNEL_UMODE_CHANOP)) {
    tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_CUMODE,
					 SILC_STATUS_ERR_NOT_YOU, 0,
					 2, tmp_ch_id, tmp_ch_len);
    goto out;
  }

  /* Check whether target client is on the channel */
  if (target_client != client) {
    if (!silc_server_client_on_channel(target_client, channel, &chl)) {
      tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
      tmp_id = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
      silc_server_command_send_status_data2(
				  cmd, SILC_COMMAND_CUMODE,
				  SILC_STATUS_ERR_USER_NOT_ON_CHANNEL, 0,
				  2, tmp_id, tmp_len,
				  3, tmp_ch_id, tmp_ch_len);
      goto out;
    }
  }

  /*
   * Change the mode
   */

  /* If the target client is founder, no one else can change their mode
     but themselves. */
  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO && client != target_client) {
    tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_CUMODE,
					 SILC_STATUS_ERR_NO_CHANNEL_FOPRIV,
					 0, 2, tmp_ch_id, tmp_ch_len);
    goto out;
  }

  if (target_mask & SILC_CHANNEL_UMODE_CHANFO) {
    if (target_client != client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					    SILC_STATUS_ERR_NO_CHANNEL_FOPRIV,
					    0);
      goto out;
    }

    if (!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      /* The client tries to claim the founder rights. */
      unsigned char *tmp_auth;
      SilcUInt32 tmp_auth_len;
      SilcChannelClientEntry chl2;
      SilcHashTableList htl;

      if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) ||
	  !channel->founder_key) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_AUTH_FAILED, 0);
	goto out;
      }

      tmp_auth = silc_argument_get_arg_type(cmd->args, 4, &tmp_auth_len);
      if (!tmp_auth) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_AUTH_FAILED, 0);
	goto out;
      }

      /* Verify the authentication payload */
      if (!silc_auth_verify_data(tmp_auth, tmp_auth_len, SILC_AUTH_PUBLIC_KEY,
				 channel->founder_key, 0, server->sha1hash,
				 client->id, SILC_ID_CLIENT)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_AUTH_FAILED, 0);
	goto out;
      }

      notify = TRUE;
      founder_key = channel->founder_key;
      fkey = silc_public_key_payload_encode(founder_key);
      if (!fkey) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_AUTH_FAILED, 0);
	goto out;
      }

      /* There cannot be anyone else as founder on the channel now.  This
	 client is definitely the founder due to this authentication.  This
	 is done only on router, not on server, since server cannot know
	 whether router will accept this mode change or not.  XXX This
	 probably shouldn't be done anymore at all, may cause problems in
	 router-router connections too (maybe just AUTH_FAILED error should
	 be returned). -Pekka */
      if (server->server_type == SILC_ROUTER) {
	silc_hash_table_list(channel->user_list, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chl2))
	  if (chl2->mode & SILC_CHANNEL_UMODE_CHANFO) {
	    chl2->mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	    silc_server_force_cumode_change(server, NULL, channel, chl2,
					    chl2->mode);
	    break;
	  }
	silc_hash_table_list_reset(&htl);
      }

      sender_mask = chl->mode |= SILC_CHANNEL_UMODE_CHANFO;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      if (target_client == client) {
	/* Remove channel founder rights from itself */
	chl->mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	notify = TRUE;
      } else {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU, 0);
	goto out;
      }
    }
  }

  if (target_mask & SILC_CHANNEL_UMODE_CHANOP) {
    /* Promote to operator */
    if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP)) {
      if (!(sender_mask & SILC_CHANNEL_UMODE_CHANOP) &&
          !(sender_mask & SILC_CHANNEL_UMODE_CHANFO)) {
	tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
        silc_server_command_send_status_data(cmd, SILC_COMMAND_CUMODE,
					     SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					     0, 2, tmp_ch_id, tmp_ch_len);
        goto out;
      }

      chl->mode |= SILC_CHANNEL_UMODE_CHANOP;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANOP) {
      if (!(sender_mask & SILC_CHANNEL_UMODE_CHANOP) &&
          !(sender_mask & SILC_CHANNEL_UMODE_CHANFO)) {
	tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
        silc_server_command_send_status_data(cmd, SILC_COMMAND_CUMODE,
					     SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					     0, 2, tmp_ch_id, tmp_ch_len);
        goto out;
      }

      /* Demote to normal user */
      chl->mode &= ~SILC_CHANNEL_UMODE_CHANOP;
      notify = TRUE;
    }
  }

  if (target_mask & SILC_CHANNEL_UMODE_BLOCK_MESSAGES) {
    if (target_client != client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					    SILC_STATUS_ERR_NOT_YOU, 0);
      goto out;
    }

    if (!(chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES)) {
      chl->mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES) {
      if (target_client != client) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU, 0);
	goto out;
      }

      chl->mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
      notify = TRUE;
    }
  }

  if (target_mask & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS) {
    if (target_client != client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					    SILC_STATUS_ERR_NOT_YOU, 0);
      goto out;
    }

    if (!(chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS)) {
      chl->mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS) {
      if (target_client != client) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU, 0);
	goto out;
      }

      chl->mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
      notify = TRUE;
    }
  }

  if (target_mask & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS) {
    if (target_client != client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					    SILC_STATUS_ERR_NOT_YOU, 0);
      goto out;
    }

    if (!(chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS)) {
      chl->mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS) {
      if (target_client != client) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU, 0);
	goto out;
      }

      chl->mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      notify = TRUE;
    }
  }

  if (target_mask & SILC_CHANNEL_UMODE_QUIET) {
    if (!(chl->mode & SILC_CHANNEL_UMODE_QUIET)) {
      if (client == target_client) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_PERM_DENIED, 0);
	goto out;
      }
      chl->mode |= SILC_CHANNEL_UMODE_QUIET;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_QUIET) {
      if (client == target_client) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_PERM_DENIED, 0);
	goto out;
      }
      chl->mode &= ~SILC_CHANNEL_UMODE_QUIET;
      notify = TRUE;
    }
  }

  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  tmp_id = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);

  /* Send notify to channel, notify only if mode was actually changed. */
  if (notify) {
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
				       SILC_NOTIFY_TYPE_CUMODE_CHANGE, 4,
				       idp->data, silc_buffer_len(idp),
				       tmp_mask, 4,
				       tmp_id, tmp_len,
				       fkey ? fkey->data : NULL,
				       fkey ? silc_buffer_len(fkey) : 0);

    /* Set CUMODE notify type to network */
    silc_server_send_notify_cumode(server, SILC_PRIMARY_ROUTE(server),
				   SILC_BROADCAST(server), channel,
				   target_mask, client->id, SILC_ID_CLIENT,
				   target_client->id, founder_key);
  }

  /* Send command reply to sender */
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_CUMODE,
				 SILC_STATUS_OK, 0, ident, 3,
				 2, tmp_mask, 4,
				 3, tmp_ch_id, tmp_ch_len,
				 4, tmp_id, tmp_len);
  silc_buffer_free(idp);

 out:
  silc_buffer_free(fkey);
  silc_server_command_free(cmd);
}

/* Server side of KICK command. Kicks client out of channel. */

SILC_SERVER_CMD_FUNC(kick)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcClientEntry target_client;
  SilcID id, id2;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer idp;
  SilcUInt32 tmp_len, target_idp_len, clen;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  unsigned char *tmp, *comment, *target_idp;

  if (!client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LEAVE, cmd, 1, 3);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->local_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_KICK,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp, tmp_len);
      goto out;
    }
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_KICK,
					 SILC_STATUS_ERR_NOT_ON_CHANNEL,
					 0, 2, tmp, tmp_len);
    goto out;
  }

  /* Check that the kicker is channel operator or channel founder */
  if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
      !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_KICK,
					 SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					 0, 2, tmp, tmp_len);
    goto out;
  }

  /* Get target Client ID */
  if (!silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id2, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }

  /* Get target client's entry */
  target_client = silc_idlist_find_client_by_id(server->local_list,
						SILC_ID_GET_ID(id2),
						TRUE, NULL);
  if (!target_client)
    target_client = silc_idlist_find_client_by_id(server->global_list,
						  SILC_ID_GET_ID(id2),
						  TRUE, NULL);

  /* Check whether target client is on the channel */
  if (!silc_server_client_on_channel(target_client, channel, &chl)) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    target_idp = silc_argument_get_arg_type(cmd->args, 2, &target_idp_len);
    silc_server_command_send_status_data2(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_USER_NOT_ON_CHANNEL,
					  0, 2, target_idp, target_idp_len,
					  3, tmp, tmp_len);
    goto out;
  }

  /* Check that the target client is not channel founder. Channel founder
     cannot be kicked from the channel. */
  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_KICK,
					 SILC_STATUS_ERR_NO_CHANNEL_FOPRIV,
					 0, 2, tmp, tmp_len);
    goto out;
  }

  /* Get comment */
  comment = silc_argument_get_arg_type(cmd->args, 3, &clen);
  if (clen > 128)
    comment = NULL;

  /* Send the reply back to the client */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  target_idp = silc_argument_get_arg_type(cmd->args, 2, &target_idp_len);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_KICK,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, tmp, tmp_len,
				 3, target_idp, target_idp_len);

  /* Send KICKED notify to local clients on the channel */
  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
				     SILC_NOTIFY_TYPE_KICKED, 3,
				     target_idp, target_idp_len,
				     comment, comment ? strlen(comment) : 0,
				     idp->data, silc_buffer_len(idp));
  silc_buffer_free(idp);

  /* Send KICKED notify to primary route */
  silc_server_send_notify_kicked(server, SILC_PRIMARY_ROUTE(server),
				 SILC_BROADCAST(server), channel,
				 target_client->id, client->id, comment);

  /* Remove the client from channel's invite list */
  if (channel->invite_list && silc_hash_table_count(channel->invite_list)) {
    SilcBuffer ab =
      silc_argument_payload_encode_one(NULL, target_idp, target_idp_len, 3);
    SilcArgumentPayload args =
      silc_argument_payload_parse(ab->data, silc_buffer_len(ab), 1);

    silc_server_inviteban_process(server, channel->invite_list, 1, args);
    silc_buffer_free(ab);
    silc_argument_payload_free(args);
  }

  /* Remove the client from the channel. If the channel does not exist
     after removing the client then the client kicked itself off the channel
     and we don't have to send anything after that. */
  if (!silc_server_remove_from_one_channel(server, NULL, channel,
					   target_client, FALSE))
    goto out;

  if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
    /* Re-generate channel key */
    if (!silc_server_create_channel_key(server, channel, 0))
      goto out;

    /* Send the channel key to the channel. The key of course is not sent
       to the client who was kicked off the channel. */
    silc_server_send_channel_key(server, target_client->connection, channel,
				 server->server_type == SILC_ROUTER ?
				 FALSE : !server->standalone);
  }

 out:
  silc_server_command_free(cmd);
}

/* Server side of OPER command. Client uses this comand to obtain server
   operator privileges to this server/router. */

SILC_SERVER_CMD_FUNC(oper)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  unsigned char *username = NULL, *auth;
  SilcUInt32 tmp_len;
  SilcServerConfigAdmin *admin;
  SilcIDListData idata = (SilcIDListData)client;
  SilcBool result = FALSE;
  SilcPublicKey cached_key;
  const char *hostname, *ip;

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_OPER, cmd, 1, 2);

  silc_socket_stream_get_info(silc_packet_stream_get_stream(cmd->sock),
			      NULL, &hostname, &ip, NULL);

  /* Get the username */
  username = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Check username */
  username = silc_identifier_check(username, strlen(username),
				   SILC_STRING_UTF8, 128, &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_BAD_USERNAME,
					  0);
    goto out;
  }

  /* Get the admin configuration */
  admin = silc_server_config_find_admin(server, (char *)ip,
					username, client->nickname);
  if (!admin) {
    admin = silc_server_config_find_admin(server, (char *)hostname,
					  username, client->nickname);
    if (!admin) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					    SILC_STATUS_ERR_AUTH_FAILED,
					    0);
      SILC_LOG_INFO(("OPER authentication failed for username '%s' by "
		     "nickname '%s' from %s", username,
		     client->nickname, hostname));
      goto out;
    }
  }

  /* Get the authentication payload */
  auth = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!auth) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Verify the authentication data. If both passphrase and public key
     is set then try both of them. */
  if (admin->passphrase)
    result = silc_auth_verify_data(auth, tmp_len, SILC_AUTH_PASSWORD,
				   admin->passphrase, admin->passphrase_len,
				   idata->hash, client->id, SILC_ID_CLIENT);
  if (!result && admin->publickeys) {
    cached_key =
      silc_server_get_public_key(server,
				 SILC_SKR_USAGE_SERVICE_AUTHORIZATION, admin);
    if (!cached_key)
      goto out;
    result = silc_auth_verify_data(auth, tmp_len, SILC_AUTH_PUBLIC_KEY,
				   cached_key, 0, idata->hash,
				   client->id, SILC_ID_CLIENT);
  }
  if (!result) {
    /* Authentication failed */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_AUTH_FAILED,
					  0);
    goto out;
  }

  /* Client is now server operator */
  client->mode |= SILC_UMODE_SERVER_OPERATOR;

  /* Update statistics */
  if (SILC_IS_LOCAL(client))
    server->stat.my_server_ops++;
  if (server->server_type == SILC_ROUTER)
    server->stat.server_ops++;

  /* Send UMODE change to primary router */
  silc_server_send_notify_umode(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), client->id,
				client->mode);

  /* Check if anyone is watching this nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL,
				   SILC_NOTIFY_TYPE_UMODE_CHANGE);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					SILC_STATUS_OK, 0);

 out:
  silc_free(username);
  silc_server_command_free(cmd);
}

SILC_TASK_CALLBACK(silc_server_command_detach_cb)
{
  SilcServer server = app_context;
  QuitInternal q = (QuitInternal)context;
  SilcClientID *client_id = (SilcClientID *)q->sock;
  SilcClientEntry client;
  SilcPacketStream sock;
  SilcIDListData idata;


  client = silc_idlist_find_client_by_id(server->local_list, client_id,
					 TRUE, NULL);
  if (client && client->connection) {
    sock = client->connection;

    SILC_LOG_DEBUG(("Detaching client %s",
		    silc_id_render(client->id, SILC_ID_CLIENT)));

    /* Stop rekey for the client. */
    silc_server_stop_rekey(server, client);

    /* Abort any active protocol */
    idata = silc_packet_get_context(sock);
    if (idata && idata->sconn && idata->sconn->op) {
      SILC_LOG_DEBUG(("Abort active protocol"));
      silc_async_abort(idata->sconn->op, NULL, NULL);
      idata->sconn->op = NULL;
    }

    /* Close the connection on our side */
    client->router = NULL;
    client->connection = NULL;
    silc_server_close_connection(server, sock);

    /* Mark the client as locally detached. */
    client->local_detached = TRUE;

    /*
     * Decrement the user count; we'll increment it if the user resumes on our
     * server.
     */
    SILC_VERIFY(&server->stat.my_clients > 0);
    server->stat.my_clients--;
  }

  silc_free(client_id);
  silc_free(q);
}

SILC_TASK_CALLBACK(silc_server_command_detach_timeout)
{
  SilcServer server = app_context;
  QuitInternal q = (QuitInternal)context;
  SilcClientID *client_id = (SilcClientID *)q->sock;
  SilcClientEntry client;

  client = silc_idlist_find_client_by_id(server->local_list, client_id,
					 TRUE, NULL);
  if (client && client->mode & SILC_UMODE_DETACHED) {
    SILC_LOG_DEBUG(("Detach timeout"));
    silc_server_free_client_data(server, NULL, client, TRUE,
				 "Detach timeout");
  }

  silc_free(client_id);
  silc_free(q);
}

/* Server side of DETACH command.  Detached the client from the network
   by closing the connection but preserving the session. */

SILC_SERVER_CMD_FUNC(detach)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  QuitInternal q;

  if (server->config->detach_disabled) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_DETACH,
					  SILC_STATUS_ERR_OPERATION_ALLOWED,
					  0);
    goto out;
  }

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_DETACH, cmd, 0, 0);

  /* Remove operator privileges, since the client may resume in some
     other server which to it does not have operator privileges. */
  SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
  SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

  /* Send the user mode notify to notify that client is detached */
  client->mode |= SILC_UMODE_DETACHED;
  client->data.status &= ~SILC_IDLIST_STATUS_RESUMED;
  client->data.status &= ~SILC_IDLIST_STATUS_NOATTR;
  client->last_command = 0;
  client->fast_command = 0;
  silc_server_send_notify_umode(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), client->id,
				client->mode);
  server->stat.my_detached++;

  /* Check if anyone is watching this nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL,
				   SILC_NOTIFY_TYPE_UMODE_CHANGE);

  q = silc_calloc(1, sizeof(*q));
  q->sock = silc_id_dup(client->id, SILC_ID_CLIENT);
  silc_schedule_task_add_timeout(server->schedule,
				 silc_server_command_detach_cb,
				 q, 0, 200000);

  if (server->config->detach_timeout) {
    q = silc_calloc(1, sizeof(*q));
    q->sock = silc_id_dup(client->id, SILC_ID_CLIENT);
    silc_schedule_task_add_timeout(server->schedule,
				   silc_server_command_detach_timeout,
				   q, server->config->detach_timeout * 60, 0);
  }

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_DETACH,
					SILC_STATUS_OK, 0);

 out:
  silc_server_command_free(cmd);
}

/* Server side of WATCH command. */

SILC_SERVER_CMD_FUNC(watch)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  char *add_nick, *del_nick;
  SilcUInt32 add_nick_len, del_nick_len, tmp_len, pk_len;
  unsigned char hash[SILC_HASH_MAXLEN], *tmp,  *pk, *nick;
  SilcClientEntry client;
  SilcID id;
  SilcUInt16 old_ident;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WATCH, cmd, 1, 3);

  if (server->server_type != SILC_ROUTER && !server->standalone) {
    if (!cmd->pending) {
      /* Send the command to router */
      SilcBuffer tmpbuf;

      /* If backup receives this from primary, handle it locally */
      if (server->server_type == SILC_BACKUP_ROUTER &&
	  cmd->sock == SILC_PRIMARY_ROUTE(server))
	goto process_watch;

      SILC_LOG_DEBUG(("Forwarding WATCH to router"));

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_WATCH,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_watch,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    } else {
      SilcServerCommandReplyContext reply = context2;
      SilcStatus status;

      if (!reply)
        goto out;

      silc_command_get_status(reply->payload, &status, NULL);

      /* Backup router handles the WATCH command also. */
      if (server->server_type != SILC_BACKUP_ROUTER ||
	  SILC_STATUS_IS_ERROR(status)) {
	/* Received reply from router, just send same data to the client. */
	SILC_LOG_DEBUG(("Received reply to WATCH from router"));
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH, status,
					      0);
	goto out;
      }
    }
  }

  /* We are router and keep the watch list for local cell */
 process_watch:

  /* Get the client ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Get the client entry which must be in local list */
  client = silc_idlist_find_client_by_id(server->local_list,
					 SILC_ID_GET_ID(id), TRUE, NULL);
  if (!client) {
    /* Backup checks global list also */
    if (server->server_type == SILC_BACKUP_ROUTER)
      client = silc_idlist_find_client_by_id(server->global_list,
					     SILC_ID_GET_ID(id), TRUE, NULL);
    if (!client) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_WATCH,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   0, 2, tmp, tmp_len);
      goto out;
    }
  }

  /* Take public key for watching by public key */
  pk = silc_argument_get_arg_type(cmd->args, 4, &pk_len);

  /* Take nickname */
  add_nick = silc_argument_get_arg_type(cmd->args, 2, &add_nick_len);
  del_nick = silc_argument_get_arg_type(cmd->args, 3, &del_nick_len);
  if (!add_nick && !del_nick && !pk) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  if (add_nick && add_nick_len > 128) {
    add_nick_len = 128;
    add_nick[add_nick_len - 1] = '\0';
  }
  if (del_nick && del_nick_len > 128) {
    del_nick_len = 128;
    del_nick[del_nick_len - 1] = '\0';
  }

  /* Add new nickname to be watched in our cell */
  if (add_nick) {
    nick = silc_identifier_check(add_nick, add_nick_len, SILC_STRING_UTF8, 128,
				 &add_nick_len);
    if (!nick) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_BAD_NICKNAME, 0);
      goto out;
    }

    /* Hash the nick, we have the hash saved, not nicks because we can
       do one to one mapping to the nick from Client ID hash this way. */
    silc_hash_make(server->md5hash, nick, add_nick_len, hash);

    /* Check whether this client is already watching this nickname */
    if (silc_hash_table_find_by_context(server->watcher_list, hash,
					client, NULL)) {
      /* Nickname is alredy being watched for this client */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_NICKNAME_IN_USE,
					    0);
      silc_free(nick);
      goto out;
    }

    /* Get the nickname from the watcher list and use the same key in
       new entries as well.  If key doesn't exist then create it. */
    if (!silc_hash_table_find(server->watcher_list, hash, (void *)&tmp, NULL))
      tmp = silc_memdup(hash, CLIENTID_HASH_LEN);

    /* Add the client to the watcher list with the specified nickname hash. */
    silc_hash_table_add(server->watcher_list, tmp, client);
    silc_free(nick);
  }

  /* Delete nickname from watch list */
  if (del_nick) {
    nick = silc_identifier_check(del_nick, del_nick_len, SILC_STRING_UTF8, 128,
				 &del_nick_len);
    if (!nick) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_BAD_NICKNAME, 0);
      goto out;
    }

    /* Hash the nick, we have the hash saved, not nicks because we can
       do one to one mapping to the nick from Client ID hash this way. */
    silc_hash_make(server->md5hash, nick, del_nick_len, hash);

    /* Check that this client is watching for this nickname */
    if (!silc_hash_table_find_by_context(server->watcher_list, hash,
					 client, (void *)&tmp)) {
      /* Nickname is alredy being watched for this client */
      silc_server_command_send_status_data(cmd, SILC_COMMAND_WATCH,
					   SILC_STATUS_ERR_NO_SUCH_NICK, 0,
					   2, nick, del_nick_len);
      silc_free(nick);
      goto out;
    }

    /* Delete the nickname from the watcher list. */
    silc_hash_table_del_by_context(server->watcher_list, hash, client);

    /* Now check whether there still exists entries with this key, if not
       then free the key to not leak memory. */
    if (!silc_hash_table_find(server->watcher_list, hash, NULL, NULL))
      silc_free(tmp);
    silc_free(nick);
  }

  /* Add/del public key */
  if (pk) {
    SilcUInt16 pkargc;
    SilcArgumentPayload pkargs;
    SilcUInt32 type;
    SilcPublicKey public_key, pkkey;

    if (pk_len < 2) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    /* Get the argument from the Argument List Payload */
    SILC_GET16_MSB(pkargc, pk);
    pkargs = silc_argument_payload_parse(pk + 2, pk_len - 2, pkargc);
    if (!pkargs) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    pk = silc_argument_get_next_arg(pkargs, &type, &pk_len);
    while (pk) {
      if (!silc_public_key_payload_decode(pk, pk_len, &public_key)) {
        pk = silc_argument_get_next_arg(pkargs, &type, &pk_len);
	continue;
      }
      if (type == 0x03)
        type = 0x00;

      if (type == 0x00) {
	/* Add public key to watch list */

	/* Check whether this client is already watching this public key */
 	if (silc_hash_table_find_by_context(server->watcher_list_pk,
					    public_key, client, NULL)) {
	  silc_pkcs_public_key_free(public_key);
	  silc_server_command_send_status_reply(
				cmd, SILC_COMMAND_WATCH,
				SILC_STATUS_ERR_NICKNAME_IN_USE, 0);
	  goto out;
	}

	/* Get the public key from the watcher list and use the same key in
	   new entries as well.  If key doesn't exist then create it. */
	pkkey = NULL;
	if (!silc_hash_table_find(server->watcher_list_pk, public_key,
				  (void *)&pkkey, NULL))
	  pkkey = public_key;
	else
	  silc_pkcs_public_key_free(public_key);

	/* Add the client to the watcher list with the specified public
	   key. */
	silc_hash_table_add(server->watcher_list_pk, pkkey, client);

      } else if (type == 0x01) {
	/* Delete public key from watch list */

	/* Check that this client is watching this public key */
 	if (silc_hash_table_find_by_context(server->watcher_list_pk,
					    public_key, client,
					    (void *)&pkkey)) {
	  silc_pkcs_public_key_free(public_key);
	  silc_server_command_send_status_reply(
				cmd, SILC_COMMAND_WATCH,
				SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	  goto out;
	}

	/* Delete the public key from the watcher list. */
	silc_hash_table_del_by_context(server->watcher_list_pk,
				       public_key, client);

	/* Now check whether there still exists entries with this key, if
	   not then free the key to not leak memory. */
	if (!silc_hash_table_find(server->watcher_list_pk, hash, NULL, NULL))
	  silc_pkcs_public_key_free(pkkey);
        silc_pkcs_public_key_free(public_key);
      }

      pk = silc_argument_get_next_arg(pkargs, &type, &pk_len);
    }
  }

  /* Send reply */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					SILC_STATUS_OK, 0);

  /* Distribute the watch list to backup routers too */
  if (server->backup) {
    SilcBuffer tmpbuf;

    /* Statistics */
    cmd->server->stat.commands_sent++;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);
    silc_server_backup_send(server, silc_packet_get_context(cmd->sock),
			    SILC_PACKET_COMMAND,
			    cmd->packet->flags, tmpbuf->data,
			    silc_buffer_len(tmpbuf),
			    FALSE, TRUE);
    silc_command_set_ident(cmd->payload, old_ident);
    silc_buffer_free(tmpbuf);
  }

 out:
  silc_server_command_free(cmd);
}

/* Server side of SILCOPER command. Client uses this comand to obtain router
   operator privileges to this router. */

SILC_SERVER_CMD_FUNC(silcoper)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  unsigned char *username = NULL, *auth;
  SilcUInt32 tmp_len;
  SilcServerConfigAdmin *admin;
  SilcIDListData idata = (SilcIDListData)client;
  SilcBool result = FALSE;
  SilcPublicKey cached_key;
  const char *hostname, *ip;

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_SILCOPER, cmd, 1, 2);

  silc_socket_stream_get_info(silc_packet_stream_get_stream(cmd->sock),
			      NULL, &hostname, &ip, NULL);

  if (server->server_type != SILC_ROUTER) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_AUTH_FAILED, 0);
    goto out;
  }

  /* Get the username */
  username = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Check username */
  username = silc_identifier_check(username, tmp_len, SILC_STRING_UTF8, 128,
				   &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_BAD_USERNAME,
					  0);
    goto out;
  }

  /* Get the admin configuration */
  admin = silc_server_config_find_admin(server, (char *)ip,
					username, client->nickname);
  if (!admin) {
    admin = silc_server_config_find_admin(server, (char *)hostname,
					  username, client->nickname);
    if (!admin) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					    SILC_STATUS_ERR_AUTH_FAILED, 0);
      SILC_LOG_INFO(("SILCOPER authentication failed for username '%s' by "
		     "nickname '%s' from %s", username,
		     client->nickname, hostname));
      goto out;
    }
  }

  /* Get the authentication payload */
  auth = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!auth) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Verify the authentication data. If both passphrase and public key
     is set then try both of them. */
  if (admin->passphrase)
    result = silc_auth_verify_data(auth, tmp_len, SILC_AUTH_PASSWORD,
				   admin->passphrase, admin->passphrase_len,
				   idata->hash, client->id, SILC_ID_CLIENT);
  if (!result && admin->publickeys) {
    cached_key =
      silc_server_get_public_key(server,
				 SILC_SKR_USAGE_SERVICE_AUTHORIZATION, admin);
    if (!cached_key)
      goto out;
    result = silc_auth_verify_data(auth, tmp_len, SILC_AUTH_PUBLIC_KEY,
				   cached_key, 0, idata->hash,
				   client->id, SILC_ID_CLIENT);
  }
  if (!result) {
    /* Authentication failed */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_AUTH_FAILED, 0);
    goto out;
  }

  /* Client is now router operator */
  client->mode |= SILC_UMODE_ROUTER_OPERATOR;

  /* Update statistics */
  if (SILC_IS_LOCAL(client))
    server->stat.my_router_ops++;
  if (server->server_type == SILC_ROUTER)
    server->stat.router_ops++;

  /* Send UMODE change to primary router */
  silc_server_send_notify_umode(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), client->id,
				client->mode);

  /* Check if anyone is watching this nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL,
				   SILC_NOTIFY_TYPE_UMODE_CHANGE);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					SILC_STATUS_OK, 0);

 out:
  silc_free(username);
  silc_server_command_free(cmd);
}

/* Server side of command BAN. This is used to manage the ban list of the
   channel. To add clients and remove clients from the ban list. */

SILC_SERVER_CMD_FUNC(ban)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcBuffer list, tmp2;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcID id;
  unsigned char *tmp_id, *tmp, *atype = NULL;
  SilcUInt32 id_len, len, len2;
  SilcArgumentPayload args;
  SilcHashTableList htl;
  void *type;
  SilcUInt16 argc = 0, ident = silc_command_get_ident(cmd->payload);
  SilcBufferStruct blist;

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_BAN, cmd, 0, 3);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry. The server must know about the channel since the
     client is expected to be on the channel. */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp_id = silc_argument_get_arg_type(cmd->args, 1, &id_len);
      silc_server_command_send_status_data(
					   cmd, SILC_COMMAND_BAN,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp_id, id_len);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    tmp_id = silc_argument_get_arg_type(cmd->args, 1, &id_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_BAN,
					 SILC_STATUS_ERR_NOT_ON_CHANNEL, 0,
					 2, tmp_id, id_len);
    goto out;
  }

  /* The client must be at least channel operator. */
  if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP)) {
    tmp_id = silc_argument_get_arg_type(cmd->args, 1, &id_len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_BAN,
					 SILC_STATUS_ERR_NO_CHANNEL_PRIV, 0,
					 2, tmp_id, id_len);
    goto out;
  }

  /* Get the ban information */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len2);
  if (tmp && len2 > 2) {
    /* Parse the arguments to see they are constructed correctly */
    SILC_GET16_MSB(argc, tmp);
    args = silc_argument_payload_parse(tmp + 2, len2 - 2, argc);
    if (!args) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    /* Get the type of action */
    atype = silc_argument_get_arg_type(cmd->args, 2, &len);
    if (atype && len == 1) {
      if (atype[0] == 0x00) {
	/* Allocate hash table for ban list if it doesn't exist yet */
	if (!channel->ban_list)
	  channel->ban_list =
	    silc_hash_table_alloc(0, silc_hash_ptr,
				  NULL, NULL, NULL,
				  silc_server_inviteban_destruct, channel,
				  TRUE);

	/* Check for resource limit */
	if (silc_hash_table_count(channel->ban_list) > 64) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
						SILC_STATUS_ERR_RESOURCE_LIMIT,
						0);
	  goto out;
	}
      }

      /* Now add or delete the information. */
      if (!silc_server_inviteban_process(server, channel->ban_list,
					 (SilcUInt8)atype[0], args)) {
	silc_server_command_send_status_reply(
				      cmd, SILC_COMMAND_BAN,
				      SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
				      0);
	goto out;
      }
    }
    silc_argument_payload_free(args);
  }

  /* Encode ban list */
  list = NULL;
  if (channel->ban_list && silc_hash_table_count(channel->ban_list)) {
    list = silc_buffer_alloc_size(2);
    silc_buffer_format(list,
		       SILC_STR_UI_SHORT(silc_hash_table_count(
					  channel->ban_list)),
		       SILC_STR_END);
    silc_hash_table_list(channel->ban_list, &htl);
    while (silc_hash_table_get(&htl, (void *)&type, (void *)&tmp2))
      list = silc_argument_payload_encode_one(list, tmp2->data,
					      silc_buffer_len(tmp2),
					      SILC_PTR_TO_32(type));
    silc_hash_table_list_reset(&htl);
  }

  tmp_id = silc_argument_get_arg_type(cmd->args, 1, &id_len);

  /* Send BAN notify type to local servers (but not clients) and to
     network. */
  if (atype && tmp && len2) {
    silc_buffer_set(&blist, tmp, len2);

    /* Send to local servers if we are router */
    if (server->server_type == SILC_ROUTER)
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, FALSE,
                                         SILC_NOTIFY_TYPE_BAN, 3,
					 tmp_id, id_len,
					 atype, 1,
					 tmp ? blist.data : NULL,
					 tmp ? silc_buffer_len(&blist) : 0);

    /* Send to network. */
    silc_server_send_notify_ban(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), channel, atype,
				&blist);
  }

  /* Send the reply back to the client */
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_BAN,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, tmp_id, id_len,
				 3, list ? list->data : NULL,
				 list ? silc_buffer_len(list) : 0);
  silc_buffer_free(list);

 out:
  silc_server_command_free(cmd);
}

/* Server side command of LEAVE. Removes client from a channel. */

SILC_SERVER_CMD_FUNC(leave)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcPacketStream sock = cmd->sock;
  SilcClientEntry id_entry = silc_packet_get_context(cmd->sock);
  SilcID id;
  SilcChannelEntry channel;
  SilcUInt32 len;
  unsigned char *tmp;

  if (id_entry->data.conn_type != SILC_CONN_CLIENT || !id_entry)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LEAVE, cmd, 1, 2);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(cmd->args, 1, SILC_ARGUMENT_ID, &id, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_LEAVE,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					   0, 2, tmp, len);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(id_entry, channel, NULL)) {
    tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
    silc_server_command_send_status_data(cmd, SILC_COMMAND_LEAVE,
					 SILC_STATUS_ERR_NOT_ON_CHANNEL, 0,
					 2, tmp, len);
    goto out;
  }

  /* Notify routers that they should remove this client from their list
     of clients on the channel. Send LEAVE notify type. */
  silc_server_send_notify_leave(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), channel, id_entry->id);

  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  silc_server_command_send_status_data(cmd, SILC_COMMAND_LEAVE,
				       SILC_STATUS_OK, 0, 2, tmp, len);

  /* Remove client from channel */
  if (!silc_server_remove_from_one_channel(server, sock, channel, id_entry,
					   TRUE))
    /* If the channel does not exist anymore we won't send anything */
    goto out;

  if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
    /* Re-generate channel key */
    if (!silc_server_create_channel_key(server, channel, 0))
      goto out;

    /* Send the channel key */
    silc_server_send_channel_key(server, NULL, channel,
				 server->server_type == SILC_ROUTER ?
				 FALSE : !server->standalone);
  }

 out:
  silc_server_command_free(cmd);
}

/* Server side of command USERS. Resolves clients and their USERS currently
   joined on the requested channel. The list of Client ID's and their modes
   on the channel is sent back. */

SILC_SERVER_CMD_FUNC(users)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcIDListData idata = silc_packet_get_context(cmd->sock);
  SilcChannelEntry channel;
  SilcID id;
  SilcBuffer idp;
  unsigned char *channel_id;
  SilcUInt32 channel_id_len;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  unsigned char lc[4];
  SilcUInt32 list_count = 0;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  char *channel_name, *channel_namec = NULL;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_USERS, cmd, 1, 2);

  /* Get Channel ID */
  channel_id = silc_argument_get_arg_type(cmd->args, 1, &channel_id_len);

  /* Get channel name */
  channel_name = silc_argument_get_arg_type(cmd->args, 2, NULL);

  if (!channel_id && !channel_name) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Check channel name */
  if (channel_name) {
    channel_namec = silc_channel_name_check(channel_name, strlen(channel_name),
					    SILC_STRING_UTF8, 256, NULL);
    if (!channel_namec) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_BAD_CHANNEL, 0);
      goto out;
    }
  }

  /* Check Channel ID */
  if (channel_id) {
    if (!silc_id_payload_parse_id(channel_id, channel_id_len, &id)) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_USERS,
					   SILC_STATUS_ERR_BAD_CHANNEL_ID, 0,
					   2, channel_id, channel_id_len);
      goto out;
    }
  }

  /* If we are server and we don't know about this channel we will send
     the command to our router. If we know about the channel then we also
     have the list of users already. */
  if (channel_id)
    channel = silc_idlist_find_channel_by_id(server->local_list,
					     SILC_ID_GET_ID(id), NULL);
  else
    channel = silc_idlist_find_channel_by_name(server->local_list,
					       channel_namec, NULL);

  if (!channel || (!server->standalone && (channel->disabled ||
		    !channel->users_resolved))) {
    if (server->server_type != SILC_ROUTER && !server->standalone &&
	!cmd->pending) {
      SilcBuffer tmpbuf;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      /* Send USERS command */
      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply */
      silc_server_command_pending(server, SILC_COMMAND_USERS,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_users,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }

    /* Check the global list as well. */
    if (channel_id)
      channel = silc_idlist_find_channel_by_id(server->global_list,
					       SILC_ID_GET_ID(id), NULL);
    else
      channel = silc_idlist_find_channel_by_name(server->global_list,
						 channel_namec, NULL);
    if (!channel) {
      /* Channel really does not exist */
      if (channel_id)
	silc_server_command_send_status_data(
				    cmd, SILC_COMMAND_USERS,
				    SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID, 0,
				    2, channel_id, channel_id_len);
      else
	silc_server_command_send_status_data(
				    cmd, SILC_COMMAND_USERS,
				    SILC_STATUS_ERR_NO_SUCH_CHANNEL, 0,
				    2, channel_name, strlen(channel_name));
      goto out;
    }
  }

  /* If the channel is private or secret do not send anything, unless the
     user requesting this command is on the channel or is server */
  if (idata->conn_type == SILC_CONN_CLIENT) {
    if (channel->mode & (SILC_CHANNEL_MODE_PRIVATE | SILC_CHANNEL_MODE_SECRET)
	&& !silc_server_client_on_channel((SilcClientEntry)idata, channel,
					  NULL)) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_USERS,
					   SILC_STATUS_ERR_NO_SUCH_CHANNEL, 0,
					   2, channel->channel_name,
					   strlen(channel->channel_name));
      goto out;
    }
  }

  /* Get the users list */
  if (!silc_server_get_users_on_channel(server, channel, &client_id_list,
					&client_mode_list, &list_count)) {
    list_count = 0;
    client_id_list = NULL;
    client_mode_list = NULL;
  }

  /* List count */
  SILC_PUT32_MSB(list_count, lc);

  /* Send reply */
  idp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_USERS,
				 SILC_STATUS_OK, 0, ident, 4,
				 2, idp->data, silc_buffer_len(idp),
				 3, lc, 4,
				 4, client_id_list ?
				 client_id_list->data : NULL,
				 client_id_list ?
				 silc_buffer_len(client_id_list) : 0,
				 5, client_mode_list ?
				 client_mode_list->data : NULL,
				 client_mode_list ?
				 silc_buffer_len(client_mode_list) : 0);
  silc_buffer_free(idp);
  if (client_id_list)
    silc_buffer_free(client_id_list);
  if (client_mode_list)
    silc_buffer_free(client_mode_list);

 out:
  silc_free(channel_namec);
  silc_server_command_free(cmd);
}

/* Server side of command GETKEY. This fetches the client's public key
   from the server where to the client is connected. */

SILC_SERVER_CMD_FUNC(getkey)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client;
  SilcServerEntry server_entry;
  SilcClientID client_id;
  SilcServerID server_id;
  SilcIDPayload idp = NULL;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBuffer pk = NULL;
  SilcIdType id_type;
  SilcPublicKey public_key;

  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }
  idp = silc_id_payload_parse(tmp, tmp_len);
  if (!idp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  id_type = silc_id_payload_get_type(idp);
  if (id_type == SILC_ID_CLIENT) {
    silc_id_payload_get_id(idp, &client_id, sizeof(client_id));

    /* If the client is not found from local list there is no chance it
       would be locally connected client so send the command further. */
    client = silc_idlist_find_client_by_id(server->local_list,
					   &client_id, TRUE, NULL);
    if (!client)
      client = silc_idlist_find_client_by_id(server->global_list,
					     &client_id, TRUE, NULL);

    if ((!client && !cmd->pending && !server->standalone) ||
	(client && !client->connection && !cmd->pending &&
	 !(client->mode & SILC_UMODE_DETACHED)) ||
	(client && !client->data.public_key && !cmd->pending)) {
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;
      SilcPacketStream dest_sock;

      dest_sock = silc_server_get_client_route(server, NULL, 0,
					       &client_id, NULL, NULL);
      if (!dest_sock)
	goto out;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, dest_sock,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_GETKEY,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_getkey,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }

    if (!client) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_GETKEY,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   0, 2, tmp, tmp_len);
      goto out;
    }

    /* The client is locally connected, just get the public key and
       send it back. If they key does not exist then do not send it,
       send just OK reply */
    public_key = client->data.public_key;
    if (public_key)
      pk = silc_public_key_payload_encode(public_key);
  } else if (id_type == SILC_ID_SERVER) {
    silc_id_payload_get_id(idp, &server_id, sizeof(server_id));

    /* If the server is not found from local list there is no chance it
       would be locally connected server so send the command further. */
    server_entry = silc_idlist_find_server_by_id(server->local_list,
						 &server_id, TRUE, NULL);
    if (!server_entry)
      server_entry = silc_idlist_find_server_by_id(server->global_list,
						   &server_id, TRUE, NULL);

    if (server_entry != server->id_entry &&
	((!server_entry && !cmd->pending && !server->standalone) ||
	 (server_entry && !server_entry->connection && !cmd->pending &&
	  !server->standalone) ||
	 (server_entry && !server_entry->data.public_key && !cmd->pending &&
	  !server->standalone))) {
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, silc_buffer_len(tmpbuf));

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_GETKEY,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_getkey,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      goto out;
    }

    if (!server_entry) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_GETKEY,
					   SILC_STATUS_ERR_NO_SUCH_SERVER_ID,
					   0, 2, tmp, tmp_len);
      goto out;
    }

    /* If they key does not exist then do not send it, send just OK reply */
    public_key = (!server_entry->data.public_key ?
		  (server_entry == server->id_entry ? server->public_key :
		   NULL) : server_entry->data.public_key);
    if (public_key)
      pk = silc_public_key_payload_encode(public_key);
  } else {
    goto out;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_GETKEY,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, tmp, tmp_len,
				 3, pk ? pk->data : NULL,
				 pk ? silc_buffer_len(pk) : 0);

 out:
  if (idp)
    silc_id_payload_free(idp);
  silc_buffer_free(pk);
  silc_server_command_free(cmd);
}

/* Server side of command SERVICE. */
/* XXX currently this just sends empty reply back */

SILC_SERVER_CMD_FUNC(service)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcUInt32 tmp_len, auth_len;
  unsigned char *service_name, *auth;
  SilcBool send_list = FALSE;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_SERVICE, cmd, 0, 256);

  /* Get requested service */
  service_name = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (service_name && tmp_len) {
    /* Verify service name */
    if (!silc_identifier_verify(service_name, tmp_len,
				SILC_STRING_UTF8, 256)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_SERVICE,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }
  }

  /* Get authentication payload if present */
  auth = silc_argument_get_arg_type(cmd->args, 2, &auth_len);
  if (auth) {
    /* XXX */
  }


  send_list = TRUE;

  /* Send our service list back */
  silc_server_send_command_reply(server, cmd->sock, SILC_COMMAND_SERVICE,
				 SILC_STATUS_OK, 0, ident, 0);

 out:
  silc_server_command_free(cmd);
}


/* Private range commands, specific to this implementation */

/* Server side command of CONNECT. Connects us to the specified remote
   server or router. */

SILC_SERVER_CMD_FUNC(connect)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  unsigned char *tmp, *host;
  SilcUInt32 tmp_len;
  SilcUInt32 port = SILC_PORT;

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_PRIV_CONNECT, cmd, 1, 2);

  /* Check whether client has the permissions. */
  if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
      !(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CONNECT,
					  SILC_STATUS_ERR_NO_SERVER_PRIV, 0);
    goto out;
  }

  if (server->server_type == SILC_ROUTER && !server->backup_router &&
      client->mode & SILC_UMODE_SERVER_OPERATOR) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CONNECT,
					  SILC_STATUS_ERR_NO_ROUTER_PRIV, 0);
    goto out;
  }

  /* Get the remote server */
  host = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!host) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CONNECT,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Get port */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp)
    SILC_GET32_MSB(port, tmp);

  /* Create the connection. It is done with timeout and is async. */
  silc_server_create_connection(server, FALSE, FALSE, host, port, NULL, NULL);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CONNECT,
					SILC_STATUS_OK, 0);

 out:
  silc_server_command_free(cmd);
}

/* Server side command of CLOSE. Closes connection to a specified server. */

SILC_SERVER_CMD_FUNC(close)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);
  SilcServerEntry server_entry;
  SilcPacketStream sock;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  unsigned char *name;
  SilcUInt32 port = SILC_PORT;

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_PRIV_CLOSE, cmd, 1, 2);

  /* Check whether client has the permissions. */
  if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
      !(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CLOSE,
					  SILC_STATUS_ERR_NO_SERVER_PRIV,
					  0);
    goto out;
  }

  /* Get the remote server */
  name = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!name) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CLOSE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Get port */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp)
    SILC_GET32_MSB(port, tmp);

  server_entry = silc_idlist_find_server_by_conn(server->local_list,
						 name, port, TRUE, NULL);
  if (!server_entry)
    server_entry = silc_idlist_find_server_by_conn(server->global_list,
						   name, port, TRUE, NULL);
  if (!server_entry) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CLOSE,
					  SILC_STATUS_ERR_NO_SERVER_ID, 0);
    goto out;
  }

  if (server_entry == server->id_entry) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CLOSE,
					  SILC_STATUS_ERR_NO_SERVER_ID, 0);
    goto out;
  }

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CLOSE,
					SILC_STATUS_OK, 0);

  /* Close the connection to the server */
  sock = server_entry->connection;

  if (server_entry->server_type == SILC_BACKUP_ROUTER) {
    server->backup_closed = TRUE;
    silc_server_backup_del(server, server_entry);
  }

  server->backup_noswitch = TRUE;
  if (server->router == server_entry) {
    server->id_entry->router = NULL;
    server->router = NULL;
    server->standalone = TRUE;
  }
  silc_server_disconnect_remote(server, sock,
				SILC_STATUS_ERR_BANNED_FROM_SERVER,
				"Closed by administrator");
  silc_server_free_sock_user_data(server, sock, NULL);
  server->backup_noswitch = FALSE;

 out:
  silc_server_command_free(cmd);
}

/* Server side command of SHUTDOWN. Shutdowns the server and closes all
   active connections. */

SILC_SERVER_CMD_FUNC(shutdown)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);

  if (client->data.conn_type != SILC_CONN_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_PRIV_SHUTDOWN, cmd, 0, 0);

  /* Check whether client has the permission. */
  if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
      !(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_SHUTDOWN,
					  SILC_STATUS_ERR_NO_SERVER_PRIV,
					  0);
    goto out;
  }

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_SHUTDOWN,
					SILC_STATUS_OK, 0);

  /* Then, gracefully, or not, bring the server down. */
  silc_server_stop(server);
  exit(0);

 out:
  silc_server_command_free(cmd);
}
