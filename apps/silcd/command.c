/*

  command.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

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
				     SilcSocketConnection sock,
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
				     SilcSocketConnection sock,
				     SilcServerCommandContext cmd,
				     SilcCommand command)
{
  SilcIDListData idata = (SilcIDListData)sock->user_data;

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
  SilcClientEntry client = (SilcClientEntry)timeout->ctx->sock->user_data;

  if (!client) {
    SILC_LOG_DEBUG(("Client entry is invalid"));
    silc_server_command_free(timeout->ctx);
    silc_free(timeout);
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
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcServerCommandContext ctx;
  SilcServerCommand *cmd;
  SilcCommand command;

  /* Allocate command context. This must be free'd by the
     command routine receiving it. */
  ctx = silc_server_command_alloc();
  ctx->server = server;
  ctx->sock = silc_socket_dup(sock);
  ctx->packet = silc_packet_context_dup(packet); /* Save original packet */
  
  /* Parse the command payload in the packet */
  ctx->payload = silc_command_payload_parse(packet->buffer->data,
					    packet->buffer->len);
  if (!ctx->payload) {
    SILC_LOG_ERROR(("Bad command payload, packet dropped"));
    silc_packet_context_free(packet);
    silc_socket_free(ctx->sock);
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
    silc_server_command_free(ctx);
    return;
  }

  /* Execute client's commands always with timeout.  Normally they are
     executed with zero (0) timeout but if client is sending command more
     frequently than once in 2 seconds, then the timeout may be 0 to 2
     seconds. */
  if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
    SilcClientEntry client = (SilcClientEntry)sock->user_data;
    SilcServerCommandTimeout timeout;
    int fast;

    if (!client) {
      SILC_LOG_DEBUG(("Client entry is invalid"));
      silc_server_command_free(ctx);
    }

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
      silc_schedule_task_add(server->schedule, sock->sock, 
			     silc_server_command_process_timeout, timeout,
			     (client->fast_command < 3 ? 0 :
			      2 - (time(NULL) - client->last_command)),
			     (client->fast_command < 3 ? 200000 : 0),
			     SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    else
      silc_schedule_task_add(server->schedule, sock->sock, 
			     silc_server_command_process_timeout, timeout,
			     0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
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
      silc_packet_context_free(ctx->packet);
    if (ctx->sock)
      silc_socket_free(ctx->sock); /* Decrease reference counter */
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

  SILC_LOG_DEBUG(("Timeout pending command"));

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
  cmdr->payload = silc_command_payload_parse(tmpreply->data, tmpreply->len);
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

bool silc_server_command_pending(SilcServer server,
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

bool silc_server_command_pending_timed(SilcServer server,
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
    silc_schedule_task_add(server->schedule, 0,
			   silc_server_command_pending_timeout, reply,
			   timeout ? timeout : 10, 0,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
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

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer = 
    silc_command_reply_payload_encode_va(command, status, error,
					 silc_command_get_ident(cmd->payload),
					 0);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0, 
			  buffer->data, buffer->len, FALSE);
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

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer = 
    silc_command_reply_payload_encode_va(command, status, 0,
					 silc_command_get_ident(cmd->payload),
					 1, arg_type, arg, arg_len);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0, 
			  buffer->data, buffer->len, FALSE);
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

    /* Send the same command reply payload */
    silc_command_set_command(cmdr->payload, silc_command_get(cmd->payload));
    silc_command_set_ident(cmdr->payload, 
			   silc_command_get_ident(cmd->payload));
    buffer = silc_command_payload_encode_payload(cmdr->payload);
    silc_server_packet_send(cmd->server, cmd->sock,
			    SILC_PACKET_COMMAND_REPLY, 0, 
			    buffer->data, buffer->len, FALSE);
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
  silc_server_query_command(cmd->server, SILC_COMMAND_WHOIS, cmd);
  silc_server_command_free(cmd);
}

/* Server side of command WHOWAS. */

SILC_SERVER_CMD_FUNC(whowas)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WHOWAS, cmd, 1, 2);
  silc_server_query_command(cmd->server, SILC_COMMAND_WHOWAS, cmd);
  silc_server_command_free(cmd);
}

/* Server side of command IDENTIFY. */

SILC_SERVER_CMD_FUNC(identify)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_IDENTIFY, cmd, 1, 256);
  silc_server_query_command(cmd->server, SILC_COMMAND_IDENTIFY, cmd);
  silc_server_command_free(cmd);
}

/* Server side of command NICK. Sets nickname for user. Setting
   nickname causes generation of a new client ID for the client. The
   new client ID is sent to the client after changing the nickname. */

SILC_SERVER_CMD_FUNC(nick)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcServer server = cmd->server;
  SilcBuffer packet, nidp, oidp = NULL;
  SilcClientID *new_id;
  SilcUInt32 nick_len;
  char *nick;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  int nickfail = 0;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_NICK, cmd, 1, 1);

  /* Check nickname */
  nick = silc_argument_get_arg_type(cmd->args, 1, &nick_len);
  if (nick_len > 128)
    nick[128] = '\0';
  if (silc_server_name_bad_chars(nick, nick_len) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_BAD_NICKNAME, 0);
    goto out;
  }

  /* Check for same nickname */
  if (!strcmp(client->nickname, nick)) {
    nidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    goto send_reply;
  }

  /* Create new Client ID */
  while (!silc_id_create_client_id(cmd->server, cmd->server->id, 
				   cmd->server->rng, 
				   cmd->server->md5hash, nick,
				   &new_id)) {
    nickfail++;
    if (nickfail > 9) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					    SILC_STATUS_ERR_BAD_NICKNAME, 0);
      goto out;
    }
    snprintf(&nick[strlen(nick) - 1], 1, "%d", nickfail);
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

  /* Remove old cache entry */
  silc_idcache_del_by_context(server->local_list->clients, client);

  silc_free(client->id);
  client->id = new_id;

  silc_free(client->nickname);
  client->nickname = strdup(nick);

  /* Update client cache */
  silc_idcache_add(server->local_list->clients, client->nickname, 
		   client->id, (void *)client, 0, NULL);

  nidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Send NICK_CHANGE notify to the client's channels */
  silc_server_send_notify_on_channels(server, NULL, client, 
				      SILC_NOTIFY_TYPE_NICK_CHANGE, 3,
				      oidp->data, oidp->len, 
				      nidp->data, nidp->len,
				      client->nickname, 
				      strlen(client->nickname));

  /* Check if anyone is watching the new nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL,
				   SILC_NOTIFY_TYPE_NICK_CHANGE);

 send_reply:
  /* Send the new Client ID as reply command back to client */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_NICK, 
						SILC_STATUS_OK, 0, ident, 2,
						2, nidp->data, nidp->len,
						3, nick, strlen(nick));
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
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
  SilcBuffer packet, idp;
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
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_LIST, 
					   status, 0, ident, 4,
					   2, idp->data, idp->len,
					   3, entry->channel_name, 
					   strlen(entry->channel_name),
					   4, topic, topic ? strlen(topic) : 0,
					   5, usercount, 4);
    silc_server_packet_send(cmd->server, cmd->sock, 
			    SILC_PACKET_COMMAND_REPLY, 0, packet->data, 
			    packet->len, FALSE);
    silc_buffer_free(packet);
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
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_LIST, 
					   status, 0, ident, 4,
					   2, idp->data, idp->len,
					   3, entry->channel_name, 
					   strlen(entry->channel_name),
					   4, topic, topic ? strlen(topic) : 0,
					   5, usercount, 4);
    silc_server_packet_send(cmd->server, cmd->sock, 
			    SILC_PACKET_COMMAND_REPLY, 0, packet->data, 
			    packet->len, FALSE);
    silc_buffer_free(packet);
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
  SilcChannelID *channel_id = NULL;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcChannelEntry *lchannels = NULL, *gchannels = NULL;
  SilcUInt32 lch_count = 0, gch_count = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LIST, cmd, 0, 1);

  /* If we are normal server, send the command to router, since we
     want to know all channels in the network. */
  if (!cmd->pending && server->server_type == SILC_SERVER && 
      !server->standalone) {
    SilcBuffer tmpbuf;
    SilcUInt16 old_ident;
    
    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    tmpbuf->data, tmpbuf->len, TRUE);

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
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (tmp) {
    channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!channel_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_LIST,
					    SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
      goto out;
    }
  }

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
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcChannelID *channel_id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer packet, idp;
  unsigned char *tmp;
  SilcUInt32 argc, tmp_len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_TOPIC, cmd, 1, 2);

  argc = silc_argument_get_arg_num(cmd->args);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Check whether the channel exists */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  if (argc > 1) {
    /* Get the topic */
    tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
    if (!tmp) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    if (strlen(tmp) > 256) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    /* See whether the client is on channel and has rights to change topic */
    if (!silc_server_client_on_channel(client, channel, &chl)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ON_CHANNEL,
					    0);
      goto out;
    }

    if (channel->mode & SILC_CHANNEL_MODE_TOPIC &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					    0);
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
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, 
					 SILC_NOTIFY_TYPE_TOPIC_SET, 2,
					 idp->data, idp->len,
					 channel->topic,
					 strlen(channel->topic));
      silc_buffer_free(idp);
    }
  }

  /* Send the topic to client as reply packet */
  idp = silc_id_payload_encode(channel_id, SILC_ID_CHANNEL);
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_TOPIC, 
						SILC_STATUS_OK, 0, ident, 2, 
						2, idp->data, idp->len,
						3, channel->topic, 
						channel->topic ? 
						strlen(channel->topic) : 0);
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
  silc_buffer_free(idp);
  silc_free(channel_id);

 out:
  silc_server_command_free(cmd);
}

/* Server side of INVITE command. Invites some client to join some channel. 
   This command is also used to manage the invite list of the channel. */

SILC_SERVER_CMD_FUNC(invite)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock, dest_sock;
  SilcChannelClientEntry chl;
  SilcClientEntry sender, dest;
  SilcClientID *dest_id = NULL;
  SilcChannelEntry channel;
  SilcChannelID *channel_id = NULL;
  SilcIDListData idata;
  SilcBuffer idp, idp2, packet;
  unsigned char *tmp, *add, *del;
  SilcUInt32 len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INVITE, cmd, 1, 4);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  /* Check whether the sender of this command is on the channel. */
  sender = (SilcClientEntry)sock->user_data;
  if (!sender || !silc_server_client_on_channel(sender, channel, &chl)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL, 0);
    goto out;
  }

  /* Check whether the channel is invite-only channel. If yes then the
     sender of this command must be at least channel operator. */
  if (channel->mode & SILC_CHANNEL_MODE_INVITE &&
      !(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
      !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV,
					  0);
    goto out;
  }

  /* Get destination client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (tmp) {
    char invite[512];
    bool resolve;

    dest_id = silc_id_payload_parse_id(tmp, len, NULL);
    if (!dest_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NO_CLIENT_ID, 0);
      goto out;
    }

    /* Get the client entry */
    dest = silc_server_query_client(server, dest_id, FALSE, &resolve);
    if (!dest) {
      if (server->server_type != SILC_SERVER || !resolve) {
	silc_server_command_send_status_reply(
					cmd, SILC_COMMAND_INVITE,
					SILC_STATUS_ERR_NO_SUCH_CLIENT_ID, 0);
	goto out;
      }
      
      /* The client info is being resolved. Reprocess this packet after
	 receiving the reply to the query. */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				  server->cmd_ident,
				  silc_server_command_invite, 
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_free(channel_id);
      silc_free(dest_id);
      goto out;
    }

    /* Check whether the requested client is already on the channel. */
    if (silc_server_client_on_channel(dest, channel, NULL)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_USER_ON_CHANNEL,
					    0);
      goto out;
    }
    
    /* Get route to the client */
    dest_sock = silc_server_get_client_route(server, NULL, 0, dest_id, 
					     &idata, NULL);
    if (!dest_sock) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					    0);
      goto out;
    }

    memset(invite, 0, sizeof(invite));
    silc_strncat(invite, sizeof(invite),
		 dest->nickname, strlen(dest->nickname));
    silc_strncat(invite, sizeof(invite), "!", 1);
    silc_strncat(invite, sizeof(invite),
		 dest->username, strlen(dest->username));
    if (!strchr(dest->username, '@')) {
      silc_strncat(invite, sizeof(invite), "@", 1);
      silc_strncat(invite, sizeof(invite), cmd->sock->hostname,
		   strlen(cmd->sock->hostname));
    }

    len = strlen(invite);
    if (!channel->invite_list)
      channel->invite_list = silc_calloc(len + 2, 
					 sizeof(*channel->invite_list));
    else
      channel->invite_list = silc_realloc(channel->invite_list, 
					  sizeof(*channel->invite_list) * 
					  (len + 
					   strlen(channel->invite_list) + 2));
    strncat(channel->invite_list, invite, len);
    strncat(channel->invite_list, ",", 1);

    if (!(dest->mode & SILC_UMODE_BLOCK_INVITE)) {
      /* Send notify to the client that is invited to the channel */
      idp = silc_id_payload_encode(channel_id, SILC_ID_CHANNEL);
      idp2 = silc_id_payload_encode(sender->id, SILC_ID_CLIENT);
      silc_server_send_notify_dest(server, dest_sock, FALSE, dest_id, 
				   SILC_ID_CLIENT,
				   SILC_NOTIFY_TYPE_INVITE, 3, 
				   idp->data, idp->len, 
				   channel->channel_name, 
				   strlen(channel->channel_name),
				   idp2->data, idp2->len);
      silc_buffer_free(idp);
      silc_buffer_free(idp2);
    }
  }

  /* Add the client to the invite list of the channel */
  add = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (add) {
    if (!channel->invite_list)
      channel->invite_list = silc_calloc(len + 2, 
					 sizeof(*channel->invite_list));
    else
      channel->invite_list = silc_realloc(channel->invite_list, 
					  sizeof(*channel->invite_list) * 
					  (len + 
					   strlen(channel->invite_list) + 2));
    if (add[len - 1] == ',')
      add[len - 1] = '\0';
    
    strncat(channel->invite_list, add, len);
    strncat(channel->invite_list, ",", 1);
  }

  /* Get the invite to be removed and remove it from the list */
  del = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (del && channel->invite_list) {
    char *start, *end, *n;

    if (!strncmp(channel->invite_list, del, 
		 strlen(channel->invite_list) - 1)) {
      silc_free(channel->invite_list);
      channel->invite_list = NULL;
    } else {
      start = strstr(channel->invite_list, del);
      if (start && strlen(start) >= len) {
	end = start + len;
	n = silc_calloc(strlen(channel->invite_list) - len, sizeof(*n));
	strncat(n, channel->invite_list, start - channel->invite_list);
	strncat(n, end + 1, ((channel->invite_list + 
			      strlen(channel->invite_list)) - end) - 1);
	silc_free(channel->invite_list);
	channel->invite_list = n;
      }
    }
  }

  /* Send notify to the primary router */
  silc_server_send_notify_invite(server, SILC_PRIMARY_ROUTE(server),
				 SILC_BROADCAST(server), channel,
				 sender->id, add, del);

  /* Send command reply */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);

  if (add || del)
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_INVITE,
					   SILC_STATUS_OK, 0, ident, 2,
					   2, tmp, len,
					   3, channel->invite_list,
					   channel->invite_list ?
					   strlen(channel->invite_list) : 0);
  else
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_INVITE,
					   SILC_STATUS_OK, 0, ident, 1,
					   2, tmp, len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);

 out:
  silc_free(dest_id);
  silc_free(channel_id);
  silc_server_command_free(cmd);
}

typedef struct {
  SilcSocketConnection sock;
  char *signoff;
} *QuitInternal;

/* Quits connection to client. This gets called if client won't
   close the connection even when it has issued QUIT command. */

SILC_TASK_CALLBACK(silc_server_command_quit_cb)
{
  SilcServer server = app_context;
  QuitInternal q = (QuitInternal)context;

  /* Free all client specific data, such as client entry and entires
     on channels this client may be on. */
  silc_server_free_client_data(server, q->sock, q->sock->user_data,
			       TRUE, q->signoff);
  q->sock->user_data = NULL;

  /* Close the connection on our side */
  silc_server_close_connection(server, q->sock);

  silc_socket_free(q->sock);
  silc_free(q->signoff);
  silc_free(q);
}

/* Quits SILC session. This is the normal way to disconnect client. */
 
SILC_SERVER_CMD_FUNC(quit)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;
  QuitInternal q;
  unsigned char *tmp = NULL;
  SilcUInt32 len = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_QUIT, cmd, 0, 1);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Get message */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (len > 128)
    tmp = NULL;

  q = silc_calloc(1, sizeof(*q));
  q->sock = silc_socket_dup(sock);
  q->signoff = tmp ? strdup(tmp) : NULL;

  /* We quit the connection with little timeout */
  silc_schedule_task_add(server->schedule, sock->sock,
			 silc_server_command_quit_cb, (void *)q,
			 0, 200000, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command KILL. This command is used by router operator
   to remove an client from the SILC Network temporarily. */

SILC_SERVER_CMD_FUNC(kill)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcClientEntry remote_client;
  SilcClientID *client_id;
  unsigned char *tmp, *comment;
  SilcUInt32 tmp_len, tmp_len2;
  bool local;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_KILL, cmd, 1, 2);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

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

  /* Get the client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					  0);
    goto out;
  }

  /* Get the client entry */
  remote_client = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
  local = TRUE;
  if (!remote_client) {
    remote_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, TRUE, NULL);
    local = FALSE;
    if (!remote_client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					    SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					    0);
      goto out;
    }
  }

  /* Get comment */
  comment = silc_argument_get_arg_type(cmd->args, 2, &tmp_len2);
  if (tmp_len2 > 128)
    tmp_len2 = 128;

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					SILC_STATUS_OK, 0);

  /* Check if anyone is watching this nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL,
				   SILC_NOTIFY_TYPE_KILLED);

  /* Now do the killing */
  silc_server_kill_client(server, remote_client, comment, client->id,
			  SILC_ID_CLIENT);

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
  SilcBuffer packet, idp;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  char *dest_server, *server_info = NULL, *server_name;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcServerEntry entry = NULL;
  SilcServerID *server_id = NULL;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INFO, cmd, 0, 2);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp) {
    server_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!server_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					    SILC_STATUS_ERR_NO_SERVER_ID, 0);
      goto out;
    }
  }

  if (server_id) {
    /* Check whether we have this server cached */
    entry = silc_idlist_find_server_by_id(server->local_list,
					  server_id, TRUE, NULL);
    if (!entry) {
      entry = silc_idlist_find_server_by_id(server->global_list,
					    server_id, TRUE, NULL);
      if (!entry && server->server_type != SILC_SERVER) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					      SILC_STATUS_ERR_NO_SUCH_SERVER,
					      0);
	goto out;
      }
    }
  }

  /* Some buggy servers has sent request to router about themselves. */
  if (server->server_type != SILC_SERVER && cmd->sock->user_data == entry)
    goto out;

  if ((!dest_server && !server_id && !entry) || (entry && 
						 entry == server->id_entry) ||
      (dest_server && !cmd->pending && 
       !strncasecmp(dest_server, server->server_name, strlen(dest_server)))) {
    /* Send our reply */
    char info_string[256];

    memset(info_string, 0, sizeof(info_string));
    snprintf(info_string, sizeof(info_string), 
	     "location: %s server: %s admin: %s <%s>",
	     server->config->server_info->location,
	     server->config->server_info->server_type,
	     server->config->server_info->admin,
	     server->config->server_info->email);

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

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, entry->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

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

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

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

  silc_free(server_id);

  if (!entry) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_NO_SUCH_SERVER, 0);
    goto out;
  }

  idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
  if (!server_info)
    server_info = entry->server_info;
  server_name = entry->server_name;

  /* Send the reply */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_INFO,
						SILC_STATUS_OK, 0, ident, 3,
						2, idp->data, idp->len,
						3, server_name, 
						strlen(server_name),
						4, server_info, 
						server_info ? 
						strlen(server_info) : 0);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_buffer_free(idp);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command PING. This just replies to the ping. */

SILC_SERVER_CMD_FUNC(ping)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcServerID *id;
  SilcUInt32 len;
  unsigned char *tmp;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INFO, cmd, 1, 2);

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NO_SERVER_ID, 0);
    goto out;
  }
  id = silc_id_str2id(tmp, len, SILC_ID_SERVER);
  if (!id)
    goto out;

  if (SILC_ID_SERVER_COMPARE(id, server->id)) {
    /* Send our reply */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_OK, 0);
  } else {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NO_SUCH_SERVER, 0);
    goto out;
  }

  silc_free(id);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command STATS. */

SILC_SERVER_CMD_FUNC(stats)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcServerID *server_id;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBuffer packet, stats;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcUInt32 uptime;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_STATS, cmd, 1, 1);

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_NO_SERVER_ID, 0);
    goto out;
  }
  server_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!server_id)
    goto out;

  /* The ID must be ours */
  if (!SILC_ID_SERVER_COMPARE(server->id, server_id)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_NO_SUCH_SERVER, 0);
    silc_free(server_id);
    goto out;
  }
  silc_free(server_id);

  /* If we are router then just send everything we got. If we are normal
     server then we'll send this to our router to get all the latest
     statistical information. */
  if (!cmd->pending && server->server_type != SILC_ROUTER && 
      !server->standalone) {
    /* Send request to our router */
    SilcBuffer idp = silc_id_payload_encode(server->router->id, 
					    SILC_ID_SERVER);
    packet = silc_command_payload_encode_va(SILC_COMMAND_STATS, 
					    ++server->cmd_ident, 1,
					    1, idp->data, idp->len);
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_COMMAND, 0, packet->data,
			    packet->len, FALSE);

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

  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_STATS, 
						SILC_STATUS_OK, 0, ident, 2,
						2, tmp, tmp_len,
						3, stats->data, stats->len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);
  silc_buffer_free(packet);
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
					     bool created,
					     bool create_key,
					     SilcUInt32 umode,
					     const unsigned char *auth,
					     SilcUInt32 auth_len)
{
  SilcSocketConnection sock = cmd->sock;
  unsigned char *tmp;
  SilcUInt32 tmp_len, user_count;
  unsigned char *passphrase = NULL, mode[4], tmp2[4], tmp3[4];
  SilcClientEntry client;
  SilcChannelClientEntry chl;
  SilcBuffer reply, chidp, clidp, keyp = NULL, user_list, mode_list;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  char check[512], check2[512];
  bool founder = FALSE;
  bool resolve;
  unsigned char *fkey = NULL;
  SilcUInt32 fkey_len = 0;

  SILC_LOG_DEBUG(("Joining client to channel"));

  if (!channel)
    return;

  /* Get the client entry */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    client = (SilcClientEntry)sock->user_data;
    if (!client)
      return;
  } else {
    client = silc_server_query_client(server, client_id, FALSE, 
				      &resolve);
    if (!client) {
      if (cmd->pending)
	goto out;

      if (!resolve) {
	silc_server_command_send_status_reply(
					 cmd, SILC_COMMAND_JOIN,
					 SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
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
		   cmd->sock->hostname, strlen(cmd->sock->hostname));
    }

    silc_strncat(check2, sizeof(check2),
		 client->nickname, strlen(client->nickname));
    if (!strchr(client->nickname, '@')) {
      silc_strncat(check2, sizeof(check2), "@", 1);
      silc_strncat(check2, sizeof(check2),
		   server->server_name, strlen(server->server_name));
    }
    silc_strncat(check2, sizeof(check2), "!", 1);
    silc_strncat(check2, sizeof(check2),
		 client->username, strlen(client->username));
    if (!strchr(client->username, '@')) {
      silc_strncat(check2, sizeof(check2), "@", 1);
      silc_strncat(check2, sizeof(check2),
		   cmd->sock->hostname, strlen(cmd->sock->hostname));
    }
    
    /* Check invite list if channel is invite-only channel */
    if (channel->mode & SILC_CHANNEL_MODE_INVITE) {
      if (!channel->invite_list ||
	  (!silc_string_match(channel->invite_list, check) &&
	   !silc_string_match(channel->invite_list, check2))) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					      SILC_STATUS_ERR_NOT_INVITED, 0);
	goto out;
      }
    }

    /* Check ban list if it exists. If the client's nickname, server,
       username and/or hostname is in the ban list the access to the
       channel is denied. */
    if (channel->ban_list) {
      if (silc_string_match(channel->ban_list, check) ||
	  silc_string_match(channel->ban_list, check2)) {
	silc_server_command_send_status_reply(
				      cmd, SILC_COMMAND_JOIN,
				      SILC_STATUS_ERR_BANNED_FROM_CHANNEL, 0);
	goto out;
      }
    }
    
    /* Check user count limit if set. */
    if (channel->mode & SILC_CHANNEL_MODE_ULIMIT) {
      if (silc_hash_table_count(channel->user_list) + 1 > 
	  channel->user_limit) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					      SILC_STATUS_ERR_CHANNEL_IS_FULL,
					      0);
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
        memcmp(passphrase, channel->passphrase, strlen(channel->passphrase))) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_BAD_PASSWORD, 0);
      goto out;
    }
  }

  /*
   * Client is allowed to join to the channel. Make it happen.
   */

  /* Check whether the client already is on the channel */
  if (silc_server_client_on_channel(client, channel, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_USER_ON_CHANNEL, 0);
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

  if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
    tmp = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
    keyp = silc_channel_key_payload_encode(silc_id_get_len(channel->id,
							   SILC_ID_CHANNEL), 
					   tmp,
					   strlen(channel->channel_key->
						  cipher->name),
					   channel->channel_key->cipher->name,
					   channel->key_len / 8, channel->key);
    silc_free(tmp);
  }

  if (channel->founder_key)
    fkey = silc_pkcs_public_key_encode(channel->founder_key, &fkey_len);

  reply = 
    silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					 SILC_STATUS_OK, 0, ident, 14,
					 2, channel->channel_name,
					 strlen(channel->channel_name),
					 3, chidp->data, chidp->len,
					 4, clidp->data, clidp->len,
					 5, mode, 4,
					 6, tmp2, 4,
					 7, keyp ? keyp->data : NULL, 
					 keyp ? keyp->len : 0,
					 8, channel->ban_list, 
					 channel->ban_list ?
					 strlen(channel->ban_list) : 0,
					 9, channel->invite_list,
					 channel->invite_list ?
					 strlen(channel->invite_list) : 0,
					 10, channel->topic,
					 channel->topic ?
					 strlen(channel->topic) : 0,
					 11, silc_hmac_get_name(channel->hmac),
					 strlen(silc_hmac_get_name(channel->
								   hmac)),
					 12, tmp3, 4,
					 13, user_list->data, user_list->len,
					 14, mode_list->data, 
					 mode_list->len,
					 15, fkey, fkey_len);

  /* Send command reply */
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  reply->data, reply->len, FALSE);

  /* Send JOIN notify to locally connected clients on the channel. If
     we are normal server then router will send or have sent JOIN notify
     already. However since we've added the client already to our channel
     we'll ignore it (in packet_receive.c) so we must send it here. If
     we are router then this will send it to local clients and local
     servers. */
  SILC_LOG_DEBUG(("Send JOIN notify to channel"));
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE, 
				     SILC_NOTIFY_TYPE_JOIN, 2,
				     clidp->data, clidp->len,
				     chidp->data, chidp->len);

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
			      keyp->data, keyp->len, FALSE, TRUE);

    /* If client became founder by providing correct founder auth data
       notify the mode change to the channel. */
    if (founder) {
      SILC_PUT32_MSB(chl->mode, mode);
      SILC_LOG_DEBUG(("Send CUMODE_CHANGE notify to channel"));
      silc_server_send_notify_to_channel(server, NULL, channel, FALSE, 
					 SILC_NOTIFY_TYPE_CUMODE_CHANGE, 4,
					 clidp->data, clidp->len,
					 mode, 4, clidp->data, clidp->len,
					 fkey, fkey_len);
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
  silc_free(fkey);

 out:
  silc_free(passphrase);
}

/* Server side of command JOIN. Joins client into requested channel. If 
   the channel does not exist it will be created. */

SILC_SERVER_CMD_FUNC(join)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  unsigned char *auth;
  SilcUInt32 tmp_len, auth_len;
  char *tmp, *channel_name = NULL, *cipher, *hmac;
  SilcChannelEntry channel;
  SilcUInt32 umode = 0;
  bool created = FALSE, create_key = TRUE;
  SilcClientID *client_id;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_JOIN, cmd, 2, 6);

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }
  channel_name = tmp;

  if (tmp_len > 256)
    channel_name[255] = '\0';

  if (silc_server_name_bad_chars(channel_name, tmp_len) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_BAD_CHANNEL, 0);
    goto out;
  }

  /* Get Client ID of the client who is joining to the channel */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Get cipher, hmac name and auth payload */
  cipher = silc_argument_get_arg_type(cmd->args, 4, NULL);
  hmac = silc_argument_get_arg_type(cmd->args, 5, NULL);
  auth = silc_argument_get_arg_type(cmd->args, 6, &auth_len);

  /* See if the channel exists */
  channel = silc_idlist_find_channel_by_name(server->local_list, 
					     channel_name, NULL);

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    SilcClientEntry entry = (SilcClientEntry)cmd->sock->user_data;
    if (!entry) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					    0);
      goto out;
    }

    silc_free(client_id);
    client_id = silc_id_dup(entry->id, SILC_ID_CLIENT);

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
	    silc_server_command_send_status_reply(
				  cmd, SILC_COMMAND_JOIN,
				  SILC_STATUS_ERR_UNKNOWN_ALGORITHM,
				  0);
	    silc_free(client_id);
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
	  if (cmd->pending) {
	    silc_free(client_id);
	    goto out;
	  }
	  
	  old_ident = silc_command_get_ident(cmd->payload);
	  silc_command_set_ident(cmd->payload, ++server->cmd_ident);
	  tmpbuf = silc_command_payload_encode_payload(cmd->payload);
	  
	  /* Send JOIN command to our router */
	  silc_server_packet_send(server, (SilcSocketConnection)
				  SILC_PRIMARY_ROUTE(server),
				  SILC_PACKET_COMMAND, cmd->packet->flags,
				  tmpbuf->data, tmpbuf->len, TRUE);
	  
	  /* Reprocess this packet after received reply from router */
	  silc_server_command_pending(server, SILC_COMMAND_JOIN, 
				      silc_command_get_ident(cmd->payload),
				      silc_server_command_join,
				      silc_server_command_dup(cmd));
	  cmd->pending = TRUE;
          silc_command_set_ident(cmd->payload, old_ident);
	  silc_buffer_free(tmpbuf);
	  silc_free(client_id);
	  goto out;
	}
	
	/* We are router and the channel does not seem exist so we will check
	   our global list as well for the channel. */
	channel = silc_idlist_find_channel_by_name(server->global_list, 
						   channel_name, NULL);
	if (!channel) {
	  /* Channel really does not exist, create it */
	  channel = silc_server_create_new_channel(server, server->id, cipher, 
						   hmac, channel_name, TRUE);
	  if (!channel) {
	    silc_server_command_send_status_reply(
				       cmd, SILC_COMMAND_JOIN,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0);
	    silc_free(client_id);
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
      if (cmd->sock->type == SILC_SOCKET_TYPE_ROUTER ||
	  server->server_type != SILC_ROUTER) {
	silc_free(client_id);
	goto out;
      }
      
      /* We are router and the channel does not seem exist so we will check
	 our global list as well for the channel. */
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 channel_name, NULL);
      if (!channel) {
	/* Channel really does not exist, create it */
	channel = silc_server_create_new_channel(server, server->id, cipher, 
						 hmac, channel_name, TRUE);
	if (!channel) {
	  silc_server_command_send_status_reply(
				       cmd, SILC_COMMAND_JOIN,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0);
	  silc_free(client_id);
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
  silc_server_command_join_channel(server, cmd, channel, client_id,
				   created, create_key, umode,
				   auth, auth_len);

  silc_free(client_id);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command MOTD. Sends server's current "message of the
   day" to the client. */

SILC_SERVER_CMD_FUNC(motd)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcBuffer packet, idp;
  char *motd, *dest_server;
  SilcUInt32 motd_len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_MOTD, cmd, 1, 1);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (!dest_server) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_MOTD,
					  SILC_STATUS_ERR_NO_SUCH_SERVER, 0);
    goto out;
  }

  if (!strncasecmp(dest_server, server->server_name, strlen(dest_server))) {
    /* Send our MOTD */

    idp = silc_id_payload_encode(server->id_entry->id, SILC_ID_SERVER);

    if (server->config && server->config->server_info &&
	server->config->server_info->motd_file) {
      /* Send motd */
      motd = silc_file_readfile(server->config->server_info->motd_file,
				&motd_len);
      if (!motd)
	goto out;
      
      motd[motd_len] = 0;
      packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						    SILC_STATUS_OK, 0, 
						    ident, 2,
						    2, idp, idp->len,
						    3, motd, motd_len);
    } else {
      /* No motd */
      packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						    SILC_STATUS_OK, 0, 
						    ident, 1,
						    2, idp, idp->len);
    }

    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			    packet->data, packet->len, FALSE);
    silc_buffer_free(packet);
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

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, entry->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

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

    if (!entry && !cmd->pending && !server->standalone) {
      /* Send to the primary router */
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

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
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					    SILC_STATUS_ERR_NO_SUCH_SERVER, 0);
      goto out;
    }

    idp = silc_id_payload_encode(server->id_entry->id, SILC_ID_SERVER);
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						  SILC_STATUS_OK, 0, ident, 2,
						  2, idp, idp->len,
						  3, entry->motd,
						  entry->motd ? 
						  strlen(entry->motd) : 0);
    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			    packet->data, packet->len, FALSE);
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

 out:
  silc_server_command_free(cmd);
}

/* Server side of command UMODE. Client can use this command to set/unset
   user mode. Client actually cannot set itself to be as server/router
   operator so this can be used only to unset the modes. */

SILC_SERVER_CMD_FUNC(umode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcBuffer packet;
  unsigned char *tmp_mask, m[4];
  SilcUInt32 mask = 0;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  bool set_mask = FALSE;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_UMODE, cmd, 1, 2);

  /* Get the client's mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (tmp_mask) {
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
    if (mask & SILC_UMODE_ANONYMOUS) {
      if (!(client->mode & SILC_UMODE_ANONYMOUS)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					      SILC_STATUS_ERR_PERM_DENIED, 0);
	goto out;
      }
    } else {
      if (client->mode & SILC_UMODE_ANONYMOUS) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					      SILC_STATUS_ERR_PERM_DENIED, 0);
	goto out;
      }
    }

    /* Update statistics */
    if (mask & SILC_UMODE_GONE) {
      if (!(client->mode & SILC_UMODE_GONE))
	server->stat.my_aways++;
    } else {
      if (client->mode & SILC_UMODE_GONE)
	server->stat.my_aways--;
    }

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
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_UMODE,
						SILC_STATUS_OK, 0, ident, 1,
						2, m, sizeof(m));
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);

 out:
  silc_server_command_free(cmd);
}

/* Server side command of CMODE. Changes channel mode */

SILC_SERVER_CMD_FUNC(cmode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcIDListData idata = (SilcIDListData)client;
  SilcChannelID *channel_id = NULL;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer packet, cidp;
  unsigned char *tmp, *tmp_id, *tmp_mask;
  char *cipher = NULL, *hmac = NULL, *passphrase = NULL;
  SilcUInt32 mode_mask = 0, old_mask = 0, tmp_len, tmp_len2;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  bool set_mask = FALSE;
  SilcPublicKey founder_key = NULL;
  unsigned char *fkey = NULL;
  SilcUInt32 fkey_len = 0;

  if (!client) {
    silc_server_command_free(cmd);
    return;
  }

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CMODE, cmd, 1, 7);

  /* Get Channel ID */
  tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
  if (!tmp_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    silc_server_command_free(cmd);
    return;
  }
  channel_id = silc_id_payload_parse_id(tmp_id, tmp_len2, NULL);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    silc_server_command_free(cmd);
    return;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      silc_free(channel_id);
      silc_server_command_free(cmd);
      return;
    }
  }
  old_mask = channel->mode;

  /* Get the channel mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp_mask) {
    SILC_GET32_MSB(mode_mask, tmp_mask);
    set_mask = TRUE;
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL, 0);
    goto out;
  }

  /* Check that client has rights to change any requested channel modes */
  if (set_mask && !silc_server_check_cmode_rights(server, channel, chl, 
						  mode_mask)) {
    SILC_LOG_DEBUG(("Client does not have rights to change mode"));
    silc_server_command_send_status_reply(
			     cmd, SILC_COMMAND_CMODE,
			     (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) ? 
			      SILC_STATUS_ERR_NO_CHANNEL_PRIV :
			      SILC_STATUS_ERR_NO_CHANNEL_FOPRIV), 0);
    goto out;
  }

  /* If mode mask was not sent as argument then merely return the current
     mode mask to the sender. */
  if (!set_mask) {
    unsigned char m[4];
    SILC_PUT32_MSB(channel->mode, m);
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CMODE,
						  SILC_STATUS_OK, 0, ident, 2,
						  2, tmp_id, tmp_len2,
						  3, m, sizeof(m));
    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0,
			    packet->data, packet->len, FALSE);
    silc_buffer_free(packet);
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
      
      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0))
	goto out;
	
      /* Send the channel key. This sends it to our local clients and if
	 we are normal server to our router as well. */
      silc_server_send_channel_key(server, NULL, channel, 
				   server->server_type == SILC_ROUTER ? 
				   FALSE : !server->standalone);
	
      cipher = channel->channel_key->cipher->name;
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
      SilcCipher newkey, oldkey;

      /* Get cipher */
      cipher = silc_argument_get_arg_type(cmd->args, 5, NULL);
      if (!cipher) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
	goto out;
      }

      /* Delete old cipher and allocate the new one */
      if (!silc_cipher_alloc(cipher, &newkey)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0);
	goto out;
      }

      oldkey = channel->channel_key;
      channel->channel_key = newkey;

      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0)) {
	/* We don't have new key, revert to old one */
	channel->channel_key = oldkey;
	goto out;
      }

      /* Remove old channel key for good */
      silc_cipher_free(oldkey);

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
      SilcCipher newkey, oldkey;
      cipher = channel->cipher;

      /* Delete old cipher and allocate default one */
      if (!silc_cipher_alloc(cipher ? cipher : SILC_DEFAULT_CIPHER, &newkey)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0);
	goto out;
      }

      oldkey = channel->channel_key;
      channel->channel_key = newkey;

      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0)) {
	/* We don't have new key, revert to old one */
	channel->channel_key = oldkey;
	goto out;
      }
      
      /* Remove old channel key for good */
      silc_cipher_free(oldkey);

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
      unsigned char hash[32];
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
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0);
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
      unsigned char hash[32];
      hmac = channel->hmac_name;

      /* Delete old hmac and allocate default one */
      silc_hmac_free(channel->hmac);
      if (!silc_hmac_alloc(hmac ? hmac : SILC_DEFAULT_HMAC, NULL, &newhmac)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM, 0);
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
      if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)) {
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
				   idata->public_key, 0, server->sha1hash,
				   client->id, SILC_ID_CLIENT)) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
						SILC_STATUS_ERR_AUTH_FAILED,
						0);
	  goto out;
	}

	/* Save the public key */
	channel->founder_key = silc_pkcs_public_key_copy(idata->public_key);
        if (!channel->founder_key) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
						SILC_STATUS_ERR_AUTH_FAILED,
						0);
	  goto out;
        }

	founder_key = channel->founder_key;
	fkey = silc_pkcs_public_key_encode(founder_key, &fkey_len);
        if (!fkey) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
						SILC_STATUS_ERR_AUTH_FAILED,
						0);
	  silc_pkcs_public_key_free(channel->founder_key);
	  channel->founder_key = NULL;
	  goto out;
        }
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

  /* Finally, set the mode */
  old_mask = channel->mode = mode_mask;

  /* Send CMODE_CHANGE notify. */
  cidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				     SILC_NOTIFY_TYPE_CMODE_CHANGE, 6,
				     cidp->data, cidp->len, 
				     tmp_mask, 4,
				     cipher, cipher ? strlen(cipher) : 0,
				     hmac, hmac ? strlen(hmac) : 0,
				     passphrase, passphrase ? 
				     strlen(passphrase) : 0,
				     fkey, fkey_len);

  /* Set CMODE notify type to network */
  silc_server_send_notify_cmode(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), channel,
				mode_mask, client->id, SILC_ID_CLIENT,
				cipher, hmac, passphrase, founder_key);

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CMODE,
						SILC_STATUS_OK, 0, ident, 2,
						2, tmp_id, tmp_len2,
						3, tmp_mask, 4);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
  silc_buffer_free(cidp);

 out:
  channel->mode = old_mask;
  silc_free(fkey);
  silc_free(channel_id);
  silc_server_command_free(cmd);
}

/* Server side of CUMODE command. Changes client's mode on a channel. */

SILC_SERVER_CMD_FUNC(cumode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcIDListData idata = (SilcIDListData)client;
  SilcChannelID *channel_id;
  SilcClientID *client_id;
  SilcChannelEntry channel;
  SilcClientEntry target_client;
  SilcChannelClientEntry chl;
  SilcBuffer packet, idp;
  unsigned char *tmp_id, *tmp_ch_id, *tmp_mask;
  SilcUInt32 target_mask, sender_mask = 0, tmp_len, tmp_ch_len;
  int notify = FALSE;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  SilcPublicKey founder_key = NULL;
  unsigned char *fkey = NULL;
  SilcUInt32 fkey_len = 0;

  if (!client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CUMODE, cmd, 3, 4);

  /* Get Channel ID */
  tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
  if (!tmp_ch_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp_ch_id, tmp_ch_len, NULL);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL, 0);
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
  tmp_id = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp_id, tmp_len, NULL);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }

  /* Get target client's entry */
  target_client = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
  if (!target_client) {
    target_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, TRUE, NULL);
  }

  if (target_client != client &&
      !(sender_mask & SILC_CHANNEL_UMODE_CHANFO) &&
      !(sender_mask & SILC_CHANNEL_UMODE_CHANOP)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV, 0);
    goto out;
  }

  /* Check whether target client is on the channel */
  if (target_client != client) {
    if (!silc_server_client_on_channel(target_client, channel, &chl)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
				 SILC_STATUS_ERR_USER_NOT_ON_CHANNEL, 0);
      goto out;
    }
  }

  /* 
   * Change the mode 
   */

  /* If the target client is founder, no one else can change their mode
     but themselves. */
  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO && client != target_client) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_FOPRIV,
					  0);
    goto out;
  }

  if (target_mask & SILC_CHANNEL_UMODE_CHANFO) {
    if (target_client != client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					    SILC_STATUS_ERR_NOT_YOU, 0);
      goto out;
    }

    if (!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      /* The client tries to claim the founder rights. */
      unsigned char *tmp_auth;
      SilcUInt32 tmp_auth_len;
      SilcChannelClientEntry chl2;
      SilcHashTableList htl;

      if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) ||
	  !channel->founder_key || !idata->public_key ||
	  !silc_pkcs_public_key_compare(channel->founder_key, 
					idata->public_key)) {
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
      fkey = silc_pkcs_public_key_encode(founder_key, &fkey_len);
      if (!fkey) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_AUTH_FAILED, 0);
	goto out;
      }

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
        silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
                                              SILC_STATUS_ERR_NO_CHANNEL_PRIV,
                                              0);
        goto out;
      }

      chl->mode |= SILC_CHANNEL_UMODE_CHANOP;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANOP) {
      if (!(sender_mask & SILC_CHANNEL_UMODE_CHANOP) &&
          !(sender_mask & SILC_CHANNEL_UMODE_CHANFO)) {
        silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,   
                                              SILC_STATUS_ERR_NO_CHANNEL_PRIV,
                                              0);
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

  /* Send notify to channel, notify only if mode was actually changed. */
  if (notify) {
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE, 
				       SILC_NOTIFY_TYPE_CUMODE_CHANGE, 4,
				       idp->data, idp->len,
				       tmp_mask, 4, 
				       tmp_id, tmp_len,
				       fkey, fkey_len);

    /* Set CUMODE notify type to network */
    silc_server_send_notify_cumode(server, SILC_PRIMARY_ROUTE(server),
				   SILC_BROADCAST(server), channel,
				   target_mask, client->id, SILC_ID_CLIENT,
				   target_client->id, founder_key);
  }

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CUMODE,
						SILC_STATUS_OK, 0, ident, 3,
						2, tmp_mask, 4,
						3, tmp_ch_id, tmp_ch_len,
						4, tmp_id, tmp_len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_free(channel_id);
  silc_free(client_id);
  silc_buffer_free(idp);

 out:
  silc_free(fkey);
  silc_server_command_free(cmd);
}

/* Server side of KICK command. Kicks client out of channel. */

SILC_SERVER_CMD_FUNC(kick)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcClientEntry target_client;
  SilcChannelID *channel_id;
  SilcClientID *client_id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer idp;
  SilcUInt32 tmp_len, target_idp_len;
  unsigned char *tmp, *comment, *target_idp;

  if (!client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LEAVE, cmd, 1, 3);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->local_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL, 0);
    goto out;
  }

  /* Check that the kicker is channel operator or channel founder */
  if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
      !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV, 0);
    goto out;
  }
  
  /* Get target Client ID */
  target_idp = silc_argument_get_arg_type(cmd->args, 2, &target_idp_len);
  if (!target_idp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }
  client_id = silc_id_payload_parse_id(target_idp, target_idp_len, NULL);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CLIENT_ID, 0);
    goto out;
  }

  /* Get target client's entry */
  target_client = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
  if (!target_client) {
    target_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, TRUE, NULL);
  }

  /* Check whether target client is on the channel */
  if (!silc_server_client_on_channel(target_client, channel, &chl)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_USER_NOT_ON_CHANNEL,
					  0);
    goto out;
  }

  /* Check that the target client is not channel founder. Channel founder
     cannot be kicked from the channel. */
  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_FOPRIV,
					  0);
    goto out;
  }
  
  /* Get comment */
  tmp_len = 0;
  comment = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp_len > 128)
    comment = NULL;

  /* Send command reply to sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK, 
					SILC_STATUS_OK, 0);

  /* Send KICKED notify to local clients on the channel */
  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				     SILC_NOTIFY_TYPE_KICKED, 3,
				     target_idp, target_idp_len,
				     comment, comment ? strlen(comment) : 0,
				     idp->data, idp->len);
  silc_buffer_free(idp);

  /* Send KICKED notify to primary route */
  silc_server_send_notify_kicked(server, SILC_PRIMARY_ROUTE(server),
				 SILC_BROADCAST(server), channel,
				 target_client->id, client->id, comment);

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
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  unsigned char *username, *auth;
  SilcUInt32 tmp_len;
  SilcServerConfigAdmin *admin;
  SilcIDListData idata = (SilcIDListData)client;
  bool result = FALSE;
  SilcPublicKey cached_key;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_OPER, cmd, 1, 2);

  /* Get the username */
  username = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  /* Get the admin configuration */
  admin = silc_server_config_find_admin(server, cmd->sock->ip,
					username, client->nickname);
  if (!admin) {
    admin = silc_server_config_find_admin(server, cmd->sock->hostname,
					  username, client->nickname);
    if (!admin) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					    SILC_STATUS_ERR_AUTH_FAILED,
					    0);
      SILC_LOG_INFO(("OPER authentication failed for username '%s' by"
		     "nickname '%s' from %s", username,
		     client->nickname, cmd->sock->hostname));
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
    cached_key = silc_server_get_public_key(server, admin->publickeys);
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
  silc_server_command_free(cmd);
}

SILC_TASK_CALLBACK(silc_server_command_detach_cb)
{
  SilcServer server = app_context;
  QuitInternal q = (QuitInternal)context;
  SilcClientID *client_id = (SilcClientID *)q->sock;
  SilcClientEntry client;
  SilcSocketConnection sock;

  client = silc_idlist_find_client_by_id(server->local_list, client_id,
					 TRUE, NULL);
  if (client && client->connection) {
    sock = client->connection;

    /* If there is pending outgoing data for the client then purge it
       to the network before closing connection. */
    silc_server_packet_queue_purge(server, sock);

    /* Close the connection on our side */
    client->router = NULL;
    client->connection = NULL;
    sock->user_data = NULL;
    silc_server_close_connection(server, sock);
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
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  QuitInternal q;

  if (server->config->detach_disabled) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_DETACH,
					  SILC_STATUS_ERR_UNKNOWN_COMMAND, 0);
    goto out;
  }

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
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
  silc_schedule_task_add(server->schedule, 0, silc_server_command_detach_cb,
			 q, 0, 200000, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

  if (server->config->detach_timeout) {
    q = silc_calloc(1, sizeof(*q));
    q->sock = silc_id_dup(client->id, SILC_ID_CLIENT);
    silc_schedule_task_add(server->schedule, 0, 
			   silc_server_command_detach_timeout,
			   q, server->config->detach_timeout * 60,
			   0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
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
  SilcUInt32 add_nick_len, del_nick_len, tmp_len;
  char nick[128 + 1];
  unsigned char hash[16], *tmp;
  SilcClientEntry client;
  SilcClientID *client_id = NULL;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WATCH, cmd, 1, 3);

  if (server->server_type == SILC_SERVER && !server->standalone) {
    if (!cmd->pending) {
      /* Send the command to router */
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_WATCH,
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_watch,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
    } else if (context2) {
      /* Received reply from router, just send same data to the client. */
      SilcServerCommandReplyContext reply = context2;
      SilcStatus status;
      silc_command_get_status(reply->payload, &status, NULL);
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH, status,
					    0);
    }

    goto out;
  }

  /* We are router and keep the watch list for local cell */

  /* Get the client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					  SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					  0);
    goto out;
  }

  /* Get the client entry which must be in local list */
  client = silc_idlist_find_client_by_id(server->local_list, 
					 client_id, TRUE, NULL);
  if (!client) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					  SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					  0);
    goto out;
  }

  /* Take nickname */
  add_nick = silc_argument_get_arg_type(cmd->args, 2, &add_nick_len);
  del_nick = silc_argument_get_arg_type(cmd->args, 3, &del_nick_len);
  if (!add_nick && !del_nick) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,
					  0);
    goto out;
  }

  if (add_nick && add_nick_len > 128)
    add_nick[128] = '\0';
  if (del_nick && del_nick_len > 128)
    del_nick[128] = '\0';

  memset(nick, 0, sizeof(nick));

  /* Add new nickname to be watched in our cell */
  if (add_nick) {
    if (silc_server_name_bad_chars(add_nick, strlen(add_nick)) == TRUE) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_BAD_NICKNAME, 0);
      goto out;
    }

    /* Hash the nick, we have the hash saved, not nicks because we can
       do one to one mapping to the nick from Client ID hash this way. */
    silc_to_lower(add_nick, nick, sizeof(nick) - 1);
    silc_hash_make(server->md5hash, nick, strlen(nick), hash);

    /* Check whether this client is already watching this nickname */
    if (silc_hash_table_find_by_context(server->watcher_list, hash, 
					client, NULL)) {
      /* Nickname is alredy being watched for this client */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_NICKNAME_IN_USE,
					    0);
      goto out;
    }

    /* Get the nickname from the watcher list and use the same key in
       new entries as well.  If key doesn't exist then create it. */
    if (!silc_hash_table_find(server->watcher_list, hash, (void **)&tmp, NULL))
      tmp = silc_memdup(hash, CLIENTID_HASH_LEN);

    /* Add the client to the watcher list with the specified nickname hash. */
    silc_hash_table_add(server->watcher_list, tmp, client);
  }

  /* Delete nickname from watch list */
  if (del_nick) {
    if (silc_server_name_bad_chars(del_nick, strlen(del_nick)) == TRUE) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_BAD_NICKNAME, 0);
      goto out;
    }

    /* Hash the nick, we have the hash saved, not nicks because we can
       do one to one mapping to the nick from Client ID hash this way. */
    silc_to_lower(del_nick, nick, sizeof(nick) - 1);
    silc_hash_make(server->md5hash, nick, strlen(nick), hash);

    /* Check that this client is watching for this nickname */
    if (!silc_hash_table_find_by_context(server->watcher_list, hash, 
					 client, (void **)&tmp)) {
      /* Nickname is alredy being watched for this client */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					    SILC_STATUS_ERR_NO_SUCH_NICK, 0);
      goto out;
    }

    /* Delete the nickname from the watcher list. */
    silc_hash_table_del_by_context(server->watcher_list, hash, client);

    /* Now check whether there still exists entries with this key, if not
       then free the key to not leak memory. */
    if (!silc_hash_table_find(server->watcher_list, hash, NULL, NULL))
      silc_free(tmp);
  }

  /* Distribute the watch list to backup routers too */
  if (server->backup) {
    SilcBuffer tmpbuf;
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);
    silc_server_backup_send(server, NULL, SILC_PACKET_COMMAND,
			    cmd->packet->flags, tmpbuf->data, tmpbuf->len,
			    FALSE, TRUE);
    silc_buffer_free(tmpbuf);
  }

  silc_server_command_send_status_reply(cmd, SILC_COMMAND_WATCH,
					SILC_STATUS_OK, 0);

 out:
  silc_free(client_id);
  silc_server_command_free(cmd);
}

/* Server side of SILCOPER command. Client uses this comand to obtain router
   operator privileges to this router. */

SILC_SERVER_CMD_FUNC(silcoper)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  unsigned char *username, *auth;
  SilcUInt32 tmp_len;
  SilcServerConfigAdmin *admin;
  SilcIDListData idata = (SilcIDListData)client;
  bool result = FALSE;
  SilcPublicKey cached_key;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_SILCOPER, cmd, 1, 2);

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

  /* Get the admin configuration */
  admin = silc_server_config_find_admin(server, cmd->sock->ip,
					username, client->nickname);
  if (!admin) {
    admin = silc_server_config_find_admin(server, cmd->sock->hostname,
					  username, client->nickname);
    if (!admin) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					    SILC_STATUS_ERR_AUTH_FAILED, 0);
      SILC_LOG_INFO(("SILCOPER authentication failed for username '%s' by"
		     "nickname '%s' from %s", username,
		     client->nickname, cmd->sock->hostname));
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
    cached_key = silc_server_get_public_key(server, admin->publickeys);
    if (!cached_key)
      goto out;
    result = silc_auth_verify_data(auth, tmp_len, SILC_AUTH_PUBLIC_KEY,
				   cached_key, 0, idata->hash, 
				   client->id, SILC_ID_CLIENT);
  }
  if (!result) {
    /* Authentication failed */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
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
  silc_server_command_free(cmd);
}

/* Server side of command BAN. This is used to manage the ban list of the
   channel. To add clients and remove clients from the ban list. */

SILC_SERVER_CMD_FUNC(ban)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcBuffer packet;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcChannelID *channel_id = NULL;
  unsigned char *id, *add, *del;
  SilcUInt32 id_len, tmp_len;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_BAN, cmd, 0, 3);

  /* Get Channel ID */
  id = silc_argument_get_arg_type(cmd->args, 1, &id_len);
  if (id) {
    channel_id = silc_id_payload_parse_id(id, id_len, NULL);
    if (!channel_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					    SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
      goto out;
    }
  }

  /* Get channel entry. The server must know about the channel since the
     client is expected to be on the channel. */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel, &chl)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL, 0);
    goto out;
  }

  /* The client must be at least channel operator. */
  if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV, 0);
    goto out;
  }

  /* Get the new ban and add it to the ban list */
  add = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (add) {
    if (!channel->ban_list)
      channel->ban_list = silc_calloc(tmp_len + 2, sizeof(*channel->ban_list));
    else
      channel->ban_list = silc_realloc(channel->ban_list, 
				       sizeof(*channel->ban_list) * 
				       (tmp_len + 
					strlen(channel->ban_list) + 2));
    if (add[tmp_len - 1] == ',')
      add[tmp_len - 1] = '\0';

    strncat(channel->ban_list, add, tmp_len);
    strncat(channel->ban_list, ",", 1);
  }

  /* Get the ban to be removed and remove it from the list */
  del = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (del && channel->ban_list) {
    char *start, *end, *n;

    if (!strncmp(channel->ban_list, del, strlen(channel->ban_list) - 1)) {
      silc_free(channel->ban_list);
      channel->ban_list = NULL;
    } else {
      start = strstr(channel->ban_list, del);
      if (start && strlen(start) >= tmp_len) {
	end = start + tmp_len;
	n = silc_calloc(strlen(channel->ban_list) - tmp_len, sizeof(*n));
	strncat(n, channel->ban_list, start - channel->ban_list);
	strncat(n, end + 1, ((channel->ban_list + strlen(channel->ban_list)) - 
			     end) - 1);
	silc_free(channel->ban_list);
	channel->ban_list = n;
      }
    }
  }

  /* Send the BAN notify type to our primary router. */
  if (add || del)
    silc_server_send_notify_ban(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), channel, add, del);

  /* Send the reply back to the client */
  packet = 
    silc_command_reply_payload_encode_va(SILC_COMMAND_BAN,
					 SILC_STATUS_OK, 0, ident, 2,
					 2, id, id_len,
					 3, channel->ban_list, 
					 channel->ban_list ? 
					 strlen(channel->ban_list) -1 : 0);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);

 out:
  silc_free(channel_id);
  silc_server_command_free(cmd);
}

/* Server side command of LEAVE. Removes client from a channel. */

SILC_SERVER_CMD_FUNC(leave)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;
  SilcClientEntry id_entry = (SilcClientEntry)cmd->sock->user_data;
  SilcChannelID *id = NULL;
  SilcChannelEntry channel;
  SilcUInt32 len;
  unsigned char *tmp;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !id_entry)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LEAVE, cmd, 1, 2);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }
  id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(id_entry, channel, NULL)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL, 0);
    goto out;
  }

  /* Notify routers that they should remove this client from their list
     of clients on the channel. Send LEAVE notify type. */
  silc_server_send_notify_leave(server, SILC_PRIMARY_ROUTE(server),
				SILC_BROADCAST(server), channel, id_entry->id);

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
  silc_free(id);
  silc_server_command_free(cmd);
}

/* Server side of command USERS. Resolves clients and their USERS currently
   joined on the requested channel. The list of Client ID's and their modes
   on the channel is sent back. */

SILC_SERVER_CMD_FUNC(users)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcChannelEntry channel;
  SilcChannelID *id = NULL;
  SilcBuffer packet, idp;
  unsigned char *channel_id;
  SilcUInt32 channel_id_len;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  unsigned char lc[4];
  SilcUInt32 list_count = 0;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  char *channel_name;

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

  if (channel_id) {
    id = silc_id_payload_parse_id(channel_id, channel_id_len, NULL);
    if (!id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_CHANNEL_ID, 0);
      goto out;
    }
  }

  /* If we are server and we don't know about this channel we will send
     the command to our router. If we know about the channel then we also
     have the list of users already. */
  if (id)
    channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
  else
    channel = silc_idlist_find_channel_by_name(server->local_list, 
					       channel_name, NULL);

  if (!channel || (!server->standalone && (channel->disabled || 
		    !channel->users_resolved))) {
    if (server->server_type != SILC_ROUTER && !server->standalone &&
	!cmd->pending) {
      SilcBuffer tmpbuf;
      
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);
      
      /* Send USERS command */
      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
      /* Reprocess this packet after received reply */
      silc_server_command_pending(server, SILC_COMMAND_USERS, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_users,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, ident);
      silc_buffer_free(tmpbuf);
      silc_free(id);
      goto out;
    }

    /* Check the global list as well. */
    if (id)
      channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
    else
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 channel_name, NULL);
    if (!channel) {
      /* Channel really does not exist */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
      goto out;
    }
  }

  /* If the channel is private or secret do not send anything, unless the
     user requesting this command is on the channel or is server */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    if (channel->mode & (SILC_CHANNEL_MODE_PRIVATE | SILC_CHANNEL_MODE_SECRET)
	&& !silc_server_client_on_channel(cmd->sock->user_data, channel, 
					  NULL)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					    0);
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
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_USERS,
						SILC_STATUS_OK, 0, ident, 4,
						2, idp->data, idp->len,
						3, lc, 4,
						4, client_id_list ? 
						client_id_list->data : NULL,
						client_id_list ?
						client_id_list->len : 0,
						5, client_mode_list ?
						client_mode_list->data : NULL,
						client_mode_list ?
						client_mode_list->len : 0);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(idp);
  silc_buffer_free(packet);
  if (client_id_list)
    silc_buffer_free(client_id_list);
  if (client_mode_list)
    silc_buffer_free(client_mode_list);
  silc_free(id);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command GETKEY. This fetches the client's public key
   from the server where to the client is connected. */

SILC_SERVER_CMD_FUNC(getkey)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcBuffer packet;
  SilcClientEntry client;
  SilcServerEntry server_entry;
  SilcClientID *client_id = NULL;
  SilcServerID *server_id = NULL;
  SilcIDPayload idp = NULL;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);
  unsigned char *tmp, *pkdata;
  SilcUInt32 tmp_len, pklen;
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
    client_id = silc_id_payload_get_id(idp);

    /* If the client is not found from local list there is no chance it
       would be locally connected client so send the command further. */
    client = silc_idlist_find_client_by_id(server->local_list, 
					   client_id, TRUE, NULL);
    if (!client)
      client = silc_idlist_find_client_by_id(server->global_list, 
					     client_id, TRUE, NULL);
    
    if ((!client && !cmd->pending && !server->standalone) ||
	(client && !client->connection && !cmd->pending &&
	 !(client->mode & SILC_UMODE_DETACHED)) ||
	(client && !client->data.public_key && !cmd->pending)) {
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;
      SilcSocketConnection dest_sock;
      
      dest_sock = silc_server_get_client_route(server, NULL, 0, 
					       client_id, NULL, NULL);
      if (!dest_sock)
	goto out;
      
      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);
      
      silc_server_packet_send(server, dest_sock,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
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
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					    SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					    0);
      goto out;
    }

    /* The client is locally connected, just get the public key and
       send it back. If they key does not exist then do not send it, 
       send just OK reply */
    public_key = client->data.public_key;
    if (!public_key) {
      pkdata = NULL;
      pklen = 0;
    } else {
      tmp = silc_pkcs_public_key_encode(public_key, &tmp_len);
      pk = silc_buffer_alloc(4 + tmp_len);
      silc_buffer_pull_tail(pk, SILC_BUFFER_END(pk));
      silc_buffer_format(pk,
			 SILC_STR_UI_SHORT(tmp_len),
			 SILC_STR_UI_SHORT(SILC_SKE_PK_TYPE_SILC),
			 SILC_STR_UI_XNSTRING(tmp, tmp_len),
			 SILC_STR_END);
      silc_free(tmp);
      pkdata = pk->data;
      pklen = pk->len;
    }
  } else if (id_type == SILC_ID_SERVER) {
    server_id = silc_id_payload_get_id(idp);

    /* If the server is not found from local list there is no chance it
       would be locally connected server so send the command further. */
    server_entry = silc_idlist_find_server_by_id(server->local_list, 
						 server_id, TRUE, NULL);
    if (!server_entry)
      server_entry = silc_idlist_find_server_by_id(server->global_list, 
						   server_id, TRUE, NULL);
    
    if (server_entry != server->id_entry &&
	((!server_entry && !cmd->pending && !server->standalone) ||
	 (server_entry && !server_entry->connection && !cmd->pending &&
	  !server->standalone) ||
	 (server_entry && !server_entry->data.public_key && !cmd->pending &&
	  !server->standalone))) {
      SilcBuffer tmpbuf;
      SilcUInt16 old_ident;
      
      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);
      
      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
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
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					    SILC_STATUS_ERR_NO_SUCH_SERVER_ID,
					    0);
      goto out;
    }

    /* If they key does not exist then do not send it, send just OK reply */
    public_key = (!server_entry->data.public_key ? 
		  (server_entry == server->id_entry ? server->public_key :
		   NULL) : server_entry->data.public_key);
    if (!public_key) {
      pkdata = NULL;
      pklen = 0;
    } else {
      tmp = silc_pkcs_public_key_encode(public_key, &tmp_len);
      pk = silc_buffer_alloc(4 + tmp_len);
      silc_buffer_pull_tail(pk, SILC_BUFFER_END(pk));
      silc_buffer_format(pk,
			 SILC_STR_UI_SHORT(tmp_len),
			 SILC_STR_UI_SHORT(SILC_SKE_PK_TYPE_SILC),
			 SILC_STR_UI_XNSTRING(tmp, tmp_len),
			 SILC_STR_END);
      silc_free(tmp);
      pkdata = pk->data;
      pklen = pk->len;
    }
  } else {
    goto out;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_GETKEY,
						SILC_STATUS_OK, 0, ident, 
						pkdata ? 2 : 1,
						2, tmp, tmp_len,
						3, pkdata, pklen);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);

  if (pk)
    silc_buffer_free(pk);

 out:
  if (idp)
    silc_id_payload_free(idp);
  silc_free(client_id);
  silc_free(server_id);
  silc_server_command_free(cmd);
}


/* Private range commands, specific to this implementation */

/* Server side command of CONNECT. Connects us to the specified remote
   server or router. */

SILC_SERVER_CMD_FUNC(connect)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  unsigned char *tmp, *host;
  SilcUInt32 tmp_len;
  SilcUInt32 port = SILC_PORT;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_PRIV_CONNECT, cmd, 1, 2);

  /* Check whether client has the permissions. */
  if (!(client->mode & SILC_UMODE_SERVER_OPERATOR) &&
      !(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PRIV_CONNECT,
					  SILC_STATUS_ERR_NO_SERVER_PRIV, 0);
    goto out;
  }

  if (server->server_type == SILC_ROUTER && 
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
  silc_server_create_connection(server, host, port);

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
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcServerEntry server_entry;
  SilcSocketConnection sock;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  unsigned char *name;
  SilcUInt32 port = SILC_PORT;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
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
						 name, port, FALSE, NULL);
  if (!server_entry)
    server_entry = silc_idlist_find_server_by_conn(server->global_list,
						   name, port, FALSE, NULL);
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
  sock = (SilcSocketConnection)server_entry->connection;

  /* If we shutdown primary router connection manually then don't trigger
     any reconnect or backup router connections, by setting the router
     to NULL here. */
  if (server->router == server_entry) {
    server->id_entry->router = NULL;
    server->router = NULL;
    server->standalone = TRUE;
  }
  silc_server_free_sock_user_data(server, sock, NULL);
  silc_server_close_connection(server, sock);
  
 out:
  silc_server_command_free(cmd);
}

/* Server side command of SHUTDOWN. Shutdowns the server and closes all
   active connections. */
 
SILC_SERVER_CMD_FUNC(shutdown)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT || !client)
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
