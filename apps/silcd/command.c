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

#include "serverincludes.h"
#include "server_internal.h"

static int silc_server_is_registered(SilcServer server,
				     SilcSocketConnection sock,
				     SilcServerCommandContext cmd,
				     SilcCommand command);
static void 
silc_server_command_send_status_reply(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcCommandStatus status);
static void 
silc_server_command_send_status_data(SilcServerCommandContext cmd,
				     SilcCommand command,
				     SilcCommandStatus status,
				     uint32 arg_type,
				     unsigned char *arg,
				     uint32 arg_len);
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
  SILC_SERVER_CMD(connect, CONNECT, 
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(ping, PING, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(oper, OPER, SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(join, JOIN, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(motd, MOTD, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(umode, UMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(cmode, CMODE, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(cumode, CUMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(kick, KICK, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(ban, BAN, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(close, CLOSE,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(shutdown, SHUTDOWN, SILC_CF_LAG | SILC_CF_REG | 
		  SILC_CF_OPER),
  SILC_SERVER_CMD(silcoper, SILCOPER,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER),
  SILC_SERVER_CMD(leave, LEAVE, SILC_CF_LAG_STRICT | SILC_CF_REG),
  SILC_SERVER_CMD(users, USERS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(getkey, GETKEY, SILC_CF_LAG | SILC_CF_REG),

  { NULL, 0 },
};

/* Performs several checks to the command. It first checks whether this
   command was called as pending command callback. If it was then it checks
   whether error occurred in the command reply where the pending command
   callback was called. 

   It also checks that the requested command includes correct amount
   of arguments. */
#define SILC_SERVER_COMMAND_CHECK(command, context, min, max)		      \
do {									      \
  uint32 _argc;								      \
									      \
  SILC_LOG_DEBUG(("Start"));						      \
									      \
  if (silc_server_command_pending_error_check(cmd, context2, command)) {      \
    silc_server_command_free(cmd);					      \
    return;								      \
  }									      \
									      \
  _argc = silc_argument_get_arg_num(cmd->args);				      \
  if (_argc < min) {							      \
    silc_server_command_send_status_reply(cmd, command,			      \
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS); \
    silc_server_command_free(cmd);					      \
    return;								      \
  }									      \
  if (_argc > max) {							      \
    silc_server_command_send_status_reply(cmd, command,			      \
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);   \
    silc_server_command_free(cmd);					      \
    return;								      \
  }									      \
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
					SILC_STATUS_ERR_NOT_REGISTERED);
  silc_server_command_free(cmd);
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

  /* Update access time */
  client->last_command = time(NULL);

  if (!(timeout->cmd->flags & SILC_CF_REG))
    timeout->cmd->cb(timeout->ctx, NULL);
  else if (silc_server_is_registered(timeout->ctx->server, 
				     timeout->ctx->sock, 
				     timeout->ctx, 
				     timeout->cmd->cmd))
    timeout->cmd->cb(timeout->ctx, NULL);

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
  ctx->payload = silc_command_payload_parse(packet->buffer);
  if (!ctx->payload) {
    SILC_LOG_ERROR(("Bad command payload, packet dropped"));
    silc_buffer_free(packet->buffer);
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

  if (cmd == NULL) {
    silc_server_command_send_status_reply(ctx, command,
					  SILC_STATUS_ERR_UNKNOWN_COMMAND);
    silc_server_command_free(ctx);
    return;
  }

  /* Execute client's commands always with timeout.  Normally they are
     executed with zero (0) timeout but if client is sending command more
     frequently than once in 2 seconds, then the timeout may be 0 to 2
     seconds. */
  if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
    SilcClientEntry client = (SilcClientEntry)sock->user_data;
    SilcServerCommandTimeout timeout = silc_calloc(1, sizeof(*timeout));
    int fast;

    timeout->ctx = ctx;
    timeout->cmd = cmd;

    if (client->last_command && (time(NULL) - client->last_command) < 2) {
      client->fast_command++;
      fast = FALSE;
    } else {
      client->fast_command = ((client->fast_command - 1) <= 0 ? 0 : 
			      client->fast_command--);
      fast = TRUE;
    }

    if (!fast && ((cmd->flags & SILC_CF_LAG_STRICT) ||
		  (client->fast_command > 5 && cmd->flags & SILC_CF_LAG)))
      silc_schedule_task_add(server->schedule, sock->sock, 
			 silc_server_command_process_timeout,
			 (void *)timeout, 
			 2 - (time(NULL) - client->last_command), 0,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
    else
      silc_schedule_task_add(server->schedule, sock->sock, 
			 silc_server_command_process_timeout,
			 (void *)timeout, 
			 0, 1,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
    return;
  }

  /* Execute for server */

  if (!(cmd->flags & SILC_CF_REG))
    cmd->cb(ctx, NULL);
  else if (silc_server_is_registered(server, sock, ctx, cmd->cmd))
    cmd->cb(ctx, NULL);
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

/* Add new pending command to be executed when reply to a command has been
   received. The `reply_cmd' is the command that will call the `callback'
   with `context' when reply has been received.  It can be SILC_COMMAND_NONE
   to match any command with the `ident'.  If `ident' is non-zero
   the `callback' will be executed when received reply with command
   identifier `ident'. */

void silc_server_command_pending(SilcServer server,
				 SilcCommand reply_cmd,
				 uint16 ident,
				 SilcServerPendingDestructor destructor,
				 SilcCommandCb callback,
				 void *context)
{
  SilcServerCommandPending *reply;

  reply = silc_calloc(1, sizeof(*reply));
  reply->reply_cmd = reply_cmd;
  reply->ident = ident;
  reply->context = context;
  reply->callback = callback;
  reply->destructor = destructor;
  silc_dlist_add(server->pending_commands, reply);
}

/* Deletes pending command by reply command type. */

void silc_server_command_pending_del(SilcServer server,
				     SilcCommand reply_cmd,
				     uint16 ident)
{
  SilcServerCommandPending *r;

  silc_dlist_start(server->pending_commands);
  while ((r = silc_dlist_get(server->pending_commands)) != SILC_LIST_END) {
    if (r->reply_cmd == reply_cmd && r->ident == ident) {
      silc_dlist_del(server->pending_commands, r);
      break;
    }
  }
}

/* Checks for pending commands and marks callbacks to be called from
   the command reply function. Returns TRUE if there were pending command. */

SilcServerCommandPendingCallbacks
silc_server_command_pending_check(SilcServer server,
				  SilcServerCommandReplyContext ctx,
				  SilcCommand command, 
				  uint16 ident,
				  uint32 *callbacks_count)
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
      callbacks[i].destructor = r->destructor;
      ctx->ident = ident;
      i++;
    }
  }

  *callbacks_count = i;
  return callbacks;
}

/* Destructor function for pending callbacks. This is called when using
   pending commands to free the context given for the pending command. */

static void silc_server_command_destructor(void *context)
{
  silc_server_command_free((SilcServerCommandContext)context);
}

/* Sends simple status message as command reply packet */

static void 
silc_server_command_send_status_reply(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcCommandStatus status)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer = 
    silc_command_reply_payload_encode_va(command, status, 
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
				     SilcCommandStatus status,
				     uint32 arg_type,
				     unsigned char *arg,
				     uint32 arg_len)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer = 
    silc_command_reply_payload_encode_va(command, status, 
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
  SilcCommandStatus status;

  if (!cmd->pending || !cmdr)
    return FALSE;

  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmdr->args, 1, NULL));
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_START &&
      status != SILC_STATUS_LIST_ITEM &&
      status != SILC_STATUS_LIST_END) {
    /* Send the error message */
    silc_server_command_send_status_reply(cmd, command, status);
    return TRUE;
  }

  return FALSE;
}

/******************************************************************************

                              WHOIS Functions

******************************************************************************/

static int
silc_server_command_whois_parse(SilcServerCommandContext cmd,
				SilcClientID ***client_id,
				uint32 *client_id_count,
				char **nickname,
				char **server_name,
				int *count,
				SilcCommand command)
{
  unsigned char *tmp;
  uint32 len;
  uint32 argc = silc_argument_get_arg_num(cmd->args);
  int i, k;

  /* If client ID is in the command it must be used instead of nickname */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!tmp) {
    /* No ID, get the nickname@server string and parse it. */
    tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
    if (tmp) {
      silc_parse_userfqdn(tmp, nickname, server_name);
    } else {
      silc_server_command_send_status_reply(cmd, command,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      return FALSE;
    }
  } else {
    /* Command includes ID, we must use that.  Also check whether the command
       has more than one ID set - take them all. */

    *client_id = silc_calloc(1, sizeof(**client_id));
    (*client_id)[0] = silc_id_payload_parse_id(tmp, len);
    if ((*client_id)[0] == NULL) {
      silc_free(*client_id);
      return FALSE;
    }
    *client_id_count = 1;

    /* Take all ID's from the command packet */
    if (argc > 1) {
      for (k = 1, i = 1; i < argc; i++) {
	tmp = silc_argument_get_arg_type(cmd->args, i + 3, &len);
	if (tmp) {
	  *client_id = silc_realloc(*client_id, sizeof(**client_id) *
				    (*client_id_count + 1));
	  (*client_id)[k] = silc_id_payload_parse_id(tmp, len);
	  if ((*client_id)[k] == NULL) {
	    /* Cleanup all and fail */
	    for (i = 0; i < *client_id_count; i++)
	      silc_free((*client_id)[i]);
	    silc_free(*client_id);
	    return FALSE;
	  }
	  (*client_id_count)++;
	  k++;
	}
      }
    }
  }

  /* Get the max count of reply messages allowed */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (tmp)
    *count = atoi(tmp);
  else
    *count = 0;

  return TRUE;
}

/* Resolve context used by both WHOIS and IDENTIFY commands */
typedef struct {
  SilcServerEntry router;
  uint16 ident;
  unsigned char **res_argv;
  uint32 *res_argv_lens;
  uint32 *res_argv_types;
  uint32 res_argc;
} *SilcServerResolveContext;

static bool
silc_server_command_whois_check(SilcServerCommandContext cmd,
				SilcClientEntry *clients,
				uint32 clients_count)
{
  SilcServer server = cmd->server;
  SilcClientEntry entry;
  SilcServerResolveContext resolve = NULL, r = NULL;
  uint32 resolve_count = 0;
  int i, k;
  bool no_res = TRUE;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (!entry || (entry->nickname && entry->username && entry->userinfo) ||
	!(entry->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	!entry->router)
      continue;

    /* We need to resolve this entry since it is not complete */

    if (!cmd->pending && entry->data.status & SILC_IDLIST_STATUS_RESOLVING) {
      /* The entry is being resolved (and we are not the resolver) so attach
	 to the command reply and we're done with this one. */
      silc_server_command_pending(server, SILC_COMMAND_NONE, 
				  entry->resolve_cmd_ident,
				  silc_server_command_destructor,
				  silc_server_command_whois,
				  silc_server_command_dup(cmd));
      no_res = FALSE;
    } else {
      if (entry->data.status & SILC_IDLIST_STATUS_RESOLVING) {
	/* We've resolved this and it still is not ready.  We'll return
	   and are that this will be handled again after it is resolved. */
	for (i = 0; i < resolve_count; i++) {
	  for (k = 0; k < r->res_argc; k++)
	    silc_free(r->res_argv[k]);
	  silc_free(r->res_argv);
	  silc_free(r->res_argv_lens);
	  silc_free(r->res_argv_types);
	}
	silc_free(resolve);
	return FALSE;
      } else {
	/* We'll resolve this client */
	SilcBuffer idp;

	r = NULL;
	for (k = 0; k < resolve_count; k++) {
	  if (resolve[k].router == entry->router) {
	    r = &resolve[k];
	    break;
	  }
	}

	if (!r) {
	  resolve = silc_realloc(resolve, sizeof(*resolve) * 
				 (resolve_count + 1));
	  r = &resolve[resolve_count];
	  memset(r, 0, sizeof(*r));
	  r->router = entry->router;
	  r->ident = ++server->cmd_ident;
	  resolve_count++;
	}

	r->res_argv = silc_realloc(r->res_argv, sizeof(*r->res_argv) *
				   (r->res_argc + 1));
	r->res_argv_lens = silc_realloc(r->res_argv_lens, 
					sizeof(*r->res_argv_lens) *
					(r->res_argc + 1));
	r->res_argv_types = silc_realloc(r->res_argv_types, 
					 sizeof(*r->res_argv_types) *
					 (r->res_argc + 1));
	idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
	r->res_argv[r->res_argc] = silc_calloc(idp->len, 
					       sizeof(**r->res_argv));
	memcpy(r->res_argv[r->res_argc], idp->data, idp->len);
	r->res_argv_lens[r->res_argc] = idp->len;
	r->res_argv_types[r->res_argc] = r->res_argc + 3;
	r->res_argc++;
	silc_buffer_free(idp);

	entry->resolve_cmd_ident = r->ident;
	entry->data.status |= SILC_IDLIST_STATUS_RESOLVING;
	entry->data.status &= ~SILC_IDLIST_STATUS_RESOLVED;
      }
    }
  }

  /* Do the resolving */
  for (i = 0; i < resolve_count; i++) {
    SilcBuffer res_cmd;

    r = &resolve[i];

    /* Send WHOIS request. We send WHOIS since we're doing the requesting
       now anyway so make it a good one. */
    res_cmd = silc_command_payload_encode(SILC_COMMAND_WHOIS,
					  r->res_argc, r->res_argv, 
					  r->res_argv_lens,
					  r->res_argv_types, 
					  r->ident);
    silc_server_packet_send(server, r->router->connection,
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    res_cmd->data, res_cmd->len, FALSE);

    /* Reprocess this packet after received reply */
    silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				r->ident,
				silc_server_command_destructor,
				silc_server_command_whois,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;

    silc_buffer_free(res_cmd);
    for (k = 0; k < r->res_argc; k++)
      silc_free(r->res_argv[k]);
    silc_free(r->res_argv);
    silc_free(r->res_argv_lens);
    silc_free(r->res_argv_types);
    no_res = FALSE;
  }
  silc_free(resolve);

  return no_res;
}

static void
silc_server_command_whois_send_reply(SilcServerCommandContext cmd,
				     SilcClientEntry *clients,
				     uint32 clients_count,
				     int count)
{
  SilcServer server = cmd->server;
  char *tmp;
  int i, k, len;
  SilcBuffer packet, idp, channels;
  SilcClientEntry entry;
  SilcCommandStatus status;
  uint16 ident = silc_command_get_ident(cmd->payload);
  char nh[256], uh[256];
  unsigned char idle[4], mode[4];
  unsigned char *fingerprint;
  SilcSocketConnection hsock;

  len = 0;
  for (i = 0; i < clients_count; i++)
    if (clients[i]->data.status & SILC_IDLIST_STATUS_REGISTERED)
      len++;

  if (len == 0 && clients_count) {
    entry = clients[0];
    if (entry->nickname) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					   SILC_STATUS_ERR_NO_SUCH_NICK,
					   3, entry->nickname, 
					   strlen(entry->nickname));
    } else {
      SilcBuffer idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   2, idp->data, idp->len);
      silc_buffer_free(idp);
    }

    return;
  }

  status = SILC_STATUS_OK;
  if (len > 1)
    status = SILC_STATUS_LIST_START;

  for (i = 0, k = 0; i < clients_count; i++) {
    entry = clients[i];

    if (!(entry->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
      if (clients_count == 1) {
	if (entry->nickname) {
	  silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					       SILC_STATUS_ERR_NO_SUCH_NICK,
					       3, entry->nickname, 
					       strlen(entry->nickname));
	} else {
	  SilcBuffer idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
	  silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
				     SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					       2, idp->data, idp->len);
	  silc_buffer_free(idp);
	}
      }
      continue;
    }

    if (k >= 1)
      status = SILC_STATUS_LIST_ITEM;

    if (clients_count > 1 && k == clients_count - 1)
      status = SILC_STATUS_LIST_END;

    if (count && k - 1 == count)
      status = SILC_STATUS_LIST_END;

    if (count && k - 1 > count)
      break;

    /* Sanity check, however these should never fail. However, as
       this sanity check has been added here they have failed. */
    if (!entry->nickname || !entry->username || !entry->userinfo)
      continue;
      
    /* Send WHOIS reply */
    idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
    tmp = silc_argument_get_first_arg(cmd->args, NULL);
    
    memset(uh, 0, sizeof(uh));
    memset(nh, 0, sizeof(nh));
    memset(idle, 0, sizeof(idle));
    
    strncat(nh, entry->nickname, strlen(entry->nickname));
    if (!strchr(entry->nickname, '@')) {
      strncat(nh, "@", 1);
      if (entry->servername) {
	strncat(nh, entry->servername, strlen(entry->servername));
      } else {
	len = entry->router ? strlen(entry->router->server_name) :
	  strlen(server->server_name);
	strncat(nh, entry->router ? entry->router->server_name :
		server->server_name, len);
      }
    }
      
    strncat(uh, entry->username, strlen(entry->username));
    if (!strchr(entry->username, '@')) {
      strncat(uh, "@", 1);
      hsock = (SilcSocketConnection)entry->connection;
      len = strlen(hsock->hostname);
      strncat(uh, hsock->hostname, len);
    }

    channels = silc_server_get_client_channel_list(server, entry);

    if (entry->data.fingerprint[0] != 0 && entry->data.fingerprint[1] != 0)
      fingerprint = entry->data.fingerprint;
    else
      fingerprint = NULL;
      
    SILC_PUT32_MSB(entry->mode, mode);

    if (entry->connection) {
      SILC_PUT32_MSB((time(NULL) - entry->data.last_receive), idle);
    }

    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					   status, ident, 8, 
					   2, idp->data, idp->len,
					   3, nh, strlen(nh),
					   4, uh, strlen(uh),
					   5, entry->userinfo, 
					   strlen(entry->userinfo),
					   6, channels ? channels->data : NULL,
					   channels ? channels->len : 0,
					   7, mode, 4,
					   8, idle, 4,
					   9, fingerprint,
					   fingerprint ? 20 : 0);

    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			    0, packet->data, packet->len, FALSE);
    
    silc_buffer_free(packet);
    silc_buffer_free(idp);
    if (channels)
      silc_buffer_free(channels);

    k++;
  }
}

static int
silc_server_command_whois_process(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  char *nick = NULL, *server_name = NULL;
  int count = 0;
  SilcClientEntry *clients = NULL, entry;
  SilcClientID **client_id = NULL;
  uint32 client_id_count = 0, clients_count = 0;
  int i, ret = 0;
  bool check_global = FALSE;

  /* Protocol dictates that we must always send the received WHOIS request
     to our router if we are normal server, so let's do it now unless we
     are standalone. We will not send any replies to the client until we
     have received reply from the router. */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT &&
      server->server_type == SILC_SERVER && !cmd->pending && 
      !server->standalone) {
    SilcBuffer tmpbuf;
    uint16 old_ident;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);

    /* Send WHOIS command to our router */
    silc_server_packet_send(server, (SilcSocketConnection)
			    server->router->connection,
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    tmpbuf->data, tmpbuf->len, TRUE);

    /* Reprocess this packet after received reply from router */
    silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				silc_command_get_ident(cmd->payload),
				silc_server_command_destructor,
				silc_server_command_whois,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;

    silc_command_set_ident(cmd->payload, old_ident);

    silc_buffer_free(tmpbuf);
    ret = -1;
    goto out;
  }

  /* We are ready to process the command request. Let's search for the
     requested client and send reply to the requesting client. */

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT)
    check_global = TRUE;
  else if (server->server_type != SILC_SERVER)
    check_global = TRUE;

  /* Parse the whois request */
  if (!silc_server_command_whois_parse(cmd, &client_id, &client_id_count, 
				       &nick, &server_name, &count,
				       SILC_COMMAND_WHOIS))
    return 0;

  /* Get all clients matching that ID or nickname from local list */
  if (client_id_count) {
    /* Check all Client ID's received in the command packet */
    for (i = 0; i < client_id_count; i++) {
      entry = silc_idlist_find_client_by_id(server->local_list, 
					    client_id[i], TRUE, NULL);
      if (!entry && check_global)
	entry = silc_idlist_find_client_by_id(server->global_list, 
					      client_id[i], TRUE, NULL);
      if (entry) {
	clients = silc_realloc(clients, sizeof(*clients) * 
			       (clients_count + 1));
	clients[clients_count++] = entry;
      }
    }
  } else {
    if (!silc_idlist_get_clients_by_hash(server->local_list, 
					 nick, server->md5hash,
					 &clients, &clients_count))
      silc_idlist_get_clients_by_nickname(server->local_list, 
					  nick, server_name,
					  &clients, &clients_count);
    if (check_global) {
      if (!silc_idlist_get_clients_by_hash(server->global_list, 
					   nick, server->md5hash,
					   &clients, &clients_count))
	silc_idlist_get_clients_by_nickname(server->global_list, 
					    nick, server_name,
					    &clients, &clients_count);
    }
  }
  
  if (!clients) {
    /* Such client(s) really does not exist in the SILC network. */
    if (!client_id_count) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					   SILC_STATUS_ERR_NO_SUCH_NICK,
					   3, nick, strlen(nick));
    } else {
      SilcBuffer idp = silc_id_payload_encode(client_id[0], SILC_ID_CLIENT);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   2, idp->data, idp->len);
      silc_buffer_free(idp);
    }
    goto out;
  }

  /* Router always finds the client entry if it exists in the SILC network.
     However, it might be incomplete entry and does not include all the
     mandatory fields that WHOIS command reply requires. Check for these and
     make query from the server who owns the client if some fields are 
     missing. */
  if (!silc_server_command_whois_check(cmd, clients, clients_count)) {
    ret = -1;
    goto out;
  }

  /* Send the command reply */
  silc_server_command_whois_send_reply(cmd, clients, clients_count,
				       count);

 out:
  if (client_id_count) {
    for (i = 0; i < client_id_count; i++)
      silc_free(client_id[i]);
    silc_free(client_id);
  }
  silc_free(clients);
  silc_free(nick);
  silc_free(server_name);

  return ret;
}

/* Server side of command WHOIS. Processes user's query and sends found 
   results as command replies back to the client. */

SILC_SERVER_CMD_FUNC(whois)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  int ret = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WHOIS, cmd, 1, 3328);

  ret = silc_server_command_whois_process(cmd);

  if (!ret)
    silc_server_command_free(cmd);
}

/******************************************************************************

                              WHOWAS Functions

******************************************************************************/

static int
silc_server_command_whowas_parse(SilcServerCommandContext cmd,
				 char **nickname,
				 char **server_name,
				 int *count)
{
  unsigned char *tmp;
  uint32 len;

  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOWAS,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return FALSE;
  }

  /* Get the nickname@server string and parse it. */
  silc_parse_userfqdn(tmp, nickname, server_name);

  /* Get the max count of reply messages allowed */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (tmp)
    *count = atoi(tmp);
  else
    *count = 0;

  return TRUE;
}

static char
silc_server_command_whowas_check(SilcServerCommandContext cmd,
				 SilcClientEntry *clients,
				 uint32 clients_count)
{
  SilcServer server = cmd->server;
  int i;
  SilcClientEntry entry;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (!entry->nickname || !entry->username) {
      SilcBuffer tmpbuf;
      uint16 old_ident;

      if (!entry->router)
	continue;
      
      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      /* Send WHOWAS command */
      silc_server_packet_send(server, entry->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
      /* Reprocess this packet after received reply */
      silc_server_command_pending(server, SILC_COMMAND_WHOWAS, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_whowas, 
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      
      silc_command_set_ident(cmd->payload, old_ident);

      silc_buffer_free(tmpbuf);
      return FALSE;
    }
  }

  return TRUE;
}

static void
silc_server_command_whowas_send_reply(SilcServerCommandContext cmd,
				      SilcClientEntry *clients,
				      uint32 clients_count)
{
  SilcServer server = cmd->server;
  char *tmp;
  int i, count = 0, len;
  SilcBuffer packet, idp;
  SilcClientEntry entry = NULL;
  SilcCommandStatus status;
  uint16 ident = silc_command_get_ident(cmd->payload);
  char found = FALSE;
  char nh[256], uh[256];

  status = SILC_STATUS_OK;
  if (clients_count > 1)
    status = SILC_STATUS_LIST_START;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    /* We will take only clients that are not valid anymore. They are the
       ones that are not registered anymore but still have a ID. They
       have disconnected us, and thus valid for WHOWAS. */
    if (entry->data.status & SILC_IDLIST_STATUS_REGISTERED)
      continue;
    if (entry->id == NULL)
      continue;

    if (count && i - 1 == count)
      break;

    found = TRUE;

    if (clients_count > 2)
      status = SILC_STATUS_LIST_ITEM;

    if (clients_count > 1 && i == clients_count - 1)
      status = SILC_STATUS_LIST_END;

    /* Sanity check, however these should never fail. However, as
       this sanity check has been added here they have failed. */
    if (!entry->nickname || !entry->username)
      continue;
      
    /* Send WHOWAS reply */
    idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
    tmp = silc_argument_get_first_arg(cmd->args, NULL);
    
    memset(uh, 0, sizeof(uh));
    memset(nh, 0, sizeof(nh));

    strncat(nh, entry->nickname, strlen(entry->nickname));
    if (!strchr(entry->nickname, '@')) {
      strncat(nh, "@", 1);
      if (entry->servername) {
	strncat(nh, entry->servername, strlen(entry->servername));
      } else {
	len = entry->router ? strlen(entry->router->server_name) :
	  strlen(server->server_name);
	strncat(nh, entry->router ? entry->router->server_name :
		server->server_name, len);
      }
    }
      
    strncat(uh, entry->username, strlen(entry->username));
    if (!strchr(entry->username, '@')) {
      strncat(uh, "@", 1);
      strcat(uh, "*private*");
    }
      
    if (entry->userinfo)
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_WHOWAS,
					     status, ident, 4, 
					     2, idp->data, idp->len,
					     3, nh, strlen(nh),
					     4, uh, strlen(uh),
					     5, entry->userinfo, 
					     strlen(entry->userinfo));
    else
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_WHOWAS,
					     status, ident, 3, 
					     2, idp->data, idp->len,
					     3, nh, strlen(nh),
					     4, uh, strlen(uh));

    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			    0, packet->data, packet->len, FALSE);
    
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

  if (found == FALSE && entry)
    silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOWAS,
					 SILC_STATUS_ERR_NO_SUCH_NICK,
					 3, entry->nickname, 
					 strlen(entry->nickname));
}

static int
silc_server_command_whowas_process(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  char *nick = NULL, *server_name = NULL;
  int count = 0;
  SilcClientEntry *clients = NULL;
  uint32 clients_count = 0;
  int ret = 0;
  bool check_global = FALSE;

  /* Protocol dictates that we must always send the received WHOWAS request
     to our router if we are normal server, so let's do it now unless we
     are standalone. We will not send any replies to the client until we
     have received reply from the router. */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT &&
      server->server_type == SILC_SERVER && !cmd->pending && 
      !server->standalone) {
    SilcBuffer tmpbuf;
    uint16 old_ident;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);

    /* Send WHOWAS command to our router */
    silc_server_packet_send(server, (SilcSocketConnection)
			    server->router->connection,
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    tmpbuf->data, tmpbuf->len, TRUE);

    /* Reprocess this packet after received reply from router */
    silc_server_command_pending(server, SILC_COMMAND_WHOWAS, 
				silc_command_get_ident(cmd->payload),
				silc_server_command_destructor,
				silc_server_command_whowas,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;

    silc_command_set_ident(cmd->payload, old_ident);

    silc_buffer_free(tmpbuf);
    ret = -1;
    goto out;
  }

  /* We are ready to process the command request. Let's search for the
     requested client and send reply to the requesting client. */

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT)
    check_global = TRUE;
  else if (server->server_type != SILC_SERVER)
    check_global = TRUE;

  /* Parse the whowas request */
  if (!silc_server_command_whowas_parse(cmd, &nick, &server_name, &count))
    return 0;

  /* Get all clients matching that nickname from local list */
  if (!silc_idlist_get_clients_by_nickname(server->local_list, 
					   nick, server_name,
					   &clients, &clients_count))
    silc_idlist_get_clients_by_hash(server->local_list, 
				    nick, server->md5hash,
				    &clients, &clients_count);
  
  /* Check global list as well */
  if (check_global) {
    if (!silc_idlist_get_clients_by_nickname(server->global_list, 
					     nick, server_name,
					     &clients, &clients_count))
      silc_idlist_get_clients_by_hash(server->global_list, 
				      nick, server->md5hash,
				      &clients, &clients_count);
  }
  
  if (!clients) {
    /* Such a client really does not exist in the SILC network. */
    silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOWAS,
					 SILC_STATUS_ERR_NO_SUCH_NICK,
					 3, nick, strlen(nick));
    goto out;
  }

  if (!silc_server_command_whowas_check(cmd, clients, clients_count)) {
    ret = -1;
    goto out;
  }

  /* Send the command reply to the client */
  silc_server_command_whowas_send_reply(cmd, clients, clients_count);

 out:
  silc_free(clients);
  silc_free(nick);
  silc_free(server_name);

  return ret;
}

/* Server side of command WHOWAS. */

SILC_SERVER_CMD_FUNC(whowas)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  int ret = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_WHOWAS, cmd, 1, 2);

  ret = silc_server_command_whowas_process(cmd);

  if (!ret)
    silc_server_command_free(cmd);
}

/******************************************************************************

                              IDENTIFY Functions

******************************************************************************/

static bool
silc_server_command_identify_parse(SilcServerCommandContext cmd,
				   SilcClientEntry **clients,
				   uint32 *clients_count,
				   SilcServerEntry **servers,
				   uint32 *servers_count,
				   SilcChannelEntry **channels,
				   uint32 *channels_count,
				   uint32 *count)
{
  SilcServer server = cmd->server;
  unsigned char *tmp;
  uint32 len;
  uint32 argc = silc_argument_get_arg_num(cmd->args);
  SilcIDPayload idp;
  bool check_global = FALSE;
  void *entry;
  int i;
  bool error = FALSE;

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT)
    check_global = TRUE;
  else if (server->server_type != SILC_SERVER)
    check_global = TRUE;

  /* If ID Payload is in the command it must be used instead of names */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!tmp) {
    /* No ID, get the names. */

    /* Try to get nickname@server. */
    tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
    if (tmp) {
      char *nick = NULL;
      char *nick_server = NULL;

      silc_parse_userfqdn(tmp, &nick, &nick_server);

      if (!silc_idlist_get_clients_by_hash(server->local_list, 
					   nick, server->md5hash,
					   clients, clients_count))
	silc_idlist_get_clients_by_nickname(server->local_list, 
					    nick, nick_server,
					    clients, clients_count);
      if (check_global) {
	if (!silc_idlist_get_clients_by_hash(server->global_list, 
					     nick, server->md5hash,
					     clients, clients_count))
	  silc_idlist_get_clients_by_nickname(server->global_list, 
					      nick, nick_server,
					      clients, clients_count);
      }

      silc_free(nick);
      silc_free(nick_server);

      if (!(*clients)) {
	silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					     SILC_STATUS_ERR_NO_SUCH_NICK,
					     3, tmp, strlen(tmp));
	return FALSE;
      }
    }

    /* Try to get server name */
    tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
    if (tmp) {
      entry = silc_idlist_find_server_by_name(server->local_list,
					      tmp, TRUE, NULL);
      if (!entry && check_global)
	entry = silc_idlist_find_server_by_name(server->global_list,
						tmp, TRUE, NULL);
      if (entry) {
	*servers = silc_realloc(*servers, sizeof(**servers) * 
				(*servers_count + 1));
	(*servers)[(*servers_count)++] = entry;
      }

      if (!(*servers)) {
	silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					     SILC_STATUS_ERR_NO_SUCH_SERVER,
					     3, tmp, strlen(tmp));
	return FALSE;
      }
    }

    /* Try to get channel name */
    tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (tmp) {
      entry = silc_idlist_find_channel_by_name(server->local_list,
					       tmp, NULL);
      if (!entry && check_global)
	entry = silc_idlist_find_channel_by_name(server->global_list,
						 tmp, NULL);
      if (entry) {
	*channels = silc_realloc(*channels, sizeof(**channels) * 
				 (*channels_count + 1));
	(*channels)[(*channels_count)++] = entry;
      }

      if (!(*channels)) {
	silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					     SILC_STATUS_ERR_NO_SUCH_CHANNEL,
					     3, tmp, strlen(tmp));
	return FALSE;
      }
    }

    if (!(*clients) && !(*servers) && !(*channels)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      return FALSE;
    }
  } else {
    /* Command includes ID, we must use that.  Also check whether the command
       has more than one ID set - take them all. */

    /* Take all ID's from the command packet */
    for (i = 0; i < argc; i++) {
      void *id;

      tmp = silc_argument_get_arg_type(cmd->args, i + 5, &len);
      if (!tmp)
	continue;
      
      idp = silc_id_payload_parse_data(tmp, len);
      if (!idp) {
	silc_free(*clients);
	silc_free(*servers);
	silc_free(*channels);
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
				      SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	return FALSE;
      }

      id = silc_id_payload_get_id(idp);
      
      switch (silc_id_payload_get_type(idp)) {
	
      case SILC_ID_CLIENT:
	entry = (void *)silc_idlist_find_client_by_id(server->local_list, 
						      id, TRUE, NULL);
	if (!entry && check_global)
	  entry = (void *)silc_idlist_find_client_by_id(server->global_list, 
							id, TRUE, NULL);
	if (entry) {
	  *clients = silc_realloc(*clients, sizeof(**clients) * 
				  (*clients_count + 1));
	  (*clients)[(*clients_count)++] = (SilcClientEntry)entry;
	} else {
	  silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					       2, tmp, len);
	  error = TRUE;
	}

	break;
	
      case SILC_ID_SERVER:
	entry = (void *)silc_idlist_find_server_by_id(server->local_list, 
						      id, TRUE, NULL);
	if (!entry && check_global)
	  entry = (void *)silc_idlist_find_server_by_id(server->global_list, 
							id, TRUE, NULL);
	if (entry) {
	  *servers = silc_realloc(*servers, sizeof(**servers) * 
				  (*servers_count + 1));
	  (*servers)[(*servers_count)++] = (SilcServerEntry)entry;
	} else {
	  silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					SILC_STATUS_ERR_NO_SUCH_SERVER_ID,
					       2, tmp, len);
	  error = TRUE;
	}
	break;
	
      case SILC_ID_CHANNEL:
	entry = (void *)silc_idlist_find_channel_by_id(server->local_list, 
						       id, NULL);
	if (!entry && check_global)
	  entry = (void *)silc_idlist_find_channel_by_id(server->global_list, 
							 id, NULL);
	if (entry) {
	  *channels = silc_realloc(*channels, sizeof(**channels) * 
				   (*channels_count + 1));
	  (*channels)[(*channels_count)++] = (SilcChannelEntry)entry;
	} else {
	  silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID,
					       2, tmp, len);
	  error = TRUE;
	}
	break;
      }

      silc_free(id);
    }
  }

  if (error) {
    silc_free(*clients);
    silc_free(*servers);
    silc_free(*channels);
    return FALSE;
  }
  
  /* Get the max count of reply messages allowed */
  tmp = silc_argument_get_arg_type(cmd->args, 4, NULL);
  if (tmp)
    *count = atoi(tmp);
  else
    *count = 0;

  return TRUE;
}

/* Checks that all mandatory fields in client entry are present. If not
   then send WHOIS request to the server who owns the client. We use
   WHOIS because we want to get as much information as possible at once. */

static bool
silc_server_command_identify_check_client(SilcServerCommandContext cmd,
					  SilcClientEntry *clients,
					  uint32 clients_count)
{
  SilcServer server = cmd->server;
  SilcClientEntry entry;
  SilcServerResolveContext resolve = NULL, r = NULL;
  uint32 resolve_count = 0;
  int i, k;
  bool no_res = TRUE;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (!entry || entry->nickname || 
	!(entry->data.status & SILC_IDLIST_STATUS_REGISTERED) ||
	!entry->router)
      continue;

    /* We need to resolve this entry since it is not complete */

    if (!cmd->pending && entry->data.status & SILC_IDLIST_STATUS_RESOLVING) {
      /* The entry is being resolved (and we are not the resolver) so attach
	 to the command reply and we're done with this one. */
      silc_server_command_pending(server, SILC_COMMAND_NONE, 
				  entry->resolve_cmd_ident,
				  silc_server_command_destructor,
				  silc_server_command_identify,
				  silc_server_command_dup(cmd));
      no_res = FALSE;
    } else {
      if (entry->data.status & SILC_IDLIST_STATUS_RESOLVING) {
	/* We've resolved this and it still is not ready.  We'll return
	   and are that this will be handled again after it is resolved. */
	for (i = 0; i < resolve_count; i++) {
	  for (k = 0; k < r->res_argc; k++)
	    silc_free(r->res_argv[k]);
	  silc_free(r->res_argv);
	  silc_free(r->res_argv_lens);
	  silc_free(r->res_argv_types);
	}
	silc_free(resolve);
	return FALSE;
      } else {
	/* We'll resolve this client */
	SilcBuffer idp;

	r = NULL;
	for (k = 0; k < resolve_count; k++) {
	  if (resolve[k].router == entry->router) {
	    r = &resolve[k];
	    break;
	  }
	}

	if (!r) {
	  resolve = silc_realloc(resolve, sizeof(*resolve) * 
				 (resolve_count + 1));
	  r = &resolve[resolve_count];
	  memset(r, 0, sizeof(*r));
	  r->router = entry->router;
	  r->ident = ++server->cmd_ident;
	  resolve_count++;
	}

	r->res_argv = silc_realloc(r->res_argv, sizeof(*r->res_argv) *
				   (r->res_argc + 1));
	r->res_argv_lens = silc_realloc(r->res_argv_lens, 
					sizeof(*r->res_argv_lens) *
					(r->res_argc + 1));
	r->res_argv_types = silc_realloc(r->res_argv_types, 
					 sizeof(*r->res_argv_types) *
					 (r->res_argc + 1));
	idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
	r->res_argv[r->res_argc] = silc_calloc(idp->len, 
					       sizeof(**r->res_argv));
	memcpy(r->res_argv[r->res_argc], idp->data, idp->len);
	r->res_argv_lens[r->res_argc] = idp->len;
	r->res_argv_types[r->res_argc] = r->res_argc + 3;
	r->res_argc++;
	silc_buffer_free(idp);

	entry->resolve_cmd_ident = r->ident;
	entry->data.status |= SILC_IDLIST_STATUS_RESOLVING;
	entry->data.status &= ~SILC_IDLIST_STATUS_RESOLVED;
      }
    }
  }

  /* Do the resolving */
  for (i = 0; i < resolve_count; i++) {
    SilcBuffer res_cmd;

    r = &resolve[i];

    /* Send WHOIS request. We send WHOIS since we're doing the requesting
       now anyway so make it a good one. */
    res_cmd = silc_command_payload_encode(SILC_COMMAND_WHOIS,
					  r->res_argc, r->res_argv, 
					  r->res_argv_lens,
					  r->res_argv_types, 
					  r->ident);
    silc_server_packet_send(server, r->router->connection,
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    res_cmd->data, res_cmd->len, FALSE);

    /* Reprocess this packet after received reply */
    silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				r->ident,
				silc_server_command_destructor,
				silc_server_command_identify,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;

    silc_buffer_free(res_cmd);
    for (k = 0; k < r->res_argc; k++)
      silc_free(r->res_argv[k]);
    silc_free(r->res_argv);
    silc_free(r->res_argv_lens);
    silc_free(r->res_argv_types);
    no_res = FALSE;
  }
  silc_free(resolve);

  return no_res;
}

static void
silc_server_command_identify_send_reply(SilcServerCommandContext cmd,
					SilcClientEntry *clients,
					uint32 clients_count,
					SilcServerEntry *servers,
					uint32 servers_count,
					SilcChannelEntry *channels,
					uint32 channels_count,
					int count)
{
  SilcServer server = cmd->server;
  int i, k, len;
  SilcBuffer packet, idp;
  SilcCommandStatus status;
  uint16 ident = silc_command_get_ident(cmd->payload);
  char nh[256], uh[256];
  SilcSocketConnection hsock;

  status = SILC_STATUS_OK;

  if (clients) {
    SilcClientEntry entry;

    len = 0;
    for (i = 0; i < clients_count; i++)
      if (clients[i]->data.status & SILC_IDLIST_STATUS_REGISTERED)
	len++;

    if (len == 0 && clients_count) {
      entry = clients[0];
      if (entry->nickname) {
	silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					     SILC_STATUS_ERR_NO_SUCH_NICK,
					     3, entry->nickname, 
					     strlen(entry->nickname));
      } else {
	SilcBuffer idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
	silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					     SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					     2, idp->data, idp->len);
	silc_buffer_free(idp);
      }
      
      return;
    }

    if (len > 1)
      status = SILC_STATUS_LIST_START;

    for (i = 0, k = 0; i < clients_count; i++) {
      entry = clients[i];
      
      if (!(entry->data.status & SILC_IDLIST_STATUS_REGISTERED)) {
	if (clients_count == 1) {
	  SilcBuffer idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
	  silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					 SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					       2, idp->data, idp->len);
	  silc_buffer_free(idp);
	}
	continue;
      }
      
      if (k >= 1)
	status = SILC_STATUS_LIST_ITEM;
      if (clients_count > 1 && k == clients_count - 1 
	  && !servers_count && !channels_count)
	status = SILC_STATUS_LIST_END;
      if (count && k - 1 == count)
	status = SILC_STATUS_LIST_END;
      if (count && k - 1 > count)
	break;
      
      /* Send IDENTIFY reply */
      idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
      
      memset(uh, 0, sizeof(uh));
      memset(nh, 0, sizeof(nh));
      
      strncat(nh, entry->nickname, strlen(entry->nickname));
      if (!strchr(entry->nickname, '@')) {
	strncat(nh, "@", 1);
	if (entry->servername) {
	  strncat(nh, entry->servername, strlen(entry->servername));
	} else {
	  len = entry->router ? strlen(entry->router->server_name) :
	    strlen(server->server_name);
	  strncat(nh, entry->router ? entry->router->server_name :
		  server->server_name, len);
	}
      }
      
      if (!entry->username) {
	packet = silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
						      status, ident, 2,
						      2, idp->data, idp->len, 
						      3, nh, strlen(nh));
      } else {
	strncat(uh, entry->username, strlen(entry->username));
	if (!strchr(entry->username, '@')) {
	  strncat(uh, "@", 1);
	  hsock = (SilcSocketConnection)entry->connection;
	  len = strlen(hsock->hostname);
	  strncat(uh, hsock->hostname, len);
	}
	
	packet = silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
						      status, ident, 3,
						      2, idp->data, idp->len, 
						      3, nh, strlen(nh),
						      4, uh, strlen(uh));
      }
      
      silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			      0, packet->data, packet->len, FALSE);
      
      silc_buffer_free(packet);
      silc_buffer_free(idp);
      
      k++;
    }
  }

  status = (status == SILC_STATUS_LIST_ITEM ? 
	    SILC_STATUS_LIST_ITEM : SILC_STATUS_OK);

  if (servers) {
    SilcServerEntry entry;

    if (status == SILC_STATUS_OK && servers_count > 1)
      status = SILC_STATUS_LIST_START;

    for (i = 0, k = 0; i < servers_count; i++) {
      entry = servers[i];
      
      if (k >= 1)
	status = SILC_STATUS_LIST_ITEM;
      if (servers_count > 1 && k == servers_count - 1 && !channels_count)
	status = SILC_STATUS_LIST_END;
      if (count && k - 1 == count)
	status = SILC_STATUS_LIST_END;
      if (count && k - 1 > count)
	break;
      
      /* Send IDENTIFY reply */
      idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
      if (entry->server_name) {
	packet = 
	  silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
					       status, ident, 2,
					       2, idp->data, idp->len, 
					       3, entry->server_name, 
					       strlen(entry->server_name));
      } else {
	packet = silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
						      status, ident, 1,
						      2, idp->data, idp->len);
      }
      
      silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			      0, packet->data, packet->len, FALSE);
      
      silc_buffer_free(packet);
      silc_buffer_free(idp);
      
      k++;
    }
  }

  status = (status == SILC_STATUS_LIST_ITEM ? 
	    SILC_STATUS_LIST_ITEM : SILC_STATUS_OK);

  if (channels) {
    SilcChannelEntry entry;

    if (status == SILC_STATUS_OK && channels_count > 1)
      status = SILC_STATUS_LIST_START;

    for (i = 0, k = 0; i < channels_count; i++) {
      entry = channels[i];
      
      if (k >= 1)
	status = SILC_STATUS_LIST_ITEM;
      if (channels_count > 1 && k == channels_count - 1)
	status = SILC_STATUS_LIST_END;
      if (count && k - 1 == count)
	status = SILC_STATUS_LIST_END;
      if (count && k - 1 > count)
	break;
      
      /* Send IDENTIFY reply */
      idp = silc_id_payload_encode(entry->id, SILC_ID_CHANNEL);
      if (entry->channel_name) {
	packet = 
	  silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
					       status, ident, 2,
					       2, idp->data, idp->len, 
					       3, entry->channel_name, 
					       strlen(entry->channel_name));
      } else {
	packet = silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
						      status, ident, 1,
						      2, idp->data, idp->len);
      }
      
      silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			      0, packet->data, packet->len, FALSE);
      
      silc_buffer_free(packet);
      silc_buffer_free(idp);
      
      k++;
    }
  }
}

static int
silc_server_command_identify_process(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  uint32 count = 0;
  int ret = 0;
  SilcClientEntry *clients = NULL;
  SilcServerEntry *servers = NULL;
  SilcChannelEntry *channels = NULL;
  uint32 clients_count = 0, servers_count = 0, channels_count = 0;

  /* Protocol dictates that we must always send the received IDENTIFY request
     to our router if we are normal server, so let's do it now unless we
     are standalone. We will not send any replies to the client until we
     have received reply from the router. */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT && 
      server->server_type == SILC_SERVER && !cmd->pending && 
      !server->standalone) {
    SilcBuffer tmpbuf;
    uint16 old_ident;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);

    /* Send IDENTIFY command to our router */
    silc_server_packet_send(server, (SilcSocketConnection)
			    server->router->connection,
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    tmpbuf->data, tmpbuf->len, TRUE);

    /* Reprocess this packet after received reply from router */
    silc_server_command_pending(server, SILC_COMMAND_IDENTIFY, 
				silc_command_get_ident(cmd->payload),
				silc_server_command_destructor,
				silc_server_command_identify,
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;

    silc_command_set_ident(cmd->payload, old_ident);

    silc_buffer_free(tmpbuf);
    ret = -1;
    goto out;
  }

  /* We are ready to process the command request. Let's search for the
     requested client and send reply to the requesting client. */

  /* Parse the IDENTIFY request */
  if (!silc_server_command_identify_parse(cmd,
					  &clients, &clients_count,
					  &servers, &servers_count,
					  &channels, &channels_count,
					  &count))
    return 0;

  /* Check that all mandatory fields are present and request those data
     from the server who owns the client if necessary. */
  if (clients && !silc_server_command_identify_check_client(cmd, clients, 
							    clients_count)) {
    ret = -1;
    goto out;
  }

  /* Send the command reply to the client */
  silc_server_command_identify_send_reply(cmd, 
					  clients, clients_count,
					  servers, servers_count,
					  channels, channels_count, 
					  count);

 out:
  silc_free(clients);
  silc_free(servers);
  silc_free(channels);

  return ret;
}

SILC_SERVER_CMD_FUNC(identify)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  int ret = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_IDENTIFY, cmd, 1, 3328);

  ret = silc_server_command_identify_process(cmd);

  if (!ret)
    silc_server_command_free(cmd);
}

/* Checks string for bad characters and returns TRUE if they are found. */

static int silc_server_command_bad_chars(char *nick)
{
  int i;

  for (i = 0; i < strlen(nick); i++) {
    if (!isascii(nick[i]))
      return TRUE;
    if (nick[i] <= 32) return TRUE;
    if (nick[i] == ' ') return TRUE;
    if (nick[i] == '\\') return TRUE;
    if (nick[i] == '\"') return TRUE;
    if (nick[i] == '*') return TRUE;
    if (nick[i] == '?') return TRUE;
    if (nick[i] == ',') return TRUE;
    if (nick[i] == '@') return TRUE;
    if (nick[i] == ':') return TRUE;
    if (nick[i] == '/') return TRUE;
    if (nick[i] == '[') return TRUE;
    if (nick[i] == '[') return TRUE;
    if (nick[i] == '(') return TRUE;
    if (nick[i] == ')') return TRUE;
    if (nick[i] == '{') return TRUE;
    if (nick[i] == '}') return TRUE;
  }

  return FALSE;
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
  char *nick;
  uint16 ident = silc_command_get_ident(cmd->payload);
  int nickfail = 0;

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_NICK, cmd, 1, 1);

  /* Check nickname */
  nick = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (silc_server_command_bad_chars(nick) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_BAD_NICKNAME);
    goto out;
  }

  if (strlen(nick) > 128)
    nick[128] = '\0';

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
    snprintf(&nick[strlen(nick) - 1], 1, "%d", nickfail);
  }

  /* Send notify about nickname change to our router. We send the new
     ID and ask to replace it with the old one. If we are router the
     packet is broadcasted. Send NICK_CHANGE notify. */
  if (!server->standalone)
    silc_server_send_notify_nick_change(server, server->router->connection, 
					server->server_type == SILC_SERVER ? 
					FALSE : TRUE, client->id,
					new_id);

  oidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Remove old cache entry */
  silc_idcache_del_by_context(server->local_list->clients, client);

  /* Free old ID */
  silc_free(client->id);

  /* Save the nickname as this client is our local client */
  silc_free(client->nickname);

  client->nickname = strdup(nick);
  client->id = new_id;

  /* Update client cache */
  silc_idcache_add(server->local_list->clients, client->nickname, 
		   client->id, (void *)client, FALSE);

  nidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Send NICK_CHANGE notify to the client's channels */
  silc_server_send_notify_on_channels(server, NULL, client, 
				      SILC_NOTIFY_TYPE_NICK_CHANGE, 2,
				      oidp->data, oidp->len, 
				      nidp->data, nidp->len);

 send_reply:
  /* Send the new Client ID as reply command back to client */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_NICK, 
						SILC_STATUS_OK, ident, 1, 
						2, nidp->data, nidp->len);
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
				    uint32 lch_count,
				    SilcChannelEntry *gch,
				    uint32 gch_count)
{
  int i;
  SilcBuffer packet, idp;
  SilcChannelEntry entry;
  SilcCommandStatus status;
  uint16 ident = silc_command_get_ident(cmd->payload);
  char *topic;
  unsigned char usercount[4];
  uint32 users;

  for (i = 0; i < lch_count; i++)
    if (lch[i]->mode & SILC_CHANNEL_MODE_SECRET)
      lch[i] = NULL;
  for (i = 0; i < gch_count; i++)
    if (gch[i]->mode & SILC_CHANNEL_MODE_SECRET)
      gch[i] = NULL;

  status = SILC_STATUS_OK;
  if ((lch_count + gch_count) > 1)
    status = SILC_STATUS_LIST_START;

  /* Local list */
  for (i = 0; i < lch_count; i++) {
    entry = lch[i];

    if (!entry)
      continue;

    if (i >= 1)
      status = SILC_STATUS_LIST_ITEM;

    if (lch_count > 1 && i == lch_count - 1 && !gch_count)
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
    if (topic)
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_LIST, 
					     status, ident, 4, 
					     2, idp->data, idp->len,
					     3, entry->channel_name, 
					     strlen(entry->channel_name),
					     4, topic, strlen(topic),
					     5, usercount, 4);
    else
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_LIST, 
					     status, ident, 3, 
					     2, idp->data, idp->len,
					     3, entry->channel_name, 
					     strlen(entry->channel_name),
					     5, usercount, 4);
    silc_server_packet_send(cmd->server, cmd->sock, 
			    SILC_PACKET_COMMAND_REPLY, 0, packet->data, 
			    packet->len, FALSE);
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

  status = i ? SILC_STATUS_LIST_ITEM : SILC_STATUS_OK;

  /* Global list */
  for (i = 0; i < gch_count; i++) {
    entry = gch[i];

    if (!entry)
      continue;

    if (i >= 1)
      status = SILC_STATUS_LIST_ITEM;

    if (gch_count > 1 && i == lch_count - 1)
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
    if (topic)
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_LIST, 
					     status, ident, 4, 
					     2, idp->data, idp->len,
					     3, entry->channel_name, 
					     strlen(entry->channel_name),
					     4, topic, strlen(topic),
					     5, usercount, 4);
    else
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_LIST, 
					     status, ident, 3, 
					     2, idp->data, idp->len,
					     3, entry->channel_name, 
					     strlen(entry->channel_name),
					     5, usercount, 4);
    silc_server_packet_send(cmd->server, cmd->sock, 
			    SILC_PACKET_COMMAND_REPLY, 0, packet->data, 
			    packet->len, FALSE);
    silc_buffer_free(packet);
    silc_buffer_free(idp);
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
  uint32 tmp_len;
  SilcChannelEntry *lchannels = NULL, *gchannels = NULL;
  uint32 lch_count = 0, gch_count = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LIST, cmd, 0, 1);

  /* If we are normal server, send the command to router, since we
     want to know all channels in the network. */
  if (!cmd->pending && server->server_type == SILC_SERVER && 
      !server->standalone) {
    SilcBuffer tmpbuf;
    uint16 old_ident;
    
    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, ++server->cmd_ident);
    tmpbuf = silc_command_payload_encode_payload(cmd->payload);
    silc_server_packet_send(server, server->router->connection,
			    SILC_PACKET_COMMAND, cmd->packet->flags,
			    tmpbuf->data, tmpbuf->len, TRUE);

    /* Reprocess this packet after received reply from router */
    silc_server_command_pending(server, SILC_COMMAND_LIST, 
				silc_command_get_ident(cmd->payload),
				silc_server_command_destructor,
				silc_server_command_list, 
				silc_server_command_dup(cmd));
    cmd->pending = TRUE;
    silc_command_set_ident(cmd->payload, old_ident);
    silc_buffer_free(tmpbuf);
    return;
  }

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (tmp) {
    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_LIST,
					    SILC_STATUS_ERR_NO_CHANNEL_ID);
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
  uint32 argc, tmp_len;
  uint16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_TOPIC, cmd, 1, 2);

  argc = silc_argument_get_arg_num(cmd->args);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
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
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  if (argc > 1) {
    /* Get the topic */
    tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
    if (!tmp) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }

    if (strlen(tmp) > 256) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }

    /* See whether the client is on channel and has rights to change topic */
    if (!silc_hash_table_find(channel->user_list, client, NULL, 
			      (void *)&chl)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					    SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
      if (channel->mode & SILC_CHANNEL_MODE_TOPIC) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					      SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	goto out;
      }
    }

    /* Set the topic for channel */
    silc_free(channel->topic);
    channel->topic = strdup(tmp);

    /* Send TOPIC_SET notify type to the network */
    if (!server->standalone)
      silc_server_send_notify_topic_set(server, server->router->connection,
					server->server_type == SILC_ROUTER ?
					TRUE : FALSE, channel, client->id,
					channel->topic);

    idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

    /* Send notify about topic change to all clients on the channel */
    silc_server_send_notify_to_channel(server, NULL, channel, TRUE,
				       SILC_NOTIFY_TYPE_TOPIC_SET, 2,
				       idp->data, idp->len,
				       channel->topic, strlen(channel->topic));
    silc_buffer_free(idp);
  }

  /* Send the topic to client as reply packet */
  idp = silc_id_payload_encode(channel_id, SILC_ID_CHANNEL);
  if (channel->topic)
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_TOPIC, 
						  SILC_STATUS_OK, ident, 2, 
						  2, idp->data, idp->len,
						  3, channel->topic, 
						  strlen(channel->topic));
  else
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_TOPIC, 
						  SILC_STATUS_OK, ident, 1, 
						  2, idp->data, idp->len);
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
  uint32 len;
  uint16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INVITE, cmd, 1, 4);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, len);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
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
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Check whether the sender of this command is on the channel. */
  sender = (SilcClientEntry)sock->user_data;
  if (!silc_server_client_on_channel(sender, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Check whether the channel is invite-only channel. If yes then the
     sender of this command must be at least channel operator. */
  if (channel->mode & SILC_CHANNEL_MODE_INVITE) {
    silc_hash_table_find(channel->user_list, sender, NULL, (void *)&chl);
    if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NO_CHANNEL_PRIV);
      goto out;
    }
  }

  /* Get destination client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (tmp) {
    char invite[512];

    dest_id = silc_id_payload_parse_id(tmp, len);
    if (!dest_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NO_CLIENT_ID);
      goto out;
    }

    /* Get the client entry */
    dest = silc_server_get_client_resolve(server, dest_id);
    if (!dest) {
      if (server->server_type != SILC_SERVER) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
				     SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
	goto out;
      }
      
      /* The client info is being resolved. Reprocess this packet after
	 receiving the reply to the query. */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				  server->cmd_ident,
				  silc_server_command_destructor,
				  silc_server_command_invite, 
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_free(channel_id);
      silc_free(dest_id);
      return;
    }

    /* Check whether the requested client is already on the channel. */
    if (silc_server_client_on_channel(dest, channel)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_USER_ON_CHANNEL);
      goto out;
    }
    
    /* Get route to the client */
    dest_sock = silc_server_get_client_route(server, NULL, 0, dest_id, &idata);
    if (!dest_sock) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					    SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
      goto out;
    }

    memset(invite, 0, sizeof(invite));
    strncat(invite, dest->nickname, strlen(dest->nickname));
    strncat(invite, "!", 1);
    strncat(invite, dest->username, strlen(dest->username));
    if (!strchr(dest->username, '@')) {
      strncat(invite, "@", 1);
      strncat(invite, cmd->sock->hostname, strlen(cmd->sock->hostname));
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
  if (!server->standalone)
    silc_server_send_notify_invite(server, server->router->connection,
				   server->server_type == SILC_ROUTER ?
				   TRUE : FALSE, channel,
				   sender->id, add, del);

  /* Send command reply */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);

  if (add || del)
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_INVITE,
					   SILC_STATUS_OK, ident, 2,
					   2, tmp, len,
					   3, channel->invite_list,
					   channel->invite_list ?
					   strlen(channel->invite_list) : 0);
  else
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_INVITE,
					   SILC_STATUS_OK, ident, 1,
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
  SilcServer server;
  SilcSocketConnection sock;
  char *signoff;
} *QuitInternal;

/* Quits connection to client. This gets called if client won't
   close the connection even when it has issued QUIT command. */

SILC_TASK_CALLBACK(silc_server_command_quit_cb)
{
  QuitInternal q = (QuitInternal)context;

  /* Free all client specific data, such as client entry and entires
     on channels this client may be on. */
  silc_server_free_client_data(q->server, q->sock, q->sock->user_data,
			       TRUE, q->signoff);
  q->sock->user_data = NULL;

  /* Close the connection on our side */
  silc_server_close_connection(q->server, q->sock);

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
  uint32 len = 0;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_QUIT, cmd, 0, 1);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Get destination ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (len > 128)
    tmp = NULL;

  q = silc_calloc(1, sizeof(*q));
  q->server = server;
  q->sock = sock;
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
  uint32 tmp_len, tmp_len2;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_KILL, cmd, 1, 2);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* KILL command works only on router */
  if (server->server_type != SILC_ROUTER) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NO_ROUTER_PRIV);
    goto out;
  }

  /* Check whether client has the permissions. */
  if (!(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NO_ROUTER_PRIV);
    goto out;
  }

  /* Get the client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					  SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
    goto out;
  }

  /* Get the client entry */
  remote_client = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
  if (!remote_client) {
    remote_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, TRUE, NULL);
    if (!remote_client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					    SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
      goto out;
    }
  }

  /* Get comment */
  comment = silc_argument_get_arg_type(cmd->args, 2, &tmp_len2);
  if (tmp_len2 > 128)
    comment = NULL;

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_KILL,
					SILC_STATUS_OK);

  /* Send the KILL notify packets. First send it to the channel, then
     to our primary router and then directly to the client who is being
     killed right now. */

  /* Send KILLED notify to the channels. It is not sent to the client
     as it will be sent differently destined directly to the client and not
     to the channel. */
  silc_server_send_notify_on_channels(server, remote_client, 
				      remote_client, SILC_NOTIFY_TYPE_KILLED,
				      comment ? 2 : 1,
				      tmp, tmp_len,
				      comment, comment ? tmp_len2 : 0);

  /* Send KILLED notify to primary route */
  if (!server->standalone)
    silc_server_send_notify_killed(server, server->router->connection, TRUE,
				   remote_client->id, comment);

  /* Send KILLED notify to the client directly */
  silc_server_send_notify_killed(server, remote_client->connection ? 
				 remote_client->connection : 
				 remote_client->router->connection, FALSE,
				 remote_client->id, comment);

  /* Remove the client from all channels. This generates new keys to the
     channels as well. */
  silc_server_remove_from_channels(server, NULL, remote_client, FALSE, 
				   NULL, TRUE);

  /* Remove the client entry, If it is locally connected then we will also
     disconnect the client here */
  if (remote_client->connection) {
    /* Remove locally conneted client */
    SilcSocketConnection sock = remote_client->connection;
    silc_server_free_client_data(server, sock, remote_client, FALSE, NULL);
    silc_server_close_connection(server, sock);
  } else {
    /* Remove remote client */
    if (!silc_idlist_del_client(server->global_list, remote_client))
      silc_idlist_del_client(server->local_list, remote_client);
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
  SilcBuffer packet, idp;
  unsigned char *tmp;
  uint32 tmp_len;
  char *dest_server, *server_info = NULL, *server_name;
  uint16 ident = silc_command_get_ident(cmd->payload);
  SilcServerEntry entry = NULL;
  SilcServerID *server_id = NULL;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INFO, cmd, 0, 2);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp) {
    server_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!server_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					    SILC_STATUS_ERR_NO_SERVER_ID);
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
					      SILC_STATUS_ERR_NO_SUCH_SERVER);
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
	     server->config->admin_info->location,
	     server->config->admin_info->server_type,
	     server->config->admin_info->admin_name,
	     server->config->admin_info->admin_email);

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
      uint16 old_ident;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, entry->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_INFO, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_info,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      return;
    }

    if (!entry && !cmd->pending && !server->standalone) {
      /* Send to the primary router */
      SilcBuffer tmpbuf;
      uint16 old_ident;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, server->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_INFO, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_info,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      return;
    }
  }

  silc_free(server_id);

  if (!entry) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_NO_SUCH_SERVER);
    goto out;
  }

  idp = silc_id_payload_encode(entry->id, SILC_ID_SERVER);
  if (!server_info)
    server_info = entry->server_info;
  server_name = entry->server_name;

  /* Send the reply */
  if (server_info)
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_INFO,
						  SILC_STATUS_OK, ident, 3,
						  2, idp->data, idp->len,
						  3, server_name, 
						  strlen(server_name),
						  4, server_info, 
						  strlen(server_info));
  else
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_INFO,
						  SILC_STATUS_OK, ident, 2,
						  2, idp->data, idp->len,
						  3, server_name, 
						  strlen(server_name));
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
  uint32 len;
  unsigned char *tmp;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_INFO, cmd, 1, 2);

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NO_SERVER_ID);
    goto out;
  }
  id = silc_id_str2id(tmp, len, SILC_ID_SERVER);
  if (!id)
    goto out;

  if (SILC_ID_SERVER_COMPARE(id, server->id)) {
    /* Send our reply */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_OK);
  } else {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NO_SUCH_SERVER);
    goto out;
  }

  silc_free(id);

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
					     uint32 umode)
{
  SilcSocketConnection sock = cmd->sock;
  unsigned char *tmp;
  uint32 tmp_len, user_count;
  unsigned char *passphrase = NULL, mode[4], tmp2[4], tmp3[4];
  SilcClientEntry client;
  SilcChannelClientEntry chl;
  SilcBuffer reply, chidp, clidp, keyp = NULL, user_list, mode_list;
  uint16 ident = silc_command_get_ident(cmd->payload);
  char check[512], check2[512];

  SILC_LOG_DEBUG(("Start"));

  if (!channel)
    return;

  /* Get the client entry */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    client = (SilcClientEntry)sock->user_data;
  } else {
    client = silc_server_get_client_resolve(server, client_id);
    if (!client) {
      if (cmd->pending)
	goto out;

      /* The client info is being resolved. Reprocess this packet after
	 receiving the reply to the query. */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				  server->cmd_ident, NULL,
				  silc_server_command_join, 
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      return;
    }

    cmd->pending = FALSE;
  }

  /*
   * Check channel modes
   */

  memset(check, 0, sizeof(check));
  memset(check2, 0, sizeof(check2));
  strncat(check, client->nickname, strlen(client->nickname));
  strncat(check, "!", 1);
  strncat(check, client->username, strlen(client->username));
  if (!strchr(client->username, '@')) {
    strncat(check, "@", 1);
    strncat(check, cmd->sock->hostname, strlen(cmd->sock->hostname));
  }

  strncat(check2, client->nickname, strlen(client->nickname));
  if (!strchr(client->nickname, '@')) {
    strncat(check2, "@", 1);
    strncat(check2, server->server_name, strlen(server->server_name));
  }
  strncat(check2, "!", 1);
  strncat(check2, client->username, strlen(client->username));
  if (!strchr(client->username, '@')) {
    strncat(check2, "@", 1);
    strncat(check2, cmd->sock->hostname, strlen(cmd->sock->hostname));
  }

  /* Check invite list if channel is invite-only channel */
  if (channel->mode & SILC_CHANNEL_MODE_INVITE) {
    if (!channel->invite_list ||
	(!silc_string_match(channel->invite_list, check) &&
	 !silc_string_match(channel->invite_list, check2))) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_NOT_INVITED);
      goto out;
    }
  }

  /* Check ban list if it exists. If the client's nickname, server,
     username and/or hostname is in the ban list the access to the
     channel is denied. */
  if (channel->ban_list) {
    if (!channel->ban_list ||
        silc_string_match(channel->ban_list, check) ||
	silc_string_match(channel->ban_list, check2)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
			      SILC_STATUS_ERR_BANNED_FROM_CHANNEL);
      goto out;
    }
  }

  /* Get passphrase */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp) {
    passphrase = silc_calloc(tmp_len, sizeof(*passphrase));
    memcpy(passphrase, tmp, tmp_len);
  }
  
  /* Check the channel passphrase if set. */
  if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
    if (!passphrase || !channel->passphrase ||
        memcmp(channel->passphrase, passphrase,
               strlen(channel->passphrase))) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_BAD_PASSWORD);
      goto out;
    }
  }

  /* Check user count limit if set. */
  if (channel->mode & SILC_CHANNEL_MODE_ULIMIT) {
    if (silc_hash_table_count(channel->user_list) + 1 > 
	channel->user_limit) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_CHANNEL_IS_FULL);
      goto out;
    }
  }

  /*
   * Client is allowed to join to the channel. Make it happen.
   */

  /* Check whether the client already is on the channel */
  if (silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_USER_ON_CHANNEL);
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
    keyp = silc_channel_key_payload_encode(SILC_ID_CHANNEL_LEN, tmp, 
					   strlen(channel->channel_key->
						  cipher->name),
					   channel->channel_key->cipher->name,
					   channel->key_len / 8, channel->key);
    silc_free(tmp);
  }

  reply = 
    silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					 SILC_STATUS_OK, ident, 13,
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
					 mode_list->len);

  /* Send command reply */
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  reply->data, reply->len, FALSE);

  /* Send JOIN notify to locally connected clients on the channel. If
     we are normal server then router will send or have sent JOIN notify
     already. However since we've added the client already to our channel
     we'll ignore it (in packet_receive.c) so we must send it here. If
     we are router then this will send it to local clients and local
     servers. */
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				     SILC_NOTIFY_TYPE_JOIN, 2,
				     clidp->data, clidp->len,
				     chidp->data, chidp->len);

  if (!cmd->pending) {
    /* Send JOIN notify packet to our primary router */
    if (!server->standalone)
      silc_server_send_notify_join(server, server->router->connection,
				   server->server_type == SILC_ROUTER ?
				   TRUE : FALSE, channel, client->id);

    if (keyp)
      /* Distribute the channel key to all backup routers. */
      silc_server_backup_send(server, NULL, SILC_PACKET_CHANNEL_KEY, 0,
			      keyp->data, keyp->len, FALSE, TRUE);
  }

  silc_buffer_free(reply);
  silc_buffer_free(clidp);
  silc_buffer_free(chidp);
  silc_buffer_free(keyp);
  silc_buffer_free(user_list);
  silc_buffer_free(mode_list);

 out:
  silc_free(passphrase);
}

/* Server side of command JOIN. Joins client into requested channel. If 
   the channel does not exist it will be created. */

SILC_SERVER_CMD_FUNC(join)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  uint32 tmp_len;
  char *tmp, *channel_name = NULL, *cipher, *hmac;
  SilcChannelEntry channel;
  uint32 umode = 0;
  bool created = FALSE, create_key = TRUE;
  SilcClientID *client_id;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_JOIN, cmd, 1, 4);

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  channel_name = tmp;

  if (strlen(channel_name) > 256)
    channel_name[255] = '\0';

  if (silc_server_command_bad_chars(channel_name) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_BAD_CHANNEL);
    goto out;
  }

  /* Get Client ID of the client who is joining to the channel */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get cipher and hmac name */
  cipher = silc_argument_get_arg_type(cmd->args, 4, NULL);
  hmac = silc_argument_get_arg_type(cmd->args, 5, NULL);

  /* See if the channel exists */
  channel = silc_idlist_find_channel_by_name(server->local_list, 
					     channel_name, NULL);

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    /* If this is coming from client the Client ID in the command packet must
       be same as the client's ID. */
    if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
      SilcClientEntry entry = (SilcClientEntry)cmd->sock->user_data;
      if (!SILC_ID_CLIENT_COMPARE(entry->id, client_id)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }
    }

    if (!channel || channel->disabled) {
      /* Channel not found */

      /* If we are standalone server we don't have a router, we just create 
	 the channel by ourselves. */
      if (server->standalone) {
	channel = silc_server_create_new_channel(server, server->id, cipher, 
						 hmac, channel_name, TRUE);
	if (!channel) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
		   			SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
	  goto out;
	}
	
	umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	created = TRUE;
	create_key = FALSE;
	
      } else {

	/* The channel does not exist on our server. If we are normal server 
	   we will send JOIN command to our router which will handle the
	   joining procedure (either creates the channel if it doesn't exist 
	   or joins the client to it). */
	if (server->server_type != SILC_ROUTER) {
	  SilcBuffer tmpbuf;
	  uint16 old_ident;

	  /* If this is pending command callback then we've resolved
	     it and it didn't work, return since we've notified the
	     client already in the command reply callback. */
	  if (cmd->pending)
	    goto out;
	  
	  old_ident = silc_command_get_ident(cmd->payload);
	  silc_command_set_ident(cmd->payload, ++server->cmd_ident);
	  tmpbuf = silc_command_payload_encode_payload(cmd->payload);
	  
	  /* Send JOIN command to our router */
	  silc_server_packet_send(server, (SilcSocketConnection)
				  server->router->connection,
				  SILC_PACKET_COMMAND, cmd->packet->flags,
				  tmpbuf->data, tmpbuf->len, TRUE);
	  
	  /* Reprocess this packet after received reply from router */
	  silc_server_command_pending(server, SILC_COMMAND_JOIN, 
				      silc_command_get_ident(cmd->payload),
				      silc_server_command_destructor,
				      silc_server_command_join,
				      silc_server_command_dup(cmd));
	  cmd->pending = TRUE;
	  return;
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
	    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
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
	  server->server_type != SILC_ROUTER)
	goto out;
      
      /* We are router and the channel does not seem exist so we will check
	 our global list as well for the channel. */
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 channel_name, NULL);
      if (!channel) {
	/* Channel really does not exist, create it */
	channel = silc_server_create_new_channel(server, server->id, cipher, 
						 hmac, channel_name, TRUE);
	if (!channel) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
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
    SilcServerCommandReplyContext reply = 
      (SilcServerCommandReplyContext)context2;
    if (silc_command_get(reply->payload) == SILC_COMMAND_JOIN) {
      tmp = silc_argument_get_arg_type(reply->args, 6, NULL);
      SILC_GET32_MSB(created, tmp);
      create_key = FALSE;	/* Router returned the key already */
    }
  }

  /* If the channel does not have global users and is also empty the client
     will be the channel founder and operator. */
  if (!channel->global_users && !silc_hash_table_count(channel->user_list))
    umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);

  /* Join to the channel */
  silc_server_command_join_channel(server, cmd, channel, client_id,
				   created, create_key, umode);

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
  uint32 motd_len;
  uint16 ident = silc_command_get_ident(cmd->payload);
  
  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_MOTD, cmd, 1, 1);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (!dest_server) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_MOTD,
					  SILC_STATUS_ERR_NO_SUCH_SERVER);
    goto out;
  }

  if (!strncasecmp(dest_server, server->server_name, strlen(dest_server))) {
    /* Send our MOTD */

    idp = silc_id_payload_encode(server->id_entry->id, SILC_ID_SERVER);

    if (server->config && server->config->motd && 
	server->config->motd->motd_file) {
      /* Send motd */
      motd = silc_file_readfile(server->config->motd->motd_file, &motd_len);
      if (!motd)
	goto out;
      
      motd[motd_len] = 0;
      packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						    SILC_STATUS_OK, ident, 2,
						    2, idp, idp->len,
						    3, motd, motd_len);
      goto out;
    } else {
      /* No motd */
      packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						    SILC_STATUS_OK, ident, 1,
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
      uint16 old_ident;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, entry->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_MOTD, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_motd,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      return;
    }

    if (!entry && !cmd->pending && !server->standalone) {
      /* Send to the primary router */
      SilcBuffer tmpbuf;
      uint16 old_ident;

      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      silc_server_packet_send(server, server->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);

      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_MOTD, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_motd,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      return;
    }

    if (!entry) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					    SILC_STATUS_ERR_NO_SUCH_SERVER);
      goto out;
    }

    idp = silc_id_payload_encode(server->id_entry->id, SILC_ID_SERVER);

    if (entry->motd)
      packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						    SILC_STATUS_OK, ident, 2,
						    2, idp, idp->len,
						    3, entry->motd,
						    strlen(entry->motd));
    else
      packet = silc_command_reply_payload_encode_va(SILC_COMMAND_MOTD,
						    SILC_STATUS_OK, ident, 1,
						    2, idp, idp->len);

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
  unsigned char *tmp_mask;
  uint32 mask;
  uint16 ident = silc_command_get_ident(cmd->payload);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_UMODE, cmd, 2, 2);

  /* Get the client's mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp_mask) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(mask, tmp_mask);

  /* 
   * Change the mode 
   */

  if (mask & SILC_UMODE_SERVER_OPERATOR) {
    if (!(client->mode & SILC_UMODE_SERVER_OPERATOR)) {
      /* Cannot operator mode */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					    SILC_STATUS_ERR_PERM_DENIED);
      goto out;
    }
  } else {
    if (client->mode & SILC_UMODE_SERVER_OPERATOR)
      /* Remove the server operator rights */
      client->mode &= ~SILC_UMODE_SERVER_OPERATOR;
  }

  if (mask & SILC_UMODE_ROUTER_OPERATOR) {
    if (!(client->mode & SILC_UMODE_ROUTER_OPERATOR)) {
      /* Cannot operator mode */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_UMODE,
					    SILC_STATUS_ERR_PERM_DENIED);
      goto out;
    }
  } else {
    if (client->mode & SILC_UMODE_ROUTER_OPERATOR)
      /* Remove the router operator rights */
      client->mode &= ~SILC_UMODE_ROUTER_OPERATOR;
  }

  if (mask & SILC_UMODE_GONE) {
    client->mode |= SILC_UMODE_GONE;
  } else {
    if (client->mode & SILC_UMODE_GONE)
      /* Remove the gone status */
      client->mode &= ~SILC_UMODE_GONE;
  }

  /* Send UMODE change to primary router */
  if (!server->standalone)
    silc_server_send_notify_umode(server, server->router->connection, TRUE,
				  client->id, client->mode);

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_UMODE,
						SILC_STATUS_OK, ident, 1,
						2, tmp_mask, 4);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
  silc_buffer_free(packet);

 out:
  silc_server_command_free(cmd);
}

/* Checks that client has rights to add or remove channel modes. If any
   of the checks fails FALSE is returned. */

int silc_server_check_cmode_rights(SilcChannelEntry channel,
				   SilcChannelClientEntry client,
				   uint32 mode)
{
  int is_op = client->mode & SILC_CHANNEL_UMODE_CHANOP;
  int is_fo = client->mode & SILC_CHANNEL_UMODE_CHANFO;

  /* Check whether has rights to change anything */
  if (!is_op && !is_fo)
    return FALSE;

  /* Check whether has rights to change everything */
  if (is_op && is_fo)
    return TRUE;

  /* We know that client is channel operator, check that they are not
     changing anything that requires channel founder rights. Rest of the
     modes are available automatically for channel operator. */

  if (mode & SILC_CHANNEL_MODE_PRIVKEY) {
    if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY))
      if (is_op && !is_fo)
	return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_PASSPHRASE) {
    if (!(channel->mode & SILC_CHANNEL_MODE_PASSPHRASE))
      if (is_op && !is_fo)
	return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }

  if (mode & SILC_CHANNEL_MODE_CIPHER) {
    if (!(channel->mode & SILC_CHANNEL_MODE_CIPHER))
      if (is_op && !is_fo)
	return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_CIPHER) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
    if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH))
      if (is_op && !is_fo)
	return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  return TRUE;
}

/* Server side command of CMODE. Changes channel mode */

SILC_SERVER_CMD_FUNC(cmode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcIDListData idata = (SilcIDListData)client;
  SilcChannelID *channel_id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer packet, cidp;
  unsigned char *tmp, *tmp_id, *tmp_mask;
  char *cipher = NULL, *hmac = NULL;
  uint32 mode_mask, tmp_len, tmp_len2;
  uint16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CMODE, cmd, 2, 7);

  /* Get Channel ID */
  tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len2);
  if (!tmp_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp_id, tmp_len2);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }

  /* Get the channel mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp_mask) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(mode_mask, tmp_mask);

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get entry to the channel user list */
  silc_hash_table_find(channel->user_list, client, NULL, (void *)&chl);

  /* Check that client has rights to change any requested channel modes */
  if (!silc_server_check_cmode_rights(channel, chl, mode_mask)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV);
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
    uint32 user_limit;
      
    /* Get user limit */
    tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (!tmp) {
      if (!(channel->mode & SILC_CHANNEL_MODE_ULIMIT)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
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
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      /* Save the passphrase */
      channel->passphrase = strdup(tmp);
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
      /* Passphrase mode is unset. remove the passphrase */
      if (channel->passphrase) {
	silc_free(channel->passphrase);
	channel->passphrase = NULL;
      }
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
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      /* Delete old cipher and allocate the new one */
      if (!silc_cipher_alloc(cipher, &newkey)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
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
				   SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
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
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      /* Delete old hmac and allocate the new one */
      if (!silc_hmac_alloc(hmac, NULL, &newhmac)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
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
				       SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
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
	SilcAuthPayload auth;
	
	tmp = silc_argument_get_arg_type(cmd->args, 7, &tmp_len);
	if (!tmp) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}

	auth = silc_auth_payload_parse(tmp, tmp_len);
	if (!auth) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}

	/* Save the public key */
	tmp = silc_pkcs_public_key_encode(idata->public_key, &tmp_len);
	silc_pkcs_public_key_decode(tmp, tmp_len, &channel->founder_key);
	silc_free(tmp);
	
	channel->founder_method = silc_auth_get_method(auth);

	if (channel->founder_method == SILC_AUTH_PASSWORD) {
	  tmp = silc_auth_get_data(auth, &tmp_len);
	  channel->founder_passwd = 
	    silc_calloc(tmp_len + 1, sizeof(*channel->founder_passwd));
	  memcpy(channel->founder_passwd, tmp, tmp_len);
	  channel->founder_passwd_len = tmp_len;
	} else {
	  /* Verify the payload before setting the mode */
	  if (!silc_auth_verify(auth, channel->founder_method, 
				channel->founder_key, 0, idata->hash,
				client->id, SILC_ID_CLIENT)) {
	    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
						  SILC_STATUS_ERR_AUTH_FAILED);
	    goto out;
	  }
	}

	silc_auth_payload_free(auth);
      }
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      if (channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
	if (channel->founder_key)
	  silc_pkcs_public_key_free(channel->founder_key);
	if (channel->founder_passwd) {
	  silc_free(channel->founder_passwd);
	  channel->founder_passwd = NULL;
	}
      }
    }
  }

  /* Finally, set the mode */
  channel->mode = mode_mask;

  /* Send CMODE_CHANGE notify */
  cidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				     SILC_NOTIFY_TYPE_CMODE_CHANGE, 4,
				     cidp->data, cidp->len, 
				     tmp_mask, 4,
				     cipher, cipher ? strlen(cipher) : 0,
				     hmac, hmac ? strlen(hmac) : 0);

  /* Set CMODE notify type to network */
  if (!server->standalone)
    silc_server_send_notify_cmode(server, server->router->connection,
				  server->server_type == SILC_ROUTER ? 
				  TRUE : FALSE, channel,
				  mode_mask, client->id, SILC_ID_CLIENT,
				  cipher, hmac);

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CMODE,
						SILC_STATUS_OK, ident, 2,
						2, tmp_id, tmp_len2,
						3, tmp_mask, 4);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_free(channel_id);
  silc_free(cidp);

 out:
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
  uint32 target_mask, sender_mask = 0, tmp_len, tmp_ch_len;
  int notify = FALSE;
  uint16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CUMODE, cmd, 3, 4);

  /* Get Channel ID */
  tmp_ch_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_ch_len);
  if (!tmp_ch_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp_ch_id, tmp_ch_len);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
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
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Check that client has rights to change other's rights */
  silc_hash_table_find(channel->user_list, client, NULL, (void *)&chl);
  sender_mask = chl->mode;
  
  /* Get the target client's channel mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp_mask) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(target_mask, tmp_mask);

  /* Get target Client ID */
  tmp_id = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp_id, tmp_len);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
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
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV);
    goto out;
  }

  /* Check whether target client is on the channel */
  if (target_client != client) {
    if (!silc_server_client_on_channel(target_client, channel)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
				 SILC_STATUS_ERR_USER_NOT_ON_CHANNEL);
      goto out;
    }

    /* Get entry to the channel user list */
    silc_hash_table_find(channel->user_list, target_client, NULL, 
			 (void *)&chl);
  }

  /* 
   * Change the mode 
   */

  /* If the target client is founder, no one else can change their mode
     but themselves. */
  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO && chl->client != target_client) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_YOU);
    goto out;
  }

  if (target_mask & SILC_CHANNEL_UMODE_CHANFO) {
    if (!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      /* The client tries to claim the founder rights. */
      unsigned char *tmp_auth;
      uint32 tmp_auth_len, auth_len;
      void *auth;
      
      if (target_client != client) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU);
	goto out;
      }

      if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) ||
	  !channel->founder_key || !idata->public_key ||
	  !silc_pkcs_public_key_compare(channel->founder_key, 
					idata->public_key)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU);
	goto out;
      }

      tmp_auth = silc_argument_get_arg_type(cmd->args, 4, &tmp_auth_len);
      if (!tmp_auth) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      auth = (channel->founder_method == SILC_AUTH_PASSWORD ?
	      (void *)channel->founder_passwd : (void *)channel->founder_key);
      auth_len = (channel->founder_method == SILC_AUTH_PASSWORD ?
		  channel->founder_passwd_len : 0);
      
      if (!silc_auth_verify_data(tmp_auth, tmp_auth_len,
				 channel->founder_method, auth, auth_len,
				 idata->hash, client->id, SILC_ID_CLIENT)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_AUTH_FAILED);
	goto out;
      }
      
      sender_mask = chl->mode |= SILC_CHANNEL_UMODE_CHANFO;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
      if (target_client == client) {
	/* Remove channel founder rights from itself */
	chl->mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	notify = TRUE;
      } else {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NOT_YOU);
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
					      SILC_STATUS_ERR_NO_CHANNEL_PRIV);
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
					      SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	goto out;
      }

      /* Demote to normal user */
      chl->mode &= ~SILC_CHANNEL_UMODE_CHANOP;
      notify = TRUE;
    }
  }

  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  tmp_id = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);

  /* Send notify to channel, notify only if mode was actually changed. */
  if (notify) {
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				       SILC_NOTIFY_TYPE_CUMODE_CHANGE, 3,
				       idp->data, idp->len,
				       tmp_mask, 4, 
				       tmp_id, tmp_len);

    /* Set CUMODE notify type to network */
    if (!server->standalone)
      silc_server_send_notify_cumode(server, server->router->connection,
				     server->server_type == SILC_ROUTER ? 
				     TRUE : FALSE, channel,
				     target_mask, client->id, 
				     SILC_ID_CLIENT,
				     target_client->id);
  }

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CUMODE,
						SILC_STATUS_OK, ident, 3,
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
  uint32 tmp_len;
  unsigned char *tmp, *comment;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LEAVE, cmd, 1, 3);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
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
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Check that the kicker is channel operator or channel founder */
  silc_hash_table_find(channel->user_list, client, NULL, (void *)&chl);
  if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV);
    goto out;
  }
  
  /* Get target Client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!client_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }

  /* Get target client's entry */
  target_client = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
  if (!target_client) {
    target_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, TRUE, NULL);
  }

  /* Check that the target client is not channel founder. Channel founder
     cannot be kicked from the channel. */
  silc_hash_table_find(channel->user_list, target_client, NULL, (void *)&chl);
  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_CHANNEL_FOPRIV);
    goto out;
  }
  
  /* Check whether target client is on the channel */
  if (!silc_server_client_on_channel(target_client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_USER_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get comment */
  tmp_len = 0;
  comment = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp_len > 128)
    comment = NULL;

  /* Send command reply to sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK, 
					SILC_STATUS_OK);

  /* Send KICKED notify to local clients on the channel */
  idp = silc_id_payload_encode(target_client->id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				     SILC_NOTIFY_TYPE_KICKED, 
				     comment ? 2 : 1,
				     idp->data, idp->len,
				     comment, comment ? strlen(comment) : 0);
  silc_buffer_free(idp);

  /* Remove the client from the channel. If the channel does not exist
     after removing the client then the client kicked itself off the channel
     and we don't have to send anything after that. */
  if (!silc_server_remove_from_one_channel(server, NULL, channel, 
					   target_client, FALSE))
    goto out;

  /* Send KICKED notify to primary route */
  if (!server->standalone)
    silc_server_send_notify_kicked(server, server->router->connection,
				   server->server_type == SILC_ROUTER ?
				   TRUE : FALSE, channel,
				   target_client->id, comment);

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
  uint32 tmp_len;
  SilcServerConfigSectionAdminConnection *admin;
  SilcIDListData idata = (SilcIDListData)client;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_OPER, cmd, 1, 2);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Get the username */
  username = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the admin configuration */
  admin = silc_server_config_find_admin(server->config, cmd->sock->ip,
					username, client->nickname);
  if (!admin) {
    admin = silc_server_config_find_admin(server->config, cmd->sock->hostname,
					  username, client->nickname);
    if (!admin) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					    SILC_STATUS_ERR_AUTH_FAILED);
      goto out;
    }
  }

  /* Get the authentication payload */
  auth = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!auth) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Verify the authentication data */
  if (!silc_auth_verify_data(auth, tmp_len, admin->auth_meth, 
			     admin->auth_data, admin->auth_data_len,
			     idata->hash, client->id, SILC_ID_CLIENT)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					  SILC_STATUS_ERR_AUTH_FAILED);
    goto out;
  }

  /* Client is now server operator */
  client->mode |= SILC_UMODE_SERVER_OPERATOR;

  /* Send UMODE change to primary router */
  if (!server->standalone)
    silc_server_send_notify_umode(server, server->router->connection, TRUE,
				  client->id, client->mode);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_OPER,
					SILC_STATUS_OK);

 out:
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
  uint32 tmp_len;
  SilcServerConfigSectionAdminConnection *admin;
  SilcIDListData idata = (SilcIDListData)client;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_SILCOPER, cmd, 1, 2);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  if (server->server_type != SILC_ROUTER) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_AUTH_FAILED);
    goto out;
  }

  /* Get the username */
  username = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!username) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the admin configuration */
  admin = silc_server_config_find_admin(server->config, cmd->sock->ip,
					username, client->nickname);
  if (!admin) {
    admin = silc_server_config_find_admin(server->config, cmd->sock->hostname,
					  username, client->nickname);
    if (!admin) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					    SILC_STATUS_ERR_AUTH_FAILED);
      goto out;
    }
  }

  /* Get the authentication payload */
  auth = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!auth) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Verify the authentication data */
  if (!silc_auth_verify_data(auth, tmp_len, admin->auth_meth, 
			     admin->auth_data, admin->auth_data_len,
			     idata->hash, client->id, SILC_ID_CLIENT)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					  SILC_STATUS_ERR_AUTH_FAILED);
    goto out;
  }

  /* Client is now router operator */
  client->mode |= SILC_UMODE_ROUTER_OPERATOR;

  /* Send UMODE change to primary router */
  if (!server->standalone)
    silc_server_send_notify_umode(server, server->router->connection, TRUE,
				  client->id, client->mode);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_SILCOPER,
					SILC_STATUS_OK);

 out:
  silc_server_command_free(cmd);
}

/* Server side command of CONNECT. Connects us to the specified remote
   server or router. */

SILC_SERVER_CMD_FUNC(connect)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  unsigned char *tmp, *host;
  uint32 tmp_len;
  uint32 port = SILC_PORT;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CONNECT, cmd, 1, 2);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Check whether client has the permissions. */
  if (client->mode == SILC_UMODE_NONE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CONNECT,
					  SILC_STATUS_ERR_NO_SERVER_PRIV);
    goto out;
  }

  if (server->server_type == SILC_ROUTER && 
      client->mode & SILC_UMODE_SERVER_OPERATOR) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CONNECT,
					  SILC_STATUS_ERR_NO_ROUTER_PRIV);
    goto out;
  }

  /* Get the remote server */
  host = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!host) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CONNECT,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get port */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp)
    SILC_GET32_MSB(port, tmp);

  /* Create the connection. It is done with timeout and is async. */
  silc_server_create_connection(server, host, port);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CONNECT,
					SILC_STATUS_OK);

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
  uint32 id_len, tmp_len;
  uint16 ident = silc_command_get_ident(cmd->payload);

  if (cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_BAN, cmd, 0, 3);

  /* Get Channel ID */
  id = silc_argument_get_arg_type(cmd->args, 1, &id_len);
  if (id) {
    channel_id = silc_id_payload_parse_id(id, id_len);
    if (!channel_id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					    SILC_STATUS_ERR_NO_CHANNEL_ID);
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
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get entry to the channel user list */
  silc_hash_table_find(channel->user_list, client, NULL, (void *)&chl);

  /* The client must be at least channel operator. */
  if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_BAN,
					  SILC_STATUS_ERR_NO_CHANNEL_PRIV);
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
  if (!server->standalone && (add || del))
    silc_server_send_notify_ban(server, server->router->connection,
				server->server_type == SILC_ROUTER ?
				TRUE : FALSE, channel, add, del);

  /* Send the reply back to the client */
  if (channel->ban_list)
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_BAN,
					   SILC_STATUS_OK, ident, 2,
					   2, id, id_len,
					   3, channel->ban_list, 
					   strlen(channel->ban_list) - 1);
  else
    packet = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_BAN,
					   SILC_STATUS_OK, ident, 1,
					   2, id, id_len);

  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);

 out:
  silc_free(channel_id);
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
  uint32 tmp_len;
  unsigned char *name;
  uint32 port = SILC_PORT;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_CLOSE, cmd, 1, 2);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Check whether client has the permissions. */
  if (client->mode == SILC_UMODE_NONE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CLOSE,
					  SILC_STATUS_ERR_NO_SERVER_PRIV);
    goto out;
  }

  /* Get the remote server */
  name = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!name) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CLOSE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
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
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CLOSE,
					  SILC_STATUS_ERR_NO_SERVER_ID);
    goto out;
  }

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CLOSE,
					SILC_STATUS_OK);

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
  silc_server_free_sock_user_data(server, sock);
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

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_SHUTDOWN, cmd, 0, 0);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Check whether client has the permission. */
  if (client->mode == SILC_UMODE_NONE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SHUTDOWN,
					  SILC_STATUS_ERR_NO_SERVER_PRIV);
    goto out;
  }

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_SHUTDOWN,
					SILC_STATUS_OK);

  /* Then, gracefully, or not, bring the server down. */
  silc_server_stop(server);
  exit(0);

 out:
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
  uint32 len;
  unsigned char *tmp;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_LEAVE, cmd, 1, 2);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  id = silc_id_payload_parse_id(tmp, len);
  if (!id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
    if (!channel) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(id_entry, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Notify routers that they should remove this client from their list
     of clients on the channel. Send LEAVE notify type. */
  if (!server->standalone)
    silc_server_send_notify_leave(server, server->router->connection,
				  server->server_type == SILC_ROUTER ?
				  TRUE : FALSE, channel, id_entry->id);

  silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					SILC_STATUS_OK);

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
  uint32 channel_id_len;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  unsigned char lc[4];
  uint32 list_count = 0;
  uint16 ident = silc_command_get_ident(cmd->payload);
  char *channel_name;

  SILC_SERVER_COMMAND_CHECK(SILC_COMMAND_USERS, cmd, 1, 2);

  /* Get Channel ID */
  channel_id = silc_argument_get_arg_type(cmd->args, 1, &channel_id_len);

  /* Get channel name */
  channel_name = silc_argument_get_arg_type(cmd->args, 2, NULL);

  if (!channel_id && !channel_name) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }

  if (channel_id) {
    id = silc_id_payload_parse_id(channel_id, channel_id_len);
    if (!id) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_CHANNEL_ID);
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

  if (!channel || channel->disabled) {
    if (server->server_type != SILC_ROUTER && !server->standalone &&
	!cmd->pending) {
      SilcBuffer tmpbuf;
      
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);
      
      /* Send USERS command */
      silc_server_packet_send(server, server->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
      /* Reprocess this packet after received reply */
      silc_server_command_pending(server, SILC_COMMAND_USERS, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_users,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      silc_command_set_ident(cmd->payload, ident);
      
      silc_buffer_free(tmpbuf);
      silc_free(id);
      return;
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
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* If the channel is private or secret do not send anything, unless the
     user requesting this command is on the channel. */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    if (channel->mode & (SILC_CHANNEL_MODE_PRIVATE | SILC_CHANNEL_MODE_SECRET)
	&& !silc_server_client_on_channel(cmd->sock->user_data, channel)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  } else {
    if (channel->mode & 
	(SILC_CHANNEL_MODE_PRIVATE | SILC_CHANNEL_MODE_SECRET)) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Get the users list */
  silc_server_get_users_on_channel(server, channel, &client_id_list,
				   &client_mode_list, &list_count);

  /* List count */
  SILC_PUT32_MSB(list_count, lc);

  /* Send reply */
  idp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_USERS,
						SILC_STATUS_OK, ident, 4,
						2, idp->data, idp->len,
						3, lc, 4,
						4, client_id_list->data,
						client_id_list->len,
						5, client_mode_list->data,
						client_mode_list->len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(idp);
  silc_buffer_free(packet);
  silc_buffer_free(client_id_list);
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
  uint16 ident = silc_command_get_ident(cmd->payload);
  unsigned char *tmp, *pkdata;
  uint32 tmp_len, pklen;
  SilcBuffer pk = NULL;
  SilcIdType id_type;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  idp = silc_id_payload_parse_data(tmp, tmp_len);
  if (!idp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
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
	(client && !client->connection && !cmd->pending) ||
	(client && !client->data.public_key && !cmd->pending)) {
      SilcBuffer tmpbuf;
      uint16 old_ident;
      SilcSocketConnection dest_sock;
      
      dest_sock = silc_server_get_client_route(server, NULL, 0, 
					       client_id, NULL);
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
				  silc_server_command_destructor,
				  silc_server_command_getkey,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      return;
    }

    if (!client) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					    SILC_STATUS_ERR_NO_SUCH_CLIENT_ID);
      goto out;
    }

    /* The client is locally connected, just get the public key and
       send it back. If they key does not exist then do not send it, 
       send just OK reply */
    if (!client->data.public_key) {
      pkdata = NULL;
      pklen = 0;
    } else {
      tmp = silc_pkcs_public_key_encode(client->data.public_key, &tmp_len);
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
      uint16 old_ident;
      
      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, ++server->cmd_ident);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);
      
      silc_server_packet_send(server, server->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
      /* Reprocess this packet after received reply from router */
      silc_server_command_pending(server, SILC_COMMAND_GETKEY, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_getkey,
				  silc_server_command_dup(cmd));
      cmd->pending = TRUE;
      
      silc_command_set_ident(cmd->payload, old_ident);
      silc_buffer_free(tmpbuf);
      return;
    }

    if (!server_entry) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_GETKEY,
					    SILC_STATUS_ERR_NO_SUCH_SERVER_ID);
      goto out;
    }

    /* If they key does not exist then do not send it, send just OK reply */
    if (!server_entry->data.public_key) {
      pkdata = NULL;
      pklen = 0;
    } else {
      tmp = silc_pkcs_public_key_encode(server_entry->data.public_key, 
					&tmp_len);
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
						SILC_STATUS_OK, ident, 
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
