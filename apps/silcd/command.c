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
				     unsigned int arg_type,
				     unsigned char *arg,
				     unsigned int arg_len);
void silc_server_command_send_users(SilcServer server,
				    SilcSocketConnection sock,
				    SilcChannelEntry channel,
				    int pending);

/* Server command list. */
SilcServerCommand silc_command_list[] =
{
  SILC_SERVER_CMD(whois, WHOIS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(whowas, WHOWAS, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(identify, IDENTIFY, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(nick, NICK, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(list, LIST, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(topic, TOPIC, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(invite, INVITE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(quit, QUIT, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(kill, KILL, SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(info, INFO, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(connect, CONNECT, 
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(ping, PING, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(oper, OPER, SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(join, JOIN, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(motd, MOTD, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(umode, UMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(cmode, CMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(cumode, CUMODE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(kick, KICK, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(restart, RESTART, 
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(close, CLOSE,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(shutdown, SHUTDOWN, SILC_CF_LAG | SILC_CF_REG | 
		  SILC_CF_OPER),
  SILC_SERVER_CMD(silcoper, SILCOPER,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER),
  SILC_SERVER_CMD(leave, LEAVE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(users, USERS, SILC_CF_LAG | SILC_CF_REG),

  { NULL, 0 },
};

#define SILC_SERVER_COMMAND_CHECK_ARGC(command, context, min, max)	      \
do {									      \
  unsigned int _argc = silc_argument_get_arg_num(cmd->args);		      \
									      \
  SILC_LOG_DEBUG(("Start"));						      \
									      \
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
  if (idata->registered)
    return TRUE;

  silc_server_command_send_status_reply(cmd, command,
					SILC_STATUS_ERR_NOT_REGISTERED);
  silc_server_command_free(cmd);
  return FALSE;
}

/* Processes received command packet. */

void silc_server_command_process(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcServerCommandContext ctx;
  SilcServerCommand *cmd;

#if 0
  /* XXX allow commands in but do not execute them more than once per
     two seconds. */

  /* Check whether it is allowed for this connection to execute any
     command. */
  if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
    time_t curtime;
    SilcClientEntry client = (SilcClientEntry)sock->user_data;

    if (!client)
      return;

    /* Allow only one command executed in 2 seconds. */
    curtime = time(NULL);
    if (client->last_command && (curtime - client->last_command) < 2)
      return;

    /* Update access time */
    client->last_command = curtime;
  }
#endif
  
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
  
  /* Execute command. If this fails the packet is dropped. */
  for (cmd = silc_command_list; cmd->cb; cmd++)
    if (cmd->cmd == silc_command_get(ctx->payload)) {

      if (!(cmd->flags & SILC_CF_REG)) {
	cmd->cb(ctx);
	break;
      }
      
      if (silc_server_is_registered(server, sock, ctx, cmd->cmd)) {
	cmd->cb(ctx);
	break;
      }
    }

  if (cmd == NULL) {
    SILC_LOG_ERROR(("Unknown command, packet dropped"));
    silc_server_command_free(ctx);
    return;
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
      silc_command_free_payload(ctx->payload);
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
   with `context' when reply has been received.  If `ident' is non-zero
   the `callback' will be executed when received reply with command
   identifier `ident'. */

void silc_server_command_pending(SilcServer server,
				 SilcCommand reply_cmd,
				 unsigned short ident,
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
				     unsigned short ident)
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

int silc_server_command_pending_check(SilcServer server,
				      SilcServerCommandReplyContext ctx,
				      SilcCommand command, 
				      unsigned short ident)
{
  SilcServerCommandPending *r;

  silc_dlist_start(server->pending_commands);
  while ((r = silc_dlist_get(server->pending_commands)) != SILC_LIST_END) {
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

  buffer = silc_command_reply_payload_encode_va(command, status, 0, 0);
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
				     unsigned int arg_type,
				     unsigned char *arg,
				     unsigned int arg_len)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer = silc_command_reply_payload_encode_va(command, status, 0, 1,
						arg_type, arg, arg_len);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0, 
			  buffer->data, buffer->len, FALSE);
  silc_buffer_free(buffer);
}

/******************************************************************************

                              WHOIS Functions

******************************************************************************/

static int
silc_server_command_whois_parse(SilcServerCommandContext cmd,
				SilcClientID ***client_id,
				unsigned int *client_id_count,
				char **nickname,
				char **server_name,
				int *count,
				SilcCommand command)
{
  unsigned char *tmp;
  unsigned int len;
  unsigned int argc = silc_argument_get_arg_num(cmd->args);
  int i, k;

  /* If client ID is in the command it must be used instead of nickname */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!tmp) {
    /* No ID, get the nickname@server string and parse it. */
    tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
    if (tmp) {
      if (strchr(tmp, '@')) {
	len = strcspn(tmp, "@");
	*nickname = silc_calloc(len + 1, sizeof(char));
	memcpy(*nickname, tmp, len);
	*server_name = silc_calloc(strlen(tmp) - len, sizeof(char));
	memcpy(*server_name, tmp + len + 1, strlen(tmp) - len - 1);
      } else {
	*nickname = strdup(tmp);
      }
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
    if (argc > 3) {
      for (k = 1, i = 4; i < argc + 1; i++) {
	tmp = silc_argument_get_arg_type(cmd->args, i, &len);
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

    /* Command includes ID, use that */
  }

  /* Get the max count of reply messages allowed */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (tmp)
    *count = atoi(tmp);
  else
    *count = 0;

  return TRUE;
}

static char
silc_server_command_whois_check(SilcServerCommandContext cmd,
				SilcClientEntry *clients,
				unsigned int clients_count)
{
  SilcServer server = cmd->server;
  int i;
  SilcClientEntry entry;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (!entry->nickname || !entry->username) {
      SilcBuffer tmpbuf;
      unsigned short old_ident;

      if (!entry->router)
	continue;
      
      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, silc_rng_get_rn16(server->rng));
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);

      /* Send WHOIS command */
      silc_server_packet_send(server, entry->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
      /* Reprocess this packet after received reply */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_whois, 
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
silc_server_command_whois_send_reply(SilcServerCommandContext cmd,
				     SilcClientEntry *clients,
				     unsigned int clients_count)
{
  SilcServer server = cmd->server;
  char *tmp;
  int i, count = 0, len;
  SilcBuffer packet, idp;
  SilcClientEntry entry;
  SilcCommandStatus status;
  unsigned short ident = silc_command_get_ident(cmd->payload);

  status = SILC_STATUS_OK;
  if (clients_count > 1)
    status = SILC_STATUS_LIST_START;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (count && i - 1 == count)
      break;

    if (clients_count > 2)
      status = SILC_STATUS_LIST_ITEM;

    if (clients_count > 1 && i == clients_count - 1)
      status = SILC_STATUS_LIST_END;

    /* Sanity check, however these should never fail. However, as
       this sanity check has been added here they have failed. */
    if (!entry->nickname || !entry->username)
      continue;
      
    /* Send WHOIS reply */
    idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
    tmp = silc_argument_get_first_arg(cmd->args, NULL);
    
    /* XXX */
    {
      char nh[256], uh[256];
      unsigned char idle[4];
      SilcSocketConnection hsock;

      memset(uh, 0, sizeof(uh));
      memset(nh, 0, sizeof(nh));

      strncat(nh, entry->nickname, strlen(entry->nickname));
      if (!strchr(entry->nickname, '@')) {
	strncat(nh, "@", 1);
	len = entry->router ? strlen(entry->router->server_name) :
	  strlen(server->server_name);
	strncat(nh, entry->router ? entry->router->server_name :
		server->server_name, len);
      }
      
      strncat(uh, entry->username, strlen(entry->username));
      if (!strchr(entry->username, '@')) {
	strncat(uh, "@", 1);
	hsock = (SilcSocketConnection)entry->connection;
	len = strlen(hsock->hostname);
	strncat(uh, hsock->hostname, len);
      }
      
      SILC_PUT32_MSB((time(NULL) - entry->data.last_receive), idle);
      
      /* XXX */
      if (entry->userinfo)
	packet = 
	  silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					       status, ident, 5, 
					       2, idp->data, idp->len,
					       3, nh, strlen(nh),
					       4, uh, strlen(uh),
					       5, entry->userinfo, 
					       strlen(entry->userinfo),
					       7, idle, 4);
      else
	packet = 
	  silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					       status, ident, 4, 
					       2, idp->data, idp->len,
					       3, nh, strlen(nh),
					       4, uh, strlen(uh),
					       7, idle, 4);
    }
    
    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			    0, packet->data, packet->len, FALSE);
    
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }
}

static int
silc_server_command_whois_from_client(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  char *nick = NULL, *server_name = NULL;
  int count = 0, clients_count = 0;
  SilcClientEntry *clients = NULL, entry;
  SilcClientID **client_id = NULL;
  unsigned int client_id_count = 0;
  int i, ret = 0;

  /* Protocol dictates that we must always send the received WHOIS request
     to our router if we are normal server, so let's do it now unless we
     are standalone. We will not send any replies to the client until we
     have received reply from the router. */
  if (server->server_type == SILC_SERVER && 
      !cmd->pending && !server->standalone) {
    SilcBuffer tmpbuf;
    unsigned short old_ident;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, silc_rng_get_rn16(server->rng));
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
					    client_id[i], NULL);
      if (entry) {
	clients = silc_realloc(clients, sizeof(*clients) * 
			       (clients_count + 1));
	clients[clients_count++] = entry;
      }
    }
  } else {
    clients = silc_idlist_get_clients_by_nickname(server->local_list, 
						  nick, server_name,
						  &clients_count);
  }
  
  /* Check global list as well */
  if (!clients) {
    if (client_id_count) {
      /* Check all Client ID's received in the command packet */
      for (i = 0; i < client_id_count; i++) {
	entry = silc_idlist_find_client_by_id(server->global_list, 
					      client_id[i], NULL);
	if (entry) {
	  clients = silc_realloc(clients, sizeof(*clients) * 
				 (clients_count + 1));
	  clients[clients_count++] = entry;
	}
      }
    } else {
      clients = silc_idlist_get_clients_by_nickname(server->global_list, 
						    nick, server_name,
						    &clients_count);
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

  /* Send the command reply to the client */
  silc_server_command_whois_send_reply(cmd, clients, clients_count);

 out:
  if (client_id_count) {
    for (i = 0; i < client_id_count; i++)
      silc_free(client_id[i]);
    silc_free(client_id);
  }
  if (clients)
    silc_free(clients);
  if (nick)
    silc_free(nick);
  if (server_name)
    silc_free(server_name);

  return ret;
}

static int
silc_server_command_whois_from_server(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  char *nick = NULL, *server_name = NULL;
  int count = 0, clients_count = 0;
  SilcClientEntry *clients = NULL, entry;
  SilcClientID **client_id = NULL;
  unsigned int client_id_count = 0;
  int i, ret = 0;

  /* Parse the whois request */
  if (!silc_server_command_whois_parse(cmd, &client_id, &client_id_count, 
				       &nick, &server_name, &count,
				       SILC_COMMAND_WHOIS))
    return 0;

  /* Process the command request. Let's search for the requested client and
     send reply to the requesting server. */

  if (client_id_count) {
    /* Check all Client ID's received in the command packet */
    for (i = 0; i < client_id_count; i++) {
      entry = silc_idlist_find_client_by_id(server->local_list, 
					    client_id[i], NULL);
      if (entry) {
	clients = silc_realloc(clients, sizeof(*clients) * 
			       (clients_count + 1));
	clients[clients_count++] = entry;
      }
    }
  } else {
    clients = silc_idlist_get_clients_by_nickname(server->local_list, 
						  nick, server_name,
						  &clients_count);
    if (!clients)
      clients = silc_idlist_get_clients_by_hash(server->local_list, 
						nick, server->md5hash,
						&clients_count);
  }
  
  /* If we are router we will check our global list as well. */
  if (!clients && server->server_type == SILC_ROUTER) {
    if (client_id_count) {
      /* Check all Client ID's received in the command packet */
      for (i = 0; i < client_id_count; i++) {
	entry = silc_idlist_find_client_by_id(server->global_list, 
					      client_id[i], NULL);
	if (entry) {
	  clients = silc_realloc(clients, sizeof(*clients) * 
				 (clients_count + 1));
	  clients[clients_count++] = entry;
	}
      }
    } else {
      clients = silc_idlist_get_clients_by_nickname(server->global_list, 
						    nick, server_name,
						    &clients_count);
      if (!clients)
	clients = silc_idlist_get_clients_by_hash(server->global_list, 
						  nick, server->md5hash,
						  &clients_count);
    }
  }

  if (!clients) {
    /* Such a client really does not exist in the SILC network. */
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

  /* Send the command reply to the client */
  silc_server_command_whois_send_reply(cmd, clients, clients_count);

 out:
  if (client_id_count) {
    for (i = 0; i < client_id_count; i++)
      silc_free(client_id[i]);
    silc_free(client_id);
  }
  if (clients)
    silc_free(clients);
  if (nick)
    silc_free(nick);
  if (server_name)
    silc_free(server_name);

  return ret;
}

/* Server side of command WHOIS. Processes user's query and sends found 
   results as command replies back to the client. */

SILC_SERVER_CMD_FUNC(whois)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  int ret = 0;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_WHOIS, cmd, 1, 3328);

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT)
    ret = silc_server_command_whois_from_client(cmd);
  else if ((cmd->sock->type == SILC_SOCKET_TYPE_SERVER) ||
	   (cmd->sock->type == SILC_SOCKET_TYPE_ROUTER))
    ret = silc_server_command_whois_from_server(cmd);

  if (!ret)
    silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(whowas)
{
}

/******************************************************************************

                              IDENTIFY Functions

******************************************************************************/

/* Checks that all mandatory fields are present. If not then send WHOIS 
   request to the server who owns the client. We use WHOIS because we want
   to get as much information as possible at once. */

static char
silc_server_command_identify_check(SilcServerCommandContext cmd,
				   SilcClientEntry *clients,
				   unsigned int clients_count)
{
  SilcServer server = cmd->server;
  int i;
  SilcClientEntry entry;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (!entry->nickname) {
      SilcBuffer tmpbuf;
      unsigned short old_ident;
      
      if (!entry->router)
	continue;
      
      old_ident = silc_command_get_ident(cmd->payload);
      silc_command_set_ident(cmd->payload, silc_rng_get_rn16(server->rng));
      silc_command_set_command(cmd->payload, SILC_COMMAND_WHOIS);
      tmpbuf = silc_command_payload_encode_payload(cmd->payload);
      
      /* Send WHOIS request. We send WHOIS since we're doing the requesting
	 now anyway so make it a good one. */
      silc_server_packet_send(server, entry->router->connection,
			      SILC_PACKET_COMMAND, cmd->packet->flags,
			      tmpbuf->data, tmpbuf->len, TRUE);
      
      /* Reprocess this packet after received reply */
      silc_server_command_pending(server, SILC_COMMAND_WHOIS, 
				  silc_command_get_ident(cmd->payload),
				  silc_server_command_destructor,
				  silc_server_command_identify,
				  silc_server_command_dup(cmd));

      cmd->pending = TRUE;
      
      /* Put old data back to the Command Payload we just changed */
      silc_command_set_ident(cmd->payload, old_ident);
      silc_command_set_command(cmd->payload, SILC_COMMAND_IDENTIFY);

      silc_buffer_free(tmpbuf);
      return FALSE;
    }
  }

  return TRUE;
}

static void
silc_server_command_identify_send_reply(SilcServerCommandContext cmd,
					SilcClientEntry *clients,
					unsigned int clients_count)
{
  SilcServer server = cmd->server;
  char *tmp;
  int i, count = 0, len;
  SilcBuffer packet, idp;
  SilcClientEntry entry;
  SilcCommandStatus status;
  unsigned short ident = silc_command_get_ident(cmd->payload);

  status = SILC_STATUS_OK;
  if (clients_count > 1)
    status = SILC_STATUS_LIST_START;

  for (i = 0; i < clients_count; i++) {
    entry = clients[i];

    if (count && i - 1 == count)
      break;

    if (clients_count > 2)
      status = SILC_STATUS_LIST_ITEM;

    if (clients_count > 1 && i == clients_count - 1)
      status = SILC_STATUS_LIST_END;

    /* Send IDENTIFY reply */
    idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
    tmp = silc_argument_get_first_arg(cmd->args, NULL);
    
    /* XXX */
    {
      char nh[256], uh[256];
      SilcSocketConnection hsock;

      memset(uh, 0, sizeof(uh));
      memset(nh, 0, sizeof(nh));
      
      strncat(nh, entry->nickname, strlen(entry->nickname));
      if (!strchr(entry->nickname, '@')) {
	strncat(nh, "@", 1);
	len = entry->router ? strlen(entry->router->server_name) :
	  strlen(server->server_name);
	strncat(nh, entry->router ? entry->router->server_name :
		server->server_name, len);
      }
      
      if (!entry->username) {
	packet = silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
						      SILC_STATUS_OK, ident, 2,
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
						      SILC_STATUS_OK, ident, 3,
						      2, idp->data, idp->len, 
						      3, nh, strlen(nh),
						      4, uh, strlen(uh));
      }
      
      silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			      0, packet->data, packet->len, FALSE);
      
      silc_buffer_free(packet);
      silc_buffer_free(idp);
    }
  }
}

static int
silc_server_command_identify_from_client(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  char *nick = NULL, *server_name = NULL;
  int count = 0, clients_count = 0; 
  SilcClientEntry *clients = NULL, entry;
  SilcClientID **client_id = NULL;
  unsigned int client_id_count = 0;
  int i, ret = 0;

  /* Protocol dictates that we must always send the received IDENTIFY request
     to our router if we are normal server, so let's do it now unless we
     are standalone. We will not send any replies to the client until we
     have received reply from the router. */
  if (server->server_type == SILC_SERVER && 
      !cmd->pending && !server->standalone) {
    SilcBuffer tmpbuf;
    unsigned short old_ident;

    old_ident = silc_command_get_ident(cmd->payload);
    silc_command_set_ident(cmd->payload, silc_rng_get_rn16(server->rng));
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
  if (!silc_server_command_whois_parse(cmd, &client_id, &client_id_count,
				       &nick, &server_name, &count,
				       SILC_COMMAND_IDENTIFY))
    return 0;

  /* Get all clients matching that ID or nickname from local list */
  if (client_id_count) { 
    /* Check all Client ID's received in the command packet */
    for (i = 0; i < client_id_count; i++) {
      entry = silc_idlist_find_client_by_id(server->local_list, 
					    client_id[i], NULL);
      if (entry) {
	clients = silc_realloc(clients, sizeof(*clients) * 
			       (clients_count + 1));
	clients[clients_count++] = entry;
      }
    }
  } else {
    clients = silc_idlist_get_clients_by_nickname(server->local_list, 
						  nick, server_name,
						  &clients_count);
  }
  
  /* Check global list as well */
  if (!clients) {
    if (client_id_count) {
      /* Check all Client ID's received in the command packet */
      for (i = 0; i < client_id_count; i++) {
	entry = silc_idlist_find_client_by_id(server->global_list, 
					      client_id[i], NULL);
	if (entry) {
	  clients = silc_realloc(clients, sizeof(*clients) * 
				 (clients_count + 1));
	  clients[clients_count++] = entry;
	}
      }
    } else {
      clients = silc_idlist_get_clients_by_nickname(server->global_list, 
						    nick, server_name,
						    &clients_count);
    }
  }
  
  if (!clients) {
    /* Such a client really does not exist in the SILC network. */
    if (!client_id_count) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					   SILC_STATUS_ERR_NO_SUCH_NICK,
					   3, nick, strlen(nick));
    } else {
      SilcBuffer idp = silc_id_payload_encode(client_id[0], SILC_ID_CLIENT);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   2, idp->data, idp->len);
      silc_buffer_free(idp);
    }
    goto out;
  }

  /* Check that all mandatory fields are present and request those data
     from the server who owns the client if necessary. */
  if (!silc_server_command_identify_check(cmd, clients, clients_count)) {
    ret = -1;
    goto out;
  }

  /* Send the command reply to the client */
  silc_server_command_identify_send_reply(cmd, clients, clients_count);

 out:
  if (client_id_count) {
    for (i = 0; i < client_id_count; i++)
      silc_free(client_id[i]);
    silc_free(client_id);
  }
  if (clients)
    silc_free(clients);
  if (nick)
    silc_free(nick);
  if (server_name)
    silc_free(server_name);

  return ret;
}

static int
silc_server_command_identify_from_server(SilcServerCommandContext cmd)
{
  SilcServer server = cmd->server;
  char *nick = NULL, *server_name = NULL;
  int count = 0, clients_count = 0;
  SilcClientEntry *clients = NULL, entry;
  SilcClientID **client_id = NULL;
  unsigned int client_id_count = 0;
  int i, ret = 0;

  /* Parse the IDENTIFY request */
  if (!silc_server_command_whois_parse(cmd, &client_id, &client_id_count,
				       &nick, &server_name, &count,
				       SILC_COMMAND_IDENTIFY))
    return 0;

  /* Process the command request. Let's search for the requested client and
     send reply to the requesting server. */

  if (client_id_count) {
    /* Check all Client ID's received in the command packet */
    for (i = 0; i < client_id_count; i++) {
      entry = silc_idlist_find_client_by_id(server->local_list, 
					    client_id[i], NULL);
      if (entry) {
	clients = silc_realloc(clients, sizeof(*clients) * 
			       (clients_count + 1));
	clients[clients_count++] = entry;
      }
    }
  } else {
    clients = silc_idlist_get_clients_by_nickname(server->local_list, 
						  nick, server_name,
						  &clients_count);
    if (!clients)
      clients = silc_idlist_get_clients_by_hash(server->local_list, 
						nick, server->md5hash,
						&clients_count);
  }
  
  /* If we are router we will check our global list as well. */
  if (!clients && server->server_type == SILC_ROUTER) {
    if (client_id_count) {
      /* Check all Client ID's received in the command packet */
      for (i = 0; i < client_id_count; i++) {
	entry = silc_idlist_find_client_by_id(server->global_list, 
					      client_id[i], NULL);
	if (entry) {
	  clients = silc_realloc(clients, sizeof(*clients) * 
				 (clients_count + 1));
	  clients[clients_count++] = entry;
	}
      }
    } else {
      clients = silc_idlist_get_clients_by_nickname(server->global_list, 
						    nick, server_name,
						    &clients_count);
      if (!clients)
	clients = silc_idlist_get_clients_by_hash(server->global_list, 
						  nick, server->md5hash,
						  &clients_count);
    }
  }

  if (!clients) {
    /* Such a client really does not exist in the SILC network. */
    if (!client_id_count) {
      silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					   SILC_STATUS_ERR_NO_SUCH_NICK,
					   3, nick, strlen(nick));
    } else {
      SilcBuffer idp = silc_id_payload_encode(client_id[0], SILC_ID_CLIENT);
      silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					   SILC_STATUS_ERR_NO_SUCH_CLIENT_ID,
					   2, idp->data, idp->len);
      silc_buffer_free(idp);
    }
    goto out;
  }

  /* Check that all mandatory fields are present and request those data
     from the server who owns the client if necessary. */
  if (!silc_server_command_identify_check(cmd, clients, clients_count)) {
    ret = -1;
    goto out;
  }

  /* Send the command reply */
  silc_server_command_identify_send_reply(cmd, clients, clients_count);

 out:
  if (client_id_count) {
    for (i = 0; i < client_id_count; i++)
      silc_free(client_id[i]);
    silc_free(client_id);
  }
  if (clients)
    silc_free(clients);
  if (nick)
    silc_free(nick);
  if (server_name)
    silc_free(server_name);

  return ret;
}

SILC_SERVER_CMD_FUNC(identify)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  int ret = 0;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_IDENTIFY, cmd, 1, 3328);

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT)
    ret = silc_server_command_identify_from_client(cmd);
  else if ((cmd->sock->type == SILC_SOCKET_TYPE_SERVER) |
	   (cmd->sock->type == SILC_SOCKET_TYPE_ROUTER))
    ret = silc_server_command_identify_from_server(cmd);

  if (!ret)
    silc_server_command_free(cmd);
}

/* Checks string for bad characters and returns TRUE if they are found. */

static int silc_server_command_bad_chars(char *nick)
{
  if (strchr(nick, '\\')) return TRUE;
  if (strchr(nick, '\"')) return TRUE;
  if (strchr(nick, '´')) return TRUE;
  if (strchr(nick, '`')) return TRUE;
  if (strchr(nick, '\'')) return TRUE;
  if (strchr(nick, '*')) return TRUE;
  if (strchr(nick, '/')) return TRUE;
  if (strchr(nick, '@')) return TRUE;

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
  SilcBuffer packet, nidp, oidp;
  SilcClientID *new_id;
  char *nick;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_NICK, cmd, 1, 1);

  /* Check nickname */
  nick = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (silc_server_command_bad_chars(nick) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_BAD_NICKNAME);
    goto out;
  }

  /* Create new Client ID */
  silc_id_create_client_id(cmd->server->id, cmd->server->rng, 
			   cmd->server->md5hash, nick,
			   &new_id);

  /* Send notify about nickname change to our router. We send the new
     ID and ask to replace it with the old one. If we are router the
     packet is broadcasted. Send NICK_CHANGE notify. */
  if (!server->standalone)
    silc_server_send_notify_nick_change(server, server->router->connection, 
					server->server_type == SILC_SERVER ? 
					FALSE : TRUE, client->id,
					new_id, SILC_ID_CLIENT_LEN);

  /* Remove old cache entry */
  silc_idcache_del_by_id(server->local_list->clients, SILC_ID_CLIENT, 
			 client->id); 

  oidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Free old ID */
  if (client->id) {
    memset(client->id, 0, SILC_ID_CLIENT_LEN);
    silc_free(client->id);
  }

  /* Save the nickname as this client is our local client */
  if (client->nickname)
    silc_free(client->nickname);

  client->nickname = strdup(nick);
  client->id = new_id;

  /* Update client cache */
  silc_idcache_add(server->local_list->clients, client->nickname, 
		   SILC_ID_CLIENT, client->id, (void *)client, TRUE);

  nidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Send NICK_CHANGE notify to the client's channels */
  silc_server_send_notify_on_channels(server, client, 
				      SILC_NOTIFY_TYPE_NICK_CHANGE, 2,
				      oidp->data, oidp->len, 
				      nidp->data, nidp->len);

  /* Send the new Client ID as reply command back to client */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_NICK, 
						SILC_STATUS_OK, 0, 1, 
						2, nidp->data, nidp->len);
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
  silc_buffer_free(nidp);
  silc_buffer_free(oidp);
  
 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(list)
{
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
  unsigned int argc, tmp_len;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_TOPIC, cmd, 1, 2);

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
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
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

    /* See whether has rights to change topic */
    silc_list_start(channel->user_list);
    while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END)
      if (chl->client == client)
	break;

    if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
      if (channel->mode & SILC_CHANNEL_MODE_TOPIC) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					      SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	goto out;
      }
    }

    /* Set the topic for channel */
    if (channel->topic)
      silc_free(channel->topic);
    channel->topic = strdup(tmp);

    /* Send TOPIC_SET notify type to the network */
    if (!server->standalone)
      silc_server_send_notify_topic_set(server, server->router->connection,
					server->server_type == SILC_ROUTER ?
					TRUE : FALSE, channel, client->id,
					SILC_ID_CLIENT_LEN, channel->topic);

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
						  SILC_STATUS_OK, 0, 2, 
						  2, idp->data, idp->len,
						  3, channel->topic, 
						  strlen(channel->topic));
  else
    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_TOPIC, 
						  SILC_STATUS_OK, 0, 1, 
						  2, idp->data, idp->len);
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
  silc_buffer_free(idp);
  silc_free(channel_id);

 out:
  silc_server_command_free(cmd);
}

/* Server side of INVITE command. Invites some client to join some channel. */

SILC_SERVER_CMD_FUNC(invite)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock, dest_sock;
  SilcClientEntry sender, dest;
  SilcClientID *dest_id;
  SilcChannelEntry channel;
  SilcChannelID *channel_id;
  SilcBuffer sidp;
  unsigned char *tmp;
  unsigned int len;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_INVITE, cmd, 1, 2);

  /* Get destination ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }
  dest_id = silc_id_payload_parse_id(tmp, len);
  if (!dest_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
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

  /* Check whether the channel exists */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
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
    SilcChannelClientEntry chl;

    silc_list_start(channel->user_list);
    while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END)
      if (chl->client == sender) {
	if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	  goto out;
	}
	break;
      }
  }

  /* Find the connection data for the destination. If it is local we will
     send it directly otherwise we will send it to router for routing. */
  dest = silc_idlist_find_client_by_id(server->local_list, dest_id, NULL);
  if (dest)
    dest_sock = (SilcSocketConnection)dest->connection;
  else
    dest_sock = silc_server_route_get(server, dest_id, SILC_ID_CLIENT);

  /* Check whether the requested client is already on the channel. */
  /* XXX if we are normal server we don't know about global clients on
     the channel thus we must request it (USERS command), check from
     local cache as well. */
  if (silc_server_client_on_channel(dest, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_USER_ON_CHANNEL);
    goto out;
  }

  sidp = silc_id_payload_encode(sender->id, SILC_ID_CLIENT);

  /* Send notify to the client that is invited to the channel */
  silc_server_send_notify_dest(server, dest_sock, FALSE, dest_id, 
			       SILC_ID_CLIENT,
			       SILC_NOTIFY_TYPE_INVITE, 2, 
			       sidp->data, sidp->len, tmp, len);

  /* Send command reply */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					SILC_STATUS_OK);

  silc_buffer_free(sidp);

 out:
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
			       q->signoff);
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
  unsigned int len = 0;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_QUIT, cmd, 0, 1);

  /* Get destination ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (len > 128)
    tmp = NULL;

  q = silc_calloc(1, sizeof(*q));
  q->server = server;
  q->sock = sock;
  q->signoff = tmp ? strdup(tmp) : NULL;

  /* We quit the connection with little timeout */
  silc_task_register(server->timeout_queue, sock->sock,
		     silc_server_command_quit_cb, (void *)q,
		     0, 200000, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(kill)
{
}

/* Server side of command INFO. This sends information about us to 
   the client. If client requested specific server we will send the 
   command to that server. */

SILC_SERVER_CMD_FUNC(info)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcBuffer packet, idp;
  char info_string[256], *dest_server;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_INFO, cmd, 1, 1);

  /* Get server name */
  dest_server = silc_argument_get_arg_type(cmd->args, 1, NULL);
  if (!dest_server) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_NO_SUCH_SERVER);
    goto out;
  }

  if (!strncasecmp(dest_server, server->server_name, strlen(dest_server))) {
    /* Send our reply */
    memset(info_string, 0, sizeof(info_string));
    snprintf(info_string, sizeof(info_string), 
	     "location: %s server: %s admin: %s <%s>",
	     server->config->admin_info->location,
	     server->config->admin_info->server_type,
	     server->config->admin_info->admin_name,
	     server->config->admin_info->admin_email);

    idp = silc_id_payload_encode(server->id, SILC_ID_SERVER);

    packet = silc_command_reply_payload_encode_va(SILC_COMMAND_INFO,
						  SILC_STATUS_OK, 0, 2,
						  2, idp->data, idp->len,
						  3, info_string, 
						  strlen(info_string));
    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			    packet->data, packet->len, FALSE);
    
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  } else {
    /* Send this command to the requested server */

    if (server->server_type == SILC_SERVER && !server->standalone) {

    }

    if (server->server_type == SILC_ROUTER) {

    }
  }
  
 out:
  silc_server_command_free(cmd);
}

/* Server side of command PING. This just replies to the ping. */

SILC_SERVER_CMD_FUNC(ping)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcServerID *id;
  unsigned int len;
  unsigned char *tmp;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_INFO, cmd, 1, 2);

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

  if (!SILC_ID_SERVER_COMPARE(id, server->id)) {
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

/* Assembles USERS command and executes it. This is called when client
   joins to a channel and we wan't to send USERS command reply to the 
   client. */

void silc_server_command_send_users(SilcServer server,
				    SilcSocketConnection sock,
				    SilcChannelEntry channel,
				    int pending)
{
  SilcServerCommandContext cmd;
  SilcBuffer buffer, idp;
  SilcPacketContext *packet = silc_packet_context_alloc();

  SILC_LOG_DEBUG(("Start"));

  /* Create USERS command packet and process it. */
  idp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_USERS, 0, 1,
					  1, idp->data, idp->len);

  packet->buffer = silc_buffer_copy(buffer);
  packet->sock = sock;
  packet->type = SILC_PACKET_COMMAND;

  cmd = silc_server_command_alloc();
  cmd->payload = silc_command_payload_parse(buffer);
  if (!cmd->payload) {
    silc_free(cmd);
    silc_buffer_free(buffer);
    silc_buffer_free(idp);
    silc_packet_context_free(packet);
    return;
  }
  cmd->args = silc_command_get_args(cmd->payload);
  cmd->server = server;
  cmd->sock = silc_socket_dup(sock);
  cmd->packet = silc_packet_context_dup(packet);
  cmd->pending = FALSE;

  if (pending) {
    /* If this function was called from pending command then instead of
       processing the command now, register a pending command callback which
       will process it after we've received the automatic USERS command 
       reply which server will send in JOIN. */
    silc_server_command_pending(server, SILC_COMMAND_USERS, 0, NULL,
				silc_server_command_users, cmd);
    cmd->pending = TRUE;
    silc_buffer_free(buffer);
    silc_buffer_free(idp);
    return;
  }

  /* Process USERS command. */
  silc_server_command_users((void *)cmd);

  silc_buffer_free(buffer);
  silc_buffer_free(idp);
  silc_packet_context_free(packet);
}

/* Internal routine to join channel. The channel sent to this function
   has been either created or resolved from ID lists. This joins the sent
   client to the channel. */

static void silc_server_command_join_channel(SilcServer server, 
					     SilcServerCommandContext cmd,
					     SilcChannelEntry channel,
					     SilcClientID *client_id,
					     int created,
					     unsigned int umode)
{
  SilcSocketConnection sock = cmd->sock;
  unsigned char *tmp;
  unsigned int tmp_len;
  unsigned char *passphrase = NULL, mode[4], tmp2[4];
  SilcClientEntry client;
  SilcChannelClientEntry chl;
  SilcBuffer reply, chidp, clidp, keyp;
  unsigned short ident = silc_command_get_ident(cmd->payload);

  SILC_LOG_DEBUG(("Start"));

  if (!channel)
    return;

  /* Get passphrase */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp) {
    passphrase = silc_calloc(tmp_len, sizeof(*passphrase));
    memcpy(passphrase, tmp, tmp_len);
  }
  
  /*
   * Check channel modes
   */

  /* Check invite list if channel is invite-only channel */
  if (channel->mode & SILC_CHANNEL_MODE_INVITE) {
    if (channel->mode & SILC_CHANNEL_MODE_INVITE_LIST) {
      /* Invite list is specified. Check whether client is invited in the
	 list. If not, then check whether it has been invited otherwise. */

    } else {
      /* XXX client must be invited to be able to join the channel */
    }
  }

  /* Check ban list if set */
  if (channel->mode & SILC_CHANNEL_MODE_BAN) {

  }

  /* Check the channel passphrase if set. */
  if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
    if (!passphrase || memcmp(channel->mode_data.passphrase, passphrase,
			      strlen(channel->mode_data.passphrase))) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_BAD_PASSWORD);
      goto out;
    }
  }

  /* Check user count limit if set. */
  if (channel->mode & SILC_CHANNEL_MODE_ULIMIT) {
    if (silc_list_count(channel->user_list) + 1 > 
	channel->mode_data.user_limit) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					    SILC_STATUS_ERR_CHANNEL_IS_FULL);
      goto out;
    }
  }

  /*
   * Client is allowed to join to the channel. Make it happen.
   */

  /* Get the client entry */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    client = (SilcClientEntry)sock->user_data;
  } else {
    client = silc_idlist_find_client_by_id(server->local_list, client_id, 
					   NULL);
    if (!client) {
      /* XXX actually this is useless since router finds always cell's
	 local clients from its local lists. */
      client = silc_idlist_find_client_by_id(server->global_list, client_id, 
					     NULL);
      if (!client)
	goto out;
    }
  }

  /* Check whether the client already is on the channel */
  if (silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_USER_ON_CHANNEL);
    goto out;
  }

  /* Generate new channel key as protocol dictates */
  if (!created || !channel->channel_key)
    silc_server_create_channel_key(server, channel, 0);

  /* Send the channel key. This is broadcasted to the channel but is not
     sent to the client who is joining to the channel. */
  silc_server_send_channel_key(server, NULL, channel, 
			       server->server_type == SILC_ROUTER ? 
			       FALSE : server->standalone);

  /* Join the client to the channel by adding it to channel's user list.
     Add also the channel to client entry's channels list for fast cross-
     referencing. */
  chl = silc_calloc(1, sizeof(*chl));
  chl->mode = umode;
  chl->client = client;
  chl->channel = channel;
  silc_list_add(channel->user_list, chl);
  silc_list_add(client->channels, chl);

  /* Encode Client ID Payload of the original client who wants to join */
  clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

  /* Encode command reply packet */
  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(channel->mode, mode);
  SILC_PUT32_MSB(created, tmp2);
  tmp = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  keyp = silc_channel_key_payload_encode(SILC_ID_CHANNEL_LEN, tmp, 
					 SILC_ID_CHANNEL_LEN,
					 channel->channel_key->cipher->name,
					 channel->key_len / 8, channel->key);
  silc_free(tmp);
  if (!channel->topic) {
    reply = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					   SILC_STATUS_OK, ident, 5,
					   2, channel->channel_name,
					   strlen(channel->channel_name),
					   3, chidp->data, chidp->len,
					   4, mode, 4,
					   5, tmp2, 4,
					   6, keyp->data, keyp->len);
  } else {
    reply = 
      silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					   SILC_STATUS_OK, ident, 6, 
					   2, channel->channel_name, 
					   strlen(channel->channel_name),
					   3, chidp->data, chidp->len,
					   4, mode, 4,
					   5, tmp2, 4,
					   6, keyp->data, keyp->len,
					   8, channel->topic, 
					   strlen(channel->topic));
  }

  /* Send command reply */
  silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  reply->data, reply->len, FALSE);

  if (!cmd->pending) {
    /* Send JOIN notify to locally connected clients on the channel */
    silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				       SILC_NOTIFY_TYPE_JOIN, 2,
				       clidp->data, clidp->len,
				       chidp->data, chidp->len);

    /* Send JOIN notify packet to our primary router */
    if (!server->standalone)
      silc_server_send_notify_join(server, server->router->connection,
				   server->server_type == SILC_ROUTER ?
				   TRUE : FALSE, channel, client->id,
				   SILC_ID_CLIENT_LEN);
  }

  /* Send USERS command reply to the joined channel so the user sees who
     is currently on the channel. */
  silc_server_command_send_users(server, sock, channel, cmd->pending);

  silc_buffer_free(reply);
  silc_buffer_free(clidp);
  silc_buffer_free(chidp);
  silc_buffer_free(keyp);

 out:
  if (passphrase)
    silc_free(passphrase);
}

/* Server side of command JOIN. Joins client into requested channel. If 
   the channel does not exist it will be created. */

SILC_SERVER_CMD_FUNC(join)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  int tmp_len;
  char *tmp, *channel_name = NULL, *cipher = NULL;
  SilcChannelEntry channel;
  unsigned int umode = 0;
  int created = FALSE;
  SilcClientID *client_id;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_JOIN, cmd, 1, 4);

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  channel_name = tmp;

  if (silc_server_command_bad_chars(channel_name) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_BAD_CHANNEL);
    silc_free(channel_name);
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

  /* Get cipher name */
  cipher = silc_argument_get_arg_type(cmd->args, 4, NULL);

  /* See if the channel exists */
  channel = silc_idlist_find_channel_by_name(server->local_list, 
					     channel_name, NULL);

  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    /* If this is coming from client the Client ID in the command packet must
       be same as the client's ID. */
    if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
      SilcClientEntry entry = (SilcClientEntry)cmd->sock->user_data;
      if (SILC_ID_CLIENT_COMPARE(entry->id, client_id)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }
    }

    if (!channel) {
      /* Channel not found */

      /* If we are standalone server we don't have a router, we just create 
	 the channel by ourselves. */
      if (server->standalone) {
	channel = silc_server_create_new_channel(server, server->id, cipher, 
						 channel_name, TRUE);
	umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	created = TRUE;

      } else {

	/* The channel does not exist on our server. If we are normal server 
	   we will send JOIN command to our router which will handle the
	   joining procedure (either creates the channel if it doesn't exist 
	   or joins the client to it). */
	if (server->server_type == SILC_SERVER) {
	  SilcBuffer tmpbuf;
	  unsigned short old_ident;
	  
	  old_ident = silc_command_get_ident(cmd->payload);
	  silc_command_set_ident(cmd->payload, silc_rng_get_rn16(server->rng));
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
						   channel_name, TRUE);
	  umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	  created = TRUE;
	}
      }
    }
  } else {
    if (!channel) {
      /* Channel not found */

      /* If the command came from router and/or we are normal server then
	 something went wrong with the joining as the channel was not found.
	 We can't do anything else but ignore this. */
      if (cmd->sock->type == SILC_SOCKET_TYPE_ROUTER ||
	  server->server_type == SILC_SERVER)
	goto out;
      
      /* We are router and the channel does not seem exist so we will check
	 our global list as well for the channel. */
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 channel_name, NULL);
      if (!channel) {
	/* Channel really does not exist, create it */
	channel = silc_server_create_new_channel(server, server->id, cipher, 
						 channel_name, TRUE);
	umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
	created = TRUE;
      }
    }
  }

  /* If the channel does not have global users and is also empty it means the
     channel was created globally (by our router) and the client will be the
     channel founder and operator. */
  if (!channel->global_users && silc_list_count(channel->user_list) == 0) {
    umode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
    created = TRUE;		/* Created globally by our router */
  }

  /* Join to the channel */
  silc_server_command_join_channel(server, cmd, channel, client_id,
				   created, umode);

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
  char *motd;
  int motd_len;
  
  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_MOTD, cmd, 1, 2);

  /* XXX show currently only our motd */

  if (server->config && server->config->motd && 
      server->config->motd->motd_file) {

    /* Send motd */
    motd = silc_file_read(server->config->motd->motd_file, &motd_len);
    if (!motd)
      goto out;

    motd[motd_len] = 0;
    silc_server_command_send_status_data(cmd, SILC_COMMAND_MOTD,
					 SILC_STATUS_OK,
					 2, motd, motd_len);
    goto out;
  } else {
    /* No motd */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_MOTD,
					  SILC_STATUS_OK);
  }

 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(umode)
{
}

/* Checks that client has rights to add or remove channel modes. If any
   of the checks fails FALSE is returned. */

int silc_server_check_cmode_rights(SilcChannelEntry channel,
				   SilcChannelClientEntry client,
				   unsigned int mode)
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
    if (is_op && !is_fo)
      return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }
  
  if (mode & SILC_CHANNEL_MODE_PASSPHRASE) {
    if (is_op && !is_fo)
      return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
      if (is_op && !is_fo)
	return FALSE;
    }
  }

  if (mode & SILC_CHANNEL_MODE_CIPHER) {
    if (is_op && !is_fo)
      return FALSE;
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_CIPHER) {
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
  SilcChannelID *channel_id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer packet, cidp;
  unsigned char *tmp, *tmp_id, *tmp_mask;
  unsigned int argc, mode_mask, tmp_len, tmp_len2;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 8) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

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
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
  }

  /* Check whether this client is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get entry to the channel user list */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END)
    if (chl->client == client)
      break;

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
    /* Nothing interesting to do here now */
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY) {
      /* The mode is removed and we need to generate and distribute
	 new channel key. Clients are not using private channel keys
	 anymore after this. */

      /* XXX Duplicated code, make own function for this!! LEAVE uses this
	 as well */

      /* Re-generate channel key */
      silc_server_create_channel_key(server, channel, 0);
      
      /* Encode channel key payload to be distributed on the channel */
      packet = 
	silc_channel_key_payload_encode(tmp_len2, tmp_id,
					strlen(channel->channel_key->
					       cipher->name),
					channel->channel_key->cipher->name,
					channel->key_len / 8, channel->key);
      
      /* If we are normal server then we will send it to our router.  If we
	 are router we will send it to all local servers that has clients on
	 the channel */
      if (server->server_type == SILC_SERVER) {
	if (!server->standalone)
	  silc_server_packet_send(server, 
				  cmd->server->router->connection,
				  SILC_PACKET_CHANNEL_KEY, 0, packet->data,
				  packet->len, TRUE);
      } else {
	
      }
      
      /* Send to locally connected clients on the channel */
      silc_server_packet_send_local_channel(server, channel, 
					    SILC_PACKET_CHANNEL_KEY, 0,
					    packet->data, packet->len, FALSE);
      silc_buffer_free(packet);
    }
  }
  
  if (mode_mask & SILC_CHANNEL_MODE_ULIMIT) {
    /* User limit is set on channel */
    unsigned int user_limit;
      
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
      channel->mode_data.user_limit = user_limit;
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
      /* User limit mode is unset. Remove user limit */
      channel->mode_data.user_limit = 0;
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
      channel->mode_data.passphrase = strdup(tmp);
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_PASSPHRASE) {
      /* Passphrase mode is unset. remove the passphrase */
      if (channel->mode_data.passphrase) {
	silc_free(channel->mode_data.passphrase);
	channel->mode_data.passphrase = NULL;
      }
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_BAN) {
    if (!(channel->mode & SILC_CHANNEL_MODE_BAN)) {
      /* Ban list is specified for channel */

      /* Get ban list */
      tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
      if (!tmp) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      /* XXX check that channel founder is not banned */

      /* Save the ban list */
      channel->mode_data.ban_list = strdup(tmp);
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_BAN) {
      /* Ban mode is unset. Remove the entire ban list */
      if (channel->mode_data.ban_list) {
	silc_free(channel->mode_data.ban_list);
	channel->mode_data.ban_list = NULL;
      }
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_INVITE_LIST) {
    if (!(channel->mode & SILC_CHANNEL_MODE_INVITE_LIST)) {
      /* Invite list is specified for channel */

      /* Get invite list */
      tmp = silc_argument_get_arg_type(cmd->args, 6, NULL);
      if (!tmp) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
				   SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      /* Save the invite linst */
      channel->mode_data.invite_list = strdup(tmp);
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_INVITE_LIST) {
      /* Invite list mode is unset. Remove the entire invite list */
      if (channel->mode_data.invite_list) {
	silc_free(channel->mode_data.invite_list);
	channel->mode_data.invite_list = NULL;
      }
    }
  }

  if (mode_mask & SILC_CHANNEL_MODE_CIPHER) {
    if (!(channel->mode & SILC_CHANNEL_MODE_CIPHER)) {
      /* Cipher to use protect the traffic */
      unsigned int key_len = 128;
      char *cp;

      /* Get cipher */
      tmp = silc_argument_get_arg_type(cmd->args, 8, NULL);
      if (!tmp) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					      SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      cp = strchr(tmp, ':');
      if (cp) {
	key_len = atoi(cp);
	*cp = '\0';
      }

      /* XXX Duplicated code, make own function for this!! */
    
      /* Delete old cipher and allocate the new one */
      silc_cipher_free(channel->channel_key);
      silc_cipher_alloc(tmp, &channel->channel_key);

      key_len /= 8;
      if (key_len > 32)
	key_len = 32;

      /* Re-generate channel key */
      silc_server_create_channel_key(server, channel, key_len);
    
      /* Encode channel key payload to be distributed on the channel */
      packet = 
	silc_channel_key_payload_encode(tmp_len2, tmp_id,
					strlen(channel->channel_key->
					       cipher->name),
					channel->channel_key->cipher->name,
					channel->key_len / 8, channel->key);
    
      /* If we are normal server then we will send it to our router.  If we
	 are router we will send it to all local servers that has clients on
	 the channel */
      if (server->server_type == SILC_SERVER) {
	if (!server->standalone)
	  silc_server_packet_send(server, 
				  cmd->server->router->connection,
				  SILC_PACKET_CHANNEL_KEY, 0, packet->data,
				  packet->len, TRUE);
      } else {
	
      }
    
      /* Send to locally connected clients on the channel */
      silc_server_packet_send_local_channel(server, channel, 
					    SILC_PACKET_CHANNEL_KEY, 0,
					  packet->data, packet->len, FALSE);
      silc_buffer_free(packet);
    }
  } else {
    if (channel->mode & SILC_CHANNEL_MODE_CIPHER) {
      /* Cipher mode is unset. Remove the cipher and revert back to 
	 default cipher */

      if (channel->mode_data.cipher) {
	silc_free(channel->mode_data.cipher);
	channel->mode_data.cipher = NULL;
	channel->mode_data.key_len = 0;
      }

      /* Generate new cipher and key for the channel */

      /* XXX Duplicated code, make own function for this!! */

      /* Delete old cipher and allocate default one */
      silc_cipher_free(channel->channel_key);
      if (!channel->cipher)
	silc_cipher_alloc("twofish", &channel->channel_key);
      else
	silc_cipher_alloc(channel->cipher, &channel->channel_key);

      /* Re-generate channel key */
      silc_server_create_channel_key(server, channel, 0);
      
      /* Encode channel key payload to be distributed on the channel */
      packet = 
	silc_channel_key_payload_encode(tmp_len2, tmp_id,
					strlen(channel->channel_key->
					       cipher->name),
					channel->channel_key->cipher->name,
					channel->key_len / 8, channel->key);
      
      /* If we are normal server then we will send it to our router.  If we
	 are router we will send it to all local servers that has clients on
	 the channel */
      if (server->server_type == SILC_SERVER) {
	if (!server->standalone)
	  silc_server_packet_send(server, 
				  cmd->server->router->connection,
				  SILC_PACKET_CHANNEL_KEY, 0, packet->data,
				  packet->len, TRUE);
      } else {
	
      }
      
      /* Send to locally connected clients on the channel */
      silc_server_packet_send_local_channel(server, channel, 
					    SILC_PACKET_CHANNEL_KEY, 0,
					    packet->data, packet->len, FALSE);
      silc_buffer_free(packet);
    }
  }

  /* Finally, set the mode */
  channel->mode = mode_mask;

  /* Send CMODE_CHANGE notify */
  cidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, NULL, channel, FALSE,
				     SILC_NOTIFY_TYPE_CMODE_CHANGE, 2,
				     cidp->data, cidp->len, 
				     tmp_mask, tmp_len);

  /* Set CMODE notify type to network */
  if (!server->standalone)
    silc_server_send_notify_cmode(server, server->router->connection,
				  server->server_type == SILC_ROUTER ? 
				  TRUE : FALSE, channel,
				  mode_mask, client->id, SILC_ID_CLIENT_LEN);

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CMODE,
						SILC_STATUS_OK, 0, 1,
						2, tmp_mask, 4);
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
  SilcChannelID *channel_id;
  SilcClientID *client_id;
  SilcChannelEntry channel;
  SilcClientEntry target_client;
  SilcChannelClientEntry chl;
  SilcBuffer packet, idp;
  unsigned char *tmp_id, *tmp_ch_id, *tmp_mask;
  unsigned int target_mask, sender_mask, tmp_len, tmp_ch_len;
  int notify = FALSE;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_CUMODE, cmd, 3, 3);

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
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Check that client has rights to change other's rights */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (chl->client == client) {
      if (!(chl->mode & SILC_CHANNEL_UMODE_CHANFO) &&
	  !(chl->mode & SILC_CHANNEL_UMODE_CHANOP)) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					      SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	goto out;
      }

      sender_mask = chl->mode;
      break;
    }
  }
  
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
						client_id, NULL);
  if (!target_client) {
    target_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, NULL);
  }

  /* Check whether target client is on the channel */
  if (!silc_server_client_on_channel(target_client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_USER_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get entry to the channel user list */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END)
    if (chl->client == target_client)
      break;

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
    /* Cannot promote anyone to channel founder */
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_YOU);
    goto out;
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
      chl->mode |= SILC_CHANNEL_UMODE_CHANOP;
      notify = TRUE;
    }
  } else {
    if (chl->mode & SILC_CHANNEL_UMODE_CHANOP) {
      /* Demote to normal user */
      chl->mode &= ~SILC_CHANNEL_UMODE_CHANOP;
      notify = TRUE;
    }
  }

  idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

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
				     SILC_ID_CLIENT_LEN,
				     target_client->id, 
				     SILC_ID_CLIENT_LEN);
  }

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CUMODE,
						SILC_STATUS_OK, 0, 2,
						2, tmp_mask, 4,
						3, tmp_id, tmp_len);
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
  unsigned int tmp_len;
  unsigned char *tmp, *comment;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_LEAVE, cmd, 1, 3);

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
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
  }

  /* Check whether sender is on the channel */
  if (!silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Check that the kicker is channel operator or channel founder */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (chl->client == client) {
      if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
					      SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	goto out;
      }
      break;
    }
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
						client_id, NULL);
  if (!target_client) {
    target_client = silc_idlist_find_client_by_id(server->global_list, 
						  client_id, NULL);
  }

  /* Check that the target client is not channel founder. Channel founder
     cannot be kicked from the channel. */
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    if (chl->client == target_client) {
      if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
	silc_server_command_send_status_reply(cmd, SILC_COMMAND_KICK,
				  SILC_STATUS_ERR_NO_CHANNEL_FOPRIV);
	goto out;
      }
      break;
    }
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
     after removing the client then the client kicked itself of the channel
     and we don't have to send anything after that. */
  if (!silc_server_remove_from_one_channel(server, NULL, channel, 
					   target_client, FALSE))
    goto out;

  /* Send KICKED notify to primary route */
  if (!server->standalone)
    silc_server_send_notify_kicked(server, server->router->connection,
				   server->server_type == SILC_ROUTER ?
				   TRUE : FALSE, channel,
				   target_client->id, SILC_ID_CLIENT_LEN,
				   comment);

  /* Re-generate channel key */
  silc_server_create_channel_key(server, channel, 0);

  /* Send the channel key to the channel. The key of course is not sent
     to the client who joined the channel. */
  silc_server_send_channel_key(server, target_client->connection, channel, 
			       server->server_type == SILC_ROUTER ? 
			       FALSE : server->standalone);

 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(oper)
{
}

SILC_SERVER_CMD_FUNC(silcoper)
{
}

/* Server side command of CONNECT. Connects us to the specified remote
   server or router. */

SILC_SERVER_CMD_FUNC(connect)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  unsigned char *tmp;
  unsigned int tmp_len;
  unsigned int port = SILC_PORT;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_CONNECT, cmd, 0, 0);

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
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CONNECT,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get port */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp)
    SILC_GET32_MSB(port, tmp);

  /* Create the connection. It is done with timeout and is async. */
  silc_server_create_connection(server, tmp, port);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CONNECT,
					SILC_STATUS_OK);

 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(restart)
{
}

/* Server side command of CLOSE. Closes connection to a specified server. */
 
SILC_SERVER_CMD_FUNC(close)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcServerEntry server_entry;
  unsigned char *tmp;
  unsigned int tmp_len;
  unsigned char *name;
  unsigned int port = SILC_PORT;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_CLOSE, cmd, 0, 0);

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
						 name, port, NULL);
  if (!server_entry) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CLOSE,
					  SILC_STATUS_ERR_NO_SERVER_ID);
    goto out;
  }

  /* Close the connection to the server */
  silc_server_free_sock_user_data(server, server_entry->connection);
  silc_server_disconnect_remote(server, server_entry->connection,
				"Server closed connection: "
				"Closed by operator");
  
  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_CLOSE,
					SILC_STATUS_OK);

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

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_SHUTDOWN, cmd, 0, 0);

  if (!client || cmd->sock->type != SILC_SOCKET_TYPE_CLIENT)
    goto out;

  /* Check whether client has the permission. */
  if (client->mode == SILC_UMODE_NONE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_SHUTDOWN,
					  SILC_STATUS_ERR_NO_SERVER_PRIV);
    goto out;
  }

  /* Then, gracefully, or not, bring the server down. */
  silc_server_stop(server);

  /* Send reply to the sender */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_SHUTDOWN,
					SILC_STATUS_OK);

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
  SilcChannelID *id;
  SilcChannelEntry channel;
  SilcBuffer packet;
  unsigned int i, len;
  unsigned char *tmp;

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_LEAVE, cmd, 1, 2);

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
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
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
				  TRUE : FALSE, channel, id_entry->id,
				  SILC_ID_CLIENT_LEN);

  /* Remove client from channel */
  i = silc_server_remove_from_one_channel(server, sock, channel, id_entry,
					  TRUE);
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					SILC_STATUS_OK);

  /* If the channel does not exist anymore we won't send anything */
  if (!i)
    goto out;

  /* Re-generate channel key */
  silc_server_create_channel_key(server, channel, 0);

  /* Encode channel key payload to be distributed on the channel */
  packet = 
    silc_channel_key_payload_encode(len, tmp,
				    strlen(channel->channel_key->cipher->name),
				    channel->channel_key->cipher->name,
				    channel->key_len / 8, channel->key);

  /* If we are normal server then we will send it to our router.  If we
     are router we will send it to all local servers that has clients on
     the channel */
  if (server->server_type == SILC_SERVER) {
    if (!server->standalone)
      silc_server_packet_send(server, 
			      cmd->server->router->connection,
			      SILC_PACKET_CHANNEL_KEY, 0, packet->data,
			      packet->len, FALSE);
  } else {

  }

  /* Send to locally connected clients on the channel */
  silc_server_packet_send_local_channel(server, channel, 
					SILC_PACKET_CHANNEL_KEY, 0,
					packet->data, packet->len, FALSE);

  silc_buffer_free(packet);
  silc_free(id);

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
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcChannelID *id;
  SilcBuffer packet;
  unsigned char *channel_id;
  unsigned int channel_id_len;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  SilcBuffer idp;
  unsigned char lc[4];
  unsigned int list_count = 0;
  unsigned short ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK_ARGC(SILC_COMMAND_USERS, cmd, 1, 1);

  /* Get Channel ID */
  channel_id = silc_argument_get_arg_type(cmd->args, 1, &channel_id_len);
  if (!channel_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  id = silc_id_payload_parse_id(channel_id, channel_id_len);
  if (!id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }

  /* If we are server and we don't know about this channel we will send
     the command to our router. If we know about the channel then we also
     have the list of users already. */
  channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
  if (!channel) {
    if (server->server_type == SILC_SERVER && !server->standalone &&
	!cmd->pending) {
      SilcBuffer tmpbuf;
      
      silc_command_set_ident(cmd->payload, silc_rng_get_rn16(server->rng));
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

    /* We are router and we will check the global list as well. */
    channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
    if (!channel) {
      /* Channel really does not exist */
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_USERS,
					    SILC_STATUS_ERR_NO_SUCH_CHANNEL);
      goto out;
    }
  }

  /* Assemble the lists now */

  client_id_list = silc_buffer_alloc((SILC_ID_CLIENT_LEN + 4) * 
				     silc_list_count(channel->user_list));
  silc_buffer_pull_tail(client_id_list, SILC_BUFFER_END(client_id_list));
  client_mode_list = 
    silc_buffer_alloc(4 * silc_list_count(channel->user_list));
  silc_buffer_pull_tail(client_mode_list, SILC_BUFFER_END(client_mode_list));

  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    /* Client ID */
    idp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
    silc_buffer_put(client_id_list, idp->data, idp->len);
    silc_buffer_pull(client_id_list, idp->len);
    silc_buffer_free(idp);

    /* Client's mode on channel */
    SILC_PUT32_MSB(chl->mode, client_mode_list->data);
    silc_buffer_pull(client_mode_list, 4);

    list_count++;
  }
  silc_buffer_push(client_id_list, 
		   client_id_list->data - client_id_list->head);
  silc_buffer_push(client_mode_list, 
		   client_mode_list->data - client_mode_list->head);

  /* List count */
  SILC_PUT32_MSB(list_count, lc);

  /* Send reply */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_USERS,
						SILC_STATUS_OK, 0, 4,
						2, channel_id, channel_id_len,
						3, lc, 4,
						4, client_id_list->data,
						client_id_list->len,
						5, client_mode_list->data,
						client_mode_list->len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);
  silc_free(id);

 out:
  silc_server_command_free(cmd);
}
