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
static void silc_server_command_free(SilcServerCommandContext cmd);

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
  SILC_SERVER_CMD(die, DIE, SILC_CF_LAG | SILC_CF_REG | SILC_CF_OPER),
  SILC_SERVER_CMD(silcoper, SILCOPER,
		  SILC_CF_LAG | SILC_CF_REG | SILC_CF_SILC_OPER),
  SILC_SERVER_CMD(leave, LEAVE, SILC_CF_LAG | SILC_CF_REG),
  SILC_SERVER_CMD(names, NAMES, SILC_CF_LAG | SILC_CF_REG),

  { NULL, 0 },
};

/* List of pending commands. */
SilcServerCommandPending *silc_command_pending = NULL;

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
      goto out;

    /* Allow only one command executed in 2 seconds. */
    curtime = time(NULL);
    if (client->last_command && (curtime - client->last_command) < 2)
      goto out;

    /* Update access time */
    client->last_command = curtime;
  }
#endif
  
  /* Allocate command context. This must be free'd by the
     command routine receiving it. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->server = server;
  ctx->sock = sock;
  ctx->packet = packet;	/* Save original packet */
  
  /* Parse the command payload in the packet */
  ctx->payload = silc_command_payload_parse(packet->buffer);
  if (!ctx->payload) {
    SILC_LOG_ERROR(("Bad command payload, packet dropped"));
    silc_buffer_free(packet->buffer);
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
    silc_free(ctx);
    goto out;
  }

 out:
  silc_buffer_free(packet->buffer);
}

/* Add new pending command to the list of pending commands. Currently
   pending commands are executed from command replies, thus we can
   execute any command after receiving some specific command reply.

   The argument `reply_cmd' is the command reply from where the callback
   function is to be called, thus, it IS NOT the command to be executed. */

void silc_server_command_pending(SilcCommand reply_cmd,
				 SilcCommandCb callback,
				 void *context)
{
  SilcServerCommandPending *reply, *r;

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

void silc_server_command_pending_del(SilcCommand reply_cmd)
{
  SilcServerCommandPending *r, *tmp;
  
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

/* Free's the command context allocated before executing the command */

static void silc_server_command_free(SilcServerCommandContext cmd)
{
  if (cmd) {
    silc_command_free_payload(cmd->payload);
    silc_free(cmd);
  }
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

/* Server side of command WHOIS. Processes user's query and sends found 
   results as command replies back to the client. */

SILC_SERVER_CMD_FUNC(whois)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  char *tmp, *nick = NULL, *server_name = NULL;
  unsigned int i, argc, count = 0, len, clients_count;
  int use_id = FALSE;
  SilcClientID *client_id = NULL;
  SilcBuffer packet, idp;
  SilcClientEntry *clients = NULL, entry;
  SilcCommandStatus status;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOIS,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 3) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOIS,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* If client ID is in the command it must be used instead of nickname */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp) {

    /* No ID, get the nickname@server string and parse it. */
    tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
    if (tmp) {
      if (strchr(tmp, '@')) {
	len = strcspn(tmp, "@");
	nick = silc_calloc(len + 1, sizeof(char));
	memcpy(nick, tmp, len);
	server_name = silc_calloc(strlen(tmp) - len, sizeof(char));
	memcpy(server_name, tmp + len + 1, strlen(tmp) - len - 1);
      } else {
	nick = strdup(tmp);
      }
    } else {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOIS,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }
  } else {
    /* Command includes ID, use that */
    client_id = silc_id_payload_parse_id(tmp, len);
    use_id = TRUE;
  }

  /* Get the max count of reply messages allowed */
  if (argc == 3) {
    tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (!tmp) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOIS,
					    SILC_STATUS_ERR_TOO_MANY_PARAMS);
      if (nick)
	silc_free(nick);
      if (server_name)
	silc_free(server_name);
      goto out;
    }
    count = atoi(tmp);
  }

  /* Get all clients matching that nickname */
  if (!use_id) {
    clients = silc_idlist_get_clients_by_nickname(server->local_list, 
						  nick, server_name,
						  &clients_count);
  } else {
    entry = silc_idlist_find_client_by_id(server->local_list, client_id);
    if (entry) {
      clients = silc_calloc(1, sizeof(*clients));
      clients[0] = entry;
      clients_count = 1;
    }
  }

  if (!clients) {
    
    /* If we are normal server and are connected to a router we will
       make global query from the router. */
    if (server->server_type == SILC_SERVER && !server->standalone) {

      goto ok;
    }
    
    /* If we are router then we will check our global list as well. */
    if (server->server_type == SILC_ROUTER) {
      entry =
	silc_idlist_find_client_by_nickname(server->global_list,
					    nick, server_name);
      if (!entry) {
	silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					     SILC_STATUS_ERR_NO_SUCH_NICK,
					     3, tmp, strlen(tmp));
	goto out;
      }
      goto ok;
    }

    silc_server_command_send_status_data(cmd, SILC_COMMAND_WHOIS,
					 SILC_STATUS_ERR_NO_SUCH_NICK,
					 3, tmp, strlen(tmp));
    goto out;
  }

 ok:

  /* XXX, works only for local server info */

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

    /* Send WHOIS reply */
    idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
    tmp = silc_argument_get_first_arg(cmd->args, NULL);
    
    /* XXX */
    if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
      char nh[256], uh[256];
      unsigned char idle[4];
      SilcSocketConnection hsock;

      memset(uh, 0, sizeof(uh));
      memset(nh, 0, sizeof(nh));
      
      strncat(nh, entry->nickname, strlen(entry->nickname));
      strncat(nh, "@", 1);
      len = entry->router ? strlen(entry->router->server_name) :
	strlen(server->server_name);
      strncat(nh, entry->router ? entry->router->server_name :
	      server->server_name, len);
      
      strncat(uh, entry->username, strlen(entry->username));
      strncat(uh, "@", 1);
      hsock = (SilcSocketConnection)entry->connection;
      len = hsock->hostname ? strlen(hsock->hostname) : strlen(hsock->ip);
      strncat(uh, hsock->hostname ? hsock->hostname : hsock->ip, len);
      
      SILC_PUT32_MSB((time(NULL) - entry->data.last_receive), idle);
      
      /* XXX */
      if (entry->userinfo)
	packet = 
	  silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					       status, 0, 5, 
					       2, idp->data, idp->len,
					       3, nh, strlen(nh),
					       4, uh, strlen(uh),
					       5, entry->userinfo, 
					       strlen(entry->userinfo),
					       7, idle, 4);
      else
	packet = 
	  silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					       status, 0, 4, 
					       2, idp->data, idp->len,
					       3, nh, strlen(nh),
					       4, uh, strlen(uh),
					       7, idle, 4);
      
    } else {
      /* XXX */
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS, 
					     status, 0, 3, 
					     2, idp->data, idp->len,
					     3, entry->nickname, 
					     strlen(entry->nickname),
					     4, tmp, strlen(tmp)); /* XXX */
    }
    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			    0, packet->data, packet->len, FALSE);
    
    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

  silc_free(clients);

  if (client_id)
    silc_free(client_id);

 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(whowas)
{
}

SILC_SERVER_CMD_FUNC(identify)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  char *tmp, *nick = NULL, *server_name = NULL;
  unsigned int argc, count = 0, len;
  int use_id = FALSE;
  SilcClientID *client_id = NULL;
  SilcClientEntry entry;
  SilcBuffer packet, idp;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 3) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* If client ID is in the command it must be used instead of nickname */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp) {

    /* Get the nickname@server string and parse it. */
    tmp = silc_argument_get_arg_type(cmd->args, 1, NULL);
    if (tmp) {
      if (strchr(tmp, '@')) {
	len = strcspn(tmp, "@");
	nick = silc_calloc(len + 1, sizeof(char));
	memcpy(nick, tmp, len);
	server_name = silc_calloc(strlen(tmp) - len, sizeof(char));
	memcpy(server_name, tmp + len + 1, strlen(tmp) - len - 1);
      } else {
	nick = strdup(tmp);
      }
    } else {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					    SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }
  } else {
    /* Command includes ID, use that */
    client_id = silc_id_payload_parse_id(tmp, len);
    use_id = TRUE;
  }

  /* Get the max count of reply messages allowed */
  if (argc == 3) {
    tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (!tmp) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					    SILC_STATUS_ERR_TOO_MANY_PARAMS);
      goto out;
    }
    count = atoi(tmp);
  }

  /* Find client */
  if (!use_id) {
    entry = silc_idlist_find_client_by_nickname(server->local_list,
						nick, NULL);
    if (!entry)
      entry = silc_idlist_find_client_by_hash(server->global_list,
					      nick, server->md5hash);
  } else {
    entry = silc_idlist_find_client_by_id(server->local_list, client_id);
  }

  /* If client was not found and if we are normal server and are connected
     to a router we will make global query from the router. */
  if (!entry && server->server_type == SILC_SERVER && !server->standalone &&
      !cmd->pending) {
    SilcBuffer buffer = cmd->packet->buffer;
    
    SILC_LOG_DEBUG(("Requesting identify from router"));
    
    /* Send IDENTIFY command to our router */
    silc_buffer_push(buffer, buffer->data - buffer->head);
    silc_server_packet_forward(server, (SilcSocketConnection)
			       server->id_entry->router->connection,
			       buffer->data, buffer->len, TRUE);
    return;
  }

  /* If we are router we have checked our local list by nickname and our
     global list by hash so far. It is possible that the client is still not
     found and we'll check it from local list by hash. */
  if (!entry && server->server_type == SILC_ROUTER)
    entry = silc_idlist_find_client_by_hash(server->local_list,
					    nick, server->md5hash);

  if (!entry) {
    /* The client definitely does not exist */
    silc_server_command_send_status_data(cmd, SILC_COMMAND_IDENTIFY,
					 SILC_STATUS_ERR_NO_SUCH_NICK,
					 3, tmp, strlen(tmp));
    goto out;
  }

  /* Send IDENTIFY reply */
  idp = silc_id_payload_encode(entry->id, SILC_ID_CLIENT);
  tmp = silc_argument_get_first_arg(cmd->args, NULL);
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_IDENTIFY,
						SILC_STATUS_OK, 0, 2,
						2, idp->data, idp->len, 
						3, nick, strlen(nick));
  if (cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED) {
    void *id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_type);
    silc_server_packet_send_dest(server, cmd->sock, 
				 SILC_PACKET_COMMAND_REPLY, 0,
				 id, cmd->packet->src_id_type,
				 packet->data, packet->len, FALSE);
    silc_free(id);
  } else {
    silc_server_packet_send(server, cmd->sock, 
			    SILC_PACKET_COMMAND_REPLY, 0, 
			    packet->data, packet->len, FALSE);
  }

  silc_buffer_free(packet);
  silc_buffer_free(idp);
  if (client_id)
    silc_free(client_id);

 out:
  if (nick)
    silc_free(nick);
  if (server_name)
    silc_free(server_name);
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

  SILC_LOG_DEBUG(("Start"));

  /* Check number of arguments */
  if (silc_argument_get_arg_num(cmd->args) < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

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
     ID and ask to replace it with the old one. */
  if (cmd->server->server_type == SILC_SERVER && !cmd->server->standalone)
    silc_server_send_replace_id(server, server->id_entry->router->connection, 
				FALSE, client->id,
				SILC_ID_CLIENT, SILC_ID_CLIENT_LEN,
				new_id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);

  /* If we are router we have to distribute the new Client ID to all 
     routers in SILC. */
  if (cmd->server->server_type == SILC_ROUTER && !cmd->server->standalone)
    silc_server_send_replace_id(server, server->id_entry->router->connection,  
				TRUE, client->id,
				SILC_ID_CLIENT, SILC_ID_CLIENT_LEN,
				new_id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);

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

  /* Send NICK_CHANGE notify */
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

  /* Check number of arguments */
  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len);

  /* Check whether the channel exists */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
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
    while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
      if (chl->client == client) {
	if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
	  silc_server_command_send_status_reply(cmd, SILC_COMMAND_TOPIC,
						SILC_STATUS_ERR_NO_CHANNEL_PRIV);
	  goto out;
	} else {
	  break;
	}
      }
    }

    /* Set the topic for channel */
    if (channel->topic)
      silc_free(channel->topic);
    channel->topic = strdup(tmp);

    idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);

    /* Send notify about topic change to all clients on the channel */
    silc_server_send_notify_to_channel(server, channel,
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
  unsigned int argc, len;

  /* Check number of arguments */
  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get destination ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }
  dest_id = silc_id_payload_parse_id(tmp, len);

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, len);

  /* Check whether the channel exists */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
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
  dest = silc_idlist_find_client_by_id(server->local_list, dest_id);
  if (dest)
    dest_sock = (SilcSocketConnection)dest->connection;
  else
    dest_sock = silc_server_get_route(server, dest_id, SILC_ID_CLIENT);

  /* Check whether the requested client is already on the channel. */
  /* XXX if we are normal server we don't know about global clients on
     the channel thus we must request it (NAMES command), check from
     local cache as well. */
  if (silc_server_client_on_channel(dest, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_USER_ON_CHANNEL);
    goto out;
  }

  sidp = silc_id_payload_encode(sender->id, SILC_ID_CLIENT);

  /* Send notify to the client that is invited to the channel */
  silc_server_send_notify_dest(server, dest_sock, dest_id, SILC_ID_CLIENT,
			       SILC_NOTIFY_TYPE_INVITE, 2, 
			       sidp->data, sidp->len, tmp, len);

  /* Send command reply */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					SILC_STATUS_OK);

  silc_buffer_free(sidp);

 out:
  silc_server_command_free(cmd);
}

/* Quits connection to client. This gets called if client won't
   close the connection even when it has issued QUIT command. */

SILC_TASK_CALLBACK(silc_server_command_quit_cb)
{
  SilcServer server = (SilcServer)context;
  SilcSocketConnection sock = server->sockets[fd];

  /* Free all client specific data, such as client entry and entires
     on channels this client may be on. */
  silc_server_free_sock_user_data(server, sock);

  /* Close the connection on our side */
  silc_server_close_connection(server, sock);
}

/* Quits SILC session. This is the normal way to disconnect client. */
 
SILC_SERVER_CMD_FUNC(quit)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;

  SILC_LOG_DEBUG(("Start"));

  /* We quit the connection with little timeout */
  silc_task_register(server->timeout_queue, sock->sock,
		     silc_server_command_quit_cb, server,
		     0, 300000, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);

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
  unsigned int argc;
  char info_string[256], *dest_server;

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INFO,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

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

SILC_SERVER_CMD_FUNC(connect)
{
}

/* Server side of command PING. This just replies to the ping. */

SILC_SERVER_CMD_FUNC(ping)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcServerID *id;
  unsigned int argc, len;
  unsigned char *tmp;

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NO_SERVER_ID);
    goto out;
  }
  id = silc_id_payload_parse_id(tmp, len);

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

SILC_SERVER_CMD_FUNC(oper)
{
}

typedef struct {
  char *channel_name;
  char *nickname;
  char *username;
  char *hostname;
  SilcChannelEntry channel;
  SilcServer server;
  SilcClientEntry client;
} JoinInternalContext;

SILC_TASK_CALLBACK(silc_server_command_join_notify)
{
  JoinInternalContext *ctx = (JoinInternalContext *)context;

  if (ctx->channel->key && ctx->channel->key_len) {
    SilcBuffer clidp;

    clidp = silc_id_payload_encode(ctx->client->id, SILC_ID_CLIENT);

    silc_server_send_notify_to_channel(ctx->server, ctx->channel,
				       SILC_NOTIFY_TYPE_JOIN, 1,
				       clidp->data, clidp->len);

    silc_buffer_free(clidp);
    silc_free(ctx);
  } else {
    silc_task_register(ctx->server->timeout_queue, fd,
		       silc_server_command_join_notify, context,
		       0, 300000, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
  }
}

/* Assembles NAMES command and executes it. This is called when client
   joins to a channel and we wan't to send NAMES command reply to the 
   client. */

void silc_server_command_send_names(SilcServer server,
				    SilcSocketConnection sock,
				    SilcChannelEntry channel)
{
  SilcServerCommandContext cmd;
  SilcBuffer buffer, idp;

  idp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_NAMES, 0, 1,
					  1, idp->data, idp->len);

  cmd = silc_calloc(1, sizeof(*cmd));
  cmd->payload = silc_command_payload_parse(buffer);
  cmd->args = silc_command_get_args(cmd->payload);
  cmd->server = server;
  cmd->sock = sock;
  cmd->pending = FALSE;

  silc_server_command_names((void *)cmd);
  silc_free(buffer);
  silc_free(idp);
}

/* Server side of command JOIN. Joins client into requested channel. If 
   the channel does not exist it will be created. */

SILC_SERVER_CMD_FUNC(join)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;
  SilcBuffer buffer = cmd->packet->buffer;
  int argc, i, k, tmp_len;
  char *tmp, *channel_name = NULL, *cipher = NULL;
  unsigned char *passphrase = NULL, mode[4];
  unsigned int umode = 0;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcServerID *router_id;
  SilcBuffer packet, idp;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  /* Check number of parameters */
  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 3) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

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

  /* Get passphrase */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (tmp) {
    passphrase = silc_calloc(tmp_len, sizeof(*passphrase));
    memcpy(passphrase, tmp, tmp_len);
  }
  
  /* Get cipher name */
  cipher = silc_argument_get_arg_type(cmd->args, 3, NULL);

  /* See if the channel exists */
  channel = 
    silc_idlist_find_channel_by_name(server->local_list, channel_name);
  if (!channel) {
    /* Channel not found */

    /* If we are standalone server we don't have a router, we just create 
       the channel by  ourselves. */
    if (server->standalone) {
      router_id = server->id;
      channel = silc_server_new_channel(server, router_id, cipher, 
					channel_name);
      umode |= SILC_CHANNEL_UMODE_CHANOP;
      umode |= SILC_CHANNEL_UMODE_CHANFO;
      if (!channel)
	goto out;

      goto join_channel;
    }

    /* No channel ID found, the channel does not exist on our server.
       We send JOIN command to our router which will handle the joining
       procedure (either creates the channel if it doesn't exist or
       joins the client to it) - if we are normal server. */
    if (server->server_type == SILC_SERVER) {

      /* Forward the original JOIN command to the router */
      silc_buffer_push(buffer, buffer->data - buffer->head);
      silc_server_packet_forward(server, (SilcSocketConnection)
				 server->id_entry->router->connection,
				 buffer->data, buffer->len, TRUE);
      
      /* Add the command to be pending. It will be re-executed after
	 router has replied back to us. */
      cmd->pending = TRUE;
      silc_server_command_pending(SILC_COMMAND_JOIN, 
				  silc_server_command_join, context);
      return;
    }
  }

  /* If we are router and the channel does not exist we will check our
     global list for the channel. */
  if (!channel && server->server_type == SILC_ROUTER) {

    /* Notify all routers about the new channel in SILC network. */
    if (!server->standalone) {
#if 0
      silc_server_send_new_id(server, server->id_entry->router->connection, 
			      TRUE,
			      xxx, SILC_ID_CHANNEL, SILC_ID_CHANNEL_LEN);
#endif
    }

  }

 join_channel:

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

  /* If the JOIN request was forwarded to us we will make a bit slower
     query to get the client pointer. Otherwise, we get the client pointer
     real easy. */
  if (!(cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED)) {
    client = (SilcClientEntry)sock->user_data;
  } else {
    void *id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_type);
    client = silc_idlist_find_client_by_id(server->local_list, id);
    if (!client) {
      /* XXX */
      goto out;
    }
    silc_free(id);
  }

  /* Check whether the client already is on the channel */
  if (silc_server_client_on_channel(client, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_USER_ON_CHANNEL);
    goto out;
  }

  /* Join the client to the channel by adding it to channel's user list.
     Add also the channel to client entry's channels list for fast cross-
     referencing. */
  chl = silc_calloc(1, sizeof(*chl));
  chl->mode = umode;
  chl->client = client;
  chl->channel = channel;
  silc_list_add(channel->user_list, chl);
  silc_list_add(client->channels, chl);

  /* Notify router about new user on channel. If we are normal server
     we send it to our router, if we are router we send it to our
     primary route. */
  if (!server->standalone) {

  }

  /* Send command reply to the client. Client receives the Channe ID,
     channel mode and possibly other information in this reply packet. */
  if (!cmd->pending) {
    idp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
    SILC_PUT32_MSB(channel->mode, mode);

    if (!channel->topic)
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					     SILC_STATUS_OK, 0, 3,
					     2, channel_name, 
					     strlen(channel_name),
					     3, idp->data, idp->len,
					     4, mode, 4);
    else
      packet = 
	silc_command_reply_payload_encode_va(SILC_COMMAND_JOIN,
					     SILC_STATUS_OK, 0, 4, 
					     2, channel_name, 
					     strlen(channel_name),
					     3, idp->data, idp->len,
					     4, mode, 4,
					     5, channel->topic, 
					     strlen(channel->topic));

    if (cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED) {
      void *id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_type);
      silc_server_packet_send_dest(cmd->server, cmd->sock, 
				   SILC_PACKET_COMMAND_REPLY, 0,
				   id, cmd->packet->src_id_type,
				   packet->data, packet->len, FALSE);
      silc_free(id);
    } else
      silc_server_packet_send(server, sock, SILC_PACKET_COMMAND_REPLY, 0, 
			      packet->data, packet->len, FALSE);
    silc_buffer_free(packet);

    /* Send channel key to the client. Client cannot start transmitting
       to the channel until we have sent the key. */
    tmp_len = strlen(channel->channel_key->cipher->name);
    packet = 
      silc_channel_key_payload_encode(idp->len, idp->data, 
				      strlen(channel->channel_key->
					     cipher->name),
				      channel->channel_key->cipher->name,
				      channel->key_len / 8, channel->key);
    
    silc_server_packet_send(server, sock, SILC_PACKET_CHANNEL_KEY, 0, 
			    packet->data, packet->len, FALSE);

    silc_buffer_free(packet);
    silc_buffer_free(idp);
  }

  /* Finally, send notify message to all clients on the channel about
     new user on the channel. */
  if (!(cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED)) {
    if (!cmd->pending) {
      SilcBuffer clidp;

      clidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
      
      silc_server_send_notify_to_channel(server, channel,
					 SILC_NOTIFY_TYPE_JOIN, 1,
					 clidp->data, clidp->len);
      
      silc_buffer_free(clidp);
    } else {
      /* This is pending command request. Send the notify after we have
	 received the key for the channel from the router. */
      JoinInternalContext *ctx = silc_calloc(1, sizeof(*ctx));
      ctx->channel_name = channel_name;
      ctx->nickname = client->nickname;
      ctx->username = client->username;
      ctx->hostname = sock->hostname ? sock->hostname : sock->ip;
      ctx->channel = channel;
      ctx->server = server;
      ctx->client = client;
      silc_task_register(server->timeout_queue, sock->sock,
			 silc_server_command_join_notify, ctx,
			 0, 10000, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
    }
  }

  /* Send NAMES command reply to the joined channel so the user sees who
     is currently on the channel. */
  silc_server_command_send_names(server, sock, channel);

 out:
  silc_server_command_free(cmd);
}

/* Server side of command MOTD. Sends server's current "message of the
   day" to the client. */

SILC_SERVER_CMD_FUNC(motd)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  unsigned int argc;
  char *motd;
  int motd_len;
  
  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

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
    if (channel->mode & SILC_CHANNEL_MODE_PRIVATE) {
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
  SilcSocketConnection sock = cmd->sock;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcChannelID *channel_id;
  SilcClientID *client_id;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcBuffer packet, cidp;
  unsigned char *tmp, *tmp_id, *tmp_mask;
  unsigned int argc, mode_mask, tmp_len, tmp_len2;
  int i;

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

  /* Get the channel mode mask */
  tmp_mask = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp_mask) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(mode_mask, tmp_mask);

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
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
      unsigned int key_len;
      unsigned char channel_key[32];

      /* XXX Duplicated code, make own function for this!! LEAVE uses this
	 as well */

      /* Re-generate channel key */
      key_len = channel->key_len / 8;
      for (i = 0; i < key_len; i++)
	channel_key[i] = silc_rng_get_byte(server->rng);
      channel->channel_key->cipher->set_key(channel->channel_key->context, 
					    channel_key, key_len);
      memset(channel->key, 0, key_len);
      silc_free(channel->key);
      channel->key = silc_calloc(key_len, sizeof(*channel->key));
      memcpy(channel->key, channel_key, key_len);
      memset(channel_key, 0, sizeof(channel_key));
      
      /* Encode channel key payload to be distributed on the channel */
      packet = 
	silc_channel_key_payload_encode(tmp_len2, tmp_id,
					strlen(channel->channel_key->
					       cipher->name),
					channel->channel_key->cipher->name,
					key_len, channel->key);
      
      /* If we are normal server then we will send it to our router.  If we
	 are router we will send it to all local servers that has clients on
	 the channel */
      if (server->server_type == SILC_SERVER) {
	if (!server->standalone)
	  silc_server_packet_send(server, 
				  cmd->server->id_entry->router->connection,
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
      unsigned char channel_key[32];
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

      /* Re-generate channel key */
      key_len /= 8;
      if (key_len > sizeof(channel_key))
	key_len = sizeof(channel_key);

      for (i = 0; i < key_len; i++)
	channel_key[i] = silc_rng_get_byte(server->rng);
      channel->channel_key->cipher->set_key(channel->channel_key->context, 
					    channel_key, key_len);
      memset(channel->key, 0, key_len);
      silc_free(channel->key);
      channel->key = silc_calloc(key_len, sizeof(*channel->key));
      memcpy(channel->key, channel_key, key_len);
      memset(channel_key, 0, sizeof(channel_key));
    
      /* Encode channel key payload to be distributed on the channel */
      packet = 
	silc_channel_key_payload_encode(tmp_len2, tmp_id,
					strlen(channel->channel_key->
					       cipher->name),
					channel->channel_key->cipher->name,
					key_len, channel->key);
    
      /* If we are normal server then we will send it to our router.  If we
	 are router we will send it to all local servers that has clients on
	 the channel */
      if (server->server_type == SILC_SERVER) {
	if (!server->standalone)
	  silc_server_packet_send(server, 
				  cmd->server->id_entry->router->connection,
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
      unsigned int key_len;
      unsigned char channel_key[32];

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
      key_len = channel->key_len / 8;
      for (i = 0; i < key_len; i++)
	channel_key[i] = silc_rng_get_byte(server->rng);
      channel->channel_key->cipher->set_key(channel->channel_key->context, 
					    channel_key, key_len);
      memset(channel->key, 0, key_len);
      silc_free(channel->key);
      channel->key = silc_calloc(key_len, sizeof(*channel->key));
      memcpy(channel->key, channel_key, key_len);
      memset(channel_key, 0, sizeof(channel_key));
      
      /* Encode channel key payload to be distributed on the channel */
      packet = 
	silc_channel_key_payload_encode(tmp_len2, tmp_id,
					strlen(channel->channel_key->
					       cipher->name),
					channel->channel_key->cipher->name,
					key_len, channel->key);
      
      /* If we are normal server then we will send it to our router.  If we
	 are router we will send it to all local servers that has clients on
	 the channel */
      if (server->server_type == SILC_SERVER) {
	if (!server->standalone)
	  silc_server_packet_send(server, 
				  cmd->server->id_entry->router->connection,
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
  silc_server_send_notify_to_channel(server, channel, 
				     SILC_NOTIFY_TYPE_CMODE_CHANGE, 2,
				     cidp->data, cidp->len, 
				     tmp_mask, tmp_len);
  silc_free(cidp);

  /* Send command reply to sender */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_CMODE,
						SILC_STATUS_OK, 0, 1,
						2, tmp_mask, 4);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_free(channel_id);

 out:
  silc_server_command_free(cmd);
}

/* Server side of CUMODE command. Changes client's mode on a channel. */

SILC_SERVER_CMD_FUNC(cumode)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;
  SilcChannelID *channel_id;
  SilcClientID *client_id;
  SilcChannelEntry channel;
  SilcClientEntry target_client;
  SilcChannelClientEntry chl;
  SilcBuffer packet, idp;
  unsigned char *tmp, *tmp_id, *tmp_mask;
  unsigned int argc, target_mask, sender_mask, tmp_len;
  int i, notify = FALSE;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 3) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 3) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get Channel ID */
  tmp_id = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp_id) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_CUMODE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp_id, tmp_len);

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
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
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  client_id = silc_id_payload_parse_id(tmp_id, tmp_len);

  /* Get target client's entry */
  target_client = silc_idlist_find_client_by_id(server->local_list, client_id);
  if (!client) {
    /* XXX If target client is not one of mine send to primary route */
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

  /* Send notify to channel, notify only if mode was actually changed. */
  if (notify) {
    idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    silc_server_send_notify_to_channel(server, channel,
				       SILC_NOTIFY_TYPE_CUMODE_CHANGE, 3,
				       idp->data, idp->len,
				       tmp_mask, 4, tmp_id, tmp_len);
    silc_buffer_free(idp);
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

 out:
  silc_server_command_free(cmd);
}

/* Server side of KICK command. Kicks client out of channel. */

SILC_SERVER_CMD_FUNC(kick)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;
  SilcClientEntry client = (SilcClientEntry)cmd->sock->user_data;

}

SILC_SERVER_CMD_FUNC(restart)
{
}
 
SILC_SERVER_CMD_FUNC(close)
{
}
 
SILC_SERVER_CMD_FUNC(die)
{
}
 
SILC_SERVER_CMD_FUNC(silcoper)
{
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
  unsigned int i, argc, key_len, len;
  unsigned char *tmp, channel_key[32];

  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  id = silc_id_payload_parse_id(tmp, len);

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, id);
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
     of clients on the channel. */
  if (!server->standalone)
    silc_server_send_remove_channel_user(server, 
					 server->id_entry->router->connection,
					 server->server_type == SILC_ROUTER ?
					 TRUE : FALSE, id_entry->id, id);

  /* Remove client from channel */
  i = silc_server_remove_from_one_channel(server, sock, channel, id_entry,
					  TRUE);
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					SILC_STATUS_OK);

  /* If the channel does not exist anymore we won't send anything */
  if (!i)
    goto out;

  /* Re-generate channel key */
  key_len = channel->key_len / 8;
  for (i = 0; i < key_len; i++)
    channel_key[i] = silc_rng_get_byte(server->rng);
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					channel_key, key_len);
  memset(channel->key, 0, key_len);
  silc_free(channel->key);
  channel->key = silc_calloc(key_len, sizeof(*channel->key));
  memcpy(channel->key, channel_key, key_len);
  memset(channel_key, 0, sizeof(channel_key));

  /* Encode channel key payload to be distributed on the channel */
  packet = 
    silc_channel_key_payload_encode(len, tmp,
				    strlen(channel->channel_key->cipher->name),
				    channel->channel_key->cipher->name,
				    key_len, channel->key);

  /* If we are normal server then we will send it to our router.  If we
     are router we will send it to all local servers that has clients on
     the channel */
  if (server->server_type == SILC_SERVER) {
    if (!server->standalone)
      silc_server_packet_send(server, 
			      cmd->server->id_entry->router->connection,
			      SILC_PACKET_CHANNEL_KEY, 0, packet->data,
			      packet->len, TRUE);
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

/* Server side of command NAMES. Resolves clients and their names currently
   joined on the requested channel. The name list is sent back to the
   client. */

SILC_SERVER_CMD_FUNC(names)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcChannelID *id;
  SilcBuffer packet;
  unsigned int i, len, len2, tmp_len, argc;
  unsigned char *tmp;
  char *name_list = NULL, *n;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NAMES,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NAMES,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  id = silc_id_payload_parse_id(tmp, tmp_len);

  /* Check whether the channel exists. If we are normal server and the
     channel does not exist we will send this same command to our router
     which will know if the channel exists. */
  channel = silc_idlist_find_channel_by_id(server->local_list, id);
  if (!channel) {
    if (server->server_type == SILC_SERVER && !server->standalone) {
      /* XXX Send names command */

      cmd->pending = TRUE;
      silc_server_command_pending(SILC_COMMAND_NAMES, 
				  silc_server_command_names, context);
      return;
    }

    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
  }

  /* Assemble the name list now */
  name_list = NULL;
  len = 0;
  silc_list_start(channel->user_list);
  i = 0;
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    n = chl->client->nickname;
    if (n) {
      len2 = strlen(n);
      len += len2;
      name_list = silc_realloc(name_list, sizeof(*name_list) * (len + 1));
      memcpy(name_list + (len - len2), n, len2);
      name_list[len] = 0;

      if (i == silc_list_count(channel->user_list) - 1)
	break;
      memcpy(name_list + len, ",", 1);
      len++;
      i++;
    }
  }
  if (!name_list)
    name_list = "";

  /* Assemble the Client ID list now */
  client_id_list = silc_buffer_alloc((SILC_ID_CLIENT_LEN + 4) * 
				     silc_list_count(channel->user_list));
  silc_buffer_pull_tail(client_id_list, SILC_BUFFER_END(client_id_list));
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    SilcBuffer idp;

    idp = silc_id_payload_encode(chl->client->id, SILC_ID_CLIENT);
    silc_buffer_format(client_id_list,
		       SILC_STR_UI_XNSTRING(idp->data, idp->len),
		       SILC_STR_END);
    silc_buffer_pull(client_id_list, idp->len);
    silc_buffer_free(idp);
  }
  silc_buffer_push(client_id_list, 
		   client_id_list->data - client_id_list->head);

  /* Assemble mode list */
  client_mode_list = silc_buffer_alloc(4 * 
				       silc_list_count(channel->user_list));
  silc_buffer_pull_tail(client_mode_list, SILC_BUFFER_END(client_mode_list));
  silc_list_start(channel->user_list);
  while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
    SILC_PUT32_MSB(chl->mode, client_mode_list->data);
    silc_buffer_pull(client_mode_list, 4);
  }
  silc_buffer_push(client_mode_list, 
		   client_mode_list->data - client_mode_list->head);

  /* Send reply */
  packet = silc_command_reply_payload_encode_va(SILC_COMMAND_NAMES,
						SILC_STATUS_OK, 0, 4,
						2, tmp, tmp_len,
						3, name_list, 
						strlen(name_list),
						4, client_id_list->data,
						client_id_list->len,
						5, client_mode_list->data,
						client_mode_list->len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_free(name_list);
  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);
  silc_free(id);

 out:
  silc_server_command_free(cmd);
}
