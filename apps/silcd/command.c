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
 * Revision 1.14  2000/09/29 07:13:04  priikone
 * 	Added support for notify type sending in notify payload.
 * 	Removed Log headers from the file.
 * 	Enabled debug messages by default for server.
 *
 * Revision 1.13  2000/08/21 14:21:21  priikone
 * 	Fixed channel joining and channel message sending inside a
 * 	SILC cell. Added silc_server_send_remove_channel_user and
 * 	silc_server_remove_channel_user functions.
 *
 * Revision 1.12  2000/07/26 07:05:11  priikone
 * 	Fixed the server to server (server to router actually) connections
 * 	and made the private message work inside a cell. Added functin
 * 	silc_server_replace_id.
 *
 * Revision 1.11  2000/07/19 07:08:09  priikone
 * 	Added version detection support to SKE.
 *
 * Revision 1.10  2000/07/17 11:47:30  priikone
 * 	Added command lagging support. Added idle counting support.
 *
 * Revision 1.9  2000/07/12 05:59:41  priikone
 * 	Major rewrite of ID Cache system. Support added for the new
 * 	ID cache system. Major rewrite of ID List stuff on server.  All
 * 	SilcXXXList's are now called SilcXXXEntry's and they are pointers
 * 	by default. A lot rewritten ID list functions.
 *
 * Revision 1.8  2000/07/10 05:42:59  priikone
 * 	Removed command packet processing from server.c and added it to
 * 	command.c.
 * 	Implemented INFO command. Added support for testing that
 * 	connections are registered before executing commands.
 *
 * Revision 1.7  2000/07/07 06:55:24  priikone
 * 	Do not allow client to join twice on same channel.
 *
 * Revision 1.6  2000/07/06 10:20:59  priikone
 * 	Cipher name in joining is not mandatory, removed check.
 *
 * Revision 1.5  2000/07/06 07:16:43  priikone
 * 	Fixed a wrong way of sending command replies. The fixed way
 * 	does comply with the protocol.
 *
 * Revision 1.4  2000/07/05 06:13:38  priikone
 * 	Added PING, INVITE and NAMES command.
 *
 * Revision 1.3  2000/07/03 05:52:22  priikone
 * 	Implemented LEAVE command.
 *
 * Revision 1.2  2000/06/28 05:06:38  priikone
 * 	Shorter timeout for channel joining notify.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

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
  switch(sock->type) {
  case SILC_SOCKET_TYPE_CLIENT:
    {
      SilcClientEntry client = (SilcClientEntry)sock->user_data;
      if (client->registered)
	return TRUE;
      break;
    }
  case SILC_SOCKET_TYPE_SERVER:
  case SILC_SOCKET_TYPE_ROUTER:
    {
      SilcServerEntry serv = (SilcServerEntry)sock->user_data;
      if (serv->registered)
	return TRUE;
      break;
    }
  default:
    break;
  }

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
  
  /* Allocate command context. This must be free'd by the
     command routine receiving it. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->server = server;
  ctx->sock = sock;
  ctx->packet = packet;	/* Save original packet */
  
  /* Parse the command payload in the packet */
  ctx->payload = silc_command_parse_payload(packet->buffer);
  if (!ctx->payload) {
    SILC_LOG_ERROR(("Bad command payload, packet dropped"));
    silc_buffer_free(packet->buffer);
    silc_free(ctx);
    return;
  }
  
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

#define SILC_COMMAND_STATUS_DATA(x) \
  (

/* Sends simple status message as command reply packet */

static void 
silc_server_command_send_status_reply(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcCommandStatus status)
{
  SilcBuffer buffer;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer = silc_command_encode_reply_payload_va(command, status, 0);
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

  buffer = silc_command_encode_reply_payload_va(command, status, 1,
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
  unsigned int argc, count = 0, len;
  SilcClientEntry entry;
  SilcBuffer packet;
  unsigned char *id_string;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_command_get_arg_num(cmd->payload);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOIS,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_WHOIS,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get the nickname@server string and parse it. */
  tmp = silc_command_get_first_arg(cmd->payload, NULL);
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

  /* Get the max count of reply messages allowed */
  if (argc == 2) {
    tmp = silc_command_get_next_arg(cmd->payload, NULL);
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

  /* Then, make the query from our local client list */
  entry = silc_idlist_find_client_by_nickname(server->local_list, 
					      nick, server_name);
  if (!entry) {

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

  /* Send WHOIS reply */
  id_string = silc_id_id2str(entry->id, SILC_ID_CLIENT);
  tmp = silc_command_get_first_arg(cmd->payload, NULL);

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

    SILC_PUT32_MSB((time(NULL) - entry->last_receive), idle);

    /* XXX */
    if (entry->userinfo)
      packet = 
        silc_command_encode_reply_payload_va(SILC_COMMAND_WHOIS,
					     SILC_STATUS_OK, 5, 
					     2, id_string, SILC_ID_CLIENT_LEN,
					     3, nh, strlen(nh),
					     4, uh, strlen(uh),
					     5, entry->userinfo, 
					     strlen(entry->userinfo),
					     7, idle, 4);
    else
      packet = 
        silc_command_encode_reply_payload_va(SILC_COMMAND_WHOIS,
					     SILC_STATUS_OK, 4, 
					     2, id_string, SILC_ID_CLIENT_LEN,
					     3, nh, strlen(nh),
					     4, uh, strlen(uh),
					     7, idle, 4);

  } else {
    /* XXX */
    packet = 
      silc_command_encode_reply_payload_va(SILC_COMMAND_WHOIS, 
					   SILC_STATUS_OK, 3, 
					   2, id_string, SILC_ID_CLIENT_LEN,
					   3, entry->nickname, 
					   strlen(entry->nickname),
					   4, tmp, strlen(tmp)); /* XXX */
  }
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_free(id_string);
  silc_buffer_free(packet);

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
  SilcClientEntry entry;
  SilcBuffer packet;
  unsigned char *id_string;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_command_get_arg_num(cmd->payload);
  if (argc < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (argc > 2) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					  SILC_STATUS_ERR_TOO_MANY_PARAMS);
    goto out;
  }

  /* Get the nickname@server string and parse it. */
  tmp = silc_command_get_first_arg(cmd->payload, NULL);
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

  /* Get the max count of reply messages allowed */
  if (argc == 2) {
    tmp = silc_command_get_next_arg(cmd->payload, NULL);
    if (!tmp) {
      silc_server_command_send_status_reply(cmd, SILC_COMMAND_IDENTIFY,
					    SILC_STATUS_ERR_TOO_MANY_PARAMS);
      goto out;
    }
    count = atoi(tmp);
  }

  /* Find client */
  entry = silc_idlist_find_client_by_nickname(server->local_list,
					      nick, NULL);
  if (!entry)
    entry = silc_idlist_find_client_by_hash(server->global_list,
					    nick, server->md5hash);

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
  id_string = silc_id_id2str(entry->id, SILC_ID_CLIENT);
  tmp = silc_command_get_first_arg(cmd->payload, NULL);
  packet = silc_command_encode_reply_payload_va(SILC_COMMAND_IDENTIFY,
						SILC_STATUS_OK, 2,
						2, id_string, 
						SILC_ID_CLIENT_LEN,
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

  silc_free(id_string);
  silc_buffer_free(packet);

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
  SilcClientEntry id_entry = (SilcClientEntry)cmd->sock->user_data;
  SilcServer server = cmd->server;
  SilcBuffer packet;
  SilcClientID *new_id;
  char *id_string;
  char *nick;

  SILC_LOG_DEBUG(("Start"));

  /* Check number of arguments */
  if (silc_command_get_arg_num(cmd->payload) < 1) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_NICK,
					  SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Check nickname */
  nick = silc_command_get_arg_type(cmd->payload, 1, NULL);
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
				FALSE, id_entry->id,
				SILC_ID_CLIENT, SILC_ID_CLIENT_LEN,
				new_id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);

  /* If we are router we have to distribute the new Client ID to all 
     routers in SILC. */
  if (cmd->server->server_type == SILC_ROUTER && !cmd->server->standalone)
    silc_server_send_replace_id(server, server->id_entry->router->connection,  
				TRUE, id_entry->id,
				SILC_ID_CLIENT, SILC_ID_CLIENT_LEN,
				new_id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);

  /* Remove old cache entry */
  silc_idcache_del_by_id(server->local_list->clients, SILC_ID_CLIENT, 
			 id_entry->id); 
  
  /* Free old ID */
  if (id_entry->id) {
    memset(id_entry->id, 0, SILC_ID_CLIENT_LEN);
    silc_free(id_entry->id);
  }

  /* Save the nickname as this client is our local client */
  if (id_entry->nickname)
    silc_free(id_entry->nickname);

  id_entry->nickname = strdup(nick);
  id_entry->id = new_id;

  /* Update client cache */
  silc_idcache_add(server->local_list->clients, id_entry->nickname, 
		   SILC_ID_CLIENT, id_entry->id, (void *)id_entry, TRUE);

  /* Send the new Client ID as reply command back to client */
  id_string = silc_id_id2str(id_entry->id, SILC_ID_CLIENT);
  packet = silc_command_encode_reply_payload_va(SILC_COMMAND_NICK, 
						SILC_STATUS_OK, 1, 
						2, id_string, 
						SILC_ID_CLIENT_LEN);
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_free(id_string);
  silc_buffer_free(packet);

 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(list)
{
}

SILC_SERVER_CMD_FUNC(topic)
{
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
  unsigned int argc, len;
  unsigned char *id_string;

  /* Check number of arguments */
  argc = silc_command_get_arg_num(cmd->payload);
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
  id_string = silc_command_get_arg_type(cmd->payload, 1, &len);
  if (!id_string) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CLIENT_ID);
    goto out;
  }
  dest_id = silc_id_str2id(id_string, SILC_ID_CLIENT);

  /* Get Channel ID */
  id_string = silc_command_get_arg_type(cmd->payload, 2, &len);
  if (!id_string) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  channel_id = silc_id_str2id(id_string, SILC_ID_CHANNEL);

  /* Check whether the channel exists */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
  if (!channel) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NO_SUCH_CHANNEL);
    goto out;
  }

  /* Check whether the sender of this command is on the channel. */
  sender = (SilcClientEntry )sock->user_data;
  if (!silc_server_client_on_channel(sender, channel)) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					  SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Check whether the channel is invite-only channel. If yes then the
     sender of this command must be at least channel operator. */
  /* XXX */

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

  /* Send notify to the client that is invited to the channel */
  silc_server_send_notify_dest(server, dest_sock, dest_id, SILC_ID_CLIENT,
			       SILC_NOTIFY_TYPE_INVITE,
			       "%s invites you to channel %s",
			       sender->nickname, channel->channel_name);

  /* Send command reply */
  silc_server_command_send_status_reply(cmd, SILC_COMMAND_INVITE,
					SILC_STATUS_OK);

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
  SilcBuffer packet;
  unsigned int argc;
  unsigned char *id_string;
  char info_string[256], *dest_server;

  argc = silc_command_get_arg_num(cmd->payload);
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
  dest_server = silc_command_get_arg_type(cmd->payload, 1, NULL);
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

    id_string = silc_id_id2str(server->id, SILC_ID_SERVER);

    packet = 
      silc_command_encode_reply_payload_va(SILC_COMMAND_INFO,
					   SILC_STATUS_OK, 2,
					   2, id_string, SILC_ID_SERVER_LEN,
					   3, info_string, 
					   strlen(info_string));
    silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			    packet->data, packet->len, FALSE);
    
    silc_free(id_string);
    silc_buffer_free(packet);
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
  unsigned int argc;
  unsigned char *id_string;

  argc = silc_command_get_arg_num(cmd->payload);
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
  id_string = silc_command_get_arg_type(cmd->payload, 1, NULL);
  if (!id_string) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_PING,
					  SILC_STATUS_ERR_NO_SERVER_ID);
    goto out;
  }
  id = silc_id_str2id(id_string, SILC_ID_SERVER);

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
} JoinInternalContext;

SILC_TASK_CALLBACK(silc_server_command_join_notify)
{
  JoinInternalContext *ctx = (JoinInternalContext *)context;

  if (ctx->channel->key && ctx->channel->key_len) {
    silc_server_send_notify_to_channel(ctx->server, ctx->channel,
				       SILC_NOTIFY_TYPE_JOIN,
				       "%s (%s@%s) has joined channel %s",
				       ctx->nickname, ctx->username,
				       ctx->hostname, ctx->channel_name);
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
  SilcBuffer buffer;
  unsigned char *id_string;

  id_string = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
  buffer = silc_command_encode_payload_va(SILC_COMMAND_NAMES, 1,
					  1, id_string, SILC_ID_CHANNEL_LEN);

  cmd = silc_calloc(1, sizeof(*cmd));
  cmd->payload = silc_command_parse_payload(buffer);
  cmd->server = server;
  cmd->sock = sock;
  cmd->pending = FALSE;

  silc_server_command_names((void *)cmd);
  silc_free(id_string);
  silc_free(buffer);
}

/* Server side of command JOIN. Joins client into requested channel. If 
   the channel does not exist it will be created. */

SILC_SERVER_CMD_FUNC(join)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  SilcServer server = cmd->server;
  SilcSocketConnection sock = cmd->sock;
  SilcBuffer buffer = cmd->packet->buffer;
  int argc, i, tmp_len;
  char *tmp, *channel_name = NULL, *cipher = NULL, *id_string = NULL;
  unsigned char *passphrase, mode[4];
  SilcChannelEntry channel;
  SilcServerID *router_id;
  SilcBuffer packet;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  /* Check number of parameters */
  argc = silc_command_get_arg_num(cmd->payload);
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
  tmp = silc_command_get_arg_type(cmd->payload, 1, &tmp_len);
  channel_name = silc_calloc(tmp_len + 1, sizeof(*channel_name));
  memcpy(channel_name, tmp, tmp_len);
  if (silc_server_command_bad_chars(tmp) == TRUE) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_JOIN,
					  SILC_STATUS_ERR_BAD_CHANNEL);
    silc_free(channel_name);
    goto out;
  }

  /* Get passphrase */
  tmp = silc_command_get_arg_type(cmd->payload, 2, &tmp_len);
  if (tmp) {
    passphrase = silc_calloc(tmp_len, sizeof(*passphrase));
    memcpy(passphrase, tmp, tmp_len);
  }
  
  /* Get cipher name */
  cipher = silc_command_get_arg_type(cmd->payload, 3, NULL);

  /* See if the channel exists */
  channel = 
    silc_idlist_find_channel_by_name(server->local_list, channel_name);
  if (!channel) {
    /* Channel not found */

    /* If we are standalone server we don't have a router, we just create 
       the channel by  ourselves. */
    if (server->standalone) {
      router_id = server->id;
      channel = silc_server_new_channel(server, router_id, 
					cipher, channel_name);
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
    silc_free(channel_name);
    goto out;
  }

  /* Join the client to the channel */
  i = channel->user_list_count;
  channel->user_list = silc_realloc(channel->user_list, 
				    sizeof(*channel->user_list) * (i + 1));
  channel->user_list[i].mode = SILC_CHANNEL_UMODE_NONE;
  channel->user_list[i].client = client;
  channel->user_list_count++;

  /* Add the channel to client's channel list */
  i = client->channel_count;
  client->channel = silc_realloc(client->channel, 
				 sizeof(*client->channel) * (i + 1));
  client->channel[i] = channel;
  client->channel_count++;

  /* Notify router about new user on channel. If we are normal server
     we send it to our router, if we are router we send it to our
     primary route. */
  if (!server->standalone) {

  }

  /* Send command reply to the client. Client receives the Channe ID,
     channel mode and possibly other information in this reply packet. */
  if (!cmd->pending) {
    id_string = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
    SILC_PUT32_MSB(channel->mode, mode);

    if (!channel->topic)
      packet = 
	silc_command_encode_reply_payload_va(SILC_COMMAND_JOIN,
					     SILC_STATUS_OK, 3,
					     2, channel_name, 
					     strlen(channel_name),
					     3, id_string, SILC_ID_CHANNEL_LEN,
					     4, mode, 4);
    else
      packet = 
	silc_command_encode_reply_payload_va(SILC_COMMAND_JOIN,
					     SILC_STATUS_OK, 4, 
					     2, channel_name, 
					     strlen(channel_name),
					     3, id_string, SILC_ID_CHANNEL_LEN,
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
  }

  /* Send channel key to the client. Client cannot start transmitting
     to the channel until we have sent the key. */
  if (!cmd->pending) {
    tmp_len = strlen(channel->channel_key->cipher->name);
    packet = 
      silc_channel_key_encode_payload(SILC_ID_CHANNEL_LEN, 
				      id_string, tmp_len, 
				      channel->channel_key->cipher->name,
				      channel->key_len / 8, channel->key);
    
    silc_server_packet_send(server, sock, SILC_PACKET_CHANNEL_KEY, 0, 
			    packet->data, packet->len, FALSE);
    silc_buffer_free(packet);
  }

  if (id_string)
    silc_free(id_string);

  /* Finally, send notify message to all clients on the channel about
     new user on the channel. */
  if (!(cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED)) {
    if (!cmd->pending) {
      silc_server_send_notify_to_channel(server, channel,
					 SILC_NOTIFY_TYPE_JOIN,
					 "%s (%s@%s) has joined channel %s",
					 client->nickname, client->username,
					 sock->hostname ? sock->hostname :
					 sock->ip, channel_name);
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

/* Server side of command MOTD. Sends servers current "message of the
   day" to the client. */

SILC_SERVER_CMD_FUNC(motd)
{

  SILC_LOG_DEBUG(("Start"));

}

SILC_SERVER_CMD_FUNC(umode)
{
}

SILC_SERVER_CMD_FUNC(cmode)
{
}

SILC_SERVER_CMD_FUNC(kick)
{
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
  unsigned int i, argc, key_len;
  unsigned char *tmp, channel_key[32];

  SILC_LOG_DEBUG(("Start"));

  argc = silc_command_get_arg_num(cmd->payload);
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
  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  id = silc_id_str2id(tmp, SILC_ID_CHANNEL);

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
    silc_channel_key_encode_payload(SILC_ID_CHANNEL_LEN, tmp,
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
  SilcChannelID *id;
  SilcBuffer packet;
  unsigned int i, len, len2, argc;
  unsigned char *tmp;
  char *name_list = NULL, *n;
  SilcBuffer client_id_list;

  SILC_LOG_DEBUG(("Start"));

  argc = silc_command_get_arg_num(cmd->payload);
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
  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_NO_CHANNEL_ID);
    goto out;
  }
  id = silc_id_str2id(tmp, SILC_ID_CHANNEL);

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
  for (i = 0; i < channel->user_list_count; i++) {
    if (!channel->user_list[i].client)
      continue;

    n = channel->user_list[i].client->nickname;
    if (n) {
      len2 = strlen(n);
      len += len2;
      name_list = silc_realloc(name_list, sizeof(*name_list) * (len + 1));
      memcpy(name_list + (len - len2), n, len2);
      name_list[len] = 0;

      if (i == channel->user_list_count - 1)
	break;
      memcpy(name_list + len, ",", 1);
      len++;
    }
  }
  if (!name_list)
    name_list = "";

  /* Assemble the Client ID list now */
  client_id_list = silc_buffer_alloc(SILC_ID_CLIENT_LEN * 
				     channel->user_list_count);
  silc_buffer_pull_tail(client_id_list, (SILC_ID_CLIENT_LEN *
					 channel->user_list_count));
  for (i = 0; i < channel->user_list_count; i++) {
    unsigned char *id_string;

    if (!channel->user_list[i].client)
      continue;

    id_string = silc_id_id2str(channel->user_list[i].client->id,
			       SILC_ID_CLIENT);
    silc_buffer_format(client_id_list,
		       SILC_STR_UI_XNSTRING(id_string, SILC_ID_CLIENT_LEN),
		       SILC_STR_END);
    silc_buffer_pull(client_id_list, SILC_ID_CLIENT_LEN);
    silc_free(id_string);
  }
  silc_buffer_push(client_id_list, 
		   client_id_list->data - client_id_list->head);

  /* Send reply */
  packet = silc_command_encode_reply_payload_va(SILC_COMMAND_NAMES,
						SILC_STATUS_OK, 3,
						2, tmp, SILC_ID_CHANNEL_LEN,
						3, name_list, 
						strlen(name_list),
						4, client_id_list->data,
						client_id_list->len);
  silc_server_packet_send(server, cmd->sock, SILC_PACKET_COMMAND_REPLY, 0, 
			  packet->data, packet->len, FALSE);
    
  silc_buffer_free(packet);
  silc_free(name_list);
  silc_buffer_free(client_id_list);
  silc_free(id);

 out:
  silc_server_command_free(cmd);
}
