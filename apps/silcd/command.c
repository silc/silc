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
 * Revision 1.3  2000/07/03 05:52:22  priikone
 * 	Implemented LEAVE command.
 *
 * Revision 1.2  2000/06/28 05:06:38  priikone
 * 	Shorter timeout for channel joining notify.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "serverincludes.h"
#include "server_internal.h"

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

/* Sends command status message as command reply packet. */

static void 
silc_server_command_send_status_msg(SilcServerCommandContext cmd,
				    SilcCommand command,
				    SilcCommandStatus status,
				    unsigned char *msg,
				    unsigned int msg_len)
{
  SilcBuffer sp_buf, buffer;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  sp_buf = silc_command_encode_status_payload(status, msg, msg_len);
  buffer = silc_command_encode_payload_va(command, 1, 
					  sp_buf->data, sp_buf->len);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0, 
			  buffer->data, buffer->len, FALSE);
  silc_buffer_free(buffer);
  silc_buffer_free(sp_buf);
}

/* Sends simple status message as command reply packet */

static void 
silc_server_command_send_status_reply(SilcServerCommandContext cmd,
				      SilcCommand command,
				      SilcCommandStatus status)
{
  SilcBuffer sp_buf, buffer;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  sp_buf = silc_command_encode_status_payload(status, NULL, 0);
  buffer = silc_command_encode_payload_va(command, 1, 
					  sp_buf->data, sp_buf->len);
  silc_server_packet_send(cmd->server, cmd->sock,
			  SILC_PACKET_COMMAND_REPLY, 0, 
			  buffer->data, buffer->len, FALSE);
  silc_buffer_free(buffer);
  silc_buffer_free(sp_buf);
}

/* Server side of command WHOIS. Processes user's query and sends found 
   results as command replies back to the client. */

SILC_SERVER_CMD_FUNC(whois)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  char *tmp, *nick = NULL, *server = NULL;
  unsigned int argc, count = 0, len;
  SilcClientList *entry;
  SilcBuffer sp_buf, packet;
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
      server = silc_calloc(strlen(tmp) - len, sizeof(char));
      memcpy(server, tmp + len + 1, strlen(tmp) - len - 1);
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
      if (server)
	silc_free(server);
      goto out;
    }
    count = atoi(tmp);
  }

  /* Then, make the query from our local client list */
  entry = silc_idlist_find_client_by_nickname(cmd->server->local_list->clients,
					      nick, server);
  if (!entry) {

    /* If we are normal server and are connected to a router we will
       make global query from the router. */
    if (cmd->server->server_type == SILC_SERVER && !cmd->server->standalone) {

      goto ok;
    }
    
    /* If we are router then we will check our global list as well. */
    if (cmd->server->server_type == SILC_ROUTER) {
      entry =
	silc_idlist_find_client_by_nickname(cmd->server->global_list->clients,
					    nick, server);
      if (!entry) {
	silc_server_command_send_status_msg(cmd, SILC_COMMAND_WHOIS,
					    SILC_STATUS_ERR_NO_SUCH_NICK,
					    tmp, strlen(tmp));
	goto out;
      }
      goto ok;
    }

    silc_server_command_send_status_msg(cmd, SILC_COMMAND_WHOIS,
					SILC_STATUS_ERR_NO_SUCH_NICK,
					tmp, strlen(tmp));
    goto out;
  }

 ok:
  /* XXX, works only for local server info */

  /* Send WHOIS reply */
  id_string = silc_id_id2str(entry->id, SILC_ID_CLIENT);
  tmp = silc_command_get_first_arg(cmd->payload, NULL),
  sp_buf = silc_command_encode_status_payload(SILC_STATUS_OK, NULL, 0);

  /* XXX */
  if (cmd->sock->type == SILC_SOCKET_TYPE_CLIENT) {
    char nh[256], uh[256];
    SilcSocketConnection hsock;

    memset(uh, 0, sizeof(uh));
    memset(nh, 0, sizeof(nh));

    strncat(nh, entry->nickname, strlen(entry->nickname));
    strncat(nh, "@", 1);
    len = entry->router ? strlen(entry->router->server_name) :
      strlen(cmd->server->server_name);
    strncat(nh, entry->router ? entry->router->server_name :
	    cmd->server->server_name, len);

    strncat(uh, entry->username, strlen(entry->username));
    strncat(uh, "@", 1);
    hsock = (SilcSocketConnection)entry->connection;
    len = hsock->hostname ? strlen(hsock->hostname) : strlen(hsock->ip);
    strncat(uh, hsock->hostname ? hsock->hostname : hsock->ip, len);

    /* XXX */
    if (entry->userinfo)
      packet = 
        silc_command_encode_payload_va(SILC_COMMAND_WHOIS, 5, 
  				       sp_buf->data, sp_buf->len,
  				       id_string, SILC_ID_CLIENT_LEN,
  				       nh, strlen(nh),
				       uh, strlen(uh),
				       entry->userinfo, 
				       strlen(entry->userinfo));
    else
      packet = 
        silc_command_encode_payload_va(SILC_COMMAND_WHOIS, 4,
  				       sp_buf->data, sp_buf->len,
  				       id_string, SILC_ID_CLIENT_LEN,
  				       nh, strlen(nh),
				       uh, strlen(uh));

  } else {
    /* XXX */
    packet = 
      silc_command_encode_payload_va(SILC_COMMAND_WHOIS, 4, 
				     sp_buf->data, sp_buf->len,
				     id_string, SILC_ID_CLIENT_LEN,
				     entry->nickname, strlen(entry->nickname),
				     tmp, strlen(tmp)); /* XXX */
  }
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_free(id_string);
  silc_buffer_free(packet);
  silc_free(sp_buf);

 out:
  silc_server_command_free(cmd);
}

SILC_SERVER_CMD_FUNC(whowas)
{
}

SILC_SERVER_CMD_FUNC(identify)
{
  SilcServerCommandContext cmd = (SilcServerCommandContext)context;
  char *tmp, *nick = NULL, *server = NULL;
  unsigned int argc, count = 0, len;
  SilcClientList *entry;
  SilcBuffer sp_buf, packet;
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
      server = silc_calloc(strlen(tmp) - len, sizeof(char));
      memcpy(server, tmp + len + 1, strlen(tmp) - len - 1);
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

  /* Then, make the query from our local client list */
  entry = silc_idlist_find_client_by_hash(cmd->server->local_list->clients,
					  nick, cmd->server->md5hash);
  if (!entry) {

    /* If we are normal server and are connected to a router we will
       make global query from the router. */
    if (cmd->server->server_type == SILC_SERVER && !cmd->server->standalone) {
      SilcBuffer buffer = cmd->packet->buffer;

      /* Send IDENTIFY command to our router */
      silc_buffer_push(buffer, buffer->data - buffer->head);
      silc_server_packet_forward(cmd->server, (SilcSocketConnection)
				 cmd->server->id_entry->router->connection,
				 buffer->data, buffer->len, TRUE);
      goto out;
    }
    
    /* If we are router then we will check our global list as well. */
    if (cmd->server->server_type == SILC_ROUTER) {
      entry = 
	silc_idlist_find_client_by_hash(cmd->server->global_list->clients,
					nick, cmd->server->md5hash);
      if (!entry) {
	silc_server_command_send_status_msg(cmd, SILC_COMMAND_IDENTIFY,
					    SILC_STATUS_ERR_NO_SUCH_NICK,
					    tmp, strlen(tmp));
	goto out;
      }
      goto ok;
    }

    silc_server_command_send_status_msg(cmd, SILC_COMMAND_IDENTIFY,
					SILC_STATUS_ERR_NO_SUCH_NICK,
					tmp, strlen(tmp));
    goto out;
  }

 ok:
  /* Send IDENTIFY reply */
  id_string = silc_id_id2str(entry->id, SILC_ID_CLIENT);
  tmp = silc_command_get_first_arg(cmd->payload, NULL);
  sp_buf = silc_command_encode_status_payload(SILC_STATUS_OK, NULL, 0);
  packet = silc_command_encode_payload_va(SILC_COMMAND_IDENTIFY, 3,
					  sp_buf->data, sp_buf->len,
					  id_string, SILC_ID_CLIENT_LEN,
					  nick, strlen(nick));
#if 0
  if (cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED) {
    void *id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_type);
    silc_server_packet_send_dest(cmd->server, cmd->sock, 
				 SILC_PACKET_COMMAND_REPLY, 0,
				 id, cmd->packet->src_id_type,
				 packet->data, packet->len, FALSE);
    silc_free(id);
  } else
#endif
    silc_server_packet_send(cmd->server, cmd->sock, 
			    SILC_PACKET_COMMAND_REPLY, 0, 
			    packet->data, packet->len, FALSE);

  silc_free(id_string);
  silc_buffer_free(packet);
  silc_free(sp_buf);

 out:
  if (nick)
    silc_free(nick);
  if (server)
    silc_free(server);
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
  SilcClientList *id_entry = (SilcClientList *)cmd->sock->user_data;
  SilcServer server = cmd->server;
  SilcBuffer packet, sp_buf;
  SilcClientID *new_id;
  char *id_string;
  char *nick;

  SILC_LOG_DEBUG(("Start"));

#define LCC(x) server->local_list->client_cache[(x) - 32]
#define LCCC(x) server->local_list->client_cache_count[(x) - 32]

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
  silc_idcache_del_by_id(LCC(id_entry->nickname[0]),
			 LCCC(id_entry->nickname[0]), 
			 SILC_ID_CLIENT, id_entry->id); 
  
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
  LCCC(nick[0]) = silc_idcache_add(&LCC(nick[0]), LCCC(nick[0]),
				   id_entry->nickname, SILC_ID_CLIENT, 
				   id_entry->id, (void *)id_entry);

  /* Send the new Client ID as reply command back to client */
  id_string = silc_id_id2str(id_entry->id, SILC_ID_CLIENT);
  sp_buf = silc_command_encode_status_payload(SILC_STATUS_OK, NULL, 0);
  packet = silc_command_encode_payload_va(SILC_COMMAND_NICK, 2, 
					  sp_buf->data, sp_buf->len,
					  id_string, SILC_ID_CLIENT_LEN);
  silc_server_packet_send(cmd->server, cmd->sock, SILC_PACKET_COMMAND_REPLY,
			  0, packet->data, packet->len, FALSE);

  silc_free(id_string);
  silc_buffer_free(packet);
  silc_free(sp_buf);

 out:
  silc_server_command_free(cmd);
#undef LCC
#undef LCCC
}

SILC_SERVER_CMD_FUNC(list)
{
}

SILC_SERVER_CMD_FUNC(topic)
{
}

SILC_SERVER_CMD_FUNC(invite)
{
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

SILC_SERVER_CMD_FUNC(info)
{
}

SILC_SERVER_CMD_FUNC(connect)
{
}

SILC_SERVER_CMD_FUNC(ping)
{
}

SILC_SERVER_CMD_FUNC(oper)
{
}

typedef struct {
  char *channel_name;
  char *nickname;
  char *username;
  char *hostname;
  SilcChannelList *channel;
  SilcServer server;
} JoinInternalContext;

SILC_TASK_CALLBACK(silc_server_command_join_notify)
{
  JoinInternalContext *ctx = (JoinInternalContext *)context;

  if (ctx->channel->key && ctx->channel->key_len) {
    silc_server_send_notify_to_channel(ctx->server, ctx->channel,
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
  SilcChannelList *channel;
  SilcServerID *router_id;
  SilcIDCache *id_cache;
  SilcBuffer packet, sp_buf;
  SilcClientList *client;

  SILC_LOG_DEBUG(("Start"));

#define LCC(x) server->local_list->channel_cache[(x) - 32]
#define LCCC(x) server->local_list->channel_cache_count[(x) - 32]

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
  if (silc_idcache_find_by_data(LCC(channel_name[0]), LCCC(channel_name[0]), 
				channel_name, &id_cache) == FALSE) {
    /* Channel not found */
    id_cache = NULL;

    /* If we are standalone server we don't have a router, we just create 
       the channel by  ourselves. */
    if (server->standalone) {
      router_id = server->id;
      channel = silc_server_new_channel(server, router_id, 
					cipher, channel_name);
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
  if (!id_cache && server->server_type == SILC_ROUTER) {

    /* Notify all routers about the new channel in SILC network. */
    if (!server->standalone) {
#if 0
      silc_server_send_new_id(server, server->id_entry->router->connection, 
			      TRUE,
			      xxx, SILC_ID_CHANNEL, SILC_ID_CHANNEL_LEN);
#endif
    }

  }

  channel = (SilcChannelList *)id_cache->context;

 join_channel:

  /* XXX must check whether the client already is on the channel */

  /* Join the client to the channel */
  i = channel->user_list_count;
  channel->user_list = silc_realloc(channel->user_list, 
				    sizeof(*channel->user_list) * (i + 1));
  channel->user_list[i].mode = SILC_CHANNEL_UMODE_NONE;

  /* If the JOIN request was forwarded to us we will make a bit slower
     query to get the client pointer. Otherwise, we get the client pointer
     real easy. */
  if (!(cmd->packet->flags & SILC_PACKET_FLAG_FORWARDED)) {
    client = (SilcClientList *)sock->user_data;
    channel->user_list[i].client = client;
  } else {
    void *id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_type);
    client = silc_idlist_find_client_by_id(server->local_list->clients, id);
    channel->user_list[i].client = client;
    silc_free(id);
  }
  channel->user_list_count++;

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
    sp_buf = silc_command_encode_status_payload(SILC_STATUS_OK, NULL, 0);
    SILC_PUT32_MSB(channel->mode, mode);

    if (!channel->topic)
      packet = 
	silc_command_encode_payload_va(SILC_COMMAND_JOIN, 4,
				       sp_buf->data, sp_buf->len,
				       channel_name, strlen(channel_name),
				       id_string, SILC_ID_CHANNEL_LEN,
				       mode, 4);
    else
      packet = 
	silc_command_encode_payload_va(SILC_COMMAND_JOIN, 5,
				       sp_buf->data, sp_buf->len,
				       channel_name, strlen(channel_name),
				       id_string, SILC_ID_CHANNEL_LEN,
				       mode, 4,
				       channel->topic, strlen(channel->topic));

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
    silc_free(sp_buf);
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

 out:
  silc_server_command_free(cmd);
#undef LCC
#undef LCCC
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
  SilcSocketConnection sock = cmd->sock;
  SilcClientList *id_entry = (SilcClientList *)cmd->sock->user_data;
  SilcServer server = cmd->server;
  SilcChannelID *id;
  SilcChannelList *channel;
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

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  if (!tmp) {
    silc_server_command_send_status_reply(cmd, SILC_COMMAND_LEAVE,
					  SILC_STATUS_ERR_BAD_CHANNEL_ID);
    goto out;
  }

  /* Get Channel ID */
  id = silc_id_str2id(tmp, SILC_ID_CHANNEL);

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list->channels, id);

  /* Remove client from channel */
  i = silc_server_remove_from_one_channel(server, sock, channel, id_entry);
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

SILC_SERVER_CMD_FUNC(names)
{
}
