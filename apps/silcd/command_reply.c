/*

  command_reply.c

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
#include "command_reply.h"

#define COMMAND_CHECK_STATUS						  \
do {									  \
  SILC_LOG_DEBUG(("Start"));						  \
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL)); \
  if (status != SILC_STATUS_OK) {					  \
    silc_server_command_reply_free(cmd);				  \
    return;								  \
  }									  \
} while(0)

#define COMMAND_CHECK_STATUS_LIST					  \
do {									  \
  SILC_LOG_DEBUG(("Start"));						  \
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL)); \
  if (status != SILC_STATUS_OK && 					  \
      status != SILC_STATUS_LIST_START &&				  \
      status != SILC_STATUS_LIST_ITEM &&				  \
      status != SILC_STATUS_LIST_END) {					  \
    silc_server_command_reply_free(cmd);				  \
    return;								  \
  }									  \
} while(0)

/* Server command reply list. Not all commands have reply function as
   they are never sent by server. More maybe added later if need appears. */
SilcServerCommandReply silc_command_reply_list[] =
{
  SILC_SERVER_CMD_REPLY(join, JOIN),
  SILC_SERVER_CMD_REPLY(whois, WHOIS),
  SILC_SERVER_CMD_REPLY(identify, IDENTIFY),
  SILC_SERVER_CMD_REPLY(users, USERS),

  { NULL, 0 },
};

/* Process received command reply. */

void silc_server_command_reply_process(SilcServer server,
				       SilcSocketConnection sock,
				       SilcBuffer buffer)
{
  SilcServerCommandReply *cmd;
  SilcServerCommandReplyContext ctx;
  SilcCommandPayload payload;
  SilcCommand command;
  unsigned short ident;

  SILC_LOG_DEBUG(("Start"));

  /* Get command reply payload from packet */
  payload = silc_command_payload_parse(buffer);
  if (!payload) {
    /* Silently ignore bad reply packet */
    SILC_LOG_DEBUG(("Bad command reply packet"));
    return;
  }
  
  /* Allocate command reply context. This must be free'd by the
     command reply routine receiving it. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->server = server;
  ctx->sock = silc_socket_dup(sock);
  ctx->payload = payload;
  ctx->args = silc_command_get_args(ctx->payload);
  ident = silc_command_get_ident(ctx->payload);
      
  /* Check for pending commands and mark to be exeucted */
  silc_server_command_pending_check(server, ctx, 
				    silc_command_get(ctx->payload), ident);

  /* Execute command reply */
  command = silc_command_get(ctx->payload);
  for (cmd = silc_command_reply_list; cmd->cb; cmd++)
    if (cmd->cmd == command)
      break;

  if (cmd == NULL || !cmd->cb) {
    silc_server_command_reply_free(ctx);
    return;
  }

  cmd->cb(ctx);
}

/* Free command reply context and its internals. */

void silc_server_command_reply_free(SilcServerCommandReplyContext cmd)
{
  if (cmd) {
    silc_command_free_payload(cmd->payload);
    if (cmd->sock)
      silc_socket_free(cmd->sock); /* Decrease the reference counter */
    silc_free(cmd);
  }
}

/* Caches the received WHOIS information. If we are normal server currently
   we cache global information only for short period of time.  */
/* XXX cache expirying not implemented yet! */

static char
silc_server_command_reply_whois_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  int len, id_len;
  unsigned char *id_data;
  char *nickname, *username, *realname;
  SilcClientID *client_id;
  SilcClientEntry client;
  SilcIDCacheEntry cache = NULL;
  char global = FALSE;
  char *nick;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!id_data || !nickname || !username || !realname) 
    return FALSE;

  client_id = silc_id_payload_parse_id(id_data, id_len);
  if (!client_id)
    return FALSE;

  /* Check if we have this client cached already. */

  client = silc_idlist_find_client_by_id(server->local_list, client_id,
					 &cache);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, &cache);
    global = TRUE;
  }

  if (!client) {
    /* If router did not find such Client ID in its lists then this must
       be bogus client or some router in the net is buggy. */
    if (server->server_type == SILC_ROUTER)
      return FALSE;

    /* Take hostname out of nick string if it includes it. */
    if (strchr(nickname, '@')) {
      int len = strcspn(nickname, "@");
      nick = silc_calloc(len + 1, sizeof(char));
      memcpy(nick, nickname, len);
    } else {
      nick = strdup(nickname);
    }

    /* We don't have that client anywhere, add it. The client is added
       to global list since server didn't have it in the lists so it must be 
       global. */
    silc_idlist_add_client(server->global_list, nick,
			   strdup(username), 
			   strdup(realname), client_id, 
			   cmd->sock->user_data, NULL);
  } else {
    /* We have the client already, update the data */

    SILC_LOG_DEBUG(("Updating client data"));

    /* Take hostname out of nick string if it includes it. */
    if (strchr(nickname, '@')) {
      int len = strcspn(nickname, "@");
      nick = silc_calloc(len + 1, sizeof(char));
      memcpy(nick, nickname, len);
    } else {
      nick = strdup(nickname);
    }

    if (client->nickname)
      silc_free(client->nickname);
    if (client->username)
      silc_free(client->username);
    if (client->userinfo)
      silc_free(client->userinfo);
    
    client->nickname = nick;
    client->username = strdup(username);
    client->userinfo = strdup(realname);

    if (cache) {
      cache->data = nick;
      silc_idcache_sort_by_data(global ? server->global_list->clients : 
				server->local_list->clients);
    }

    silc_free(client_id);
  }

  return TRUE;
}

/* Reiceved reply for WHOIS command. We sent the whois request to our
   primary router, if we are normal server, and thus has now received reply
   to the command. We will figure out what client originally sent us the
   command and will send the reply to it.  If we are router we will figure
   out who server sent us the command and send reply to that one. */

SILC_SERVER_CMD_REPLY_FUNC(whois)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcCommandStatus status;

  COMMAND_CHECK_STATUS_LIST;

  if (!silc_server_command_reply_whois_save(cmd))
    goto out;

  /* Execute any pending commands */
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_WHOIS);

 out:
  SILC_SERVER_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_WHOIS);
  silc_server_command_reply_free(cmd);
}

/* Caches the received IDENTIFY information. */

static char
silc_server_command_reply_identify_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  int len, id_len;
  unsigned char *id_data;
  char *nickname, *username;
  SilcClientID *client_id;
  SilcClientEntry client;
  SilcIDCacheEntry cache = NULL;
  char global = FALSE;
  char *nick = NULL;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (!id_data)
    return FALSE;

  client_id = silc_id_payload_parse_id(id_data, id_len);
  if (!client_id)
    return FALSE;

  /* Check if we have this client cached already. */

  client = silc_idlist_find_client_by_id(server->local_list, client_id,
					 &cache);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, &cache);
    global = TRUE;
  }

  if (!client) {
    /* If router did not find such Client ID in its lists then this must
       be bogus client or some router in the net is buggy. */
    if (server->server_type == SILC_ROUTER)
      return FALSE;

    /* Take hostname out of nick string if it includes it. */
    if (nickname) {
      if (strchr(nickname, '@')) {
	int len = strcspn(nickname, "@");
	nick = silc_calloc(len + 1, sizeof(char));
	memcpy(nick, nickname, len);
      } else {
	nick = strdup(nickname);
      }
    }

    /* We don't have that client anywhere, add it. The client is added
       to global list since server didn't have it in the lists so it must be 
       global. */
    silc_idlist_add_client(server->global_list, nick,
			   username ? strdup(username) : NULL, NULL,
			   client_id, cmd->sock->user_data, NULL);
  } else {
    /* We have the client already, update the data */

    SILC_LOG_DEBUG(("Updating client data"));

    /* Take hostname out of nick string if it includes it. */
    if (nickname) {
      if (strchr(nickname, '@')) {
	int len = strcspn(nickname, "@");
	nick = silc_calloc(len + 1, sizeof(char));
	memcpy(nick, nickname, len);
      } else {
	nick = strdup(nickname);
      }
    }

    if (nickname && client->nickname)
      silc_free(client->nickname);

    if (nickname)
      client->nickname = nick;

    if (username && client->username) {
      silc_free(client->username);
      client->username = strdup(username);
    }

    if (nickname && cache) {
      cache->data = nick;
      silc_idcache_sort_by_data(global ? server->global_list->clients : 
				server->local_list->clients);
    }

    silc_free(client_id);
  }

  return TRUE;
}

/* Received reply for forwarded IDENTIFY command. We have received the
   requested identify information now and we will cache it. After this we
   will call the pending command so that the requestee gets the information
   after all. */

SILC_SERVER_CMD_REPLY_FUNC(identify)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcCommandStatus status;

  COMMAND_CHECK_STATUS_LIST;

  if (!silc_server_command_reply_identify_save(cmd))
    goto out;

  /* Execute any pending commands */
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_IDENTIFY);

 out:
  SILC_SERVER_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_IDENTIFY);
  silc_server_command_reply_free(cmd);
}

/* Received reply for forwarded JOIN command. Router has created or joined
   the client to the channel. We save some channel information locally
   for future use. */

SILC_SERVER_CMD_REPLY_FUNC(join)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcChannelID *id;
  SilcChannelEntry entry;
  unsigned int id_len, len;
  unsigned char *id_string;
  char *channel_name, *tmp;
  unsigned int mode, created;
  SilcBuffer keyp;

  COMMAND_CHECK_STATUS;

  /* Get channel name */
  channel_name = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!channel_name)
    goto out;

  /* Get channel ID */
  id_string = silc_argument_get_arg_type(cmd->args, 3, &id_len);
  if (!id_string)
    goto out;

  /* Get mode mask */
  tmp = silc_argument_get_arg_type(cmd->args, 4, NULL);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(mode, tmp);

  /* Get created boolean value */
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(created, tmp);
  if (created != 0 && created != 1)
    goto out;

  /* Get channel key */
  tmp = silc_argument_get_arg_type(cmd->args, 6, &len);
  if (!tmp)
    goto out;
  keyp = silc_buffer_alloc(len);
  silc_buffer_pull_tail(keyp, SILC_BUFFER_END(keyp));
  silc_buffer_put(keyp, tmp, len);

  id = silc_id_payload_parse_id(id_string, id_len);
  if (!id)
    goto out;

  /* See whether we already have the channel. */
  entry = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
  if (!entry) {
    /* Add new channel */

    SILC_LOG_DEBUG(("Adding new [%s] channel %s id(%s)", 
		    (created == 0 ? "existing" : "created"), channel_name,
		    silc_id_render(id, SILC_ID_CHANNEL)));

    /* Add the channel to our local list. */
    entry = silc_idlist_add_channel(server->local_list, strdup(channel_name), 
				    SILC_CHANNEL_MODE_NONE, id, 
				    server->router, NULL);
    if (!entry) {
      silc_free(id);
      goto out;
    }
  } else {
    silc_free(id);
  }

  /* If channel was not created we know there is global users on the 
     channel. */
  entry->global_users = (created == 0 ? TRUE : FALSE);

  /* If channel was just created the mask must be zero */
  if (!entry->global_users && mode) {
    SILC_LOG_DEBUG(("Buggy router `%s' sent non-zero mode mask for "
		    "new channel, forcing it to zero", cmd->sock->hostname));
    mode = 0;
  }

  /* Save channel mode */
  entry->mode = mode;

  /* Save channel key */
  silc_server_save_channel_key(server, keyp, entry);
  silc_buffer_free(keyp);

  /* Execute any pending commands */
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_JOIN);

 out:
  SILC_SERVER_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_JOIN);
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(users)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcChannelEntry channel;
  SilcChannelID *channel_id = NULL;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  unsigned char *tmp;
  unsigned int tmp_len;
  unsigned int list_count, i;

  COMMAND_CHECK_STATUS;

  /* Get channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp)
    goto out;
  channel_id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!channel_id)
    goto out;

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
  if (!tmp)
    goto out;

  client_id_list = silc_buffer_alloc(tmp_len);
  silc_buffer_pull_tail(client_id_list, tmp_len);
  silc_buffer_put(client_id_list, tmp, tmp_len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &tmp_len);
  if (!tmp)
    goto out;

  client_mode_list = silc_buffer_alloc(tmp_len);
  silc_buffer_pull_tail(client_mode_list, tmp_len);
  silc_buffer_put(client_mode_list, tmp, tmp_len);

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel)
      goto out;
  }

  /* Cache the received Client ID's and modes. This cache expires
     whenever server sends notify message to channel. It means two things;
     some user has joined or leaved the channel. XXX! */
  for (i = 0; i < list_count; i++) {
    unsigned short idp_len;
    unsigned int mode;
    SilcClientID *client_id;
    SilcClientEntry client;

    /* Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list->data, idp_len);
    if (!client_id)
      continue;
    silc_buffer_pull(client_id_list, idp_len);
    
    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list->data);
    silc_buffer_pull(client_mode_list, 4);

    /* Check if we have this client cached already. */
    client = silc_idlist_find_client_by_id(server->local_list, client_id,
					   NULL);
    if (!client)
      client = silc_idlist_find_client_by_id(server->global_list, 
					     client_id, NULL);
    if (!client) {
      /* If router did not find such Client ID in its lists then this must
	 be bogus client or some router in the net is buggy. */
      if (server->server_type == SILC_ROUTER)
	goto out;

      /* We don't have that client anywhere, add it. The client is added
	 to global list since server didn't have it in the lists so it must be 
	 global. */
      client = silc_idlist_add_client(server->global_list, NULL, NULL, 
				      NULL, client_id, cmd->sock->user_data, 
				      NULL);
      if (!client) {
	silc_free(client_id);
	continue;
      }
    } else {
      /* We have the client already. */
      silc_free(client_id);
    }

    if (!silc_server_client_on_channel(client, channel)) {
      /* Client was not on the channel, add it. */
      SilcChannelClientEntry chl = silc_calloc(1, sizeof(*chl));
      chl->client = client;
      chl->mode = mode;
      chl->channel = channel;
      silc_list_add(channel->user_list, chl);
      silc_list_add(client->channels, chl);
    }
  }

  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);

  /* Execute any pending commands */
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_USERS);

 out:
  SILC_SERVER_PENDING_DESTRUCTOR(cmd, SILC_COMMAND_USERS);
  if (channel_id)
    silc_free(channel_id);
  silc_server_command_reply_free(cmd);
}
