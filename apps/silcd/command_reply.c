/*

  command_reply.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

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

/* All functions that call the COMMAND_CHECK_STATUS or the
   COMMAND_CHECK_STATUS_LIST macros must have out: goto label. */

#define COMMAND_CHECK_STATUS						  \
do {									  \
  SILC_LOG_DEBUG(("Start"));						  \
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL)); \
  if (status != SILC_STATUS_OK)						  \
    goto out;								  \
} while(0)

#define COMMAND_CHECK_STATUS_LIST					  \
do {									  \
  SILC_LOG_DEBUG(("Start"));						  \
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL)); \
  if (status != SILC_STATUS_OK &&					  \
      status != SILC_STATUS_LIST_START &&				  \
      status != SILC_STATUS_LIST_ITEM &&				  \
      status != SILC_STATUS_LIST_END)					  \
    goto out;								  \
} while(0)

/* Server command reply list. Not all commands have reply function as
   they are never sent by server. More maybe added later if need appears. */
SilcServerCommandReply silc_command_reply_list[] =
{
  SILC_SERVER_CMD_REPLY(whois, WHOIS),
  SILC_SERVER_CMD_REPLY(whowas, WHOWAS),
  SILC_SERVER_CMD_REPLY(identify, IDENTIFY),
  SILC_SERVER_CMD_REPLY(info, INFO),
  SILC_SERVER_CMD_REPLY(motd, MOTD),
  SILC_SERVER_CMD_REPLY(join, JOIN),
  SILC_SERVER_CMD_REPLY(stats, STATS),
  SILC_SERVER_CMD_REPLY(users, USERS),
  SILC_SERVER_CMD_REPLY(getkey, GETKEY),
  SILC_SERVER_CMD_REPLY(list, LIST),

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
  SilcUInt16 ident;

  SILC_LOG_DEBUG(("Start"));

  /* Get command reply payload from packet */
  payload = silc_command_payload_parse(buffer->data, buffer->len);
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
  ctx->callbacks = 
    silc_server_command_pending_check(server, ctx, 
				      silc_command_get(ctx->payload), 
				      ident, &ctx->callbacks_count);

  /* Execute command reply */
  command = silc_command_get(ctx->payload);
  for (cmd = silc_command_reply_list; cmd->cb; cmd++)
    if (cmd->cmd == command)
      break;

  if (cmd == NULL || !cmd->cb) {
    silc_server_command_reply_free(ctx);
    return;
  }

  cmd->cb(ctx, NULL);
}

/* Free command reply context and its internals. */

void silc_server_command_reply_free(SilcServerCommandReplyContext cmd)
{
  if (cmd) {
    silc_command_payload_free(cmd->payload);
    if (cmd->sock)
      silc_socket_free(cmd->sock); /* Decrease the reference counter */
    silc_free(cmd->callbacks);
    silc_free(cmd);
  }
}

/* Caches the received WHOIS information. */

static char
silc_server_command_reply_whois_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  unsigned char *tmp, *id_data;
  char *nickname, *username, *realname, *servername = NULL;
  unsigned char *fingerprint;
  SilcClientID *client_id;
  SilcClientEntry client;
  char global = FALSE;
  char *nick;
  SilcUInt32 mode = 0, len, id_len, flen;
  int expire = 0;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!id_data || !nickname || !username || !realname) {
    SILC_LOG_ERROR(("Incomplete WHOIS info: %s %s %s",
		    nickname ? nickname : "",
		    username ? username : "",
		    realname ? realname : ""));
    return FALSE;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);

  client_id = silc_id_payload_parse_id(id_data, id_len, NULL);
  if (!client_id)
    return FALSE;

  fingerprint = silc_argument_get_arg_type(cmd->args, 9, &flen);

  /* Check if we have this client cached already. */

  client = silc_idlist_find_client_by_id(server->local_list, client_id, 
					 FALSE, NULL);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list, client_id, 
					   FALSE, NULL);
    global = TRUE;
  }

  if (!client) {
    /* If router did not find such Client ID in its lists then this must
       be bogus client or some router in the net is buggy. */
    if (server->server_type != SILC_SERVER)
      return FALSE;

    /* Take hostname out of nick string if it includes it. */
    silc_parse_userfqdn(nickname, &nick, &servername);

    /* We don't have that client anywhere, add it. The client is added
       to global list since server didn't have it in the lists so it must be 
       global. */
    client = silc_idlist_add_client(server->global_list, nick, 
				    strdup(username), 
				    strdup(realname), client_id, 
				    cmd->sock->user_data, NULL, 
				    time(NULL) + 300);
    if (!client) {
      SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
      return FALSE;
    }

    client->data.status |= 
      (SILC_IDLIST_STATUS_REGISTERED | SILC_IDLIST_STATUS_RESOLVED);
    client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    client->mode = mode;
    client->servername = servername;
  } else {
    /* We have the client already, update the data */

    SILC_LOG_DEBUG(("Updating client data"));

    /* Take hostname out of nick string if it includes it. */
    silc_parse_userfqdn(nickname, &nick, &servername);

    /* Remove the old cache entry  */
    silc_idcache_del_by_context(global ? server->global_list->clients :
				server->local_list->clients, client);

    silc_free(client->nickname);
    silc_free(client->username);
    silc_free(client->userinfo);
    silc_free(client->servername);
    
    client->nickname = nick;
    client->username = strdup(username);
    client->userinfo = strdup(realname);
    client->servername = servername;
    client->mode = mode;
    client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
    client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;

    /* If client is global and is not on any channel then add that we'll
       expire the entry after a while. */
    if (global && !silc_hash_table_count(client->channels) &&
	server->server_type == SILC_SERVER)
      expire = time(NULL) + 300;

    /* Create new cache entry */
    silc_idcache_add(global ? server->global_list->clients :
		     server->local_list->clients, nick, client->id, 
		     client, expire, NULL); 
    silc_free(client_id);
  }

  if (fingerprint && flen == sizeof(client->data.fingerprint))
    memcpy(client->data.fingerprint, fingerprint, flen);

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
  SilcServer server = cmd->server;
  SilcCommandStatus status;

  COMMAND_CHECK_STATUS_LIST;

  if (!silc_server_command_reply_whois_save(cmd))
    goto out;

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

 out:
  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID &&
      cmd->sock->type == SILC_SOCKET_TYPE_ROUTER) {
    SilcClientEntry client;
    SilcUInt32 tmp_len;
    unsigned char *tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
    if (tmp) {
      SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (client_id) {
	SILC_LOG_DEBUG(("Received invalid client ID notification, deleting "
			"the entry from cache"));
	client = silc_idlist_find_client_by_id(server->global_list, 
					       client_id, FALSE, NULL);
	if (client) {
	  silc_server_remove_from_channels(server, NULL, client, TRUE, 
					   NULL, TRUE);
	  silc_idlist_del_client(server->global_list, client);
	}
	silc_free(client_id);
      }
    }
  }

  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_WHOIS);
  silc_server_command_reply_free(cmd);
}

/* Caches the received WHOWAS information for a short period of time. */

static char
silc_server_command_reply_whowas_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  SilcUInt32 len, id_len;
  unsigned char *id_data;
  char *nickname, *username, *realname, *servername = NULL;
  SilcClientID *client_id;
  SilcClientEntry client;
  SilcIDCacheEntry cache = NULL;
  char *nick;
  int global = FALSE;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (!id_data || !nickname || !username)
    return FALSE;

  realname = silc_argument_get_arg_type(cmd->args, 5, &len);

  client_id = silc_id_payload_parse_id(id_data, id_len, NULL);
  if (!client_id)
    return FALSE;

  /* Check if we have this client cached already. */

  client = silc_idlist_find_client_by_id(server->local_list, client_id,
					 FALSE, &cache);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, FALSE, &cache);
    global = TRUE;
  }

  if (!client) {
    /* If router did not find such Client ID in its lists then this must
       be bogus client or some router in the net is buggy. */
    if (server->server_type != SILC_SERVER)
      return FALSE;

    /* Take hostname out of nick string if it includes it. */
    silc_parse_userfqdn(nickname, &nick, &servername);

    /* We don't have that client anywhere, add it. The client is added
       to global list since server didn't have it in the lists so it must be 
       global. */
    client = silc_idlist_add_client(server->global_list, nick,
				    strdup(username), strdup(realname), 
				    silc_id_dup(client_id, SILC_ID_CLIENT), 
				    cmd->sock->user_data, NULL,
				    SILC_ID_CACHE_EXPIRE_DEF);
    if (!client) {
      SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
      return FALSE;
    }

    client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED; 
    client->servername = servername;
  } else {
    /* We have the client already, update the data */

    /* Take hostname out of nick string if it includes it. */
    silc_parse_userfqdn(nickname, &nick, &servername);

    silc_free(client->nickname);
    silc_free(client->username);
    
    client->nickname = nick;
    client->username = strdup(username);
    client->servername = servername;

    /* Remove the old cache entry and create a new one */
    silc_idcache_del_by_context(global ? server->global_list->clients :
				server->local_list->clients, client);
    silc_idcache_add(global ? server->global_list->clients :
		     server->local_list->clients, nick, client->id, 
		     client, 0, NULL);
  }

  silc_free(client_id);

  return TRUE;
}

/* Received reply for WHOWAS command. Cache the client information only for
   a short period of time. */

SILC_SERVER_CMD_REPLY_FUNC(whowas)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcCommandStatus status;

  COMMAND_CHECK_STATUS_LIST;

  if (!silc_server_command_reply_whowas_save(cmd))
    goto out;

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_WHOWAS);
  silc_server_command_reply_free(cmd);
}

/* Caches the received IDENTIFY information. */

static char
silc_server_command_reply_identify_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  SilcUInt32 len, id_len;
  unsigned char *id_data;
  char *name, *info;
  SilcClientID *client_id = NULL;
  SilcServerID *server_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcClientEntry client;
  SilcServerEntry server_entry;
  SilcChannelEntry channel;
  char global = FALSE;
  char *nick = NULL;
  SilcIDPayload idp = NULL;
  SilcIdType id_type;
  int expire = 0;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  if (!id_data)
    return FALSE;
  idp = silc_id_payload_parse(id_data, id_len);
  if (!idp)
    return FALSE;

  name = silc_argument_get_arg_type(cmd->args, 3, &len);
  info = silc_argument_get_arg_type(cmd->args, 4, &len);

  id_type = silc_id_payload_get_type(idp);

  switch (id_type) {
  case SILC_ID_CLIENT:
    client_id = silc_id_payload_get_id(idp);
    if (!client_id)
      goto error;

    SILC_LOG_DEBUG(("Received client information"));

    client = silc_idlist_find_client_by_id(server->local_list, 
					   client_id, FALSE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->global_list, client_id,
					     FALSE, NULL);
      global = TRUE;
    }
    if (!client) {
      /* If router did not find such Client ID in its lists then this must
	 be bogus client or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER)
	goto error;

      /* Take nickname */
      if (name)
	silc_parse_userfqdn(name, &nick, NULL);

      /* We don't have that client anywhere, add it. The client is added
	 to global list since server didn't have it in the lists so it must be 
	 global. */
      client = silc_idlist_add_client(server->global_list, nick, 
				      info ? strdup(info) : NULL, NULL,
				      client_id, cmd->sock->user_data, NULL,
				      time(NULL) + 300);
      if (!client) {
	SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
	goto error;
      }
      client->data.status |= SILC_IDLIST_STATUS_REGISTERED;
      client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
      client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    } else {
      /* We have the client already, update the data */
      
      SILC_LOG_DEBUG(("Updating client data"));
      
      /* Take nickname */
      if (name) {
	silc_parse_userfqdn(name, &nick, NULL);

	/* Remove the old cache entry */
	silc_idcache_del_by_context(global ? server->global_list->clients :
				    server->local_list->clients, client);

	silc_free(client->nickname);
	client->nickname = nick;
      }
      
      if (info) {
	silc_free(client->username);
	client->username = strdup(info);
      }

      client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
      client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
      
      if (name) {
	/* If client is global and is not on any channel then add that we'll
	   expire the entry after a while. */
	if (global && !silc_hash_table_count(client->channels) &&
	    server->server_type == SILC_SERVER)
	  expire = time(NULL) + 300;

	/* Add new cache entry */
	silc_idcache_add(global ? server->global_list->clients :
			 server->local_list->clients, nick, client->id, 
			 client, expire, NULL);
      }

      silc_free(client_id);
    }

    break;

  case SILC_ID_SERVER:
    if (!name)
      goto error;

    server_id = silc_id_payload_get_id(idp);
    if (!server_id)
      goto error;

    SILC_LOG_DEBUG(("Received server information"));

    server_entry = silc_idlist_find_server_by_id(server->local_list, 
						 server_id, FALSE, NULL);
    if (!server_entry)
      server_entry = silc_idlist_find_server_by_id(server->global_list, 
						   server_id, FALSE, NULL);
    if (!server_entry) {
      /* If router did not find such Server ID in its lists then this must
	 be bogus server or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER)
	goto error;
      
      /* We don't have that server anywhere, add it. */
      server_entry = silc_idlist_add_server(server->global_list, 
					    strdup(name), 0,
					    server_id, NULL, NULL);
      if (!server_entry) {
	silc_free(server_id);
	goto error;
      }
      server_entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;
      server_entry->data.status |= SILC_IDLIST_STATUS_RESOLVED;
      server_entry->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
      server_id = NULL;
    }

    silc_free(server_id);
    break;

  case SILC_ID_CHANNEL:
    if (!name)
      goto error;

    channel_id = silc_id_payload_get_id(idp);
    if (!channel_id)
      goto error;

    SILC_LOG_DEBUG(("Received channel information"));

    channel = silc_idlist_find_channel_by_name(server->local_list, 
					       name, NULL);
    if (!channel)
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 name, NULL);
    if (!channel) {
      /* If router did not find such Channel ID in its lists then this must
	 be bogus channel or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER)
	goto error;
      
      /* We don't have that server anywhere, add it. */
      channel = silc_idlist_add_channel(server->global_list, strdup(name),
					SILC_CHANNEL_MODE_NONE, channel_id, 
					server->router, NULL, NULL, 0);
      if (!channel) {
	silc_free(channel_id);
	goto error;
      }
      channel_id = NULL;
    }

    silc_free(channel_id);
    break;
  }

  silc_id_payload_free(idp);
  return TRUE;

 error:
  silc_id_payload_free(idp);
  return FALSE;
}

/* Received reply for forwarded IDENTIFY command. We have received the
   requested identify information now and we will cache it. After this we
   will call the pending command so that the requestee gets the information
   after all. */

SILC_SERVER_CMD_REPLY_FUNC(identify)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;

  COMMAND_CHECK_STATUS_LIST;

  if (!silc_server_command_reply_identify_save(cmd))
    goto out;

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

 out:
  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID &&
      cmd->sock->type == SILC_SOCKET_TYPE_ROUTER) {
    SilcClientEntry client;
    SilcUInt32 tmp_len;
    unsigned char *tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
    if (tmp) {
      SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (client_id) {
	SILC_LOG_DEBUG(("Received invalid client ID notification, deleting "
			"the entry from cache"));
	client = silc_idlist_find_client_by_id(server->global_list, 
					       client_id, FALSE, NULL);
	if (client) {
	  silc_server_remove_from_channels(server, NULL, client, TRUE, 
					   NULL, TRUE);
	  silc_idlist_del_client(server->global_list, client);
	}
	silc_free(client_id);
      }
    }
  }

  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_IDENTIFY);
  silc_server_command_reply_free(cmd);
}

/* Received reply fro INFO command. Cache the server and its information */

SILC_SERVER_CMD_REPLY_FUNC(info)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcServerEntry entry;
  SilcServerID *server_id;
  SilcUInt32 tmp_len;
  unsigned char *tmp, *name;

  COMMAND_CHECK_STATUS;

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp)
    goto out;
  server_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!server_id)
    goto out;

  /* Get the name */
  name = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp_len > 256)
    goto out;

  entry = silc_idlist_find_server_by_id(server->local_list, server_id, 
					FALSE, NULL);
  if (!entry) {
    entry = silc_idlist_find_server_by_id(server->global_list, server_id, 
					  FALSE, NULL);
    if (!entry) {
      /* Add the server to global list */
      server_id = silc_id_dup(server_id, SILC_ID_SERVER);
      entry = silc_idlist_add_server(server->global_list, name, 0,
				     server_id, NULL, NULL);
      if (!entry) {
	silc_free(server_id);
	goto out;
      }
      entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;
    }
  }

  /* Get the info string */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
  if (tmp_len > 256)
    tmp = NULL;

  entry->server_info = tmp ? strdup(tmp) : NULL;

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_INFO);
  silc_server_command_reply_free(cmd);
}

/* Received reply fro MOTD command. */

SILC_SERVER_CMD_REPLY_FUNC(motd)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcServerEntry entry = NULL;
  SilcServerID *server_id;
  SilcUInt32 tmp_len;
  unsigned char *tmp;

  COMMAND_CHECK_STATUS;

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp)
    goto out;
  server_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!server_id)
    goto out;

  entry = silc_idlist_find_server_by_id(server->local_list, server_id, 
					TRUE, NULL);
  if (!entry) {
    entry = silc_idlist_find_server_by_id(server->global_list, server_id, 
					  TRUE, NULL);
    if (!entry)
      goto out;
  }

  /* Get the motd */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp_len > 256)
    tmp = NULL;

  entry->motd = tmp;

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_MOTD);
  silc_server_command_reply_free(cmd);

  if (entry)
    entry->motd = NULL;
}

/* Received reply for forwarded JOIN command. Router has created or joined
   the client to the channel. We save some channel information locally
   for future use. */

SILC_SERVER_CMD_REPLY_FUNC(join)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcIDCacheEntry cache = NULL;
  SilcCommandStatus status;
  SilcChannelID *id;
  SilcClientID *client_id = NULL;
  SilcChannelEntry entry;
  SilcHmac hmac = NULL;
  SilcUInt32 id_len, len, list_count;
  unsigned char *id_string;
  char *channel_name, *tmp;
  SilcUInt32 mode, created;
  SilcBuffer keyp = NULL, client_id_list = NULL, client_mode_list = NULL;

  COMMAND_CHECK_STATUS;

  /* Get channel name */
  channel_name = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!channel_name)
    goto out;

  /* Get channel ID */
  id_string = silc_argument_get_arg_type(cmd->args, 3, &id_len);
  if (!id_string)
    goto out;

  /* Get client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (!tmp)
    goto out;
  client_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!client_id)
    goto out;

  /* Get mode mask */
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(mode, tmp);

  /* Get created boolean value */
  tmp = silc_argument_get_arg_type(cmd->args, 6, NULL);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(created, tmp);
  if (created != 0 && created != 1)
    goto out;

  /* Get channel key */
  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (tmp) {
    keyp = silc_buffer_alloc(len);
    silc_buffer_pull_tail(keyp, SILC_BUFFER_END(keyp));
    silc_buffer_put(keyp, tmp, len);
  }

  /* Parse the Channel ID */
  id = silc_id_payload_parse_id(id_string, id_len, NULL);
  if (!id)
    goto out;

  /* Get hmac */
  tmp = silc_argument_get_arg_type(cmd->args, 11, NULL);
  if (tmp) {
    if (!silc_hmac_alloc(tmp, NULL, &hmac))
      goto out;
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 12, &len);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 13, &len);
  if (!tmp)
    goto out;

  client_id_list = silc_buffer_alloc(len);
  silc_buffer_pull_tail(client_id_list, len);
  silc_buffer_put(client_id_list, tmp, len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 14, &len);
  if (!tmp)
    goto out;

  client_mode_list = silc_buffer_alloc(len);
  silc_buffer_pull_tail(client_mode_list, len);
  silc_buffer_put(client_mode_list, tmp, len);

  /* See whether we already have the channel. */
  entry = silc_idlist_find_channel_by_name(server->local_list, 
					   channel_name, &cache);
  if (!entry) {
    /* Add new channel */

    SILC_LOG_DEBUG(("Adding new [%s] channel %s id(%s)", 
		    (created == 0 ? "existing" : "created"), channel_name,
		    silc_id_render(id, SILC_ID_CHANNEL)));

    /* If the channel is found from global list we must move it to the
       local list. */
    entry = silc_idlist_find_channel_by_name(server->global_list,
					     channel_name, &cache);
    if (entry)
      silc_idlist_del_channel(server->global_list, entry);

    /* Add the channel to our local list. */
    entry = silc_idlist_add_channel(server->local_list, strdup(channel_name),
				    SILC_CHANNEL_MODE_NONE, id,
				    server->router, NULL, hmac, 0);
    if (!entry) {
      silc_free(id);
      goto out;
    }
    server->stat.my_channels++;
  } else {
    /* The entry exists. */

    /* If ID has changed, then update it to the cache too. */
    if (!SILC_ID_CHANNEL_COMPARE(entry->id, id))
      silc_idlist_replace_channel_id(server->local_list, entry->id, id);

    entry->disabled = FALSE;

    /* Remove the founder auth data if the mode is not set but we have
       them in the entry */
    if (!(mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) && entry->founder_key) {
      silc_pkcs_public_key_free(entry->founder_key);
      silc_free(entry->founder_passwd);
      entry->founder_passwd = NULL;
    }
  }

  if (entry->hmac_name && hmac) {
    silc_free(entry->hmac_name);
    entry->hmac_name = strdup(silc_hmac_get_name(hmac));
  }

  /* Get the ban list */
  tmp = silc_argument_get_arg_type(cmd->args, 8, &len);
  if (tmp) {
    silc_free(entry->ban_list);
    entry->ban_list = silc_memdup(tmp, len);
  }

  /* Get the invite list */
  tmp = silc_argument_get_arg_type(cmd->args, 9, &len);
  if (tmp) {
    silc_free(entry->invite_list);
    entry->invite_list = silc_memdup(tmp, len);
  }

  /* Get the topic */
  tmp = silc_argument_get_arg_type(cmd->args, 10, &len);
  if (tmp) {
    silc_free(entry->topic);
    entry->topic = strdup(tmp);
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
  if (keyp) {
    if (!(entry->mode & SILC_CHANNEL_MODE_PRIVKEY))
      silc_server_save_channel_key(server, keyp, entry);
    silc_buffer_free(keyp);
  }

  /* Save the users to the channel */
  silc_server_save_users_on_channel(server, cmd->sock, entry, 
				    client_id, client_id_list,
				    client_mode_list, list_count);

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_JOIN);
  silc_free(client_id);
  silc_server_command_reply_free(cmd);

  if (client_id_list)
    silc_buffer_free(client_id_list);
  if (client_mode_list)
    silc_buffer_free(client_mode_list);
}

/* Received reply to STATS command.  */

SILC_SERVER_CMD_REPLY_FUNC(stats)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBufferStruct buf;

  COMMAND_CHECK_STATUS;

  /* Get statistics structure */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (server->server_type == SILC_SERVER && tmp) {
    silc_buffer_set(&buf, tmp, tmp_len);
    silc_buffer_unformat(&buf,
			 SILC_STR_UI_INT(NULL),
			 SILC_STR_UI_INT(NULL),
			 SILC_STR_UI_INT(NULL),
			 SILC_STR_UI_INT(NULL),
			 SILC_STR_UI_INT(NULL),
			 SILC_STR_UI_INT(NULL),
			 SILC_STR_UI_INT(&server->stat.cell_clients),
			 SILC_STR_UI_INT(&server->stat.cell_channels),
			 SILC_STR_UI_INT(&server->stat.cell_servers),
			 SILC_STR_UI_INT(&server->stat.clients),
			 SILC_STR_UI_INT(&server->stat.channels),
			 SILC_STR_UI_INT(&server->stat.servers),
			 SILC_STR_UI_INT(&server->stat.routers),
			 SILC_STR_UI_INT(&server->stat.server_ops),
			 SILC_STR_UI_INT(&server->stat.router_ops),
			 SILC_STR_END);
  }

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_USERS);
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
  SilcUInt32 tmp_len;
  SilcUInt32 list_count;

  COMMAND_CHECK_STATUS;

  /* Get channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp)
    goto out;
  channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!channel_id)
    goto out;

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, 
					   channel_id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      SilcBuffer idp;

      if (server->server_type != SILC_SERVER)
	goto out;

      idp = silc_id_payload_encode(channel_id, SILC_ID_CHANNEL);
      silc_server_send_command(server, server->router->connection,
			       SILC_COMMAND_IDENTIFY, ++server->cmd_ident,
			       1, 5, idp->data, idp->len);
      silc_buffer_free(idp);

      /* Register pending command callback. After we've received the channel
	 information we will reprocess this command reply by re-calling this
	 USERS command reply callback. */
      silc_server_command_pending(server, SILC_COMMAND_IDENTIFY, 
				  server->cmd_ident,
				  silc_server_command_reply_users, cmd);
      return;
    }
  }

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

  /* Save the users to the channel */
  silc_server_save_users_on_channel(server, cmd->sock, channel, NULL,
				    client_id_list, client_mode_list, 
				    list_count);

  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_USERS);
  silc_free(channel_id);
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(getkey)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcClientEntry client = NULL;
  SilcServerEntry server_entry = NULL;
  SilcClientID *client_id = NULL;
  SilcServerID *server_id = NULL;
  SilcSKEPKType type;
  unsigned char *tmp, *pk;
  SilcUInt32 len;
  SilcUInt16 pk_len;
  SilcIDPayload idp = NULL;
  SilcIdType id_type;
  SilcPublicKey public_key = NULL;

  COMMAND_CHECK_STATUS;

  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;
  idp = silc_id_payload_parse(tmp, len);
  if (!idp)
    goto out;

  /* Get the public key payload */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!tmp)
    goto out;

  /* Decode the public key */

  SILC_GET16_MSB(pk_len, tmp);
  SILC_GET16_MSB(type, tmp + 2);
  pk = tmp + 4;

  if (type != SILC_SKE_PK_TYPE_SILC)
    goto out;

  if (!silc_pkcs_public_key_decode(pk, pk_len, &public_key))
    goto out;

  id_type = silc_id_payload_get_type(idp);
  if (id_type == SILC_ID_CLIENT) {
    client_id = silc_id_payload_get_id(idp);

    client = silc_idlist_find_client_by_id(server->local_list, client_id,
					   TRUE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->global_list, 
					     client_id, TRUE, NULL);
      if (!client)
	goto out;
    }

    client->data.public_key = public_key;
  } else if (id_type == SILC_ID_SERVER) {
    server_id = silc_id_payload_get_id(idp);

    server_entry = silc_idlist_find_server_by_id(server->local_list, server_id,
						 TRUE, NULL);
    if (!server_entry) {
      server_entry = silc_idlist_find_server_by_id(server->global_list, 
						   server_id, TRUE, NULL);
      if (!server_entry)
	goto out;
    }

    server_entry->data.public_key = public_key;
  } else {
    goto out;
  }

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_GETKEY);
  if (idp)
    silc_id_payload_free(idp);
  silc_free(client_id);
  silc_free(server_id);
  if (public_key)
    silc_pkcs_public_key_free(public_key);
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(list)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcChannelID *channel_id = NULL;
  SilcChannelEntry channel;
  SilcIDCacheEntry cache;
  SilcUInt32 len;
  unsigned char *tmp, *name, *topic;
  SilcUInt32 usercount = 0;
  bool global_list = FALSE;

  COMMAND_CHECK_STATUS_LIST;

  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto out;

  name = silc_argument_get_arg_type(cmd->args, 3, NULL);
  topic = silc_argument_get_arg_type(cmd->args, 4, NULL);
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(usercount, tmp);

  /* Add the channel entry if we do not have it already */
  channel = silc_idlist_find_channel_by_name(server->local_list, 
					     name, &cache);
  if (!channel) {
    channel = silc_idlist_find_channel_by_name(server->global_list, 
					       name, &cache);
    global_list = TRUE;
  }
  if (!channel) {
    /* If router did not find such channel in its lists then this must
       be bogus channel or some router in the net is buggy. */
    if (server->server_type != SILC_SERVER)
      goto out;
    
    channel = silc_idlist_add_channel(server->global_list, strdup(name),
				      SILC_CHANNEL_MODE_NONE, channel_id, 
				      server->router, NULL, NULL, 
				      time(NULL) + 60);
    if (!channel)
      goto out;
    channel_id = NULL;
  } else {
    /* Found, update expiry */
    if (global_list && server->server_type == SILC_SERVER)
      cache->expire = time(NULL) + 60;
  }

  channel->user_count = usercount;

  if (topic) {
    silc_free(channel->topic);
    channel->topic = strdup(topic);
  }

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

  /* Now purge all old entries from the global list, otherwise we'll might
     have non-existent entries for long periods of time in the cache. */
  silc_idcache_purge(server->global_list->channels);

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_LIST);
  silc_free(channel_id);
  silc_server_command_reply_free(cmd);
}
