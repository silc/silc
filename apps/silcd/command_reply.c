/*

  command_reply.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005, 2007 Pekka Riikonen

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
#include "command_reply.h"

/* All functions that call the COMMAND_CHECK_STATUS macros must have
   out: and err: goto labels. */

#define COMMAND_CHECK_STATUS						\
do {									\
  SILC_LOG_DEBUG(("Start"));						\
  if (!silc_command_get_status(cmd->payload, &status, &error)) {	\
    if (SILC_STATUS_IS_ERROR(status))					\
      goto out;								\
    if (status == SILC_STATUS_LIST_END)					\
      goto out;								\
    goto err;								\
  }									\
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
  SILC_SERVER_CMD_REPLY(watch, WATCH),
  SILC_SERVER_CMD_REPLY(ping, PING),

  { NULL, 0 },
};

/* Process received command reply. */

void silc_server_command_reply_process(SilcServer server,
				       SilcPacketStream sock,
				       SilcBuffer buffer)
{
  SilcIDListData idata = silc_packet_get_context(sock);
  SilcServerCommandReply *cmd;
  SilcServerCommandReplyContext ctx;
  SilcCommandPayload payload;
  SilcCommand command;

  SILC_LOG_DEBUG(("Start"));

  /* Get command reply payload from packet */
  payload = silc_command_payload_parse(buffer->data, silc_buffer_len(buffer));
  if (!payload) {
    /* Silently ignore bad reply packet */
    SILC_LOG_DEBUG(("Bad command reply packet"));
    return;
  }

  /* Allocate command reply context. This must be free'd by the
     command reply routine receiving it. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->server = server;
  ctx->sock = sock;
  ctx->payload = payload;
  ctx->args = silc_command_get_args(ctx->payload);
  ctx->ident = silc_command_get_ident(ctx->payload);
  command = silc_command_get(ctx->payload);
  silc_packet_stream_ref(sock);

  /* Client is not allowed to send reply to all commands */
  if (idata->conn_type == SILC_CONN_CLIENT &&
      command != SILC_COMMAND_WHOIS) {
    silc_server_command_reply_free(ctx);
    return;
  }

  /* Check for pending commands and mark to be exeucted */
  ctx->callbacks =
    silc_server_command_pending_check(server, command,
				      ctx->ident, &ctx->callbacks_count);

  /* Execute command reply */
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
      silc_packet_stream_unref(cmd->sock);
    silc_free(cmd->callbacks);
    silc_free(cmd);
  }
}

static void
silc_server_command_process_error(SilcServerCommandReplyContext cmd,
				  SilcStatus error)
{
  SilcServer server = cmd->server;
  SilcIDListData idata = silc_packet_get_context(cmd->sock);

  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID &&
      idata->conn_type == SILC_CONN_ROUTER) {
    SilcClientEntry client;
    SilcID id;
    if (silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id,
				  NULL)) {
      SILC_LOG_DEBUG(("Received invalid client ID notification, deleting "
		      "the entry from cache"));
      client = silc_idlist_find_client_by_id(server->global_list,
					     SILC_ID_GET_ID(id), FALSE, NULL);
      if (!client)
	return;

      silc_server_remove_from_channels(server, NULL, client, TRUE,
				       NULL, TRUE, FALSE);
      silc_dlist_del(server->expired_clients, client);
      silc_idlist_del_data(client);
      silc_idlist_del_client(server->global_list, client);
    }
  }
}

/* Caches the received WHOIS information. */

static char
silc_server_command_reply_whois_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  unsigned char *id_data, *umodes;
  char *nickname, *username, *realname, *tmp;
  unsigned char *fingerprint;
  SilcID id;
  SilcClientEntry client;
  char global = FALSE;
  char nick[128 + 1], servername[256 + 1], uname[128 + 1];
  SilcUInt32 mode = 0, len, len2, id_len, flen;
  const char *hostname, *ip;

  silc_socket_stream_get_info(silc_packet_stream_get_stream(cmd->sock),
			      NULL, &hostname, &ip, NULL);

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!id_data || !nickname || !username || !realname)
    return FALSE;

  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);

  if (!silc_id_payload_parse_id(id_data, id_len, &id))
    return FALSE;

  fingerprint = silc_argument_get_arg_type(cmd->args, 9, &flen);

  /* Check if we have this client cached already. */

  client = silc_idlist_find_client_by_id(server->local_list,
					 SILC_ID_GET_ID(id),
					 FALSE, NULL);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list,
					   SILC_ID_GET_ID(id),
					   FALSE, NULL);
    global = TRUE;
  }

  if (!client) {
    /* If router did not find such Client ID in its lists then this must
       be bogus client or some router in the net is buggy. */
    if (server->server_type != SILC_SERVER)
      return FALSE;

    /* Take hostname out of nick string if it includes it. */
    silc_parse_userfqdn(nickname, nick, sizeof(nick), servername,
			sizeof(servername));

    /* We don't have that client anywhere, add it. The client is added
       to global list since server didn't have it in the lists so it must be
       global. This will check for valid nickname and username strings. */
    client = silc_idlist_add_client(server->global_list,
				    strdup(nick), username,
				    strdup(realname),
				    silc_id_dup(SILC_ID_GET_ID(id),
						SILC_ID_CLIENT),
				    silc_packet_get_context(cmd->sock),
				    NULL);
    if (!client) {
      SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
      return FALSE;
    }

    client->data.status |=
      (SILC_IDLIST_STATUS_REGISTERED | SILC_IDLIST_STATUS_RESOLVED);
    client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    client->mode = mode;
    client->servername = servername[0] ? strdup(servername) : NULL;
  } else {
    /* We have the client already, update the data */

    SILC_LOG_DEBUG(("Updating client data"));

    /* Check nickname */
    silc_parse_userfqdn(nickname, nick, sizeof(nick), servername,
			sizeof(servername));
    nickname = silc_identifier_check(nick, strlen(nick), SILC_STRING_UTF8,
				     128, NULL);
    if (!nickname) {
      SILC_LOG_ERROR(("Malformed nickname '%s' received in WHOIS reply "
		      "from %s",
		      hostname ? hostname : "", nick));
      return FALSE;
    }

    /* Check username */
    silc_parse_userfqdn(username, uname, sizeof(uname), NULL, 0);
    if (!silc_identifier_verify(uname, strlen(uname), SILC_STRING_UTF8, 128)) {
      SILC_LOG_ERROR(("Malformed username '%s' received in WHOIS reply "
		      "from %s",
		      hostname ? hostname : "", tmp));
      return FALSE;
    }

    /* Update entry */
    silc_idcache_update_by_context(global ? server->global_list->clients :
				   server->local_list->clients, client, NULL,
				   nickname, TRUE);

    silc_free(client->nickname);
    silc_free(client->username);
    silc_free(client->userinfo);
    silc_free(client->servername);

    client->nickname = strdup(nick);
    client->username = strdup(username);
    client->userinfo = strdup(realname);
    client->servername = servername[0] ? strdup(servername) : NULL;
    client->mode = mode;
    client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
    client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
  }

  /* Save channel list if it was sent to us */
  if (server->server_type == SILC_SERVER) {
    tmp = silc_argument_get_arg_type(cmd->args, 6, &len);
    umodes = silc_argument_get_arg_type(cmd->args, 10, &len2);
    if (tmp && umodes) {
      SilcBufferStruct channels_buf, umodes_buf;
      silc_buffer_set(&channels_buf, tmp, len);
      silc_buffer_set(&umodes_buf, umodes, len2);
      silc_server_save_user_channels(server, cmd->sock, client, &channels_buf,
				     &umodes_buf);
    } else {
      silc_server_save_user_channels(server, cmd->sock, client, NULL, NULL);
    }
  }

  if (fingerprint && flen == sizeof(client->data.fingerprint))
    memcpy(client->data.fingerprint, fingerprint, flen);

  /* Take Requested Attributes if set. */
  tmp = silc_argument_get_arg_type(cmd->args, 11, &len);
  if (tmp) {
    silc_free(client->attrs);
    client->attrs = silc_memdup(tmp, len);
    client->attrs_len = len;

    /* Try to take public key from attributes if present and we don't have
       the key already.  Do this only on normal server.  Routers do GETKEY
       for all clients anyway. */
    if (server->server_type != SILC_ROUTER && !client->data.public_key) {
      SilcAttributePayload attr;
      SilcAttributeObjPk pk;
      unsigned char f[SILC_HASH_MAXLEN];
      SilcDList attrs = silc_attribute_payload_parse(tmp, len);

      SILC_LOG_DEBUG(("Take client public key from attributes"));

      if (attrs) {
	silc_dlist_start(attrs);
	while ((attr = silc_dlist_get(attrs)) != SILC_LIST_END) {
	  if (silc_attribute_get_attribute(attr) ==
	      SILC_ATTRIBUTE_USER_PUBLIC_KEY) {

	    if (!silc_attribute_get_object(attr, &pk, sizeof(pk)))
	      continue;

	    /* Take only SILC public keys */
	    if (strcmp(pk.type, "silc-rsa")) {
	      silc_free(pk.type);
	      silc_free(pk.data);
	      continue;
	    }

	    /* Verify that the server provided fingerprint matches the key */
	    silc_hash_make(server->sha1hash, pk.data, pk.data_len, f);
	    if (memcmp(f, client->data.fingerprint, sizeof(f))) {
	      silc_free(pk.type);
	      silc_free(pk.data);
	      continue;
	    }

	    /* Save the public key. */
	    if (!silc_pkcs_public_key_alloc(SILC_PKCS_SILC,
					    pk.data, pk.data_len,
					    &client->data.public_key)) {
	      silc_free(pk.type);
	      silc_free(pk.data);
	      continue;
	    }

	    SILC_LOG_DEBUG(("Saved client public key from attributes"));

	    /* Add client's public key to repository */
	    if (!silc_server_get_public_key_by_client(server, client, NULL))
	      silc_skr_add_public_key_simple(server->repository,
					     client->data.public_key,
					     SILC_SKR_USAGE_IDENTIFICATION,
					     client, NULL);

	    silc_free(pk.type);
	    silc_free(pk.data);
	    break;
	  }
	}

	silc_attribute_payload_list_free(attrs);
      }
    }
  }

  return TRUE;
}

/* Handle requested attributes reply in WHOIS from client */

static char
silc_server_command_reply_whois_save_client(SilcServerCommandReplyContext cmd)
{
  unsigned char *tmp;
  SilcUInt32 len;
  SilcClientEntry client = silc_packet_get_context(cmd->sock);

  /* Take Requested Attributes if set. */
  tmp = silc_argument_get_arg_type(cmd->args, 11, &len);
  if (tmp && client) {
    silc_free(client->attrs);
    client->attrs = silc_memdup(tmp, len);
    client->attrs_len = len;
  }

  client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;

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
  SilcIDListData idata = silc_packet_get_context(cmd->sock);
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

  if (idata->conn_type != SILC_CONN_CLIENT) {
    if (!silc_server_command_reply_whois_save(cmd))
      goto out;
  } else {
    if (!silc_server_command_reply_whois_save_client(cmd))
      goto out;
  }

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

 out:
  silc_server_command_process_error(cmd, error);
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_WHOIS);
  silc_server_command_reply_free(cmd);
  return;

 err:
  silc_server_command_process_error(cmd, error);
  silc_server_command_reply_free(cmd);
}

/* Caches the received WHOWAS information for a short period of time. */

static char
silc_server_command_reply_whowas_save(SilcServerCommandReplyContext cmd)
{
  SilcServer server = cmd->server;
  SilcUInt32 len, id_len;
  unsigned char *id_data;
  char *nickname, *username, *realname;
  SilcID id;
  SilcClientEntry client;
  SilcIDCacheEntry cache = NULL;
  char nick[128 + 1], servername[256 + 1], uname[128 + 1];
  int global = FALSE;
  const char *hostname, *ip;

  silc_socket_stream_get_info(silc_packet_stream_get_stream(cmd->sock),
			      NULL, &hostname, &ip, NULL);

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (!id_data || !nickname || !username)
    return FALSE;

  realname = silc_argument_get_arg_type(cmd->args, 5, &len);

  if (!silc_id_payload_parse_id(id_data, id_len, &id))
    return FALSE;

  /* Check if we have this client cached already. */

  client = silc_idlist_find_client_by_id(server->local_list,
					 SILC_ID_GET_ID(id),
					 FALSE, &cache);
  if (!client) {
    client = silc_idlist_find_client_by_id(server->global_list,
					   SILC_ID_GET_ID(id),
					   FALSE, &cache);
    global = TRUE;
  }

  if (!client) {
    /* If router did not find such Client ID in its lists then this must
       be bogus client or some router in the net is buggy. */
    if (server->server_type != SILC_SERVER)
      return FALSE;

    /* Take hostname out of nick string if it includes it. */
    silc_parse_userfqdn(nickname, nick, sizeof(nick), servername,
			sizeof(servername));

    /* We don't have that client anywhere, add it. The client is added
       to global list since server didn't have it in the lists so it must be
       global. */
    client = silc_idlist_add_client(server->global_list,
				    strdup(nick), username,
				    strdup(realname),
				    silc_id_dup(SILC_ID_GET_ID(id),
						SILC_ID_CLIENT),
				    silc_packet_get_context(cmd->sock), NULL);
    if (!client) {
      SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
      return FALSE;
    }

    client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
    client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
    client->servername = servername[0] ? strdup(servername) : NULL;
  } else {
    /* We have the client already, update the data */

    /* Check nickname */
    silc_parse_userfqdn(nickname, nick, sizeof(nick), servername,
			sizeof(servername));
    nickname = silc_identifier_check(nick, strlen(nick), SILC_STRING_UTF8,
				     128, NULL);
    if (!nickname) {
      SILC_LOG_ERROR(("Malformed nickname '%s' received in WHOWAS reply "
		      "from %s",
		      nick, hostname ? hostname : ""));
      return FALSE;
    }

    /* Check username */
    silc_parse_userfqdn(username, uname, sizeof(uname), NULL, 0);
    if (!silc_identifier_verify(uname, strlen(uname), SILC_STRING_UTF8, 128))
      return FALSE;

    silc_free(client->nickname);
    silc_free(client->username);
    silc_free(client->servername);

    client->nickname = strdup(nick);
    client->username = strdup(username);
    client->servername = servername[0] ? strdup(servername) : NULL;
    client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
    client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;

    /* Update cache entry */
    silc_idcache_update_by_context(global ? server->global_list->clients :
				   server->local_list->clients, client, NULL,
				   nickname, TRUE);
  }

  /* If client is global and is not on any channel then add that we'll
     expire the entry after a while. */
  if (global) {
    client = silc_idlist_find_client_by_id(server->global_list, client->id,
					   FALSE, &cache);
    if (client && !silc_hash_table_count(client->channels)) {
      client->data.created = silc_time();
      silc_dlist_del(server->expired_clients, client);
      silc_dlist_add(server->expired_clients, client);
    }
  }

  return TRUE;
}

/* Received reply for WHOWAS command. Cache the client information only for
   a short period of time. */

SILC_SERVER_CMD_REPLY_FUNC(whowas)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

  if (!silc_server_command_reply_whowas_save(cmd))
    goto out;

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

 out:
  silc_server_command_process_error(cmd, error);
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_WHOWAS);
  silc_server_command_reply_free(cmd);
  return;

 err:
  silc_server_command_process_error(cmd, error);
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
  SilcClientID client_id;
  SilcServerID server_id;
  SilcChannelID*channel_id;
  SilcClientEntry client;
  SilcServerEntry server_entry;
  SilcChannelEntry channel;
  char global = FALSE;
  char nick[128 + 1];
  SilcIDPayload idp = NULL;
  SilcIdType id_type;

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
    if (!silc_id_payload_get_id(idp, &client_id, sizeof(client_id)))
      goto error;

    SILC_LOG_DEBUG(("Received client information"));

    client = silc_idlist_find_client_by_id(server->local_list,
					   &client_id, FALSE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->global_list, &client_id,
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
	silc_parse_userfqdn(name, nick, sizeof(nick), NULL, 0);

      /* We don't have that client anywhere, add it. The client is added
	 to global list since server didn't have it in the lists so it must be
	 global. */
      client = silc_idlist_add_client(server->global_list,
				      nick[0] ? nick : NULL, info, NULL,
				      silc_id_dup(&client_id, SILC_ID_CLIENT),
				      silc_packet_get_context(cmd->sock),
				      NULL);
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
	silc_parse_userfqdn(name, nick, sizeof(nick), NULL, 0);

	/* Check nickname */
	name = silc_identifier_check(nick, strlen(nick), SILC_STRING_UTF8,
				     128, NULL);
	if (!name) {
	  SILC_LOG_ERROR(("Malformed nickname '%s' received in IDENTIFY "
			  "reply ", nick));
	  return FALSE;
	}

	silc_free(client->nickname);
	client->nickname = strdup(nick);

	/* Update the context */
	silc_idcache_update_by_context(global ? server->global_list->clients :
				       server->local_list->clients, client,
				       NULL, name, TRUE);
      }

      if (info) {
	silc_free(client->username);
	client->username = strdup(info);
      }

      client->data.status |= SILC_IDLIST_STATUS_RESOLVED;
      client->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    }

    break;

  case SILC_ID_SERVER:
    if (!name)
      goto error;

    if (!silc_id_payload_get_id(idp, &server_id, sizeof(server_id)))
      goto error;

    SILC_LOG_DEBUG(("Received server information"));

    server_entry = silc_idlist_find_server_by_id(server->local_list,
						 &server_id, FALSE, NULL);
    if (!server_entry)
      server_entry = silc_idlist_find_server_by_id(server->global_list,
						   &server_id, FALSE, NULL);
    if (!server_entry) {
      /* If router did not find such Server ID in its lists then this must
	 be bogus server or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER)
	goto error;

      /* We don't have that server anywhere, add it. */
      server_entry = silc_idlist_add_server(server->global_list,
					    strdup(name), 0,
					    silc_id_dup(&server_id,
							SILC_ID_SERVER),
					    server->router,
					    SILC_PRIMARY_ROUTE(server));
      if (!server_entry)
	goto error;

      server_entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;
      server_entry->data.status |= SILC_IDLIST_STATUS_RESOLVED;
      server_entry->data.status &= ~SILC_IDLIST_STATUS_RESOLVING;
    }

    break;

  case SILC_ID_CHANNEL:
    if (!name)
      goto error;

    if (!silc_id_payload_get_id(idp, &channel_id, sizeof(channel_id)))
      goto error;

    SILC_LOG_DEBUG(("Received channel information"));

    /* Check channel name */
    info = silc_channel_name_check(name, strlen(name), SILC_STRING_UTF8,
				   256, NULL);
    if (!info)
      goto error;

    channel = silc_idlist_find_channel_by_name(server->local_list,
					       info, NULL);
    if (!channel)
      channel = silc_idlist_find_channel_by_name(server->global_list,
						 info, NULL);
    if (!channel) {
      /* If router did not find such Channel ID in its lists then this must
	 be bogus channel or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER) {
	silc_free(info);
	goto error;
      }

      /* We don't have that channel anywhere, add it. */
      channel = silc_idlist_add_channel(server->global_list, strdup(name),
					SILC_CHANNEL_MODE_NONE,
					silc_id_dup(&channel_id,
						    SILC_ID_CHANNEL),
					server->router, NULL, NULL, 0);
      if (!channel) {
	silc_free(info);
	goto error;
      }
      silc_free(info);
    }

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
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

  if (!silc_server_command_reply_identify_save(cmd))
    goto out;

  /* Pending callbacks are not executed if this was an list entry */
  if (status != SILC_STATUS_OK &&
      status != SILC_STATUS_LIST_END) {
    silc_server_command_reply_free(cmd);
    return;
  }

 out:
  silc_server_command_process_error(cmd, error);
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_IDENTIFY);
  silc_server_command_reply_free(cmd);
  return;

 err:
  silc_server_command_process_error(cmd, error);
  silc_server_command_reply_free(cmd);
}

/* Received reply fro INFO command. Cache the server and its information */

SILC_SERVER_CMD_REPLY_FUNC(info)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcStatus status, error;
  SilcServerEntry entry;
  SilcID id;
  SilcUInt32 tmp_len;
  unsigned char *tmp, *name;

  COMMAND_CHECK_STATUS;

  /* Get Server ID */
  if (!silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get the name */
  name = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!name)
    goto out;

  entry = silc_idlist_find_server_by_id(server->local_list,
					SILC_ID_GET_ID(id),
					FALSE, NULL);
  if (!entry) {
    entry = silc_idlist_find_server_by_id(server->global_list,
					  SILC_ID_GET_ID(id),
					  FALSE, NULL);
    if (!entry) {
      /* Add the server to global list */
      entry = silc_idlist_add_server(server->global_list, strdup(name), 0,
				     silc_id_dup(SILC_ID_GET_ID(id),
						 SILC_ID_SERVER),
				     silc_packet_get_context(cmd->sock),
				     cmd->sock);
      if (!entry)
	goto out;

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
 err:
  silc_server_command_reply_free(cmd);
}

/* Received reply fro MOTD command. */

SILC_SERVER_CMD_REPLY_FUNC(motd)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcStatus status, error;
  SilcServerEntry entry = NULL;
  SilcID id;
  SilcUInt32 tmp_len;
  unsigned char *tmp;

  COMMAND_CHECK_STATUS;

  /* Get Server ID */
  if (!silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  entry = silc_idlist_find_server_by_id(server->local_list,
					SILC_ID_GET_ID(id),
					TRUE, NULL);
  if (!entry) {
    entry = silc_idlist_find_server_by_id(server->global_list,
					  SILC_ID_GET_ID(id),
					  TRUE, NULL);
    if (!entry) {
      SilcBuffer buffer;

      /* If router did not find such Server ID in its lists then this must
	 be bogus client or some router in the net is buggy. */
      if (server->server_type != SILC_SERVER)
	goto out;

      /* Statistics */
      cmd->server->stat.commands_sent++;

      /* entry isn't known so we IDENTIFY it. otherwise the
         silc_server_command_motd won't know about it and tell
         the client that there is no such server */
      tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
      buffer = silc_command_payload_encode_va(SILC_COMMAND_IDENTIFY,
	  				      ++server->cmd_ident, 5,
					      1, NULL, 0, 2, NULL, 0,
					      3, NULL, 0, 4, NULL, 0,
					      5, tmp, tmp_len);
      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
	  		      SILC_PACKET_COMMAND, 0, buffer->data,
			      silc_buffer_len(buffer));
      silc_server_command_pending(server, SILC_COMMAND_IDENTIFY,
	  			  server->cmd_ident,
				  silc_server_command_reply_motd,
				  cmd);
      silc_buffer_free(buffer);
      return;
    }
  }

  /* Get the motd */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (tmp_len > 256)
    tmp = NULL;

  entry->motd = tmp;

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_MOTD);
 err:
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
  SilcStatus status, error;
  SilcID id, id2;
  SilcChannelEntry entry;
  SilcHmac hmac = NULL;
  SilcUInt32 len, list_count;
  char *channel_name, *channel_namec = NULL, *tmp;
  SilcUInt32 mode, created;
  SilcBuffer keyp = NULL, client_id_list = NULL, client_mode_list = NULL;
  SilcPublicKey founder_key = NULL;

  COMMAND_CHECK_STATUS;

  /* Get channel name */
  channel_name = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!channel_name)
    goto out;

  /* Get channel ID */
  if (!silc_argument_get_decoded(cmd->args, 3, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get client ID */
  if (!silc_argument_get_decoded(cmd->args, 4, SILC_ARGUMENT_ID, &id2, NULL))
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
    silc_buffer_pull_tail(keyp, silc_buffer_truelen(keyp));
    silc_buffer_put(keyp, tmp, len);
  }

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

  /* Get founder key */
  tmp = silc_argument_get_arg_type(cmd->args, 15, &len);
  if (tmp)
    silc_public_key_payload_decode(tmp, len, &founder_key);

  /* See whether we already have the channel. */
  channel_namec = silc_channel_name_check(channel_name, strlen(channel_name),
					  SILC_STRING_UTF8, 256, NULL);
  if (!channel_namec)
    goto out;
  entry = silc_idlist_find_channel_by_name(server->local_list,
					   channel_namec, &cache);
  if (!entry) {
    /* Add new channel */

    SILC_LOG_DEBUG(("Adding new [%s] channel %s id(%s)",
		    (created == 0 ? "existing" : "created"), channel_name,
		    silc_id_render(SILC_ID_GET_ID(id), SILC_ID_CHANNEL)));

    /* If the channel is found from global list we must move it to the
       local list. */
    entry = silc_idlist_find_channel_by_name(server->global_list,
					     channel_namec, &cache);
    if (entry)
      silc_idlist_del_channel(server->global_list, entry);

    /* Add the channel to our local list. */
    entry = silc_idlist_add_channel(server->local_list, strdup(channel_name),
				    SILC_CHANNEL_MODE_NONE,
				    silc_id_dup(SILC_ID_GET_ID(id),
						SILC_ID_CHANNEL),
				    server->router, NULL, NULL, hmac);
    if (!entry)
      goto out;

    hmac = NULL;
    server->stat.my_channels++;
    server->stat.channels++;
  } else {
    /* The entry exists. */

    /* If ID has changed, then update it to the cache too. */
    if (!SILC_ID_CHANNEL_COMPARE(entry->id, SILC_ID_GET_ID(id)))
      silc_idlist_replace_channel_id(server->local_list, entry->id,
				     SILC_ID_GET_ID(id));

    entry->disabled = FALSE;

    /* Remove the founder auth data if the mode is not set but we have
       them in the entry */
    if (!(mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) && entry->founder_key) {
      silc_pkcs_public_key_free(entry->founder_key);
      entry->founder_key = NULL;
    }
  }

  if (founder_key) {
    if (entry->founder_key)
      silc_pkcs_public_key_free(entry->founder_key);
    entry->founder_key = founder_key;
    founder_key = NULL;
  }

  if (entry->hmac_name && (hmac || (!hmac && entry->hmac))) {
    silc_free(entry->hmac_name);
    entry->hmac_name = strdup(silc_hmac_get_name(hmac ? hmac : entry->hmac));
  }

  /* Get the ban list */
  tmp = silc_argument_get_arg_type(cmd->args, 8, &len);
  if (tmp && len > 2) {
    SilcArgumentPayload iargs;
    SilcUInt16 iargc;
    SILC_GET16_MSB(iargc, tmp);
    iargs = silc_argument_payload_parse(tmp + 2, len - 2, iargc);
    if (iargs) {
      /* Delete old ban list */
      if (entry->ban_list)
	silc_hash_table_free(entry->ban_list);
      entry->ban_list =
	silc_hash_table_alloc(0, silc_hash_ptr,
			      NULL, NULL, NULL,
			      silc_server_inviteban_destruct, entry, TRUE);

      /* Add new ban list */
      silc_server_inviteban_process(server, entry->ban_list, 0, iargs);
      silc_argument_payload_free(iargs);
    }
  }

  /* Get the invite list */
  tmp = silc_argument_get_arg_type(cmd->args, 9, &len);
  if (tmp && len > 2) {
    SilcArgumentPayload iargs;
    SilcUInt16 iargc;
    SILC_GET16_MSB(iargc, tmp);
    iargs = silc_argument_payload_parse(tmp + 2, len - 2, iargc);
    if (iargs) {
      /* Delete old invite list */
      if (entry->invite_list)
	silc_hash_table_free(entry->invite_list);
      entry->invite_list =
	silc_hash_table_alloc(0, silc_hash_ptr,
			      NULL, NULL, NULL,
			      silc_server_inviteban_destruct, entry, TRUE);

      /* Add new invite list */
      silc_server_inviteban_process(server, entry->invite_list, 0, iargs);
      silc_argument_payload_free(iargs);
    }
  }

  /* Get the topic */
  tmp = silc_argument_get_arg_type(cmd->args, 10, &len);
  if (tmp) {
    silc_free(entry->topic);
    entry->topic = strdup(tmp);
  }

  /* Get channel public key list */
  tmp = silc_argument_get_arg_type(cmd->args, 16, &len);
  if (tmp && server->server_type != SILC_ROUTER)
    silc_server_set_channel_pk_list(server, NULL, entry, tmp, len);

  /* The the user limit */
  tmp = silc_argument_get_arg_type(cmd->args, 17, &len);
  if (tmp && len == 4)
    SILC_GET32_MSB(entry->user_limit, tmp);

  /* If channel was not created we know there is global users on the
     channel. */
  entry->global_users = (created == 0 ? TRUE : FALSE);

  /* If channel was just created the mask must be zero */
  if (!entry->global_users && mode)
    mode = 0;

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
				    SILC_ID_GET_ID(id2), client_id_list,
				    client_mode_list, list_count);
  entry->users_resolved = TRUE;

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_JOIN);
 err:
  silc_free(channel_namec);
  if (hmac)
    silc_hmac_free(hmac);
  silc_server_command_reply_free(cmd);

  if (founder_key)
    silc_pkcs_public_key_free(founder_key);
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
  SilcStatus status, error;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBufferStruct buf;

  COMMAND_CHECK_STATUS;

  /* Get statistics structure */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (server->server_type != SILC_ROUTER && tmp) {
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
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_STATS);
 err:
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(users)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcStatus status, error;
  SilcChannelEntry channel;
  SilcID id;
  SilcBuffer client_id_list;
  SilcBuffer client_mode_list;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcUInt32 list_count;

  COMMAND_CHECK_STATUS;

  /* Get channel ID */
  if (!silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list,
					   SILC_ID_GET_ID(id), NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list,
					     SILC_ID_GET_ID(id), NULL);
    if (!channel) {
      SilcBuffer idp;

      if (server->server_type != SILC_SERVER)
	goto out;

      idp = silc_id_payload_encode(SILC_ID_GET_ID(id), SILC_ID_CHANNEL);
      silc_server_send_command(server, SILC_PRIMARY_ROUTE(server),
			       SILC_COMMAND_IDENTIFY, ++server->cmd_ident,
			       1, 5, idp->data, silc_buffer_len(idp));
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

  channel->global_users = silc_server_channel_has_global(channel);
  channel->users_resolved = TRUE;

  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_USERS);
 err:
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(getkey)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcStatus status, error;
  SilcClientEntry client = NULL;
  SilcServerEntry server_entry = NULL;
  SilcClientID client_id;
  SilcServerID server_id;
  unsigned char *tmp;
  SilcUInt32 len;
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

  /* Decode the public key payload */
  if (!silc_public_key_payload_decode(tmp, len, &public_key))
    goto out;

  id_type = silc_id_payload_get_type(idp);
  if (id_type == SILC_ID_CLIENT) {
    silc_id_payload_get_id(idp, &client_id, sizeof(client_id));

    client = silc_idlist_find_client_by_id(server->local_list, &client_id,
					   TRUE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->global_list,
					     &client_id, TRUE, NULL);
      if (!client)
	goto out;
    }

    if (!client->data.public_key) {
      /* Add client's public key to repository */
      if (!silc_server_get_public_key_by_client(server, client, NULL))
	silc_skr_add_public_key_simple(server->repository,
				       public_key,
				       SILC_SKR_USAGE_IDENTIFICATION,
				       client, NULL);
      client->data.public_key = public_key;
      public_key = NULL;
    }
  } else if (id_type == SILC_ID_SERVER) {
    silc_id_payload_get_id(idp, &server_id, sizeof(server_id));

    server_entry = silc_idlist_find_server_by_id(server->local_list,
						 &server_id, TRUE, NULL);
    if (!server_entry) {
      server_entry = silc_idlist_find_server_by_id(server->global_list,
						   &server_id, TRUE, NULL);
      if (!server_entry)
	goto out;
    }

    server_entry->data.public_key = public_key;
    public_key = NULL;
  } else {
    goto out;
  }

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_GETKEY);
  if (idp)
    silc_id_payload_free(idp);
  if (public_key)
    silc_pkcs_public_key_free(public_key);
 err:
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(list)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcStatus status, error;
  SilcID id;
  SilcChannelEntry channel;
  SilcIDCacheEntry cache;
  unsigned char *tmp, *name, *namec = NULL, *topic;
  SilcUInt32 usercount = 0;
  SilcBool global_list = FALSE;

  COMMAND_CHECK_STATUS;

  if (!silc_argument_get_decoded(cmd->args, 2, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  name = silc_argument_get_arg_type(cmd->args, 3, NULL);
  topic = silc_argument_get_arg_type(cmd->args, 4, NULL);
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(usercount, tmp);

  namec = silc_channel_name_check(name, strlen(name), SILC_STRING_UTF8,
				  256, NULL);
  if (!namec)
    goto out;

  /* Add the channel entry if we do not have it already */
  channel = silc_idlist_find_channel_by_name(server->local_list,
					     namec, &cache);
  if (!channel) {
    channel = silc_idlist_find_channel_by_name(server->global_list,
					       namec, &cache);
    global_list = TRUE;
  }
  if (!channel) {
    /* If router did not find such channel in its lists then this must
       be bogus channel or some router in the net is buggy. */
    if (server->server_type != SILC_SERVER)
      goto out;

    channel = silc_idlist_add_channel(server->global_list, strdup(name),
				      SILC_CHANNEL_MODE_NONE,
				      silc_id_dup(SILC_ID_GET_ID(id),
						  SILC_ID_CHANNEL),
				      server->router, NULL, NULL, NULL);
    if (!channel)
      goto out;
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

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_LIST);
 err:
  silc_free(namec);
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(watch)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_WATCH);
 err:
  silc_server_command_reply_free(cmd);
}

SILC_SERVER_CMD_REPLY_FUNC(ping)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  SILC_SERVER_PENDING_EXEC(cmd, SILC_COMMAND_PING);
 err:
  silc_server_command_reply_free(cmd);
}
