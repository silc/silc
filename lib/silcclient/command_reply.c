/*

  command_reply.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/*
 * Command reply functions are "the otherside" of the command functions.
 * Reply to a command sent by server is handled by these functions.
 *
 * The arguments received from server are also passed to the calling
 * application through command_reply client operation.  The arguments are
 * exactly same and in same order as the server sent it.  However, ID's are
 * not sent to the application.  Instead, corresponding ID entry is sent
 * to the application.  For example, instead of sending Client ID the
 * corresponding SilcClientEntry is sent to the application.  The case is
 * same with for example Channel ID's.  This way application has all the
 * necessary data already in hand without redundant searching.  If ID is
 * received but ID entry does not exist, NULL is sent.
 */

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

#define SAY cmd->client->internal->ops->say

/* All functions that call the COMMAND_CHECK_STATUS macro must have
   out: and err: goto labels. out label should call the pending
   command replies, and the err label just handle error condition. */

#define COMMAND_CHECK_STATUS					\
do {								\
  SILC_LOG_DEBUG(("Start"));					\
  if (!silc_command_get_status(cmd->payload, NULL, NULL)) {	\
    if (SILC_STATUS_IS_ERROR(cmd->status)) {			\
      /* Single error */					\
      COMMAND_REPLY_ERROR;					\
      goto out;							\
    }								\
    /* List of errors */					\
    COMMAND_REPLY_ERROR;					\
    if (cmd->status == SILC_STATUS_LIST_END)			\
      goto out;							\
    goto err;							\
  }								\
} while(0)

/* Same as COMMAND_CHECK_STATUS but doesn't call client operation */
#define COMMAND_CHECK_STATUS_I					\
do {								\
  SILC_LOG_DEBUG(("Start"));					\
  if (!silc_command_get_status(cmd->payload, NULL, NULL)) {	\
    if (SILC_STATUS_IS_ERROR(cmd->status))			\
      goto out;							\
    if (cmd->status == SILC_STATUS_LIST_END)			\
      goto out;							\
    goto err;							\
  }								\
} while(0)

/* Process received command reply. */

void silc_client_command_reply_process(SilcClient client,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientCommand cmd;
  SilcClientCommandReplyContext ctx;
  SilcCommandPayload payload;
  SilcCommand command;
  SilcCommandCb reply = NULL;

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
  ctx->users++;
  ctx->client = client;
  ctx->sock = sock;
  ctx->payload = payload;
  ctx->args = silc_command_get_args(ctx->payload);
  ctx->packet = packet;
  ctx->ident = silc_command_get_ident(ctx->payload);
  silc_command_get_status(ctx->payload, &ctx->status, &ctx->error);

  /* Check for pending commands and mark to be exeucted */
  ctx->callbacks =
    silc_client_command_pending_check(sock->user_data, ctx,
				      silc_command_get(ctx->payload),
				      ctx->ident, &ctx->callbacks_count);

  /* Execute command reply */

  command = silc_command_get(ctx->payload);

  /* Try to find matching the command identifier */
  silc_list_start(client->internal->commands);
  while ((cmd = silc_list_get(client->internal->commands)) != SILC_LIST_END) {
    if (cmd->cmd == command && !cmd->ident)
      reply = cmd->reply;
    if (cmd->cmd == command && cmd->ident == ctx->ident) {
      (*cmd->reply)((void *)ctx, NULL);
      break;
    }
  }

  if (cmd == SILC_LIST_END) {
    if (reply)
      /* No specific identifier for command reply, call first one found */
      (*reply)(ctx, NULL);
    else
      silc_free(ctx);
  }
}

/* Duplicate Command Reply Context by adding reference counter. The context
   won't be free'd untill it hits zero. */

SilcClientCommandReplyContext
silc_client_command_reply_dup(SilcClientCommandReplyContext cmd)
{
  cmd->users++;
  SILC_LOG_DEBUG(("Command reply context %p refcnt %d->%d", cmd,
		  cmd->users - 1, cmd->users));
  return cmd;
}

/* Free command reply context and its internals. */

void silc_client_command_reply_free(SilcClientCommandReplyContext cmd)
{
  cmd->users--;
  SILC_LOG_DEBUG(("Command reply context %p refcnt %d->%d", cmd,
		  cmd->users + 1, cmd->users));
  if (cmd->users < 1) {
    silc_command_payload_free(cmd->payload);
    silc_free(cmd);
  }
}

static void
silc_client_command_reply_whois_save(SilcClientCommandReplyContext cmd,
				     SilcStatus status,
				     bool notify)
{
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id;
  SilcClientEntry client_entry = NULL;
  SilcUInt32 len;
  unsigned char *id_data, *tmp;
  char *nickname = NULL, *username = NULL;
  char *realname = NULL;
  SilcUInt32 idle = 0, mode = 0;
  SilcBufferStruct channels, ch_user_modes;
  bool has_channels = FALSE, has_user_modes = FALSE;
  unsigned char *fingerprint;
  SilcUInt32 fingerprint_len;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!id_data) {
    if (notify)
      COMMAND_REPLY_ERROR;
    return;
  }

  client_id = silc_id_payload_parse_id(id_data, len, NULL);
  if (!client_id) {
    if (notify)
      COMMAND_REPLY_ERROR;
    return;
  }

  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!nickname || !username || !realname) {
    if (notify)
      COMMAND_REPLY_ERROR;
    return;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 6, &len);
  if (tmp) {
    silc_buffer_set(&channels, tmp, len);
    has_channels = TRUE;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);

  tmp = silc_argument_get_arg_type(cmd->args, 8, &len);
  if (tmp)
    SILC_GET32_MSB(idle, tmp);

  fingerprint = silc_argument_get_arg_type(cmd->args, 9, &fingerprint_len);

  tmp = silc_argument_get_arg_type(cmd->args, 10, &len);
  if (tmp) {
    silc_buffer_set(&ch_user_modes, tmp, len);
    has_user_modes = TRUE;
  }

  /* Check if we have this client cached already. */
  client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
  if (!client_entry) {
    SILC_LOG_DEBUG(("Adding new client entry"));
    client_entry =
      silc_client_add_client(cmd->client, conn, nickname, username, realname,
			     client_id, mode);
  } else {
    silc_client_update_client(cmd->client, conn, client_entry,
			      nickname, username, realname, mode);
    silc_free(client_id);
  }

  if (fingerprint && !client_entry->fingerprint) {
    client_entry->fingerprint = silc_memdup(fingerprint, fingerprint_len);
    client_entry->fingerprint_len = fingerprint_len;
  }

  /* Take Requested Attributes if set. */
  tmp = silc_argument_get_arg_type(cmd->args, 11, &len);
  if (tmp) {
    if (client_entry->attrs)
      silc_attribute_payload_list_free(client_entry->attrs);
    client_entry->attrs = silc_attribute_payload_parse(tmp, len);
  }

  client_entry->status &= ~SILC_CLIENT_STATUS_RESOLVING;

  /* Notify application */
  if (!cmd->callbacks_count && notify)
    COMMAND_REPLY((SILC_ARGS, client_entry, nickname, username, realname,
		   has_channels ? &channels : NULL, mode, idle,
		   fingerprint, has_user_modes ? &ch_user_modes : NULL,
		   client_entry->attrs));
}

/* Received reply for WHOIS command. This maybe called several times
   for one WHOIS command as server may reply with list of results. */

SILC_CLIENT_CMD_REPLY_FUNC(whois)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  COMMAND_CHECK_STATUS;

  /* Save WHOIS info */
  silc_client_command_reply_whois_save(cmd, cmd->status, TRUE);

  /* Pending callbacks are not executed if this was an list entry */
  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_WHOIS);

 err:
  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
    SilcClientEntry client_entry;
    SilcUInt32 tmp_len;
    unsigned char *tmp =
      silc_argument_get_arg_type(silc_command_get_args(cmd->payload),
				 2, &tmp_len);
    if (tmp) {
      SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (client_id) {
	client_entry = silc_client_get_client_by_id(cmd->client, conn,
						    client_id);
	if (client_entry)
	  silc_client_del_client(cmd->client, conn, client_entry);
	silc_free(client_id);
      }
    }
  }

  silc_client_command_reply_free(cmd);
}

/* Received reply for WHOWAS command. */

SILC_CLIENT_CMD_REPLY_FUNC(whowas)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id;
  SilcClientEntry client_entry = NULL;
  SilcUInt32 len;
  unsigned char *id_data;
  char *nickname, *username;
  char *realname = NULL;

  COMMAND_CHECK_STATUS;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!id_data) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  client_id = silc_id_payload_parse_id(id_data, len, NULL);
  if (!client_id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get the client entry, if exists */
  client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
  silc_free(client_id);

  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!nickname || !username) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application. We don't save any history information to any
     cache. Just pass the data to the application for displaying on
     the screen. */
  COMMAND_REPLY((SILC_ARGS, client_entry, nickname, username, realname));

  /* Pending callbacks are not executed if this was an list entry */
  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_WHOWAS);
 err:
  silc_client_command_reply_free(cmd);
}

static void
silc_client_command_reply_identify_save(SilcClientCommandReplyContext cmd,
					SilcStatus status,
					bool notify)
{
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClient client = cmd->client;
  SilcClientID *client_id = NULL;
  SilcServerID *server_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcClientEntry client_entry;
  SilcServerEntry server_entry;
  SilcChannelEntry channel_entry;
  SilcUInt32 len;
  unsigned char *id_data;
  char *name = NULL, *info = NULL;
  SilcIDPayload idp = NULL;
  SilcIdType id_type;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!id_data) {
    if (notify)
      COMMAND_REPLY_ERROR;
    return;
  }
  idp = silc_id_payload_parse(id_data, len);
  if (!idp) {
    if (notify)
      COMMAND_REPLY_ERROR;
    return;
  }

  name = silc_argument_get_arg_type(cmd->args, 3, &len);
  info = silc_argument_get_arg_type(cmd->args, 4, &len);

  id_type = silc_id_payload_get_type(idp);

  switch (id_type) {
  case SILC_ID_CLIENT:
    client_id = silc_id_payload_get_id(idp);

    SILC_LOG_DEBUG(("Received client information"));

    /* Check if we have this client cached already. */
    client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
    if (!client_entry) {
      SILC_LOG_DEBUG(("Adding new client entry"));
      client_entry =
	silc_client_add_client(cmd->client, conn, name, info, NULL,
			       silc_id_dup(client_id, id_type), 0);
    } else {
      silc_client_update_client(cmd->client, conn, client_entry,
				name, info, NULL, 0);
    }

    client_entry->status &= ~SILC_CLIENT_STATUS_RESOLVING;

    /* Notify application */
    if (notify)
      COMMAND_REPLY((SILC_ARGS, client_entry, name, info));
    break;

  case SILC_ID_SERVER:
    server_id = silc_id_payload_get_id(idp);

    SILC_LOG_DEBUG(("Received server information"));

    /* Check if we have this server cached already. */
    server_entry = silc_client_get_server_by_id(cmd->client, conn, server_id);
    if (!server_entry) {
      SILC_LOG_DEBUG(("Adding new server entry"));
      server_entry = silc_client_add_server(cmd->client, conn, name, info,
					    silc_id_dup(server_id, id_type));
      if (!server_entry) {
	if (notify)
	  COMMAND_REPLY_ERROR;
	return;
      }
    } else {
      silc_client_update_server(client, conn, server_entry, name, info);
    }

    server_entry->resolve_cmd_ident = 0;

    /* Notify application */
    if (notify)
      COMMAND_REPLY((SILC_ARGS, server_entry, name, info));
    break;

  case SILC_ID_CHANNEL:
    channel_id = silc_id_payload_get_id(idp);

    SILC_LOG_DEBUG(("Received channel information"));

    /* Check if we have this channel cached already. */
    channel_entry = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel_entry) {
      if (!name)
	break;

      /* Add new channel entry */
      channel_entry = silc_client_add_channel(client, conn, name, 0,
					      channel_id);
      channel_id = NULL;
    }

    /* Notify application */
    if (notify)
      COMMAND_REPLY((SILC_ARGS, channel_entry, name, info));
    break;
  }

  silc_id_payload_free(idp);
  silc_free(client_id);
  silc_free(server_id);
  silc_free(channel_id);
}

/* Received reply for IDENTIFY command. This maybe called several times
   for one IDENTIFY command as server may reply with list of results.
   This is totally silent and does not print anything on screen. */

SILC_CLIENT_CMD_REPLY_FUNC(identify)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  COMMAND_CHECK_STATUS;

  /* Save IDENTIFY info */
  silc_client_command_reply_identify_save(cmd, cmd->status, TRUE);

  /* Pending callbacks are not executed if this was an list entry */
  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_IDENTIFY);

 err:
  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
    SilcClientEntry client_entry;
    SilcUInt32 tmp_len;
    unsigned char *tmp =
      silc_argument_get_arg_type(silc_command_get_args(cmd->payload),
				 2, &tmp_len);
    if (tmp) {
      SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (client_id) {
	client_entry = silc_client_get_client_by_id(cmd->client, conn,
						    client_id);
	if (client_entry)
	  silc_client_del_client(cmd->client, conn, client_entry);
	silc_free(client_id);
      }
    }
  }

  silc_client_command_reply_free(cmd);
}

/* Received reply for command NICK. If everything went without errors
   we just received our new Client ID. */

SILC_CLIENT_CMD_REPLY_FUNC(nick)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcIDPayload idp;
  unsigned char *tmp;
  SilcUInt32 argc, len;
  SilcClientID old_client_id;

  SILC_LOG_DEBUG(("Start"));

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot set nickname: %s",
	silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 2 || argc > 3) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot set nickname: bad reply to command");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Save old Client ID */
  old_client_id = *conn->local_id;

  /* Take received Client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  idp = silc_id_payload_parse(tmp, len);
  if (!idp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  silc_client_receive_new_id(cmd->client, cmd->sock, idp);

  /* Take the new nickname too */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (tmp) {
    silc_idcache_del_by_context(conn->internal->client_cache,
				conn->local_entry);
    if (conn->nickname)
      silc_free(conn->nickname);
    conn->nickname = strdup(tmp);
    conn->local_entry->nickname = conn->nickname;
    silc_client_nickname_format(cmd->client, conn, conn->local_entry);
    silc_idcache_add(conn->internal->client_cache, strdup(tmp),
                     conn->local_entry->id, conn->local_entry, 0, NULL);
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, conn->local_entry, conn->local_entry->nickname,
		 (const SilcClientID *)&old_client_id));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_NICK);
  silc_client_command_reply_free(cmd);
}

/* Received reply to the LIST command. */

SILC_CLIENT_CMD_REPLY_FUNC(list)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  unsigned char *tmp, *name, *topic;
  SilcUInt32 usercount = 0, len;
  SilcChannelID *channel_id = NULL;
  SilcChannelEntry channel_entry;

  COMMAND_CHECK_STATUS;

  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  name = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!name) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  topic = silc_argument_get_arg_type(cmd->args, 4, NULL);
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(usercount, tmp);

  /* Check whether the channel exists, and add it to cache if it doesn't. */
  channel_entry = silc_client_get_channel_by_id(cmd->client, conn,
						channel_id);
  if (!channel_entry) {
    /* Add new channel entry */
    channel_entry = silc_client_add_channel(cmd->client, conn, name, 0,
					    channel_id);
    if (!channel_entry) {
      COMMAND_REPLY_ERROR;
      goto out;
    }
    channel_id = NULL;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel_entry, name, topic, usercount));

  /* Pending callbacks are not executed if this was an list entry */
  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

 out:
  silc_free(channel_id);
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_LIST);
 err:
  silc_client_command_reply_free(cmd);
}

/* Received reply to topic command. */

SILC_CLIENT_CMD_REPLY_FUNC(topic)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcChannelEntry channel;
  SilcChannelID *channel_id = NULL;
  unsigned char *tmp;
  char *topic;
  SilcUInt32 argc, len;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot set topic: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 1 || argc > 3) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  /* Take topic */
  topic = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!topic)
    goto out;

  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel, topic));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_TOPIC);
  silc_client_command_reply_free(cmd);
}

/* Received reply to invite command. */

SILC_CLIENT_CMD_REPLY_FUNC(invite)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcChannelEntry channel;
  SilcChannelID *channel_id;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcBufferStruct buf;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot invite: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get the invite list */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (tmp)
    silc_buffer_set(&buf, tmp, len);

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel, tmp ? &buf : NULL));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_INVITE);
  silc_client_command_reply_free(cmd);
}

/* Received reply to the KILL command. */

SILC_CLIENT_CMD_REPLY_FUNC(kill)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id;
  SilcClientEntry client_entry = NULL;
  SilcUInt32 len;
  unsigned char *id_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot kill: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (id_data) {
    client_id = silc_id_payload_parse_id(id_data, len, NULL);
    if (!client_id) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    /* Get the client entry, if exists */
    client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
    silc_free(client_id);
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, client_entry));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_KILL);
  silc_client_command_reply_free(cmd);
}

/* Received reply to INFO command. We receive the server ID and some
   information about the server user requested. */

SILC_CLIENT_CMD_REPLY_FUNC(info)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  unsigned char *tmp;
  SilcServerEntry server;
  SilcServerID *server_id = NULL;
  char *server_name, *server_info;
  SilcUInt32 len;

  SILC_LOG_DEBUG(("Start"));

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR, "%s",
	silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  server_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!server_id)
    goto out;

  /* Get server name */
  server_name = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!server_name)
    goto out;

  /* Get server info */
  server_info = silc_argument_get_arg_type(cmd->args, 4, NULL);
  if (!server_info)
    goto out;

  /* See whether we have this server cached. If not create it. */
  server = silc_client_get_server_by_id(cmd->client, conn, server_id);
  if (!server) {
    SILC_LOG_DEBUG(("New server entry"));
    server = silc_client_add_server(cmd->client, conn, server_name,
				    server_info,
				    silc_id_dup(server_id, SILC_ID_SERVER));
    if (!server)
      goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, server, server->server_name, server->server_info));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_INFO);
  silc_free(server_id);
  silc_client_command_reply_free(cmd);
}

/* Received reply to STATS command. */

SILC_CLIENT_CMD_REPLY_FUNC(stats)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  unsigned char *tmp, *buf = NULL;
  SilcUInt32 len, buf_len = 0;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  /* Get statistics structure */
  buf = silc_argument_get_arg_type(cmd->args, 3, &buf_len);

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, buf, buf_len));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_STATS);
  silc_client_command_reply_free(cmd);
}

/* Received reply to PING command. The reply time is shown to user. */

SILC_CLIENT_CMD_REPLY_FUNC(ping)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  void *id;
  int i;
  time_t diff, curtime;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  curtime = time(NULL);
  id = silc_id_str2id(cmd->packet->src_id, cmd->packet->src_id_len,
		      cmd->packet->src_id_type);
  if (!id || !conn->internal->ping) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  for (i = 0; i < conn->internal->ping_count; i++) {
    if (!conn->internal->ping[i].dest_id)
      continue;
    if (SILC_ID_SERVER_COMPARE(conn->internal->ping[i].dest_id, id)) {
      diff = curtime - conn->internal->ping[i].start_time;
      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	  "Ping reply from %s: %d second%s",
	  conn->internal->ping[i].dest_name, diff,
	  diff == 1 ? "" : "s");

      conn->internal->ping[i].start_time = 0;
      silc_free(conn->internal->ping[i].dest_id);
      conn->internal->ping[i].dest_id = NULL;
      silc_free(conn->internal->ping[i].dest_name);
      conn->internal->ping[i].dest_name = NULL;
      break;
    }
  }

  silc_free(id);

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_PING);
  silc_client_command_reply_free(cmd);
}

/* Received reply for JOIN command. */

SILC_CLIENT_CMD_REPLY_FUNC(join)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcChannelID *channel_id;
  SilcUInt32 argc, mode = 0, len, list_count;
  char *topic, *tmp, *channel_name = NULL, *hmac;
  SilcBuffer keyp = NULL, client_id_list = NULL, client_mode_list = NULL;
  SilcPublicKey founder_key = NULL;
  SilcBufferStruct chpklist;
  int i;

  SILC_LOG_DEBUG(("Start"));

  if (cmd->error != SILC_STATUS_OK) {
    if (cmd->error != SILC_STATUS_ERR_USER_ON_CHANNEL)
      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	  "Cannot join channel: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc < 7) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel_name = tmp;

  /* Get Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!tmp) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot join channel: Bad reply packet");
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel mode */
  tmp = silc_argument_get_arg_type(cmd->args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);

  /* Get channel key */
  tmp = silc_argument_get_arg_type(cmd->args, 7, &len);
  if (tmp) {
    keyp = silc_buffer_alloc(len);
    silc_buffer_pull_tail(keyp, SILC_BUFFER_END(keyp));
    silc_buffer_put(keyp, tmp, len);
  }

  /* Get topic */
  topic = silc_argument_get_arg_type(cmd->args, 10, NULL);

  /* Check whether we have this channel entry already. */
  channel = silc_client_get_channel(cmd->client, conn, channel_name);
  if (channel) {
    if (!SILC_ID_CHANNEL_COMPARE(channel->id, channel_id))
      silc_client_replace_channel_id(cmd->client, conn, channel, channel_id);
  } else {
    /* Create new channel entry */
    channel = silc_client_add_channel(cmd->client, conn, channel_name,
				      mode, channel_id);
  }

  conn->current_channel = channel;

  /* Get hmac */
  hmac = silc_argument_get_arg_type(cmd->args, 11, NULL);
  if (hmac) {
    if (!silc_hmac_alloc(hmac, NULL, &channel->hmac)) {
      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	  "Cannot join channel: Unsupported HMAC `%s'", hmac);
      COMMAND_REPLY_ERROR;
      goto out;
    }
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

  /* Add clients we received in the reply to the channel */
  for (i = 0; i < list_count; i++) {
    SilcUInt16 idp_len;
    SilcUInt32 mode;
    SilcClientID *client_id;
    SilcClientEntry client_entry;

    /* Client ID */
    SILC_GET16_MSB(idp_len, client_id_list->data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list->data, idp_len, NULL);
    if (!client_id)
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list->data);

    /* Check if we have this client cached already. */
    client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
    if (!client_entry) {
      /* No, we don't have it, add entry for it. */
      client_entry =
	silc_client_add_client(cmd->client, conn, NULL, NULL, NULL,
			       silc_id_dup(client_id, SILC_ID_CLIENT), 0);
    }

    /* Join client to the channel */
    if (!silc_client_on_channel(channel, client_entry)) {
      chu = silc_calloc(1, sizeof(*chu));
      chu->client = client_entry;
      chu->channel = channel;
      chu->mode = mode;
      silc_hash_table_add(channel->user_list, client_entry, chu);
      silc_hash_table_add(client_entry->channels, channel, chu);
    }

    silc_free(client_id);
    silc_buffer_pull(client_id_list, idp_len);
    silc_buffer_pull(client_mode_list, 4);
  }
  silc_buffer_push(client_id_list, client_id_list->data -
		   client_id_list->head);
  silc_buffer_push(client_mode_list, client_mode_list->data -
		   client_mode_list->head);

  /* Save channel key */
  if (keyp && !(channel->mode & SILC_CHANNEL_MODE_PRIVKEY))
    silc_client_save_channel_key(cmd->client, conn, keyp, channel);

  /* Get founder key */
  tmp = silc_argument_get_arg_type(cmd->args, 15, &len);
  if (tmp)
    silc_pkcs_public_key_payload_decode(tmp, len, &founder_key);

  /* Get channel public key list */
  tmp = silc_argument_get_arg_type(cmd->args, 16, &len);
  if (tmp)
    silc_buffer_set(&chpklist, tmp, len);

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel_name, channel, mode, 0,
		 keyp ? keyp->head : NULL, NULL,
		 NULL, topic, hmac, list_count, client_id_list,
		 client_mode_list, founder_key, tmp ? &chpklist : NULL));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_JOIN);
  silc_client_command_reply_free(cmd);
  if (founder_key)
    silc_pkcs_public_key_free(founder_key);
  silc_buffer_free(keyp);
  silc_buffer_free(client_id_list);
  silc_buffer_free(client_mode_list);
}

/* Received reply for MOTD command */

SILC_CLIENT_CMD_REPLY_FUNC(motd)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcUInt32 argc, i;
  char *motd = NULL, *cp, line[256];

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    return;
  }

  argc = silc_argument_get_arg_num(cmd->args);
  if (argc > 3) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  if (argc == 3) {
    motd = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (!motd) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    i = 0;
    cp = motd;
    while(cp[i] != 0) {
      if (cp[i++] == '\n') {
	memset(line, 0, sizeof(line));
	silc_strncat(line, sizeof(line), cp, i - 1);
	cp += i;

	if (i == 2)
	  line[0] = ' ';

	SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO, "%s", line);

	if (!strlen(cp))
	  break;
	i = 0;
      }
    }
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, motd));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_MOTD);
  silc_client_command_reply_free(cmd);
}

/* Received reply tot he UMODE command. Save the current user mode */

SILC_CLIENT_CMD_REPLY_FUNC(umode)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  unsigned char *tmp;
  SilcUInt32 mode;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot change mode: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  SILC_GET32_MSB(mode, tmp);
  conn->local_entry->mode = mode;

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, mode));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_UMODE);
  silc_client_command_reply_free(cmd);
}

/* Received reply for CMODE command. */

SILC_CLIENT_CMD_REPLY_FUNC(cmode)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  unsigned char *tmp;
  SilcUInt32 mode;
  SilcChannelID *channel_id;
  SilcChannelEntry channel;
  SilcUInt32 len;
  SilcPublicKey public_key = NULL;
  SilcBufferStruct channel_pubkeys;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot change mode: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;
  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel mode */
  tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!tmp) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Save the mode */
  SILC_GET32_MSB(mode, tmp);
  channel->mode = mode;

  /* Get founder public key */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (tmp) {
    if (!silc_pkcs_public_key_payload_decode(tmp, len, &public_key))
      public_key = NULL;
  }

  /* Get channel public key(s) */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (tmp)
    silc_buffer_set(&channel_pubkeys, tmp, len);

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel, mode, public_key,
		 tmp ? &channel_pubkeys : NULL));

  silc_free(channel_id);

 out:
  if (public_key)
    silc_pkcs_public_key_free(public_key);
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_CMODE);
  silc_client_command_reply_free(cmd);
}

/* Received reply for CUMODE command */

SILC_CLIENT_CMD_REPLY_FUNC(cumode)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id;
  SilcChannelID *channel_id;
  SilcClientEntry client_entry;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  unsigned char *modev, *tmp, *id;
  SilcUInt32 len, mode;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot change mode: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get channel mode */
  modev = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!modev) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!tmp)
    goto out;
  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get Client ID */
  id = silc_argument_get_arg_type(cmd->args, 4, &len);
  if (!id) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }
  client_id = silc_id_payload_parse_id(id, len, NULL);
  if (!client_id) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get client entry */
  client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
  if (!client_entry) {
    silc_free(channel_id);
    silc_free(client_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Save the mode */
  SILC_GET32_MSB(mode, modev);
  chu = silc_client_on_channel(channel, client_entry);
  if (chu)
    chu->mode = mode;

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, mode, channel, client_entry));
  silc_free(client_id);
  silc_free(channel_id);

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_CUMODE);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(kick)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientID *client_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel = NULL;
  unsigned char *tmp;
  SilcUInt32 len;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Cannot kick: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (tmp) {
    channel_id = silc_id_payload_parse_id(tmp, len, NULL);
    if (!channel_id) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    /* Get the channel entry */
    channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
    if (!channel) {
      COMMAND_REPLY_ERROR;
      goto out;
    }
  }

  /* Get Client ID */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (tmp) {
    client_id = silc_id_payload_parse_id(tmp, len, NULL);
    if (!client_id) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    /* Get client entry */
    client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
    if (!client_entry) {
      COMMAND_REPLY_ERROR;
      goto out;
    }
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel, client_entry));

 out:
  silc_free(channel_id);
  silc_free(client_id);
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_KICK);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(silcoper)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_SILCOPER);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(oper)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_OPER);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(detach)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcBuffer detach;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

  /* Generate the detachment data and deliver it to the client in the
     detach client operation */
  detach = silc_client_get_detach_data(cmd->client, conn);
  if (detach) {
    cmd->client->internal->ops->detach(cmd->client, conn,
				       detach->data, detach->len);
    silc_buffer_free(detach);
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_DETACH);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(watch)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_WATCH);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(ban)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcChannelEntry channel;
  SilcChannelID *channel_id;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcBufferStruct buf;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel) {
    silc_free(channel_id);
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get the ban list */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (tmp)
    silc_buffer_set(&buf, tmp, len);

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel, tmp ? &buf : NULL));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_BAN);
  silc_client_command_reply_free(cmd);
}

/* Reply to LEAVE command. */

SILC_CLIENT_CMD_REPLY_FUNC(leave)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcChannelID *channel_id;
  SilcChannelEntry channel = NULL;
  SilcChannelUser chu;
  unsigned char *tmp;
  SilcUInt32 len;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* From protocol version 1.1 we get the channel ID of the left channel */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (tmp) {
    channel_id = silc_id_payload_parse_id(tmp, len, NULL);
    if (!channel_id)
      goto out;

    /* Get the channel entry */
    channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
    if (!channel) {
      silc_free(channel_id);
      COMMAND_REPLY_ERROR;
      goto out;
    }

    /* Remove us from this channel. */
    chu = silc_client_on_channel(channel, conn->local_entry);
    if (chu) {
      silc_hash_table_del(chu->client->channels, chu->channel);
      silc_hash_table_del(chu->channel->user_list, chu->client);
      silc_free(chu);
    }

    silc_free(channel_id);
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS, channel));

  /* Now delete the channel. */
  if (channel)
    silc_client_del_channel(cmd->client, conn, channel);

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_LEAVE);
  silc_client_command_reply_free(cmd);
}

/* Channel resolving callback for USERS command reply. */

static void silc_client_command_reply_users_cb(SilcClient client,
					       SilcClientConnection conn,
					       SilcChannelEntry *channels,
					       SilcUInt32 channels_count,
					       void *context)
{
  if (!channels_count) {
    SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
    SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

    cmd->status = cmd->error = SILC_STATUS_ERR_NO_SUCH_CHANNEL;
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_USERS);
    silc_client_command_reply_free(cmd);
    return;
  }

  silc_client_command_reply_users(context, NULL);
}

static int
silc_client_command_reply_users_save(SilcClientCommandReplyContext cmd,
				     SilcStatus status,
				     bool notify,
				     bool resolve,
				     SilcGetChannelCallback get_channel,
				     SilcCommandCb get_clients)
{
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcChannelEntry channel;
  SilcClientEntry client_entry;
  SilcChannelUser chu;
  SilcChannelID *channel_id = NULL;
  SilcBufferStruct client_id_list, client_mode_list;
  unsigned char *tmp;
  SilcUInt32 tmp_len, list_count;
  int i;
  unsigned char **res_argv = NULL;
  SilcUInt32 *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;
  bool wait_res = FALSE;

  SILC_LOG_DEBUG(("Start"));

  /* Get channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!channel_id) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  silc_buffer_set(&client_id_list, tmp, tmp_len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  silc_buffer_set(&client_mode_list, tmp, tmp_len);

  /* Get channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel) {
    /* Resolve the channel from server */
    silc_client_get_channel_by_id_resolve(cmd->client, conn, channel_id,
					  get_channel, cmd);
    silc_free(channel_id);
    return 1;
  }

  SILC_LOG_DEBUG(("channel %s, %d users", channel->channel_name, list_count));

  /* Cache the received Client ID's and modes. */
  for (i = 0; i < list_count; i++) {
    SilcUInt16 idp_len;
    SilcUInt32 mode;
    SilcClientID *client_id;

    /* Client ID */
    SILC_GET16_MSB(idp_len, client_id_list.data + 2);
    idp_len += 4;
    client_id = silc_id_payload_parse_id(client_id_list.data, idp_len, NULL);
    if (!client_id)
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list.data);

    /* Check if we have this client cached already. */
    client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
    if (!client_entry || !client_entry->username || !client_entry->realname) {
      if (resolve) {
	/* No we don't have it (or it is incomplete in information), query
	   it from the server. Assemble argument table that will be sent
	   for the WHOIS command later. */
	res_argv = silc_realloc(res_argv, sizeof(*res_argv) *
				(res_argc + 1));
	res_argv_lens = silc_realloc(res_argv_lens, sizeof(*res_argv_lens) *
				     (res_argc + 1));
	res_argv_types = silc_realloc(res_argv_types, sizeof(*res_argv_types) *
				      (res_argc + 1));
	res_argv[res_argc] = client_id_list.data;
	res_argv_lens[res_argc] = idp_len;
	res_argv_types[res_argc] = res_argc + 4;
	res_argc++;
      }
    } else {
      if (!silc_client_on_channel(channel, client_entry)) {
	chu = silc_calloc(1, sizeof(*chu));
	chu->client = client_entry;
	chu->mode = mode;
	chu->channel = channel;
	silc_hash_table_add(channel->user_list, client_entry, chu);
	silc_hash_table_add(client_entry->channels, channel, chu);
      }
    }

    silc_free(client_id);
    silc_buffer_pull(&client_id_list, idp_len);
    silc_buffer_pull(&client_mode_list, 4);
  }

  /* Query the client information from server if the list included clients
     that we don't know about. */
  if (res_argc) {
    SilcBuffer res_cmd;

    /* Send the WHOIS command to server */
    silc_client_command_register(cmd->client, SILC_COMMAND_WHOIS, NULL, NULL,
				 silc_client_command_reply_whois_i, 0,
				 ++conn->cmd_ident);
    res_cmd = silc_command_payload_encode(SILC_COMMAND_WHOIS,
					  res_argc, res_argv, res_argv_lens,
					  res_argv_types, conn->cmd_ident);
    silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND,
			    NULL, 0, NULL, NULL, res_cmd->data, res_cmd->len,
			    TRUE);

    /* Register pending command callback. After we've received the WHOIS
       command reply we will reprocess this command reply by re-calling this
       USERS command reply callback. */
    silc_client_command_pending(conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
				get_clients, cmd);

    silc_buffer_free(res_cmd);
    silc_free(channel_id);
    silc_free(res_argv);
    silc_free(res_argv_lens);
    silc_free(res_argv_types);
    return 1;
  }

  if (wait_res)
    return 1;

  silc_buffer_push(&client_id_list, (client_id_list.data -
				     client_id_list.head));
  silc_buffer_push(&client_mode_list, (client_mode_list.data -
				       client_mode_list.head));

  /* Notify application */
  if (notify)
    COMMAND_REPLY((SILC_ARGS, channel, list_count, &client_id_list,
		   &client_mode_list));

 out:
  silc_free(channel_id);
  return 0;
}

/* Reply to USERS command. Received list of client ID's and theirs modes
   on the channel we requested. */

SILC_CLIENT_CMD_REPLY_FUNC(users)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcClientCommandReplyContext r = (SilcClientCommandReplyContext)context2;

  SILC_LOG_DEBUG(("Start"));

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"Query failed: %s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  if (r && !silc_command_get_status(r->payload, NULL, &cmd->error)) {
    if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
      /* Do not resolve anymore. Server may be sending us some non-existent
	 Client ID (a bug in server), and we want to show the users list
	 anyway. */
      silc_client_command_reply_users_save(cmd, cmd->status, TRUE, FALSE,
					   silc_client_command_reply_users_cb,
					   silc_client_command_reply_users);
      goto out;
    } else {
      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	  "Query failed: %s", silc_get_status_message(cmd->error));
      COMMAND_REPLY_ERROR;
      goto out;
    }
  }

  if (silc_client_command_reply_users_save(cmd, cmd->status, TRUE, TRUE,
					   silc_client_command_reply_users_cb,
					   silc_client_command_reply_users))
    return;

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_USERS);
  silc_client_command_reply_free(cmd);
}

/* Received command reply to GETKEY command. WE've received the remote
   client's public key. */

SILC_CLIENT_CMD_REPLY_FUNC(getkey)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  SilcIDPayload idp = NULL;
  SilcClientID *client_id = NULL;
  SilcClientEntry client_entry;
  SilcServerID *server_id = NULL;
  SilcServerEntry server_entry;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcIdType id_type;
  SilcPublicKey public_key = NULL;

  SILC_LOG_DEBUG(("Start"));

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }
  idp = silc_id_payload_parse(tmp, len);
  if (!idp) {
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Get the public key payload */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (tmp) {
    if (!silc_pkcs_public_key_payload_decode(tmp, len, &public_key))
      public_key = NULL;
  }

  id_type = silc_id_payload_get_type(idp);
  if (id_type == SILC_ID_CLIENT) {
    /* Received client's public key */
    client_id = silc_id_payload_get_id(idp);
    client_entry = silc_client_get_client_by_id(cmd->client, conn, client_id);
    if (!client_entry) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    /* Save fingerprint */
    if (!client_entry->fingerprint) {
      client_entry->fingerprint = silc_calloc(20, sizeof(unsigned char));
      client_entry->fingerprint_len = 20;
      silc_hash_make(cmd->client->sha1hash, tmp + 4, len - 4,
		     client_entry->fingerprint);
    }

    /* Notify application */
    COMMAND_REPLY((SILC_ARGS, id_type, client_entry, public_key));
  } else if (id_type == SILC_ID_SERVER) {
    /* Received server's public key */
    server_id = silc_id_payload_get_id(idp);
    server_entry = silc_client_get_server_by_id(cmd->client, conn, server_id);
    if (!server_entry) {
      COMMAND_REPLY_ERROR;
      goto out;
    }

    /* Notify application */
    COMMAND_REPLY((SILC_ARGS, id_type, server_entry, public_key));
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_GETKEY);
  if (idp)
    silc_id_payload_free(idp);
  if (public_key)
    silc_pkcs_public_key_free(public_key);
  silc_free(client_id);
  silc_free(server_id);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(quit)
{
  silc_client_command_reply_free(context);
}


/******************************************************************************

                      Internal command reply functions

******************************************************************************/

SILC_CLIENT_CMD_REPLY_FUNC(whois_i)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  COMMAND_CHECK_STATUS_I;

  /* Save WHOIS info */
  silc_client_command_reply_whois_save(cmd, cmd->status, FALSE);

  /* Pending callbacks are not executed if this was an list entry */
  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_WHOIS);

 err:
  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
    SilcClientEntry client_entry;
    SilcUInt32 tmp_len;
    unsigned char *tmp =
      silc_argument_get_arg_type(silc_command_get_args(cmd->payload),
				 2, &tmp_len);
    if (tmp) {
      SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (client_id) {
	client_entry = silc_client_get_client_by_id(cmd->client, conn,
						    client_id);
	if (client_entry)
	  silc_client_del_client(cmd->client, conn, client_entry);
	silc_free(client_id);
      }
    }
  }

  /* Unregister this command reply */
  silc_client_command_unregister(cmd->client, SILC_COMMAND_WHOIS,
				 NULL, silc_client_command_reply_whois_i,
				 cmd->ident);

  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(identify_i)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  COMMAND_CHECK_STATUS_I;

  /* Save IDENTIFY info */
  silc_client_command_reply_identify_save(cmd, cmd->status, FALSE);

  /* Pending callbacks are not executed if this was an list entry */
  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END) {
    silc_client_command_reply_free(cmd);
    return;
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_IDENTIFY);

 err:
  /* If we received notify for invalid ID we'll remove the ID if we
     have it cached. */
  if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
    SilcClientEntry client_entry;
    SilcUInt32 tmp_len;
    unsigned char *tmp =
      silc_argument_get_arg_type(silc_command_get_args(cmd->payload),
				 2, &tmp_len);
    if (tmp) {
      SilcClientID *client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (client_id) {
	client_entry = silc_client_get_client_by_id(cmd->client, conn,
						    client_id);
	if (client_entry)
	  silc_client_del_client(cmd->client, conn, client_entry);
	silc_free(client_id);
      }
    }
  }

  /* Unregister this command reply */
  silc_client_command_unregister(cmd->client, SILC_COMMAND_IDENTIFY,
				 NULL, silc_client_command_reply_identify_i,
				 cmd->ident);

  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(info_i)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;
  unsigned char *tmp;
  SilcServerEntry server;
  SilcServerID *server_id = NULL;
  char *server_name, *server_info;
  SilcUInt32 len;

  COMMAND_CHECK_STATUS_I;

  /* Get server ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto out;

  server_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!server_id)
    goto out;

  /* Get server name */
  server_name = silc_argument_get_arg_type(cmd->args, 3, NULL);
  if (!server_name)
    goto out;

  /* Get server info */
  server_info = silc_argument_get_arg_type(cmd->args, 4, NULL);
  if (!server_info)
    goto out;

  /* See whether we have this server cached. If not create it. */
  server = silc_client_get_server_by_id(cmd->client, conn, server_id);
  if (!server) {
    SILC_LOG_DEBUG(("New server entry"));
    silc_client_add_server(cmd->client, conn, server_name, server_info,
			   silc_id_dup(server_id, SILC_ID_SERVER));
  }

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_INFO);
  silc_free(server_id);
 err:
  silc_client_command_reply_free(cmd);
}

static void silc_client_command_reply_users_i_cb(SilcClient client,
						 SilcClientConnection conn,
						 SilcChannelEntry *channels,
						 SilcUInt32 channels_count,
						 void *context)
{
  if (!channels_count) {
    SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
    SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

    cmd->status = cmd->error = SILC_STATUS_ERR_NO_SUCH_CHANNEL;
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_USERS);
    silc_client_command_reply_free(cmd);
    return;
  }

  silc_client_command_reply_users_i(context, NULL);
}

SILC_CLIENT_CMD_REPLY_FUNC(users_i)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;

  COMMAND_CHECK_STATUS_I;

  /* Save USERS info */
  if (silc_client_command_reply_users_save(
				    cmd, cmd->status, FALSE, TRUE,
				    silc_client_command_reply_users_i_cb,
				    silc_client_command_reply_users_i))
    return;

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_USERS);

 err:
  /* Unregister this command reply */
  silc_client_command_unregister(cmd->client, SILC_COMMAND_USERS,
				 NULL, silc_client_command_reply_users_i,
				 cmd->ident);

  silc_client_command_reply_free(cmd);
}

/* Private range commands, specific to this implementation (and compatible
   with SILC Server >= 0.9). */

SILC_CLIENT_CMD_REPLY_FUNC(connect)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_PRIV_CONNECT);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(close)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_PRIV_CLOSE);
  silc_client_command_reply_free(cmd);
}

SILC_CLIENT_CMD_REPLY_FUNC(shutdown)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SilcClientConnection conn = (SilcClientConnection)cmd->sock->user_data;

  if (cmd->error != SILC_STATUS_OK) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	"%s", silc_get_status_message(cmd->error));
    COMMAND_REPLY_ERROR;
    goto out;
  }

  /* Notify application */
  COMMAND_REPLY((SILC_ARGS));

 out:
  SILC_CLIENT_PENDING_EXEC(cmd, SILC_COMMAND_PRIV_SHUTDOWN);
  silc_client_command_reply_free(cmd);
}
