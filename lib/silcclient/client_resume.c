/*

  client_resume.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002, 2004, 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

SILC_CLIENT_CMD_REPLY_FUNC(resume);
SILC_CLIENT_CMD_FUNC(resume_identify);
SILC_CLIENT_CMD_FUNC(resume_cmode);
SILC_CLIENT_CMD_FUNC(resume_users);

#define RESUME_CALL_COMPLETION(client, session, s)			\
do {									\
  SILC_LOG_DEBUG(("Calling completion"));				\
  session->success = s;							\
  silc_schedule_task_add(client->schedule, 0,				\
			 silc_client_resume_call_completion, session,	\
			 0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);	\
} while(0)

/* Generic command reply callback. */

SILC_CLIENT_CMD_REPLY_FUNC(resume)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  SILC_LOG_DEBUG(("Start"));
  SILC_CLIENT_PENDING_EXEC(cmd, silc_command_get(cmd->payload));
}

/* Special command reply callback for IDENTIFY callbacks.  This calls
   the pending callback for every returned command entry. */

SILC_CLIENT_CMD_REPLY_FUNC(resume_special)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;
  int i;

  SILC_LOG_DEBUG(("Start"));
  for (i = 0; i < cmd->callbacks_count; i++)
    if (cmd->callbacks[i].callback)
      (*cmd->callbacks[i].callback)(cmd->callbacks[i].context, cmd);
}

/* Completion calling callback */

SILC_TASK_CALLBACK(silc_client_resume_call_completion)
{
  SilcClientResumeSession session = context;
  int i;

  SILC_LOG_DEBUG(("Session completed"));

  for (i = 0; i < session->cmd_idents_count; i++)
    silc_client_command_pending_del(session->conn, SILC_COMMAND_IDENTIFY,
				    session->cmd_idents[i]);
  silc_free(session->cmd_idents);

  session->callback(session->client, session->conn, session->success,
		    session->context);

  memset(session, 'F', sizeof(*session));
  silc_free(session);
}

/* This function is used to perform the resuming procedure after the
   client has connected to the server properly and has received the
   Client ID for the resumed session.  This resolves all channels
   that the resumed client is joined, joined users, users modes
   and channel modes.  The `callback' is called after this procedure
   is completed. */

void silc_client_resume_session(SilcClient client,
				SilcClientConnection conn,
				SilcClientResumeSessionCallback callback,
				void *context)
{
  SilcClientResumeSession session;
  SilcIDCacheList list;
  SilcIDCacheEntry entry;
  SilcChannelEntry channel;
  SilcBuffer tmp;
  int i;
  SilcBool ret;

  SILC_LOG_DEBUG(("Resuming detached session"));

  session = silc_calloc(1, sizeof(*session));
  if (!session) {
    callback(client, conn, FALSE, context);
    return;
  }
  session->client = client;
  session->conn = conn;
  session->callback = callback;
  session->context = context;

  /* First, send UMODE commandto get our own user mode in the network */
  SILC_LOG_DEBUG(("Sending UMODE"));
  tmp = silc_id_payload_encode(conn->local_entry->id, SILC_ID_CLIENT);
  silc_client_command_send(client, conn, SILC_COMMAND_UMODE,
			   conn->cmd_ident, 1, 1, tmp->data, tmp->len);
  silc_buffer_free(tmp);

  /* Second, send IDENTIFY command of all channels we know about.  These
     are the channels we've joined to according our detachment data. */
  if (silc_idcache_get_all(conn->internal->channel_cache, &list)) {
    unsigned char **res_argv = NULL;
    SilcUInt32 *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;

    session->channel_count = silc_idcache_list_count(list);

    ret = silc_idcache_list_first(list, &entry);
    while (ret) {
      channel = entry->context;
      tmp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
      res_argv = silc_realloc(res_argv, sizeof(*res_argv) * (res_argc + 1));
      res_argv_lens = silc_realloc(res_argv_lens, sizeof(*res_argv_lens) *
				   (res_argc + 1));
      res_argv_types = silc_realloc(res_argv_types, sizeof(*res_argv_types) *
				    (res_argc + 1));
      res_argv[res_argc] = silc_memdup(tmp->data, tmp->len);
      res_argv_lens[res_argc] = tmp->len;
      res_argv_types[res_argc] = res_argc + 5;
      res_argc++;
      silc_buffer_free(tmp);
      ret = silc_idcache_list_next(list, &entry);
    }
    silc_idcache_list_free(list);

    if (res_argc) {
      /* Send the IDENTIFY command */
      SILC_LOG_DEBUG(("Sending IDENTIFY"));
      silc_client_command_register(client, SILC_COMMAND_IDENTIFY, NULL, NULL,
				   silc_client_command_reply_resume_special,
				   0, ++conn->cmd_ident);
      silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY,
				  conn->cmd_ident,
				  silc_client_command_resume_identify,
				  session);

      tmp = silc_command_payload_encode(SILC_COMMAND_IDENTIFY,
					res_argc, res_argv, res_argv_lens,
					res_argv_types, conn->cmd_ident);
      silc_client_packet_send(client, conn->sock, SILC_PACKET_COMMAND,
			      NULL, 0, NULL, NULL, tmp->data, tmp->len, TRUE);

      session->cmd_idents = silc_realloc(session->cmd_idents,
					 sizeof(*session->cmd_idents) *
					 (session->cmd_idents_count + 1));
      session->cmd_idents[session->cmd_idents_count] = conn->cmd_ident;
      session->cmd_idents_count++;

      for (i = 0; i < res_argc; i++)
	silc_free(res_argv[i]);
      silc_free(res_argv);
      silc_free(res_argv_lens);
      silc_free(res_argv_types);
      silc_buffer_free(tmp);
    }
  }

  if (!session->channel_count)
    RESUME_CALL_COMPLETION(client, session, TRUE);

  /* Now, we wait for replies to come back and then continue with USERS,
     CMODE and TOPIC commands. */
}

/* Received identify reply for a channel entry */

SILC_CLIENT_CMD_FUNC(resume_identify)
{
  SilcClientResumeSession session = context;
  SilcClientCommandReplyContext cmd = context2;
  SilcClient client = session->client;
  SilcClientConnection conn = session->conn;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcChannelEntry channel = NULL;
  SilcChannelID *channel_id;
  SilcIDPayload idp;
  SilcIdType id_type;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp)
    goto err;

  if (cmd->error != SILC_STATUS_OK) {
    /* Delete unknown channel from our cache */
    if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID) {
      channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (channel_id) {
	channel = silc_client_get_channel_by_id(client, conn, channel_id);
	if (channel)
	  silc_client_del_channel(client, conn, channel);
	silc_free(channel_id);
      }
    }
    goto err;
  }

  idp = silc_id_payload_parse(tmp, tmp_len);
  if (!idp) {
    return;
  }
  id_type = silc_id_payload_get_type(idp);

  switch (id_type) {
  case SILC_ID_CHANNEL:
    channel_id = silc_id_payload_get_id(idp);
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    silc_free(channel_id);
    break;
  default:
    silc_id_payload_free(idp);
    goto err;
    break;
  }

  /* Now, send CMODE command for this channel.  We send only this one
     because this will return also error if we are not currently joined
     on this channel, plus we get the channel mode.  USERS and TOPIC
     commands are called after this returns. */
  if (channel) {
    SILC_LOG_DEBUG(("Sending CMODE"));
    silc_client_command_register(client, SILC_COMMAND_CMODE, NULL, NULL,
				 silc_client_command_reply_resume, 0,
				 ++conn->cmd_ident);
    silc_client_command_send(client, conn, SILC_COMMAND_CMODE,
			     conn->cmd_ident, 1, 1, tmp, tmp_len);
    silc_client_command_pending(conn, SILC_COMMAND_CMODE, conn->cmd_ident,
				silc_client_command_resume_cmode, session);
  }

  silc_id_payload_free(idp);

  if (cmd->status != SILC_STATUS_OK &&
      cmd->status != SILC_STATUS_LIST_END)
    return;

  /* Unregister this command reply */
  silc_client_command_unregister(client, SILC_COMMAND_IDENTIFY, NULL,
				 silc_client_command_reply_resume,
				 cmd->ident);
  return;

 err:
  session->channel_count--;
  if (!session->channel_count)
    RESUME_CALL_COMPLETION(client, session, FALSE);
}

/* Received cmode to channel entry */

SILC_CLIENT_CMD_FUNC(resume_cmode)
{
  SilcClientResumeSession session = context;
  SilcClientCommandReplyContext cmd = context2;
  SilcClient client = session->client;
  SilcClientConnection conn = session->conn;
  unsigned char *tmp;
  SilcChannelID *channel_id;
  SilcChannelEntry channel;
  SilcUInt32 len;

  SILC_LOG_DEBUG(("Start"));

  /* Unregister this command reply */
  silc_client_command_unregister(client, SILC_COMMAND_CMODE, NULL,
				 silc_client_command_reply_resume,
				 cmd->ident);

  if (cmd->error != SILC_STATUS_OK)
    goto err;

  /* Take Channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &len);
  if (!tmp)
    goto err;
  channel_id = silc_id_payload_parse_id(tmp, len, NULL);
  if (!channel_id)
    goto err;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (channel) {

    /* Get channel mode */
    tmp = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (tmp)
      SILC_GET32_MSB(channel->mode, tmp);

    tmp = silc_argument_get_arg_type(cmd->args, 2, &len);

    /* And now, we will send USERS to get users on the channel */
    SILC_LOG_DEBUG(("Sending USERS"));
    silc_client_command_register(client, SILC_COMMAND_USERS, NULL, NULL,
				 silc_client_command_reply_users_i, 0,
				 ++conn->cmd_ident);
    silc_client_command_send(client, conn, SILC_COMMAND_USERS,
			     conn->cmd_ident, 1, 1, tmp, len);
    silc_client_command_pending(conn, SILC_COMMAND_USERS, conn->cmd_ident,
				silc_client_command_resume_users, session);
  }

  silc_free(channel_id);
  return;

 err:
  session->channel_count--;
  if (!session->channel_count)
    RESUME_CALL_COMPLETION(client, session, FALSE);
}

/* Received users reply to a channel entry */

SILC_CLIENT_CMD_FUNC(resume_users)
{
  SilcClientResumeSession session = context;
  SilcClientCommandReplyContext cmd = context2;
  SilcClient client = session->client;
  SilcClientConnection conn = session->conn;
  SilcBufferStruct client_id_list, client_mode_list;
  unsigned char *tmp;
  SilcUInt32 tmp_len, list_count;
  SilcChannelEntry channel;
  SilcChannelID *channel_id = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Unregister this command reply */
  silc_client_command_unregister(client, SILC_COMMAND_USERS, NULL,
				 silc_client_command_reply_users_i,
				 cmd->ident);

  if (cmd->error != SILC_STATUS_OK)
    goto err;

  /* Get channel ID */
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto err;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!channel_id) {
    COMMAND_REPLY_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto err;
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto err;
  }
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto err;
  }
  silc_buffer_set(&client_id_list, tmp, tmp_len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto err;
  }
  silc_buffer_set(&client_mode_list, tmp, tmp_len);

  /* Get channel entry */
  channel = silc_client_get_channel_by_id(cmd->client, conn, channel_id);
  if (!channel)
    goto err;

  /* Send fake JOIN command reply to application */
  client->internal->ops->command_reply(client, conn, cmd->payload, TRUE,
				       SILC_COMMAND_JOIN, cmd->status,
				       channel->channel_name, channel,
				       channel->mode, 0,
				       NULL, NULL, NULL, NULL,
				       channel->hmac, list_count,
				       &client_id_list, client_mode_list);

  /* Send TOPIC for this channel to get the topic */
  SILC_LOG_DEBUG(("Sending TOPIC"));
  tmp = silc_argument_get_arg_type(cmd->args, 2, &tmp_len);
  silc_client_command_send(client, conn, SILC_COMMAND_TOPIC,
			   ++conn->cmd_ident, 1, 1, tmp, tmp_len);

  /* Call the completion callback after we've got reply to all of
     our channels */
  session->channel_count--;
  if (!session->channel_count)
    RESUME_CALL_COMPLETION(client, session, TRUE);

  silc_free(channel_id);
  return;

 err:
  silc_free(channel_id);
  session->channel_count--;
  if (!session->channel_count)
    RESUME_CALL_COMPLETION(client, session, FALSE);
}
