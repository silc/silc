/*

  client_resume.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

SILC_CLIENT_CMD_REPLY_FUNC(resume);
SILC_CLIENT_CMD_FUNC(resume_identify);
SILC_CLIENT_CMD_FUNC(resume_cmode);
SILC_CLIENT_CMD_FUNC(resume_users);

#define RESUME_CALL_COMPLETION(client, session, s)			\
do {									\
  session->success = s;							\
  silc_schedule_task_add(client->schedule, 0,				\
			 silc_client_resume_call_completion, session,	\
			 0, 1, SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);	\
} while(0)

/* Generates the session detachment data. This data can be used later
   to resume back to the server. */

SilcBuffer silc_client_get_detach_data(SilcClient client,
				       SilcClientConnection conn)
{
  SilcBuffer detach;
  SilcHashTableList htl;
  SilcChannelUser chu;
  int ch_count;

  SILC_LOG_DEBUG(("Creating detachment data"));

  ch_count = silc_hash_table_count(conn->local_entry->channels);

  /* Save the nickname, Client ID and user mode in SILC network */
  detach = silc_buffer_alloc_size(2 + strlen(conn->nickname) +
				  2 + conn->local_id_data_len + 4 + 4);
  silc_buffer_format(detach,
		     SILC_STR_UI_SHORT(strlen(conn->nickname)),
		     SILC_STR_UI_XNSTRING(conn->nickname,
					  strlen(conn->nickname)),
		     SILC_STR_UI_SHORT(conn->local_id_data_len),
		     SILC_STR_UI_XNSTRING(conn->local_id_data,
					  conn->local_id_data_len),
		     SILC_STR_UI_INT(conn->local_entry->mode),
		     SILC_STR_UI_INT(ch_count),
		     SILC_STR_END);

  /* Save all joined channels */
  silc_hash_table_list(conn->local_entry->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&chu)) {
    unsigned char *chid = silc_id_id2str(chu->channel->id, SILC_ID_CHANNEL);
    SilcUInt16 chid_len = silc_id_get_len(chu->channel->id, SILC_ID_CHANNEL);

    detach = silc_buffer_realloc(detach, detach->truelen + 2 +
				 strlen(chu->channel->channel_name) +
				 2 + chid_len + 4);
    silc_buffer_pull(detach, detach->len);
    silc_buffer_pull_tail(detach, 2 + strlen(chu->channel->channel_name) +
			  2 + chid_len + 4);
    silc_buffer_format(detach,
		       SILC_STR_UI_SHORT(strlen(chu->channel->channel_name)),
		       SILC_STR_UI_XNSTRING(chu->channel->channel_name,
					   strlen(chu->channel->channel_name)),
		       SILC_STR_UI_SHORT(chid_len),
		       SILC_STR_UI_XNSTRING(chid, chid_len),
		       SILC_STR_UI_INT(chu->channel->mode),
		       SILC_STR_END);
    silc_free(chid);
  }
  silc_hash_table_list_reset(&htl);

  silc_buffer_push(detach, detach->data - detach->head);

  SILC_LOG_HEXDUMP(("Detach data"), detach->data, detach->len);

  return detach;
}

/* Processes the detachment data. This creates channels and other
   stuff according the data found in the the connection parameters.
   This doesn't actually resolve any detailed information from the
   server.  To do that call silc_client_resume_session function. 
   This returns the old detached session client ID. */

bool silc_client_process_detach_data(SilcClient client,
				     SilcClientConnection conn,
				     unsigned char **old_id,
				     SilcUInt16 *old_id_len)
{
  SilcBufferStruct detach;
  SilcUInt32 ch_count;
  int i, len;

  SILC_LOG_DEBUG(("Start"));

  silc_free(conn->nickname);
  silc_buffer_set(&detach, conn->params.detach_data, 
		  conn->params.detach_data_len);

  SILC_LOG_HEXDUMP(("Detach data"), detach.data, detach.len);

  /* Take the old client ID from the detachment data */
  len = silc_buffer_unformat(&detach,
			     SILC_STR_UI16_NSTRING_ALLOC(&conn->nickname, 
							 NULL),
			     SILC_STR_UI16_NSTRING_ALLOC(old_id, old_id_len),
			     SILC_STR_UI_INT(NULL),
			     SILC_STR_UI_INT(&ch_count),
			     SILC_STR_END);
  if (len == -1)
    return FALSE;

  silc_buffer_pull(&detach, len);

  for (i = 0; i < ch_count; i++) {
    char *channel;
    unsigned char *chid;
    SilcUInt16 chid_len;
    SilcUInt32 ch_mode;
    SilcChannelID *channel_id;
    SilcChannelEntry channel_entry;

    len = silc_buffer_unformat(&detach,
			       SILC_STR_UI16_NSTRING_ALLOC(&channel, NULL),
			       SILC_STR_UI16_NSTRING(&chid, &chid_len),
			       SILC_STR_UI_INT(&ch_mode),
			       SILC_STR_END);
    if (len == -1)
      return FALSE;

    /* Add new channel */
    channel_id = silc_id_str2id(chid, chid_len, SILC_ID_CHANNEL);
    channel_entry = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel_entry) {
      channel_entry = silc_client_add_channel(client, conn, channel, ch_mode,
					      channel_id);
    } else {
      silc_free(channel);
      silc_free(channel_id);
    }

    silc_buffer_pull(&detach, len);
  }
  silc_buffer_push(&detach, detach.data - detach.head);

  return TRUE;
}


/* Resume session context */
typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcClientResumeSessionCallback callback;
  void *context;
  SilcUInt32 channel_count;
  bool success;
} *SilcClientResumeSession;

/* Generic command reply callback */

SILC_CLIENT_CMD_REPLY_FUNC(resume)
{
  SilcClientCommandReplyContext cmd = (SilcClientCommandReplyContext)context;

  SILC_LOG_DEBUG(("Start"));

  if (cmd->callback)
    (*cmd->callback)(cmd->context, cmd);
}

/* Completion calling callback */

SILC_TASK_CALLBACK(silc_client_resume_call_completion)
{
  SilcClientResumeSession session = context;
  session->callback(session->client, session->conn, session->success,
		    session->context);
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
  bool ret;

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
  if (silc_idcache_get_all(conn->channel_cache, &list)) {
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
				   silc_client_command_reply_resume,
				   0, ++conn->cmd_ident);
      tmp = silc_command_payload_encode(SILC_COMMAND_IDENTIFY,
					res_argc, res_argv, res_argv_lens,
					res_argv_types, conn->cmd_ident);
      silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				  conn->cmd_ident,
				  silc_client_command_resume_identify,
				  session);
      silc_client_packet_send(client, conn->sock, SILC_PACKET_COMMAND, 
			      NULL, 0, NULL, NULL, tmp->data, tmp->len, TRUE);

      for (i = 0; i < res_argc; i++)
	silc_free(res_argv[i]);
      silc_free(res_argv);
      silc_free(res_argv_lens);
      silc_free(res_argv_types);
      silc_buffer_free(tmp);
    }
  }

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
    COMMAND_REPLY_ERROR;
    goto err;
  }
  channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
  if (!channel_id) {
    COMMAND_REPLY_ERROR;
    goto err;
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(cmd->args, 3, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto err;
  }
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(cmd->args, 4, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
    goto err;
  }
  silc_buffer_set(&client_id_list, tmp, tmp_len);

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(cmd->args, 5, &tmp_len);
  if (!tmp) {
    COMMAND_REPLY_ERROR;
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
			   conn->cmd_ident, 1, 1, tmp, tmp_len);

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
