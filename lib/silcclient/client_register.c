/*

  client_register.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************** Types and definitions ***************************/

/* Resume session context */
typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcBufferStruct detach;
  char *nickname;
  SilcClientID client_id;
  SilcUInt32 channel_count;
  SilcUInt32 *cmd_idents;
  SilcUInt32 cmd_idents_count;
  SilcBool success;
} *SilcClientResumeSession;

/************************ Static utility functions **************************/

/* Command callback.  Nothing interesting to do here. */

static SilcBool
silc_client_register_command_called(SilcClient client,
				    SilcClientConnection conn,
				    SilcCommand command,
				    SilcStatus status,
				    SilcStatus error,
				    void *context,
				    va_list ap)
{
  return FALSE;
}

/* Continues resuming after resolving.  Continue after last reply. */

static SilcBool
silc_client_resume_continue(SilcClient client,
			    SilcClientConnection conn,
			    SilcCommand command,
			    SilcStatus status,
			    SilcStatus error,
			    void *context,
			    va_list ap)
{
  if (status == SILC_STATUS_OK || status == SILC_STATUS_LIST_END ||
      SILC_STATUS_IS_ERROR(status)) {
    silc_fsm_continue(&conn->internal->event_thread);
    return FALSE;
  }

  return TRUE;
}

/****************************** NEW_ID packet *******************************/

/* Received new ID packet from server during registering to SILC network */

SILC_FSM_STATE(silc_client_new_id)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcID id;

  if (conn->local_id)
    goto out;

  SILC_LOG_DEBUG(("New ID received from server"));

  if (!silc_id_payload_parse_id(silc_buffer_data(&packet->buffer),
				silc_buffer_len(&packet->buffer), &id))
    goto out;

  SILC_LOG_DEBUG(("New ID %s", silc_id_render(&id.u.client_id,
					      SILC_ID_CLIENT)));

  /* Create local client entry */
  conn->local_entry = silc_client_add_client(client, conn,
					     client->username,
					     client->username,
					     client->realname,
					     &id.u.client_id, 0);
  if (!conn->local_entry)
    goto out;

  /* Save the ID */
  conn->local_id = &conn->local_entry->id;
  conn->internal->local_idp = silc_buffer_copy(&packet->buffer);

  /* Save cache entry */
  silc_mutex_lock(conn->internal->lock);
  if (!silc_idcache_find_by_id_one(conn->internal->client_cache,
				   conn->local_id,
				   &conn->internal->local_entry)) {
    silc_mutex_unlock(conn->internal->lock);
    goto out;
  }
  silc_mutex_unlock(conn->internal->lock);

  /* Save remote ID */
  if (packet->src_id_len) {
    conn->internal->remote_idp =
      silc_id_payload_encode_data(packet->src_id,
				  packet->src_id_len,
				  packet->src_id_type);
    if (!conn->internal->remote_idp)
      goto out;
    silc_id_payload_parse_id(silc_buffer_data(conn->internal->remote_idp),
			     silc_buffer_len(conn->internal->remote_idp),
			     &conn->remote_id);
  }

  /* Set IDs to the packet stream */
  silc_packet_set_ids(conn->stream, SILC_ID_CLIENT, conn->local_id,
		      conn->remote_id.type, SILC_ID_GET_ID(conn->remote_id));

  /* Signal connection that new ID was received so it can continue
     with the registering. */
  if (conn->internal->registering)
    silc_fsm_continue_sync(&conn->internal->event_thread);

 out:
  /** Packet processed */
  silc_packet_free(packet);
  return SILC_FSM_FINISH;
}


/************************ Register to SILC network **************************/

/* Register to network */

SILC_FSM_STATE(silc_client_st_register)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  SILC_LOG_DEBUG(("Register to network"));

  /* Send NEW_CLIENT packet to register to network */
  if (!silc_packet_send_va(conn->stream, SILC_PACKET_NEW_CLIENT, 0,
			   SILC_STR_UI_SHORT(strlen(client->username)),
			   SILC_STR_DATA(client->username,
					 strlen(client->username)),
			   SILC_STR_UI_SHORT(strlen(client->realname)),
			   SILC_STR_DATA(client->realname,
					 strlen(client->realname)),
			   SILC_STR_END)) {
    /** Error sending packet */
    silc_fsm_next(fsm, silc_client_st_register_error);
    return SILC_FSM_CONTINUE;
  }

  /** Wait for new ID */
  conn->internal->registering = TRUE;
  silc_fsm_next_later(fsm, silc_client_st_register_complete,
		      conn->internal->retry_timer, 0);
  return SILC_FSM_WAIT;
}

/* Wait for NEW_ID packet to arrive */

SILC_FSM_STATE(silc_client_st_register_complete)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  if (!conn->local_id) {
    if (conn->internal->retry_count++ >= SILC_CLIENT_RETRY_COUNT) {
      /** Timeout, ID not received */
      conn->internal->registering = FALSE;
      conn->internal->retry_count = 0;
      conn->internal->retry_timer = SILC_CLIENT_RETRY_MIN;
      silc_fsm_next(fsm, silc_client_st_register_error);
      return SILC_FSM_CONTINUE;
    }

    /** Resend registering packet */
    silc_fsm_next(fsm, silc_client_st_register);
    conn->internal->retry_timer = ((conn->internal->retry_timer *
				    SILC_CLIENT_RETRY_MUL) +
				   (silc_rng_get_rn16(client->rng) %
				    SILC_CLIENT_RETRY_RAND));
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Registered to network"));

  /* Issue IDENTIFY command for itself to get resolved hostname
     correctly from server. */
  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
			   silc_client_register_command_called, NULL,
			   1, 5, silc_buffer_data(conn->internal->local_idp),
			   silc_buffer_len(conn->internal->local_idp));

  /* Call NICK command if the nickname was set by the application (and is
     not same as the username). */
  if (conn->internal->params.nickname &&
      !silc_utf8_strcasecmp(conn->internal->params.nickname, client->username))
    silc_client_command_call(client, conn, NULL,
			     "NICK", conn->internal->params.nickname, NULL);

  /* Issue INFO command to fetch the real server name and server
     information and other stuff. */
  silc_client_command_send(client, conn, SILC_COMMAND_INFO,
			   silc_client_register_command_called, NULL,
			   1, 2, silc_buffer_data(conn->internal->remote_idp),
			   silc_buffer_len(conn->internal->remote_idp));

  /* Call connection callback.  We are now inside SILC network. */
  conn->callback(client, conn, SILC_CLIENT_CONN_SUCCESS, 0, NULL,
		 conn->callback_context);

  conn->internal->registering = FALSE;
  silc_schedule_task_del_by_all(conn->internal->schedule, 0,
				silc_client_connect_timeout, conn);

  return SILC_FSM_FINISH;
}

/* Error registering to network */

SILC_FSM_STATE(silc_client_st_register_error)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  SILC_LOG_DEBUG(("Error registering to network"));

  /* Signal to close connection */
  if (!conn->internal->disconnected) {
    conn->internal->disconnected = TRUE;
    SILC_FSM_SEMA_POST(&conn->internal->wait_event);
  }

  /* Call connect callback */
  conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		 conn->callback_context);

  silc_schedule_task_del_by_all(conn->internal->schedule, 0,
				silc_client_connect_timeout, conn);

  return SILC_FSM_FINISH;
}

/************************* Resume detached session **************************/

/* Resume detached session */

SILC_FSM_STATE(silc_client_st_resume)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientResumeSession resume;
  SilcBuffer auth;
  unsigned char *id;
  SilcUInt16 id_len;
  int ret;

  SILC_LOG_DEBUG(("Resuming detached session"));

  resume = silc_calloc(1, sizeof(*resume));
  if (!resume) {
    /** Out of memory */
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }
  silc_fsm_set_state_context(fsm, resume);

  silc_buffer_set(&resume->detach, conn->internal->params.detach_data,
		  conn->internal->params.detach_data_len);
  SILC_LOG_HEXDUMP(("Detach data"), silc_buffer_data(&resume->detach),
		   silc_buffer_len(&resume->detach));

  /* Take the old client ID from the detachment data */
  ret = silc_buffer_unformat(&resume->detach,
			     SILC_STR_ADVANCE,
			     SILC_STR_UI16_NSTRING_ALLOC(&resume->nickname,
							 NULL),
			     SILC_STR_UI16_NSTRING(&id, &id_len),
			     SILC_STR_UI_INT(NULL),
			     SILC_STR_UI_INT(&resume->channel_count),
			     SILC_STR_END);
  if (ret < 0) {
    /** Malformed detach data */
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }

  if (!silc_id_str2id(id, id_len, SILC_ID_CLIENT, &resume->client_id,
		      sizeof(resume->client_id))) {
    /** Malformed ID */
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }

  /* Generate authentication data that server will verify */
  auth = silc_auth_public_key_auth_generate(conn->public_key,
					    conn->private_key,
					    client->rng,
					    conn->internal->hash,
					    &resume->client_id,
					    SILC_ID_CLIENT);
  if (!auth) {
    /** Out of memory */
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }

  /* Send RESUME_CLIENT packet to resume to network */
  if (!silc_packet_send_va(conn->stream, SILC_PACKET_RESUME_CLIENT, 0,
			   SILC_STR_UI_SHORT(id_len),
			   SILC_STR_DATA(id, id_len),
			   SILC_STR_DATA(silc_buffer_data(auth),
					 silc_buffer_len(auth)),
			   SILC_STR_END)) {
    /** Error sending packet */
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }

  /** Wait for new ID */
  conn->internal->registering = TRUE;
  silc_fsm_next_later(fsm, silc_client_st_resume_resolve_channels, 15, 0);
  return SILC_FSM_WAIT;
}

/* Resolve the old session information, user mode and joined channels. */

SILC_FSM_STATE(silc_client_st_resume_resolve_channels)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientResumeSession resume = state_context;
  SilcUInt32 *res_argv_lens = NULL, *res_argv_types = NULL, res_argc = 0;
  unsigned char **res_argv = NULL;
  int i;

  if (!conn->local_id) {
    /** Timeout, ID not received */
    conn->internal->registering = FALSE;
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }

  /* First, send UMODE command to get our own user mode in the network */
  SILC_LOG_DEBUG(("Resolving user mode"));
  silc_client_command_send(client, conn, SILC_COMMAND_UMODE,
			   silc_client_register_command_called, NULL,
			   1, 1, silc_buffer_data(conn->internal->local_idp),
			   silc_buffer_len(conn->internal->local_idp));

  /* Second, send IDENTIFY command for all channels we know about.  These
     are the channels we've joined to according our detachment data. */
  for (i = 0; i < resume->channel_count; i++) {
    SilcChannelID channel_id;
    unsigned char *chid;
    SilcUInt16 chid_len;
    SilcBuffer idp;

    if (silc_buffer_unformat(&resume->detach,
			     SILC_STR_ADVANCE,
			     SILC_STR_UI16_NSTRING(NULL, NULL),
			     SILC_STR_UI16_NSTRING(&chid, &chid_len),
			     SILC_STR_UI_INT(NULL),
			     SILC_STR_END) < 0)
      continue;

    idp = silc_id_payload_encode_data(chid, chid_len, SILC_ID_CHANNEL);
    if (!idp)
      continue;
    res_argv = silc_realloc(res_argv, sizeof(*res_argv) * (res_argc + 1));
    res_argv_lens = silc_realloc(res_argv_lens, sizeof(*res_argv_lens) *
				 (res_argc + 1));
    res_argv_types = silc_realloc(res_argv_types, sizeof(*res_argv_types) *
				  (res_argc + 1));
    res_argv[res_argc] = silc_buffer_steal(idp, &res_argv_lens[res_argc]);
    res_argv_types[res_argc] = res_argc + 5;
    res_argc++;
    silc_buffer_free(idp);
  }

  /* Send IDENTIFY command */
  SILC_LOG_DEBUG(("Resolving joined channels"));
  silc_client_command_send_argv(client, conn, SILC_COMMAND_IDENTIFY,
				silc_client_resume_continue, conn,
				res_argc, res_argv, res_argv_lens,
				res_argv_types);

  for (i = 0; i < resume->channel_count; i++)
    silc_free(res_argv[i]);
  silc_free(res_argv);
  silc_free(res_argv_lens);
  silc_free(res_argv_types);

  /** Wait for channels */
  silc_fsm_next(fsm, silc_client_st_resume_resolve_cmodes);
  return SILC_FSM_WAIT;
}

/* Resolve joined channel modes. */

SILC_FSM_STATE(silc_client_st_resume_resolve_cmodes)
{
  SilcClientConnection conn = fsm_context;
  SilcClientResumeSession resume = state_context;
  SilcHashTableList htl;
  SilcChannelUser chu;

  SILC_LOG_DEBUG(("Resolving joined channel modes"));

  silc_hash_table_list(conn->local_entry->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {

  }
  silc_hash_table_list_reset(&htl);

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_client_st_resume_error)
{
  /* XXX */
  /* Close connection */

  return SILC_FSM_FINISH;
}

/* Generates the session detachment data. This data can be used later
   to resume back to the server. */

SilcBuffer silc_client_get_detach_data(SilcClient client,
				       SilcClientConnection conn)
{
  SilcBuffer detach;
  SilcHashTableList htl;
  SilcChannelUser chu;
  int ret, ch_count;

  SILC_LOG_DEBUG(("Creating detachment data"));

  ch_count = silc_hash_table_count(conn->local_entry->channels);

  /* Save the nickname, Client ID and user mode in SILC network */
  detach = silc_buffer_alloc(0);
  if (!detach)
    return NULL;
  ret =
    silc_buffer_format(detach,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI_SHORT(strlen(conn->local_entry->nickname)),
		       SILC_STR_DATA(conn->local_entry->nickname,
				     strlen(conn->local_entry->nickname)),
		       SILC_STR_UI_SHORT(silc_buffer_len(conn->internal->
							 local_idp)),
		       SILC_STR_DATA(silc_buffer_data(conn->internal->
						      local_idp),
				     silc_buffer_len(conn->internal->
						     local_idp)),
		       SILC_STR_UI_INT(conn->local_entry->mode),
		       SILC_STR_UI_INT(ch_count),
		       SILC_STR_END);
  if (ret < 0) {
    silc_buffer_free(detach);
    return NULL;
  }

  /* Save all joined channels */
  silc_hash_table_list(conn->local_entry->channels, &htl);
  while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
    unsigned char chid[32];
    SilcUInt32 chid_len;

    silc_id_id2str(&chu->channel->id, SILC_ID_CHANNEL, chid, sizeof(chid),
		   &chid_len);
    silc_buffer_format(detach,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI_SHORT(strlen(chu->channel->channel_name)),
		       SILC_STR_DATA(chu->channel->channel_name,
				     strlen(chu->channel->channel_name)),
		       SILC_STR_UI_SHORT(chid_len),
		       SILC_STR_DATA(chid, chid_len),
		       SILC_STR_UI_INT(chu->channel->mode),
		       SILC_STR_END);
    silc_free(chid);
  }
  silc_hash_table_list_reset(&htl);

  silc_buffer_start(detach);
  SILC_LOG_HEXDUMP(("Detach data"), silc_buffer_data(detach),
		   silc_buffer_len(detach));

  return detach;
}
