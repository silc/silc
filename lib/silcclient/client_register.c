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
  silc_idcache_find_by_id_one(conn->internal->client_cache, conn->local_id,
			      &conn->internal->local_entry);

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
  silc_fsm_next_later(fsm, silc_client_st_register_complete, 15, 0);
  return SILC_FSM_WAIT;
}

/* Wait for NEW_ID packet to arrive */

SILC_FSM_STATE(silc_client_st_register_complete)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  if (!conn->local_id) {
    /** Timeout, ID not received */
    conn->internal->registering = FALSE;
    silc_fsm_next(fsm, silc_client_st_register_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Registered to network"));

  /* Issue IDENTIFY command for itself to get resolved hostname
     correctly from server. */
  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY, NULL, NULL,
			   1, 5, silc_buffer_data(conn->internal->local_idp),
			   silc_buffer_len(conn->internal->local_idp));

  /* Send NICK command if the nickname was set by the application (and is
     not same as the username).  Send this with little timeout. */
  if (conn->internal->params.nickname &&
      !silc_utf8_strcasecmp(conn->internal->params.nickname, client->username))
    silc_client_command_send(client, conn, SILC_COMMAND_NICK, NULL, NULL,
			     1, 1, conn->internal->params.nickname,
			     strlen(conn->internal->params.nickname));

  /* Issue INFO command to fetch the real server name and server
     information and other stuff. */
  silc_client_command_send(client, conn, SILC_COMMAND_INFO, NULL, NULL,
			   1, 2, silc_buffer_data(conn->internal->remote_idp),
			   silc_buffer_len(conn->internal->remote_idp));

  /* Call connection callback.  We are now inside SILC network. */
  conn->callback(client, conn, SILC_CLIENT_CONN_SUCCESS, 0, NULL,
		 conn->callback_context);

  conn->internal->registering = FALSE;
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_client_st_register_error)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  /* XXX */
  /* Close connection */

  conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		 conn->callback_context);

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
			   SILC_STR_UI_XNSTRING(id, id_len),
			   SILC_STR_UI_XNSTRING(silc_buffer_data(auth),
						silc_buffer_len(auth)),
			   SILC_STR_END)) {
    /** Error sending packet */
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }

  /** Wait for new ID */
  conn->internal->registering = TRUE;
  silc_fsm_next_later(fsm, silc_client_st_resume_resolve, 15, 0);
  return SILC_FSM_WAIT;
}

/* Resolve the old session information */

SILC_FSM_STATE(silc_client_st_resume_resolve)
{
#if 0
  SilcClientConnection conn = fsm_context;
  SilcClientResumeSession resume = state_context;

  if (!conn->local_id) {
    /** Timeout, ID not received */
    conn->internal->registering = FALSE;
    silc_fsm_next(fsm, silc_client_st_resume_error);
    return SILC_FSM_CONTINUE;
  }


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
#endif /* 0 */

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
