/*

  command_reply.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

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

/************************** Types and definitions ***************************/

/* Calls error command reply callback back to command sender. */
#define ERROR_CALLBACK(err)					\
do {								\
  void *arg1 = NULL, *arg2 = NULL;				\
  if (cmd->status != SILC_STATUS_OK)				\
    silc_status_get_args(cmd->status, args, &arg1, &arg2);	\
  else								\
    cmd->status = cmd->error = err;				\
  SILC_LOG_DEBUG(("Error in command reply: %s",			\
		 silc_get_status_message(cmd->status)));	\
  silc_client_command_callback(cmd, arg1, arg2);		\
} while(0)

/* Check for error */
#define CHECK_STATUS(msg)						\
  SILC_LOG_DEBUG(("%s", silc_get_command_name(cmd->cmd)));		\
  if (cmd->error != SILC_STATUS_OK) {					\
    if (cmd->verbose)							\
      SAY(cmd->conn->client, cmd->conn, SILC_CLIENT_MESSAGE_ERROR,	\
	  msg "%s", silc_get_status_message(cmd->error));		\
    ERROR_CALLBACK(cmd->error);						\
    silc_client_command_process_error(cmd, state_context, cmd->error);	\
    silc_fsm_next(fsm, silc_client_command_reply_processed);		\
    return SILC_FSM_CONTINUE;						\
  }

/* Check for correct arguments */
#define CHECK_ARGS(min, max)					\
  if (silc_argument_get_arg_num(args) < min ||			\
      silc_argument_get_arg_num(args) > max) {			\
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);		\
    silc_fsm_next(fsm, silc_client_command_reply_processed);	\
    return SILC_FSM_CONTINUE;					\
  }

#define SAY cmd->conn->client->internal->ops->say

/************************ Static utility functions **************************/

/* Delivers the command reply back to application */

static inline void
silc_client_command_callback(SilcClientCommandContext cmd, ...)
{
  SilcClientCommandReplyCallback cb;
  va_list ap, cp;

  va_start(ap, cmd);

  /* Default reply callback */
  if (cmd->called) {
    silc_va_copy(cp, ap);
    cmd->conn->client->internal->ops->command_reply(
		       cmd->conn->client, cmd->conn, cmd->cmd, cmd->status,
		       cmd->error, cp);
    va_end(cp);
  }

  /* Reply callback */
  silc_list_start(cmd->reply_callbacks);
  while ((cb = silc_list_get(cmd->reply_callbacks)))
    if (!cb->do_not_call) {
      silc_va_copy(cp, ap);
      cb->do_not_call = !cb->reply(cmd->conn->client, cmd->conn, cmd->cmd,
				   cmd->status, cmd->error, cb->context, cp);
      va_end(cp);
    }

  va_end(ap);
}

/* Handles common error status types. */

static void silc_client_command_process_error(SilcClientCommandContext cmd,
					      SilcCommandPayload payload,
					      SilcStatus error)
{
  SilcClient client = cmd->conn->client;
  SilcClientConnection conn = cmd->conn;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry;
  SilcID id;

  if (cmd->error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
    /* Remove unknown client entry from cache */
    if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL))
      return;

    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (client_entry) {
      silc_client_unref_client(client, conn, client_entry);
      silc_client_del_client(client, conn, client_entry);
    }
  }
}

/***************************** Command Reply ********************************/

/* Process received command reply packet */

SILC_FSM_STATE(silc_client_command_reply)
{
  SilcClientConnection conn = fsm_context;
  SilcPacket packet = state_context;
  SilcClientCommandContext cmd;
  SilcCommandPayload payload;
  SilcCommand command;
  SilcUInt16 cmd_ident;

  /* Get command reply payload from packet */
  payload = silc_command_payload_parse(silc_buffer_datalen(&packet->buffer));
  silc_packet_free(packet);
  if (!payload) {
    SILC_LOG_DEBUG(("Bad command reply packet"));
    return SILC_FSM_FINISH;
  }

  cmd_ident = silc_command_get_ident(payload);
  command = silc_command_get(payload);

  /* Find the command pending reply */
  silc_mutex_lock(conn->internal->lock);
  silc_list_start(conn->internal->pending_commands);
  while ((cmd = silc_list_get(conn->internal->pending_commands))) {
    if ((cmd->cmd == command || cmd->cmd == SILC_COMMAND_NONE)
	&& cmd->cmd_ident == cmd_ident) {
      silc_list_del(conn->internal->pending_commands, cmd);
      break;
    }
  }
  silc_mutex_unlock(conn->internal->lock);

  if (!cmd) {
    SILC_LOG_DEBUG(("Unknown command reply %s, ident %d",
		    silc_get_command_name(command), cmd_ident));
    silc_command_payload_free(payload);
    return SILC_FSM_FINISH;
  }

  /* Signal command thread that command reply has arrived */
  silc_fsm_set_state_context(&cmd->thread, payload);
  silc_fsm_next(&cmd->thread, silc_client_command_reply_process);
  silc_fsm_continue_sync(&cmd->thread);

  return SILC_FSM_FINISH;
}

/* Wait here for command reply to arrive from remote host */

SILC_FSM_STATE(silc_client_command_reply_wait)
{
  SILC_LOG_DEBUG(("Wait for command reply"));

  /** Wait for command reply */
  silc_fsm_set_state_context(fsm, NULL);
  silc_fsm_next_later(fsm, silc_client_command_reply_timeout, 20, 0);
  return SILC_FSM_WAIT;
}

/* Timeout occurred while waiting command reply */

SILC_FSM_STATE(silc_client_command_reply_timeout)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcArgumentPayload args = NULL;

  SILC_LOG_DEBUG(("Command %s timeout", silc_get_command_name(cmd->cmd)));

  /* Timeout, reply not received in timely fashion */
  silc_list_del(conn->internal->pending_commands, cmd);
  ERROR_CALLBACK(SILC_STATUS_ERR_TIMEDOUT);
  return SILC_FSM_FINISH;
}

/* Process received command reply payload */

SILC_FSM_STATE(silc_client_command_reply_process)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcCommandPayload payload = state_context;

  silc_command_get_status(payload, &cmd->status, &cmd->error);

  switch (cmd->cmd) {
  case SILC_COMMAND_WHOIS:
    /** WHOIS */
    silc_fsm_next(fsm, silc_client_command_reply_whois);
    break;
  case SILC_COMMAND_WHOWAS:
    /** WHOWAS */
    silc_fsm_next(fsm, silc_client_command_reply_whowas);
    break;
  case SILC_COMMAND_IDENTIFY:
    /** IDENTIFY */
    silc_fsm_next(fsm, silc_client_command_reply_identify);
    break;
  case SILC_COMMAND_NICK:
    /** NICK */
    silc_fsm_next(fsm, silc_client_command_reply_nick);
    break;
  case SILC_COMMAND_LIST:
    /** LIST */
    silc_fsm_next(fsm, silc_client_command_reply_list);
    break;
  case SILC_COMMAND_TOPIC:
    /** TOPIC */
    silc_fsm_next(fsm, silc_client_command_reply_topic);
    break;
  case SILC_COMMAND_INVITE:
    /** INVITE */
    silc_fsm_next(fsm, silc_client_command_reply_invite);
    break;
  case SILC_COMMAND_QUIT:
    /** QUIT */
    silc_fsm_next(fsm, silc_client_command_reply_quit);
    break;
  case SILC_COMMAND_KILL:
    /** KILL */
    silc_fsm_next(fsm, silc_client_command_reply_kill);
    break;
  case SILC_COMMAND_INFO:
    /** INFO */
    silc_fsm_next(fsm, silc_client_command_reply_info);
    break;
  case SILC_COMMAND_STATS:
    /** STATS */
    silc_fsm_next(fsm, silc_client_command_reply_stats);
    break;
  case SILC_COMMAND_PING:
    /** PING */
    silc_fsm_next(fsm, silc_client_command_reply_ping);
    break;
  case SILC_COMMAND_OPER:
    /** OPER */
    silc_fsm_next(fsm, silc_client_command_reply_oper);
    break;
  case SILC_COMMAND_JOIN:
    /** JOIN */
    silc_fsm_next(fsm, silc_client_command_reply_join);
    break;
  case SILC_COMMAND_MOTD:
    /** MOTD */
    silc_fsm_next(fsm, silc_client_command_reply_motd);
    break;
  case SILC_COMMAND_UMODE:
    /** UMODE */
    silc_fsm_next(fsm, silc_client_command_reply_umode);
    break;
  case SILC_COMMAND_CMODE:
    /** CMODE */
    silc_fsm_next(fsm, silc_client_command_reply_cmode);
    break;
  case SILC_COMMAND_CUMODE:
    /** CUMODE */
    silc_fsm_next(fsm, silc_client_command_reply_cumode);
    break;
  case SILC_COMMAND_KICK:
    /** KICK */
    silc_fsm_next(fsm, silc_client_command_reply_kick);
    break;
  case SILC_COMMAND_BAN:
    /** BAN */
    silc_fsm_next(fsm, silc_client_command_reply_ban);
    break;
  case SILC_COMMAND_DETACH:
    /** DETACH */
    silc_fsm_next(fsm, silc_client_command_reply_detach);
    break;
  case SILC_COMMAND_WATCH:
    /** WATCH */
    silc_fsm_next(fsm, silc_client_command_reply_watch);
    break;
  case SILC_COMMAND_SILCOPER:
    /** SILCOPER */
    silc_fsm_next(fsm, silc_client_command_reply_silcoper);
    break;
  case SILC_COMMAND_LEAVE:
    /** LEAVE */
    silc_fsm_next(fsm, silc_client_command_reply_leave);
    break;
  case SILC_COMMAND_USERS:
    /** USERS */
    silc_fsm_next(fsm, silc_client_command_reply_users);
    break;
  case SILC_COMMAND_GETKEY:
    /** GETKEY */
    silc_fsm_next(fsm, silc_client_command_reply_getkey);
    break;
  case SILC_COMMAND_SERVICE:
    /** SERVICE */
    silc_fsm_next(fsm, silc_client_command_reply_service);
    break;
  default:
    return SILC_FSM_FINISH;
  }

  return SILC_FSM_CONTINUE;
}

/* Completes command reply processing */

SILC_FSM_STATE(silc_client_command_reply_processed)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcCommandPayload payload = state_context;

  silc_command_payload_free(payload);

  if (cmd->status == SILC_STATUS_OK || cmd->status == SILC_STATUS_LIST_END ||
      SILC_STATUS_IS_ERROR(cmd->status))
    return SILC_FSM_FINISH;

  /* Add back to pending command reply list */
  silc_mutex_lock(conn->internal->lock);
  cmd->resolved = FALSE;
  silc_list_add(conn->internal->pending_commands, cmd);
  silc_mutex_unlock(conn->internal->lock);

  /** Wait more command payloads */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/******************************** WHOIS *************************************/

/* Received reply for WHOIS command. */

SILC_FSM_STATE(silc_client_command_reply_whois)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry = NULL;
  SilcUInt32 idle = 0, mode = 0, fingerprint_len, len, *umodes = NULL;
  SilcBufferStruct channels, ch_user_modes;
  SilcBool has_channels = FALSE;
  SilcDList channel_list = NULL;
  SilcID id;
  char *nickname = NULL, *username = NULL, *realname = NULL;
  unsigned char *fingerprint, *tmp;

  CHECK_STATUS("WHOIS: ");
  CHECK_ARGS(5, 11);

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get names */
  nickname = silc_argument_get_arg_type(args, 3, NULL);
  username = silc_argument_get_arg_type(args, 4, NULL);
  realname = silc_argument_get_arg_type(args, 5, NULL);
  if (!nickname || !username || !realname) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get joined channel list */
  memset(&channels, 0, sizeof(channels));
  tmp = silc_argument_get_arg_type(args, 6, &len);
  if (tmp) {
    has_channels = TRUE;
    silc_buffer_set(&channels, tmp, len);

    /* Get channel user mode list */
    tmp = silc_argument_get_arg_type(args, 10, &len);
    if (!tmp) {
      ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }
    silc_buffer_set(&ch_user_modes, tmp, len);
  }

  /* Get user mode */
  tmp = silc_argument_get_arg_type(args, 7, &len);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);

  /* Get idle time */
  tmp = silc_argument_get_arg_type(args, 8, &len);
  if (tmp)
    SILC_GET32_MSB(idle, tmp);

  /* Get fingerprint */
  fingerprint = silc_argument_get_arg_type(args, 9, &fingerprint_len);

  /* Check if we have this client cached already. */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry) {
    SILC_LOG_DEBUG(("Adding new client entry (WHOIS)"));
    client_entry =
      silc_client_add_client(client, conn, nickname, username, realname,
			     &id.u.client_id, mode);
    if (!client_entry) {
      ERROR_CALLBACK(SILC_STATUS_ERR_RESOURCE_LIMIT);
      goto out;
    }
    silc_client_ref_client(client, conn, client_entry);
  } else {
    silc_client_update_client(client, conn, client_entry,
			      nickname, username, realname, mode);
  }

  if (fingerprint && fingerprint_len == sizeof(client_entry->fingerprint))
    memcpy(client_entry->fingerprint, fingerprint, fingerprint_len);

  /* Get user attributes */
  tmp = silc_argument_get_arg_type(args, 11, &len);
  if (tmp) {
    if (client_entry->attrs)
      silc_attribute_payload_list_free(client_entry->attrs);
    client_entry->attrs = silc_attribute_payload_parse(tmp, len);
  }

  /* Parse channel and channel user mode list */
  if (has_channels) {
    channel_list = silc_channel_payload_parse_list(silc_buffer_data(&channels),
						   silc_buffer_len(&channels));
    if (channel_list)
      silc_get_mode_list(&ch_user_modes, silc_dlist_count(channel_list),
			 &umodes);
  }

  /* Notify application */
  silc_client_command_callback(cmd, client_entry, nickname, username,
			       realname, channel_list, mode, idle, fingerprint,
			       umodes, client_entry->attrs);

  silc_client_unref_client(client, conn, client_entry);
  if (has_channels) {
    silc_dlist_uninit(channel_list);
    silc_free(umodes);
  }

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** WHOWAS ************************************/

/* Received reply for WHOWAS command. */

SILC_FSM_STATE(silc_client_command_reply_whowas)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry = NULL;
  SilcID id;
  char *nickname, *username;
  char *realname = NULL;

  CHECK_STATUS("WHOWAS: ");
  CHECK_ARGS(4, 5);

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);

  /* Get names */
  nickname = silc_argument_get_arg_type(args, 3, NULL);
  username = silc_argument_get_arg_type(args, 4, NULL);
  realname = silc_argument_get_arg_type(args, 5, NULL);
  if (!nickname || !username) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Notify application. We don't save any history information to any
     cache. Just pass the data to the application. */
  silc_client_command_callback(cmd, client_entry, nickname, username,
			       realname);

 out:
  silc_client_unref_client(client, conn, client_entry);
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** IDENTIFY **********************************/

/* Received reply for IDENTIFY command. */

SILC_FSM_STATE(silc_client_command_reply_identify)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry;
  SilcServerEntry server_entry;
  SilcChannelEntry channel_entry;
  SilcUInt32 len;
  SilcID id;
  char *name = NULL, *info = NULL;

  CHECK_STATUS("IDENTIFY: ");
  CHECK_ARGS(2, 4);

  /* Get the ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get names */
  name = silc_argument_get_arg_type(args, 3, &len);
  info = silc_argument_get_arg_type(args, 4, &len);

  switch (id.type) {
  case SILC_ID_CLIENT:
    SILC_LOG_DEBUG(("Received client information"));

    /* Check if we have this client cached already. */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!client_entry) {
      SILC_LOG_DEBUG(("Adding new client entry (IDENTIFY)"));
      client_entry =
	silc_client_add_client(client, conn, name, info, NULL,
			       &id.u.client_id, 0);
      if (!client_entry) {
	ERROR_CALLBACK(SILC_STATUS_ERR_RESOURCE_LIMIT);
	goto out;
      }
      silc_client_ref_client(client, conn, client_entry);
    } else {
      silc_client_update_client(client, conn, client_entry,
				name, info, NULL, 0);
    }

    /* Notify application */
    silc_client_command_callback(cmd, client_entry, name, info);
    silc_client_unref_client(client, conn, client_entry);
    break;

  case SILC_ID_SERVER:
    SILC_LOG_DEBUG(("Received server information"));

    /* Check if we have this server cached already. */
    server_entry = silc_client_get_server_by_id(client, conn, &id.u.server_id);
    if (!server_entry) {
      SILC_LOG_DEBUG(("Adding new server entry (IDENTIFY)"));
      server_entry = silc_client_add_server(client, conn, name, info,
					    &id.u.server_id);
      if (!server_entry) {
	ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }
      silc_client_ref_server(client, conn, server_entry);
    } else {
      silc_client_update_server(client, conn, server_entry, name, info);
    }
    server_entry->internal.resolve_cmd_ident = 0;

    /* Notify application */
    silc_client_command_callback(cmd, server_entry, name, info);
    silc_client_unref_server(client, conn, server_entry);
    break;

  case SILC_ID_CHANNEL:
    SILC_LOG_DEBUG(("Received channel information"));

    /* Check if we have this channel cached already. */
    channel_entry = silc_client_get_channel_by_id(client, conn,
						  &id.u.channel_id);
    if (!channel_entry) {
      SILC_LOG_DEBUG(("Adding new channel entry (IDENTIFY"));

      if (!name) {
	ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }

      /* Add new channel entry */
      channel_entry = silc_client_add_channel(client, conn, name, 0,
					      &id.u.channel_id);
      if (!channel_entry) {
	ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }
      silc_client_ref_channel(client, conn, channel_entry);
    }

    /* Notify application */
    silc_client_command_callback(cmd, channel_entry, name, info);
    silc_client_unref_channel(client, conn, channel_entry);
    break;
  }

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** NICK ************************************/

/* Received reply for command NICK. */

SILC_FSM_STATE(silc_client_command_reply_nick)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  unsigned char *tmp, *nick, *idp;
  SilcUInt32 len, idp_len;
  SilcClientID old_client_id;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot set nickname: ");
  CHECK_ARGS(2, 3);

  old_client_id = *conn->local_id;

  /* Take received Client ID */
  idp = silc_argument_get_arg_type(args, 2, &idp_len);
  if (!idp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (!silc_id_payload_parse_id(idp, idp_len, &id)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Take the new nickname */
  nick = silc_argument_get_arg_type(args, 3, &len);
  if (!nick) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Normalize nickname */
  tmp = silc_identifier_check(nick, len, SILC_STRING_UTF8, 128, NULL);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_BAD_NICKNAME);
    goto out;
  }

  /* Update the client entry */
  silc_mutex_lock(conn->internal->lock);
  if (!silc_idcache_update(conn->internal->client_cache,
			   conn->internal->local_entry,
			   &id.u.client_id, tmp, TRUE)) {
    silc_free(tmp);
    silc_mutex_unlock(conn->internal->lock);
    ERROR_CALLBACK(SILC_STATUS_ERR_BAD_NICKNAME);
    goto out;
  }
  silc_mutex_unlock(conn->internal->lock);
  memset(conn->local_entry->nickname, 0, sizeof(conn->local_entry->nickname));
  memcpy(conn->local_entry->nickname, nick, len);
  conn->local_entry->nickname_normalized = tmp;
  silc_buffer_enlarge(conn->internal->local_idp, idp_len);
  silc_buffer_put(conn->internal->local_idp, idp, idp_len);
  silc_client_nickname_format(client, conn, conn->local_entry);
  silc_packet_set_ids(conn->stream, SILC_ID_CLIENT, conn->local_id, 0, NULL);

  /* Notify application */
  silc_client_command_callback(cmd, conn->local_entry,
			       conn->local_entry->nickname, &old_client_id);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** LIST ************************************/

/* Received reply to the LIST command. */

SILC_FSM_STATE(silc_client_command_reply_list)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  unsigned char *tmp, *name, *topic;
  SilcUInt32 usercount = 0;
  SilcChannelEntry channel_entry = NULL;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot list channels: ");

  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    /* There were no channels in the network. */
    silc_client_command_callback(cmd, NULL, NULL, NULL, 0);
    silc_fsm_next(fsm, silc_client_command_reply_processed);
    return SILC_FSM_CONTINUE;
  }

  CHECK_ARGS(3, 5);

  name = silc_argument_get_arg_type(args, 3, NULL);
  if (!name) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  topic = silc_argument_get_arg_type(args, 4, NULL);
  tmp = silc_argument_get_arg_type(args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(usercount, tmp);

  /* Check whether the channel exists, and add it to cache if it doesn't. */
  channel_entry = silc_client_get_channel_by_id(client, conn,
						&id.u.channel_id);
  if (!channel_entry) {
    /* Add new channel entry */
    channel_entry = silc_client_add_channel(client, conn, name, 0,
					    &id.u.channel_id);
    if (!channel_entry) {
      ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }
    silc_client_ref_channel(client, conn, channel_entry);
  }

  /* Notify application */
  silc_client_command_callback(cmd, channel_entry, name, topic, usercount);

 out:
  silc_client_unref_channel(client, conn, channel_entry);
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* TOPIC ************************************/

/* Received reply to topic command. */

SILC_FSM_STATE(silc_client_command_reply_topic)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcChannelEntry channel;
  char *topic;
  SilcUInt32 len;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot set topic: ");
  CHECK_ARGS(2, 3);

  /* Take Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Take topic */
  topic = silc_argument_get_arg_type(args, 3, &len);
  if (topic) {
    silc_free(channel->topic);
    channel->topic = silc_memdup(topic, len);
  }

  /* Notify application */
  silc_client_command_callback(cmd, channel, channel->topic);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* INVITE ***********************************/

/* Received reply to invite command. */

SILC_FSM_STATE(silc_client_command_reply_invite)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcChannelEntry channel;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcArgumentPayload invite_args = NULL;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot invite: ");
  CHECK_ARGS(2, 3);

  /* Take Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the invite list */
  tmp = silc_argument_get_arg_type(args, 3, &len);
  if (tmp)
    invite_args = silc_argument_list_parse(tmp, len);

  /* Notify application */
  silc_client_command_callback(cmd, channel, invite_args);

  if (invite_args)
    silc_argument_payload_free(invite_args);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** KILL ************************************/

/* Received reply to the KILL command. */

SILC_FSM_STATE(silc_client_command_reply_kill)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot kill: ");
  CHECK_ARGS(2, 2);

  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the client entry, if exists */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);

  /* Notify application */
  silc_client_command_callback(cmd, client_entry);

  /* Remove the client from all channels and free it */
  if (client_entry) {
    silc_client_del_client(client, conn, client_entry);
    silc_client_unref_client(client, conn, client_entry);
  }

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** INFO ************************************/

/* Received reply to INFO command. We receive the server ID and some
   information about the server user requested. */

SILC_FSM_STATE(silc_client_command_reply_info)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcServerEntry server;
  char *server_name, *server_info;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot get info: ");
  CHECK_ARGS(4, 4);

  /* Get server ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get server name */
  server_name = silc_argument_get_arg_type(args, 3, NULL);
  if (!server_name) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get server info */
  server_info = silc_argument_get_arg_type(args, 4, NULL);
  if (!server_info) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* See whether we have this server cached. If not create it. */
  server = silc_client_get_server_by_id(client, conn, &id.u.server_id);
  if (!server) {
    SILC_LOG_DEBUG(("Add new server entry (INFO)"));
    server = silc_client_add_server(client, conn, server_name,
				    server_info, &id.u.server_id);
    if (!server)
      goto out;
    silc_client_ref_server(client, conn, server);
  }

  /* Notify application */
  silc_client_command_callback(cmd, server, server->server_name,
			       server->server_info);
  silc_client_unref_server(client, conn, server);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** STATS ***********************************/

/* Received reply to STATS command. */

SILC_FSM_STATE(silc_client_command_reply_stats)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientStats stats;
  unsigned char *buf = NULL;
  SilcUInt32 buf_len = 0;
  SilcBufferStruct b;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot get stats: ");
  CHECK_ARGS(2, 3);

  /* Get server ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get statistics structure */
  memset(&stats, 0, sizeof(stats));
  buf = silc_argument_get_arg_type(args, 3, &buf_len);
  if (buf) {
    silc_buffer_set(&b, buf, buf_len);
    silc_buffer_unformat(&b,
			 SILC_STR_UI_INT(&stats.starttime),
			 SILC_STR_UI_INT(&stats.uptime),
			 SILC_STR_UI_INT(&stats.my_clients),
			 SILC_STR_UI_INT(&stats.my_channels),
			 SILC_STR_UI_INT(&stats.my_server_ops),
			 SILC_STR_UI_INT(&stats.my_router_ops),
			 SILC_STR_UI_INT(&stats.cell_clients),
			 SILC_STR_UI_INT(&stats.cell_channels),
			 SILC_STR_UI_INT(&stats.cell_servers),
			 SILC_STR_UI_INT(&stats.clients),
			 SILC_STR_UI_INT(&stats.channels),
			 SILC_STR_UI_INT(&stats.servers),
			 SILC_STR_UI_INT(&stats.routers),
			 SILC_STR_UI_INT(&stats.server_ops),
			 SILC_STR_UI_INT(&stats.router_ops),
			 SILC_STR_END);
  }

  /* Notify application */
  silc_client_command_callback(cmd, &stats);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** PING ************************************/

/* Received reply to PING command. */

SILC_FSM_STATE(silc_client_command_reply_ping)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcInt64 diff;

  diff = silc_time() - SILC_PTR_TO_64(cmd->context);
  if (cmd->verbose)
    SAY(client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Ping reply from %s: %d second%s", conn->remote_host,
	(int)diff, diff == 1 ? "" : "s");

  /* Notify application */
  silc_client_command_callback(cmd);

  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** JOIN ************************************/

/* Continue JOIN command reply processing after resolving unknown users */

static void
silc_client_command_reply_join_resolved(SilcClient client,
					SilcClientConnection conn,
					SilcStatus status,
					SilcDList clients,
					void *context)
{
  SilcClientCommandContext cmd = context;
  SilcChannelEntry channel = cmd->context;

  channel->internal.resolve_cmd_ident = 0;
  silc_client_unref_channel(client, conn, channel);

  SILC_FSM_CALL_CONTINUE(&cmd->thread);
}


/* Received reply for JOIN command. */

SILC_FSM_STATE(silc_client_command_reply_join)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcChannelEntry channel;
  SilcUInt32 mode = 0, len, list_count;
  char *topic, *tmp, *channel_name = NULL, *hmac;
  const char *cipher;
  SilcBufferStruct client_id_list, client_mode_list, keyp;
  SilcHashTableList htl;
  SilcDList chpks = NULL;
  SilcID id;
  int i;

  /* Sanity checks */
  CHECK_STATUS("Cannot join channel: ");
  CHECK_ARGS(9, 17);

  /* Get channel name */
  channel_name = silc_argument_get_arg_type(args, 2, NULL);
  if (!channel_name) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get Channel ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Check whether we have this channel entry already. */
  channel = silc_client_get_channel(client, conn, channel_name);
  if (channel) {
    if (!SILC_ID_CHANNEL_COMPARE(&channel->id, &id.u.channel_id))
      silc_client_replace_channel_id(client, conn, channel, &id.u.channel_id);
  } else {
    /* Create new channel entry */
    channel = silc_client_add_channel(client, conn, channel_name,
				      mode, &id.u.channel_id);
    if (!channel) {
      ERROR_CALLBACK(SILC_STATUS_ERR_BAD_CHANNEL);
      goto out;
    }
    silc_client_ref_channel(client, conn, channel);
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(args, 12, &len);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(args, 13, &len);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  silc_buffer_set(&client_id_list, tmp, len);

  /* Resolve users we do not know about */
  if (!cmd->resolved) {
    cmd->resolved = TRUE;
    cmd->context = channel;
    SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		  silc_client_get_clients_by_list(
			  client, conn, list_count, &client_id_list,
			  silc_client_command_reply_join_resolved, cmd));
    /* NOT REACHED */
  }

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(args, 14, &len);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  silc_buffer_set(&client_mode_list, tmp, len);

  /* Add clients we received in the reply to the channel */
  for (i = 0; i < list_count; i++) {
    SilcUInt16 idp_len;
    SilcUInt32 mode;
    SilcID id;
    SilcClientEntry client_entry;

    /* Client ID */
    SILC_GET16_MSB(idp_len, client_id_list.data + 2);
    idp_len += 4;
    if (!silc_id_payload_parse_id(client_id_list.data, idp_len, &id))
      continue;

    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list.data);

    /* Get client entry */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!client_entry)
      continue;

    /* Join client to the channel */
    silc_client_add_to_channel(client, conn, channel, client_entry, mode);
    silc_client_unref_client(client, conn, client_entry);

    if (!silc_buffer_pull(&client_id_list, idp_len))
      goto out;
    if (!silc_buffer_pull(&client_mode_list, 4))
      goto out;
  }

  /* Get hmac */
  hmac = silc_argument_get_arg_type(args, 11, NULL);
  if (hmac) {
    if (!silc_hmac_alloc(hmac, NULL, &channel->internal.hmac)) {
      if (cmd->verbose)
	SAY(client, conn, SILC_CLIENT_MESSAGE_ERROR,
	    "Cannot join channel: Unsupported HMAC `%s'", hmac);
      ERROR_CALLBACK(SILC_STATUS_ERR_UNKNOWN_ALGORITHM);
      goto out;
    }
  }

  /* Get channel mode */
  tmp = silc_argument_get_arg_type(args, 5, NULL);
  if (tmp)
    SILC_GET32_MSB(mode, tmp);
  channel->mode = mode;

  /* Get channel key and save it */
  tmp = silc_argument_get_arg_type(args, 7, &len);
  if (tmp) {
    silc_buffer_set(&keyp, tmp, len);
    silc_client_save_channel_key(client, conn, &keyp, channel);
  }

  /* Get topic */
  topic = silc_argument_get_arg_type(args, 10, NULL);
  if (topic) {
    silc_free(channel->topic);
    channel->topic = silc_memdup(topic, strlen(topic));
  }

  /* Get founder key */
  tmp = silc_argument_get_arg_type(args, 15, &len);
  if (tmp) {
    if (channel->founder_key)
      silc_pkcs_public_key_free(channel->founder_key);
    channel->founder_key = NULL;
    silc_public_key_payload_decode(tmp, len, &channel->founder_key);
  }

  /* Get user limit */
  tmp = silc_argument_get_arg_type(args, 17, &len);
  if (tmp && len == 4)
    SILC_GET32_MSB(channel->user_limit, tmp);
  if (!(channel->mode & SILC_CHANNEL_MODE_ULIMIT))
    channel->user_limit = 0;

  /* Get channel public key list */
  tmp = silc_argument_get_arg_type(args, 16, &len);
  if (tmp)
    chpks = silc_argument_list_parse_decoded(tmp, len,
					     SILC_ARGUMENT_PUBLIC_KEY);

  /* Set current channel */
  conn->current_channel = channel;

  cipher = (channel->internal.channel_key ?
	    silc_cipher_get_name(channel->internal.channel_key) : NULL);
  silc_hash_table_list(channel->user_list, &htl);

  /* Notify application */
  silc_client_command_callback(cmd, channel_name, channel, mode, &htl,
			       topic, cipher, hmac, channel->founder_key,
			       chpks, channel->user_limit);

  if (chpks)
    silc_argument_list_free(chpks, SILC_ARGUMENT_PUBLIC_KEY);
  silc_hash_table_list_reset(&htl);
  silc_client_unref_channel(client, conn, channel);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** MOTD ************************************/

/* Received reply for MOTD command */

SILC_FSM_STATE(silc_client_command_reply_motd)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcUInt32 i;
  char *motd = NULL, *cp, line[256];

  /* Sanity checks */
  CHECK_STATUS("Cannot get motd: ");
  CHECK_ARGS(2, 3);

  if (silc_argument_get_arg_num(args) == 3) {
    motd = silc_argument_get_arg_type(args, 3, NULL);
    if (!motd) {
      ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
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

	if (cmd->verbose)
	  SAY(client, conn, SILC_CLIENT_MESSAGE_INFO, "%s", line);

	if (!strlen(cp))
	  break;
	i = 0;
      }
    }
  }

  /* Notify application */
  silc_client_command_callback(cmd, motd);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** UMODE ***********************************/

/* Received reply to the UMODE command. Save the current user mode */

SILC_FSM_STATE(silc_client_command_reply_umode)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  unsigned char *tmp;
  SilcUInt32 mode, len;

  /* Sanity checks */
  CHECK_STATUS("Cannot change mode: ");
  CHECK_ARGS(2, 2);

  tmp = silc_argument_get_arg_type(args, 2, &len);
  if (!tmp || len != 4) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  SILC_GET32_MSB(mode, tmp);
  conn->local_entry->mode = mode;

  /* Notify application */
  silc_client_command_callback(cmd, mode);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** CMODE ***********************************/

/* Received reply for CMODE command. */

SILC_FSM_STATE(silc_client_command_reply_cmode)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  unsigned char *tmp;
  SilcUInt32 mode;
  SilcChannelEntry channel;
  SilcUInt32 len;
  SilcPublicKey public_key = NULL;
  SilcDList channel_pubkeys = NULL;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot change mode: ");
  CHECK_ARGS(3, 6);

  /* Take Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get channel mode */
  tmp = silc_argument_get_arg_type(args, 3, &len);
  if (!tmp || len != 4) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Save the mode */
  SILC_GET32_MSB(mode, tmp);
  channel->mode = mode;

  /* Get founder public key */
  tmp = silc_argument_get_arg_type(args, 4, &len);
  if (tmp)
    silc_public_key_payload_decode(tmp, len, &public_key);

  /* Get user limit */
  tmp = silc_argument_get_arg_type(args, 6, &len);
  if (tmp && len == 4)
    SILC_GET32_MSB(channel->user_limit, tmp);
  if (!(channel->mode & SILC_CHANNEL_MODE_ULIMIT))
    channel->user_limit = 0;

  /* Get channel public key(s) */
  tmp = silc_argument_get_arg_type(args, 5, &len);
  if (tmp)
    channel_pubkeys =
      silc_argument_list_parse_decoded(tmp, len, SILC_ARGUMENT_PUBLIC_KEY);

  /* Notify application */
  silc_client_command_callback(cmd, channel, mode, public_key,
			       channel_pubkeys, channel->user_limit);

  silc_argument_list_free(channel_pubkeys, SILC_ARGUMENT_PUBLIC_KEY);

 out:
  if (public_key)
    silc_pkcs_public_key_free(public_key);
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** CUMODE **********************************/

/* Received reply for CUMODE command */

SILC_FSM_STATE(silc_client_command_reply_cumode)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  unsigned char *modev;
  SilcUInt32 len, mode;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot change mode: ");
  CHECK_ARGS(4, 4);

  /* Get channel mode */
  modev = silc_argument_get_arg_type(args, 2, &len);
  if (!modev || len != 4) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(mode, modev);

  /* Take Channel ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 4, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Save the mode */
  chu = silc_client_on_channel(channel, client_entry);
  if (chu)
    chu->mode = mode;

  /* Notify application */
  silc_client_command_callback(cmd, mode, channel, client_entry);

  silc_client_unref_client(client, conn, client_entry);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** KICK ************************************/

SILC_FSM_STATE(silc_client_command_reply_kick)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry;
  SilcChannelEntry channel;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot kick: ");
  CHECK_ARGS(3, 3);

  /* Take Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Notify application */
  silc_client_command_callback(cmd, channel, client_entry);

  silc_client_unref_client(client, conn, client_entry);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** SILCOPER **********************************/

SILC_FSM_STATE(silc_client_command_reply_silcoper)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);

  /* Sanity checks */
  CHECK_STATUS("Cannot change mode: ");
  CHECK_ARGS(1, 1);

  /* Notify application */
  silc_client_command_callback(cmd);

  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** OPER ************************************/

SILC_FSM_STATE(silc_client_command_reply_oper)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);

  /* Sanity checks */
  CHECK_STATUS("Cannot change mode: ");
  CHECK_ARGS(1, 1);

  /* Notify application */
  silc_client_command_callback(cmd);

  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* DETACH ***********************************/

SILC_FSM_STATE(silc_client_command_reply_detach)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcBuffer detach;

  /* Sanity checks */
  CHECK_STATUS("Cannot detach: ");
  CHECK_ARGS(1, 1);

  /* Notify application */
  silc_client_command_callback(cmd);

#if 0
  /* Generate the detachment data and deliver it to the client in the
     detach client operation */
  detach = silc_client_get_detach_data(client, conn);
  if (detach) {
    client->internal->ops->detach(client, conn, silc_buffer_data(detach),
				  silc_buffer_len(detach));
    silc_buffer_free(detach);
  }
#endif /* 0 */

  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** WATCH ***********************************/

SILC_FSM_STATE(silc_client_command_reply_watch)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);

  /* Sanity checks */
  CHECK_STATUS("Cannot set watch: ");
  CHECK_ARGS(1, 1);

  /* Notify application */
  silc_client_command_callback(cmd);

  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/*********************************** BAN ************************************/

SILC_FSM_STATE(silc_client_command_reply_ban)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcChannelEntry channel;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcArgumentPayload invite_args = NULL;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot set ban: ");
  CHECK_ARGS(2, 3);

  /* Take Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the invite list */
  tmp = silc_argument_get_arg_type(args, 3, &len);
  if (tmp)
    invite_args = silc_argument_list_parse(tmp, len);

  /* Notify application */
  silc_client_command_callback(cmd, channel, invite_args);

  if (invite_args)
    silc_argument_payload_free(invite_args);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** LEAVE ***********************************/

/* Reply to LEAVE command. */

SILC_FSM_STATE(silc_client_command_reply_leave)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcChannelEntry channel;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot set leave: ");
  CHECK_ARGS(2, 2);

  /* Get Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Remove us from this channel. */
  silc_client_remove_from_channel(client, conn, channel, conn->local_entry);

  /* Notify application */
  silc_client_command_callback(cmd, channel);

  /* Now delete the channel. */
  silc_client_del_channel(client, conn, channel);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* USERS ************************************/

/* Continue USERS command reply processing after resolving unknown users */

static void
silc_client_command_reply_users_resolved(SilcClient client,
					 SilcClientConnection conn,
					 SilcStatus status,
					 SilcDList clients,
					 void *context)
{
  SilcClientCommandContext cmd = context;
  SILC_FSM_CALL_CONTINUE(&cmd->thread);
}


/* Continue USERS command after resolving unknown channel */

static void
silc_client_command_reply_users_continue(SilcClient client,
					 SilcClientConnection conn,
					 SilcStatus status,
					 SilcDList channels,
					 void *context)
{
  SilcClientCommandContext cmd = context;

  if (!channels) {
    SilcCommandPayload payload = silc_fsm_get_state_context(&cmd->thread);
    SilcArgumentPayload args = silc_command_get_args(payload);

    cmd->status = SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID;
    ERROR_CALLBACK(cmd->status);
    silc_fsm_next(&cmd->thread, silc_client_command_reply_processed);
  }

  SILC_FSM_CALL_CONTINUE(&cmd->thread);
}

/* Reply to USERS command. Received list of client ID's and theirs modes
   on the channel we requested. */

SILC_FSM_STATE(silc_client_command_reply_users)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  unsigned char *tmp;
  SilcUInt32 tmp_len, list_count;
  SilcUInt16 idp_len, mode;
  SilcHashTableList htl;
  SilcBufferStruct client_id_list, client_mode_list;
  SilcChannelEntry channel;
  SilcClientEntry client_entry;
  SilcID id;
  int i;

  /* Sanity checks */
  CHECK_STATUS("Cannot get users: ");
  CHECK_ARGS(5, 5);

  /* Get channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel) {
    /* Resolve the channel from server */
    SILC_FSM_CALL(silc_client_get_channel_by_id_resolve(
			client, conn, &id.u.channel_id,
			silc_client_command_reply_users_continue, cmd));
    /* NOT REACHED */
  }

  /* Get the list count */
  tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
  if (!tmp || tmp_len != 4) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  SILC_GET32_MSB(list_count, tmp);

  /* Get Client ID list */
  tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  silc_buffer_set(&client_id_list, tmp, tmp_len);

  /* Resolve users we do not know about */
  if (!cmd->resolved) {
    cmd->resolved = TRUE;
    SILC_FSM_CALL(silc_client_get_clients_by_list(
			  client, conn, list_count, &client_id_list,
			  silc_client_command_reply_users_resolved, cmd));
    /* NOT REACHED */
  }

  /* Get client mode list */
  tmp = silc_argument_get_arg_type(args, 5, &tmp_len);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  silc_buffer_set(&client_mode_list, tmp, tmp_len);

  SILC_LOG_DEBUG(("channel %s, %d users", channel->channel_name, list_count));

  /* Cache the received Client ID's and modes. */
  for (i = 0; i < list_count; i++) {
    SILC_GET16_MSB(idp_len, client_id_list.data + 2);
    idp_len += 4;
    if (!silc_id_payload_parse_id(client_id_list.data, idp_len, &id))
      goto out;

    /* Mode */
    SILC_GET32_MSB(mode, client_mode_list.data);

    /* Save the client on this channel.  Unknown clients are ignored as they
       clearly do not exist since the resolving didn't find them. */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (client_entry)
      silc_client_add_to_channel(client, conn, channel, client_entry, mode);
    silc_client_unref_client(client, conn, client_entry);

    if (!silc_buffer_pull(&client_id_list, idp_len))
      goto out;
    if (!silc_buffer_pull(&client_mode_list, 4))
      goto out;
  }

  /* Notify application */
  silc_hash_table_list(channel->user_list, &htl);
  silc_client_command_callback(cmd, channel, &htl);
  silc_hash_table_list_reset(&htl);

 out:
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** GETKEY **********************************/

/* Received command reply to GETKEY command. WE've received the remote
   client's public key. */

SILC_FSM_STATE(silc_client_command_reply_getkey)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcClientEntry client_entry;
  SilcServerEntry server_entry;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcPublicKey public_key;
  SilcID id;

  /* Sanity checks */
  CHECK_STATUS("Cannot get key: ");
  CHECK_ARGS(2, 3);

  /* Get the ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Get the public key */
  tmp = silc_argument_get_arg_type(args, 3, &len);
  if (!tmp) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }
  if (!silc_public_key_payload_decode(tmp, len, &public_key)) {
    ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (id.type == SILC_ID_CLIENT) {
    /* Received client's public key */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!client_entry) {
      ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }

    /* Save fingerprint */
    if (!client_entry->fingerprint)
      silc_hash_make(conn->internal->sha1hash, tmp + 4, len - 4,
		     client_entry->fingerprint);
    if (!client_entry->public_key) {
      client_entry->public_key = public_key;
      public_key = NULL;
    }

    /* Notify application */
    silc_client_command_callback(cmd, SILC_ID_CLIENT, client_entry,
				 client_entry->public_key);
    silc_client_unref_client(client, conn, client_entry);
  } else if (id.type == SILC_ID_SERVER) {
    /* Received server's public key */
    server_entry = silc_client_get_server_by_id(client, conn, &id.u.server_id);
    if (!server_entry) {
      ERROR_CALLBACK(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }

    if (!server_entry->public_key) {
      server_entry->public_key = public_key;
      public_key = NULL;
    }

    /* Notify application */
    silc_client_command_callback(cmd, SILC_ID_SERVER, server_entry,
				 server_entry->public_key);
    silc_client_unref_server(client, conn, server_entry);
  }

 out:
  if (public_key)
    silc_pkcs_public_key_free(public_key);
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** SERVICE *********************************/

/* Reply to SERVICE command. */
/* XXX incomplete */

SILC_FSM_STATE(silc_client_command_reply_service)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcCommandPayload payload = state_context;
  SilcArgumentPayload args = silc_command_get_args(payload);
  SilcUInt32 tmp_len;
  unsigned char *service_list, *name;

  /* Sanity checks */
  CHECK_STATUS("Cannot get service: ");

  /* Get service list */
  service_list = silc_argument_get_arg_type(args, 2, &tmp_len);

  /* Get requested service name */
  name = silc_argument_get_arg_type(args, 3, &tmp_len);

  /* Notify application */
  silc_client_command_callback(cmd, service_list, name);

  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}

/*********************************** QUIT ***********************************/

/* QUIT command reply stub */

SILC_FSM_STATE(silc_client_command_reply_quit)
{
  silc_fsm_next(fsm, silc_client_command_reply_processed);
  return SILC_FSM_CONTINUE;
}
