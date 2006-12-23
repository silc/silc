/*

  server_st_command.c

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

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

/************************** Types and definitions ***************************/

#define SILC_SERVER_COMMAND_CHECK(min, max)				\
do {									\
  SilcUInt32 _argc;							\
									\
  SILC_LOG_DEBUG(("Start"));						\
									\
  _argc = silc_argument_get_arg_num(args);				\
  if (_argc < min) {							\
    SILC_LOG_DEBUG(("Not enough parameters in command"));		\
    silc_server_command_status_reply(cmd,				\
				     silc_command_get(cmd->payload),	\
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS,	\
				     0);				\
    silc_server_command_free(cmd);					\
    SILC_FSM_FINISH;						\
  }									\
  if (_argc > max) {							\
    SILC_LOG_DEBUG(("Too many parameters in command"));			\
    silc_server_command_status_reply(cmd,				\
				     silc_command_get(cmd->payload),	\
				     SILC_STATUS_ERR_TOO_MANY_PARAMS,	\
				     0);				\
    silc_server_command_free(cmd);					\
    SILC_FSM_FINISH;						\
  }									\
} while(0)


/************************ Static utility functions **************************/

/* Sends simple status message as command reply packet */

static void
silc_server_command_status_reply(SilcServerCommand cmd,
				      SilcCommand command,
				      SilcStatus status,
				      SilcStatus error)
{
  SilcBuffer buffer;

  /* Statistics */
  cmd->thread->server->stat.commands_sent++;

  SILC_LOG_DEBUG(("Sending command status %d", status));
  buffer =
    silc_command_reply_payload_encode_va(command, status, error,
					 silc_command_get_ident(cmd->payload),
					 0);
  silc_packet_send(cmd->packet->stream, SILC_PACKET_COMMAND_REPLY, 0,
		   buffer->data, silc_buffer_len(buffer));
  silc_buffer_free(buffer);
}

/* Sends command status reply with one extra argument. The argument
   type must be sent as argument. */

static void
silc_server_command_status_data(SilcServerCommand cmd,
				     SilcCommand command,
				     SilcStatus status,
				     SilcStatus error,
				     SilcUInt32 arg_type,
				     const unsigned char *arg,
				     SilcUInt32 arg_len)
{
  SilcBuffer buffer;

  /* Statistics */
  cmd->thread->server->stat.commands_sent++;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer =
    silc_command_reply_payload_encode_va(command, status, 0,
					 silc_command_get_ident(cmd->payload),
					 1, arg_type, arg, arg_len);
  silc_packet_send(cmd->packet->stream, SILC_PACKET_COMMAND_REPLY, 0,
		   buffer->data, silc_buffer_len(buffer));
  silc_buffer_free(buffer);
}

static void
silc_server_command_status_data2(SilcServerCommand cmd,
				      SilcCommand command,
				      SilcStatus status,
				      SilcStatus error,
				      SilcUInt32 arg_type1,
				      const unsigned char *arg1,
				      SilcUInt32 arg_len1,
				      SilcUInt32 arg_type2,
				      const unsigned char *arg2,
				      SilcUInt32 arg_len2)
{
  SilcBuffer buffer;

  /* Statistics */
  cmd->thread->server->stat.commands_sent++;

  SILC_LOG_DEBUG(("Sending command status %d", status));

  buffer =
    silc_command_reply_payload_encode_va(command, status, 0,
					 silc_command_get_ident(cmd->payload),
					 2, arg_type1, arg1, arg_len1,
					 arg_type2, arg2, arg_len2);
  silc_packet_send(cmd->packet->stream, SILC_PACKET_COMMAND_REPLY, 0,
		   buffer->data, silc_buffer_len(buffer));
  silc_buffer_free(buffer);
}

void silc_server_command_pending_free(SilcServerThread thread,
				      SilcServerPending pending);


/**************************** Utility functions *****************************/

/* Gets command context from freelist or allocates a new one. */

SilcServerCommand silc_server_command_alloc(SilcServerThread thread)
{
  SilcServerCommand cmd;

  silc_mutex_lock(thread->server->lock);

  /* Get command context from freelist or allocate new one. */
  cmd = silc_list_get(thread->server->command_pool);
  if (!cmd) {
    silc_mutex_unlock(thread->server->lock);

    cmd = silc_calloc(1, sizeof(*cmd));
    if (!cmd)
      return NULL;

    SILC_LOG_DEBUG(("Allocating command context %p", cmd));

    cmd->thread = thread;

    return cmd;
  }

  SILC_LOG_DEBUG(("Get command context %p", cmd));

  /* Delete from freelist */
  silc_list_del(thread->server->command_pool, cmd);

  cmd->thread = thread;

  silc_mutex_unlock(thread->server->lock);

  return cmd;
}

/* Puts the command context back to freelist */

void silc_server_command_free(SilcServerCommand cmd)
{
  SilcServerThread thread = cmd->thread;

  silc_mutex_lock(thread->server->lock);

#if defined(SILC_DEBUG)
  /* Check for double free */
  assert(cmd->packet != NULL);
#endif /* SILC_DEBUG */

  if (cmd->packet)
    silc_packet_free(cmd->packet);
  cmd->packet = NULL;

  if (cmd->pending)
    silc_server_command_pending_free(thread, cmd->pending);

  /* Put the packet back to freelist */
  silc_list_add(thread->server->command_pool, cmd);

  silc_mutex_unlock(thread->server->lock);
}

/* Returns pending context used to wait for a command reply. */

SilcServerPending silc_server_command_pending(SilcServerThread thread,
					      SilcUInt16 cmd_ident)
{
  SilcServerPending pending;

  silc_mutex_lock(thread->server->lock);

  /* Check if pending already */
  if (silc_hash_table_find(thread->server->pending_commands,
			   SILC_32_TO_PTR(cmd_ident), NULL,
			   (void **)&pending)) {
    pending->refcnt++;
    silc_mutex_unlock(thread->server->lock);
    return pending;
  }

  pending = silc_calloc(1, sizeof(*pending));
  if (!pending) {
    silc_mutex_unlock(thread->server->lock);
    return NULL;
  }

  silc_fsm_event_init(&pending->wait_reply, &thread->fsm, 0);
  pending->refcnt = 1;
  pending->cmd_ident = cmd_ident;

  /* Add to pending commands hash table */
  if (!silc_hash_table_add(thread->server->pending_commands,
			   SILC_32_TO_PTR(cmd_ident), pending)) {
    silc_mutex_unlock(thread->server->lock);
    silc_free(pending);
    return NULL;
  }

  silc_mutex_unlock(thread->server->lock);

  return pending;
}

/* Free's the pending command context */

void silc_server_command_pending_free(SilcServerThread thread,
				      SilcServerPending pending)
{
  silc_mutex_lock(thread->server->lock);

  pending->refcnt--;
  if (pending->refcnt > 0) {
    silc_mutex_unlock(thread->server->lock);
    return;
  }

  /* If command reply context set, free it also */
  if (pending->reply) {
    pending->reply->pending = NULL;
    silc_server_command_free(pending->reply);
  }

  /* Remove from pending commands */
  silc_hash_table_del_by_context(thread->server->pending_commands,
				 SILC_32_TO_PTR(pending->cmd_ident), pending);
  silc_free(pending);

  silc_mutex_unlock(thread->server->lock);
}

/* Returns pending command context for command identifier */

SilcServerPending silc_server_command_pending_get(SilcServerThread thread,
						  SilcUInt16 cmd_ident)
{
  SilcServerPending pending = NULL;

  silc_mutex_lock(thread->server->lock);
  silc_hash_table_find(thread->server->pending_commands,
		       SILC_32_TO_PTR(cmd_ident), NULL, (void **)&pending);
  silc_mutex_unlock(thread->server->lock);

  return pending;
}

/* Signals pending command waiters.  Used by command reply routines. */

void silc_server_command_pending_signal(SilcServerCommand cmd)
{
  SilcServerThread thread = cmd->thread;
  SilcServerPending pending = cmd->pending;

  if (!pending)
    return;

  silc_mutex_lock(thread->server->lock);

  /* Signal */
  pending->reply = cmd;
  SILC_FSM_EVENT_SIGNAL(&pending->wait_reply);

  /* Remove from pending */
  silc_hash_table_del_by_context(thread->server->pending_commands,
				 SILC_32_TO_PTR(pending->cmd_ident), pending);

  silc_mutex_unlock(thread->server->lock);
}


/**************************** Command received ******************************/

/* Received a COMMAND packet.  We parse the packet and process the
   requested command. */

SILC_FSM_STATE(silc_server_st_packet_command)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;
  SilcEntryData data = silc_packet_get_context(packet->stream);
  SilcServerCommand cmd;
  SilcUInt32 timeout = 0;

  /* Allocate command context. */
  cmd = silc_server_command_alloc(thread);
  if (!cmd) {
    silc_packet_free(packet);
    SILC_FSM_FINISH;
  }

  cmd->packet = packet;

  /* Parse the command payload in the packet */
  cmd->payload = silc_command_payload_parse(packet->buffer.data,
					    silc_buffer_len(&packet->buffer));
  if (!cmd->payload) {
    SILC_LOG_ERROR(("Bad command payload"));
    silc_server_command_free(cmd);
    SILC_FSM_FINISH;
  }

  /* If client executes commands more frequently than once in 2 seconds,
     apply 0 - 2 seconds of timeout to prevent flooding. */
  if (data->type == SILC_CONN_CLIENT) {
    SilcClientEntry client = (SilcClientEntry)data;

    if (client->last_command && (time(NULL) - client->last_command) < 2) {
      client->fast_command++;
      if (client->fast_command > 5)
	timeout = (client->fast_command < 3 ? 0 :
		   2 - (time(NULL) - client->last_command));
    } else {
      if (client->fast_command - 2 <= 0)
	client->fast_command = 0;
      else
	client->fast_command -= 2;
    }

    client->last_command = time(NULL) + timeout;
  }

  silc_fsm_set_state_context(fsm, cmd);

  SILC_LOG_DEBUG(("Processing %s command (%d timeout)",
		  silc_get_command_name(silc_command_get(cmd->payload)),
		  timeout));

  /* Process command */
  switch (silc_command_get(cmd->payload)) {

  case SILC_COMMAND_WHOIS:
    /** Command WHOIS */
    silc_fsm_next_later(fsm, silc_server_st_command_whois, timeout, 0);
    break;

  case SILC_COMMAND_WHOWAS:
    /** Command WHOWAS */
    silc_fsm_next_later(fsm, silc_server_st_command_whowas, timeout, 0);
    break;

  case SILC_COMMAND_IDENTIFY:
    /** Command IDENTIFY */
    silc_fsm_next_later(fsm, silc_server_st_command_identify, timeout, 0);
    break;

  case SILC_COMMAND_NICK:
    /** Command NICK */
    silc_fsm_next_later(fsm, silc_server_st_command_nick, timeout, 0);
    break;

  case SILC_COMMAND_LIST:
    /** Command LIST */
    silc_fsm_next_later(fsm, silc_server_st_command_list, timeout, 0);
    break;

  case SILC_COMMAND_TOPIC:
    /** Command TOPIC */
    silc_fsm_next_later(fsm, silc_server_st_command_topic, timeout, 0);
    break;

  case SILC_COMMAND_INVITE:
    /** Command INVITE */
    silc_fsm_next_later(fsm, silc_server_st_command_invite, timeout, 0);
    break;

  case SILC_COMMAND_QUIT:
    /** Command QUIT */
    silc_fsm_next_later(fsm, silc_server_st_command_quit, timeout, 0);
    break;

  case SILC_COMMAND_KILL:
    /** Command KILL */
    silc_fsm_next_later(fsm, silc_server_st_command_kill, timeout, 0);
    break;

  case SILC_COMMAND_INFO:
    /** Command INFO */
    silc_fsm_next_later(fsm, silc_server_st_command_info, timeout, 0);
    break;

  case SILC_COMMAND_STATS:
    /** Command STATS */
    silc_fsm_next_later(fsm, silc_server_st_command_stats, timeout, 0);
    break;

  case SILC_COMMAND_PING:
    /** Command INFO */
    silc_fsm_next_later(fsm, silc_server_st_command_ping, timeout, 0);
    break;

  case SILC_COMMAND_OPER:
    /** Command OPER */
    silc_fsm_next_later(fsm, silc_server_st_command_oper, timeout, 0);
    break;

  case SILC_COMMAND_JOIN:
    /** Command JOIN */
    silc_fsm_next_later(fsm, silc_server_st_command_join, timeout, 0);
    break;

  case SILC_COMMAND_MOTD:
    /** Command MOTD */
    silc_fsm_next_later(fsm, silc_server_st_command_motd, timeout, 0);
    break;

  case SILC_COMMAND_UMODE:
    /** Command UMODE */
    silc_fsm_next_later(fsm, silc_server_st_command_umode, timeout, 0);
    break;

  case SILC_COMMAND_CMODE:
    /** Command CMODE */
    silc_fsm_next_later(fsm, silc_server_st_command_cmode, timeout, 0);
    break;

  case SILC_COMMAND_CUMODE:
    /** Command CUMODE */
    silc_fsm_next_later(fsm, silc_server_st_command_cumode, timeout, 0);
    break;

  case SILC_COMMAND_KICK:
    /** Command KICK */
    silc_fsm_next_later(fsm, silc_server_st_command_kick, timeout, 0);
    break;

  case SILC_COMMAND_BAN:
    /** Command BAN */
    silc_fsm_next_later(fsm, silc_server_st_command_ban, timeout, 0);
    break;

  case SILC_COMMAND_DETACH:
    /** Command DETACH */
    silc_fsm_next_later(fsm, silc_server_st_command_detach, timeout, 0);
    break;

  case SILC_COMMAND_WATCH:
    /** Command WATCH */
    silc_fsm_next_later(fsm, silc_server_st_command_watch, timeout, 0);
    break;

  case SILC_COMMAND_SILCOPER:
    /** Command SILCOPER */
    silc_fsm_next_later(fsm, silc_server_st_command_silcoper, timeout, 0);
    break;

  case SILC_COMMAND_LEAVE:
    /** Command LEAVE */
    silc_fsm_next_later(fsm, silc_server_st_command_leave, timeout, 0);
    break;

  case SILC_COMMAND_USERS:
    /** Command USERS */
    silc_fsm_next_later(fsm, silc_server_st_command_users, timeout, 0);
    break;

  case SILC_COMMAND_GETKEY:
    /** Command GETKEY */
    silc_fsm_next_later(fsm, silc_server_st_command_getkey, timeout, 0);
    break;

  case SILC_COMMAND_SERVICE:
    /** Command SERVICE */
    silc_fsm_next_later(fsm, silc_server_st_command_service, timeout, 0);
    break;

  default:
    SILC_LOG_DEBUG(("Unknown command %d", silc_command_get(cmd->payload)));
    silc_server_command_free(cmd);
    SILC_FSM_FINISH;
    break;
  }

  /* Statistics */
  thread->server->stat.commands_received++;

  return timeout ? SILC_FSM_WAIT : SILC_FSM_CONTINUE;
}

/********************************* WHOIS ************************************/

SILC_FSM_STATE(silc_server_st_command_whois)
{
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(1, 256);

  /** WHOIS query */
  silc_fsm_next(fsm, silc_server_st_query_whois);

  SILC_FSM_CONTINUE;
}


/********************************* WHOWAS ***********************************/

SILC_FSM_STATE(silc_server_st_command_whowas)
{
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(1, 2);

  /** WHOWAS query */
  silc_fsm_next(fsm, silc_server_st_query_whowas);

  SILC_FSM_CONTINUE;
}


/******************************** IDENTIFY **********************************/

SILC_FSM_STATE(silc_server_st_command_identify)
{
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(1, 256);

  /** IDENTIFY query */
  silc_fsm_next(fsm, silc_server_st_query_identify);

  SILC_FSM_CONTINUE;
}


/********************************** NICK ************************************/

SILC_FSM_STATE(silc_server_st_command_nick)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);
  SilcClientEntry client = silc_packet_get_context(cmd->packet->stream);
  SilcBuffer nidp, oidp = NULL;
  SilcClientID new_id;
  SilcUInt32 nick_len;
  unsigned char *nick, *nickc;
  SilcUInt16 ident = silc_command_get_ident(cmd->payload);

  SILC_SERVER_COMMAND_CHECK(1, 1);

  /* This command can come only from client */
  if (!SILC_IS_CLIENT(client)) {
    silc_server_command_status_reply(cmd, SILC_COMMAND_NICK,
				     SILC_STATUS_ERR_OPERATION_ALLOWED, 0);
    goto out;
  }

  /* Get nickname */
  nick = silc_argument_get_arg_type(args, 1, &nick_len);
  if (!nick) {
    silc_server_command_status_reply(cmd, SILC_COMMAND_NICK,
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
    goto out;
  }

  /* Truncate over long nicks */
  if (nick_len > 128) {
    nick_len = 128;
    nick[nick_len - 1] = '\0';
  }

  /* Check for same nickname */
  if (strlen(client->nickname) == nick_len &&
      !memcmp(client->nickname, nick, nick_len)) {
    nidp = silc_id_payload_encode(&client->id, SILC_ID_CLIENT);
    goto send_reply;
  }

  /* Check for valid nickname string. */
  nickc = silc_identifier_check(nick, nick_len, SILC_STRING_UTF8, 128, NULL);
  if (!nickc) {
    silc_server_command_status_reply(cmd, SILC_COMMAND_NICK,
				     SILC_STATUS_ERR_BAD_NICKNAME, 0);
    goto out;
  }

  /* Create new Client ID */
  if (!silc_server_create_client_id(thread->server, nickc, &new_id)) {
    silc_server_command_status_reply(cmd, SILC_COMMAND_NICK,
				     SILC_STATUS_ERR_OPERATION_ALLOWED, 0);
    goto out;
  }
  silc_free(nickc);

  oidp = silc_id_payload_encode(&client->id, SILC_ID_CLIENT);

  /* Replace the old nickname and ID with new ones.  This checks for
     validity of the nickname too. */
  if (!silc_server_replace_client_id(thread->server, &client->id, &new_id,
				     nick)) {
    silc_server_command_status_reply(cmd, SILC_COMMAND_NICK,
				     SILC_STATUS_ERR_BAD_NICKNAME, 0);
    goto out;
  }

  nidp = silc_id_payload_encode(&client->id, SILC_ID_CLIENT);

#if 0
  /* Send notify about nickname and ID change to network. */
  silc_server_send_notify_nick_change(server, SILC_PRIMARY_ROUTE(server),
				      SILC_BROADCAST(server), client->id,
				      &new_id, nick);

  /* Send NICK_CHANGE notify to the client's channels */
  silc_server_send_notify_on_channels(server, NULL, client,
				      SILC_NOTIFY_TYPE_NICK_CHANGE, 3,
				      oidp->data, silc_buffer_len(oidp),
				      nidp->data, silc_buffer_len(nidp),
				      client->nickname,
				      strlen(client->nickname));
#endif

 send_reply:
  /* Send the new Client ID as reply command back to client */
  silc_server_send_command_reply(thread->server, cmd->packet->stream,
				 SILC_COMMAND_NICK,
				 SILC_STATUS_OK, 0, ident, 2,
				 2, nidp->data, silc_buffer_len(nidp),
				 3, nick, nick_len);
  silc_buffer_free(nidp);
  silc_buffer_free(oidp);

 out:
  silc_server_command_free(cmd);
  SILC_FSM_FINISH;
}


/********************************** LIST ************************************/

SILC_FSM_STATE(silc_server_st_command_list)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** TOPIC ***********************************/

SILC_FSM_STATE(silc_server_st_command_topic)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************* INVITE ***********************************/

SILC_FSM_STATE(silc_server_st_command_invite)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** QUIT ************************************/

SILC_FSM_STATE(silc_server_st_command_quit)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** KILL ************************************/

SILC_FSM_STATE(silc_server_st_command_kill)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** INFO ************************************/

SILC_FSM_STATE(silc_server_st_command_info)
{
  SILC_FSM_FINISH;
}


/********************************** STATS ***********************************/

SILC_FSM_STATE(silc_server_st_command_stats)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** PING ************************************/

SILC_FSM_STATE(silc_server_st_command_ping)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);
  SilcUInt32 tmp_len;
  unsigned char *tmp;
  SilcID id;

  SILC_SERVER_COMMAND_CHECK(1, 1);

  /* Get Server ID */
  tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
  if (!tmp) {
    silc_server_command_status_reply(cmd, silc_command_get(cmd->payload),
				     SILC_STATUS_ERR_NOT_ENOUGH_PARAMS, 0);
    goto out;
  }
  if (!silc_id_payload_parse_id(tmp, tmp_len, &id)) {
    silc_server_command_status_data(cmd, silc_command_get(cmd->payload),
				    SILC_STATUS_ERR_BAD_SERVER_ID, 0,
				    2, tmp, tmp_len);
    goto out;
  }

  /* Must be our ID */
  if (!SILC_ID_SERVER_COMPARE(&id.u.server_id, &thread->server->id)) {
    silc_server_command_status_data(cmd, silc_command_get(cmd->payload),
				    SILC_STATUS_ERR_NO_SUCH_SERVER_ID, 0,
				    2, tmp, tmp_len);
    goto out;
  }

  /* Send our reply */
  silc_server_command_status_reply(cmd, silc_command_get(cmd->payload),
				   SILC_STATUS_OK, 0);

 out:
  silc_server_command_free(cmd);
  SILC_FSM_FINISH;
}


/*********************************** OPER ***********************************/

SILC_FSM_STATE(silc_server_st_command_oper)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/*********************************** JOIN ***********************************/

SILC_FSM_STATE(silc_server_st_command_join)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/*********************************** MOTD ***********************************/

SILC_FSM_STATE(silc_server_st_command_motd)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/*********************************** UMODE **********************************/

SILC_FSM_STATE(silc_server_st_command_umode)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/*********************************** CMODE **********************************/

SILC_FSM_STATE(silc_server_st_command_cmode)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** CUMODE **********************************/

SILC_FSM_STATE(silc_server_st_command_cumode)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/*********************************** KICK ***********************************/

SILC_FSM_STATE(silc_server_st_command_kick)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/*********************************** BAN ************************************/

SILC_FSM_STATE(silc_server_st_command_ban)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** DETACH **********************************/

SILC_FSM_STATE(silc_server_st_command_detach)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** WATCH ***********************************/

SILC_FSM_STATE(silc_server_st_command_watch)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************* SILCOPER *********************************/

SILC_FSM_STATE(silc_server_st_command_silcoper)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** LEAVE ***********************************/

SILC_FSM_STATE(silc_server_st_command_leave)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** USERS ***********************************/

SILC_FSM_STATE(silc_server_st_command_users)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** GETKEY **********************************/

SILC_FSM_STATE(silc_server_st_command_getkey)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}


/********************************** SERVICE *********************************/

SILC_FSM_STATE(silc_server_st_command_service)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);

  SILC_FSM_FINISH;
}
