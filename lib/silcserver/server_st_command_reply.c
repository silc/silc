/*

  server_st_command_reply.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

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


/************************ Static utility functions **************************/

/* Free's command reply context */

static void silc_server_command_reply_free(SilcServerCommand cmd)
{
  /* If pending commmands existed, they will eventually free this context */
  if (!cmd->pending)
    silc_server_command_free(cmd);
}


/************************* Command reply received ***************************/

/* Received a COMMAND_REPLY packet.  We parse the packet and process the
   command reply. */

SILC_FSM_STATE(silc_server_st_packet_command_reply)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;
  SilcEntryData data = silc_packet_get_context(packet->stream);
  SilcServerCommand cmd;
  SilcCommandPayload payload;
  SilcCommand command;

  SILC_LOG_DEBUG(("Process command reply"));

  /* Allocate command context. */
  cmd = silc_server_command_alloc(thread);
  if (!cmd) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  cmd->packet = packet;

  /* Get command reply payload from packet */
  cmd->payload = silc_command_payload_parse(packet->buffer.data,
					    silc_buffer_len(&packet->buffer));
  if (!cmd->payload) {
    SILC_LOG_DEBUG(("Bad command reply payload"));
    silc_server_command_reply_free(cmd);
    return SILC_FSM_FINISH;
  }

  /* Client is allowed to send reply only to WHOIS command. */
  if (data->type == SILC_CONN_CLIENT &&
      silc_command_get(cmd->payload) != SILC_COMMAND_WHOIS) {
    silc_server_command_reply_free(cmd);
    return SILC_FSM_FINISH;
  }

  /* Get all command pending for this reply */
  cmd->pending =
    silc_server_command_pending_get(thread,
				    silc_command_get_ident(cmd->payload));

  silc_fsm_set_state_context(fsm, cmd);

  /* Process command reply */
  switch (silc_command_get(cmd->payload)) {

  case SILC_COMMAND_WHOIS:
    /** Command reply WHOIS */
    silc_fsm_next(fsm, silc_server_st_command_reply_whois);
    break;

  case SILC_COMMAND_WHOWAS:
    /** Command reply WHOWAS */
    silc_fsm_next(fsm, silc_server_st_command_reply_whowas);
    break;

  case SILC_COMMAND_IDENTIFY:
    /** Command reply IDENTIFY */
    silc_fsm_next(fsm, silc_server_st_command_reply_identify);
    break;

  case SILC_COMMAND_LIST:
    /** Command reply LIST */
    silc_fsm_next(fsm, silc_server_st_command_reply_list);
    break;

  case SILC_COMMAND_INFO:
    /** Command reply INFO */
    silc_fsm_next(fsm, silc_server_st_command_reply_info);
    break;

  case SILC_COMMAND_STATS:
    /** Command reply STATS */
    silc_fsm_next(fsm, silc_server_st_command_reply_stats);
    break;

  case SILC_COMMAND_PING:
    /** Command reply PING */
    silc_fsm_next(fsm, silc_server_st_command_reply_ping);
    break;

  case SILC_COMMAND_JOIN:
    /** Command reply JOIN */
    silc_fsm_next(fsm, silc_server_st_command_reply_join);
    break;

  case SILC_COMMAND_MOTD:
    /** Command reply MOTD */
    silc_fsm_next(fsm, silc_server_st_command_reply_motd);
    break;

  case SILC_COMMAND_WATCH:
    /** Command reply WATCH */
    silc_fsm_next(fsm, silc_server_st_command_reply_watch);
    break;

  case SILC_COMMAND_USERS:
    /** Command reply USERS */
    silc_fsm_next(fsm, silc_server_st_command_reply_users);
    break;

  case SILC_COMMAND_GETKEY:
    /** Command reply SERVICE */
    silc_fsm_next(fsm, silc_server_st_command_reply_getkey);
    break;

  case SILC_COMMAND_SERVICE:
    /** Command reply SERVICE */
    silc_fsm_next(fsm, silc_server_st_command_reply_service);
    break;

  default:
    SILC_LOG_DEBUG(("Unknown command %d", silc_command_get(cmd->payload)));
    cmd->pending = NULL;
    silc_server_command_reply_free(cmd);
    return SILC_FSM_FINISH;
    break;
  }

  /* Statistics */

  return SILC_FSM_CONTINUE;
}


/********************************* WHOIS ************************************/

SILC_FSM_STATE(silc_server_st_command_reply_whois)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************* WHOWAS ***********************************/

SILC_FSM_STATE(silc_server_st_command_reply_whowas)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/******************************** IDENTIFY **********************************/

SILC_FSM_STATE(silc_server_st_command_reply_identify)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** LIST ************************************/

SILC_FSM_STATE(silc_server_st_command_reply_list)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** INFO ************************************/

SILC_FSM_STATE(silc_server_st_command_reply_info)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** STATS ***********************************/

SILC_FSM_STATE(silc_server_st_command_reply_stats)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);
  SilcStatus status, error;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBufferStruct buf;

  COMMAND_CHECK_STATUS;

  /* Get statistics structure */
  tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
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
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** PING ************************************/

SILC_FSM_STATE(silc_server_st_command_reply_ping)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** JOIN ************************************/

SILC_FSM_STATE(silc_server_st_command_reply_join)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** MOTD ************************************/

SILC_FSM_STATE(silc_server_st_command_reply_motd)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** WATCH ***********************************/

SILC_FSM_STATE(silc_server_st_command_reply_watch)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** USERS ***********************************/

SILC_FSM_STATE(silc_server_st_command_reply_users)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/********************************** GETKEY **********************************/

SILC_FSM_STATE(silc_server_st_command_reply_getkey)
{
  SilcServerThread thread = fsm_context;
  SilcServer server = thread->server;
  SilcServerCommand cmd = state_context;
  SilcArgumentPayload args = silc_command_get_args(cmd->payload);
  SilcStatus status, error;
  unsigned char *tmp;
  SilcUInt32 len;
  SilcClientEntry client = NULL;
  SilcServerEntry server_entry = NULL;
  SilcIDPayload idp = NULL;
  SilcClientID client_id;
  SilcServerID server_id;
  SilcIdType id_type;
  SilcPublicKey public_key = NULL;

  COMMAND_CHECK_STATUS;

  /* Get ID */
  tmp = silc_argument_get_arg_type(args, 2, &len);
  if (!tmp)
    goto out;
  idp = silc_id_payload_parse(tmp, len);
  if (!idp)
    goto out;

  /* Get the public key payload */
  tmp = silc_argument_get_arg_type(args, 3, &len);
  if (!tmp)
    goto out;
  if (!silc_public_key_payload_decode(tmp, len, &public_key))
    goto out;

  /* Store the public key */
  id_type = silc_id_payload_get_type(idp);
  if (id_type == SILC_ID_CLIENT) {
    if (!silc_id_payload_get_id(idp, &client_id, sizeof(client_id)))
      goto out;

    client = silc_server_find_client_by_id(server, &client_id, TRUE, NULL);
    if (!client)
      goto out;

    if (!client->data.public_key) {
      silc_skr_add_public_key_simple(server->repository, public_key,
				     SILC_SKR_USAGE_IDENTIFICATION, client);
      client->data.public_key = public_key;
      public_key = NULL;
    }

  } else if (id_type == SILC_ID_SERVER) {
    if (!silc_id_payload_get_id(idp, &server_id, sizeof(server_id)))
      goto out;

    server_entry = silc_server_find_server_by_id(server, &server_id,
						 TRUE, NULL);
    if (!server_entry)
      goto out;

    server_entry->data.public_key = public_key;
    public_key = NULL;
  }

 out:
  silc_server_command_pending_signal(cmd);
  if (idp)
    silc_id_payload_free(idp);
  if (public_key)
    silc_pkcs_public_key_free(public_key);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}


/******************************** SERVICE ***********************************/

SILC_FSM_STATE(silc_server_st_command_reply_service)
{
  SilcServerThread thread = fsm_context;
  SilcServerCommand cmd = state_context;
  SilcStatus status, error;

  COMMAND_CHECK_STATUS;

 out:
  silc_server_command_pending_signal(cmd);
 err:
  silc_server_command_reply_free(cmd);

  return SILC_FSM_FINISH;
}
