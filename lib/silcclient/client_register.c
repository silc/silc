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
					     (client->nickname ?
					      client->nickname :
					      client->username),
					     client->username,
					     client->realname,
					     &id.u.client_id, 0);
  if (!conn->local_entry)
    goto out;

  /* Save the ID */
  conn->local_id = &conn->local_entry->id;
  conn->local_idp = silc_buffer_copy(&packet->buffer);

  /* Save cache entry */
  silc_idcache_find_by_id_one(conn->internal->client_cache, conn->local_id,
			      &conn->internal->local_entry);

  /* Save remote ID */
  if (packet->src_id_len) {
    conn->remote_idp = silc_id_payload_encode_data(packet->src_id,
						   packet->src_id_len,
						   packet->src_id_type);
    if (!conn->remote_idp)
      goto out;
    silc_id_payload_parse_id(silc_buffer_data(conn->remote_idp),
			     silc_buffer_len(conn->remote_idp),
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
    /* Timeout, ID not received */
    conn->internal->registering = FALSE;
    silc_fsm_next(fsm, silc_client_st_register_error);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Registered to network"));

  /* Issue IDENTIFY command for itself to get resolved hostname
     correctly from server. */
  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY, NULL, NULL,
			   1, 5, silc_buffer_data(conn->local_idp),
			   silc_buffer_len(conn->local_idp));

  /* Send NICK command if the nickname was set by the application (and is
     not same as the username).  Send this with little timeout. */
  if (client->nickname &&
      !silc_utf8_strcasecmp(client->nickname, client->username))
    silc_client_command_send(client, conn, SILC_COMMAND_NICK, NULL, NULL,
			     1, 1, client->nickname, strlen(client->nickname));

  /* Issue INFO command to fetch the real server name and server
     information and other stuff. */
  silc_client_command_send(client, conn, SILC_COMMAND_INFO, NULL, NULL,
			   1, 2, silc_buffer_data(conn->remote_idp),
			   silc_buffer_len(conn->remote_idp));

  /* Call connection callback.  We are now inside SILC network. */
  conn->callback(client, conn, SILC_CLIENT_CONN_SUCCESS, 0, NULL,
		 conn->context);

  conn->internal->registering = FALSE;
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_client_st_register_error)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  /* XXX */
  /* Close connection */

  conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL, conn->context);

  return SILC_FSM_FINISH;
}


/************************* Resume detached session **************************/

/* Resume detached session */

SILC_FSM_STATE(silc_client_st_resume)
{

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_client_st_resume_new_id)
{
  SilcClientConnection conn = fsm_context;

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_client_st_resume_error)
{
  /* XXX */
  /* Close connection */

  return SILC_FSM_FINISH;
}
