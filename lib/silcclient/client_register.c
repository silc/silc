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


/************************ Register to SILC network **************************/

/* Register to network */

SILC_FSM_STATE(silc_client_st_register)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcBufferStruct buf;
  int ret;

  SILC_LOG_DEBUG(("Register to network"));

  memset(&buf, 0, sizeof(buf));
  ret = silc_buffer_format(&buf,
			   SILC_STR_UI_SHORT(strlen(client->username)),
			   SILC_STR_DATA(client->username,
					 strlen(client->username)),
			   SILC_STR_UI_SHORT(strlen(client->realname)),
			   SILC_STR_DATA(client->realname,
					 strlen(client->realname)),
			   SILC_STR_END);
  if (ret < 0) {
    /** Out of memory */
    silc_fsm_next(fsm, silc_client_st_register_error);
    return SILC_FSM_CONTINUE;
  }

  /* Send the packet */
  if (!silc_packet_send(conn->stream, SILC_PACKET_NEW_CLIENT, 0,
			silc_buffer_data(&buf), silc_buffer_len(&buf))) {
    /** Error sending packet */
    silc_buffer_purge(&buf);
    silc_fsm_next(fsm, silc_client_st_register_error);
    return SILC_FSM_CONTINUE;
  }

  silc_buffer_purge(&buf);

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
  conn->callback(client, conn, SILC_CLIENT_CONN_SUCCESS, conn->context);

  conn->internal->registering = FALSE;
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_client_st_register_error)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  /* XXX */
  /* Close connection */

  conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, conn->context);

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
