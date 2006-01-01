/*

  server_st_packet.c

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


/************************ Static utility functions **************************/


/***************************** Packet received ******************************/

SILC_FSM_STATE(silc_server_st_packet_disconnect)
{
  SilcPacket packet = fsm_context;
  SilcEntryData data = silc_packet_get_context(packet->stream);

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_channel_message)
{
#if 0
    /*
     * Received channel message. Channel messages are special packets
     * (although probably most common ones) thus they are handled
     * specially.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    idata->last_receive = time(NULL);
    silc_server_channel_message(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_channel_key)
{
#if 0
    /*
     * Received key for channel. As channels are created by the router
     * the keys are as well. We will distribute the key to all of our
     * locally connected clients on the particular channel. Router
     * never receives this channel and thus is ignored.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_channel_key(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_private_message)
{
#if 0
    /*
     * Received private message packet. The packet is coming from either
     * client or server.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    idata->last_receive = time(NULL);
    silc_server_private_message(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_private_message_key)
{
#if 0
    /*
     * Private message key packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_private_message_key(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_new_id)
{
#if 0
    /*
     * Received New ID packet. This includes some new ID that has been
     * created. It may be for client, server or channel. This is the way
     * to distribute information about new registered entities in the
     * SILC network.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_id_list(server, sock, packet);
    else
      silc_server_new_id(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_new_channel)
{
#if 0
    /*
     * Received new channel packet. Information about new channel in the
     * network are distributed using this packet.
     */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      silc_server_new_channel_list(server, sock, packet);
    else
      silc_server_new_channel(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_key_agreement)
{
#if 0
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_key_agreement(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_ftp)
{
#if 0
    /* FTP packet */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_ftp(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_resume_router)
{
#if 0
    /* Resume router packet received. This packet is received for backup
       router resuming protocol. */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_server_backup_resume_router(server, sock, packet);
#endif

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_server_st_packet_received)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;

  SILC_LOG_DEBUG(("Received %s packet [flags %d]",
		  silc_get_packet_name(packet->type), packet->flags));

  /* Parse the packet type */
  switch (packet->type) {
  case SILC_PACKET_CHANNEL_MESSAGE:
    /** Packet CHANNEL_MESSAGE */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_channel_message);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_PRIVATE_MESSAGE:
    /** Packet PRIVATE_MESSAGE */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_private_message);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_NOTIFY:
    /** Packet NOTIFY */
    silc_fsm_next(fsm, silc_server_st_packet_notify);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_COMMAND:
    /** Packet COMMAND */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_command);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /** Packet COMMAND_REPLY */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_command_reply);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_CHANNEL_KEY:
    /** Packet CHANNEL_KEY */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_channel_key);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_NEW_ID:
    /** Packet NEW_ID */
    silc_fsm_next(fsm, silc_server_st_packet_new_id);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_NEW_CLIENT:
    /** Packet NEW_CLIENT */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_new_client);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_NEW_SERVER:
    /** Packet NEW_SERVER */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_new_server);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_NEW_CHANNEL:
    /** Packet NEW_CHANNEL */
    silc_fsm_next(fsm, silc_server_st_packet_new_channel);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_KEY_AGREEMENT:
    /** Packet KEY_AGREEMENT */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_key_agreement);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_FTP:
    /** Packet FTP */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_ftp);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_RESUME_CLIENT:
    /** Packet RESUME_CLIENT */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_resume_client);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_RESUME_ROUTER:
    /** Packet RESUME_ROUTER */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_resume_router);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_DISCONNECT:
    /** Packet DISCONNECT */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_disconnect);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /** Packet PRIVATE_MESSAGE */
    if (packet->flags & SILC_PACKET_FLAG_LIST)
      break;
    silc_fsm_next(fsm, silc_server_st_packet_private_message_key);
    return SILC_FSM_CONTINUE;
    break;

  case SILC_PACKET_HEARTBEAT:
  case SILC_PACKET_SUCCESS:
  case SILC_PACKET_FAILURE:
  case SILC_PACKET_REJECT:
  case SILC_PACKET_KEY_EXCHANGE:
  case SILC_PACKET_KEY_EXCHANGE_1:
  case SILC_PACKET_KEY_EXCHANGE_2:
  case SILC_PACKET_REKEY:
  case SILC_PACKET_REKEY_DONE:
  case SILC_PACKET_CONNECTION_AUTH:
  case SILC_PACKET_CONNECTION_AUTH_REQUEST:
    /* Not handled */
    break;

  default:
    SILC_LOG_ERROR(("Unsupported packet type %d", packet->type));
    break;
  }

  silc_packet_free(packet);
  return SILC_FSM_FINISH;
}

/* Received NEW_CLIENT packet, used to register client to SILC network. */

SILC_FSM_STATE(silc_server_st_packet_new_client)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;
  SilcServerAccept ac = silc_packet_get_context(packet->stream);

  if (!ac || ac->register_packet) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  /* Signal that client registers to network */
  ac->register_packet = packet;
  SILC_FSM_SEMA_POST(&ac->wait_register);

  return SILC_FSM_FINISH;
}

/* Received NEW_SERVER packet, used to register server to SILC network. */

SILC_FSM_STATE(silc_server_st_packet_new_server)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;
  SilcServerAccept ac = silc_packet_get_context(packet->stream);

  if (!ac || ac->register_packet) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  /* Signal that server registers to network */
  ac->register_packet = packet;
  SILC_FSM_SEMA_POST(&ac->wait_register);

  return SILC_FSM_FINISH;
}

/* Received RESUME_CLIENT packet, used to resume detached session. */

SILC_FSM_STATE(silc_server_st_packet_resume_client)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;
  SilcServerAccept ac = silc_packet_get_context(packet->stream);

  if (!ac || ac->register_packet) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  /* Signal that client resumes session */
  ac->register_packet = packet;
  SILC_FSM_SEMA_POST(&ac->wait_register);

  return SILC_FSM_FINISH;
}
