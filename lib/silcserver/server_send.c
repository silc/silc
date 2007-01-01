/*

  server_send.c

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
/* $Id: */

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

/******************************* Heartbeat **********************************/

/* Send the heartbeat packet. */

SilcBool silc_server_send_heartbeat(SilcPacketStream stream)
{
  return stream ? silc_packet_send(stream, SILC_PACKET_HEARTBEAT, 0,
				   NULL, 0) : FALSE;
}


/********************************* Error ************************************/

/* Sends error packet. */

SilcBool silc_server_send_error(SilcPacketStream stream, const char *fmt, ...)
{
  unsigned char buf[2048];
  va_list ap;

  if (!stream)
    return FALSE;

  memset(buf, 0, sizeof(buf));
  va_start(ap, fmt);
  vsilc_snprintf(buf, sizeof(buf) - 1, fmt, ap);
  va_end(ap);

  return silc_packet_send(stream, SILC_PACKET_ERROR, 0, buf, strlen(buf));
}


/********************************* New ID ***********************************/

/* Sends New ID packet.  The packet is used to distribute information about
   new registered clients, servers and channels.  If the argument `broadcast'
   is TRUE then the packet is sent as broadcast packet. */

SilcBool silc_server_send_new_id(SilcPacketStream stream,
				 SilcBool broadcast,
				 void *id, SilcIdType id_type)
{
  SilcBuffer idp;
  SilcBool ret = FALSE;

  if (!stream || !id)
    return ret;

  SILC_LOG_DEBUG(("Sending new ID (%s)", silc_id_render(id, id_type)));

  idp = silc_id_payload_encode(id, id_type);
  if (!idp)
    return ret;

  ret = silc_packet_send(stream, SILC_PACKET_NEW_ID,
			 broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			 idp->data, silc_buffer_len(idp));

  silc_buffer_free(idp);
  return ret;
}


/****************************** Command packets *****************************/

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form in correct order, and they must as follows:
   { argument type, argument data, argument length }. */

SilcBool silc_server_send_command(SilcServer server,
				  SilcPacketStream stream,
				  SilcCommand command,
				  SilcUInt16 ident,
				  SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;
  SilcBool ret = FALSE;

  /* Statistics */
  server->stat.commands_sent++;

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, ident, argc, ap);
  if (!packet) {
    va_end(ap);
    return ret;
  }

  ret = silc_packet_send(stream, SILC_PACKET_COMMAND, 0,
			 packet->data, silc_buffer_len(packet));

  silc_buffer_free(packet);
  va_end(ap);

  return ret;
}

/* Generic function to send a command reply.  The arguments must be sent
   already encoded into correct form in correct order, and they must be
   { argument type, argument data, argument length }. */

SilcBool silc_server_send_command_reply(SilcServer server,
					SilcPacketStream stream,
					SilcCommand command,
					SilcStatus status,
					SilcStatus error,
					SilcUInt16 ident,
					SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;
  SilcBool ret = FALSE;

  /* Statistics */
  server->stat.commands_sent++;

  va_start(ap, argc);

  packet = silc_command_reply_payload_encode_vap(command, status, error,
						 ident, argc, ap);
  if (!packet) {
    va_end(ap);
    return ret;
  }

  ret = silc_packet_send(stream, SILC_PACKET_COMMAND_REPLY, 0,
			 packet->data, silc_buffer_len(packet));

  silc_buffer_free(packet);
  va_end(ap);

  return ret;
}


/****************************** Notify packets ******************************/

/* Sends notify packet.  Each variable argument format in the argument list
   must be { argument data, argument length }. */

SilcBool silc_server_send_notify(SilcServer server,
				 SilcPacketStream stream,
				 SilcBool broadcast,
				 SilcNotifyType type,
				 SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer packet;
  SilcBool ret = FALSE;

  if (!stream)
    return FALSE;

  va_start(ap, argc);

  packet = silc_notify_payload_encode(type, argc, ap);
  if (!packet) {
    va_end(ap);
    return ret;
  }

  ret = silc_packet_send(stream, SILC_PACKET_NOTIFY,
			 broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			 packet->data, silc_buffer_len(packet));

#if 0
  /* Send to backup routers if this is being broadcasted to primary
     router.  The silc_server_backup_send checks further whether to
     actually send it or not. */
  if ((broadcast && stream == SILC_PRIMARY_ROUTE(server)) ||
      (broadcast && !SILC_PRIMARY_ROUTE(server)))
    silc_server_backup_send(server, NULL, SILC_PACKET_NOTIFY, 0,
			    packet->data, packet->len, FALSE, TRUE);
#endif /* 0 */

  silc_buffer_free(packet);
  va_end(ap);

  return ret;
}

/* Sends current motd to client in notify packet */

SilcBool silc_server_send_motd(SilcServer server, SilcPacketStream stream)
{
  char *motd, *motd_file = NULL;
  SilcUInt32 motd_len;
  SilcBool ret = FALSE;

  if (!stream || !server->params)
    return FALSE;

  motd_file = server->params->server_info->motd_file;
  if (!motd_file)
    return FALSE;

  motd = silc_file_readfile(motd_file, &motd_len);
  if (!motd)
    return FALSE;

  motd[motd_len] = 0;
  ret = silc_server_send_notify(server, stream, FALSE,
				SILC_NOTIFY_TYPE_MOTD, 1, motd, motd_len);
  silc_free(motd);

  return ret;
}


/* Sends notify packet and gets the arguments from the `args' Argument
   Payloads. */

SilcBool silc_server_send_notify_args(SilcPacketStream stream,
				      SilcBool broadcast,
				      SilcNotifyType type,
				      SilcUInt32 argc,
				      SilcBuffer args)
{
  SilcBuffer packet;
  SilcBool ret = FALSE;

  if (!stream)
    return FALSE;

  packet = silc_notify_payload_encode_args(type, argc, args);
  if (!packet)
    return ret;

  ret = silc_packet_send(stream, SILC_PACKET_NOTIFY,
			 broadcast ? SILC_PACKET_FLAG_BROADCAST : 0,
			 packet->data, silc_buffer_len(packet));

  silc_buffer_free(packet);
  return ret;
}

/* Send CHANNEL_CHANGE notify type. This tells the receiver to replace the
   `old_id' with the `new_id'. */

SilcBool silc_server_send_notify_channel_change(SilcServer server,
						SilcPacketStream stream,
						SilcBool broadcast,
						SilcChannelID *old_id,
						SilcChannelID *new_id)
{
  SilcBuffer idp1, idp2;
  SilcBool ret = FALSE;

  if (!server || !stream)
    return ret;

  idp1 = silc_id_payload_encode((void *)old_id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode((void *)new_id, SILC_ID_CHANNEL);
  if (!idp1 || !idp2)
    return ret;

  ret = silc_server_send_notify(server, stream, broadcast,
				SILC_NOTIFY_TYPE_CHANNEL_CHANGE,
				2, idp1->data, silc_buffer_len(idp1),
				idp2->data, silc_buffer_len(idp2));
  silc_buffer_free(idp1);
  silc_buffer_free(idp2);

  return ret;
}
