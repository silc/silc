/*

  packet_send.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef PACKET_SEND_H
#define PACKET_SEND_H

/* Prototypes */

int silc_server_packet_send_real(SilcServer server,
				 SilcSocketConnection sock,
				 int force_send);
void silc_server_packet_send(SilcServer server,
			     SilcSocketConnection sock, 
			     SilcPacketType type, 
			     SilcPacketFlags flags,
			     unsigned char *data, 
			     unsigned int data_len,
			     int force_send);
void silc_server_packet_send_dest(SilcServer server,
				  SilcSocketConnection sock, 
				  SilcPacketType type, 
				  SilcPacketFlags flags,
				  void *dst_id,
				  SilcIdType dst_id_type,
				  unsigned char *data, 
				  unsigned int data_len,
				  int force_send);
void silc_server_packet_broadcast(SilcServer server,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet);
void silc_server_packet_route(SilcServer server,
			      SilcSocketConnection sock,
			      SilcPacketContext *packet);
void silc_server_packet_send_to_channel(SilcServer server,
					SilcSocketConnection sender,
					SilcChannelEntry channel,
					SilcPacketType type,
					unsigned char route,
					unsigned char *data,
					unsigned int data_len,
					int force_send);
void silc_server_packet_relay_to_channel(SilcServer server,
					 SilcSocketConnection sender_sock,
					 SilcChannelEntry channel,
					 void *sender, 
					 SilcIdType sender_type,
					 unsigned char *data,
					 unsigned int data_len,
					 int force_send);
void silc_server_packet_send_local_channel(SilcServer server,
					   SilcChannelEntry channel,
					   SilcPacketType type,
					   SilcPacketFlags flags,
					   unsigned char *data,
					   unsigned int data_len,
					   int force_send);
void silc_server_send_private_message(SilcServer server,
				      SilcSocketConnection dst_sock,
				      SilcCipher cipher,
				      SilcHmac hmac,
				      SilcPacketContext *packet);
void silc_server_send_motd(SilcServer server,
			   SilcSocketConnection sock);
void silc_server_send_error(SilcServer server,
			    SilcSocketConnection sock,
			    const char *fmt, ...);
void silc_server_send_notify(SilcServer server,
			     SilcSocketConnection sock,
			     SilcNotifyType type,
			     unsigned int argc, ...);
void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  unsigned int argc, ...);
void silc_server_send_notify_to_channel(SilcServer server,
					SilcSocketConnection sender,
					SilcChannelEntry channel,
					unsigned char route_notify,
					SilcNotifyType type,
					unsigned int argc, ...);
void silc_server_send_notify_on_channels(SilcServer server,
					 SilcClientEntry client,
					 SilcNotifyType type,
					 unsigned int argc, ...);
void silc_server_send_new_id(SilcServer server,
			     SilcSocketConnection sock,
			     int broadcast,
			     void *id, SilcIdType id_type, 
			     unsigned int id_len);
void silc_server_send_replace_id(SilcServer server,
				 SilcSocketConnection sock,
				 int broadcast,
				 void *old_id, SilcIdType old_id_type,
				 unsigned int old_id_len,
				 void *new_id, SilcIdType new_id_type,
				 unsigned int new_id_len);
void silc_server_send_remove_channel_user(SilcServer server,
					  SilcSocketConnection sock,
					  int broadcast,
					  void *client_id, void *channel_id);
void silc_server_send_new_channel(SilcServer server,
				  SilcSocketConnection sock,
				  int broadcast,
				  char *channel_name,
				  void *channel_id, 
				  unsigned int channel_id_len);
void silc_server_send_new_channel_user(SilcServer server,
				       SilcSocketConnection sock,
				       int broadcast,
				       void *channel_id, 
				       unsigned int channel_id_len,
				       void *client_id,
				       unsigned int client_id_len);
void silc_server_send_channel_key(SilcServer server,
				  SilcSocketConnection sender,
				  SilcChannelEntry channel,
				  unsigned char route);
void silc_server_send_command(SilcServer server, 
			      SilcSocketConnection sock,
			      SilcCommand command, 
			      unsigned int argc, ...);
void silc_server_send_remove_id(SilcServer server,
				SilcSocketConnection sock,
				int broadcast,
				void *id, unsigned int id_len,
				SilcIdType id_type);
void silc_server_send_set_mode(SilcServer server,
			       SilcSocketConnection sock,
			       int broadcast,
			       int mode_type, unsigned int mode_mask,
			       unsigned int argc, ...);

#endif
