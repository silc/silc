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
				 bool force_send);
void silc_server_packet_send(SilcServer server,
			     SilcSocketConnection sock, 
			     SilcPacketType type, 
			     SilcPacketFlags flags,
			     unsigned char *data, 
			     uint32 data_len,
			     bool force_send);
void silc_server_packet_send_dest(SilcServer server,
				  SilcSocketConnection sock, 
				  SilcPacketType type, 
				  SilcPacketFlags flags,
				  void *dst_id,
				  SilcIdType dst_id_type,
				  unsigned char *data, 
				  uint32 data_len,
				  bool force_send);
void silc_server_packet_send_srcdest(SilcServer server,
				     SilcSocketConnection sock, 
				     SilcPacketType type, 
				     SilcPacketFlags flags,
				     void *src_id,
				     SilcIdType src_id_type,
				     void *dst_id,
				     SilcIdType dst_id_type,
				     unsigned char *data, 
				     uint32 data_len,
				     bool force_send);
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
					bool route,
					unsigned char *data,
					uint32 data_len,
					bool force_send);
void silc_server_packet_relay_to_channel(SilcServer server,
					 SilcSocketConnection sender_sock,
					 SilcChannelEntry channel,
					 void *sender, 
					 SilcIdType sender_type,
					 void *sender_entry,
					 unsigned char *data,
					 uint32 data_len,
					 bool force_send);
void silc_server_packet_send_local_channel(SilcServer server,
					   SilcChannelEntry channel,
					   SilcPacketType type,
					   SilcPacketFlags flags,
					   unsigned char *data,
					   uint32 data_len,
					   bool force_send);
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
			     int broadcast,
			     SilcNotifyType type,
			     uint32 argc, ...);
void silc_server_send_notify_args(SilcServer server,
				  SilcSocketConnection sock,
				  int broadcast,
				  SilcNotifyType type,
				  uint32 argc,
				  SilcBuffer args);
void silc_server_send_notify_channel_change(SilcServer server,
					    SilcSocketConnection sock,
					    int broadcast,
					    SilcChannelID *old_id,
					    SilcChannelID *new_id);
void silc_server_send_notify_nick_change(SilcServer server,
					 SilcSocketConnection sock,
					 int broadcast,
					 SilcClientID *old_id,
					 SilcClientID *new_id);
void silc_server_send_notify_join(SilcServer server,
				  SilcSocketConnection sock,
				  int broadcast,
				  SilcChannelEntry channel,
				  SilcClientID *client_id);
void silc_server_send_notify_leave(SilcServer server,
				   SilcSocketConnection sock,
				   int broadcast,
				   SilcChannelEntry channel,
				   SilcClientID *client_id);
void silc_server_send_notify_cmode(SilcServer server,
				   SilcSocketConnection sock,
				   int broadcast,
				   SilcChannelEntry channel,
				   uint32 mode_mask,
				   void *id, SilcIdType id_type,
				   char *cipher, char *hmac);
void silc_server_send_notify_cumode(SilcServer server,
				    SilcSocketConnection sock,
				    int broadcast,
				    SilcChannelEntry channel,
				    uint32 mode_mask,
				    void *id, SilcIdType id_type,
				    SilcClientID *target);
void silc_server_send_notify_signoff(SilcServer server,
				     SilcSocketConnection sock,
				     int broadcast,
				     SilcClientID *client_id,
				     char *message);
void silc_server_send_notify_topic_set(SilcServer server,
				       SilcSocketConnection sock,
				       int broadcast,
				       SilcChannelEntry channel,
				       SilcClientID *client_id,
				       char *topic);
void silc_server_send_notify_kicked(SilcServer server,
				    SilcSocketConnection sock,
				    int broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    char *comment);
void silc_server_send_notify_killed(SilcServer server,
				    SilcSocketConnection sock,
				    int broadcast,
				    SilcClientID *client_id,
				    char *comment);
void silc_server_send_notify_umode(SilcServer server,
				   SilcSocketConnection sock,
				   int broadcast,
				   SilcClientID *client_id,
				   uint32 mode_mask);
void silc_server_send_notify_ban(SilcServer server,
				 SilcSocketConnection sock,
				 int broadcast,
				 SilcChannelEntry channel,
				 char *add, char *del);
void silc_server_send_notify_invite(SilcServer server,
				    SilcSocketConnection sock,
				    int broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    char *add, char *del);
void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  int broadcast,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  uint32 argc, ...);
void silc_server_send_notify_to_channel(SilcServer server,
					SilcSocketConnection sender,
					SilcChannelEntry channel,
					unsigned char route_notify,
					SilcNotifyType type,
					uint32 argc, ...);
void silc_server_send_notify_on_channels(SilcServer server,
					 SilcClientEntry sender,
					 SilcClientEntry client,
					 SilcNotifyType type,
					 uint32 argc, ...);
void silc_server_send_new_id(SilcServer server,
			     SilcSocketConnection sock,
			     int broadcast,
			     void *id, SilcIdType id_type, 
			     uint32 id_len);
void silc_server_send_new_channel(SilcServer server,
				  SilcSocketConnection sock,
				  int broadcast,
				  char *channel_name,
				  void *channel_id, 
				  uint32 channel_id_len,
				  uint32 mode);
void silc_server_send_channel_key(SilcServer server,
				  SilcSocketConnection sender,
				  SilcChannelEntry channel,
				  unsigned char route);
void silc_server_send_command(SilcServer server, 
			      SilcSocketConnection sock,
			      SilcCommand command, 
			      uint16 ident,
			      uint32 argc, ...);
void silc_server_send_heartbeat(SilcServer server,
				SilcSocketConnection sock);
void silc_server_relay_packet(SilcServer server,
			      SilcSocketConnection dst_sock,
			      SilcCipher cipher,
			      SilcHmac hmac,
			      SilcPacketContext *packet,
			      bool force_send);
void silc_server_send_connection_auth_request(SilcServer server,
					      SilcSocketConnection sock,
					      uint16 conn_type,
					      SilcAuthMethod auth_meth);
void silc_server_packet_queue_purge(SilcServer server,
				    SilcSocketConnection sock);

#endif
