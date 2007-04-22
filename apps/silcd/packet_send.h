/*

  packet_send.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2004, 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef PACKET_SEND_H
#define PACKET_SEND_H

/* Prototypes */

SilcBool silc_server_packet_send(SilcServer server,
				 SilcPacketStream sock,
				 SilcPacketType type,
				 SilcPacketFlags flags,
				 unsigned char *data,
				 SilcUInt32 data_len);
SilcBool silc_server_packet_send_dest(SilcServer server,
				      SilcPacketStream sock,
				      SilcPacketType type,
				      SilcPacketFlags flags,
				      void *dst_id,
				      SilcIdType dst_id_type,
				      unsigned char *data,
				      SilcUInt32 data_len);
SilcBool silc_server_packet_send_srcdest(SilcServer server,
					 SilcPacketStream sock,
					 SilcPacketType type,
					 SilcPacketFlags flags,
					 void *src_id,
					 SilcIdType src_id_type,
					 void *dst_id,
					 SilcIdType dst_id_type,
					 unsigned char *data,
					 SilcUInt32 data_len);
SilcBool silc_server_packet_broadcast(SilcServer server,
				      SilcPacketStream sock,
				      SilcPacket packet);
SilcBool silc_server_packet_route(SilcServer server,
				  SilcPacketStream sock,
				  SilcPacket packet);
void silc_server_packet_send_clients(SilcServer server,
				     SilcHashTable clients,
				     SilcPacketType type,
				     SilcPacketFlags flags,
				     SilcBool route,
				     unsigned char *data,
				     SilcUInt32 data_len);
void silc_server_packet_send_to_channel(SilcServer server,
					SilcPacketStream sender,
					SilcChannelEntry channel,
					SilcPacketType type,
					SilcBool route,
					SilcBool send_to_clients,
					unsigned char *data,
					SilcUInt32 data_len);
void silc_server_packet_relay_to_channel(SilcServer server,
					 SilcPacketStream sender_sock,
					 SilcChannelEntry channel,
					 void *sender_id,
					 SilcIdType sender_type,
					 SilcClientEntry sender_entry,
					 unsigned char *data,
					 SilcUInt32 data_len);
void silc_server_packet_send_local_channel(SilcServer server,
					   SilcChannelEntry channel,
					   SilcPacketType type,
					   SilcPacketFlags flags,
					   unsigned char *data,
					   SilcUInt32 data_len);
void silc_server_send_motd(SilcServer server,
			   SilcPacketStream sock);
void silc_server_send_error(SilcServer server,
			    SilcPacketStream sock,
			    const char *fmt, ...);
void silc_server_send_notify(SilcServer server,
			     SilcPacketStream sock,
			     SilcBool broadcast,
			     SilcNotifyType type,
			     SilcUInt32 argc, ...);
void silc_server_send_notify_args(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  SilcNotifyType type,
				  SilcUInt32 argc,
				  SilcBuffer args);
void silc_server_send_notify_channel_change(SilcServer server,
					    SilcPacketStream sock,
					    SilcBool broadcast,
					    SilcChannelID *old_id,
					    SilcChannelID *new_id);
void silc_server_send_notify_nick_change(SilcServer server,
					 SilcPacketStream sock,
					 SilcBool broadcast,
					 SilcClientID *old_id,
					 SilcClientID *new_id,
					 const char *nickname);
void silc_server_send_notify_join(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  SilcChannelEntry channel,
				  SilcClientID *client_id);
void silc_server_send_notify_leave(SilcServer server,
				   SilcPacketStream sock,
				   SilcBool broadcast,
				   SilcChannelEntry channel,
				   SilcClientID *client_id);
void silc_server_send_notify_cmode(SilcServer server,
				   SilcPacketStream sock,
				   SilcBool broadcast,
				   SilcChannelEntry channel,
				   SilcUInt32 mode_mask,
				   void *id, SilcIdType id_type,
				   const char *cipher, const char *hmac,
				   const char *passphrase,
				   SilcPublicKey founder_key,
				   SilcBuffer channel_pubkeys);
void silc_server_send_notify_cumode(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcChannelEntry channel,
				    SilcUInt32 mode_mask,
				    void *id, SilcIdType id_type,
				    SilcClientID *target,
				    SilcPublicKey founder_key);
void silc_server_send_notify_signoff(SilcServer server,
				     SilcPacketStream sock,
				     SilcBool broadcast,
				     SilcClientID *client_id,
				     const char *message);
void silc_server_send_notify_topic_set(SilcServer server,
				       SilcPacketStream sock,
				       SilcBool broadcast,
				       SilcChannelEntry channel,
				       void *id, SilcIdType id_type,
				       char *topic);
void silc_server_send_notify_kicked(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    SilcClientID *kicker,
				    char *comment);
void silc_server_send_notify_killed(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcClientID *client_id,
				    const char *comment,
				    void *killer, SilcIdType killer_type);
void silc_server_send_notify_umode(SilcServer server,
				   SilcPacketStream sock,
				   SilcBool broadcast,
				   SilcClientID *client_id,
				   SilcUInt32 mode_mask);
void silc_server_send_notify_ban(SilcServer server,
				 SilcPacketStream sock,
				 SilcBool broadcast,
				 SilcChannelEntry channel,
				 unsigned char *action,
				 SilcBuffer list);
void silc_server_send_notify_invite(SilcServer server,
				    SilcPacketStream sock,
				    SilcBool broadcast,
				    SilcChannelEntry channel,
				    SilcClientID *client_id,
				    unsigned char *action,
				    SilcBuffer list);
void silc_server_send_notify_watch(SilcServer server,
				   SilcPacketStream sock,
				   SilcClientEntry watcher,
				   SilcClientEntry client,
				   const char *nickname,
				   SilcNotifyType type,
				   SilcPublicKey public_key);
void silc_server_send_notify_dest(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  SilcUInt32 argc, ...);
void silc_server_send_notify_to_channel(SilcServer server,
					SilcPacketStream sender,
					SilcChannelEntry channel,
					SilcBool route_notify,
					SilcBool send_to_clients,
					SilcNotifyType type,
					SilcUInt32 argc, ...);
void silc_server_send_notify_on_channels(SilcServer server,
					 SilcClientEntry sender,
					 SilcClientEntry client,
					 SilcNotifyType type,
					 SilcUInt32 argc, ...);
void silc_server_send_new_id(SilcServer server,
			     SilcPacketStream sock,
			     SilcBool broadcast,
			     void *id, SilcIdType id_type,
			     SilcUInt32 id_len);
void silc_server_send_new_channel(SilcServer server,
				  SilcPacketStream sock,
				  SilcBool broadcast,
				  char *channel_name,
				  void *channel_id,
				  SilcUInt32 channel_id_len,
				  SilcUInt32 mode);
void silc_server_send_channel_key(SilcServer server,
				  SilcPacketStream sender,
				  SilcChannelEntry channel,
				  unsigned char route);
void silc_server_send_command(SilcServer server,
			      SilcPacketStream sock,
			      SilcCommand command,
			      SilcUInt16 ident,
			      SilcUInt32 argc, ...);
void silc_server_send_command_reply(SilcServer server,
				    SilcPacketStream sock,
				    SilcCommand command,
				    SilcStatus status,
				    SilcStatus error,
				    SilcUInt16 ident,
				    SilcUInt32 argc, ...);
void silc_server_send_dest_command_reply(SilcServer server,
					 SilcPacketStream sock,
					 void *dst_id,
					 SilcIdType dst_id_type,
					 SilcCommand command,
					 SilcStatus status,
					 SilcStatus error,
					 SilcUInt16 ident,
					 SilcUInt32 argc, ...);
void silc_server_relay_packet(SilcServer server,
			      SilcPacketStream dst_sock,
			      SilcCipher cipher,
			      SilcHmac hmac,
			      SilcUInt32 sequence,
			      SilcPacket *packet);
void silc_server_send_connection_auth_request(SilcServer server,
					      SilcPacketStream sock,
					      SilcUInt16 conn_type,
					      SilcAuthMethod auth_meth);
void silc_server_send_opers(SilcServer server,
			    SilcPacketType type,
			    SilcPacketFlags flags,
			    SilcBool route, bool local,
			    unsigned char *data,
			    SilcUInt32 data_len);
void silc_server_send_opers_notify(SilcServer server,
				   SilcBool route,
				   SilcBool local,
				   SilcNotifyType type,
				   SilcUInt32 argc, ...);

#endif /* PACKET_SEND_H */
