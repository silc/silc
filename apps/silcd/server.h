/*

  server.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVER_H
#define SERVER_H

/* Forward declaration for SILC Server object. The actual object is
   defined in internal header file for server routines. I want to keep
   the object private hence this declaration. */
typedef struct SilcServerObjectStruct *SilcServer;

#define SILC_SERVER_MAX_CONNECTIONS 10000

/* General definitions */

#define SILC_SERVER 0
#define SILC_ROUTER 1

/* Prototypes */
int silc_server_alloc(SilcServer *new_server);
void silc_server_free(SilcServer server);
int silc_server_init(SilcServer server);
void silc_server_run(SilcServer server);
void silc_server_stop(SilcServer server);
void silc_server_packet_parse(SilcPacketParserContext *parser_context);
void silc_server_packet_parse_type(SilcServer server, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet);
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
void silc_server_packet_forward(SilcServer server,
				SilcSocketConnection sock,
				unsigned char *data, unsigned int data_len,
				int force_send);
void silc_server_packet_send_to_channel(SilcServer server,
					SilcChannelEntry channel,
					SilcPacketType type,
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
void silc_server_packet_relay_command_reply(SilcServer server,
					    SilcSocketConnection sock,
					    SilcPacketContext *packet);
void silc_server_close_connection(SilcServer server,
				  SilcSocketConnection sock);
void silc_server_free_sock_user_data(SilcServer server, 
				     SilcSocketConnection sock);
void silc_server_remove_from_channels(SilcServer server, 
				      SilcSocketConnection sock,
				      SilcClientEntry client);
int silc_server_remove_from_one_channel(SilcServer server, 
					SilcSocketConnection sock,
					SilcChannelEntry channel,
					SilcClientEntry client,
					int notify);
int silc_server_client_on_channel(SilcClientEntry client,
				  SilcChannelEntry channel);
void silc_server_disconnect_remote(SilcServer server,
				   SilcSocketConnection sock,
				   const char *fmt, ...);
void silc_server_private_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
void silc_server_channel_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
void silc_server_channel_key(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet);
void silc_server_send_motd(SilcServer server,
			   SilcSocketConnection sock);
void silc_server_send_error(SilcServer server,
			    SilcSocketConnection sock,
			    const char *fmt, ...);
void silc_server_send_notify(SilcServer server,
			     SilcSocketConnection sock,
			     SilcNotifyType type,
			     unsigned int argc,
			     unsigned int format,
			     const char *fmt, ...);
void silc_server_send_notify_dest(SilcServer server,
				  SilcSocketConnection sock,
				  void *dest_id,
				  SilcIdType dest_id_type,
				  SilcNotifyType type,
				  unsigned int argc,
				  unsigned int format,
				  const char *fmt, ...);
void silc_server_send_notify_to_channel(SilcServer server,
					SilcChannelEntry channel,
					SilcNotifyType type,
					unsigned int argc,
					unsigned int format,
					const char *fmt, ...);
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
void silc_server_replace_id(SilcServer server,
			    SilcSocketConnection sock,
			    SilcPacketContext *packet);
SilcChannelEntry silc_server_new_channel(SilcServer server, 
					 SilcServerID *router_id,
					 char *cipher, char *channel_name);
SilcClientEntry silc_server_new_client(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet);
SilcServerEntry silc_server_new_server(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet);
void silc_server_new_id(SilcServer server, SilcSocketConnection sock,
			SilcPacketContext *packet);
void silc_server_remove_channel_user(SilcServer server,
				     SilcSocketConnection sock,
				     SilcPacketContext *packet);

#endif
