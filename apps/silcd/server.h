/*

  server.h

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

#ifndef SERVER_H
#define SERVER_H

/* Forward declaration for SILC Server object. The actual object is
   defined in internal header file for server routines. I want to keep
   the object private hence this declaration. */
typedef struct SilcServerStruct *SilcServer;

#define SILC_SERVER_MAX_CONNECTIONS 10000

/* General definitions */

/* SILC port */
#define SILC_PORT 768;

/* Server and router. Used internally by the code. */
#define SILC_SERVER 0
#define SILC_ROUTER 1

/* Connection retry timeout. We implement exponential backoff algorithm
   in connection retry. The interval of timeuot grows when retry count
   grows. */
#define SILC_SERVER_RETRY_COUNT        4	 /* Max retry count */
#define SILC_SERVER_RETRY_MULTIPLIER   7 / 4	 /* Interval growth */
#define SILC_SERVER_RETRY_RANDOMIZER   2	 /* timeout += rnd % 2 */
#define SILC_SERVER_RETRY_INTERVAL_MIN 10	 /* Min retry timeout */
#define SILC_SERVER_RETRY_INTERVAL_MAX 600	 /* Max generated timeout */

/* 
   Silc Server Params.

   Structure to hold various default parameters for server that can be
   given before running the server. 

*/
typedef struct {
  unsigned int retry_count;
  unsigned long retry_interval_min;
  unsigned long retry_interval_min_usec;
  unsigned long retry_interval_max;
  char retry_keep_trying;

  unsigned long protocol_timeout;
  unsigned long protocol_timeout_usec;

  char require_reverse_mapping;
} *SilcServerParams;

/* Macros */

/* This macro is used to send notify messages with formatted string. The
   string is formatted with arguments and the formatted string is sent as
   argument. */
#define SILC_SERVER_SEND_NOTIFY(server, sock, type, fmt)	\
do {								\
  char *__fmt__ = silc_format fmt;				\
  silc_server_send_notify(server, sock, FALSE, 			\
			  type, 1, __fmt__, strlen(__fmt__));	\
  silc_free(__fmt__);						\
} while(0);

/* Prototypes */
int silc_server_alloc(SilcServer *new_server);
void silc_server_free(SilcServer server);
int silc_server_init(SilcServer server);
void silc_server_daemonise(SilcServer server);
void silc_server_run(SilcServer server);
void silc_server_stop(SilcServer server);
void silc_server_packet_parse(SilcPacketParserContext *parser_context);
void silc_server_packet_parse_type(SilcServer server, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet);
void silc_server_create_connection(SilcServer server,
				   char *remote_host, unsigned int port);
void silc_server_close_connection(SilcServer server,
				  SilcSocketConnection sock);
void silc_server_free_client_data(SilcServer server, 
				  SilcSocketConnection sock,
				  SilcClientEntry client, 
				  int notify,
				  char *signoff);
void silc_server_free_sock_user_data(SilcServer server, 
				     SilcSocketConnection sock);
int silc_server_channel_has_global(SilcChannelEntry channel);
int silc_server_channel_has_local(SilcChannelEntry channel);
int silc_server_remove_clients_by_server(SilcServer server, 
					 SilcServerEntry entry);
void silc_server_remove_from_channels(SilcServer server, 
				      SilcSocketConnection sock,
				      SilcClientEntry client,
				      int notify,
				      char *signoff_message,
				      int keygen);
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
SilcChannelEntry silc_server_create_new_channel(SilcServer server, 
						SilcServerID *router_id,
						char *cipher, 
						char *hmac,
						char *channel_name,
						int broadcast);
SilcChannelEntry 
silc_server_create_new_channel_with_id(SilcServer server, 
				       char *cipher, 
				       char *hmac,
				       char *channel_name,
				       SilcChannelID *channel_id,
				       int broadcast);
void silc_server_create_channel_key(SilcServer server, 
				    SilcChannelEntry channel,
				    unsigned int key_len);
SilcChannelEntry silc_server_save_channel_key(SilcServer server,
					      SilcBuffer key_payload,
					      SilcChannelEntry channel);
void silc_server_perform_heartbeat(SilcSocketConnection sock,
				   void *hb_context);
void silc_server_announce_servers(SilcServer server);
void silc_server_announce_clients(SilcServer server);
void silc_server_announce_channels(SilcServer server);
void silc_server_get_users_on_channel(SilcServer server,
				      SilcChannelEntry channel,
				      SilcBuffer *user_list,
				      SilcBuffer *mode_list,
				      unsigned int *user_count);
void silc_server_save_users_on_channel(SilcServer server,
				       SilcSocketConnection sock,
				       SilcChannelEntry channel,
				       SilcClientID *noadd,
				       SilcBuffer user_list,
				       SilcBuffer mode_list,
				       unsigned int user_count);
SilcSocketConnection silc_server_get_client_route(SilcServer server,
						  unsigned char *id_data,
						  unsigned int id_len,
						  SilcClientID *client_id,
						  SilcIDListData *idata);
SilcBuffer silc_server_get_client_channel_list(SilcServer server,
					       SilcClientEntry client);
SilcClientEntry silc_server_get_client_resolve(SilcServer server,
					       SilcClientID *client_id);

#endif
