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

/* Forward declaration of backup server context */
typedef struct SilcServerBackupStruct *SilcServerBackup;

#define SILC_SERVER_MAX_CONNECTIONS 1000

/* General definitions */

/* SILC port */
#define SILC_PORT 768;

/* Server and router. Used internally by the code. */
#define SILC_SERVER 0
#define SILC_ROUTER 1
#define SILC_BACKUP_ROUTER 2

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
  uint32 retry_count;
  uint32 retry_interval_min;
  uint32 retry_interval_min_usec;
  uint32 retry_interval_max;
  char retry_keep_trying;

  uint32 protocol_timeout;
  uint32 protocol_timeout_usec;

  char require_reverse_mapping;
} *SilcServerParams;

/* Callback function that is called after the key exchange and connection
   authentication protocols has been completed with a remote router. The
   `server_entry' is the remote router entry. */
typedef void (*SilcServerConnectRouterCallback)(SilcServer server,
						SilcServerEntry server_entry,
						void *context);

typedef struct {
  SilcSocketConnection sock;

  /* Remote host name and port */
  char *remote_host;
  int remote_port;
  bool backup;
  
  /* Current connection retry info */
  uint32 retry_count;
  uint32 retry_timeout;

  /* Back pointer to server */
  SilcServer server;

  SilcServerConnectRouterCallback callback;
  void *callback_context;
} *SilcServerConnection;

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

/* Check whether rekey protocol is active */
#define SILC_SERVER_IS_REKEY(sock)					\
  (sock->protocol && sock->protocol->protocol && 			\
   sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY)

/* Prototypes */
int silc_server_alloc(SilcServer *new_server);
void silc_server_free(SilcServer server);
int silc_server_init(SilcServer server);
void silc_server_daemonise(SilcServer server);
void silc_server_run(SilcServer server);
void silc_server_stop(SilcServer server);
void silc_server_start_key_exchange(SilcServer server,
				    SilcServerConnection sconn,
				    int sock);
void silc_server_packet_parse(SilcPacketParserContext *parser_context);
void silc_server_packet_parse_type(SilcServer server, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet);
void silc_server_create_connection(SilcServer server,
				   char *remote_host, uint32 port);
void silc_server_close_connection(SilcServer server,
				  SilcSocketConnection sock);
void silc_server_free_client_data(SilcServer server, 
				  SilcSocketConnection sock,
				  SilcClientEntry client, 
				  int notify,
				  char *signoff);
void silc_server_free_sock_user_data(SilcServer server, 
				     SilcSocketConnection sock);
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
bool silc_server_create_channel_key(SilcServer server, 
				    SilcChannelEntry channel,
				    uint32 key_len);
SilcChannelEntry silc_server_save_channel_key(SilcServer server,
					      SilcBuffer key_payload,
					      SilcChannelEntry channel);
void silc_server_perform_heartbeat(SilcSocketConnection sock,
				   void *hb_context);
void silc_server_announce_get_channel_users(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *channel_users,
					    SilcBuffer *channel_users_modes);
void silc_server_announce_get_channels(SilcServer server,
				       SilcIDList id_list,
				       SilcBuffer *channels,
				       SilcBuffer *channel_users,
				       SilcBuffer **channel_users_modes,
				       uint32 *channel_users_modes_c,
				       SilcChannelID ***channel_ids,
				       unsigned long creation_time);
void silc_server_announce_servers(SilcServer server, bool global,
				  unsigned long creation_time,
				  SilcSocketConnection remote);
void silc_server_announce_clients(SilcServer server,
				  unsigned long creation_time,
				  SilcSocketConnection remote);
void silc_server_announce_channels(SilcServer server,
				   unsigned long creation_time,
				   SilcSocketConnection remote);
void silc_server_get_users_on_channel(SilcServer server,
				      SilcChannelEntry channel,
				      SilcBuffer *user_list,
				      SilcBuffer *mode_list,
				      uint32 *user_count);
void silc_server_save_users_on_channel(SilcServer server,
				       SilcSocketConnection sock,
				       SilcChannelEntry channel,
				       SilcClientID *noadd,
				       SilcBuffer user_list,
				       SilcBuffer mode_list,
				       uint32 user_count);
SilcSocketConnection silc_server_get_client_route(SilcServer server,
						  unsigned char *id_data,
						  uint32 id_len,
						  SilcClientID *client_id,
						  SilcIDListData *idata);
SilcBuffer silc_server_get_client_channel_list(SilcServer server,
					       SilcClientEntry client);
SilcClientEntry silc_server_get_client_resolve(SilcServer server,
					       SilcClientID *client_id);

#endif
