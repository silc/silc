/*

  server.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005, 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVER_H
#define SERVER_H

/* Forward declarations */
typedef struct SilcServerEntryStruct *SilcServerEntry;
typedef struct SilcClientEntryStruct *SilcClientEntry;
typedef struct SilcChannelEntryStruct *SilcChannelEntry;
typedef struct SilcServerBackupStruct *SilcServerBackup;
typedef struct SilcIDListDataObject *SilcIDListData, SilcIDListDataStruct;
typedef struct SilcIDListStruct *SilcIDList;

/* Callback function that is called after the key exchange and connection
   authentication protocols has been completed with a remote router. The
   `server_entry' is the remote router entry or NULL on error. */
typedef void (*SilcServerConnectCallback)(SilcServer server,
					  SilcServerEntry server_entry,
					  void *context);

/* Connection structure used when connection to remote */
typedef struct SilcServerConnectionStruct {
  SilcServer server;
  SilcStream stream;
  SilcPacketStream sock;
  SilcAsyncOperation op;
  SilcServerConfigRef conn;

  char *remote_host;
  int remote_port;

  char *backup_replace_ip;
  int backup_replace_port;

  /* Current connection retry info */
  SilcUInt32 retry_count;
  SilcUInt32 retry_timeout;
  SilcServerConnectCallback callback;
  void *callback_context;
  int rekey_timeout;

  unsigned int backup          : 1;   /* Set when backup router connection */
  unsigned int backup_resuming : 1;   /* Set when running resuming protocol */
  unsigned int no_reconnect    : 1;   /* Set when to not reconnect */
  unsigned int no_conf         : 1;   /* Set when connecting without pre-
					 configuration. */
} *SilcServerConnection;

/* General definitions */

/* SILC port */
#define SILC_PORT 706

/* Server and router. Used internally by the code. */
#define SILC_SERVER 0
#define SILC_ROUTER 1
#define SILC_BACKUP_ROUTER 2

/* Default parameter values */

/* Connection retry timeout. We implement exponential backoff algorithm
   in connection retry. The interval of timeout grows when retry count
   grows. */
#define SILC_SERVER_RETRY_COUNT        7	 /* Max retry count */
#define SILC_SERVER_RETRY_MULTIPLIER   2	 /* Interval growth */
#define SILC_SERVER_RETRY_RANDOMIZER   2	 /* timeout += rnd % 2 */
#define SILC_SERVER_RETRY_INTERVAL_MIN 10	 /* Min retry timeout */
#define SILC_SERVER_RETRY_INTERVAL_MAX 600	 /* Max generated timeout */

#define SILC_SERVER_KEEPALIVE          300	 /* Heartbeat interval */
#define SILC_SERVER_CHANNEL_REKEY      3600	 /* Channel rekey interval */
#define SILC_SERVER_REKEY              3600	 /* Session rekey interval */
#define SILC_SERVER_SKE_TIMEOUT        60	 /* SKE timeout */
#define SILC_SERVER_CONNAUTH_TIMEOUT   60	 /* CONN_AUTH timeout */
#define SILC_SERVER_MAX_CONNECTIONS    1000	 /* Max connections */
#define SILC_SERVER_MAX_CONNECTIONS_SINGLE 1000  /* Max connections per host */
#define SILC_SERVER_LOG_FLUSH_DELAY    300       /* Default log flush delay */
#define SILC_SERVER_QOS_RATE_LIMIT     10        /* Default QoS rate limit */
#define SILC_SERVER_QOS_BYTES_LIMIT    2048      /* Default QoS bytes limit */
#define SILC_SERVER_QOS_LIMIT_SEC      0         /* Default QoS limit sec */
#define SILC_SERVER_QOS_LIMIT_USEC     500000    /* Default QoS limit usec */
#define SILC_SERVER_CH_JOIN_LIMIT      50        /* Default join limit */

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
} while(0)

/* Send notify to operators */
#define SILC_SERVER_SEND_OPERS(server, route, local, type, fmt)		\
do {									\
  char *__fmt__ = silc_format fmt;					\
  silc_server_send_opers_notify(server, route, local,			\
			        type, 1, __fmt__, strlen(__fmt__));	\
  silc_free(__fmt__);							\
} while(0)

/* Output a message to stderr or to the appropriate log facility wether
   we are in the background or not. */
#define SILC_SERVER_LOG_INFO(fmt)					\
  silc_server_stderr(SILC_LOG_INFO, silc_format fmt)
#define SILC_SERVER_LOG_WARNING(fmt)					\
  silc_server_stderr(SILC_LOG_WARNING, silc_format fmt)
#define SILC_SERVER_LOG_ERROR(fmt)					\
  silc_server_stderr(SILC_LOG_ERROR, silc_format fmt)
#define SILC_SERVER_LOG_FATAL(fmt)					\
  silc_server_stderr(SILC_LOG_WARNING, silc_format fmt)

/* Prototypes */
SilcBool silc_server_alloc(SilcServer *new_server);
void silc_server_free(SilcServer server);
SilcBool silc_server_init(SilcServer server);
SilcBool silc_server_rehash(SilcServer server);
void silc_server_run(SilcServer server);
void silc_server_stop(SilcServer server);
void silc_server_start_key_exchange(SilcServerConnection sconn);
void silc_server_create_connection(SilcServer server,
				   SilcBool reconnect,
				   SilcBool dynamic,
				   const char *remote_host, SilcUInt32 port,
				   SilcServerConnectCallback callback,
				   void *context);
void silc_server_close_connection(SilcServer server,
				  SilcPacketStream sock);
void silc_server_free_client_data(SilcServer server,
				  SilcPacketStream sock,
				  SilcClientEntry client,
				  int notify,
				  const char *signoff);
void silc_server_free_sock_user_data(SilcServer server,
				     SilcPacketStream sock,
				     const char *signoff_message);
void silc_server_remove_from_channels(SilcServer server,
				      SilcPacketStream sock,
				      SilcClientEntry client,
				      SilcBool notify,
				      const char *signoff_message,
				      SilcBool keygen, bool killed);
SilcBool silc_server_remove_from_one_channel(SilcServer server,
					 SilcPacketStream sock,
					 SilcChannelEntry channel,
					 SilcClientEntry client,
					 SilcBool notify);
void silc_server_disconnect_remote(SilcServer server,
				   SilcPacketStream sock,
				   SilcStatus status, ...);
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
SilcBool silc_server_create_channel_key(SilcServer server,
				    SilcChannelEntry channel,
				    SilcUInt32 key_len);
SilcChannelEntry silc_server_save_channel_key(SilcServer server,
					      SilcBuffer key_payload,
					      SilcChannelEntry channel);
void silc_server_perform_heartbeat(SilcPacketStream sock,
				   void *hb_context);
void silc_server_announce_get_channel_topic(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *topic);
void silc_server_announce_get_channel_users(SilcServer server,
					    SilcChannelEntry channel,
					    SilcBuffer *channel_modes,
					    SilcBuffer *channel_users,
					    SilcBuffer *channel_users_modes);
void silc_server_announce_get_channels(SilcServer server,
				       SilcIDList id_list,
				       SilcBuffer *channels,
				       SilcBuffer **channel_modes,
				       SilcBuffer *channel_users,
				       SilcBuffer **channel_users_modes,
				       SilcUInt32 *channel_users_modes_c,
				       SilcBuffer **channel_topics,
				       SilcBuffer **channel_invites,
				       SilcBuffer **channel_bans,
				       SilcChannelID ***channel_ids,
				       unsigned long creation_time);
void silc_server_announce_servers(SilcServer server, SilcBool global,
				  unsigned long creation_time,
				  SilcPacketStream remote);
void silc_server_announce_clients(SilcServer server,
				  unsigned long creation_time,
				  SilcPacketStream remote);
void silc_server_announce_channels(SilcServer server,
				   unsigned long creation_time,
				   SilcPacketStream remote);
void silc_server_announce_watches(SilcServer server,
				  SilcPacketStream remote);
SilcBool silc_server_get_users_on_channel(SilcServer server,
				      SilcChannelEntry channel,
				      SilcBuffer *user_list,
				      SilcBuffer *mode_list,
				      SilcUInt32 *user_count);
void silc_server_save_users_on_channel(SilcServer server,
				       SilcPacketStream sock,
				       SilcChannelEntry channel,
				       SilcClientID *noadd,
				       SilcBuffer user_list,
				       SilcBuffer mode_list,
				       SilcUInt32 user_count);
void silc_server_save_user_channels(SilcServer server,
				    SilcPacketStream sock,
				    SilcClientEntry client,
				    SilcBuffer channels,
				    SilcBuffer channels_user_modes);
SilcPacketStream
silc_server_get_client_route(SilcServer server,
			     unsigned char *id_data,
			     SilcUInt32 id_len,
			     SilcClientID *client_id,
			     SilcIDListData *idata,
			     SilcClientEntry *client_entry);
SilcBuffer silc_server_get_client_channel_list(SilcServer server,
					       SilcClientEntry client,
					       SilcBool get_private,
					       SilcBool get_secret,
					       SilcBuffer *user_mode_list);
void silc_server_stderr(SilcLogType type, char *message);
void silc_server_http_init(SilcServer server);
void silc_server_http_uninit(SilcServer server);

#endif
