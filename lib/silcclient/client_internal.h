/*

  client_internal.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_INTERNAL_H
#define CLIENT_INTERNAL_H

/* Internal context for connection process. This is needed as we
   doing asynchronous connecting. */
typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcTask task;
  int sock;
  char *host;
  int port;
  int tries;
  void *context;
} SilcClientInternalConnectContext;

/* Structure to hold ping time information. Every PING command will 
   add entry of this structure and is removed after reply to the ping
   as been received. */
struct SilcClientPingStruct {
  time_t start_time;
  void *dest_id;
  char *dest_name;
};

/* Structure to hold away messages set by user. This is mainly created
   for future extensions where away messages could be set according filters
   such as nickname and hostname. For now only one away message can 
   be set in one connection. */
struct SilcClientAwayStruct {
  char *away;
  struct SilcClientAwayStruct *next;
};

/* Internal context for the client->internal pointer in the SilcClient. */
struct SilcClientInternalStruct {
  /* All client operations that are implemented by the application. */
  SilcClientOperations *ops;

  /* Client Parameters */
  SilcClientParams *params;

  /* Table of connections in client. All the connection data is saved here. */
  SilcClientConnection *conns;
  SilcUInt32 conns_count;

  /* Table of listenning sockets in client.  Client can have listeners
     (like key agreement protocol server) and those sockets are saved here.
     This table is checked always if the connection object cannot be found
     from the `conns' table. */
  SilcSocketConnection *sockets;
  SilcUInt32 sockets_count;

  /* Registered commands */
  SilcList commands;

  /* Generic cipher and hash objects. */
  SilcCipher none_cipher;
  SilcHash md5hash;
  SilcHash sha1hash;
  SilcHmac md5hmac;
  SilcHmac sha1hmac;

  /* Client version. Used to compare to remote host's version strings. */
  char *silc_client_version;
};

/* Session resuming callback */
typedef void (*SilcClientResumeSessionCallback)(SilcClient client,
						SilcClientConnection conn,
						bool success,
						void *context);

/* Macros */

/* Registers generic task for file descriptor for reading from network and
   writing to network. As being generic task the actual task is allocated 
   only once and after that the same task applies to all registered fd's. */
#define SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(fd)	\
do {							\
  silc_schedule_task_add(client->schedule, (fd),	\
			 silc_client_packet_process,	\
			 context, 0, 0,			\
			 SILC_TASK_GENERIC,		\
		         SILC_TASK_PRI_NORMAL);		\
} while(0)

#define SILC_CLIENT_SET_CONNECTION_FOR_INPUT(s, fd)		\
do {								\
  silc_schedule_set_listen_fd((s), (fd), SILC_TASK_READ);	\
} while(0)
     
#define SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(s, fd)		\
do {								\
  silc_schedule_set_listen_fd((s), (fd), (SILC_TASK_READ |	\
				          SILC_TASK_WRITE));	\
} while(0)

/* Finds socket connection object by file descriptor */
#define SILC_CLIENT_GET_SOCK(__x, __fd, __sock)			\
do {								\
  int __i;							\
								\
  for (__i = 0; __i < (__x)->internal->conns_count; __i++)	\
    if ((__x)->internal->conns[__i] &&				\
	(__x)->internal->conns[__i]->sock->sock == (__fd))	\
      break;							\
								\
  if (__i >= (__x)->internal->conns_count) {			\
    (__sock) = NULL;						\
    for (__i = 0; __i < (__x)->internal->sockets_count; __i++)	\
      if ((__x)->internal->sockets[__i] &&			\
	  (__x)->internal->sockets[__i]->sock == (__fd))	\
        (__sock) = (__x)->internal->sockets[__i];		\
  } else							\
    (__sock) = (__x)->internal->conns[__i]->sock;		\
} while(0)

/* Check whether rekey protocol is active */
#define SILC_CLIENT_IS_REKEY(sock)					\
  (sock->protocol && sock->protocol->protocol && 			\
   sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)

/* Prototypes */

SILC_TASK_CALLBACK_GLOBAL(silc_client_packet_process);
int silc_client_packet_send_real(SilcClient client,
				 SilcSocketConnection sock,
				 bool force_send);
void silc_client_ftp_free_sessions(SilcClient client,
				   SilcClientConnection conn);
void silc_client_ftp_session_free(SilcClientFtpSession session);
void silc_client_ftp_session_free_client(SilcClientConnection conn,
					 SilcClientEntry client_entry);
void silc_client_packet_send(SilcClient client, 
			     SilcSocketConnection sock,
			     SilcPacketType type, 
			     void *dst_id,
			     SilcIdType dst_id_type,
			     SilcCipher cipher,
			     SilcHmac hmac,
			     unsigned char *data, 
			     SilcUInt32 data_len, 
			     int force_send);
void silc_client_close_connection_real(SilcClient client,
				       SilcSocketConnection sock,
				       SilcClientConnection conn);
void silc_client_disconnected_by_server(SilcClient client,
					SilcSocketConnection sock,
					SilcBuffer message);
void silc_client_error_by_server(SilcClient client,
				 SilcSocketConnection sock,
				 SilcBuffer message);
void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				SilcIDPayload idp);
void silc_client_save_channel_key(SilcClient client,
				  SilcClientConnection conn,
				  SilcBuffer key_payload, 
				  SilcChannelEntry channel);
void silc_client_receive_channel_key(SilcClient client,
				     SilcSocketConnection sock,
				     SilcBuffer packet);
void silc_client_channel_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet);
void silc_client_remove_from_channels(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry);
void silc_client_replace_from_channels(SilcClient client, 
				       SilcClientConnection conn,
				       SilcClientEntry old,
				       SilcClientEntry newclient);
void silc_client_process_failure(SilcClient client,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
void silc_client_key_agreement(SilcClient client,
			       SilcSocketConnection sock,
			       SilcPacketContext *packet);
void silc_client_notify_by_server(SilcClient client,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet);
void silc_client_private_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet);
void silc_client_connection_auth_request(SilcClient client,
					 SilcSocketConnection sock,
					 SilcPacketContext *packet);
void silc_client_ftp(SilcClient client,
		     SilcSocketConnection sock,
		     SilcPacketContext *packet);
SilcBuffer silc_client_get_detach_data(SilcClient client,
				       SilcClientConnection conn);
bool silc_client_process_detach_data(SilcClient client,
				     SilcClientConnection conn,
				     unsigned char **old_id,
				     SilcUInt16 *old_id_len);
void silc_client_resume_session(SilcClient client,
				SilcClientConnection conn,
				SilcClientResumeSessionCallback callback,
				void *context);

#endif
