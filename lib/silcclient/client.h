/*

  client.h

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

#ifndef CLIENT_H
#define CLIENT_H

/* Forward declaration for client */
typedef struct SilcClientObject *SilcClient;

/* Forward declaration for client connection */
typedef struct SilcClientConnectionObject *SilcClientConnection;

#include "idlist.h"
#include "command.h"
#include "ops.h"

/* Structure to hold ping time information. Every PING command will 
   add entry of this structure and is removed after reply to the ping
   as been received. */
typedef struct SilcClientPingStruct {
  time_t start_time;
  void *dest_id;
  char *dest_name;
} SilcClientPing;

/* Structure to hold away messages set by user. This is mainly created
   for future extensions where away messages could be set according filters
   such as nickname and hostname. For now only one away message can 
   be set in one connection. */
typedef struct SilcClientAwayStruct {
  char *away;
  struct SilcClientAwayStruct *next;
} SilcClientAway;

/* Connection structure used in client to associate all the important
   connection specific data to this structure. */
struct SilcClientConnectionObject {
  /*
   * Local data 
   */
  char *nickname;

  /* Local client ID for this connection */
  SilcClientID *local_id;

  /* Decoded local ID so that the above defined ID would not have
     to be decoded for every packet. */
  unsigned char *local_id_data;
  unsigned int local_id_data_len;

  /* Own client entry. */
  SilcClientEntry local_entry;

  /*
   * Remote data 
   */
  char *remote_host;
  int remote_port;
  int remote_type;
  char *remote_info;

  /* Remote server ID for this connection */
  SilcServerID *remote_id;

  /* Decoded remote ID so that the above defined ID would not have
     to be decoded for every packet. */
  unsigned char *remote_id_data;
  unsigned int remote_id_data_len;

  /*
   * Common data 
   */
  /* Keys */
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcHmac hmac;
  unsigned char *hmac_key;
  unsigned int hmac_key_len;

  /* Client ID and Channel ID cache. Messages transmitted in SILC network
     are done using different unique ID's. These are the cache for
     thoses ID's used in the communication. */
  SilcIDCache client_cache;
  SilcIDCache channel_cache;
  SilcIDCache server_cache;

  /* Current channel on window. All channels are saved (allocated) into
     the cache entries. */
  SilcChannelEntry current_channel;

  /* Socket connection object for this connection (window). This
     object will have a back-pointer to this window object for fast
     referencing (sock->user_data). */
  SilcSocketConnection sock;

  /* Requested pings. */
  SilcClientPing *ping;
  unsigned int ping_count;

  /* Set away message */
  SilcClientAway *away;

  /* Pointer back to the SilcClient. This object is passed to the application
     and the actual client object is accesible through this pointer. */
  SilcClient client;

  /* User data context. Library does not touch this. */
  void *context;
};

/* Main client structure. */
struct SilcClientObject {
  /*
   * Public data. All the following pointers must be set by the allocator
   * of this structure.
   */

  /* Users's username, hostname and realname. */
  char *username;
  char *hostname;
  char *realname;

  /* Private and public key of the user. */
  SilcPKCS pkcs;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;

  /* Application specific user data pointer. Client library does not
     touch this. */
  void *application;

  /*
   * Private data. Following pointers are used internally by the client
   * library and should be considered read-only fields.
   */

  /* All client operations that are implemented in the application. */
  SilcClientOperations *ops;

  /* SILC client task queues */
  SilcTaskQueue io_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;

  /* Table of connections in client. All the connection data is saved here. */
  SilcClientConnection *conns;
  unsigned int conns_count;

  /* Generic cipher and hash objects. These can be used and referenced
     by the application as well. */
  SilcCipher none_cipher;
  SilcHash md5hash;
  SilcHash sha1hash;
  SilcHmac md5hmac;
  SilcHmac sha1hmac;

  /* Random Number Generator. Application should use this as its primary
     random number generator. */
  SilcRng rng;
};

/* Macros */

/* Registers generic task for file descriptor for reading from network and
   writing to network. As being generic task the actual task is allocated 
   only once and after that the same task applies to all registered fd's. */
#define SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(fd)			\
do {									\
  SilcTask tmptask = silc_task_register(client->generic_queue, (fd),	\
					silc_client_packet_process,	\
					context, 0, 0,			\
					SILC_TASK_GENERIC,		\
					SILC_TASK_PRI_NORMAL);		\
  silc_task_set_iotype(tmptask, SILC_TASK_WRITE);			\
} while(0)

#define SILC_CLIENT_SET_CONNECTION_FOR_INPUT(fd)		\
do {								\
  silc_schedule_set_listen_fd((fd), (1L << SILC_TASK_READ));	\
} while(0)							\
     
#define SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(fd)		\
do {								\
  silc_schedule_set_listen_fd((fd), ((1L << SILC_TASK_READ) |	\
				     (1L << SILC_TASK_WRITE)));	\
} while(0)

/* Finds socket connection object by file descriptor */
#define SILC_CLIENT_GET_SOCK(__x, __fd, __sock)		\
do {							\
  int __i;						\
							\
  for (__i = 0; __i < (__x)->conns_count; __i++)	\
    if ((__x)->conns[__i]->sock->sock == (__fd))	\
      break;						\
							\
  if (__i >= (__x)->conns_count)			\
    (__sock) = NULL;					\
 (__sock) = (__x)->conns[__i]->sock;			\
} while(0)

/* Prototypes */

SilcClient silc_client_alloc(SilcClientOperations *ops, void *application);
void silc_client_free(SilcClient client);
int silc_client_init(SilcClient client);
void silc_client_stop(SilcClient client);
void silc_client_run(SilcClient client);
SilcClientConnection silc_client_add_connection(SilcClient client,
						char *hostname,
						int port,
						void *context);
int silc_client_connect_to_server(SilcClient client, int port,
				  char *host, void *context);
int silc_client_start_key_exchange(SilcClient client,
			           SilcClientConnection conn,
                                   int fd);
void silc_client_packet_send(SilcClient client, 
			     SilcSocketConnection sock,
			     SilcPacketType type, 
			     void *dst_id,
			     SilcIdType dst_id_type,
			     SilcCipher cipher,
			     SilcHmac hmac,
			     unsigned char *data, 
			     unsigned int data_len, 
			     int force_send);
void silc_client_packet_send_to_channel(SilcClient client, 
					SilcSocketConnection sock,
					SilcChannelEntry channel,
					unsigned char *data, 
					unsigned int data_len, 
					int force_send);
void silc_client_packet_send_private_message(SilcClient client,
					     SilcSocketConnection sock,
					     SilcClientEntry client_entry,
					     unsigned char *data, 
					     unsigned int data_len, 
					     int force_send);
void silc_client_close_connection(SilcClient client,
				  SilcSocketConnection sock);
void silc_client_disconnected_by_server(SilcClient client,
					SilcSocketConnection sock,
					SilcBuffer message);
void silc_client_error_by_server(SilcClient client,
				 SilcSocketConnection sock,
				 SilcBuffer message);
void silc_client_notify_by_server(SilcClient client,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet);
void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				SilcIDPayload idp);
void silc_client_new_channel_id(SilcClient client,
				SilcSocketConnection sock,
				char *channel_name,
				unsigned int mode, SilcIDPayload idp);
void silc_client_receive_channel_key(SilcClient client,
				     SilcSocketConnection sock,
				     SilcBuffer packet);
void silc_client_channel_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet);
void silc_client_private_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet);
void silc_client_remove_from_channels(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry);
void silc_client_replace_from_channels(SilcClient client, 
				       SilcClientConnection conn,
				       SilcClientEntry old,
				       SilcClientEntry new);
#endif
