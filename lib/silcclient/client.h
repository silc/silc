/*

  client.h

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

#ifndef CLIENT_H
#define CLIENT_H

/* Forward declarations */
typedef struct SilcClientStruct *SilcClient;
typedef struct SilcClientConnectionStruct *SilcClientConnection;
typedef struct SilcClientPingStruct SilcClientPing;
typedef struct SilcClientAwayStruct SilcClientAway;
typedef struct SilcClientKeyAgreementStruct *SilcClientKeyAgreement;

#include "idlist.h"
#include "command.h"
#include "silcapi.h"

/* Generic rekey context for connections */
typedef struct {
  /* Current sending encryption key, provided for re-key. The `pfs'
     is TRUE if the Perfect Forward Secrecy is performed in re-key. */
  unsigned char *send_enc_key;
  uint32 enc_key_len;
  int ske_group;
  bool pfs;
  uint32 timeout;
  void *context;
} *SilcClientRekey;

/* Connection structure used in client to associate all the important
   connection specific data to this structure. */
struct SilcClientConnectionStruct {
  /*
   * Local data 
   */
  char *nickname;

  /* Local client ID for this connection */
  SilcClientID *local_id;

  /* Decoded local ID so that the above defined ID would not have
     to be decoded for every packet. */
  unsigned char *local_id_data;
  uint32 local_id_data_len;

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
  uint32 remote_id_data_len;

  /*
   * Common data 
   */
  /* Keys and stuff negotiated in the SKE protocol */
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcHmac hmac_send;
  SilcHmac hmac_receive;
  SilcHash hash;

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

  /* Pending command queue for this connection */
  SilcDList pending_commands;

  /* Current command identifier, 0 not used */
  uint16 cmd_ident;

  /* Requested pings. */
  SilcClientPing *ping;
  uint32 ping_count;

  /* Set away message */
  SilcClientAway *away;

  /* Re-key context */
  SilcClientRekey rekey;

  /* Pointer back to the SilcClient. This object is passed to the application
     and the actual client object is accesible through this pointer. */
  SilcClient client;

  /* User data context. Library does not touch this. */
  void *context;
};

/* Main client structure. */
struct SilcClientStruct {
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

  /* Client Parameters */
  SilcClientParams *params;

  /* SILC client scheduler and task queues */
  SilcSchedule schedule;
  SilcTaskQueue io_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;

  /* Table of connections in client. All the connection data is saved here. */
  SilcClientConnection *conns;
  uint32 conns_count;

  /* Table of listenning sockets in client.  Client can have listeners
     (like key agreement protocol server) and those sockets are saved here.
     This table is checked always if the connection object cannot be found
     from the `conns' table. */
  SilcSocketConnection *sockets;
  uint32 sockets_count;

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

  /* Client version. Used to compare to remote host's version strings. */
  char *silc_client_version;
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

#define SILC_CLIENT_SET_CONNECTION_FOR_INPUT(s, fd)			\
do {									\
  silc_schedule_set_listen_fd((s), (fd), (1L << SILC_TASK_READ));	\
} while(0)
     
#define SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(s, fd)			\
do {									\
  silc_schedule_set_listen_fd((s), (fd), ((1L << SILC_TASK_READ) |	\
				     (1L << SILC_TASK_WRITE)));		\
} while(0)

/* Finds socket connection object by file descriptor */
#define SILC_CLIENT_GET_SOCK(__x, __fd, __sock)		\
do {							\
  int __i;						\
							\
  for (__i = 0; __i < (__x)->conns_count; __i++)	\
    if ((__x)->conns[__i] &&				\
	(__x)->conns[__i]->sock->sock == (__fd))	\
      break;						\
							\
  if (__i >= (__x)->conns_count) {			\
    (__sock) = NULL;					\
    for (__i = 0; __i < (__x)->sockets_count; __i++)	\
      if ((__x)->sockets[__i] &&			\
	  (__x)->sockets[__i]->sock == (__fd))		\
        (__sock) = (__x)->sockets[__i];			\
  } else						\
    (__sock) = (__x)->conns[__i]->sock;			\
} while(0)

/* Check whether rekey protocol is active */
#define SILC_CLIENT_IS_REKEY(sock)					\
  (sock->protocol && sock->protocol->protocol && 			\
   sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)

/* Prototypes (some of the prototypes are defined in the silcapi.h) */

void silc_client_packet_send(SilcClient client, 
			     SilcSocketConnection sock,
			     SilcPacketType type, 
			     void *dst_id,
			     SilcIdType dst_id_type,
			     SilcCipher cipher,
			     SilcHmac hmac,
			     unsigned char *data, 
			     uint32 data_len, 
			     int force_send);
void silc_client_disconnected_by_server(SilcClient client,
					SilcSocketConnection sock,
					SilcBuffer message);
void silc_client_error_by_server(SilcClient client,
				 SilcSocketConnection sock,
				 SilcBuffer message);
void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				SilcIDPayload idp);
SilcChannelEntry silc_client_new_channel_id(SilcClient client,
					    SilcSocketConnection sock,
					    char *channel_name,
					    uint32 mode, 
					    SilcIDPayload idp);
void silc_client_save_channel_key(SilcClientConnection conn,
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
				       SilcClientEntry new);
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

#endif
