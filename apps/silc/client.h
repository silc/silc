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

/* Forward declaration for client window */
typedef struct SilcClientWindowObject *SilcClientWindow;

#include "idlist.h"

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

/* Window structure used in client to associate all the important
   connection (window) specific data to this structure. How the window
   actually appears on the screen in handeled by the silc_screen*
   routines in screen.c. */
struct SilcClientWindowObject {
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

  /* Remote client ID for this connection */
  SilcClientID *remote_id;

  /* Remote local ID so that the above defined ID would not have
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

  /* Current channel on window. All channel's are saved (allocated) into
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

  /* The actual physical screen. This data is handled by the
     screen handling routines. */
  void *screen;
};

struct SilcClientObject {
  char *username;
  char *realname;

  /* Private and public key */
  SilcPKCS pkcs;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;

  /* SILC client task queues */
  SilcTaskQueue io_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;

  /* Input buffer that holds the characters user types. This is
     used only to store the typed chars for a while. */
  SilcBuffer input_buffer;

  /* Table of windows in client. All the data, including connection
     specific data, is saved in here. */
  SilcClientWindow *windows;
  unsigned int windows_count;

  /* Currently active window. This is pointer to the window table 
     defined above. This must never be free'd directly. */
  SilcClientWindow current_win;

  /* The SILC client screen object */
  SilcScreen screen;

  /* Generic cipher and hash objects */
  SilcCipher none_cipher;
  SilcHash md5hash;
  SilcHash sha1hash;
  SilcHmac md5hmac;
  SilcHmac sha1hmac;

  /* Configuration object */
  SilcClientConfig config;

  /* Random Number Generator */
  SilcRng rng;

#ifdef SILC_SIM
  /* SIM (SILC Module) table */
  SilcSimContext **sim;
  unsigned int sim_count;
#endif
};

/* Macros */

#ifndef CTRL
#define CTRL(x) ((x) & 0x1f)	/* Ctrl+x */
#endif

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
  for (__i = 0; __i < (__x)->windows_count; __i++)	\
    if ((__x)->windows[__i]->sock->sock == (__fd))	\
      break;						\
							\
  if (__i >= (__x)->windows_count)			\
    (__sock) = NULL;					\
 (__sock) = (__x)->windows[__i]->sock;			\
} while(0)

/* Returns TRUE if windows is currently active window */
#define SILC_CLIENT_IS_CURRENT_WIN(__x, __win) ((__x)->current_win == (__win))

/* Prototypes */
int silc_client_alloc(SilcClient *new_client);
void silc_client_free(SilcClient client);
int silc_client_init(SilcClient client);
void silc_client_stop(SilcClient client);
void silc_client_run(SilcClient client);
void silc_client_parse_command_line(unsigned char *buffer, 
				    unsigned char ***parsed,
				    unsigned int **parsed_lens,
				    unsigned int **parsed_types,
				    unsigned int *parsed_num,
				    unsigned int max_args);
int silc_client_connect_to_server(SilcClient client, int port,
				  char *host);
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
				  SilcBuffer message);
void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				unsigned char *id_string);
void silc_client_new_channel_id(SilcClient client,
				SilcSocketConnection sock,
				char *channel_name,
				unsigned int mode,
				unsigned char *id_string);
void silc_client_receive_channel_key(SilcClient client,
				     SilcSocketConnection sock,
				     SilcBuffer packet);
void silc_client_channel_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet);
#endif
