/*

  server_internal.h

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

#ifndef SERVER_INTERNAL_H
#define SERVER_INTERNAL_H

/* Server statistics structure. This holds various statistics about
   various things. */
/* XXX TODO */
typedef struct {

} SilcServerStatistics;

typedef struct {
  void *id_entry;
  SilcSocketConnection sock;

  /* Remote host name and port */
  char *remote_host;
  int remote_port;
  
  /* Current connection retry info */
  unsigned int retry_count;
  unsigned int retry_timeout;

  /* Back pointer to server */
  SilcServer server;
} *SilcServerConnection;

/* 
   SILC Server Object.

*/
struct SilcServerStruct {
  char *server_name;
  int server_type;
  int sock;
  int standalone;
  int listenning;
  SilcServerID *id;
  SilcIdType id_type;
  SilcServerEntry id_entry;

  /* SILC server task queues */
  SilcTaskQueue io_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;

  /* ID lists. */
  SilcIDList local_list;
  SilcIDList global_list;

  /* Table of connected sockets */
  SilcSocketConnection *sockets;

  /* Server keys */
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcCipher none_cipher;

  /* Server public key */
  SilcPKCS pkcs;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;

  /* Hash objects for general hashing */
  SilcHash md5hash;
  SilcHash sha1hash;

  /* HMAC objects for MAC's. */
  SilcHmac md5hmac;
  SilcHmac sha1hmac;

  /* Configuration object */
  SilcConfigServer config;

  /* Random pool */
  SilcRng rng;

  /* Server statistics */
  SilcServerStatistics stats;

  /* Pending command queue */
  SilcDList pending_commands;

  /* Default parameteres for server */
  SilcServerParams params;

#ifdef SILC_SIM
  /* SIM (SILC Module) list */
  SilcDList sim;
#endif
};

/* Macros */

/* Registers generic task for file descriptor for reading from network and
   writing to network. As being generic task the actual task is allocated 
   only once and after that the same task applies to all registered fd's. */
#define SILC_REGISTER_CONNECTION_FOR_IO(fd)				\
do {									\
  SilcTask tmptask = silc_task_register(server->generic_queue, (fd),	\
					silc_server_packet_process,	\
					context, 0, 0, 			\
					SILC_TASK_GENERIC,		\
					SILC_TASK_PRI_NORMAL);		\
  silc_task_set_iotype(tmptask, SILC_TASK_WRITE);			\
} while(0)

#define SILC_SET_CONNECTION_FOR_INPUT(fd)				\
do {									\
  silc_schedule_set_listen_fd((fd), (1L << SILC_TASK_READ));            \
} while(0)
     
#define SILC_SET_CONNECTION_FOR_OUTPUT(fd)				\
do {									\
  silc_schedule_set_listen_fd((fd), ((1L << SILC_TASK_READ) |           \
				     (1L << SILC_TASK_WRITE)));         \
} while(0)

/* Prototypes */

#endif
