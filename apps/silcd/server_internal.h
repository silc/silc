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
typedef struct {
  /* Local stats (server and router) */
  unsigned long my_clients;	  /* Locally connected clients */
  unsigned long my_servers;	  /* Locally connected servers */
  unsigned long my_routers;	  /* Locally connected routers */
  unsigned long my_channels;	  /* Locally created channels */
  unsigned long my_chanclients;	  /* Local clients on local channels */
  unsigned long my_aways;	  /* Local clients away (XXX) */
  unsigned long my_server_ops;	  /* Local server operators */
  unsigned long my_router_ops;	  /* Local router operators */

  /* Global stats (mainly for router) */
  unsigned long cell_clients;	  /* All clients in cell */
  unsigned long cell_servers;	  /* All servers in cell */
  unsigned long cell_channels;	  /* All channels in cell */
  unsigned long cell_chanclients; /* All clients on cell's channels */
  unsigned long clients;	  /* All clients */
  unsigned long servers;	  /* All servers */
  unsigned long routers;	  /* All routers */
  unsigned long channels;	  /* All channels */
  unsigned long chanclients;	  /* All clients on channels */
  unsigned long server_ops;	  /* All server operators */
  unsigned long router_ops;	  /* All router operators */

  /* General */
  unsigned long conn_attempts;	  /* Connection attempts */
  unsigned long conn_failures;	  /* Connection failure */
  unsigned long auth_attempts;	  /* Authentication attempts */
  unsigned long auth_failures;	  /* Authentication failures */
  unsigned long packets_sent;	  /* Sent packets */
  unsigned long packets_received; /* Received packets */
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
  unsigned char *id_string;
  unsigned int id_string_len;
  SilcIdType id_type;

  /* Server's own ID entry. */
  SilcServerEntry id_entry;

  /* Back pointer to the primary router of this server. */
  SilcServerEntry router;

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
  SilcServerStatistics stat;

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
