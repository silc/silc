/*

  server_internal.h

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

#ifndef SERVER_INTERNAL_H
#define SERVER_INTERNAL_H

/* Server statistics structure. This holds various statistics about
   various things. */
typedef struct {
  /* Local stats (server and router) */
  uint32 my_clients;	          /* Locally connected clients */
  uint32 my_servers;		  /* Locally connected servers */
  uint32 my_routers;		  /* Locally connected routers */
  uint32 my_channels;		  /* Locally created channels */
  uint32 my_chanclients;	  /* Local clients on local channels */
  uint32 my_aways;		  /* Local clients away (XXX) */
  uint32 my_server_ops;		  /* Local server operators */
  uint32 my_router_ops;		  /* Local router operators */

  /* Global stats (mainly for router) */
  uint32 cell_clients;		  /* All clients in cell */
  uint32 cell_servers;		  /* All servers in cell */
  uint32 cell_channels;		  /* All channels in cell */
  uint32 cell_chanclients;	  /* All clients on cell's channels */
  uint32 clients;		  /* All clients */
  uint32 servers;		  /* All servers */
  uint32 routers;		  /* All routers */
  uint32 channels;		  /* All channels */
  uint32 chanclients;		  /* All clients on channels */
  uint32 server_ops;		  /* All server operators */
  uint32 router_ops;		  /* All router operators */

  /* General */
  uint32 conn_attempts;		  /* Connection attempts */
  uint32 conn_failures;		  /* Connection failure */
  uint32 auth_attempts;		  /* Authentication attempts */
  uint32 auth_failures;		  /* Authentication failures */
  uint32 packets_sent;		  /* Sent packets */
  uint32 packets_received;	  /* Received packets */
} SilcServerStatistics;

typedef struct {
  SilcSocketConnection sock;

  /* Remote host name and port */
  char *remote_host;
  int remote_port;
  
  /* Current connection retry info */
  uint32 retry_count;
  uint32 retry_timeout;

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
  uint32 id_string_len;
  SilcIdType id_type;

  /* Current command identifier, 0 not used */
  uint16 cmd_ident;

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
  SilcServerConfig config;

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

/* Server's heartbeat context */
typedef struct {
  SilcServer server;
} *SilcServerHBContext;

/* Failure context. This is allocated when failure packet is received.
   Failure packets are processed with timeout and data is saved in this
   structure. */
typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  uint32 failure;
} *SilcServerFailureContext;

/* Session key's re-key context. */
typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  uint32 timeout;
} *SilcServerRekeyContext;

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
SILC_TASK_CALLBACK_GLOBAL(silc_server_rekey_final);

#endif
