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

/* 
   SILC Server Object.

*/
struct SilcServerStruct {
  char *server_name;
  int server_type;
  int sock;
  SilcServerID *id;
  unsigned char *id_string;
  uint32 id_string_len;
  SilcIdType id_type;

  bool standalone;		     /* TRUE if server is standalone, and
					does not have connection to network. */
  bool listenning;		     /* TRUE if server is listenning for
					incoming connections. */
  SilcServerEntry id_entry;	     /* Server's own ID entry */
  SilcServerEntry router;	     /* Pointer to the primary router */
  unsigned long router_connect;	     /* Time when router was connected */
  SilcServerBackup backup;	     /* Backup routers */
  bool backup_router;		     /* TRUE if this is backup router */
  bool backup_primary;		     /* TRUE if we've switched our primary
				        router to a backup router. */
  SilcServerConnection router_conn; /* non-NULL when connecting to the
				       primary router, and NULL otherwise. */

  /* Current command identifier, 0 not used */
  uint16 cmd_ident;

  /* SILC server scheduler */
  SilcSchedule schedule;

  /* ID lists. */
  SilcIDList local_list;
  SilcIDList global_list;

  /* Table of connected sockets */
  SilcSocketConnection *sockets;

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

/* Macros */

/* Registers generic task for file descriptor for reading from network and
   writing to network. As being generic task the actual task is allocated 
   only once and after that the same task applies to all registered fd's. */
#define SILC_REGISTER_CONNECTION_FOR_IO(fd)		\
do {							\
  silc_schedule_task_add(server->schedule, (fd),	\
		         silc_server_packet_process,	\
		         context, 0, 0,			\
		         SILC_TASK_GENERIC,		\
			 SILC_TASK_PRI_NORMAL);		\
} while(0)

#define SILC_SET_CONNECTION_FOR_INPUT(s, fd)			\
do {								\
  silc_schedule_set_listen_fd((s), (fd), SILC_TASK_READ);	\
} while(0)
     
#define SILC_SET_CONNECTION_FOR_OUTPUT(s, fd)				      \
do {									      \
  silc_schedule_set_listen_fd((s), (fd), (SILC_TASK_READ | SILC_TASK_WRITE)); \
} while(0)

#define SILC_OPER_STATS_UPDATE(c, type, mod)	\
do {						\
  if ((c)->mode & (mod)) {			\
    if ((c)->connection)			\
      server->stat.my_ ## type ## _ops--;	\
    if (server->server_type == SILC_ROUTER)	\
      server->stat. type ## _ops--;		\
  }						\
} while(0)

/* Prototypes */
SILC_TASK_CALLBACK_GLOBAL(silc_server_rekey_final);

#endif
