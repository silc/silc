/*

  server_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

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
  SilcUInt32 my_clients;	          /* Locally connected clients */
  SilcUInt32 my_servers;		  /* Locally connected servers */
  SilcUInt32 my_routers;		  /* Locally connected routers */
  SilcUInt32 my_channels;		  /* Locally created channels */
  SilcUInt32 my_chanclients;	          /* Local clients on local channels */
  SilcUInt32 my_aways;			  /* Local clients away (gone) */
  SilcUInt32 my_detached;		  /* Local clients detached */
  SilcUInt32 my_server_ops;		  /* Local server operators */
  SilcUInt32 my_router_ops;		  /* Local router operators */

  /* Global stats (mainly for router) */
  SilcUInt32 cell_clients;		  /* All clients in cell */
  SilcUInt32 cell_servers;		  /* All servers in cell */
  SilcUInt32 cell_channels;		  /* All channels in cell */
  SilcUInt32 cell_chanclients;		  /* All clients on cell's channels */
  SilcUInt32 clients;			  /* All clients */
  SilcUInt32 servers;			  /* All servers */
  SilcUInt32 routers;			  /* All routers */
  SilcUInt32 channels;			  /* All channels */
  SilcUInt32 chanclients;		  /* All clients on channels */
  SilcUInt32 aways;			  /* All clients away (gone) */
  SilcUInt32 detached;		          /* All clients detached */
  SilcUInt32 server_ops;		  /* All server operators */
  SilcUInt32 router_ops;		  /* All router operators */

  /* General */
  SilcUInt32 conn_attempts;		  /* Connection attempts */
  SilcUInt32 conn_failures;		  /* Connection failure */
  SilcUInt32 auth_attempts;		  /* Authentication attempts */
  SilcUInt32 auth_failures;		  /* Authentication failures */
  SilcUInt32 packets_sent;		  /* Sent SILC packets */
  SilcUInt32 packets_received;		  /* Received SILC packets */
} SilcServerStatistics;

/*
   SILC Server Object.

*/
struct SilcServerStruct {
  char *server_name;
  int sock;
  SilcServerEntry id_entry;
  SilcServerID *id;
  unsigned char *id_string;
  SilcUInt32 id_string_len;
  SilcUInt32 starttime;

  unsigned int server_type    : 2;   /* Server type (server.h) */
  unsigned int standalone     : 1;   /* Set if server is standalone, and
					does not have connection to network. */
  unsigned int listenning     : 1;   /* Set if server is listenning for
					incoming connections. */
  unsigned int background     : 1;   /* Set when server is on background */
  unsigned int backup_router  : 1;   /* Set if this is backup router */
  unsigned int backup_primary : 1;   /* Set if we've switched our primary
				        router to a backup router. */
  unsigned int wait_backup    : 1;   /* Set if we are waiting for backup
				        router to connect to us. */

  SilcServerEntry router;	     /* Pointer to the primary router */
  unsigned long router_connect;	     /* Time when router was connected */
  SilcServerConnection router_conn;  /* non-NULL when connecting to the
					primary router, and NULL otherwise. */
  SilcServerBackup backup;	     /* Backup routers */

  /* Current command identifier, 0 not used */
  SilcUInt16 cmd_ident;

  /* SILC server scheduler */
  SilcSchedule schedule;

  /* ID lists. */
  SilcIDList local_list;
  SilcIDList global_list;
  SilcHashTable watcher_list;

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
  SilcServerConfigRef config_ref;
  char *config_file;

  /* Random pool */
  SilcRng rng;

  /* Server statistics */
  SilcServerStatistics stat;

  /* Pending command queue */
  SilcDList pending_commands;

  /* Purge context for disconnected clients */
  SilcIDListPurge purge_i;
  SilcIDListPurge purge_g;

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
  SilcUInt32 failure;
} *SilcServerFailureContext;

/* Macros */

/* Return pointer to the primary router connection */
#define SILC_PRIMARY_ROUTE(server) \
  (!server->standalone && server->router ? server->router->connection : NULL)

/* Return TRUE if a packet must be broadcasted (router broadcasts) */
#define SILC_BROADCAST(server) (server->server_type == SILC_ROUTER) 

/* Return TRUE if entry is locally connected or local to us */
#define SILC_IS_LOCAL(entry) \
  (((SilcIDListData)entry)->status & SILC_IDLIST_STATUS_LOCAL)

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
    if (SILC_IS_LOCAL((c)))     		\
      server->stat.my_ ## type ## _ops--;	\
    if (server->server_type == SILC_ROUTER)	\
      server->stat. type ## _ops--;		\
    (c)->mode &= ~(mod);			\
  }						\
} while(0)

#define SILC_UMODE_STATS_UPDATE(oper, mod)	\
do {						\
    if (client->mode & (mod)) {			\
      if (!(mode & (mod))) {			\
	if (SILC_IS_LOCAL(client))      	\
	  server->stat.my_ ## oper ## _ops--;	\
        if (server->server_type == SILC_ROUTER)	\
	  server->stat. oper ## _ops--;		\
      }						\
    } else {					\
      if (mode & (mod)) {			\
	if (SILC_IS_LOCAL(client))      	\
	  server->stat.my_ ## oper ## _ops++;	\
        if (server->server_type == SILC_ROUTER)	\
	  server->stat. oper ## _ops++;		\
      }						\
    }						\
} while(0)

#define SILC_GET_SKE_FLAGS(x, p)			\
  if ((x)) {						\
    if ((x)->param && (x)->param->key_exchange_pfs)	\
      (p)->flags |= SILC_SKE_SP_FLAG_PFS;		\
    if (!(x)->publickeys)				\
      (p)->flags |= SILC_SKE_SP_FLAG_MUTUAL;		\
  }

/* Prototypes */
SILC_TASK_CALLBACK_GLOBAL(silc_server_rekey_final);
void silc_server_watcher_list_destroy(void *key, void *context,
				      void *user_context);

#endif
