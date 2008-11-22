/*

  server_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

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
  /* More to add
  SilcUInt32 secret_channels;
  SilcUInt32 private_channels;
  */

  /* General */
  SilcUInt32 conn_attempts;		  /* Connection attempts */
  SilcUInt32 conn_failures;		  /* Connection failure */
  SilcUInt32 auth_attempts;		  /* Authentication attempts */
  SilcUInt32 auth_failures;		  /* Authentication failures */
  SilcUInt32 packets_sent;		  /* Sent SILC packets */
  SilcUInt32 packets_received;		  /* Received SILC packets */
  SilcUInt32 conn_num;			  /* Number of connections */
  SilcUInt32 commands_sent;	          /* Commands/replies sent */
  SilcUInt32 commands_received;	          /* Commands/replies received */
} SilcServerStatistics;

/*
   SILC Server Object.

*/
struct SilcServerStruct {
  SilcSchedule schedule;	     /* Server scheduler */
  SilcDList listeners;		     /* TCP listeners */
  SilcPacketEngine packet_engine;    /* Packet engine */
  SilcDList conns;		     /* Connections in server */
  SilcSKR repository;		     /* Public key repository */
  SilcPublicKey public_key;	     /* Server public key */
  SilcPrivateKey private_key;	     /* Server private key */
  SilcDList expired_clients;	     /* Expired client entries */
  SilcHttpServer httpd;		     /* HTTP server */

  char *server_name;		     /* Server's name */
  SilcServerEntry id_entry;	     /* Server's local entry */
  SilcServerID *id;		     /* Server's ID */
  unsigned char id_string[32];	     /* Server's ID as string */
  SilcUInt32 id_string_len;
  SilcUInt32 starttime;		     /* Server start time */

  SilcServerEntry router;	     /* Pointer to the primary router */
  unsigned long router_connect;	     /* Time when router was connected */
  SilcServerConnection router_conn;  /* non-NULL when connecting to the
					primary router, and NULL otherwise. */
  SilcServerBackup backup;	     /* Backup routers */

  /* Current command identifier, 0 not used */
  SilcUInt16 cmd_ident;

  /* ID lists. */
  SilcIDList local_list;
  SilcIDList global_list;
  SilcHashTable watcher_list;
  SilcHashTable watcher_list_pk;

  /* Hash objects for general hashing */
  SilcHash md5hash;
  SilcHash sha1hash;

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

  unsigned int server_type    : 2;   /* Server type (server.h) */
  unsigned int standalone     : 1;   /* Set if server is standalone, and
					does not have connection to network. */
  unsigned int listenning     : 1;   /* Set if server is listenning for
					incoming connections. */
  unsigned int background     : 1;   /* Set when server is on background */
  unsigned int backup_router  : 1;   /* Set if this is backup router */
  unsigned int backup_primary : 1;   /* Set if we've switched our primary
				        router to a backup router. */
  unsigned int backup_noswitch: 1;   /* Set if we've won't switch to
					become primary (we are backup) */
  unsigned int backup_closed  : 1;   /* Set if backup closed connection.
					Do not allow resuming in this case. */
  unsigned int wait_backup    : 1;   /* Set if we are waiting for backup
				        router to connect to us. */
  unsigned int server_shutdown: 1;   /* Set when shutting down */
  unsigned int no_reconnect   : 1;   /* If set, server won't reconnect to
					router after disconnection. */
  unsigned int no_conf        : 1;   /* Set when connecting without
					configuration. */
};

/* Failure context. This is allocated when failure packet is received.
   Failure packets are processed with timeout and data is saved in this
   structure. */
typedef struct {
  SilcPacketStream sock;
  SilcUInt32 failure;
} *SilcServerFailureContext;

/* Rekey must be performed at the lastest when this many packets is sent */
#define SILC_SERVER_REKEY_THRESHOLD 0xfffffe00

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

#define SILC_SET_CONNECTION_FOR_INPUT(s, fd)				\
do {									\
  silc_schedule_set_listen_fd((s), (fd), SILC_TASK_READ, FALSE);	\
} while(0)

#define SILC_SET_CONNECTION_FOR_OUTPUT(s, fd)				     \
do {									     \
  silc_schedule_set_listen_fd((s), (fd), (SILC_TASK_READ | SILC_TASK_WRITE), \
			      FALSE);					     \
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
      (p) |= SILC_SKE_SP_FLAG_PFS;			\
    if (!(x)->publickeys)				\
      (p) |= SILC_SKE_SP_FLAG_MUTUAL;			\
  }

#define SILC_CONNTYPE_STRING(ctype)			\
  (ctype == SILC_CONN_CLIENT ? "Client" :		\
   ctype == SILC_CONN_SERVER ? "Server" :		\
   ctype == SILC_CONN_ROUTER ? "Router" : "Unknown")

/* Prototypes */
SILC_TASK_CALLBACK(silc_server_rekey_final);
SILC_TASK_CALLBACK(silc_server_rekey_callback);
SILC_TASK_CALLBACK(silc_server_connect_to_router);
SILC_TASK_CALLBACK(silc_server_connect_to_router_retry);
void silc_server_watcher_list_destroy(void *key, void *context,
				      void *user_context);

#endif
