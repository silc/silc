/*

  server_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

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

#include "server_st_accept.h"
#include "server_st_connect.h"
#include "server_st_notify.h"
#include "server_st_query.h"
#include "server_st_command.h"
#include "server_st_command_reply.h"
#include "server_st_packet.h"

/* SILC port */
#define SILC_PORT 706

/* Server type */
typedef enum {
  SILC_SERVER         = 0,
  SILC_ROUTER         = 1,
  SILC_BACKUP_ROUTER  = 2
} SilcServerType;

/* Forward declarations */
typedef struct SilcServerEntryStruct *SilcServerEntry;
typedef struct SilcClientEntryStruct *SilcClientEntry;
typedef struct SilcChannelEntryStruct *SilcChannelEntry;
typedef struct SilcServerCommandStruct *SilcServerCommand;
typedef struct SilcServerThreadStruct *SilcServerThread;

/* Pending command context */
typedef struct {
  SilcFSMSemaStruct wait_reply;	        /* Pending command signaller */
  SilcServerCommand reply;		/* Command reply context */
  SilcUInt16 cmd_ident;			/* Command identifier */
  SilcInt16 refcnt;			/* Reference counter */
} *SilcServerPending;

/* Command state context.  This is used with both commands and command
   replies.  When command or command reply is executed its state is saved
   here while processing. */
struct SilcServerCommandStruct {
  struct SilcServerCommandStruct *next;
  SilcServerThread thread;		/* Server thread */
  SilcPacket packet;			/* Command packet */
  SilcCommandPayload payload;		/* Command payload */
  SilcServerPending pending;		/* Pending command context */
};

/* Entry data header.  Client and server entries has this as their first
   field. */
typedef struct {
  SilcConnectionType type;	     /* Connection type */
  SilcSKE ske;			     /* Key exchange protocol, for rekey */
  SilcHash hash;		     /* Hash selected in SKE protocol */
  SilcPublicKey public_key;	     /* Public key */
  unsigned char fingerprint[20];     /* SHA-1 fingerprint */

  long last_receive;		     /* Time last received data */
  long last_sent;		     /* Time last sent data */

  unsigned long created;	     /* Time when entry was created */

  SilcUInt32 refcnt;		     /* Reference counter */

  /* Flags */
  unsigned int registered     : 1;   /* Set if registered to network */
  unsigned int local          : 1;   /* Set if locally connected entry */
  unsigned int resolving      : 1;   /* Set if entry data being resolved */
  unsigned int resolved       : 1;   /* Set if entry data resolved */
  unsigned int disabled       : 1;   /* Set if entry is disabled */
  unsigned int resumed        : 1;   /* Set if entry resumed */
  unsigned int resume_res     : 1;   /* Set if resolved while resuming */
  unsigned int noattr         : 1;   /* Set if entry does not support
					user attributes in WHOIS */
} *SilcEntryData, SilcEntryDataStruct;

/* Server entry */
struct SilcServerEntryStruct {
  SilcEntryDataStruct data;	     /* Entry data header */
  SilcServerID id;		     /* Server ID */
  char *server_name;		     /* Server name */
  char *server_info;		     /* Server info */
  char *motd;			     /* Message of the day */
  SilcPacketStream stream;	     /* Connection to entry/origin of entry */
  SilcUInt8 server_type;	     /* Server type */
};

/* Client's joined channel entry */
typedef struct SilcChannelClientEntryStruct {
  SilcClientEntry client;	     /* Client on channel */
  SilcChannelEntry channel;	     /* Joined channel */
  SilcUInt32 mode;		     /* Client's mode on channel */
} *SilcChannelClientEntry;

/* Client entry */
struct SilcClientEntryStruct {
  SilcEntryDataStruct data;	     /* Entry data header */
  SilcClientID id;		     /* Client ID */
  unsigned char *nickname;	     /* Client's nickname (not normalized) */
  char *servername;		     /* Client's server's name */
  char *username;		     /* Client's username */
  char *userinfo;		     /* Client's user info */
  SilcUInt32 mode;		     /* Client's mode in the network */
  unsigned char *attrs;		     /* User attributes */
  SilcUInt16 attrs_len;		     /* Attributes data length */
  SilcHashTable channels;	     /* Joined channels */
  SilcPacketStream stream;	     /* Connection to entry/origin of entry */

  long last_command;
  SilcUInt8 fast_command;
  unsigned long updated;

  /* data.status is RESOLVING and this includes the resolving command
     reply identifier. */
  SilcUInt16 resolve_cmd_ident;

  /* we need this so nobody can resume more than once at the same time -
   * server crashes, really odd behaviour, ... */
  SilcClientEntry resuming_client;
};

/* Channel entry */
struct SilcChannelEntryStruct {
  SilcChannelID id;		     /* Channel ID */
  char *channel_name;		     /* Channel name */
  SilcUInt32 mode;		     /* Channel's mode */
  SilcPacketStream router;	     /* Channel's owner */

  unsigned char *passphrase;	     /* Channel's passphrase */
  SilcHashTable channel_pubkeys;     /* Channel authentication public keys */
  SilcPublicKey founder_key;	     /* Channel founder's public key */

  char *topic;			     /* Current topic */
  char *cipher;			     /* User set cipher */
  char *hmac_name;		     /* User set HMAC */
  SilcUInt32 user_limit;	     /* Maximum user limit */
  SilcHashTable invite_list;	     /* Invited list */
  SilcHashTable ban_list;	     /* Ban list */
  SilcHashTable user_list;	     /* Joined users */

  SilcCipher channel_key;	     /* Current channel key */
  unsigned char *key;		     /* Current channel key data */
  SilcUInt32 key_len;		     /* Channel key data length */
  SilcHmac hmac;		     /* Current HMAC */
  SilcUInt32 refcnt;		     /* Reference counter */

  //  SilcServerChannelRekey rekey;
  unsigned long created;
  unsigned long updated;

  /* Flags */
  unsigned int global_users : 1;
  unsigned int disabled : 1;
  unsigned int users_resolved : 1;
};

/* Internal context for accepting new connection */
typedef struct SilcServerAcceptStruct {
  SilcEntryDataStruct data;
  SilcServerThread thread;
  SilcFSMThread t;		     /* Thread for accepting connection */
  SilcStream stream;		     /* Remote connection */
  SilcPacketStream packet_stream;    /* Remote connection */
  SilcConnAuth connauth;	     /* Connection authentication context */
  SilcFSMSemaStruct wait_register;   /* Signaller when registering received */
  SilcPacket register_packet;	     /* NEW_CLIENT/NEW_SERVER packet */

  SilcServerParamClient cconfig;
  SilcServerParamServer sconfig;
  SilcServerParamRouter rconfig;
  SilcSKEStatus status;
  SilcSKESecurityProperties prop;
  SilcSKEKeyMaterial keymat;
  SilcSKERekeyMaterial rekey;
  SilcAsyncOperation op;
  const char *hostname;
  const char *ip;
  SilcUInt16 port;
  SilcStatus error;
  char *error_string;
  SilcBool auth_success;
  SilcConnectionType conn_type;
  SilcHash hash;
  struct SilcServerAcceptStruct *next;
} *SilcServerAccept;

/* Server statistics structure. */
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

/* Server thread context */
struct SilcServerThreadStruct {
  struct SilcServerThreadStruct *next;
  SilcServer server;		     /* Pointer to server */
  SilcStack stack;		     /* Data stack for fast allocations */
  SilcPacketEngine packet_engine;    /* Packet engine */
  SilcFSMThreadStruct thread;	     /* FSM thread */
  SilcFSMStruct fsm;		     /* Thread's FSM */
  SilcFSMSemaStruct wait_event;	     /* Thread's event signaller */
  SilcUInt32 num_conns;		     /* Number of connections in the thread */
  SilcList new_conns;		     /* New network connections */
  SilcList packet_queue;	     /* Incoming packet queue */

  /* Events */
  unsigned int new_connection  : 1;  /* New connection received */
  unsigned int new_packet      : 1;  /* New packet in packet queue */
};

/* Server context. */
struct SilcServerStruct {
  char *server_name;		     /* Server name */
  SilcServerEntry server_entry;	     /* Server entry */
  SilcServerID id;		     /* Server ID */
  SilcUInt32 starttime;

  SilcFSMStruct fsm;		     /* Server FSM */
  SilcSchedule schedule;	     /* Scheduler */
  SilcMutex lock;		     /* Server lock */
  SilcRng rng;			     /* Random number generator */
  SilcServerParams params;	     /* Server parameters */
  SilcDList listeners;		     /* Network listeners */
  SilcList threads;		     /* Server worker threads */
  SilcList new_conns;		     /* New network connections */
  SilcList command_pool;	     /* Command context freelist */
  SilcHashTable pending_commands;    /* Pending commands */

  SilcFSMSemaStruct wait_event;	     /* Main state signaller */
  SilcFSMSemaStruct thread_up;	     /* Signaller when thread is up */

  SilcIDCache clients;		     /* Client entry cache */
  SilcIDCache servers;		     /* Server entry cache */
  SilcIDCache channels;		     /* Channel entry cache */

  SilcSKR repository;		     /* Public key/certificate repository */
  SilcHashTable watcher_list;	     /* Watcher list, nickname */
  SilcHashTable watcher_list_pk;     /* Watcher list, public keys */

  void *app_context;		     /* Application specific context */

  char *config_file;

  /* Events */
  unsigned int new_connection  : 1;  /* New connection received */
  unsigned int connect_router  : 1;  /* Connect to configured routers */
  unsigned int get_statistics  : 1;  /* Get statistics */
  unsigned int reconfigure     : 1;  /* Reconfigure server */
  unsigned int server_shutdown : 1;  /* Shutdown server */
  unsigned int run_callback    : 1;  /* Call running callback */

  /* Flags */
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
  unsigned int no_reconnect   : 1;   /* If set, server won't reconnect to
					router after disconnection. */

  SilcPacketStream router;	     /* Pointer to the primary router */

  /* Current command identifier, 0 not used */
  SilcUInt16 cmd_ident;

  /* Server public key */
  SilcPKCS pkcs;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;

  /* Hash objects for general hashing */
  SilcHash md5hash;
  SilcHash sha1hash;

  /* Server statistics */
  SilcServerStatistics stat;

#ifdef SILC_SIM
  /* SIM (SILC Module) list */
  SilcDList sim;
#endif

  /* Application callbacks */
  SilcServerRunning running;	     /* Called to indicate server is up */
  SilcServerStop stopped;	     /* Called to indicate server is down */
  void *running_context;
  void *stop_context;
};

/* Rekey must be performed at the lastest when this many packets is sent */
#define SILC_SERVER_REKEY_THRESHOLD 0xfffffe00

/* Macros */

/* Return pointer to the primary router connection */
#define SILC_PRIMARY_ROUTE(server) server->router

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
      (p) |= SILC_SKE_SP_FLAG_PFS;		\
    if (!(x)->publickeys)				\
      (p) |= SILC_SKE_SP_FLAG_MUTUAL;		\
  }

#define SILC_CONNTYPE_STRING(ctype) \
 (ctype == SILC_CONN_CLIENT ? "Client" : \
  ctype == SILC_CONN_SERVER ? "Server" : "Router")

/* This macro is used to send notify messages with formatted string. The
   string is formatted with arguments and the formatted string is sent as
   argument. */
#define SILC_SERVER_SEND_NOTIFY(server, stream, type, fmt)	\
do {								\
  char *__fmt__ = silc_format fmt;				\
  if (__fmt__)						       	\
    silc_server_send_notify(server, stream, FALSE,     		\
			    type, 1, __fmt__, strlen(__fmt__));	\
  silc_free(__fmt__);						\
} while(0)

/* Send notify to operators */
#define SILC_SERVER_SEND_OPERS(server, route, local, type, fmt)		\
do {									\
  char *__fmt__ = silc_format fmt;					\
  silc_server_send_opers_notify(server, route, local,			\
			        type, 1, __fmt__, strlen(__fmt__));	\
  silc_free(__fmt__);							\
} while(0)

/* Connection retry timeout. We implement exponential backoff algorithm
   in connection retry. The interval of timeout grows when retry count
   grows. */
#define SILC_SERVER_RETRY_COUNT        7	 /* Max retry count */
#define SILC_SERVER_RETRY_MULTIPLIER   2	 /* Interval growth */
#define SILC_SERVER_RETRY_RANDOMIZER   2	 /* timeout += rnd % 2 */
#define SILC_SERVER_RETRY_INTERVAL_MIN 10	 /* Min retry timeout */
#define SILC_SERVER_RETRY_INTERVAL_MAX 600	 /* Max generated timeout */

#define SILC_SERVER_KEEPALIVE          300	 /* Heartbeat interval */
#define SILC_SERVER_REKEY              3600	 /* Session rekey interval */
#define SILC_SERVER_MAX_CONNECTIONS    1000	 /* Max connections */
#define SILC_SERVER_MAX_CONNECTIONS_SINGLE 1000  /* Max connections per host */
#define SILC_SERVER_LOG_FLUSH_DELAY    300       /* Default log flush delay */

/* Macros */

/* Check whether rekey protocol is active */
#define SILC_SERVER_IS_REKEY(sock)					\
  (sock->protocol && sock->protocol->protocol && 			\
   sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_REKEY)

/* Check whether backup resuming protocol is active */
#define SILC_SERVER_IS_BACKUP(sock)					\
  (sock->protocol && sock->protocol->protocol && 			\
   sock->protocol->protocol->type == SILC_PROTOCOL_SERVER_BACKUP)

/* Output a message to stderr or to the appropriate log facility wether
   we are in the background or not. */
#define SILC_SERVER_LOG_INFO(fmt)					\
  silc_server_stderr(SILC_LOG_INFO, silc_format fmt)
#define SILC_SERVER_LOG_WARNING(fmt)					\
  silc_server_stderr(SILC_LOG_WARNING, silc_format fmt)
#define SILC_SERVER_LOG_ERROR(fmt)					\
  silc_server_stderr(SILC_LOG_ERROR, silc_format fmt)
#define SILC_SERVER_LOG_FATAL(fmt)					\
  silc_server_stderr(SILC_LOG_WARNING, silc_format fmt)

/* Server's states */
SILC_FSM_STATE(silc_server_st_run);
SILC_FSM_STATE(silc_server_st_new_connection);
SILC_FSM_STATE(silc_server_st_wait_new_thread);
SILC_FSM_STATE(silc_server_st_stop);
SILC_FSM_STATE(silc_server_st_reconfigure);
SILC_FSM_STATE(silc_server_st_get_stats);
SILC_FSM_STATE(silc_server_st_connect_router);

/* Server's thread's states */
SILC_FSM_STATE(silc_server_thread_st_start);
SILC_FSM_STATE(silc_server_thread_st_run);

/* Prototypes */
void silc_server_watcher_list_destroy(void *key, void *context,
				      void *user_context);

#include "server_entry.h"

#endif /* SERVER_INTERNAL_H */
