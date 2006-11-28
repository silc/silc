/*

  client_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_INTERNAL_H
#define CLIENT_INTERNAL_H

#include "command.h"
#include "command_reply.h"
#include "client_connect.h"
#include "client_register.h"
#include "client_entry.h"
#include "client_prvmsg.h"
#include "client_channel.h"
#include "client_notify.h"

/* Context to hold the connection authentication request callbacks that
   will be called when the server has replied back to our request about
   current authentication method in the session. */
typedef struct {
  SilcConnectionAuthRequest callback;
  void *context;
  SilcTask timeout;
} *SilcClientConnAuthRequest;

/* Generic rekey context for connections */
typedef struct {
  /* Current sending encryption key, provided for re-key. The `pfs'
     is TRUE if the Perfect Forward Secrecy is performed in re-key. */
  unsigned char *send_enc_key;
  SilcUInt32 enc_key_len;
  int ske_group;
  SilcBool pfs;
  SilcUInt32 timeout;
  void *context;
} *SilcClientRekey;

/* Internal context for connection process. This is needed as we
   doing asynchronous connecting. */
typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  SilcTask task;
  int sock;
  char *host;
  int port;
  void *context;
} SilcClientInternalConnectContext;

/* Structure to hold away messages set by user. This is mainly created
   for future extensions where away messages could be set according filters
   such as nickname and hostname. For now only one away message can
   be set in one connection. */
struct SilcClientAwayStruct {
  char *away;
  struct SilcClientAwayStruct *next;
};

/* Command and command reply context used to hold registered commands
   in the SILC client. */
typedef struct SilcClientCommandStruct {
  struct SilcClientCommandStruct *next;
  SilcCommand cmd;		      /* Command type */
  SilcFSMStateCallback command;	      /* Command function */
  SilcFSMStateCallback reply;	      /* Command reply callback */
  char *name;			      /* Name of the command (optional) */
  SilcUInt8 max_args;		      /* Maximum arguments (optional)  */
} *SilcClientCommand;

/* Command reply callback structure */
typedef struct SilcClientCommandReplyCallbackStruct  {
  struct SilcClientCommandReplyCallbackStruct *next;
  SilcClientCommandReply reply;	      /* Command reply callback */
  void *context;		      /* Command reply context */
  unsigned int do_not_call     : 1;   /* Set to not call the callback */
} *SilcClientCommandReplyCallback;

/* Command context given as argument to command state functions.  This same
   context is used when calling, sending and procesing command and command
   reply. */
typedef struct SilcClientCommandContextStruct {
  struct SilcClientCommandContextStruct *next;
  SilcClientConnection conn;          /* Connection */
  SilcFSMThreadStruct thread;	      /* FSM thread for command call */

  SilcCommand cmd;		      /* Command */
  SilcUInt16 cmd_ident;		      /* Command identifier */
  SilcUInt32 argc;		      /* Number of arguments */
  unsigned char **argv;		      /* Arguments, may be NULL */
  SilcUInt32 *argv_lens;	      /* Argument lengths, may be NULL */
  SilcUInt32 *argv_types;	      /* Argument types, may be NULL */

  SilcList reply_callbacks;	      /* Command reply callbacks */
  SilcStatus status;		      /* Current command reply status */
  SilcStatus error;		      /* Current command reply error */

  void *context;		      /* Context for free use */
  unsigned int called        : 1;     /* Set when called by application */
  unsigned int verbose       : 1;     /* Verbose with 'say' client operation */
  unsigned int resolved      : 1;     /* Set when resolving something */
} *SilcClientCommandContext;

/* Internal context for the client->internal pointer in the SilcClient. */
struct SilcClientInternalStruct {
  SilcFSMStruct fsm;			 /* Client's FSM */
  SilcFSMSemaStruct wait_event;		 /* Event signaller */
  SilcClientOperations *ops;		 /* Client operations */
  SilcClientParams *params;		 /* Client parameters */
  SilcPacketEngine packet_engine;        /* Packet engine */
  SilcMutex lock;			 /* Client lock */

  /* List of connections in client. All the connection data is saved here. */
  SilcDList conns;

  /* Registered commands */
  SilcList commands;

  /* Client version. Used to compare to remote host's version strings. */
  char *silc_client_version;

  /* Events */
  unsigned int run_callback    : 1;	 /* Call running callback */
};

/* Internal context for conn->internal in SilcClientConnection. */
struct SilcClientConnectionInternalStruct {
  SilcIDCacheEntry local_entry;		 /* Local client cache entry */
  SilcClientConnectionParams params;	 /* Connection parameters */

  SilcFSMStruct fsm;			 /* Connection FSM */
  SilcFSMThreadStruct event_thread;      /* FSM thread for events */
  SilcFSMSemaStruct wait_event;		 /* Event signaller */
  SilcSchedule schedule;		 /* Connection's scheduler */
  SilcMutex lock;		         /* Connection lock */
  SilcSKE ske;				 /* Key exchange protocol */
  SilcSKERekeyMaterial rekey;		 /* Rekey material */
  SilcList thread_pool;			 /* Packet thread pool */
  SilcList pending_commands;		 /* Pending commands list */
  SilcHash hash;			 /* Negotiated hash function */
  SilcHash sha1hash;			 /* SHA-1 default hash context */

  SilcIDCache client_cache;		 /* Client entry cache */
  SilcIDCache channel_cache;		 /* Channel entry cache */
  SilcIDCache server_cache;		 /* Server entry cache */

  SilcBuffer local_idp;		         /* Local ID Payload */
  SilcBuffer remote_idp;		 /* Remote ID Payload */

  SilcAtomic16 cmd_ident;		 /* Current command identifier */

  /* Events */
  unsigned int connect            : 1;	 /* Connect remote host */
  unsigned int disconnected       : 1;	 /* Disconnected by remote host */
  unsigned int key_exchange       : 1;   /* Start key exchange */

  /* Flags */
  unsigned int verbose            : 1;   /* Notify application */
  unsigned int registering        : 1;	 /* Set when registering to network */

  SilcClientAway *away;
  SilcClientConnAuthRequest connauth;
  SilcDList ftp_sessions;
  SilcUInt32 next_session_id;
  SilcClientFtpSession active_session;
  SilcHashTable attrs;
  SilcHashTable privmsg_wait;	         /* Waited private messages */
};

SILC_FSM_STATE(silc_client_connection_st_run);
SILC_FSM_STATE(silc_client_connection_st_packet);
SILC_FSM_STATE(silc_client_connection_st_close);
SILC_FSM_STATE(silc_client_error);
SILC_FSM_STATE(silc_client_disconnect);

void silc_client_del_connection(SilcClient client, SilcClientConnection conn);
SilcBool silc_client_del_client(SilcClient client, SilcClientConnection conn,
				SilcClientEntry client_entry);
SilcBool silc_client_del_channel(SilcClient client, SilcClientConnection conn,
				 SilcChannelEntry channel);
SilcBool silc_client_del_server(SilcClient client, SilcClientConnection conn,
				SilcServerEntry server);
SilcUInt16 silc_client_command_send_argv(SilcClient client,
					 SilcClientConnection conn,
					 SilcCommand command,
					 SilcClientCommandReply reply,
					 void *reply_context,
					 SilcUInt32 argc,
					 unsigned char **argv,
					 SilcUInt32 *argv_lens,
					 SilcUInt32 *argv_types);

void silc_client_ftp(SilcClient client, SilcClientConnection conn,
		     SilcPacket packet);
void silc_client_key_agreement(SilcClient client,
			       SilcClientConnection conn,
			       SilcPacket packet);
void silc_client_connection_auth_request(SilcClient client,
					 SilcClientConnection conn,
					 SilcPacket packet);

#endif
