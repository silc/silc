/*

  client_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2014 Pekka Riikonen

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
#include "client_keyagr.h"
#include "client_ftp.h"
#include "client_listener.h"

/****************************** Definitions *********************************/

/* Packet retry counter and timer defines, for exponential backoff algorithm.
   Meaningful with UDP transport when packets may get lost. */
#define SILC_CLIENT_RETRY_COUNT   4      /* Max packet retry count */
#define SILC_CLIENT_RETRY_MUL     2      /* Retry timer interval growth */
#define SILC_CLIENT_RETRY_RAND    2      /* Randomizer, timeout += rnd % 2 */
#define SILC_CLIENT_RETRY_MIN     1      /* Min retry timeout, seconds */
#define SLIC_CLIENT_RETRY_MAX     16	 /* Max retry timeout, seconds */

/********************************** Types ***********************************/

/* Public key verification context */
typedef struct {
  SilcSKE ske;
  SilcSKEVerifyCbCompletion completion;
  SilcPublicKey public_key;
  void *completion_context;
  void *context;
  SilcBool aborted;
} *SilcVerifyKeyContext;

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
  SilcFSMEventStruct wait_event;	 /* Event signaller */
  SilcClientOperations *ops;		 /* Client operations */
  SilcClientParams *params;		 /* Client parameters */
  SilcPacketEngine packet_engine;        /* Packet engine */
  SilcMutex lock;			 /* Client lock */
  SilcList commands;			 /* Registered commands */
  SilcDList ftp_sessions;	         /* FTP sessions */
  char *silc_client_version;		 /* Version set by application */
  SilcClientRunning running;	         /* Running/Stopped callback */
  void *running_context;		 /* Context for runnign callback */
  SilcAtomic32 conns;			 /* Number of connections in client */
  SilcUInt16 next_session_id;		 /* Next FTP session ID */

  /* Events */
  unsigned int stop              : 1;	 /* Stop client */
  unsigned int run_callback      : 1;	 /* Call running/stopped callback */
  unsigned int connection_closed : 1;	 /* A connection closed */
};

/* Internal context for conn->internal in SilcClientConnection. */
struct SilcClientConnectionInternalStruct {
  SilcClientConnectionParams params;	 /* Connection parameters */
  SilcFSMStruct fsm;			 /* Connection FSM */
  SilcFSMThreadStruct event_thread;      /* FSM thread for events */
  SilcFSMEventStruct wait_event;	 /* Event signaller */
  SilcSchedule schedule;		 /* Connection's scheduler */
  SilcMutex lock;		         /* Connection lock */
  SilcSKE ske;				 /* Key exchange protocol */
  SilcSKERekeyMaterial rekey;		 /* Rekey material */
  SilcList thread_pool;			 /* Packet thread pool */
  SilcList pending_commands;		 /* Pending commands list */
  SilcHash hash;			 /* Negotiated hash function */
  SilcHash sha1hash;			 /* SHA-1 default hash context */
  SilcBuffer local_idp;		         /* Local ID Payload */
  SilcBuffer remote_idp;		 /* Remote ID Payload */
  SilcAsyncOperation op;	         /* Protocols async operation */
  SilcAsyncOperation cop;	         /* Async operation for application */
  SilcHashTable attrs;		         /* Configured user attributes */
  SilcStream user_stream;		 /* Low level stream in connecting */
  char *disconnect_message;		 /* Disconnection message */
  char *away_message;		         /* Away message */

  SilcIDCache client_cache;		 /* Client entry cache */
  SilcIDCache channel_cache;		 /* Channel entry cache */
  SilcIDCache server_cache;		 /* Server entry cache */

  SilcUInt32 remote_version;	         /* Remote SILC protocol version */
  SilcAtomic16 cmd_ident;		 /* Current command identifier */
  SilcUInt8 retry_count;		 /* Packet retry counter */
  SilcUInt8 retry_timer;		 /* Packet retry timer */
  SilcClientConnectionStatus status;	 /* Connection callback status */
  SilcStatus error;			 /* Connection callback error */
  SilcUInt32 ake_generation;		 /* next AKE rekey generation */

  /* Events */
  unsigned int connect            : 1;	 /* Connect remote host */
  unsigned int disconnected       : 1;	 /* Disconnect remote connection */
  unsigned int key_exchange       : 1;   /* Start key exchange */
  unsigned int rekeying           : 1;   /* Start rekey */

  /* Flags */
  unsigned int verbose            : 1;   /* Notify application */
  unsigned int registering        : 1;	 /* Set when registering to network */
  unsigned int rekey_responder    : 1;   /* Set when rekeying as responder */
  unsigned int auth_request       : 1;   /* Set when requesting auth method */
};

SILC_FSM_STATE(silc_client_connection_st_run);
SILC_FSM_STATE(silc_client_connection_st_packet);
SILC_FSM_STATE(silc_client_connection_st_close);
SILC_FSM_STATE(silc_client_error);
SILC_FSM_STATE(silc_client_disconnect);
SILC_FSM_STATE(silc_client_st_stop);

void silc_client_del_connection(SilcClient client, SilcClientConnection conn);
void silc_client_fsm_destructor(SilcFSM fsm, void *fsm_context,
				void *destructor_context);
void silc_client_command_free(SilcClientCommandContext cmd);
SilcClientConnection
silc_client_add_connection(SilcClient client,
			   SilcConnectionType conn_type,
			   SilcBool connect,
			   SilcClientConnectionParams *params,
			   SilcPublicKey public_key,
			   SilcPrivateKey private_key,
			   char *remote_host, int port,
			   SilcClientConnectCallback callback,
			   void *context);
SilcBuffer silc_client_attributes_process(SilcClient client,
                                          SilcClientConnection conn,
                                          SilcDList attrs);

#endif /* CLIENT_INTERNAL_H */
