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

/* Structure to hold ping time information. Every PING command will
   add entry of this structure and is removed after reply to the ping
   as been received. */
struct SilcClientPingStruct {
  time_t start_time;
  void *dest_id;
  char *dest_name;
};

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
  unsigned int processed     : 1;     /* Set when reply was processed  */
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

  /* Generic cipher and hash objects. */
  SilcHmac md5hmac;
  SilcHmac sha1hmac;

  /* Client version. Used to compare to remote host's version strings. */
  char *silc_client_version;

  /* Events */
  unsigned int run_callback    : 1;	 /* Call running callback */
};

/* Internal context for conn->internal in SilcClientConnection. */
struct SilcClientConnectionInternalStruct {
  /* Client ID and Channel ID cache. Messages transmitted in SILC network
     are done using different unique ID's. These are the cache for
     thoses ID's used in the communication. */
  SilcIDCache client_cache;
  SilcIDCache channel_cache;
  SilcIDCache server_cache;

  /* Pending command queue for this connection */
  SilcList pending_commands;

  /* Requested pings. */
  SilcClientPing *ping;
  SilcUInt32 ping_count;

  /* Set away message */
  SilcClientAway *away;

  /* Authentication request context. */
  SilcClientConnAuthRequest connauth;

  /* File transmission sessions */
  SilcDList ftp_sessions;
  SilcUInt32 next_session_id;
  SilcClientFtpSession active_session;

  /* Requested Attributes */
  SilcHashTable attrs;

  SilcFSMStruct fsm;			 /* Connection FSM */
  SilcFSMThreadStruct packet_thread;     /* FSM thread for packet processor */
  SilcFSMThreadStruct event_thread;      /* FSM thread for events */
  SilcFSMSemaStruct wait_event;		 /* Event signaller */
  SilcMutex lock;		         /* Connection lock */
  SilcSchedule schedule;		 /* Connection's scheduler */
  SilcSKE ske;				 /* Key exchange protocol */
  SilcSKERekeyMaterial rekey;		 /* Rekey material */
  SilcHash hash;			 /* Negotiated hash function */
  SilcClientConnectionParams params;	 /* Connection parameters */
  SilcAtomic16 cmd_ident;		 /* Current command identifier */
  SilcIDCacheEntry local_entry;		 /* Local client cache entry */

  SilcHashTable privmsg_wait;	         /* Waited private messages */

  /* Events */
  unsigned int connect            : 1;	 /* Connect remote host */
  unsigned int disconnected       : 1;	 /* Disconnected by remote host */
  unsigned int key_exchange       : 1;   /* Start key exchange */
  unsigned int new_packet         : 1;	 /* New packet received */

  /* Flags */
  unsigned int verbose            : 1;   /* Notify application */
  unsigned int registering        : 1;	 /* Set when registering to network */
};

SILC_FSM_STATE(silc_client_connection_st_packet);

void silc_client_channel_message(SilcClient client,
				 SilcClientConnection conn,
				 SilcPacket packet);
void silc_client_ftp(SilcClient client, SilcClientConnection conn,
		     SilcPacket packet);
void silc_client_channel_key(SilcClient client,
			     SilcClientConnection conn,
			     SilcPacket packet);
void silc_client_notify(SilcClient client,
			SilcClientConnection conn,
			SilcPacket packet);
void silc_client_disconnect(SilcClient client,
			    SilcClientConnection conn,
			    SilcPacket packet);
void silc_client_error(SilcClient client,
		       SilcClientConnection conn,
		       SilcPacket packet);
void silc_client_key_agreement(SilcClient client,
			       SilcClientConnection conn,
			       SilcPacket packet);
void silc_client_connection_auth_request(SilcClient client,
					 SilcClientConnection conn,
					 SilcPacket packet);
SilcUInt16 silc_client_command_send_argv(SilcClient client,
					 SilcClientConnection conn,
					 SilcCommand command,
					 SilcClientCommandReply reply,
					 void *reply_context,
					 SilcUInt32 argc,
					 unsigned char **argv,
					 SilcUInt32 *argv_lens,
					 SilcUInt32 *argv_types);

#if 0
/* Session resuming callback */
typedef void (*SilcClientResumeSessionCallback)(SilcClient client,
						SilcClientConnection conn,
						SilcBool success,
						void *context);

/* Rekey must be performed at the lastest when this many packets is sent */
#define SILC_CLIENT_REKEY_THRESHOLD 0xfffffe00

/* Macros */

/* Registers generic task for file descriptor for reading from network and
   writing to network. As being generic task the actual task is allocated
   only once and after that the same task applies to all registered fd's. */
#define SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(fd)	\
do {							\
  silc_schedule_task_add(client->schedule, (fd),	\
			 silc_client_packet_process,	\
			 context, 0, 0,			\
			 SILC_TASK_GENERIC,		\
		         SILC_TASK_PRI_NORMAL);		\
} while(0)

#define SILC_CLIENT_SET_CONNECTION_FOR_INPUT(s, fd)			\
do {									\
  silc_schedule_set_listen_fd((s), (fd), SILC_TASK_READ, FALSE);	\
} while(0)

#define SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(s, fd)			\
do {									\
  silc_schedule_set_listen_fd((s), (fd), (SILC_TASK_READ |		\
				          SILC_TASK_WRITE), FALSE);	\
} while(0)

/* Finds socket connection object by file descriptor */
#define SILC_CLIENT_GET_SOCK(__x, __fd, __sock)			\
do {								\
  int __i;							\
								\
  for (__i = 0; __i < (__x)->internal->conns_count; __i++)	\
    if ((__x)->internal->conns[__i] &&				\
	(__x)->internal->conns[__i]->sock &&			\
	(__x)->internal->conns[__i]->sock->sock == (__fd))	\
      break;							\
								\
  if (__i >= (__x)->internal->conns_count) {			\
    (__sock) = NULL;						\
    for (__i = 0; __i < (__x)->internal->sockets_count; __i++)	\
      if ((__x)->internal->sockets[__i] &&			\
	  (__x)->internal->sockets[__i]->sock == (__fd))	\
        (__sock) = (__x)->internal->sockets[__i];		\
  } else							\
    (__sock) = (__x)->internal->conns[__i]->sock;		\
} while(0)

/* Check whether rekey protocol is active */
#define SILC_CLIENT_IS_REKEY(sock)					\
  (sock->protocol && sock->protocol->protocol && 			\
   sock->protocol->protocol->type == SILC_PROTOCOL_CLIENT_REKEY)

/* Prototypes */

SILC_TASK_CALLBACK_GLOBAL(silc_client_packet_process);
void silc_client_packet_send(SilcClient client,
                             SilcClientConnection conn,
                             SilcPacketType type,
                             void *dst_id,
                             SilcIdType dst_id_type,
                             SilcCipher cipher,
                             SilcHmac hmac,
                             unsigned char *data,
                             SilcUInt32 data_len,
                             SilcBool force_send);
int silc_client_packet_send_real(SilcClient client,
				 SilcClientConnection conn,
				 SilcBool force_send);
void silc_client_ftp_free_sessions(SilcClient client,
				   SilcClientConnection conn);
void silc_client_ftp_session_free(SilcClientFtpSession session);
void silc_client_ftp_session_free_client(SilcClientConnection conn,
					 SilcClientEntry client_entry);
void silc_client_close_connection_real(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientConnection conn);

void silc_client_save_channel_key(SilcClient client,
				  SilcClientConnection conn,
				  SilcBuffer key_payload,
				  SilcChannelEntry channel);
void silc_client_remove_from_channels(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry);
void silc_client_replace_from_channels(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry old,
				       SilcClientEntry newclient);
void silc_client_process_failure(SilcClient client,
				 SilcClientConnection conn,
				 SilcPacket packet);
SilcBuffer silc_client_get_detach_data(SilcClient client,
				       SilcClientConnection conn);
SilcBool silc_client_process_detach_data(SilcClient client,
				     SilcClientConnection conn,
				     unsigned char **old_id,
				     SilcUInt16 *old_id_len);
void silc_client_resume_session(SilcClient client,
				SilcClientConnection conn,
				SilcClientResumeSessionCallback callback,
				void *context);
SilcBuffer silc_client_attributes_process(SilcClient client,
					  SilcClientConnection conn,
					  SilcDList attrs);
void silc_client_packet_queue_purge(SilcClient client,
				    SilcClientConnection conn);
SILC_TASK_CALLBACK_GLOBAL(silc_client_rekey_callback);
void
silc_client_command_reply_whois_save(SilcClientCommandReplyContext cmd,
				     SilcStatus status,
				     SilcBool notify);
#endif /* 0 */

#endif
