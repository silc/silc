/*

  client.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_H
#define CLIENT_H

/* Forward declarations */
typedef struct SilcClientStruct *SilcClient;
typedef struct SilcClientInternalStruct *SilcClientInternal;
typedef struct SilcClientConnectionStruct *SilcClientConnection;
typedef struct SilcClientPingStruct SilcClientPing;
typedef struct SilcClientAwayStruct SilcClientAway;
typedef struct SilcClientKeyAgreementStruct *SilcClientKeyAgreement;
typedef struct SilcClientFtpSessionStruct *SilcClientFtpSession;

#include "idlist.h"
#include "command.h"
#include "silcapi.h"

/* Generic rekey context for connections */
typedef struct {
  /* Current sending encryption key, provided for re-key. The `pfs'
     is TRUE if the Perfect Forward Secrecy is performed in re-key. */
  unsigned char *send_enc_key;
  uint32 enc_key_len;
  int ske_group;
  bool pfs;
  uint32 timeout;
  void *context;
} *SilcClientRekey;

/* Context to hold the connection authentication request callbacks that
   will be called when the server has replied back to our request about
   current authentication method in the session. */
typedef struct {
  SilcConnectionAuthRequest callback;
  void *context;
  SilcTask timeout;
} *SilcClientConnAuthRequest;

/* Connection structure used in client to associate all the important
   connection specific data to this structure. */
struct SilcClientConnectionStruct {
  /*
   * Local data 
   */
  char *nickname;

  /* Local client ID for this connection */
  SilcClientID *local_id;

  /* Decoded local ID so that the above defined ID would not have
     to be decoded for every packet. */
  unsigned char *local_id_data;
  uint32 local_id_data_len;

  /* Own client entry. */
  SilcClientEntry local_entry;

  /*
   * Remote data 
   */
  char *remote_host;
  int remote_port;
  int remote_type;
  char *remote_info;

  /* Remote server ID for this connection */
  SilcServerID *remote_id;

  /* Decoded remote ID so that the above defined ID would not have
     to be decoded for every packet. */
  unsigned char *remote_id_data;
  uint32 remote_id_data_len;

  /*
   * Common data 
   */
  /* Keys and stuff negotiated in the SKE protocol */
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcHmac hmac_send;
  SilcHmac hmac_receive;
  SilcHash hash;
  uint32 psn_send;
  uint32 psn_receive;

  /* Client ID and Channel ID cache. Messages transmitted in SILC network
     are done using different unique ID's. These are the cache for
     thoses ID's used in the communication. */
  SilcIDCache client_cache;
  SilcIDCache channel_cache;
  SilcIDCache server_cache;

  /* Current channel on window. All channels are saved (allocated) into
     the cache entries. */
  SilcChannelEntry current_channel;

  /* Socket connection object for this connection (window). This
     object will have a back-pointer to this window object for fast
     referencing (sock->user_data). */
  SilcSocketConnection sock;

  /* Pending command queue for this connection */
  SilcDList pending_commands;

  /* Current command identifier, 0 not used */
  uint16 cmd_ident;

  /* Requested pings. */
  SilcClientPing *ping;
  uint32 ping_count;

  /* Set away message */
  SilcClientAway *away;

  /* Re-key context */
  SilcClientRekey rekey;

  /* Authentication request context. */
  SilcClientConnAuthRequest connauth;

  /* File transmission sessions */
  SilcDList ftp_sessions;
  uint32 next_session_id;
  SilcClientFtpSession active_session;

  /* Pointer back to the SilcClient. This object is passed to the application
     and the actual client object is accesible through this pointer. */
  SilcClient client;

  /* User data context. Library does not touch this. */
  void *context;
};

/* Main client structure. */
struct SilcClientStruct {
  char *username;		/* Username, must be set by application */
  char *nickname;		/* Nickname, may be set by application  */
  char *hostname;		/* hostname, must be set by application */
  char *realname;		/* Real name, must be set be application */

  SilcPublicKey public_key;	/* Public key of user, set by application */
  SilcPrivateKey private_key;	/* Private key of user, set by application */
  SilcPKCS pkcs;		/* PKCS allocated by application */

  SilcSchedule schedule;	/* Scheduler, automatically allocated by
				   the client library. */

  /* Random Number Generator. Application should use this as its primary
     random number generator. */
  SilcRng rng;

  /* Application specific user data pointer. Client library does not
     touch this. This the context sent as argument to silc_client_alloc. */
  void *application;

  /* Internal data for client library. Application cannot access this
     data at all. */
  SilcClientInternal internal;
};

#endif
