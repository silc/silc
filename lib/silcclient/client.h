/*

  client.h

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

#ifndef CLIENT_H
#define CLIENT_H

#ifndef SILCCLIENT_H
#error "Do not include this header directly"
#endif

/* Forward declarations */
typedef struct SilcClientStruct *SilcClient;
typedef struct SilcClientConnectionStruct *SilcClientConnection;
typedef struct SilcClientEntryStruct *SilcClientEntry;
typedef struct SilcChannelEntryStruct *SilcChannelEntry;
typedef struct SilcServerEntryStruct *SilcServerEntry;

typedef struct SilcClientAwayStruct SilcClientAway;
typedef struct SilcClientKeyAgreementStruct *SilcClientKeyAgreement;
typedef struct SilcClientFtpSessionStruct *SilcClientFtpSession;
typedef struct SilcClientCommandReplyContextStruct
                                           *SilcClientCommandReplyContext;
typedef struct SilcChannelUserStruct *SilcChannelUser;
typedef struct SilcClientInternalStruct *SilcClientInternal;
typedef struct SilcClientConnectionInternalStruct
					   *SilcClientConnectionInternal;
typedef struct SilcChannelPrivateKeyStruct *SilcChannelPrivateKey;


/* Internal client entry context */
typedef struct SilcClientEntryInternalStruct {
  SilcCipher send_key;		/* Private message key for sending */
  SilcCipher receive_key;	/* Private message key for receiving */
  SilcHmac hmac_send;		/* Private mesage key HMAC for sending */
  SilcHmac hmac_receive;	/* Private mesage key HMAC for receiving */
  unsigned char *key;		/* Valid if application provided the key */
  SilcUInt32 key_len;		/* Key data length */
  SilcClientKeyAgreement ke;	/* Current key agreement context or NULL */

  /* Flags */
  unsigned int valid       : 1;	/* FALSE if this entry is not valid */
  unsigned int resolving   : 1; /* TRUE when entry is being resolved */
  unsigned int generated   : 1; /* TRUE if library generated `key' */
  unsigned int prv_resp    : 1; /* TRUE if we are responder when using
				   private message keys. */
  SilcUInt16 resolve_cmd_ident;	/* Command identifier when resolving */
  SilcAtomic8 refcnt;		/* Reference counter */
} SilcClientEntryInternal;

/* Internal channel entry context */
typedef struct SilcChannelEntryInternalStruct {
  /* SilcChannelEntry status information */
  SilcDList old_channel_keys;
  SilcDList old_hmacs;

  /* Channel private keys */
  SilcDList private_keys;		     /* List of private keys or NULL */
  SilcChannelPrivateKey curr_key;	     /* Current private key */

  /* Channel keys */
  SilcCipher channel_key;                    /* The channel key */
  SilcHmac hmac;			     /* Current HMAC */
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE]; /* Current IV */

  SilcUInt16 resolve_cmd_ident;		     /* Channel information resolving
						identifier. This is used when
						resolving users, and other
						stuff that relates to the
						channel. Not used for the
						channel resolving itself. */
  SilcAtomic16 refcnt;		             /* Reference counter */
} SilcChannelEntryInternal;

/* Internal server entry context */
typedef struct SilcServerEntryInternalStruct {
  SilcUInt16 resolve_cmd_ident;		     /* Resolving identifier */
  SilcAtomic8 refcnt;		             /* Reference counter */
} SilcServerEntryInternal;

#endif /* CLIENT_H */
