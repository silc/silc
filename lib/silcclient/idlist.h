/*

  idlist.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef IDLIST_H
#define IDLIST_H

/* Client entry context. When client receives information about new client
   (it receives its ID, for example, by IDENTIFY request) we create new
   client entry. This entry also includes the private message keys if
   they are used. */
typedef struct SilcClientEntryStruct {
  char *nickname;		/* nickname */
  char *username;		/* username[@host] */
  char *server;			/* SILC server name */
  char *realname;		/* Realname (userinfo) */
  uint32 num;
  uint32 mode;			/* User mode in SILC */
  SilcClientID *id;		/* The Client ID */
  SilcCipher send_key;		/* Private message key for sending */
  SilcCipher receive_key;	/* Private message key for receiving */
  unsigned char *key;		/* Set only if appliation provided the
				   key material. NULL if the library 
				   generated the key. */
  uint32 key_len;
  int generated;		/* TRUE if library generated the key */
  SilcClientKeyAgreement ke;	/* Current key agreement context or NULL */
} *SilcClientEntry;

/* Client and its mode on a channel */
typedef struct SilcChannelUserStruct {
  SilcClientEntry client;
  uint32 mode;
  struct SilcChannelUserStruct *next;
} *SilcChannelUser;

/* Structure to hold one channel private key. */
typedef struct {
  SilcCipher cipher;		      /* The cipher and key */
  SilcHmac hmac;		      /* The HMAC and hmac key */
  unsigned char *key;		      /* The key data */
  uint32 key_len;		      /* The key length */
} *SilcChannelPrivateKey;

/* Channel entry context. This is allocate for every channel client has
   joined to. This includes for example the channel specific keys */
typedef struct SilcChannelEntryStruct {
  char *channel_name;
  SilcChannelID *id;
  uint32 mode;
  int on_channel;

  /* Joined clients */
  SilcList clients;

  /* Channel keys */
  SilcCipher channel_key;                    /* The channel key */
  unsigned char *key;			     /* Raw key data */
  uint32 key_len;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE]; /* Current IV */
  SilcHmac hmac;			     /* Current HMAC */
  SilcDList private_keys;		     /* List of private keys or NULL */
  SilcChannelPrivateKey curr_key;	     /* Current private key */
} *SilcChannelEntry;

/* Prototypes (some functions are defined in the silcapi.h) */

SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       char *nickname,
				       char *server,
				       uint32 num,
				       int query);

#endif
