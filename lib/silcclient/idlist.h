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
  unsigned int num;
  SilcClientID *id;		/* The Client ID */
  SilcCipher send_key;		/* Private message key for sending */
  SilcCipher receive_key;	/* Private message key for receiving */
  unsigned char *key;		/* Set only if appliation provided the
				   key material. NULL if the library 
				   generated the key. */
  unsigned int key_len;
  int generated;		/* TRUE if library generated the key */
} *SilcClientEntry;

/* Client and its mode on a channel */
typedef struct SilcChannelUserStruct {
  SilcClientEntry client;
  unsigned int mode;
  struct SilcChannelUserStruct *next;
} *SilcChannelUser;

/* Channel entry context. This is allocate for every channel client has
   joined to. This includes for example the channel specific keys */
/* XXX channel_key is the server generated key. Later this context must 
   include the channel private key. */
typedef struct SilcChannelEntryStruct {
  char *channel_name;
  SilcChannelID *id;
  unsigned int mode;
  int on_channel;

  /* Joined clients */
  SilcList clients;

  /* Channel keys */
  SilcCipher channel_key;
  unsigned char *key;
  unsigned int key_len;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];
} *SilcChannelEntry;

/* Prototypes (some functions are defined in the silcapi.h) */

SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       char *nickname,
				       char *server,
				       unsigned int num,
				       int query);

#endif
