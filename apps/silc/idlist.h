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
  char *nickname;
  SilcClientID *id;

  /* Keys, these are defined if private message key has been defined 
     with the remote client. */
  SilcCipher send_key;
  SilcCipher receive_key;
} SilcClientEntryObject;

typedef SilcClientEntryObject *SilcClientEntry;

/* Channel entry context. This is allocate for every channel client has
   joined to. This includes for example the channel specific keys */
/* XXX channel_key is the server generated key. Later this context must 
   include the channel private key. */
typedef struct SilcChannelEntryStruct {
  char *channel_name;
  SilcChannelID *id;
  int on_channel;

  /* Channel keys */
  SilcCipher channel_key;
  unsigned char *key;
  unsigned int key_len;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];
} SilcChannelEntryObject;

typedef SilcChannelEntryObject *SilcChannelEntry;

#endif
