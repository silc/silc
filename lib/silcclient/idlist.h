/*

  idlist.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef IDLIST_H
#define IDLIST_H

/* Client entry status */
typedef enum {
  SILC_CLIENT_STATUS_NONE       = 0x0000,
  SILC_CLIENT_STATUS_RESOLVING  = 0x0001,
} SilcClientStatus;

/* Client entry context. When client receives information about new client
   (it receives its ID, for example, by IDENTIFY request) we create new
   client entry. This entry also includes the private message keys if
   they are used. */
struct SilcClientEntryStruct {
  char *nickname;		/* nickname */
  char *username;		/* username */
  char *hostname;		/* hostname */
  char *server;			/* SILC server name */
  char *realname;		/* Realname (userinfo) */
  SilcUInt32 num;
  SilcUInt32 mode;			/* User mode in SILC */
  SilcClientID *id;		/* The Client ID */
  unsigned char *fingerprint;	/* Fingerprint of client's public key */
  SilcUInt32 fingerprint_len;	/* Length of the fingerprint */
  bool valid;			/* FALSE if this entry is not valid */
  SilcCipher send_key;		/* Private message key for sending */
  SilcCipher receive_key;	/* Private message key for receiving */
  unsigned char *key;		/* Set only if appliation provided the
				   key material. NULL if the library 
				   generated the key. */
  SilcUInt32 key_len;
  bool generated;		/* TRUE if library generated the key */
  SilcClientKeyAgreement ke;	/* Current key agreement context or NULL */
  SilcClientStatus status;	/* Status mask */
  SilcHashTable channels;	/* All channels client has joined */
};

/* Client and its mode on a channel */
struct SilcChannelUserStruct {
  SilcClientEntry client;
  SilcUInt32 mode;
  SilcChannelEntry channel;
};

/* Channel entry context. This is allocate for every channel client has
   joined to. This includes for example the channel specific keys */
struct SilcChannelEntryStruct {
  char *channel_name;
  SilcChannelID *id;
  SilcUInt32 mode;

  /* All clients that has joined this channel */
  SilcHashTable user_list;

  /* Channel keys */
  SilcCipher channel_key;                    /* The channel key */
  unsigned char *key;			     /* Raw key data */
  SilcUInt32 key_len;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE]; /* Current IV */
  SilcHmac hmac;			     /* Current HMAC */
  SilcDList private_keys;		     /* List of private keys or NULL */
  SilcChannelPrivateKey curr_key;	     /* Current private key */

  /* Old channel key is saved for a short period of time when rekey occurs
     in case if someone is sending messages after the rekey encrypted with
     the old key, we can still decrypt them. */
  SilcCipher old_channel_key;
  SilcHmac old_hmac;
  SilcTask rekey_task;
};

/* Server entry context. This represents one server. When server information
   is resolved with INFO command the server info is saved in this context. 
   Also the connected servers are saved here. */
struct SilcServerEntryStruct {
  char *server_name;
  char *server_info;
  SilcServerID *server_id;
};

/* Prototypes. These are used only by the library. Application should not
   call these directly. */

SilcClientEntry
silc_client_add_client(SilcClient client, SilcClientConnection conn,
		       char *nickname, char *username, 
		       char *userinfo, SilcClientID *id, SilcUInt32 mode);
void silc_client_update_client(SilcClient client,
			       SilcClientConnection conn,
			       SilcClientEntry client_entry,
			       const char *nickname,
			       const char *username,
			       const char *userinfo,
			       SilcUInt32 mode);
void silc_client_del_client_entry(SilcClient client, 
				  SilcClientConnection conn,
				  SilcClientEntry client_entry);
SilcClientEntry silc_idlist_get_client(SilcClient client,
				       SilcClientConnection conn,
				       const char *nickname,
				       const char *format,
				       bool query);
SilcChannelEntry silc_client_add_channel(SilcClient client,
					 SilcClientConnection conn,
					 const char *channel_name,
					 SilcUInt32 mode, 
					 SilcChannelID *channel_id);
SilcServerEntry silc_client_add_server(SilcClient client,
				       SilcClientConnection conn,
				       const char *server_name,
				       const char *server_info,
				       SilcServerID *server_id);
bool silc_client_replace_channel_id(SilcClient client,
				    SilcClientConnection conn,
				    SilcChannelEntry channel,
				    SilcChannelID *new_id);
void silc_client_nickname_format(SilcClient client, 
				 SilcClientConnection conn,
				 SilcClientEntry client_entry);

#endif
