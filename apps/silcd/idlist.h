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

/* Forward declarations */
typedef struct SilcServerEntryStruct *SilcServerEntry;
typedef struct SilcClientEntryStruct *SilcClientEntry;
typedef struct SilcChannelEntryStruct *SilcChannelEntry;

/* 
   SILC Server entry object.

   This entry holds information about servers in SILC network. However, 
   contents of this entry is highly dependent of what kind of server we are 
   (normal server or router server) and whether the entry is used as a local 
   list or a global list. These factors dictates the contents of this entry.

   This entry is defined as follows:

   Server type   List type      Contents
   =======================================================================
   server        local list     Server itself
   server        global list    NULL
   router        local list     All servers is the cell
   router        global list    All servers in the SILC network

   Following short description of the fields:

   char *server_name

       Logical name of the server. There is no limit of the length of the
       server name. This is usually the same name as defined in DNS.

   int server_type

       Type of the server. SILC_SERVER or SILC_ROUTER are the possible
       choices for this.

   SilcServerID *id

       ID of the server. This includes all the relevant information about
       the server SILC will ever need. These are also the informations
       that is broadcasted between servers and routers in the SILC network.

   long last_receive

       Time when data was received from the server last time.

   SilcServerEntry router

       This is a pointer back to the server list. This is the router server 
       where this server is connected to. If this is the router itself and 
       it doesn't have a route this is NULL.

   SilcCipher send_key
   SilcCipher receive_key

       Data sending and receiving keys.

   void *connection

       A pointer, usually, to the socket list for fast referencing to
       the data used in connection with this server.  This may be anything
       but as just said, this is usually pointer to the socket connection
       list.
   
*/
struct SilcServerEntryStruct {
  char *server_name;
  int server_type;
  SilcServerID *id;
  long last_receive;

  /* TRUE when server is registered to server */
  int registered;

  /* Pointer to the router */
  SilcServerEntry router;

  /* Keys */
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcPKCS pkcs;
  SilcPublicKey public_key;
  SilcHmac hmac;
  unsigned char *hmac_key;
  unsigned int hmac_key_len;

  /* Connection data */
  void *connection;
};

/* 
   SILC Client entry object.

   This entry holds information about connected clients ie. users in the SILC
   network. The contents of this entrt is depended on whether we are normal 
   server or router server and whether the list is a local or global list.

   This entry is defined as follows:

   Server type   List type      Contents
   =======================================================================
   server        local list     All clients in server
   server        global list    NULL
   router        local list     All clients in cell
   router        global list    All clients in SILC

   Following short description of the fields:

   char username

       Client's (meaning user's) real name. This is defined in following 
       manner:

       Server type   List type      Contents
       ====================================================
       server        local list     User's name
       router        local list     NULL
       router        global list    NULL

       Router doesn't hold this information since it is not vital data 
       for the router. If this information is needed by the client it is
       fetched when it is needed.

   char userinfo

       Information about user. This is free information and can be virtually
       anything. This is defined in following manner:
       
       Server type   List type      Contents
       ====================================================
       server        local list     User's information
       router        local list     NULL
       router        global list    NULL

       Router doesn't hold this information since it is not vital data 
       for the router. If this information is needed by the client it is
       fetched when it is needed.

   SilcClientID *id

       ID of the client. This includes all the information SILC will ever
       need. Notice that no nickname of the user is saved anywhere. This is
       beacuse of SilcClientID includes 88 bit hash value of the user's 
       nickname which can be used to track down specific user by their 
       nickname. Nickname is not relevant information that would need to be 
       saved as plain.

   int mode

       Client's mode.  Client maybe for example server operator or
       router operator (SILC operator).

   long last_receive

       Time of last time data was received from the client. This is
       result of normal time().

   long last_command

       Time of last time client executed command. We are strict and will
       not allow any command to be exeucted more than once in about
       2 seconds. This is result of normal time().

   int registered

       Boolean value to indicate whether this client has registered itself
       to the server. After KE and authentication protocols has been
       successfully completed will client become registered.

   SilcServerEntry router

       This is a pointer to the server list. This is the router server whose 
       cell this client is coming from. This is used to route messages to 
       this client.

   SilcCipher session_key

       The actual session key established by key exchange protcol between
       connecting parties. This is used for both encryption and decryption.

   SilcPKCS pkcs

       PKCS of the client. This maybe NULL.

   SilcHmac hmac

       MAC key used to compute MAC's for packets. 

   void *connection

       A pointer, usually, to the socket list for fast referencing to
       the data used in connection with this client.  This may be anything
       but as just said, this is usually pointer to the socket connection
       list.

*/
struct SilcClientEntryStruct {
  char *nickname;
  char *username;
  char *userinfo;
  SilcClientID *id;
  int mode;

  /* Time of last accesses of the client */
  long last_receive;
  long last_command;

  /* TRUE when client is registered to server */
  int registered;

  /* Pointer to the router */
  SilcServerEntry router;

  /* List of channels client has joined to */
  SilcChannelEntry *channel;
  unsigned int channel_count;

  /* Keys */
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcPKCS pkcs;
  SilcHmac hmac;
  SilcPublicKey public_key;

  /* Connection data */
  void *connection;
};

/* 
   SILC Channel Client entry structure.

   This entry used only by the SilcChannelEntry object and it holds
   information about current clients (ie. users) on channel. Following
   short description  of the fields:

   SilcClientEntry client

       Pointer to the client list. This is the client currently on channel.

   unsigned int mode

       Client's current mode on the channel.

*/
typedef struct SilcChannelClientEntryStruct {
  SilcClientEntry client;
  unsigned int mode;
  struct SilcChannelClientEntryStruct *next;
} *SilcChannelClientEntry;

/* 
   SILC Channel entry object.

   This entry holds information about channels in SILC network. The contents 
   of this entry is depended on whether we are normal server or router server 
   and whether the list is a local or global list.

   This entry is defined as follows:

   Server type   List type      Contents
   =======================================================================
   server        local list     All channels in server
   server        global list    NULL
   router        local list     All channels in cell
   router        global list    All channels in SILC

   Following short description of the fields:

   char *channel_name

       Logical name of the channel.

   unsigned int mode

       Current mode of the channel.  See lib/silccore/silcchannel.h for
       all modes.

   SilcChannelID *id

       ID of the channel. This includes all the information SILC will ever
       need.

   int global_users
 
       Boolean value to tell whether there are users outside this server
       on this channel. This is set to TRUE if router sends message to
       the server that there are users outside your server on your
       channel as well. This way server knows that messages needs to be
       sent to the router for further routing. If this is a normal 
       server and this channel is not created on this server this field
       is always TRUE. If this server is a router this field is ignored.

   char *topic

       Current topic of the channel.

   char *cipher

       Default cipher of the channel. If this is NULL then server picks
       the cipher to be used. This can be set at SILC_COMMAND_JOIN.

   SilcServerEntry router

       This is a pointer to the server list. This is the router server 
       whose cell this channel belongs to. This is used to route messages 
       to this channel.

   SilcCipher channel_key

       The key of the channel (the cipher actually).

   unsigned char *key
   unsigned int key_len

       Raw key data of the channel key.

   unsigned char iv[SILC_CIPHER_MAX_IV_SIZE]

       Current initial vector. Initial vector is received always along
       with the channel packet. By default this is filled with NULL.

*/
struct SilcChannelEntryStruct {
  char *channel_name;
  unsigned int mode;
  SilcChannelID *id;
  int global_users;
  char *topic;
  char *cipher;

  /* Data that is related to different channel modes. */
  struct {
    unsigned int user_limit;
    unsigned char *passphrase;
    unsigned char *ban_list;
    unsigned char *invite_list;
    unsigned char *cipher;
    unsigned int key_len;
  } mode_data;

  /* List of users on channel */
  SilcList user_list;

  /* Pointer to the router */
  SilcServerEntry router;

  /* Channel keys */
  SilcCipher channel_key;
  unsigned char *key;
  unsigned int key_len;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];
};

/* 
   SILC ID List object.

   As for remainder these lists are defined as follows:

   Entry list (cache)  Server type   List type      Contents
   =======================================================================
   servers             server        local list     Server itself
   servers             server        global list    NULL
   servers             router        local list     All servers in cell
   servers             router        global list    All servers in SILC

   clients             server        local list     All clients in server
   clients             server        global list    NULL
   clients             router        local list     All clients in cell
   clients             router        global list    All clients in SILC

   channels            server        local list     All channels in server
   channels            server        global list    NULL
   channels            router        local list     All channels in cell
   channels            router        global list    All channels in SILC

   As seen on the list normal server never defines a global list. This is
   because of normal server don't know anything about anything global data,
   they get it from the router if and when they need it. Routers, on the
   other hand, always define local and global lists because routers really
   know all the relevant data in the SILC network.

   This object is used as local and global list by the server/router.
   Above table shows how this is defined on different conditions.

   This object holds pointers to the ID cache system. Every ID cache entry
   has a specific context pointer to allocated entry (server, client or
   channel entry).

*/
typedef struct SilcIDListStruct {
  SilcIDCache servers;
  SilcIDCache clients;
  SilcIDCache channels;
} *SilcIDList;

/*
   Temporary ID Entry object.

   This is used during authentication phases where we still don't know 
   what kind of connection remote connection is, hence, we will use this
   structure instead until we know what type of connection remote end is.

   This is not in any list. This is always individually allocated and
   used as such.

*/
typedef struct {
  SilcCipher send_key;
  SilcCipher receive_key;
  SilcPKCS pkcs;
  SilcPublicKey public_key;

  SilcHmac hmac;
  unsigned char *hmac_key;
  unsigned int hmac_key_len;

  /* SilcComp comp */
} *SilcUnknownEntry;

/* Prototypes */
SilcServerEntry 
silc_idlist_add_server(SilcIDList id_list, 
		       char *server_name, int server_type,
		       SilcServerID *id, SilcServerEntry router,
		       SilcCipher send_key, SilcCipher receive_key,
		       SilcPKCS pkcs, SilcHmac hmac, 
		       SilcPublicKey public_key, void *connection);
SilcServerEntry
silc_idlist_find_server_by_id(SilcIDList id_list, SilcServerID *id);
SilcServerEntry
silc_idlist_replace_server_id(SilcIDList id_list, SilcServerID *old_id,
			      SilcServerID *new_id);
SilcClientEntry
silc_idlist_add_client(SilcIDList id_list, char *nickname, char *username,
		       char *userinfo, SilcClientID *id, 
		       SilcServerEntry router,
		       SilcCipher send_key, SilcCipher receive_key,
		       SilcPKCS pkcs, SilcHmac hmac, 
		       SilcPublicKey public_key, void *connection);
void silc_idlist_del_client(SilcIDList id_list, SilcClientEntry entry);
SilcClientEntry *
silc_idlist_get_clients_by_nickname(SilcIDList id_list, char *nickname,
				    char *server, unsigned int *clients_count);
SilcClientEntry
silc_idlist_find_client_by_nickname(SilcIDList id_list, char *nickname,
				    char *server);
SilcClientEntry
silc_idlist_find_client_by_hash(SilcIDList id_list, char *nickname,
				SilcHash md5hash);
SilcClientEntry
silc_idlist_find_client_by_id(SilcIDList id_list, SilcClientID *id);
SilcClientEntry
silc_idlist_replace_client_id(SilcIDList id_list, SilcClientID *old_id,
			      SilcClientID *new_id);
SilcChannelEntry
silc_idlist_add_channel(SilcIDList id_list, char *channel_name, int mode,
			SilcChannelID *id, SilcServerEntry router,
			SilcCipher channel_key);
void silc_idlist_del_channel(SilcIDList id_list, SilcChannelEntry entry);
SilcChannelEntry
silc_idlist_find_channel_by_name(SilcIDList id_list, char *name);
SilcChannelEntry
silc_idlist_find_channel_by_id(SilcIDList id_list, SilcChannelID *id);

#endif
