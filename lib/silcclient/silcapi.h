/*

  silcapi.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCAPI_H
#define SILCAPI_H

#include "clientlibincludes.h"

/*
   This file defines the SILC Client Library API for the application.  The
   client operations are defined first.  These are callback functions that
   the application MUST implement since the library may call the functions
   at any time.  At the end of file is the API for the application that
   it can use from the library.  This is the only file that the application
   may include from the SIlC Client Library.

   Please, refer to the README file in this directory for the directions
   of how to use the SILC Client Library.
*/

/* General definitions */

/* Key agreement status types indicating the status of the protocol. */
typedef enum {
  SILC_KEY_AGREEMENT_OK,	       /* Everything is Ok */
  SILC_KEY_AGREEMENT_ERROR,	       /* Unknown error occured */
  SILC_KEY_AGREEMENT_FAILURE,	       /* The protocol failed */
  SILC_KEY_AGREEMENT_TIMEOUT,	       /* The protocol timeout */
} SilcKeyAgreementStatus;

/* Key agreement callback that is called after the key agreement protocol
   has been performed. This is called also if error occured during the
   key agreement protocol. The `key' is the allocated key material and
   the caller is responsible of freeing it. The `key' is NULL if error
   has occured. The application can freely use the `key' to whatever
   purpose it needs. See lib/silcske/silcske.h for the definition of
   the SilcSKEKeyMaterial structure. */
typedef void (*SilcKeyAgreementCallback)(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 SilcKeyAgreementStatus status,
					 SilcSKEKeyMaterial *key,
					 void *context);

/* Structure to hold the list of private message keys. The array of this
   structure is returned by the silc_client_list_private_message_keys
   function. */
typedef struct {
  SilcClientEntry client_entry;       /* The remote client entry */
  char *cipher;			      /* The cipher name */
  unsigned char *key;		      /* The original key, If the appliation
					 provided it. This is NULL if the
					 library generated the key or if
					 the SKE key material was used. */
  uint32 key_len;		      /* The key length */
} *SilcPrivateMessageKeys;

/******************************************************************************

                           SILC Client Operations

  These functions must be implemented by the application calling the SILC
  client library. The client library can call these functions at any time.

  To use this structure: define a static SilcClientOperations variable,
  fill it and pass its pointer to silc_client_alloc function.

******************************************************************************/

/* SILC Client Operations. These must be implemented by the application. */
typedef struct {
  /* Message sent to the application by library. `conn' associates the
     message to a specific connection.  `conn', however, may be NULL. */
  void (*say)(SilcClient client, SilcClientConnection conn, char *msg, ...);

  /* Message for a channel. The `sender' is the sender of the message 
     The `channel' is the channel. */
  void (*channel_message)(SilcClient client, SilcClientConnection conn, 
			  SilcClientEntry sender, SilcChannelEntry channel, 
			  SilcMessageFlags flags, char *msg);

  /* Private message to the client. The `sender' is the sender of the
     message. */
  void (*private_message)(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessageFlags flags,
			  char *msg);

  /* Notify message to the client. The notify arguments are sent in the
     same order as servers sends them. The arguments are same as received
     from the server except for ID's.  If ID is received application receives
     the corresponding entry to the ID. For example, if Client ID is received
     application receives SilcClientEntry.  Also, if the notify type is
     for channel the channel entry is sent to application (even if server
     does not send it because client library gets the channel entry from
     the Channel ID in the packet's header). */
  void (*notify)(SilcClient client, SilcClientConnection conn, 
		 SilcNotifyType type, ...);

  /* Command handler. This function is called always in the command function.
     If error occurs it will be called as well. `conn' is the associated
     client connection. `cmd_context' is the command context that was
     originally sent to the command. `success' is FALSE if error occured
     during command. `command' is the command being processed. It must be
     noted that this is not reply from server. This is merely called just
     after application has called the command. Just to tell application
     that the command really was processed. */
  void (*command)(SilcClient client, SilcClientConnection conn, 
		  SilcClientCommandContext cmd_context, int success,
		  SilcCommand command);

  /* Command reply handler. This function is called always in the command reply
     function. If error occurs it will be called as well. Normal scenario
     is that it will be called after the received command data has been parsed
     and processed. The function is used to pass the received command data to
     the application. 
     
     `conn' is the associated client connection. `cmd_payload' is the command
     payload data received from server and it can be ignored. It is provided
     if the application would like to re-parse the received command data,
     however, it must be noted that the data is parsed already by the library
     thus the payload can be ignored. `success' is FALSE if error occured.
     In this case arguments are not sent to the application. The `status' is
     the command reply status server returned. The `command' is the command
     reply being processed. The function has variable argument list and each
     command defines the number and type of arguments it passes to the
     application (on error they are not sent). */
  void (*command_reply)(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, int success,
			SilcCommand command, SilcCommandStatus status, ...);

  /* Called to indicate that connection was either successfully established
     or connecting failed.  This is also the first time application receives
     the SilcClientConnection objecet which it should save somewhere. */
  void (*connect)(SilcClient client, SilcClientConnection conn, int success);

  /* Called to indicate that connection was disconnected to the server. */
  void (*disconnect)(SilcClient client, SilcClientConnection conn);

  /* Find authentication method and authentication data by hostname and
     port. The hostname may be IP address as well. The found authentication
     method and authentication data is returned to `auth_meth', `auth_data'
     and `auth_data_len'. The function returns TRUE if authentication method
     is found and FALSE if not. `conn' may be NULL. */
  int (*get_auth_method)(SilcClient client, SilcClientConnection conn,
			 char *hostname, uint16 port,
			 SilcProtocolAuthMeth *auth_meth,
			 unsigned char **auth_data,
			 uint32 *auth_data_len);

  /* Verifies received public key. The `conn_type' indicates which entity
     (server, client etc.) has sent the public key. If user decides to trust
     the key may be saved as trusted public key for later use. If user does
     not trust the key this returns FALSE. If everything is Ok this returns
     TRUE. */ 
  int (*verify_public_key)(SilcClient client, SilcClientConnection conn,
			   SilcSocketType conn_type, unsigned char *pk, 
			   uint32 pk_len, SilcSKEPKType pk_type);

  /* Ask (interact, that is) a passphrase from user. Returns the passphrase
     or NULL on error. */
  unsigned char *(*ask_passphrase)(SilcClient client, 
				   SilcClientConnection conn);

  /* Notifies application that failure packet was received.  This is called
     if there is some protocol active in the client.  The `protocol' is the
     protocol context.  The `failure' is opaque pointer to the failure
     indication.  Note, that the `failure' is protocol dependant and
     application must explicitly cast it to correct type.  Usually `failure'
     is 32 bit failure type (see protocol specs for all protocol failure
     types). */
  void (*failure)(SilcClient client, SilcClientConnection conn, 
		  SilcProtocol protocol, void *failure);

  /* Asks whether the user would like to perform the key agreement protocol.
     This is called after we have received an key agreement packet or an
     reply to our key agreement packet. This returns TRUE if the user wants
     the library to perform the key agreement protocol and FALSE if it is not
     desired (application may start it later by calling the function
     silc_client_perform_key_agreement). If TRUE is returned also the
     `completion' and `context' arguments must be set by the application. */
  int (*key_agreement)(SilcClient client, SilcClientConnection conn,
		       SilcClientEntry client_entry, char *hostname,
		       int port,
		       SilcKeyAgreementCallback *completion,
		       void **context);
} SilcClientOperations;



/******************************************************************************

                           SILC Client Library API

  This is the API that is published by the SILC Client Library for the
  applications.  These functions are implemented in the SILC Client Library.
  Application may freely call these functions from the library.

******************************************************************************/

/* Initialization functions (client.c) */

/* Allocates new client object. This has to be done before client may
   work. After calling this one must call silc_client_init to initialize
   the client. The `application' is application specific user data pointer
   and caller must free it. */
SilcClient silc_client_alloc(SilcClientOperations *ops, void *application);

/* Frees client object and its internals. */
void silc_client_free(SilcClient client);

/* Initializes the client. This makes all the necessary steps to make
   the client ready to be run. One must call silc_client_run to run the
   client. Returns FALSE if error occured, TRUE otherwise. */
int silc_client_init(SilcClient client);

/* Runs the client. This starts the scheduler from the utility library.
   When this functions returns the execution of the appliation is over. */
void silc_client_run(SilcClient client);

/* Stops the client. This is called to stop the client and thus to stop
   the program. */
void silc_client_stop(SilcClient client);


/* Connecting functions (client.c) */

/* Connects to remote server. This is the main routine used to connect
   to SILC server. Returns -1 on error and the created socket otherwise. 
   The `context' is user context that is saved into the SilcClientConnection
   that is created after the connection is created. Note that application
   may handle the connecting process outside the library. If this is the
   case then this function is not used at all. When the connecting is
   done the `connect' client operation is called. */
int silc_client_connect_to_server(SilcClient client, int port,
				  char *host, void *context);

/* Allocates and adds new connection to the client. This adds the allocated
   connection to the connection table and returns a pointer to it. A client
   can have multiple connections to multiple servers. Every connection must
   be added to the client using this function. User data `context' may
   be sent as argument. This function is normally used only if the 
   application performed the connecting outside the library. The library
   however may use this internally. */
SilcClientConnection silc_client_add_connection(SilcClient client,
						char *hostname,
						int port,
						void *context);

/* Removes connection from client. Frees all memory. */
void silc_client_del_connection(SilcClient client, SilcClientConnection conn);

/* Adds listener socket to the listener sockets table. This function is
   used to add socket objects that are listeners to the client.  This should
   not be used to add other connection objects. */
void silc_client_add_socket(SilcClient client, SilcSocketConnection sock);

/* Deletes listener socket from the listener sockets table. */
void silc_client_del_socket(SilcClient client, SilcSocketConnection sock);

/* Start SILC Key Exchange (SKE) protocol to negotiate shared secret
   key material between client and server.  This function can be called
   directly if application is performing its own connecting and does not
   use the connecting provided by this library. This function is normally
   used only if the application performed the connecting outside the library.
   The library however may use this internally. */
int silc_client_start_key_exchange(SilcClient client,
			           SilcClientConnection conn,
                                   int fd);

/* Closes connection to remote end. Free's all allocated data except
   for some information such as nickname etc. that are valid at all time. 
   If the `sock' is NULL then the conn->sock will be used.  If `sock' is
   provided it will be checked whether the sock and `conn->sock' are the
   same (they can be different, ie. a socket can use `conn' as its
   connection but `conn->sock' might be actually a different connection
   than the `sock'). */
void silc_client_close_connection(SilcClient client,
				  SilcSocketConnection sock,
				  SilcClientConnection conn);


/* Message sending functions (client_channel.c and client_prvmsg.c) */

/* Sends packet to the `channel'. Packet to channel is always encrypted
   differently from "normal" packets. SILC header of the packet is 
   encrypted with the next receiver's key and the rest of the packet is
   encrypted with the channel specific key. Padding and HMAC is computed
   with the next receiver's key. The `data' is the channel message. If
   the `force_send' is TRUE then the packet is sent immediately. 

   If `key' is provided then that private key is used to encrypt the
   channel message.  If it is not provided, private keys has not been
   set at all, the normal channel key is used automatically.  If private
   keys are set then the first key (the key that was added first as
   private key) is used. */
void silc_client_send_channel_message(SilcClient client, 
				      SilcClientConnection conn,
				      SilcChannelEntry channel,
				      SilcChannelPrivateKey key,
				      SilcMessageFlags flags,
				      unsigned char *data, 
				      uint32 data_len, 
				      int force_send);

/* Sends private message to remote client. If private message key has
   not been set with this client then the message will be encrypted using
   normal session keys. Private messages are special packets in SILC
   network hence we need this own function for them. This is similiar
   to silc_client_packet_send_to_channel except that we send private
   message. The `data' is the private message. If the `force_send' is
   TRUE the packet is sent immediately. */
void silc_client_send_private_message(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry,
				      SilcMessageFlags flags,
				      unsigned char *data, 
				      uint32 data_len, 
				      int force_send);


/* Client and Channel entry retrieval (idlist.c) */

/* Callback function given to the silc_client_get_client function. The
   found entries are allocated into the `clients' array. The array must
   not be freed by the caller, the library will free it later. If the
   `clients' is NULL, no such clients exist in the SILC Network. */
typedef void (*SilcGetClientCallback)(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry *clients,
				      uint32 clients_count,
				      void *context);

/* Finds client entry or entries by the `nickname' and `server'. The 
   completion callback will be called when the client entries has been found.

   Note: this function is always asynchronous and resolves the client
   information from the server. Thus, if you already know the client
   information then use the silc_client_get_client_by_id function to
   get the client entry since this function may be very slow and should
   be used only to initially get the client entries. */
void silc_client_get_clients(SilcClient client,
			     SilcClientConnection conn,
			     char *nickname,
			     char *server,
			     SilcGetClientCallback completion,
			     void *context);

/* Same as above function but does not resolve anything from the server.
   This checks local cache and returns all clients from the cache. */
SilcClientEntry *silc_client_get_clients_local(SilcClient client,
					       SilcClientConnection conn,
					       char *nickname,
					       char *server,
					       uint32 *clients_count);

/* Gets client entries by the list of client ID's `client_id_list'. This
   always resolves those client ID's it does not know yet from the server
   so this function might take a while. The `client_id_list' is a list
   of ID Payloads added one after other.  JOIN command reply and USERS
   command reply for example returns this sort of list. The `completion'
   will be called after the entries are available. */
void silc_client_get_clients_by_list(SilcClient client,
				     SilcClientConnection conn,
				     uint32 list_count,
				     SilcBuffer client_id_list,
				     SilcGetClientCallback completion,
				     void *context);

/* Find entry for client by the client's ID. Returns the entry or NULL
   if the entry was not found. */
SilcClientEntry silc_client_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id);

/* Same as above but will always resolve the information from the server.
   Use this only if you know that you don't have the entry and the only
   thing you know about the client is its ID. */
void silc_client_get_client_by_id_resolve(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientID *client_id,
					  SilcGetClientCallback completion,
					  void *context);

/* Finds entry for channel by the channel name. Returns the entry or NULL
   if the entry was not found. It is found only if the client is joined
   to the channel. */
SilcChannelEntry silc_client_get_channel(SilcClient client,
					 SilcClientConnection conn,
					 char *channel);


/* Command management (command.c) */

/* Allocate Command Context. The context is defined in `command.h' file.
   The context is used by the library commands and applications should use
   it as well. However, application may choose to use some own context
   for its local commands. All library commands, however, must use this
   context. */
SilcClientCommandContext silc_client_command_alloc();

/* Free command context and its internals */
void silc_client_command_free(SilcClientCommandContext ctx);

/* Duplicate Command Context by adding reference counter. The context won't
   be free'd untill it hits zero. */
SilcClientCommandContext silc_client_command_dup(SilcClientCommandContext ctx);

/* Finds and returns a pointer to the command list. Return NULL if the
   command is not found. See the `command.[ch]' for the command list. */
SilcClientCommand *silc_client_command_find(const char *name);

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form and in correct order. */
void silc_client_send_command(SilcClient client, SilcClientConnection conn,
			      SilcCommand command, uint16 ident,
			      uint32 argc, ...);

/* Pending Command callback destructor. This is called after calling the
   pending callback or if error occurs while processing the pending command.
   If error occurs then the callback won't be called at all, and only this
   destructor is called. The `context' is the context given for the function
   silc_client_command_pending. */
typedef void (*SilcClientPendingDestructor)(void *context);

/* Add new pending command to be executed when reply to a command has been
   received.  The `reply_cmd' is the command that will call the `callback'
   with `context' when reply has been received.  If `ident is non-zero
   the `callback' will be executed when received reply with command 
   identifier `ident'. */
void silc_client_command_pending(SilcClientConnection conn,
				 SilcCommand reply_cmd,
				 uint16 ident,
				 SilcClientPendingDestructor destructor,
				 SilcCommandCb callback,
				 void *context);


/* Private Message key management (client_prvmsg.c) */

/* Adds private message key to the client library. The key will be used to
   encrypt all private message between the client and the remote client
   indicated by the `client_entry'. If the `key' is NULL and the boolean
   value `generate_key' is TRUE the library will generate random key.
   The `key' maybe for example pre-shared-key, passphrase or similar.
   The `cipher' MAY be provided but SHOULD be NULL to assure that the
   requirements of the SILC protocol are met. The API, however, allows
   to allocate any cipher.

   It is not necessary to set key for normal private message usage. If the
   key is not set then the private messages are encrypted using normal
   session keys. Setting the private key, however, increases the security. 

   Returns FALSE if the key is already set for the `client_entry', TRUE
   otherwise. */
int silc_client_add_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry,
					char *cipher,
					unsigned char *key,
					uint32 key_len,
					int generate_key);

/* Same as above but takes the key material from the SKE key material
   structure. This structure is received if the application uses the
   silc_client_send_key_agreement to negotiate the key material. The
   `cipher' SHOULD be provided as it is negotiated also in the SKE
   protocol. */
int silc_client_add_private_message_key_ske(SilcClient client,
					    SilcClientConnection conn,
					    SilcClientEntry client_entry,
					    char *cipher,
					    SilcSKEKeyMaterial *key);

/* Sends private message key payload to the remote client indicated by
   the `client_entry'. If the `force_send' is TRUE the packet is sent
   immediately. Returns FALSE if error occurs, TRUE otherwise. The
   application should call this function after setting the key to the
   client.

   Note that the key sent using this function is sent to the remote client
   through the SILC network. The packet is protected using normal session
   keys. */
int silc_client_send_private_message_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 int force_send);

/* Removes the private message from the library. The key won't be used
   after this to protect the private messages with the remote `client_entry'
   client. Returns FALSE on error, TRUE otherwise. */
int silc_client_del_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry);

/* Returns array of set private message keys associated to the connection
   `conn'. Returns allocated SilcPrivateMessageKeys array and the array
   count to the `key_count' argument. The array must be freed by the caller
   by calling the silc_client_free_private_message_keys function. Note: 
   the keys returned in the array is in raw format. It might not be desired
   to show the keys as is. The application might choose not to show the keys
   at all or to show the fingerprints of the keys. */
SilcPrivateMessageKeys
silc_client_list_private_message_keys(SilcClient client,
				      SilcClientConnection conn,
				      uint32 *key_count);

/* Frees the SilcPrivateMessageKeys array returned by the function
   silc_client_list_private_message_keys. */
void silc_client_free_private_message_keys(SilcPrivateMessageKeys keys,
					   uint32 key_count);


/* Channel private key management (client_channel.c, 
   SilcChannelPrivateKey is defined in idlist.h) */

/* Adds private key for channel. This may be set only if the channel's mode
   mask includes the SILC_CHANNEL_MODE_PRIVKEY. This returns FALSE if the
   mode is not set. When channel has private key then the messages are
   encrypted using that key. All clients on the channel must also know the
   key in order to decrypt the messages. However, it is possible to have
   several private keys per one channel. In this case only some of the
   clients on the channel may know the one key and only some the other key.

   The private key for channel is optional. If it is not set then the
   channel messages are encrypted using the channel key generated by the
   server. However, setting the private key (or keys) for the channel 
   significantly adds security. If more than one key is set the library
   will automatically try all keys at the message decryption phase. Note:
   setting many keys slows down the decryption phase as all keys has to
   be tried in order to find the correct decryption key. However, setting
   a few keys does not have big impact to the decryption performace. 

   NOTE: that this is entirely local setting. The key set using this function
   is not sent to the network at any phase.

   NOTE: If the key material was originated by the SKE protocol (using
   silc_client_send_key_agreement) then the `key' MUST be the
   key->send_enc_key as this is dictated by the SILC protocol. However,
   currently it is not expected that the SKE key material would be used
   as channel private key. However, this API allows it. */
int silc_client_add_channel_private_key(SilcClient client,
					SilcClientConnection conn,
					SilcChannelEntry channel,
					char *cipher,
					char *hmac,
					unsigned char *key,
					uint32 key_len);

/* Removes all private keys from the `channel'. The old channel key is used
   after calling this to protect the channel messages. Returns FALSE on
   on error, TRUE otherwise. */
int silc_client_del_channel_private_keys(SilcClient client,
					 SilcClientConnection conn,
					 SilcChannelEntry channel);

/* Removes and frees private key `key' from the channel `channel'. The `key'
   is retrieved by calling the function silc_client_list_channel_private_keys.
   The key is not used after this. If the key was last private key then the
   old channel key is used hereafter to protect the channel messages. This
   returns FALSE on error, TRUE otherwise. */
int silc_client_del_channel_private_key(SilcClient client,
					SilcClientConnection conn,
					SilcChannelEntry channel,
					SilcChannelPrivateKey key);

/* Returns array (pointers) of private keys associated to the `channel'.
   The caller must free the array by calling the function
   silc_client_free_channel_private_keys. The pointers in the array may be
   used to delete the specific key by giving the pointer as argument to the
   function silc_client_del_channel_private_key. */
SilcChannelPrivateKey *
silc_client_list_channel_private_keys(SilcClient client,
				      SilcClientConnection conn,
				      SilcChannelEntry channel,
				      uint32 *key_count);

/* Frees the SilcChannelPrivateKey array. */
void silc_client_free_channel_private_keys(SilcChannelPrivateKey *keys,
					   uint32 key_count);


/* Key Agreement routines (client_keyagr.c) */

/* Sends key agreement request to the remote client indicated by the
   `client_entry'. If the caller provides the `hostname' and the `port'
   arguments then the library will bind the client to that hostname and
   that port for the key agreement protocol. It also sends the `hostname'
   and the `port' in the key agreement packet to the remote client. This
   would indicate that the remote client may initiate the key agreement
   protocol to the `hostname' on the `port'.  If port is zero then the
   bound port is undefined (the operating system defines it).

   If the `hostname' and `port' is not provided then empty key agreement
   packet is sent to the remote client. The remote client may reply with
   the same packet including its hostname and port. If the library receives
   the reply from the remote client the `key_agreement' client operation
   callback will be called to verify whether the user wants to perform the
   key agreement or not. 

   NOTE: If the application provided the `hostname' and the `port' and the 
   remote side initiates the key agreement protocol it is not verified
   from the user anymore whether the protocol should be executed or not.
   By setting the `hostname' and `port' the user gives permission to
   perform the protocol (we are responder in this case).

   NOTE: If the remote side decides not to initiate the key agreement
   or decides not to reply with the key agreement packet then we cannot
   perform the key agreement at all. If the key agreement protocol is
   performed the `completion' callback with the `context' will be called.
   If remote side decides to ignore the request the `completion' will be
   called after the specified timeout, `timeout_secs'. 

   NOTE: There can be only one active key agreement for one client entry.
   Before setting new one, the old one must be finished (it is finished
   after calling the completion callback) or the function 
   silc_client_abort_key_agreement must be called. */
void silc_client_send_key_agreement(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry,
				    char *hostname,
				    int port,
				    uint32 timeout_secs,
				    SilcKeyAgreementCallback completion,
				    void *context);

/* Performs the actual key agreement protocol. Application may use this
   to initiate the key agreement protocol. This can be called for example
   after the application has received the `key_agreement' client operation,
   and did not return TRUE from it.

   The `hostname' is the remote hostname (or IP address) and the `port'
   is the remote port. The `completion' callback with the `context' will
   be called after the key agreement protocol.
   
   NOTE: If the application returns TRUE in the `key_agreement' client
   operation the library will automatically start the key agreement. In this
   case the application must not call this function. However, application
   may choose to just ignore the `key_agreement' client operation (and
   merely just print information about it on the screen) and call this
   function when the user whishes to do so (by, for example, giving some
   specific command). Thus, the API provides both, automatic and manual
   initiation of the key agreement. Calling this function is the manual
   initiation and returning TRUE in the `key_agreement' client operation
   is the automatic initiation. */
void silc_client_perform_key_agreement(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry,
				       char *hostname,
				       int port,
				       SilcKeyAgreementCallback completion,
				       void *context);

/* Same as above but application has created already the connection to 
   the remote host. The `sock' is the socket to the remote connection. 
   Application can use this function if it does not want the client library
   to create the connection. */
void silc_client_perform_key_agreement_fd(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  int sock,
					  char *hostname,
					  SilcKeyAgreementCallback completion,
					  void *context);

/* This function can be called to unbind the hostname and the port for
   the key agreement protocol. However, this function has effect only 
   before the key agreement protocol has been performed. After it has
   been performed the library will automatically unbind the port. The 
   `client_entry' is the client to which we sent the key agreement 
   request. */
void silc_client_abort_key_agreement(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry client_entry);

#endif
