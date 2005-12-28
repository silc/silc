/*

  silcclient.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcclient/Client Library Interface
 *
 * DESCRIPTION
 *
 * This interface defines the SILC Client Library API for the application.
 * The client operations are defined first.  These are callback functions that
 * the application MUST implement since the library may call the functions
 * at any time.  At the end of file is the API for the application that
 * it can use from the library.  This is the only file that the application
 * may include from the SIlC Client Library.
 *
 * o SILC Client Operations
 *
 *   These functions must be implemented by the application calling the SILC
 *   client library. The client library can call these functions at any time.
 *
 *   To use this structure: define a static SilcClientOperations variable,
 *   fill it and pass its pointer to silc_client_alloc function.
 *
 * o SILC Client Library API
 *
 *   This is the API that is published by the SILC Client Library for the
 *   applications.  These functions are implemented in the SILC Client Library.
 *   Application may freely call these functions from the library.
 *
 ***/

#ifndef SILCCLIENT_H
#define SILCCLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "client.h"

/* General definitions */

/****s* silcclient/SilcClientAPI/SilcClient
 *
 * NAME
 *
 *    typedef struct SilcClientStruct { ... } *SilcClient
 *
 * DESCRIPTION
 *
 *    This is the actual SILC Client structure which represents one
 *    SILC Client.  It is allocated with the silc_client_alloc function
 *    and given as argument to all SILC Client Library functions.  It
 *    is initialized with silc_client_init function, and freed with
 *    silc_client_free function.
 *
 * SOURCE
 */
struct SilcClientStruct {
  /*
   * The following fields are set by application. Strings MUST be UTF-8
   * encoded strings.
   */
  char *nickname;               /* Nickname, MAY be set by application  */
  char *username;               /* Username, MUST be set by application */
  char *hostname;               /* hostname, MUST be set by application */
  char *realname;               /* Real name, MUST be set be application */

  SilcPublicKey public_key;     /* Public key of user, set by application */
  SilcPrivateKey private_key;   /* Private key of user, set by application */
  SilcPKCS pkcs;                /* PKCS allocated by application */

  /*
   * The following fields are set by the library
   */

  /* Scheduler, set by library.  Application may use this pointer. */
  SilcSchedule schedule;

  /* Random Number Generator. Application should use this as its primary
     random number generator. */
  SilcRng rng;

  /* Application specific user data pointer. Client library does not
     touch this.  This the context sent as argument to silc_client_alloc.
     Application can use it freely. */
  void *application;

  /* Generic hash context for application usage */
  SilcHash md5hash;
  SilcHash sha1hash;

  /* Internal data for client library. Application cannot access this
     data at all. */
  SilcClientInternal internal;
};
/***/

/****s* silcclient/SilcClientAPI/SilcClientConnection
 *
 * NAME
 *
 *    typedef struct SilcClientConnectionStruct { ... }
 *                      *SilcClientConnection
 *
 * DESCRIPTION
 *
 *    This structure represents a connection.  When connection is created
 *    to server this is context is returned to the application in the
 *    "connected" client operation.  It includes all the important
 *    data for the session, such as nickname, local and remote IDs, and
 *    other information.  All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcClientConnectionStruct {
  /*
   * Local data
   */
  char *nickname;		  /* Current nickname */
  SilcClientEntry local_entry;	  /* Own Client Entry */
  SilcClientID *local_id;	  /* Current Client ID */
  unsigned char *local_id_data;	  /* Current Client ID decoded */
  SilcUInt32 local_id_data_len;

  /*
   * Remote data
   */
  char *remote_host;		  /* Remote host name, UTF-8 encoded */
  int remote_port;		  /* Remote port */
  SilcServerID *remote_id;	  /* Remote Server ID */
  unsigned char *remote_id_data;  /* Remote Server ID decoded */
  SilcUInt32 remote_id_data_len;

  /*
   * Common data
   */

  /* Current command identifier for a command that was sent last.
     Application may get the value from this variable to find out the
     command identifier for last command. */
  SilcUInt16 cmd_ident;

  /* User data context. Library does not touch this. Application may
     freely set and use this pointer for its needs. */
  void *context;

  /* Pointer back to the SilcClient.  Application may use this. */
  SilcClient client;

  /* Current channel.  Application may use and set this pointer if needed. */
  SilcChannelEntry current_channel;

  /* Socket connection object for this connection.  Application may
     use this if needed.  The sock->user_data is back pointer to this
     structure. */
  SilcSocketConnection sock;

  /* Internal data for client library. Application cannot access this
     data at all. */
  SilcClientConnectionInternal internal;
};
/***/

/****s* silcclient/SilcClientAPI/SilcClientEntry
 *
 * NAME
 *
 *    typedef struct SilcClientEntryStruct { ... } *SilcClientEntry
 *
 * DESCRIPTION
 *
 *    This structure represents a client or a user in the SILC network.
 *    The local user has this structure also and it can be accessed from
 *    SilcClientConnection structure.  All other users in the SILC network
 *    that are accessed using the Client Library routines will have their
 *    own SilcClientEntry structure.  For example, when finding users by
 *    their nickname the Client Library returns this structure back to
 *    the application.  All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcClientEntryStruct {
  /* General information */
  char *nickname;		/* nickname */
  char *username;		/* username */
  char *hostname;		/* hostname */
  char *server;			/* SILC server name */
  char *realname;		/* Realname (userinfo) */

  /* Mode, ID and other information */
  SilcUInt32 mode;		/* User mode in SILC, see SilcUserMode */
  SilcClientID *id;		/* The Client ID */
  SilcDList attrs;		/* Requested Attributes (maybe NULL) */
  unsigned char *fingerprint;	/* Fingerprint of client's public key */
  SilcUInt32 fingerprint_len;	/* Length of the fingerprint */
  SilcPublicKey public_key;	/* User's public key, may be NULL */

  /* Private message keys */
  SilcCipher send_key;		/* Private message key for sending */
  SilcCipher receive_key;	/* Private message key for receiving */
  SilcHmac hmac_send;		/* Private mesage key HMAC for sending */
  SilcHmac hmac_receive;	/* Private mesage key HMAC for receiving */
  unsigned char *key;		/* Set only if application provided the
				   key material. NULL if the library
				   generated the key. */
  SilcUInt32 key_len;		/* Key length */
  SilcClientKeyAgreement ke;	/* Current key agreement context or NULL */

  /* SilcClientEntry status information */
  SilcEntryStatus status;	/* Status mask */
  SilcHashTable channels;	/* All channels client has joined */
  SilcUInt16 resolve_cmd_ident;	/* Command identifier when resolving */
  unsigned int generated   : 1; /* TRUE if library generated `key' */
  unsigned int valid       : 1;	/* FALSE if this entry is not valid */
  unsigned int prv_resp    : 1; /* TRUE if private message key indicator
				   has been received (responder). */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;
};
/***/

/****s* silcclient/SilcClientAPI/SilcChannelEntry
 *
 * NAME
 *
 *    typedef struct SilcChannelEntryStruct { ... } *SilcChannelEntry
 *
 * DESCRIPTION
 *
 *    This structure represents a channel in the SILC network.  All
 *    channels that the client are aware of or have joined in will be
 *    represented as SilcChannelEntry.  The structure includes information
 *    about the channel.  All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcChannelEntryStruct {
  /* General information */
  char *channel_name;		             /* Channel name */
  SilcChannelID *id;			     /* Channel ID */
  SilcUInt32 mode;			     /* Channel mode, ChannelModes. */
  char *topic;				     /* Current topic, may be NULL */
  SilcPublicKey founder_key;		     /* Founder key, may be NULL */
  SilcUInt32 user_limit;		     /* User limit on channel */

  /* All clients that has joined this channel.  The key to the table is the
     SilcClientEntry and the context is SilcChannelUser context. */
  SilcHashTable user_list;

  /* Channel keys */
  SilcCipher channel_key;                    /* The channel key */
  unsigned char *key;			     /* Raw key data */
  SilcUInt32 key_len;		             /* Raw key data length */
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE]; /* Current IV */
  SilcHmac hmac;			     /* Current HMAC */

  /* Channel private keys */
  SilcDList private_keys;		     /* List of private keys or NULL */
  SilcChannelPrivateKey curr_key;	     /* Current private key */

  /* SilcChannelEntry status information */
  SilcDList old_channel_keys;
  SilcDList old_hmacs;
  SilcUInt16 resolve_cmd_ident;		     /* Command identifier when
						resolving this entry */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;
};
/***/

/****s* silcclient/SilcClientAPI/SilcChannelUser
 *
 * NAME
 *
 *    typedef struct SilcChannelUserStruct { ... } *SilcChannelUser
 *
 * DESCRIPTION
 *
 *    This structure represents a client that has joined to a channel.
 *    It shows the client and the channel and the client's mode (channel
 *    user mode) on the channel.
 *
 * SOURCE
 */
struct SilcChannelUserStruct {
  SilcClientEntry client;	             /* Client joined on channel */
  SilcUInt32 mode;			     /* mode, ChannelUserModes */
  SilcChannelEntry channel;		     /* The channel user has joined */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;
};
/***/

/****s* silcclient/SilcClientAPI/SilcServerEntry
 *
 * NAME
 *
 *    typedef struct SilcServerEntryStruct { ... } *SilcServerEntry
 *
 * DESCRIPTION
 *
 *    This structure represents a server in the SILC network.  All servers
 *    that the client is aware of and have for example resolved with
 *    SILC_COMMAND_INFO command have their on SilcServerEntry structure.
 *    All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcServerEntryStruct {
  /* General information */
  char *server_name;			     /* Server name */
  char *server_info;			     /* Server info */
  SilcServerID *server_id;		     /* Server ID */
  SilcUInt16 resolve_cmd_ident;		     /* Command identifier when
					        resolving this entry */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;
};
/***/

/****d* silcclient/SilcClientAPI/SilcKeyAgreementStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcKeyAgreementStatus;
 *
 * DESCRIPTION
 *
 *    Key agreement status types indicating the status of the key
 *    agreement protocol.  These types are returned to the application
 *    in the SilcKeyAgreementCallback callback function.
 *
 * SOURCE
 */
typedef enum {
  SILC_KEY_AGREEMENT_OK,	       /* Everything is Ok */
  SILC_KEY_AGREEMENT_ERROR,	       /* Unknown error occurred */
  SILC_KEY_AGREEMENT_FAILURE,	       /* The protocol failed */
  SILC_KEY_AGREEMENT_TIMEOUT,	       /* The protocol timeout */
  SILC_KEY_AGREEMENT_ABORTED,	       /* The protocol aborted */
  SILC_KEY_AGREEMENT_ALREADY_STARTED,  /* Already started */
  SILC_KEY_AGREEMENT_SELF_DENIED,      /* Negotiationg with itself denied */
} SilcKeyAgreementStatus;
/***/

/****f* silcclient/SilcClientAPI/SilcKeyAgreementCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcKeyAgreementCallback)(SilcClient client,
 *                                             SilcClientConnection conn,
 *                                             SilcClientEntry client_entry,
 *                                             SilcKeyAgreementStatus status,
 *                                             SilcSKEKeyMaterial *key,
 *                                             void *context);
 *
 * DESCRIPTION
 *
 *    Key agreement callback that is called after the key agreement protocol
 *    has been performed. This is called also if error occurred during the
 *    key agreement protocol. The `key' is the allocated key material and
 *    the caller is responsible of freeing it. The `key' is NULL if error
 *    has occurred. The application can freely use the `key' to whatever
 *    purpose it needs. See lib/silcske/silcske.h for the definition of
 *    the SilcSKEKeyMaterial structure.
 *
 ***/
typedef void (*SilcKeyAgreementCallback)(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 SilcKeyAgreementStatus status,
					 SilcSKEKeyMaterial *key,
					 void *context);

/****s* silcclient/SilcClientAPI/SilcPrivateMessageKeys
 *
 * NAME
 *
 *    typedef struct { ... } SilcPrivateMessageKeys;
 *
 * DESCRIPTION
 *
 *    Structure to hold the list of private message keys. The array of this
 *    structure is returned by the silc_client_list_private_message_keys
 *    function.
 *
 * SOURCE
 */
typedef struct {
  SilcClientEntry client_entry;       /* The remote client entry */
  char *cipher;			      /* The cipher name */
  unsigned char *key;		      /* The original key, If the appliation
					 provided it. This is NULL if the
					 library generated the key or if
					 the SKE key material was used. */
  SilcUInt32 key_len;		      /* The key length */
} *SilcPrivateMessageKeys;
/***/

/****s* silcclient/SilcClientAPI/SilcChannelPrivateKey
 *
 * NAME
 *
 *    typedef struct SilcChannelPrivateKeyStruct { ... }
 *                      *SilcChannelPrivateKey;
 *
 * DESCRIPTION
 *
 *    Structure to hold one channel private key. The array of this structure
 *    is returned by silc_client_list_channel_private_keys function.
 *
 * SOURCE
 */
struct SilcChannelPrivateKeyStruct {
  char *name;			      /* Application given name */
  SilcCipher cipher;		      /* The cipher and key */
  SilcHmac hmac;		      /* The HMAC and hmac key */
  unsigned char *key;		      /* The key data */
  SilcUInt32 key_len;		      /* The key length */
};
/***/

/****f* silcclient/SilcClientAPI/SilcAskPassphrase
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcAskPassphrase)(unsigned char *passphrase,
 *			                SilcUInt32 passphrase_len,
 *			                void *context);
 *
 * DESCRIPTION
 *
 *    Ask passphrase callback. This is called by the application when the
 *    library calls `ask_passphrase' client operation.  The callback delivers
 *    the passphrase to the library.  The passphrases in SILC protocol
 *    MUST be in UTF-8 encoding, therefore the `passphrase' SHOULD be UTF-8
 *    encoded, and if it is not then library will attempt to encode it.
 *
 ***/
typedef void (*SilcAskPassphrase)(unsigned char *passphrase,
				  SilcUInt32 passphrase_len,
				  void *context);

/****f* silcclient/SilcClientAPI/SilcVerifyPublicKey
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcVerifyPublicKey)(SilcBool success, void *context);
 *
 * DESCRIPTION
 *
 *    Public key (or certificate) verification callback. This is called
 *    by the application to indicate that the public key verification was
 *    either success or failure.
 *
 ***/
typedef void (*SilcVerifyPublicKey)(SilcBool success, void *context);

/****f* silcclient/SilcClientAPI/SilcGetAuthMeth
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcGetAuthMeth)(SilcBool success,
 *                                    SilcProtocolAuthMeth auth_meth,
 *                                    const unsigned char *auth_data,
 *                                    SilcUInt32 auth_data_len, void *context);
 *
 * DESCRIPTION
 *
 *    Authentication method resolving callback. This is called by the
 *    application to return the resolved authentication method. The client
 *    library has called the get_auth_method client operation and given
 *    this function pointer as argument. The `success' will indicate whether
 *    the authentication method could be resolved. The `auth_meth' is the
 *    resolved authentication method. The `auth_data' and the `auth_data_len'
 *    are the resolved authentication data. The `context' is the libary's
 *    context sent to the get_auth_method client operation.
 *
 ***/
typedef void (*SilcGetAuthMeth)(SilcBool success,
				SilcProtocolAuthMeth auth_meth,
				const unsigned char *auth_data,
				SilcUInt32 auth_data_len, void *context);

/****d* silcclient/SilcClientAPI/SilcClientMessageType
 *
 * NAME
 *
 *    typedef enum { ... } SilcClientMessageType;
 *
 * DESCRIPTION
 *
 *    Different message types for `say' client operation.  The application
 *    may filter the message sent by the library according this type.
 *
 * SOURCE
 */
typedef enum {
  SILC_CLIENT_MESSAGE_INFO,	       /* Informational */
  SILC_CLIENT_MESSAGE_WARNING,	       /* Warning */
  SILC_CLIENT_MESSAGE_ERROR,	       /* Error */
  SILC_CLIENT_MESSAGE_AUDIT,	       /* Auditable */
} SilcClientMessageType;
/***/

/****d* silcclient/SilcClientAPI/SilcClientConnectionStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcClientConnectionStatus
 *
 * DESCRIPTION
 *
 *    This type is returned to the `connect' client operation to indicate
 *    the status of the created connection.  It can indicate if it was
 *    successful or whether an error occurred.
 *
 * SOURCE
 */
typedef enum {
  SILC_CLIENT_CONN_SUCCESS,	       /* Successfully connected */
  SILC_CLIENT_CONN_SUCCESS_RESUME,     /* Successfully connected and
					  resumed old detached session */
  SILC_CLIENT_CONN_ERROR,	       /* Unknown error occurred during
					  connecting */
  SILC_CLIENT_CONN_ERROR_KE,	       /* Key Exchange failed */
  SILC_CLIENT_CONN_ERROR_AUTH,	       /* Authentication failed */
  SILC_CLIENT_CONN_ERROR_RESUME,       /* Resuming failed */
  SILC_CLIENT_CONN_ERROR_TIMEOUT,      /* Timeout during connecting */
} SilcClientConnectionStatus;
/***/

/****s* silcclient/SilcClientAPI/SilcClientOperations
 *
 * NAME
 *
 *    typedef struct { ... } SilcClientOperations;
 *
 * DESCRIPTION
 *
 *    SILC Client Operations. These must be implemented by the application.
 *    The Client library may call any of these routines at any time.  The
 *    routines are used to deliver certain information to the application
 *    or from the application to the client library.
 *
 * SOURCE
 */
typedef struct {
  /* Message sent to the application by library. `conn' associates the
     message to a specific connection.  `conn', however, may be NULL.
     The `type' indicates the type of the message sent by the library.
     The application can for example filter the message according the
     type.  The variable argument list is arguments to the formatted
     message that `msg' may be. */
  void (*say)(SilcClient client, SilcClientConnection conn,
	      SilcClientMessageType type, char *msg, ...);

  /* Message for a channel. The `sender' is the sender of the message
     The `channel' is the channel. The `message' is the message.  Note
     that `message' maybe NULL.  The `flags' indicates message flags
     and it is used to determine how the message can be interpreted
     (like it may tell the message is multimedia message). */
  void (*channel_message)(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcChannelEntry channel,
			  SilcMessagePayload payload,
			  SilcChannelPrivateKey key, SilcMessageFlags flags,
			  const unsigned char *message,
			  SilcUInt32 message_len);

  /* Private message to the client. The `sender' is the sender of the
     message. The message is `message'and maybe NULL.  The `flags'
     indicates message flags  and it is used to determine how the message
     can be interpreted (like it may tell the message is multimedia
     message). */
  void (*private_message)(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessagePayload payload,
			  SilcMessageFlags flags,
			  const unsigned char *message,
			  SilcUInt32 message_len);

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
     originally sent to the command. `success' is FALSE if error occurred
     during command. `command' is the command being processed. It must be
     noted that this is not reply from server. This is merely called just
     after application has called the command. Just to tell application
     that the command really was processed. */
  void (*command)(SilcClient client, SilcClientConnection conn,
		  SilcClientCommandContext cmd_context, SilcBool success,
		  SilcCommand command, SilcStatus status);

  /* Command reply handler. This function is called always in the command reply
     function. If error occurs it will be called as well. Normal scenario
     is that it will be called after the received command data has been parsed
     and processed. The function is used to pass the received command data to
     the application.

     `conn' is the associated client connection. `cmd_payload' is the command
     payload data received from server and it can be ignored. It is provided
     if the application would like to re-parse the received command data,
     however, it must be noted that the data is parsed already by the library
     thus the payload can be ignored. `success' is FALSE if error occurred.
     In this case arguments are not sent to the application. The `status' is
     the command reply status server returned. The `command' is the command
     reply being processed. The function has variable argument list and each
     command defines the number and type of arguments it passes to the
     application (on error they are not sent).

     The arguments are sent in the same order as servers sends them.  The
     arguments are same as received from the server except for ID's.  If
     ID is received application receives the corresponding entry to the
     ID. For example, if Client ID is receives application receives
     SilcClientEntry. */
  void (*command_reply)(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, SilcBool success,
			SilcCommand command, SilcStatus status, ...);

  /* Called to indicate that connection was either successfully established
     or connecting failed.  This is also the first time application receives
     the SilcClientConnection object which it should save somewhere.
     The `status' indicated whether the connection were successful.  If it
     is error value the application must always call the function
     silc_client_close_connection. */
  void (*connected)(SilcClient client, SilcClientConnection conn,
		    SilcClientConnectionStatus status);

  /* Called to indicate that connection was disconnected to the server.
     The `status' may tell the reason of the disconnection, and if the
     `message' is non-NULL it may include the disconnection message
     received from server. Application must not call the
     silc_client_close_connection in this callback.  The 'conn' is also
     invalid after this function returns back to library. */
  void (*disconnected)(SilcClient client, SilcClientConnection conn,
		       SilcStatus status, const char *message);

  /* Find authentication method and authentication data by hostname and
     port. The hostname may be IP address as well. When the authentication
     method has been resolved the `completion' callback with the found
     authentication method and authentication data is called. The `conn'
     may be NULL. */
  void (*get_auth_method)(SilcClient client, SilcClientConnection conn,
			  char *hostname, SilcUInt16 port,
			  SilcGetAuthMeth completion, void *context);

  /* Verifies received public key. The `conn_type' indicates which entity
     (server, client etc.) has sent the public key. If user decides to trust
     the application may save the key as trusted public key for later
     use. The `completion' must be called after the public key has been
     verified. */
  void (*verify_public_key)(SilcClient client, SilcClientConnection conn,
			    SilcSocketType conn_type, unsigned char *pk,
			    SilcUInt32 pk_len, SilcSKEPKType pk_type,
			    SilcVerifyPublicKey completion, void *context);

  /* Ask (interact, that is) a passphrase from user. The passphrase is
     returned to the library by calling the `completion' callback with
     the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
     if not then the library will attempt to encode. */
  void (*ask_passphrase)(SilcClient client, SilcClientConnection conn,
			 SilcAskPassphrase completion, void *context);

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
  SilcBool (*key_agreement)(SilcClient client, SilcClientConnection conn,
		        SilcClientEntry client_entry, const char *hostname,
		        SilcUInt16 port, SilcKeyAgreementCallback *completion,
		        void **context);

  /* Notifies application that file transfer protocol session is being
     requested by the remote client indicated by the `client_entry' from
     the `hostname' and `port'. The `session_id' is the file transfer
     session and it can be used to either accept or reject the file
     transfer request, by calling the silc_client_file_receive or
     silc_client_file_close, respectively. */
  void (*ftp)(SilcClient client, SilcClientConnection conn,
	      SilcClientEntry client_entry, SilcUInt32 session_id,
	      const char *hostname, SilcUInt16 port);

  /* Delivers SILC session detachment data indicated by `detach_data' to the
     application.  If application has issued SILC_COMMAND_DETACH command
     the client session in the SILC network is not quit.  The client remains
     in the network but is detached.  The detachment data may be used later
     to resume the session in the SILC Network.  The appliation is
     responsible of saving the `detach_data', to for example in a file.

     The detachment data can be given as argument to the functions
     silc_client_connect_to_server, or silc_client_add_connection when
     creating connection to remote server, inside SilcClientConnectionParams
     structure.  If it is provided the client library will attempt to resume
     the session in the network.  After the connection is created
     successfully, the application is responsible of setting the user
     interface for user into the same state it was before detaching (showing
     same channels, channel modes, etc).  It can do this by fetching the
     information (like joined channels) from the client library. */
  void (*detach)(SilcClient client, SilcClientConnection conn,
		 const unsigned char *detach_data,
		 SilcUInt32 detach_data_len);
} SilcClientOperations;
/***/

/****f* silcclient/SilcClientAPI/SilcNicknameFormatParse
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcNicknameFormatParse)(const char *nickname,
 *                                            char **ret_nickname);
 *
 * DESCRIPTION
 *
 *    A callback function provided by the application for the library in
 *    SilcClientParams structure. This function parses the formatted
 *    nickname string `nickname' and returns the true nickname to the
 *    `ret_nickname' pointer. The library can call this function at
 *    any time.
 *
 ***/
typedef void (*SilcNicknameFormatParse)(const char *nickname,
					char **ret_nickname);

/****s* silcclient/SilcClientAPI/SilcClientParams
 *
 * NAME
 *
 *    typedef struct { ... } SilcClientParams;
 *
 * DESCRIPTION
 *
 *    Client parameters. This can be filled with proper values and
 *    given as argument to the silc_client_alloc function. The structure
 *    hold various parameters which affects the function of the client.
 *
 * SOURCE
 */
typedef struct {
  /* Number of maximum tasks the client library's scheduler can handle.
     If set to zero, the default value will be used (200). For WIN32
     systems this should be set to 64 as it is the hard limit dictated
     by the WIN32. */
  int task_max;

  /* Rekey timeout in seconds. The client will perform rekey in this
     time interval. If set to zero, the default value will be used. */
  unsigned int rekey_secs;

  /* Connection authentication method request timeout. If server does not
     reply back the current authentication method when we've requested it
     in this time interval we'll assume the reply will not come at all.
     If set to zero, the default value (2 seconds) will be used. */
  unsigned int connauth_request_secs;

  /* Nickname format string. This can be used to order the client library
     to save the nicknames in the library in a certain format. Since
     nicknames are not unique in SILC it is possible to have multiple same
     nicknames. Using this format string it is possible to order the library
     to separate the multiple same nicknames from each other. The format
     types are defined below and they can appear in any order in the format
     string. If this is NULL then default format is used which is the
     default nickname without anything else. The string MUST be NULL
     terminated.

     Following format types are available:

     %n  nickname      - the real nickname returned by the server (mandatory)
     %h  hostname      - the stripped hostname of the client
     %H  full hostname - the full hostname of the client
     %s  server name   - the server name the client is connected
     %S  full server   - the full server name the client is connected
     %a  number        - ascending number in case there are several
                         same nicknames (fe. nick@host and nick@host2)

     Example format strings: "%n@%h%a"   (fe. nick@host, nick@host2)
                             "%a!%n@%s"  (fe. nick@server, 2!nick@server)
			     "%n@%H"     (fe. nick@host.domain.com)

     By default this format is employed to the nicknames by the libary
     only when there appears multiple same nicknames. If the library has
     only one nickname cached the nickname is saved as is and without the
     defined format. If you want always to save the nickname in the defined
     format set the boolean field `nickname_force_format' to value TRUE.
  */
  char nickname_format[32];

  /* If this is set to TRUE then the `nickname_format' is employed to all
     saved nicknames even if there are no multiple same nicknames in the
     cache. By default this is FALSE, which means that the `nickname_format'
     is employed only if the library will receive a nickname that is
     already saved in the cache. It is recommended to leave this to FALSE
     value. */
  SilcBool nickname_force_format;

  /* A callback function provided by the application for the library to
     parse the nickname from the formatted nickname string. Even though
     the libary formats the nicknames the application knows generally the
     format better so this function should be provided for the library
     if the application sets the `nickname_format' field. The library
     will call this to get the true nickname from the provided formatted
     nickname string whenever it needs the true nickname. */
  SilcNicknameFormatParse nickname_parse;

  /* If this is set to TRUE then the client will ignore all incoming
     Requested Attributes queries and does not reply anything back.  This
     usually leads into situation where server does not anymore send
     the queries after seeing that client does not reply anything back.
     If your application does not support Requested Attributes or you do
     not want to use them set this to TRUE.  See SilcAttribute and
     silc_client_attribute_add for more information on attributes. */
  SilcBool ignore_requested_attributes;

  /* If this is set to TRUE, the silcclient library will not register and
     deregister the cipher, pkcs, hash and hmac algorithms. The application
     itself will need to handle that. */
  SilcBool dont_register_crypto_library;

} SilcClientParams;
/***/


/* Initialization functions (client.c) */

/****f* silcclient/SilcClientAPI/silc_client_alloc
 *
 * SYNOPSIS
 *
 *    SilcClient silc_client_alloc(SilcClientOperations *ops,
 *                                 SilcClientParams *params,
 *                                 void *application,
 *                                 const char *silc_version);
 *
 * DESCRIPTION
 *
 *    Allocates new client object. This has to be done before client may
 *    work. After calling this one must call silc_client_init to initialize
 *    the client. The `application' is application specific user data pointer
 *    and caller must free it. The `silc_version' is the application version
 *    that will be used to compare against remote host's (usually a server)
 *    version string.  The `application' context is accessible by the
 *    application by client->application, client being SilcClient.
 *
 ***/
SilcClient silc_client_alloc(SilcClientOperations *ops,
			     SilcClientParams *params,
			     void *application,
			     const char *version_string);

/****f* silcclient/SilcClientAPI/silc_client_free
 *
 * SYNOPSIS
 *
 *    void silc_client_free(SilcClient client);
 *
 * DESCRIPTION
 *
 *    Frees client object and its internals.  The execution of the client
 *    should be stopped with silc_client_stop function before calling
 *    this function.
 *
 ***/
void silc_client_free(SilcClient client);

/****f* silcclient/SilcClientAPI/silc_client_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_init(SilcClient client);
 *
 * DESCRIPTION
 *
 *    Initializes the client. This makes all the necessary steps to make
 *    the client ready to be run. One must call silc_client_run to run the
 *    client. Returns FALSE if error occurred, TRUE otherwise.
 *
 ***/
SilcBool silc_client_init(SilcClient client);

/****f* silcclient/SilcClientAPI/silc_client_run
 *
 * SYNOPSIS
 *
 *    void silc_client_run(SilcClient client);
 *
 * DESCRIPTION
 *
 *    Runs the client. This starts the scheduler from the utility library.
 *    When this functions returns the execution of the appliation is over.
 *    The client must be initialized before calling this.
 *
 ***/
void silc_client_run(SilcClient client);

/****f* silcclient/SilcClientAPI/silc_client_run_one
 *
 * SYNOPSIS
 *
 *    void silc_client_run_one(SilcClient client);
 *
 * DESCRIPTION
 *
 *    Runs the client and returns immeadiately. This function is used when
 *    the SILC Client object indicated by the `client' is run under some
 *    other scheduler, or event loop or main loop.  On GUI applications,
 *    for example this may be desired to used to run the client under the
 *    GUI application's main loop.  Typically the GUI application would
 *    register an idle task that calls this function multiple times in
 *    a second to quickly process the SILC specific data.
 *
 ***/
void silc_client_run_one(SilcClient client);

/****f* silcclient/SilcClientAPI/silc_client_stop
 *
 * SYNOPSIS
 *
 *    void silc_client_stop(SilcClient client);
 *
 * DESCRIPTION
 *
 *    Stops the client. This is called to stop the client and thus to stop
 *    the program.  The client context must be freed with the silc_client_free
 *    function.
 *
 ***/
void silc_client_stop(SilcClient client);


/* Connecting functions (client.c) */

/****s* silcclient/SilcClientAPI/SilcClientConnectionParams
 *
 * NAME
 *
 *    typedef struct { ... } SilcClientConnectionParams;
 *
 * DESCRIPTION
 *
 *    Client connection parameters.  This can be filled by the application
 *    and given as argument to silc_client_connect_to_server or to
 *    silc_client_add_connection.
 *
 * SOURCE
 */
typedef struct {
  /* The SILC session detachment data that was returned by `detach' client
     operation when the application detached from the network.  Application
     is responsible of saving the data and giving it as argument here
     for resuming the session in the SILC network.

     If this is provided here the client library will attempt to resume
     the session in the network.  After the connection is created
     successfully, the application is responsible of setting the user
     interface for user into the same state it was before detaching (showing
     same channels, channel modes, etc).  It can do this by fetching the
     information (like joined channels) from the client library. */
  unsigned char *detach_data;
  SilcUInt32 detach_data_len;

} SilcClientConnectionParams;
/***/

/****f* silcclient/SilcClientAPI/silc_client_connect_to_server
 *
 * SYNOPSIS
 *
 *    int silc_client_connect_to_server(SilcClient client,
 *                                      SilcClientConnectionParams *params,
 *                                      int port, char *host, void *context);
 *
 * DESCRIPTION
 *
 *    Connects to remote server. This is the main routine used to connect
 *    to SILC server. Returns -1 on error and the created socket otherwise.
 *    The `context' is user context that is saved into the SilcClientConnection
 *    that is created after the connection is created. Note that application
 *    may handle the connecting process outside the library. If this is the
 *    case then this function is not used at all. When the connecting is
 *    done the `connect' client operation is called, and the `context' is
 *    accessible with conn->context, conn being SilcClientConnection.
 *    If the `params' is provided they are used by the routine.
 *
 ***/
int silc_client_connect_to_server(SilcClient client,
				  SilcClientConnectionParams *params,
				  int port, char *host, void *context);

/****f* silcclient/SilcClientAPI/silc_client_add_connection
 *
 * SYNOPSIS
 *
 *
 *    SilcClientConnection
 *    silc_client_add_connection(SilcClient client,
 *                               SilcClientConnectionParams *params,
 *                               char *hostname, int port, void *context);
 *
 * DESCRIPTION
 *
 *    Allocates and adds new connection to the client. This adds the allocated
 *    connection to the connection table and returns a pointer to it. A client
 *    can have multiple connections to multiple servers. Every connection must
 *    be added to the client using this function. User data `context' may
 *    be sent as argument.  If the `params' is provided they are used by
 *    the routine.
 *
 * NOTES
 *
 *    This function is normally used only if the application performed
 *    the connecting outside the library, and did not called the
 *    silc_client_connect_to_server function at all. The library
 *    however may use this internally.
 *
 ***/
SilcClientConnection
silc_client_add_connection(SilcClient client,
			   SilcClientConnectionParams *params,
			   char *hostname, int port, void *context);

/****f* silcclient/SilcClientAPI/silc_client_del_connection
 *
 * SYNOPSIS
 *
 *    void silc_client_del_connection(SilcClient client,
 *                                    SilcClientConnection conn);
 *
 * DESCRIPTION
 *
 *    Removes connection from client. Frees all memory. The library
 *    call this function automatically for all connection contexts.
 *    The application however may free the connection contexts it has
 *    allocated.
 *
 ***/
void silc_client_del_connection(SilcClient client, SilcClientConnection conn);

/****f* silcclient/SilcClientAPI/silc_client_add_socket
 *
 * SYNOPSIS
 *
 *    void silc_client_add_socket(SilcClient client,
 *                                SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Adds listener socket to the listener sockets table. This function is
 *    used to add socket objects that are listeners to the client.  This should
 *    not be used to add other connection objects.
 *
 ***/
void silc_client_add_socket(SilcClient client, SilcSocketConnection sock);

/****f* silcclient/SilcClientAPI/silc_client_del_socket
 *
 * SYNOPSIS
 *
 *    void silc_client_del_socket(SilcClient client,
 *                                SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Deletes listener socket from the listener sockets table.  If the
 *    application has added a socket with silc_client_add_socket it must
 *    also free it using this function.
 *
 ***/
void silc_client_del_socket(SilcClient client, SilcSocketConnection sock);

/****f* silcclient/SilcClientAPI/silc_client_start_key_exchange
 *
 * SYNOPSIS
 *
 *    void silc_client_start_key_exchange(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        int fd);
 *
 * DESCRIPTION
 *
 *    Start SILC Key Exchange (SKE) protocol to negotiate shared secret
 *    key material between client and server.  This function can be called
 *    directly if application is performing its own connecting and does not
 *    use the connecting provided by this library. This function is normally
 *    used only if the application performed the connecting outside the
 *    library. The library however may use this internally.  After the
 *    key exchange is performed the `connect' client operation is called.
 *
 * NOTES
 *
 *    The silc_client_add_connection must be called before calling this
 *    function to create the SilcClientConnection context for this
 *    connection.
 *
 ***/
void silc_client_start_key_exchange(SilcClient client,
				    SilcClientConnection conn,
				    int fd);

/****f* silcclient/SilcClientAPI/silc_client_close_connection
 *
 * SYNOPSIS
 *
 *    void silc_client_close_connection(SilcClient client,
 *                                      SilcClientConnection conn);
 *
 * DESCRIPTION
 *
 *    Closes connection to remote end. Free's all allocated data except
 *    for some information such as nickname etc. that are valid at all time.
 *    Usually application does not need to directly call this, except
 *    when explicitly closing the connection, or if an error occurs
 *    during connection to server (see 'connect' client operation for
 *    more information).
 *
 ***/
void silc_client_close_connection(SilcClient client,
				  SilcClientConnection conn);


/* Message sending functions (client_channel.c and client_prvmsg.c) */

/****f* silcclient/SilcClientAPI/silc_client_send_channel_message
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_send_channel_message(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcChannelEntry channel,
 *                                          SilcChannelPrivateKey key,
 *                                          SilcMessageFlags flags,
 *                                          unsigned char *data,
 *                                          SilcUInt32 data_len,
 *                                          SilcBool force_send);
 *
 * DESCRIPTION
 *
 *    Sends packet to the `channel'. Packet to channel is always encrypted
 *    differently from "normal" packets. SILC header of the packet is
 *    encrypted with the next receiver's key and the rest of the packet is
 *    encrypted with the channel specific key. Padding and HMAC is computed
 *    with the next receiver's key. The `data' is the channel message. If
 *    the `force_send' is TRUE then the packet is sent immediately.
 *
 *    If `key' is provided then that private key is used to encrypt the
 *    channel message.  If it is not provided, private keys has not been
 *    set at all, the normal channel key is used automatically.  If private
 *    keys are set then the first key (the key that was added first as
 *    private key) is used.
 *
 *    If the `flags' includes SILC_MESSAGE_FLAG_SIGNED the message will be
 *    digitally signed with the SILC key pair.
 *
 *    Returns TRUE if the message was sent, and FALSE if error occurred or
 *    the sending is not allowed due to channel modes (like sending is
 *    blocked).
 *
 ***/
SilcBool silc_client_send_channel_message(SilcClient client,
				      SilcClientConnection conn,
				      SilcChannelEntry channel,
				      SilcChannelPrivateKey key,
				      SilcMessageFlags flags,
				      unsigned char *data,
				      SilcUInt32 data_len,
				      SilcBool force_send);

/****f* silcclient/SilcClientAPI/silc_client_send_private_message
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_send_private_message(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcClientEntry client_entry,
 *                                          SilcMessageFlags flags,
 *                                          unsigned char *data,
 *                                          SilcUInt32 data_len,
 *                                          SilcBool force_send);
 *
 * DESCRIPTION
 *
 *    Sends private message to remote client. If private message key has
 *    not been set with this client then the message will be encrypted using
 *    normal session keys. Private messages are special packets in SILC
 *    network hence we need this own function for them. This is similar
 *    to silc_client_packet_send_to_channel except that we send private
 *    message. The `data' is the private message. If the `force_send' is
 *    TRUE the packet is sent immediately.
 *
 *    If the `flags' includes SILC_MESSAGE_FLAG_SIGNED the message will be
 *    digitally signed with the SILC key pair.
 *
 *    Returns TRUE if the message was sent, and FALSE if error occurred.
 *
 ***/
SilcBool silc_client_send_private_message(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry,
				      SilcMessageFlags flags,
				      unsigned char *data,
				      SilcUInt32 data_len,
				      SilcBool force_send);


/* Client and Channel entry retrieval (idlist.c) */

/****f* silcclient/SilcClientAPI/SilcGetClientCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcGetClientCallback)(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcClientEntry *clients,
 *                                          SilcUInt32 clients_count,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Callback function given to the silc_client_get_client function. The
 *    found entries are allocated into the `clients' array. The array must
 *    not be freed by the receiver, the library will free it later. If the
 *    `clients' is NULL, no such clients exist in the SILC Network.
 *
 ***/
typedef void (*SilcGetClientCallback)(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry *clients,
				      SilcUInt32 clients_count,
				      void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients
 *
 * SYNOPSIS
 *
 *    void silc_client_get_clients(SilcClient client,
 *                                 SilcClientConnection conn,
 *                                 const char *nickname,
 *                                 const char *server,
 *                                 SilcGetClientCallback completion,
 *                                 void *context);
 *
 * DESCRIPTION
 *
 *    Finds client entry or entries by the `nickname' and `server'. The
 *    completion callback will be called when the client entries has been
 *    found.  After the server returns the client information it is cached
 *    and can be accesses locally at a later time.  The resolving is done
 *    with IDENTIFY command.  The `server' may be NULL.
 *
 * NOTES
 *
 *    NOTE: This function is always asynchronous and resolves the client
 *    information from the server. Thus, if you already know the client
 *    information then use the silc_client_get_client_by_id function to
 *    get the client entry since this function may be very slow and should
 *    be used only to initially get the client entries.
 *
 *    Since this routine resolves with IDENTIFY command only the relevant
 *    information (user's nickname and username) is resolved.  For example,
 *    user's real name, channel list and others are not resolved.  Caller
 *    can/must resolve those separately if they are needed (for example,
 *    with silc_client_get_client_by_id_resolve).
 *
 ***/
void silc_client_get_clients(SilcClient client,
			     SilcClientConnection conn,
			     const char *nickname,
			     const char *server,
			     SilcGetClientCallback completion,
			     void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_whois
 *
 * SYNOPSIS
 *
 *    void silc_client_get_clients_whois(SilcClient client,
 *                                       SilcClientConnection conn,
 *                                       const char *nickname,
 *                                       const char *server,
 *                                       SilcBuffer attributes,
 *                                       SilcGetClientCallback completion,
 *                                       void *context);
 *
 * DESCRIPTION
 *
 *    Finds client entry or entries by the `nickname' and `server'. The
 *    completion callback will be called when the client entries has been
 *    found.  After the server returns the client information it is cached
 *    and can be accesses locally at a later time.  The resolving is done
 *    with WHOIS command.  The `server' may be NULL.
 *
 *    If the `attributes' is non-NULL then the buffer includes Requested
 *    Attributes which can be used to fetch very detailed information
 *    about the user. If it is NULL then only normal WHOIS query is
 *    made (for more information about attributes see SilcAttribute).
 *    Caller may create the `attributes' with silc_client_attributes_request
 *    function.
 *
 * NOTES
 *
 *    The resolving is done with WHOIS command. For this reason this
 *    command may take a long time because it resolves detailed user
 *    information.
 *
 ***/
void silc_client_get_clients_whois(SilcClient client,
				   SilcClientConnection conn,
				   const char *nickname,
				   const char *server,
				   SilcBuffer attributes,
				   SilcGetClientCallback completion,
				   void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_local
 *
 * SYNOPSIS
 *
 *    SilcClientEntry *silc_client_get_clients_local(SilcClient client,
 *                                                   SilcClientConnection conn,
 *                                                   const char *nickname,
 *                                                   const char *format,
 *                                                   SilcUInt32 *clients_count);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_get_clients function but does not resolve anything
 *    from the server. This checks local cache and returns all matching
 *    clients from the local cache. If none was found this returns NULL.
 *    The `nickname' is the real nickname of the client, and the `format'
 *    is the formatted nickname to find exact match from multiple found
 *    entries. The format must be same as given in the SilcClientParams
 *    structure to the client library. If the `format' is NULL all found
 *    clients by `nickname' are returned. The caller must return the
 *    returned array.
 *
 ***/
SilcClientEntry *silc_client_get_clients_local(SilcClient client,
					       SilcClientConnection conn,
					       const char *nickname,
					       const char *format,
					       SilcUInt32 *clients_count);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_by_channel
 *
 * SYNOPSIS
 *
 *    void silc_client_get_clients_by_channel(SilcClient client,
 *                                            SilcClientConnection conn,
 *                                            SilcChannelEntry channel,
 *                                            SilcGetClientCallback completion,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    Gets client entries by the channel indicated by `channel'. Thus,
 *    it resovles the users currently on that channel. If all users are
 *    already resolved this returns the users from the channel. If the
 *    users are resolved only partially this resolves the complete user
 *    information. If no users are resolved on this channel at all, this
 *    calls USERS command to resolve all users on the channel. The `completion'
 *    will be called after the entries are available. When server returns
 *    the client information it will be cached and can be accessed locally
 *    at a later time.
 *
 *    This function can be used for example in SILC_COMMAND_JOIN command
 *    reply handling in application to resolve users on that channel.  It
 *    also can be used after calling silc_client_get_channel_resolve to
 *    resolve users on that channel.
 *
 * NOTES
 *
 *    The resolving is done with WHOIS command. For this reason this
 *    command may take a long time because it resolves detailed user
 *    information.
 *
 ***/
void silc_client_get_clients_by_channel(SilcClient client,
					SilcClientConnection conn,
					SilcChannelEntry channel,
					SilcGetClientCallback completion,
					void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_clients_by_list
 *
 * SYNOPSIS
 *
 *    void silc_client_get_clients_by_list(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcUInt32 list_count,
 *                                         SilcBuffer client_id_list,
 *                                         SilcGetClientCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Gets client entries by the list of client ID's `client_id_list'. This
 *    always resolves those client ID's it does not know yet from the server
 *    so this function might take a while. The `client_id_list' is a list
 *    of ID Payloads added one after other.  JOIN command reply and USERS
 *    command reply for example returns this sort of list. The `completion'
 *    will be called after the entries are available. When server returns
 *    the client information it will be cached and can be accessed locally
 *    at a later time.
 *
 * NOTES
 *
 *    The resolving is done with IDENTIFY command. This means that only
 *    the relevant information of user (it's nickname and username) is
 *    resolved. For example, user's real name, channel lists and others
 *    are not resolved. Caller can/must resolve those separately if they
 *    are needed (for example, with silc_client_get_client_by_id_resolve).
 *
 ***/
void silc_client_get_clients_by_list(SilcClient client,
				     SilcClientConnection conn,
				     SilcUInt32 list_count,
				     SilcBuffer client_id_list,
				     SilcGetClientCallback completion,
				     void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_client_by_id
 *
 * SYNOPSIS
 *
 *    SilcClientEntry silc_client_get_client_by_id(SilcClient client,
 *                                                 SilcClientConnection conn,
 *                                                 SilcClientID *client_id);
 *
 * DESCRIPTION
 *
 *    Find entry for client by the client's ID. Returns the entry or NULL
 *    if the entry was not found.  This checks the local cache and does
 *    not resolve anything from server.
 *
 ***/
SilcClientEntry silc_client_get_client_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientID *client_id);

/****f* silcclient/SilcClientAPI/silc_client_get_client_by_id_resolve
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_get_client_by_id_resolve(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcClientID *client_id,
 *                                         SilcBuffer attributes,
 *                                         SilcGetClientCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_get_client_by_id but will always resolve the
 *    information from the server. Use this only if you know that you
 *    do not have the entry and the only thing you know about the client
 *    is its ID. When server returns the client information it will be
 *    cache and can be accessed locally at a later time. The resolving
 *    is done by sending WHOIS command.
 *
 *    If the `attributes' is non-NULL then the buffer includes Requested
 *    Attributes which can be used to fetch very detailed information
 *    about the user. If it is NULL then only normal WHOIS query is
 *    made (for more information about attributes see SilcAttribute).
 *    Caller may create the `attributes' with silc_client_attributes_request
 *    function.
 *
 ***/
void silc_client_get_client_by_id_resolve(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientID *client_id,
					  SilcBuffer attributes,
					  SilcGetClientCallback completion,
					  void *context);

/****f* silcclient/SilcClientAPI/silc_client_del_client
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_client(SilcClient client, SilcClientConnection conn,
 *                                SilcClientEntry client_entry)
 *
 * DESCRIPTION
 *
 *    Removes client from local cache by the client entry indicated by
 *    the `client_entry'.  Returns TRUE if the deletion were successful.
 *
 ***/
SilcBool silc_client_del_client(SilcClient client, SilcClientConnection conn,
			    SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/SilcGetChannelCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcGetChannelCallback)(SilcClient client,
 *                                           SilcClientConnection conn,
 *                                           SilcChannelEntry *channels,
 *                                           SilcUInt32 channels_count,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    Callback function given to the silc_client_get_channel_* functions.
 *    The found entries are allocated into the `channels' array. The array
 *    must not be freed by the receiver, the library will free it later.
 *    If the `channel' is NULL, no such channel exist in the SILC Network.
 *
 ***/
typedef void (*SilcGetChannelCallback)(SilcClient client,
				       SilcClientConnection conn,
				       SilcChannelEntry *channels,
				       SilcUInt32 channels_count,
				       void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_channel
 *
 * SYNOPSIS
 *
 *    SilcChannelEntry silc_client_get_channel(SilcClient client,
 *                                             SilcClientConnection conn,
 *                                             char *channel_name);
 *
 * DESCRIPTION
 *
 *    Finds entry for channel by the channel name. Returns the entry or NULL
 *    if the entry was not found. It is found only if the client is joined
 *    to the channel.  Use silc_client_get_channel_resolve or
 *    silc_client_get_channel_by_id_resolve to resolve channel that client
 *    is not joined.
 *
 ***/
SilcChannelEntry silc_client_get_channel(SilcClient client,
					 SilcClientConnection conn,
					 char *channel_name);

/****f* silcclient/SilcClientAPI/silc_client_get_channel_resolve
 *
 * SYNOPSIS
 *
 *    void silc_client_get_channel_resolve(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         char *channel_name,
 *                                         SilcGetChannelCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Resolves entry for channel by the channel name from the server.
 *    The resolving is done with IDENTIFY command. Note that users on
 *    the channel are not resolved at the same time. Use for example
 *    silc_client_get_clients_by_channel to resolve all users on a channel.
 *
 ***/
void silc_client_get_channel_resolve(SilcClient client,
				     SilcClientConnection conn,
				     char *channel_name,
				     SilcGetChannelCallback completion,
				     void *context);

/****f* silcclient/SilcClientAPI/silc_client_get_channel_by_id
 *
 * SYNOPSIS
 *
 *    SilcChannelEntry
 *    silc_client_get_channel_by_id(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  SilcChannelID *channel_id);
 *
 * DESCRIPTION
 *
 *    Finds channel entry by the channel ID. Returns the entry or NULL
 *    if the entry was not found.  This checks the local cache and does
 *    not resolve anything from server.
 *
 ***/
SilcChannelEntry silc_client_get_channel_by_id(SilcClient client,
					       SilcClientConnection conn,
					       SilcChannelID *channel_id);

/****f* silcclient/SilcClientAPI/silc_client_get_channel_by_id_resolve
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_get_channel_by_id_resolve(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcChannelID *channel_id,
 *                                          SilcGetClientCallback completion,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Resolves the channel information (its name mainly) from the server
 *    by the `channel_id'. Use this only if you know that you do not have
 *    the entry cached locally. The resolving is done with IDENTIFY command.
 *
 *    Note that users on the channel are not resolved at the same time.
 *    Use for example silc_client_get_clients_by_channel to resolve all
 *    users on a channel.
 *
 ***/
void silc_client_get_channel_by_id_resolve(SilcClient client,
					   SilcClientConnection conn,
					   SilcChannelID *channel_id,
					   SilcGetChannelCallback completion,
					   void *context);

/****f* silcclient/SilcClientAPI/silc_client_del_channel
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_channel(SilcClient client,
 *                                 SilcClientConnection conn,
 *                                 SilcChannelEntry channel)
 *
 * DESCRIPTION
 *
 *    Removes channel from local cache by the channel entry indicated by
 *    the `channel'.  Returns TRUE if the deletion were successful.
 *
 ***/
SilcBool silc_client_del_channel(SilcClient client, SilcClientConnection conn,
			     SilcChannelEntry channel);

/****f* silcclient/SilcClientAPI/silc_client_get_server
 *
 * SYNOPSIS
 *
 *    SilcServerEntry silc_client_get_server(SilcClient client,
 *                                           SilcClientConnection conn,
 *                                           char *server_name)
 *
 * DESCRIPTION
 *
 *    Finds entry for server by the server name. Returns the entry or NULL
 *    if the entry was not found.
 *
 ***/
SilcServerEntry silc_client_get_server(SilcClient client,
				       SilcClientConnection conn,
				       char *server_name);

/****f* silcclient/SilcClientAPI/silc_client_get_server_by_id
 *
 * SYNOPSIS
 *
 *    SilcServerEntry silc_client_get_server_by_id(SilcClient client,
 *                                                 SilcClientConnection conn,
 *                                                 SilcServerID *server_id);
 *
 * DESCRIPTION
 *
 *    Finds entry for server by the server ID. Returns the entry or NULL
 *    if the entry was not found.
 *
 ***/
SilcServerEntry silc_client_get_server_by_id(SilcClient client,
					     SilcClientConnection conn,
					     SilcServerID *server_id);

/****f* silcclient/SilcClientAPI/silc_client_del_server
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_server(SilcClient client, SilcClientConnection conn,
 *                                SilcServerEntry server);
 *
 * DESCRIPTION
 *
 *    Removes server from local cache by the server entry indicated by
 *    the `server'.  Returns TRUE if the deletion were successful.
 *
 ***/
SilcBool silc_client_del_server(SilcClient client, SilcClientConnection conn,
			    SilcServerEntry server);

/****f* silcclient/SilcClientAPI/silc_client_on_channel
 *
 * SYNOPSIS
 *
 *    SilcChannelUser silc_client_on_channel(SilcChannelEntry channel,
 *                                           SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Returns the SilcChannelUser entry if the `client_entry' is joined on the
 *    channel indicated by the `channel'. NULL if client is not joined on
 *    the channel.
 *
 ***/
SilcChannelUser silc_client_on_channel(SilcChannelEntry channel,
				       SilcClientEntry client_entry);

/* Command management (command.c) */

/****f* silcclient/SilcClientAPI/silc_client_command_call
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_command_call(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  const char *command_line, ...);
 *
 * DESCRIPTION
 *
 *    Calls and executes the command indicated by the `command_name'.
 *    The `command_line' is a string which includes the command's name and
 *    its arguments separated with whitespaces (' ').  If `command_line'
 *    is non-NULL then all variable arguments are ignored by default.
 *
 *    If `command_line' is NULL, then the variable arguments define the
 *    command's name and its arguments.  The first variable argument must
 *    be the command name.  The variable argument list must be terminated
 *    with NULL.
 *
 *    Returns FALSE if the command is not known and TRUE after command.
 *    execution.  The "command" client operation is called when the
 *    command is executed to indicate whether the command executed
 *    successfully or not.
 *
 *    The "command_reply" client operation will be called when reply is
 *    received from the server to the command.  Application may also use
 *    the silc_client_command_pending to attach to the command reply.
 *    The command identifier for silc_client_command_pending function after
 *    this function call is conn->cmd_ident, which application may use.
 *
 * EXAMPLE
 *
 *    silc_client_command_call(client, conn, NULL, "PING", "silc.silcnet.org",
 *                             NULL);
 *    silc_client_command_call(client, conn, "PING silc.silcnet.org");
 *
 * NOTES
 *
 *    This command executes the commands implemented inside the client
 *    library.  These commands are designed for command line applications,
 *    but GUI application may call them too if needed.  Alternatively
 *    application may override the library and use silc_client_command_send
 *    function instead.
 *
 ***/
SilcBool silc_client_command_call(SilcClient client,
			      SilcClientConnection conn,
			      const char *command_line, ...);

/****f* silcclient/SilcClientAPI/silc_client_command_send
 *
 * SYNOPSIS
 *
 *    void silc_client_command_send(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  SilcCommand command, SilcUInt16 ident,
 *                                  SilcUInt32 argc, ...);
 *
 * DESCRIPTION
 *
 *    Generic function to send any command. The arguments must be sent already
 *    encoded into correct form and in correct order. If application wants
 *    to perform the commands by itself, it can do so and send the data
 *    directly to the server using this function.  If application is using
 *    the silc_client_command_call, this function is usually not used.
 *    Note that this overriders the Client Librarys commands and sends
 *    the command packet directly to server.
 *
 *    Programmer should get familiar with the SILC protocol commands
 *    specification when using this function, as the arguments needs to
 *    be encoded as specified in the protocol.
 *
 *    The variable arguments are a pair of { type, data, data_length },
 *    and the `argc' is the number of these pairs.
 *
 * EXAMPLE
 *
 *    silc_client_command_send(client, conn, SILC_COMMAND_WHOIS, 0, 1,
 *                             1, nickname, strlen(nickname));
 *
 ***/
void silc_client_command_send(SilcClient client, SilcClientConnection conn,
			      SilcCommand command, SilcUInt16 ident,
			      SilcUInt32 argc, ...);

/****f* silcclient/SilcClientAPI/silc_client_command_pending
 *
 * SYNOPSIS
 *
 *    void silc_client_command_pending(SilcClientConnection conn,
 *                                     SilcCommand reply_cmd,
 *                                     SilcUInt16 ident,
 *                                     SilcCommandCb callback,
 *                                     void *context);
 *
 * DESCRIPTION
 *
 *    This function can be used to add pending command callback to be
 *    called when an command reply is received to an earlier sent command.
 *    The `reply_cmd' is the command that must be received in order for
 *    the pending command callback indicated by `callback' to be called.
 *    The `callback' will deliver the `context' and
 *    SilcClientCommandReplyContext which includes the internals of the
 *    command reply.
 *
 *    The `ident' is a command identifier which was set for the earlier
 *    sent command.  The command reply will include the same identifier
 *    and pending command callback will be called when the reply is
 *    received with the same command identifier.  It is possible to
 *    add multiple pending command callbacks for same command and for
 *    same identifier.
 *
 *    Application may use this function to add its own command reply
 *    handlers if it wishes not to use the standard `command_reply'
 *    client operation.  However, note that the pending command callback
 *    does not deliver parsed command reply, but application must parse
 *    it itself.
 *
 *    Note also that the application is notified about the received command
 *    reply through the `command_reply' client operation before calling
 *    the `callback` pending command callback.  That is the normal
 *    command reply handling, and is called regardless whether pending
 *    command callbacks are used or not.
 *
 *    Commands that application calls with silc_client_command_call
 *    will use a command identifier from conn->cmd_ident variable.  After
 *    calling the silc_client_command_call, the conn->cmd_ident includes
 *    the command identifier that was used for the command sending.
 *
 * EXAMPLE
 *
 *    silc_client_command_call(client, conn, "PING silc.silcnet.org");
 *    silc_client_command_pending(conn, SILC_COMMAND_PING, conn->cmd_ident,
 *                                my_ping_handler, my_ping_context);
 *
 ***/
void silc_client_command_pending(SilcClientConnection conn,
				 SilcCommand reply_cmd,
				 SilcUInt16 ident,
				 SilcCommandCb callback,
				 void *context);


/* Private Message key management (client_prvmsg.c) */

/****f* silcclient/SilcClientAPI/silc_client_add_private_message_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_add_private_message_key(SilcClient client,
 *                                             SilcClientConnection conn,
 *                                             SilcClientEntry client_entry,
 *                                             const char *cipher,
 *                                             const char *hmac,
 *                                             unsigned char *key,
 *                                             SilcUInt32 key_len,
 *                                             SilcBool generate_key,
 *                                             SilcBool responder);
 *
 * DESCRIPTION
 *
 *    Adds private message key to the client library. The key will be used to
 *    encrypt all private message between the client and the remote client
 *    indicated by the `client_entry'. If the `key' is NULL and the boolean
 *    value `generate_key' is TRUE the library will generate random key.
 *    The `key' maybe for example pre-shared-key, passphrase or similar.
 *    The `cipher' and `hmac' MAY be provided but SHOULD be NULL to assure
 *    that the requirements of the SILC protocol are met. The API, however,
 *    allows to allocate any cipher and HMAC.
 *
 *    If `responder' is TRUE then the sending and receiving keys will be
 *    set according the client being the receiver of the private key.  If
 *    FALSE the client is being the sender (or negotiator) of the private
 *    key.
 *
 *    It is not necessary to set key for normal private message usage. If the
 *    key is not set then the private messages are encrypted using normal
 *    session keys. Setting the private key, however, increases the security.
 *
 *    Returns FALSE if the key is already set for the `client_entry', TRUE
 *    otherwise.
 *
 ***/
SilcBool silc_client_add_private_message_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 const char *cipher,
					 const char *hmac,
					 unsigned char *key,
					 SilcUInt32 key_len,
					 SilcBool generate_key,
					 SilcBool responder);

/****f* silcclient/SilcClientAPI/silc_client_add_private_message_key_ske
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_add_private_message_key_ske(SilcClient client,
 *                                            SilcClientConnection conn,
 *                                            SilcClientEntry client_entry,
 *                                            const char *cipher,
 *                                            const char *hmac,
 *                                            SilcSKEKeyMaterial *key);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_add_private_message_key but takes the key material
 *    from the SKE key material structure. This structure is received if
 *    the application uses the silc_client_send_key_agreement to negotiate
 *    the key material. The `cipher' and `hmac' SHOULD be provided as it is
 *    negotiated also in the SKE protocol.
 *
 ***/
SilcBool silc_client_add_private_message_key_ske(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry,
					     const char *cipher,
					     const char *hmac,
					     SilcSKEKeyMaterial *key,
					     SilcBool responder);

/****f* silcclient/SilcClientAPI/silc_client_del_private_message_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_private_message_key(SilcClient client,
 *                                             SilcClientConnection conn,
 *                                             SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Removes the private message from the library. The key won't be used
 *    after this to protect the private messages with the remote `client_entry'
 *    client. Returns FALSE on error, TRUE otherwise.
 *
 ***/
SilcBool silc_client_del_private_message_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_list_private_message_keys
 *
 * SYNOPSIS
 *
 *    SilcPrivateMessageKeys
 *    silc_client_list_private_message_keys(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcUInt32 *key_count);
 *
 * DESCRIPTION
 *
 *    Returns array of set private message keys associated to the connection
 *    `conn'. Returns allocated SilcPrivateMessageKeys array and the array
 *    count to the `key_count' argument. The array must be freed by the caller
 *    by calling the silc_client_free_private_message_keys function. Note:
 *    the keys returned in the array is in raw format. It might not be desired
 *    to show the keys as is. The application might choose not to show the keys
 *    at all or to show the fingerprints of the keys.
 *
 ***/
SilcPrivateMessageKeys
silc_client_list_private_message_keys(SilcClient client,
				      SilcClientConnection conn,
				      SilcUInt32 *key_count);

/****f* silcclient/SilcClientAPI/silc_client_send_private_message_key_request
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_send_private_message_key_request(SilcClient client,
 *                                               SilcClientConnection conn,
 *                                               SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    This function can be used to send an private message key indicator
 *    request to the remote client indicated by 'client_entry'.  This can
 *    be used when setting a static or pre-shared private message key.
 *    The sender of this packet is the initiator and must set the 'responder'
 *    argument in silc_client_add_private_message_key function to FALSE.
 *    The receiver of this indicator request must set it to TRUE, if the
 *    receiver decides to set a private message key.  By using this
 *    function applications may automate initiator/responder setting in
 *    private message key functions, without asking from user which one is
 *    the initiator and which one is responder.
 *
 * NOTES
 *
 *    The sender of this packet must set the private message key for
 *    'client_entry' before calling this function.  The 'responder'
 *    argument MUST be set to FALSE when setting the key.
 *
 ***/
SilcBool
silc_client_send_private_message_key_request(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_free_private_message_keys
 *
 * SYNOPSIS
 *
 *    void silc_client_free_private_message_keys(SilcPrivateMessageKeys keys,
 *                                               SilcUInt32 key_count);
 *
 * DESCRIPTION
 *
 *    Frees the SilcPrivateMessageKeys array returned by the function
 *    silc_client_list_private_message_keys.
 *
 ***/
void silc_client_free_private_message_keys(SilcPrivateMessageKeys keys,
					   SilcUInt32 key_count);


/* Channel private key management (client_channel.c,
   SilcChannelPrivateKey is defined in idlist.h) */

/****f* silcclient/SilcClientAPI/silc_client_add_channel_private_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_add_channel_private_key(SilcClient client,
 *                                             SilcClientConnection conn,
 *                                             SilcChannelEntry channel,
 *                                             const char *name,
 *                                             char *cipher,
 *                                             char *hmac,
 *                                             unsigned char *key,
 *                                             SilcUInt32 key_len,
 *                                             SilcChannelPrivateKey *ret_key);
 *
 * DESCRIPTION
 *
 *    Adds private key for channel. When channel has private key then the
 *    messages are encrypted using that key. All clients on the channel
 *    must also know the key in order to decrypt the messages. However,
 *    it is possible to have several private keys per one channel. In this
 *    case only some of the clients on the channel may know the one key
 *    and only some the other key.  The `name' can be application given
 *    name for the key.  This returns the created key to the 'ret_key'
 *    pointer if it is non-NULL;
 *
 *    If `cipher' and/or `hmac' is NULL then default values will be used
 *    (aes-256-cbc for cipher and hmac-sha1-96 for hmac).
 *
 *    The private key for channel is optional. If it is not set then the
 *    channel messages are encrypted using the channel key generated by the
 *    server. However, setting the private key (or keys) for the channel
 *    significantly adds security. If more than one key is set the library
 *    will automatically try all keys at the message decryption phase. Note:
 *    setting many keys slows down the decryption phase as all keys has to
 *    be tried in order to find the correct decryption key. However, setting
 *    a few keys does not have big impact to the decryption performace.
 *
 * NOTES
 *
 *    NOTE: This is entirely local setting. The key set using this function
 *    is not sent to the network at any phase.
 *
 *    NOTE: If the key material was originated by the SKE protocol (using
 *    silc_client_send_key_agreement) then the `key' MUST be the
 *    key->send_enc_key as this is dictated by the SILC protocol. However,
 *    currently it is not expected that the SKE key material would be used
 *    as channel private key. However, this API allows it.
 *
 ***/
SilcBool silc_client_add_channel_private_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcChannelEntry channel,
					 const char *name,
					 char *cipher,
					 char *hmac,
					 unsigned char *key,
					 SilcUInt32 key_len,
					 SilcChannelPrivateKey *ret_key);

/****f* silcclient/SilcClientAPI/silc_client_del_channel_private_keys
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_channel_private_keys(SilcClient client,
 *                                              SilcClientConnection conn,
 *                                              SilcChannelEntry channel);
 *
 * DESCRIPTION
 *
 *    Removes all private keys from the `channel'. The old channel key is used
 *    after calling this to protect the channel messages. Returns FALSE on
 *    on error, TRUE otherwise.
 *
 ***/
SilcBool silc_client_del_channel_private_keys(SilcClient client,
					  SilcClientConnection conn,
					  SilcChannelEntry channel);

/****f* silcclient/SilcClientAPI/silc_client_del_channel_private_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_del_channel_private_key(SilcClient client,
 *                                            SilcClientConnection conn,
 *                                            SilcChannelEntry channel,
 *                                            SilcChannelPrivateKey key);
 *
 * DESCRIPTION
 *
 *    Removes and frees private key `key' from the channel `channel'.
 *    The `key' is retrieved by calling the function
 *    silc_client_list_channel_private_keys. The key is not used after
 *    this. If the key was last private key then the old channel key is
 *    used hereafter to protect the channel messages. This returns FALSE
 *    on error, TRUE otherwise.
 *
 ***/
SilcBool silc_client_del_channel_private_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcChannelEntry channel,
					 SilcChannelPrivateKey key);

/****f* silcclient/SilcClientAPI/silc_client_list_channel_private_keys
 *
 * SYNOPSIS
 *
 *    SilcChannelPrivateKey *
 *    silc_client_list_channel_private_keys(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcChannelEntry channel,
 *                                          SilcUInt32 *key_count);
 *
 * DESCRIPTION
 *
 *    Returns array (pointers) of private keys associated to the `channel'.
 *    The caller must free the array by calling the function
 *    silc_client_free_channel_private_keys. The pointers in the array may be
 *    used to delete the specific key by giving the pointer as argument to the
 *    function silc_client_del_channel_private_key.
 *
 ***/
SilcChannelPrivateKey *
silc_client_list_channel_private_keys(SilcClient client,
				      SilcClientConnection conn,
				      SilcChannelEntry channel,
				      SilcUInt32 *key_count);

/****f* silcclient/SilcClientAPI/silc_client_free_channel_private_keys
 *
 * SYNOPSIS
 *
 *    void silc_client_free_channel_private_keys(SilcChannelPrivateKey *keys,
 *                                               SilcUInt32 key_count);
 *
 * DESCRIPTION
 *
 *    Frees the SilcChannelPrivateKey array.
 *
 ***/
void silc_client_free_channel_private_keys(SilcChannelPrivateKey *keys,
					   SilcUInt32 key_count);

/****f* silcclient/SilcClientAPI/silc_client_current_channel_private_key
 *
 * SYNOPSIS
 *
 *    void silc_client_current_channel_private_key(SilcClient client,
 *                                                 SilcClientConnection conn,
 *                                                 SilcChannelEntry channel,
 *                                                 SilcChannelPrivateKey key);
 *
 * DESCRIPTION
 *
 *    Sets the `key' to be used as current channel private key on the
 *    `channel'.  Packet sent after calling this function will be secured
 *    with `key'.
 *
 ***/
void silc_client_current_channel_private_key(SilcClient client,
					     SilcClientConnection conn,
					     SilcChannelEntry channel,
					     SilcChannelPrivateKey key);


/* Key Agreement routines (client_keyagr.c) */

/****f* silcclient/SilcClientAPI/silc_client_send_key_agreement
 *
 * SYNOPSIS
 *
 *    void silc_client_send_key_agreement(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        SilcClientEntry client_entry,
 *                                        char *hostname,
 *                                        int port,
 *                                        SilcUInt32 timeout_secs,
 *                                        SilcKeyAgreementCallback completion,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Sends key agreement request to the remote client indicated by the
 *    `client_entry'. If the caller provides the `hostname' and the `port'
 *    arguments then the library will bind the client to that hostname and
 *    that port for the key agreement protocol. It also sends the `hostname'
 *    and the `port' in the key agreement packet to the remote client. This
 *    would indicate that the remote client may initiate the key agreement
 *    protocol to the `hostname' on the `port'.  If port is zero then the
 *    bound port is undefined (the operating system defines it).
 *
 *    If the `hostname' and `port' is not provided then empty key agreement
 *    packet is sent to the remote client. The remote client may reply with
 *    the same packet including its hostname and port. If the library receives
 *    the reply from the remote client the `key_agreement' client operation
 *    callback will be called to verify whether the user wants to perform the
 *    key agreement or not.
 *
 * NOTES
 *
 *    NOTE: If the application provided the `hostname' and the `port' and the
 *    remote side initiates the key agreement protocol it is not verified
 *    from the user anymore whether the protocol should be executed or not.
 *    By setting the `hostname' and `port' the user gives permission to
 *    perform the protocol (we are responder in this case).
 *
 *    NOTE: If the remote side decides not to initiate the key agreement
 *    or decides not to reply with the key agreement packet then we cannot
 *    perform the key agreement at all. If the key agreement protocol is
 *    performed the `completion' callback with the `context' will be called.
 *    If remote side decides to ignore the request the `completion' will be
 *    called after the specified timeout, `timeout_secs'.
 *
 *    NOTE: If the `hostname' and the `port' was not provided the `completion'
 *    will not be called at all since this does nothing more than sending
 *    a packet to the remote host.
 *
 *    NOTE: There can be only one active key agreement for one client entry.
 *    Before setting new one, the old one must be finished (it is finished
 *    after calling the completion callback) or the function
 *    silc_client_abort_key_agreement must be called.
 *
 ***/
void silc_client_send_key_agreement(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry,
				    const char *hostname,
				    const char *bindhost,
				    int port,
				    SilcUInt32 timeout_secs,
				    SilcKeyAgreementCallback completion,
				    void *context);

/****f* silcclient/SilcClientAPI/silc_client_perform_key_agreement
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_perform_key_agreement(SilcClient client,
 *                                      SilcClientConnection conn,
 *                                      SilcClientEntry client_entry,
 *                                      char *hostname,
 *                                      int port,
 *                                      SilcKeyAgreementCallback completion,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Performs the actual key agreement protocol. Application may use this
 *    to initiate the key agreement protocol. This can be called for example
 *    after the application has received the `key_agreement' client operation,
 *    and did not return TRUE from it.
 *
 *    The `hostname' is the remote hostname (or IP address) and the `port'
 *    is the remote port. The `completion' callback with the `context' will
 *    be called after the key agreement protocol.
 *
 * NOTES
 *
 *    NOTE: If the application returns TRUE in the `key_agreement' client
 *    operation the library will automatically start the key agreement. In this
 *    case the application must not call this function. However, application
 *    may choose to just ignore the `key_agreement' client operation (and
 *    merely just print information about it on the screen) and call this
 *    function when the user whishes to do so (by, for example, giving some
 *    specific command). Thus, the API provides both, automatic and manual
 *    initiation of the key agreement. Calling this function is the manual
 *    initiation and returning TRUE in the `key_agreement' client operation
 *    is the automatic initiation.
 *
 ***/
void silc_client_perform_key_agreement(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry,
				       char *hostname,
				       int port,
				       SilcKeyAgreementCallback completion,
				       void *context);

/****f* silcclient/SilcClientAPI/silc_client_perform_key_agreement_fd
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_perform_key_agreement_fd(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcClientEntry client_entry,
 *                                         int sock,
 *                                         char *hostname,
 *                                         SilcKeyAgreementCallback completion,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Same as above but application has created already the connection to
 *    the remote host. The `sock' is the socket to the remote connection.
 *    Application can use this function if it does not want the client library
 *    to create the connection.
 *
 ***/
void silc_client_perform_key_agreement_fd(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  int sock,
					  char *hostname,
					  SilcKeyAgreementCallback completion,
					  void *context);

/****f* silcclient/SilcClientAPI/silc_client_abort_key_agreement
 *
 * SYNOPSIS
 *
 *    void silc_client_abort_key_agreement(SilcClient client,
 *                                         SilcClientConnection conn,
 *                                         SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    This function can be called to unbind the hostname and the port for
 *    the key agreement protocol. However, this function has effect only
 *    before the key agreement protocol has been performed. After it has
 *    been performed the library will automatically unbind the port. The
 *    `client_entry' is the client to which we sent the key agreement
 *    request.  The key agreement completion callback will be called
 *    with SILC_KEY_AGREEMENT_ABORTED status.
 *
 ***/
void silc_client_abort_key_agreement(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry client_entry);


/* Misc functions */

/****f* silcclient/SilcClientAPI/silc_client_set_away_message
 *
 * SYNOPSIS
 *
 *    void silc_client_set_away_message(SilcClient client,
 *                                      SilcClientConnection conn,
 *                                      char *message);
 *
 * DESCRIPTION
 *
 *    Sets away `message'.  The away message may be set when the client's
 *    mode is changed to SILC_UMODE_GONE and the client whishes to reply
 *    to anyone who sends private message.  The `message' will be sent
 *    automatically back to the the client who send private message.  If
 *    away message is already set this replaces the old message with the
 *    new one.  If `message' is NULL the old away message is removed.
 *    The sender may freely free the memory of the `message'.
 *
 ***/
void silc_client_set_away_message(SilcClient client,
				  SilcClientConnection conn,
				  char *message);

/****f* silcclient/SilcClientAPI/SilcConnectionAuthRequest
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcConnectionAuthRequest)(SilcClient client,
 *                                              SilcClientConnection conn,
 *                                              SilcAuthMethod auth_meth,
 *                                              void *context);
 *
 * DESCRIPTION
 *
 *    Connection authentication method request callback. This is called
 *    by the client library after it has received the authentication method
 *    that the application requested by calling the function
 *    silc_client_request_authentication_method.
 *
 ***/
typedef void (*SilcConnectionAuthRequest)(SilcClient client,
					  SilcClientConnection conn,
					  SilcAuthMethod auth_meth,
					  void *context);

/****f* silcclient/SilcClientAPI/silc_client_request_authentication_method
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_request_authentication_method(SilcClient client,
 *                                              SilcClientConnection conn,
 *                                              SilcConnectionAuthRequest
 *                                                callback,
 *                                              void *context);
 *
 * DESCRIPTION
 *
 *    This function can be used to request the current authentication method
 *    from the server. This may be called when connecting to the server
 *    and the client library requests the authentication data from the
 *    application. If the application does not know the current authentication
 *    method it can request it from the server using this function.
 *    The `callback' with `context' will be called after the server has
 *    replied back with the current authentication method.
 *
 ***/
void
silc_client_request_authentication_method(SilcClient client,
					  SilcClientConnection conn,
					  SilcConnectionAuthRequest callback,
					  void *context);

/****d* silcclient/SilcClientAPI/SilcClientMonitorStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcClientMonitorStatus;
 *
 * DESCRIPTION
 *
 *    File transmission session status types.  These will indicate
 *    the status of the file transmission session.
 *
 * SOURCE
 */
typedef enum {
  SILC_CLIENT_FILE_MONITOR_KEY_AGREEMENT,    /* In key agreemenet phase */
  SILC_CLIENT_FILE_MONITOR_SEND,	     /* Sending file */
  SILC_CLIENT_FILE_MONITOR_RECEIVE,	     /* Receiving file */
  SILC_CLIENT_FILE_MONITOR_GET,
  SILC_CLIENT_FILE_MONITOR_PUT,
  SILC_CLIENT_FILE_MONITOR_CLOSED,	     /* Session closed */
  SILC_CLIENT_FILE_MONITOR_ERROR,	     /* Error during session */
} SilcClientMonitorStatus;
/***/

/****d* silcclient/SilcClientAPI/SilcClientFileError
 *
 * NAME
 *
 *    typedef enum { ... } SilcClientFileError;
 *
 * DESCRIPTION
 *
 *    File transmission error types.  These types are returned by
 *    some of the file transmission functions, and by the monitor
 *    callback to indicate error.
 *
 * SOURCE
 */
typedef enum {
  SILC_CLIENT_FILE_OK,
  SILC_CLIENT_FILE_ERROR,
  SILC_CLIENT_FILE_UNKNOWN_SESSION,
  SILC_CLIENT_FILE_ALREADY_STARTED,
  SILC_CLIENT_FILE_NO_SUCH_FILE,
  SILC_CLIENT_FILE_PERMISSION_DENIED,
  SILC_CLIENT_FILE_KEY_AGREEMENT_FAILED,
} SilcClientFileError;
/***/

/****f* silcclient/SilcClientAPI/SilcClientFileMonitor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcClientFileMonitor)(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcClientMonitorStatus status,
 *                                          SilcClientFileError error,
 *                                          SilcUInt64 offset,
 *                                          SilcUInt64 filesize,
 *                                          SilcClientEntry client_entry,
 *                                          SilcUInt32 session_id,
 *                                          const char *filepath,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Monitor callback that is called during the file transmission to
 *    monitor the transmission process.  The `status' indicates the current
 *    monitoring process.  The `error' will indicate the error type
 *    if `status' is SILC_CLIENT_FILE_MONITOR_ERROR.  The `offset' is the
 *    currently transmitted amount of total `filesize'.  The `client_entry'
 *    indicates the remote client, and the transmission session ID is the
 *    `session_id'.  The filename being transmitted is indicated by the
 *    `filepath'.
 *
 ***/
typedef void (*SilcClientFileMonitor)(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientMonitorStatus status,
				      SilcClientFileError error,
				      SilcUInt64 offset,
				      SilcUInt64 filesize,
				      SilcClientEntry client_entry,
				      SilcUInt32 session_id,
				      const char *filepath,
				      void *context);

/****f* silcclient/SilcClientAPI/SilcClientFileName
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcClientFileName)(const char *filepath,
 *                                       void *context);
 *
 * DESCRIPTION
 *
 *    Completion callback for the SilcClientFileAskName callback function.
 *    Application calls this to deliver the filepath and filename where
 *    the downloaded file is to be saved.
 *
 ***/
typedef void (*SilcClientFileName)(const char *filepath,
				   void *context);

/****f* silcclient/SilcClientAPI/SilcClientFileAskName
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcClientFileAskName)(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcUInt32 session_id,
 *                                          const char *remote_filename,
 *                                          SilcClientFileName completion,
 *                                          void *completion_context,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    File name asking callback, that is called if it is given to the
 *    silc_client_file_receive and the path given to that as argument was
 *    NULL.  The library calls this to ask the filename and filepath to
 *    where the file is to be saved.  The 'remote_filename' is the file
 *    that is being downloaded.  Application must call the 'completion'
 *    with 'completion_context' to continue with the file downloading.
 *    It is not mandatory to provide this to the silc_client_file_receive.
 *
 ***/
typedef void (*SilcClientFileAskName)(SilcClient client,
				      SilcClientConnection conn,
				      SilcUInt32 session_id,
				      const char *remote_filename,
				      SilcClientFileName completion,
				      void *completion_context,
				      void *context);

/****f* silcclient/SilcClientAPI/silc_client_file_send
 *
 * SYNOPSIS
 *
 *    SilcClientFileError
 *    silc_client_file_send(SilcClient client,
 *                          SilcClientConnection conn,
 *                          SilcClientFileMonitor monitor,
 *                          void *monitor_context,
 *                          const char *local_ip,
 *                          SilcUInt32 local_port,
 *                          SilcBool do_not_bind,
 *                          SilcClientEntry client_entry,
 *                          const char *filepath);
 *                          SilcUInt32 *session_id);
 *
 * DESCRIPTION
 *
 *    Sends a file indicated by the `filepath' to the remote client
 *    indicated by the `client_entry'.  This will negotiate a secret key
 *    with the remote client before actually starting the transmission of
 *    the file.  The `monitor' callback will be called to monitor the
 *    transmission of the file.
 *
 *    This returns a file session ID for the file transmission to the
 *    `session_id' pointer.  It can be used to close the session (and
 *    abort the file transmission) by calling the silc_client_file_close
 *    function.  The session ID is also returned in the `monitor' callback.
 *
 *    If the `local_ip' is provided then this will try to bind the
 *    listener for key exchange protocol to that IP.  If `local_port' is
 *    non-zero that port is used.  If `local_ip' is NULL then this will
 *    automatically attempt to bind it to local IP address of the machine.
 *    If `do_not_bind' is TRUE then the `local_ip' and `local_port' are
 *    ignored and it is expected that the receiver will provide the
 *    point of contact.  This is usefull if the sender is behind NAT.
 *
 *    If error will occur during the file transfer process the error
 *    status will be returned in the monitor callback.  In this case
 *    the application must call silc_client_file_close to close the
 *    session.
 *
 ***/
SilcClientFileError
silc_client_file_send(SilcClient client,
		      SilcClientConnection conn,
		      SilcClientFileMonitor monitor,
		      void *monitor_context,
		      const char *local_ip,
		      SilcUInt32 local_port,
		      SilcBool do_not_bind,
		      SilcClientEntry client_entry,
		      const char *filepath,
		      SilcUInt32 *session_id);

/****f* silcclient/SilcClientAPI/silc_client_file_receive
 *
 * SYNOPSIS
 *
 *    SilcClientFileError
 *    silc_client_file_receive(SilcClient client,
 *                             SilcClientConnection conn,
 *                             SilcClientFileMonitor monitor,
 *                             void *monitor_context,
 *                             const char *path,
 *                             SilcUInt32 session_id,
 *                             SilcClientFileAskName ask_name,
 *                             void *ask_name_context);
 *
 * DESCRIPTION
 *
 *    Receives a file from a client indicated by the `client_entry'.  The
 *    `session_id' indicates the file transmission session and it has been
 *    received in the `ftp' client operation function.  This will actually
 *    perform the key agreement protocol with the remote client before
 *    actually starting the file transmission.  The `monitor' callback
 *    will be called to monitor the transmission.  If `path' is non-NULL
 *    the file will be saved into that directory.  If NULL the file is
 *    saved in the current working directory, unless the 'ask_name'
 *    callback is non-NULL.  In this case the callback is called to ask
 *    the path and filename from application.
 *
 *    If error will occur during the file transfer process the error
 *    status will be returned in the monitor callback.  In this case
 *    the application must call silc_client_file_close to close the
 *    session.
 *
 ***/
SilcClientFileError
silc_client_file_receive(SilcClient client,
			 SilcClientConnection conn,
			 SilcClientFileMonitor monitor,
			 void *monitor_context,
			 const char *path,
			 SilcUInt32 session_id,
			 SilcClientFileAskName ask_name,
			 void *ask_name_context);

/****f* silcclient/SilcClientAPI/silc_client_file_close
 *
 * SYNOPSIS
 *
 *    SilcClientFileError silc_client_file_close(SilcClient client,
 *                                               SilcClientConnection conn,
 *                                               SilcUInt32 session_id);
 *
 * DESCRIPTION
 *
 *    Closes file transmission session indicated by the `session_id'.
 *    If file transmission is being conducted it will be aborted
 *    automatically. This function is also used to close the session
 *    after successful file transmission. This function can be used
 *    also to reject incoming file transmission request.  If the
 *    session was already started and the monitor callback was set
 *    the monitor callback will be called with the monitor status
 *    SILC_CLIENT_FILE_MONITOR_CLOSED.
 *
 ***/
SilcClientFileError silc_client_file_close(SilcClient client,
					   SilcClientConnection conn,
					   SilcUInt32 session_id);

/****f* silcclient/SilcClientAPI/silc_client_attribute_add
 *
 * SYNOPSIS
 *
 *    SilcAttributePayload
 *    silc_client_attribute_add(SilcClient client,
 *                              SilcClientConnection conn,
 *                              SilcAttribute attribute,
 *                              void *object,
 *                              SilcUInt32 object_size);
 *
 * DESCRIPTION
 *
 *    Add new Requsted Attribute for WHOIS command to the client library.
 *    The `attribute' object indicated by `object' is added and allocated
 *    SilcAttributePayload is returned.  The `object' must be of correct
 *    type and of correct size.  See the SilcAttribute for object types
 *    for different attributes.  You may also get all added attributes
 *    from the client with silc_client_attributes_get function.
 *
 *    Requested Attributes are different personal information about the
 *    user, status information and other information which other users
 *    may query with WHOIS command.  Application may set these so that
 *    if someone sends WHOIS query these attributes will be replied back
 *    to the sender.  The library always puts the public key to the
 *    Requested Attributes, but if application wishes to add additional
 *    public keys (or certificates) it can be done with this interface.
 *    Library also always computes digital signature of the attributes
 *    automatically, so application does not need to do that.
 *
 ***/
SilcAttributePayload silc_client_attribute_add(SilcClient client,
					       SilcClientConnection conn,
					       SilcAttribute attribute,
					       void *object,
					       SilcUInt32 object_size);

/****f* silcclient/SilcClientAPI/silc_client_attribute_del
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_attribute_del(SilcClient client,
 *                                   SilcClientConnection conn,
 *                                   SilcAttribute attribute,
 *                                   SilcAttributePayload attr);
 *
 * DESCRIPTION
 *
 *    Delete a Requested Attribute from the client.  If the `attribute'
 *    is non-zero then all attributes of that type are deleted and the
 *    `attr' is ignored.  If `attr' is non-NULL then that specific
 *    attribute is deleted and `attribute' is ignored.
 *
 *    You may get all added attributes with the function
 *    silc_client_attributes_get and to get the SilcAttributePayload.
 *    This function Returns TRUE if the attribute was found and deleted.
 *
 ***/
SilcBool silc_client_attribute_del(SilcClient client,
				   SilcClientConnection conn,
				   SilcAttribute attribute,
				   SilcAttributePayload attr);

/****f* silcclient/SilcClientAPI/silc_client_attributes_get
 *
 * SYNOPSIS
 *
 *    const SilcHashTable
 *    silc_client_attributes_get(SilcClient client,
 *                               SilcClientConnection conn);
 *
 * DESCRIPTION
 *
 *    Returns pointer to the SilcHashTable which includes all the added
 *    Requested Attributes.  The caller must not free the hash table.
 *    The caller may use SilcHashTableList and silc_hash_table_list to
 *    traverse the table.  Each entry in the hash table is one added
 *    SilcAttributePayload.  It is possible to delete a attribute
 *    payload while traversing the table.
 *
 ***/
SilcHashTable silc_client_attributes_get(SilcClient client,
					 SilcClientConnection conn);

/****f* silcclient/SilcClientAPI/silc_client_attributes_request
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_client_attributes_request(SilcAttribute attribute, ...);
 *
 * DESCRIPTION
 *
 *    Constructs a Requested Attributes buffer. If the `attribute' is zero (0)
 *    then all attributes are requested.  Alternatively, `attribute' and
 *    all variable arguments can each be requested attribute.  In this case
 *    the last must be set to zero (0) to complete the variable list of
 *    requested attributes.  See SilcAttribute for all attributes.
 *    You can give the returned buffer as argument to for example
 *    silc_client_get_client_by_id_resolve function.
 *
 * EXAMPLE
 *
 *    Request all attributes
 *    buffer = silc_client_attributes_request(0);
 *
 *    Request only the following attributes
 *    buffer = silc_client_attributes_request(SILC_ATTRIBUTE_USER_INFO,
 *                                            SILC_ATTRIBUTE_SERVICE,
 *                                            SILC_ATTRIBUTE_MOOD, 0);
 *
 ***/
SilcBuffer silc_client_attributes_request(SilcAttribute attribute, ...);

/* Low level packet sending functions */

/****f* silcclient/SilcClientAPI/silc_client_send_packet
 *
 * SYNOPSIS
 *
 *     SilcBool silc_client_send_packet(SilcClient client,
 *                                  SilcClientConnection conn,
 *                                  SilcPacketType type,
 *                                  const unsigned char *data,
 *                                  SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    This routine can be used by application to send packets directly
 *    to a connection indicated by `conn'.  Usually application does not
 *    need this routine since the Client Library handles the packet
 *    sending.  The `type' indicates the packet type.  If `data' is
 *    NULL then empty packet is sent.  This returns FALSE if packet cannot
 *    be sent.
 *
 ***/
SilcBool silc_client_send_packet(SilcClient client,
			     SilcClientConnection conn,
			     SilcPacketType type,
			     const unsigned char *data,
			     SilcUInt32 data_len);

#include "command.h"
#include "command_reply.h"
#include "idlist.h"
#include "protocol.h"

#ifdef __cplusplus
}
#endif

#endif /* SILCCLIENT_H */
