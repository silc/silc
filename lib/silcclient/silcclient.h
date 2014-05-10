/*

  silcclient.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2014 Pekka Riikonen

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
 * The Client Library is a full featured SILC client without user interface.
 * A simple interface called SILC Client Operations (SilcClientOperations)
 * is provided for applications to implmeent the necessary functions to use
 * the client library.  The silcclient.h header file includes client library
 * API, such as command handling and message sending.  The silcclient_entry.h
 * header file includes entry handling, such as channel and user entry
 * handling.
 *
 * Practically all functions in the Client Library API accepts SilcClient
 * and SilcClientConnection as their first two argument.  The first argument
 * is the actual SilcClient context and the second is the SilcClientConnection
 * context of the connection in question.  Application may create and handle
 * multiple connections in one SilcClient.  Connections can be created to
 * servers and other clients.
 *
 * The Client Library support multiple threads and is threads safe if used
 * correctly.  Messages can be sent from multiple threads without any
 * locking.  Messages however are always received only in one thread unless
 * message waiting (see silc_client_private_message_wait as an example) is
 * used.  The threads can be turned on and off by giving a parameter to the
 * SilcClient.  When turned on, each new connection to remote host is always
 * executed in an own thread.  All tasks related to that connection are then
 * executed in that thread.  This means that client operation callbacks for
 * that connections may be called from threads and application will need to
 * employ concurrency control if the callbacks need to access shared data
 * in the application.  Messages are also received in that thread.
 *
 ***/

#ifndef SILCCLIENT_H
#define SILCCLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "client.h"
#include "silcclient_entry.h"

/* General definitions */

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
  SILC_CLIENT_CONN_DISCONNECTED,       /* Remote host disconnected */
  SILC_CLIENT_CONN_ERROR,	       /* Error occurred during connecting */
  SILC_CLIENT_CONN_ERROR_KE,	       /* Key Exchange failed */
  SILC_CLIENT_CONN_ERROR_AUTH,	       /* Authentication failed */
  SILC_CLIENT_CONN_ERROR_RESUME,       /* Resuming failed */
  SILC_CLIENT_CONN_ERROR_TIMEOUT,      /* Timeout during connecting */
} SilcClientConnectionStatus;
/***/

/****f* silcclient/SilcClientAPI/SilcClientRunning
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcClientRunning)(SilcClient client, void *context);
 *
 * DESCRIPTION
 *
 *    The callback given as argument to silc_client_init function.  Once
 *    this is called the client library is running and application may
 *    start using the Client library API.
 *
 ***/
typedef void (*SilcClientRunning)(SilcClient client, void *context);

/****f* silcclient/SilcClientAPI/SilcClientStopped
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcClientStopped)(SilcClient client, void *context);
 *
 * DESCRIPTION
 *
 *    The callback given as argument to silc_client_stop.  Once this is
 *    called the client library has stopped and can be freed by calling
 *    silc_client_free.  Note that this won't be called if there are
 *    active connections in the client.  Connections must first be closed
 *    by calling silc_client_close_connection or by sending QUIT command to
 *    the server connection.
 *
 ***/
typedef void (*SilcClientStopped)(SilcClient client, void *context);

/****f* silcclient/SilcClientAPI/SilcClientConnectCallback
 *
 * SYNOPSIS
 *
 *    void (*SilcClientConnectCallback)(SilcClient client,
 *                                      SilcClientConnection conn,
 *                                      SilcClientConnectionStatus status,
 *                                      SilcStatus error,
 *                                      const char *message,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Connect callbak given as argument to silc_client_connect_to_server,
 *    silc_client_connect_to_client and silc_client_key_exchange functions.
 *    It is called to indicate the status of the connection, indicated
 *    by the `status'.  It is called after the connection has been
 *    established to the remote host and when connection is disconnected
 *    by the remote host.  The `context' is the context given as argument
 *    to the connecting function.  If the `status' is an error the `error'
 *    may indicate more detailed error.  If `error' is SILC_STATUS_OK no
 *    detailed error message is available.
 *
 *    When the `status' is SILC_CLIENT_CONN_DISCONNECTED the `error' will
 *    indicate the reason for disconnection.  If the `message' is non-NULL
 *    it delivers error or disconnection message.
 *
 *    The `conn' is the connection to the remote host.  In case error
 *    occurred the `conn' may be NULL, however, in some cases a valid `conn'
 *    is returned even in error.  If `conn' is non-NULL the receiver is
 *    responsible of closing the connection with silc_client_close_connection
 *    function, except when SILC_CLINET_CONN_DISCONNECTED or some error
 *    was received.  In these cases the library will close the connection.
 *
 ***/
typedef void (*SilcClientConnectCallback)(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientConnectionStatus status,
					  SilcStatus error,
					  const char *message,
					  void *context);

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
 *    This context represents the client.  Each connection to remote server
 *    is represented by SilcClientConnection context.
 *
 * SOURCE
 */
struct SilcClientStruct {
  char *username;               /* Username */
  char *hostname;               /* hostname */
  char *realname;               /* Real name */
  SilcSchedule schedule;	/* Client scheduler */
  SilcRng rng;			/* Random number generator */
  void *application;		/* Application specific context, set with
				   silc_client_alloc. */

  /* Internal data for client library.  Application cannot access this. */
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
 *    This structure represents a connection.  It is allocated and freed by
 *    the library.  It is returned to application in SilcClientConnectCallback.
 *    It includes all the important data for the session such as local
 *    client entry (which includes current nickname), local and remote IDs,
 *    and other information.  All strings in the structure are UTF-8 encoded.
 *
 * SOURCE
 */
struct SilcClientConnectionStruct {
  SilcClientEntry local_entry;	       /* Our own Client Entry */
  SilcClientID *local_id;	       /* Our current Client ID */

  char *remote_host;		       /* Remote host name */
  int remote_port;		       /* Remote port */
  SilcID remote_id;		       /* Remote ID */

  SilcChannelEntry current_channel;    /* Current joined channel */
  SilcPublicKey public_key;	       /* Public key used in this connection */
  SilcPrivateKey private_key;	       /* Private key */
  SilcPacketStream stream;	       /* Connection to remote host */
  SilcConnectionType type;	       /* Connection type */
  SilcClientConnectCallback callback;  /* Connection callback */
  void *callback_context;	       /* Connection context */
  SilcClient client;		       /* Pointer back to SilcClient */

  /* Current say() or verify_public_key() operation associated context,
     identifies the client, channel or server the operation is related to.
     Application can use this information to target the operation better. */
  union {
    SilcClientEntry client_entry;
    SilcChannelEntry channel_entry;
    SilcServerEntry server_entry;
  };
  SilcIdType context_type;		/* Defines which pointer is set
					   in the union.  If SILC_ID_NONE
					   pointer is NULL. */

  /* Application specific data.  Application may set here whatever it wants. */
  void *context;

  /* Internal data for client library.  Application cannot access this. */
  SilcClientConnectionInternal internal;
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

/****s* silcclient/SilcClientAPI/SilcClientStats
 *
 * NAME
 *
 *    typedef struct { ... } SilcClientStats;
 *
 * DESCRIPTION
 *
 *    This structure holds SILC network statistics returned by the
 *    SILC_COMMAND_STATS command reply to the application.
 *
 * SOURCE
 */
typedef struct SilcClientStatsStruct {
  SilcUInt32 starttime;		/* SILC server start time */
  SilcUInt32 uptime;		/* SILC server uptime*/
  SilcUInt32 my_clients;	/* Number of clients in the server */
  SilcUInt32 my_channels;	/* Number of channel in the server */
  SilcUInt32 my_server_ops;	/* Number of server operators in the server */
  SilcUInt32 my_router_ops;	/* Number of router operators in the router */
  SilcUInt32 cell_clients;	/* Number of clients in the cell */
  SilcUInt32 cell_channels;	/* Number of channels in the cell */
  SilcUInt32 cell_servers;	/* Number of server in the cell */
  SilcUInt32 clients;		/* All clients in SILC network */
  SilcUInt32 channels;		/* All channels in SILC network */
  SilcUInt32 servers;		/* All servers in SILC network */
  SilcUInt32 routers;		/* All routers in SILC network */
  SilcUInt32 server_ops;	/* All server operators in SILC network */
  SilcUInt32 router_ops;	/* All router operators in SILC network */
} SilcClientStats;
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
  SILC_KEY_AGREEMENT_NO_MEMORY,        /* System out of memory */
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
					 SilcSKEKeyMaterial key,
					 void *context);

/****s* silcclient/SilcClientAPI/SilcPrivateMessageKeys
 *
 * NAME
 *
 *    typedef struct { ... } SilcPrivateMessageKeys;
 *
 * DESCRIPTION
 *
 *    Structure to hold the list of private message keys. The list of these
 *    structures is returned by the silc_client_list_private_message_keys
 *    function.
 *
 * SOURCE
 */
typedef struct SilcPrivateMessageKeysStruct {
  SilcClientEntry client_entry;       /* The remote client entry */
  char *cipher;			      /* The cipher name */
  unsigned char *key;		      /* The original key, If the appliation
					 provided it. This is NULL if
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
  SilcCipher send_key;		      /* The cipher and key */
  SilcCipher receive_key;	      /* The cipher and key */
  SilcHmac hmac;		      /* The HMAC and hmac key */
};
/***/

/****f* silcclient/SilcClientAPI/SilcAskPassphrase
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcAskPassphrase)(const unsigned char *passphrase,
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
typedef void (*SilcAskPassphrase)(const unsigned char *passphrase,
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
 *    typedef void (*SilcGetAuthMeth)(SilcAuthMethod auth_meth,
 *                                    const void *auth, SilcUInt32 auth_len,
 *                                    void *context);
 *
 * DESCRIPTION
 *
 *    Authentication data resolving callback. This is called by the
 *    application to return the resolved authentication data. The client
 *    library has called the get_auth_method client operation and given
 *    this function pointer as argument. The `auth_meth' is the selected
 *    authentication method. The `auth_data' and the `auth_data_len'
 *    are the resolved authentication data. The `context' is the libary's
 *    context sent to the get_auth_method client operation.
 *
 *    If the `auth_method' is SILC_AUTH_PASSWORD then `auth' and `auth_len'
 *    is the passphrase and its length.  If it is SILC_AUTH_PUBLIC_KEY the
 *    `auth' must be NULL.  The library will use the private key given as
 *    argument to silc_client_connect_to_server, silc_client_connect_to_client
 *    or silc_client_key_exchange.  If it is SILC_AUTH_NONE, both `auth' and
 *    `auth_len' are ignored.
 *
 ***/
typedef void (*SilcGetAuthMeth)(SilcAuthMethod auth_meth,
				const void *auth, SilcUInt32 auth_len,
				void *context);

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
  SILC_CLIENT_MESSAGE_COMMAND_ERROR,   /* Error during command */
  SILC_CLIENT_MESSAGE_AUDIT,	       /* Auditable */
} SilcClientMessageType;
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
typedef struct SilcClientOperationsStruct {
  /* Message sent to the application by library. `conn' associates the
     message to a specific connection.  `conn', however, may be NULL.
     The `type' indicates the type of the message sent by the library.
     The application can for example filter the message according the
     type.  The variable argument list is arguments to the formatted
     message `msg'.  A SilcClientEntry, SilcChannelEntry or SilcServerEntry
     can be associated with the message inside the SilcClientConnection
     by the library, and application may use it to better target the
     message. */
  void (*say)(SilcClient client, SilcClientConnection conn,
	      SilcClientMessageType type, char *msg, ...);

  /* Message for a channel. The `sender' is the sender of the message
     The `channel' is the channel. The `message' is the message.  Note
     that `message' maybe NULL.  The `flags' indicates message flags
     and it is used to determine how the message can be interpreted
     (like it may tell the message is multimedia message).  The `payload'
     may be used to retrieve all the details of the message. */
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
     message).  The `payload' may be used to retrieve all the details of
     the message. */
  void (*private_message)(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessagePayload payload,
			  SilcMessageFlags flags, const unsigned char *message,
			  SilcUInt32 message_len);

  /* Notify message to the client.  The arguments are notify `type' specific.
     See separate documentation in the Toolkit Reference Manual for the notify
     arguments. */
  void (*notify)(SilcClient client, SilcClientConnection conn,
		 SilcNotifyType type, ...);

  /* Command handler. This function is called always after application has
     called a command.  It will be called to indicate that the command
     was processed.  It will also be called if error occurs while processing
     the command.  The `success' indicates whether the command was sent
     or if error occurred.  The `status' indicates the actual error.
     The `argc' and `argv' are the command line arguments sent to the
     command by application.  Note that, this is not reply to the command
     from server, this is merely and indication to application that the
     command was processed. */
  void (*command)(SilcClient client, SilcClientConnection conn,
		  SilcBool success, SilcCommand command, SilcStatus status,
		  SilcUInt32 argc, unsigned char **argv);

  /* Command reply handler.  Delivers a reply to command that was sent
     earlier.  The `conn' is the associated client connection.  The `command'
     indicates the command reply type.  If the `status' other than
     SILC_STATUS_OK an error occurred.  In this case the `error' will indicate
     the error.  It is possible to receive list of command replies and list
     of errors.  In this case the `status' will indicate it is an list entry
     (the `status' is SILC_STATUS_LIST_START, SILC_STATUS_LIST_ITEM and/or
     SILC_STATUS_LIST_END).

     The arguments received in `ap' are command specific.  See a separate
     documentation in the Toolkit Reference Manual for the command reply
     arguments. */
  void (*command_reply)(SilcClient client, SilcClientConnection conn,
			SilcCommand command, SilcStatus status,
			SilcStatus error, va_list ap);

  /* Find authentication method and authentication data by hostname and
     port. The hostname may be IP address as well. The `auth_method' is
     the authentication method the remote connection requires.  It is
     however possible that remote accepts also some other authentication
     method.  Application should use the method that may have been
     configured for this connection.  If none has been configured it should
     use the required `auth_method'.  If the `auth_method' is
     SILC_AUTH_NONE, server does not require any authentication or the
     required authentication method is not known.  The `completion'
     callback must be called to deliver the chosen authentication method
     and data. The `conn' may be NULL. */
  void (*get_auth_method)(SilcClient client, SilcClientConnection conn,
			  char *hostname, SilcUInt16 port,
			  SilcAuthMethod auth_method,
			  SilcGetAuthMeth completion, void *context);

  /* Called to verify received public key. The `conn_type' indicates which
     entity (server or client) has sent the public key. If user decides to
     trust the key the application may save the key as trusted public key for
     later use. The `completion' must be called after the public key has
     been verified.  A SilcClientEntry or SilcServerEntry can be associated
     with this request inside the SilcClientConnection by the library, and
     application may use it to better target the verification request. */
  void (*verify_public_key)(SilcClient client, SilcClientConnection conn,
			    SilcConnectionType conn_type,
			    SilcPublicKey public_key,
			    SilcVerifyPublicKey completion, void *context);

  /* Ask from end user a passphrase or a password. The passphrase is
     returned to the library by calling the `completion' callback with
     the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
     if not then the library will attempt to encode. */
  void (*ask_passphrase)(SilcClient client, SilcClientConnection conn,
			 SilcAskPassphrase completion, void *context);

  /* Called to indicate that incoming key agreement request has been
     received.  If the application wants to perform key agreement it may
     call silc_client_perform_key_agreement to initiate key agreement or
     silc_client_send_key_agreement to provide connection point to the
     remote client in case the `hostname' is NULL.  If key agreement is
     not desired this request can be ignored.  The `protocol' is either
     value 0 for TCP or value 1 for UDP. */
  void (*key_agreement)(SilcClient client, SilcClientConnection conn,
			SilcClientEntry client_entry,
			const char *hostname, SilcUInt16 protocol,
			SilcUInt16 port);

  /* Notifies application that file transfer protocol session is being
     requested by the remote client indicated by the `client_entry' from
     the `hostname' and `port'. The `session_id' is the file transfer
     session and it can be used to either accept or reject the file
     transfer request, by calling the silc_client_file_receive or
     silc_client_file_close, respectively. */
  void (*ftp)(SilcClient client, SilcClientConnection conn,
	      SilcClientEntry client_entry, SilcUInt32 session_id,
	      const char *hostname, SilcUInt16 port);
} SilcClientOperations;
/***/

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
typedef struct SilcClientParamsStruct {
  /* If this boolean is set to TRUE then the client library will use
     threads.  Any of the callback functions in the SilcClientOperations
     and other callbacks may be called at any time in a thread.  The
     application may need to employ appropriate concurrency control
     in the callbacks to protect application specific data. */
  SilcBool threads;

  /* Nickname format string. This can be used to order the client library
     to save the nicknames in the library in a certain format. Since
     nicknames are not unique in SILC it is possible to have multiple same
     nicknames. Using this format string it is possible to order the library
     to separate the multiple same nicknames from each other. If this is
     empty then default format is used which is the default nickname
     without anything else. The string MUST be NULL terminated.

     Following format types are available:

     %n  nickname      - the real nickname returned by the server (mandatory)
     %a  number        - ascending number in case there are several
                         same nicknames (fe. nick#2 and nick#3)
     %h  hostname      - the stripped hostname of the client
     %H  full hostname - the full hostname of the client

     Example format strings: "%n#%a"     (fe. nick#2, nick#3)
                             "%n#%h%a"   (fe. nick#host, nick#host2)
                             "%a!%n#%h"  (fe. nick#host, 2!nick#host)

     Note that there must always be some separator characters around '%n'
     format.  It is not possible to put format characters before or after
     '%n' without separators (such ash '#').  Also note that the separator
     character should be a character that cannot be part of normal nickname.
     Note that, using '@' as a separator is not recommended as the nickname
     string may contain it to separate a server name from the nickname (eg.
     nickname@silcnet.org).
  */
  char nickname_format[32];

  /* If this is set to TRUE then the `nickname_format' is employed to all
     saved nicknames even if there are no multiple same nicknames in the
     cache. By default this is FALSE, which means that the `nickname_format'
     is employed only if the library will receive a nickname that is
     already saved in the cache. It is recommended to leave this to FALSE
     value. */
  SilcBool nickname_force_format;

  /* If this is set to TRUE then all nickname strings returned by the library
     and stored by the library are in the format of 'nickname@server', eg.
     nickname@silcnet.org.  If this is FALSE then the server name of the
     nickname is available only from the SilcClientEntry structure.  When this
     is TRUE the server name is still parsed to SilcClientEntry. */
  SilcBool full_nicknames;

  /* If this is set to TRUE then all channel name strings returned by the
     library and stored by the library are in the format of 'channel@server',
     eg. silc@silcnet.org.  If this is FALSE then the server name of the
     channel is available only from the SilcChannelEntry structure.  When this
     is TRUE the server name is still parsed to SilcChannelEntry.  Note that,
     not all SILC server versions return such channel name strings. */
  SilcBool full_channel_names;

  /* If this is set to TRUE, the silcclient library will not register and
     deregister the cipher, pkcs, hash and hmac algorithms. The application
     itself will need to handle that. */
  SilcBool dont_register_crypto_library;

  /* If this is set to TRUE, the silcclient library will not automatically
     negotiate private message keys using SKE over the SILC network but will
     use normal session keys to protect private messages. */
  SilcBool dont_autoneg_prvmsg_keys;
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
 *    SilcBool silc_client_init(SilcClient client, const char *username,
 *                              const char *hostname, const char *realname,
 *                              SilcClientRunning running, void *context);
 *
 * DESCRIPTION
 *
 *    Initializes the client. This makes all the necessary steps to make
 *    the client ready to be run. One must call silc_client_run to run the
 *    client. Returns FALSE if error occurred, TRUE otherwise.
 *
 *    The `username' and `hostname' strings must be given and they must be
 *    UTF-8 encoded.  The `username' is the client's username in the
 *    operating system, `hostname' is the client's host name and the
 *    `realname' is the user's real name.
 *
 *    The `running' callback with `context' is called after the client is
 *    running after silc_client_run or silc_client_run_one has been called.
 *    Application may start using the Client library API after that.  Setting
 *    the callback is optional, but highly recommended.
 *
 ***/
SilcBool silc_client_init(SilcClient client, const char *username,
			  const char *hostname, const char *realname,
			  SilcClientRunning running, void *context);

/****f* silcclient/SilcClientAPI/silc_client_run
 *
 * SYNOPSIS
 *
 *    void silc_client_run(SilcClient client);
 *
 * DESCRIPTION
 *
 *    Runs the client.  This starts the scheduler from the utility library.
 *    When this functions returns the execution of the application is over.
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
 *    void silc_client_stop(SilcClient client, SilcClientStopped stopped,
 *                          void *context);
 *
 * DESCRIPTION
 *
 *    Stops the client. This is called to stop the client and thus to stop
 *    the program.  The client context must be freed with the silc_client_free
 *    function.  All connections that exist in this client must be closed
 *    before calling this function.  Connections can be closed by calling
 *    silc_client_close_connection.
 *
 *    The `stopped' will be called once the client and all connections have
 *    finished.  The client may be freed after that.  Note that the `stopped'
 *    won't be called before all connections have finished.  Setting the
 *    callback is optional.
 *
 ***/
void silc_client_stop(SilcClient client, SilcClientStopped stopped,
		      void *context);

/* Connecting functions */

/****s* silcclient/SilcClientAPI/SilcClientConnectionParams
 *
 * NAME
 *
 *    typedef struct { ... } SilcClientConnectionParams;
 *
 * DESCRIPTION
 *
 *    Client connection parameters.  This can be filled by the application
 *    and given as argument to silc_client_connect_to_server,
 *    silc_client_connect_to_client, silc_client_key_exchange or
 *    silc_client_send_key_agreement.
 *
 * SOURCE
 */
typedef struct SilcClientConnectionParamsStruct {
  /* If this is provided the user's nickname in the network will be the
     string given here.  If it is given, it must be UTF-8 encoded.  If this
     string is not given, the user's username by default is used as nickname.
     The nickname may later be changed by using NICK command.  The maximum
     length for the nickname string is 128 bytes. */
  char *nickname;

  /* If this key repository pointer is non-NULL then public key received in
     the key exchange protocol will be verified from this repository.  If
     this is not provided then the `verify_public_key' client operation will
     be called back to application.  If the boolean `verify_notfound' is set
     to TRUE then the `verify_public_key' client operation will be called
     in case the public key is not found in `repository'.  Only public keys
     added with at least SILC_SKR_USAGE_KEY_AGREEMENT in the repository will
     be checked, other keys will be ignored. */
  SilcSKR repository;
  SilcBool verify_notfound;

  /* Authentication data.  Application may set here the authentication data
     and authentication method to be used in connecting.  If `auth_set'
     boolean is TRUE then authentication data is provided by application.
     If the authentication method is public key authentication then the key
     pair given as argument when connecting will be used and `auth' field
     is NULL.  If it is passphrase authentication, it can be provided in
     `auth' and `auth_len' fields.  If `auth_set' is FALSE
     the `get_auth_method' client operation will be called to get the
     authentication method and data from application. */
  SilcBool auth_set;
  SilcAuthMethod auth_method;
  void *auth;
  SilcUInt32 auth_len;

  /* If this boolean is set to TRUE then the connection will use UDP instead
     of TCP.  If UDP is set then also the next `local_ip' and `local_port'
     must be set. */
  SilcBool udp;

  /* The `local_ip' specifies the local IP address used with the connection.
     It must be non-NULL if `udp' boolean is TRUE.  If the `local_port' is
     non-zero it will be used as local port with UDP connection.  The remote
     host will also send packets to the specified address and port.  If the
     `bind_ip' is non-NULL a listener is bound to that address instead of
     `local_ip'. */
  char *local_ip;
  char *bind_ip;
  int local_port;

  /* If this boolean is set to TRUE then the key exchange is done with
     perfect forward secrecy. */
  SilcBool pfs;

  /* If this boolean is set to TRUE then connection authentication protocol
     is not performed during connecting.  Only key exchange protocol is
     performed.  This usually must be set to TRUE when connecting to another
     client, but must be FALSE with server connections. */
  SilcBool no_authentication;

  /* The SILC session detachment data that was returned in the `command_reply'
     client operation for SILC_COMMAND_DETACH command.  If this is provided
     here the client library will attempt to resume the session in the network.
     After the connection is created and the session has been resumed the
     client will receive SILC_COMMAND_NICK command_reply for the client's
     nickname in the network and SILC_COMMAND_JOIN command reply for all the
     channels that the client has joined in the network.  It may also receive
     SILC_COMMAND_UMODE command reply to set user's mode on the network. */
  unsigned char *detach_data;
  SilcUInt32 detach_data_len;

  /* Connection timeout.  If non-zero, the connection will timeout unless
     the SILC connection is completed in the specified amount of time. */
  SilcUInt32 timeout_secs;

  /* Rekey timeout in seconds.  The client will perform rekey in this
     time interval.  If set to zero, the default value will be used
     (3600 seconds, 1 hour). */
  SilcUInt32 rekey_secs;

  /* If this is set to TRUE then the client will ignore all incoming
     Requested Attributes queries and does not reply anything back.  This
     usually leads into situation where server does not anymore send
     the queries after seeing that client does not reply anything back.
     If your application does not support Requested Attributes or you do
     not want to use them set this to TRUE.  See SilcAttribute and
     silc_client_attribute_add for more information on attributes. */
  SilcBool ignore_requested_attributes;

  /* User context for SilcClientConnection.  If non-NULL this context is
     set to the 'context' field in SilcClientConnection when the connection
     context is created. */
  void *context;
} SilcClientConnectionParams;
/***/

/****f* silcclient/SilcClientAPI/silc_client_connect_to_server
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_client_connect_to_server(SilcClient client,
 *                                  SilcClientConnectionParams *params,
 *                                  SilcPublicKey public_key,
 *                                  SilcPrivateKey private_key,
 *                                  char *remote_host, int port,
 *                                  SilcClientConnectCallback callback,
 *                                  void *context);
 *
 * DESCRIPTION
 *
 *    Connects to remote server `remote_host' at port `port'.  This function
 *    can be used to create connection to remote SILC server and start
 *    SILC session in the SILC network.  The `params' may be provided
 *    to provide various connection parameters.  The `public_key' and the
 *    `private_key' is your identity used in this connection.  When
 *    authentication method is based on digital signatures, this key pair
 *    will be used.  The `callback' with `context' will be called after the
 *    connection has been created.  It will also be called later when remote
 *    host disconnects.
 *
 *    If application wishes to create the network connection itself, use
 *    the silc_client_key_exchange after creating the connection to start
 *    key exchange and authentication with the server.
 *
 *    Returns SilcAsyncOperation which can be used to cancel the connecting,
 *    or NULL on error.  Note that the returned pointer becomes invalid
 *    after the `callback' is called.
 *
 ***/
SilcAsyncOperation
silc_client_connect_to_server(SilcClient client,
			      SilcClientConnectionParams *params,
			      SilcPublicKey public_key,
			      SilcPrivateKey private_key,
			      char *remote_host, int port,
			      SilcClientConnectCallback callback,
			      void *context);

/****f* silcclient/SilcClientAPI/silc_client_connect_to_client
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_client_connect_to_client(SilcClient client,
 *                                  SilcClientConnectionParams *params,
 *                                  SilcPublicKey public_key,
 *                                  SilcPrivateKey private_key,
 *                                  char *remote_host, int port,
 *                                  SilcClientConnectCallback callback,
 *                                  void *context);
 *
 * DESCRIPTION
 *
 *    Connects to remote client `remote_host' at port `port'.  This function
 *    can be used to create peer-to-peer connection to another SILC client,
 *    for example, for direct conferencing, or file transfer or for other
 *    purposes.  The `params' may be provided to provide various connection
 *    parameters.  The `public_key' and the `private_key' is your identity
 *    used in this connection.  The `callback' with `context' will be called
 *    after the connection has been created.  It will also be called later
 *    when remote host disconnects.
 *
 *    If application wishes to create the network connection itself, use
 *    the silc_client_key_exchange after creating the connection to start
 *    key exchange with the client.
 *
 *    Returns SilcAsyncOperation which can be used to cancel the connecting,
 *    or NULL on error.  Note that the returned pointer becomes invalid
 *    after the `callback' is called.
 *
 ***/
SilcAsyncOperation
silc_client_connect_to_client(SilcClient client,
			      SilcClientConnectionParams *params,
			      SilcPublicKey public_key,
			      SilcPrivateKey private_key,
			      char *remote_host, int port,
			      SilcClientConnectCallback callback,
			      void *context);

/****f* silcclient/SilcClientAPI/silc_client_key_exchange
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_client_key_exchange(SilcClient client,
 *                             SilcClientConnectionParams *params,
 *                             SilcPublicKey public_key,
 *                             SilcPrivateKey private_key,
 *                             SilcStream stream,
 *                             SilcConnectionType conn_type,
 *                             SilcClientConnectCallback callback,
 *                             void *context);
 *
 * DESCRIPTION
 *
 *    Starts key exchange protocol and authentication protocol in the
 *    connection indicated by `stream'.  This function can be be used to
 *    start SILC session with remote host (usually server) when the caller
 *    has itself created the connection, instead of calling the function
 *    silc_client_connect_to_server or silc_client_connect_to_client.  If
 *    one of those functions was used this function must not be called as
 *    in that case the key exchange is performed automatically.
 *
 *    Use this function only if you have created the connection by yourself.
 *    After creating the connection the socket must be wrapped into a
 *    socket stream.  See silcsocketstream.h for more information.  Note that
 *    the `stream' must have valid remote IP address (and optionally also
 *    hostname) and port set.
 *
 *    The `params' may be provided to provide various connection parameters.
 *    The `public_key' and the `private_key' is your identity used in this
 *    session.  The `callback' with `context' will be called after the session
 *    has been set up.  It will also be called later when remote host
 *    disconnects.  The `conn_type' is the type of session this is going to
 *    be.  If the remote is SILC server it is SILC_CONN_SERVER or if it is
 *    SILC client it is SILC_CONN_CLIENT.
 *
 *    Returns SilcAsyncOperation which can be used to cancel the connecting,
 *    or NULL on error.  Note that the returned pointer becomes invalid
 *    after the `callback' is called.
 *
 * EXAMPLE
 *
 *    int sock;
 *
 *    // Create remote connection stream.  Resolve hostname and IP also.
 *    sock = create_connection(remote_host, port);
 *    silc_socket_tcp_stream_create(sock, TRUE, FALSE, schedule,
 *                                  stream_create_cb, app);
 *
 *    // Stream callback delivers our new SilcStream context
 *    void stream_create_cb(SilcSocketStreamStatus status, SilcStream stream,
 *                          void *context)
 *    {
 *      ...
 *      if (status != SILC_SOCKET_OK)
 *        error(status);
 *
 *      // Start key exchange
 *      silc_client_key_exchange(client, NULL, public_key, private_key,
 *                               stream, SILC_CONN_SERVER, connection_cb, app);
 *      ...
 *    }
 *
 ***/
SilcAsyncOperation
silc_client_key_exchange(SilcClient client,
			 SilcClientConnectionParams *params,
			 SilcPublicKey public_key,
			 SilcPrivateKey private_key,
			 SilcStream stream,
			 SilcConnectionType conn_type,
			 SilcClientConnectCallback callback,
			 void *context);

/****f* silcclient/SilcClientAPI/silc_client_close_connection
 *
 * SYNOPSIS
 *
 *    void silc_client_close_connection(SilcClient client,
 *                                      SilcClientConnection conn);
 *
 * DESCRIPTION
 *
 *    Closes the remote connection `conn'.  The `conn' will become invalid
 *    after this call.  Usually this function is called only when explicitly
 *    closing connection for example in case of error, or when the remote
 *    connection was created by the application or when the remote is client
 *    connection.  Server connections are usually closed by sending QUIT
 *    command to the server.  However, this call may also be used.
 *
 ***/
void silc_client_close_connection(SilcClient client,
				  SilcClientConnection conn);

/* Message sending functions */

/****f* silcclient/SilcClientAPI/silc_client_send_channel_message
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_send_channel_message(SilcClient client,
 *                                              SilcClientConnection conn,
 *                                              SilcChannelEntry channel,
 *                                              SilcChannelPrivateKey key,
 *                                              SilcMessageFlags flags,
 *                                              SilcHash hash,
 *                                              unsigned char *data,
 *                                              SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Sends encrypted message to the `channel'.  The plaintext message is
 *    the `data' of `data_len' bytes in length.
 *
 *    If `key' is provided then that private channel message key is used to
 *    encrypt the message.  If it is not provided and the `channel' does not
 *    have SILC_CHANNEL_MODE_PRIVKEY set, the curent channel key is used
 *    instead.  If the mode is set but `key' is NULL the key that was added
 *    first as private channel message key will be used.
 *
 *    If the `flags' includes SILC_MESSAGE_FLAG_SIGNED the message will be
 *    digitally signed with the SILC key pair associated with the `conn'.
 *    In this case the `hash' pointer must be provided as well.
 *
 *    Returns TRUE if the message was sent, and FALSE if error occurred or
 *    the sending is not allowed due to channel modes (like sending is
 *    blocked).  This function is thread safe and channel messages can be
 *    sent from multiple threads.
 *
 ***/
SilcBool silc_client_send_channel_message(SilcClient client,
					  SilcClientConnection conn,
					  SilcChannelEntry channel,
					  SilcChannelPrivateKey key,
					  SilcMessageFlags flags,
					  SilcHash hash,
					  unsigned char *data,
					  SilcUInt32 data_len);

/****f* silcclient/SilcClientAPI/silc_client_send_private_message
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_send_private_message(SilcClient client,
 *                                              SilcClientConnection conn,
 *                                              SilcClientEntry client_entry,
 *                                              SilcMessageFlags flags,
 *                                              SilcHash hash,
 *                                              unsigned char *data,
 *                                              SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Sends private message to remote client. If private message key has
 *    not been set with this client then the message will be encrypted using
 *    the session keys used in `conn' connection.  If the `flags' includes
 *    SILC_MESSAGE_FLAG_SIGNED the message will be digitally signed with the
 *    SILC key pair associated with `conn'.  In this case the caller must also
 *    provide the `hash' pointer.
 *
 *    Returns TRUE if the message was sent, and FALSE if error occurred.
 *    This function is thread safe and private messages can be sent from
 *    multiple threads.
 *
 ***/
SilcBool silc_client_send_private_message(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  SilcMessageFlags flags,
					  SilcHash hash,
					  unsigned char *data,
					  SilcUInt32 data_len);

/****f* silcclient/SilcClientAPI/silc_client_private_message_wait_init
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_private_message_wait_init(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Initializes private message waiting functionality for the client
 *    indicated by `client_entry'.  Once this is called private message
 *    from remote connection indicated by `conn' for `client_entry' may
 *    be waiter for, for example in a thread.  The function
 *    silc_client_private_message_wait is used to block the current thread
 *    until a private message is received from a specified client entry.
 *    Return FALSE in case an internal error occurred.
 *
 ***/
SilcBool silc_client_private_message_wait_init(SilcClient client,
					       SilcClientConnection conn,
					       SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_private_message_wait_uninit
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_private_message_wait_uninit(SilcClient client,
 *                                            SilcClientConnection conn,
 *                                            SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Unintializes private message waiting for client indicated by
 *    `client_entry'.  After this call private message cannot be waited
 *    anymore and silc_client_private_message_wait will return with FALSE
 *    value.
 *
 ***/
void silc_client_private_message_wait_uninit(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry);

/****f* silcclient/SilcClientAPI/silc_client_private_message_wait
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_private_message_wait(SilcClient client,
 *                                     SilcClientConnection conn,
 *                                     SilcClientEntry client_entry,
 *                                     SilcMessagePayload *payload);
 *
 * DESCRIPTION
 *
 *    Blocks current thread or process until a private message has been
 *    received from the remote client indicated by `client_entry'.  Before
 *    private messages can be waited the silc_client_private_message_wait_init
 *    must be called.  This function can be used from a thread to wait for
 *    private message from the specified client.  Multiple threads can be
 *    created to wait messages from multiple clients.  Any other private
 *    message received from the connection indicated by `conn' will be
 *    forwarded to the normal `private_message' client operation callback.
 *    The private messages from `client_entry' will not be delivered to the
 *    `private_message' client operation callback.
 *
 *    Returns TRUE and the received private message into `payload'.  The caller
 *    must free the returned SilcMessagePayload.  If this function returns
 *    FALSE the private messages cannot be waited anymore.  This happens
 *    when some other thread calls silc_client_private_message_wait_uninit.
 *    This returns FALSE also if silc_client_private_message_wait_init has
 *    not been called.
 *
 ***/
SilcBool silc_client_private_message_wait(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  SilcMessagePayload *payload);

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


/* Command management */

/****f* silcclient/SilcClientAPI/silc_client_command_call
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_client_command_call(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        const char *command_line, ...);
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
 *    Returns command identifier for this sent command.  It can be used
 *    to additionally attach to the command reply using the function
 *    silc_client_command_pending, if needed.  Returns 0 on error.
 *
 *    The `command' client operation callback will be called when the
 *    command is executed to indicate whether or not the command executed
 *    successfully.
 *
 *    The `command_reply' client operation callbak will be called when reply
 *    is received from the server to the command.  Application may also use
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
SilcUInt16 silc_client_command_call(SilcClient client,
				    SilcClientConnection conn,
				    const char *command_line, ...);

/****f* silcclient/SilcClientAPI/SilcClientCommandReply
 *
 * SYNOPSIS
 *
 *    typedef SilcBool (*SilcClientCommandReply)(SilcClient client,
 *                                               SilcClientConnection conn,
 *                                               SilcCommand command,
 *                                               SilcStatus status,
 *                                               SilcStatus error,
 *                                               void *context,
 *                                               va_list ap);
 *
 * DESCRIPTION
 *
 *    The command reply callback function given as argument to functions
 *    silc_client_command_send and silc_client_command_pending.  This is
 *    called to deliver the command replies to the caller.  Each command
 *    reply received from the server to the `command' will be delivered
 *    separately to the caller by calling this callback.  The `status' will
 *    indicate whether there is only one reply or multiple replies.  The
 *    `error' will indicate if an error occurred.  The `ap' will include
 *    command reply arguments.  They are the same arguments as for
 *    `command_reply' client operation callback in SilcClientOperations.
 *
 *    If `status' is SILC_STATUS_OK only one reply was received and error
 *    did not occur.  If it is SILC_STATUS_LIST_START, SILC_STATUS_LIST_ITEM
 *    or SILC_STATUS_LIST_END, there are will be two or more replies.  The
 *    first reply is SILC_STATUS_LIST_START and last one SILC_STATUS_LIST_END.
 *
 *    If FALSE is returned in this function this callback will not be called
 *    again for `command' even if there are more comand replies.  By returning
 *    FALSE the caller my stop the command reply handling when needed.
 *
 ***/
typedef SilcBool (*SilcClientCommandReply)(SilcClient client,
					   SilcClientConnection conn,
					   SilcCommand command,
					   SilcStatus status,
					   SilcStatus error,
					   void *context,
					   va_list ap);

/****f* silcclient/SilcClientAPI/silc_client_command_send
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_client_command_send(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        SilcCommand command,
 *                                        SilcClientCommandReply reply,
 *                                        void *reply_context,
 *                                        SilcUInt32 argc, ...);
 *
 * DESCRIPTION
 *
 *    Generic function to send any command.  The arguments must be given
 *    already encoded into correct format and in correct order. If application
 *    wants to perform the commands by itself, it can do so and send the data
 *    directly to the server using this function.  If application is using
 *    the silc_client_command_call, this function is usually not used.
 *    Programmer should get familiar with the SILC protocol commands
 *    specification when using this function, as the arguments needs to
 *    be encoded as specified in the protocol.
 *
 *    The variable arguments are a set of { type, data, data_length },
 *    and the `argc' is the number of these sets.
 *
 *    The `reply' callback must be provided, and it is called when the
 *    command reply is received from the server.  Note that, when using this
 *    function the default `command_reply' client operation callback will not
 *    be called when reply is received.
 *
 *    Returns command identifier for this sent command.  It can be used
 *    to additionally attach to the command reply using the function
 *    silc_client_command_pending, if needed.  Returns 0 on error.
 *
 * EXAMPLE
 *
 *    silc_client_command_send(client, conn, SILC_COMMAND_WHOIS,
 *                             my_whois_command_reply, cmd_ctx,
 *                             1, 1, nickname, strlen(nickname));
 *
 ***/
SilcUInt16 silc_client_command_send(SilcClient client,
				    SilcClientConnection conn,
				    SilcCommand command,
				    SilcClientCommandReply reply,
				    void *reply_context,
				    SilcUInt32 argc, ...);

/****f* silcclient/SilcClientAPI/silc_client_command_pending
 *
 * SYNOPSIS
 *
 *    void silc_client_command_pending(SilcClientConnection conn,
 *                                     SilcCommand command,
 *                                     SilcUInt16 cmd_ident,
 *                                     SilcClientCommandReply reply,
 *                                     void *context);
 *
 * DESCRIPTION
 *
 *    This function can be used to add pending command callback to be
 *    called when an command reply is received to an earlier sent command.
 *    The `command' is the command that must be received in order for
 *    the pending command callback indicated by `callback' to be called.
 *
 *    The `cmd_ident' is a command identifier which was set for the earlier
 *    sent command.  The command reply will include the same identifier
 *    and pending command callback will be called when the reply is
 *    received with the same command identifier.  It is possible to
 *    add multiple pending command callbacks for same command and for
 *    same identifier.
 *
 *    Application may use this function to add its own command reply
 *    handlers if it wishes not to use the standard `command_reply'
 *    client operation.
 *
 *    Note also that the application is notified about the received command
 *    reply through the `command_reply' client operation before calling
 *    the `callback` pending command callback.  That is the normal
 *    command reply handling, and is called regardless whether pending
 *    command callbacks are used or not.
 *
 * EXAMPLE
 *
 *    SilcUInt16 cmd_ident;
 *    cmd_ident = silc_client_command_call(client, conn,
 *                                         "PING silc.silcnet.org");
 *    silc_client_command_pending(conn, SILC_COMMAND_PING, cmd_ident,
 *                                my_ping_handler, my_ping_context);
 *
 ***/
SilcBool silc_client_command_pending(SilcClientConnection conn,
				     SilcCommand command,
				     SilcUInt16 cmd_ident,
				     SilcClientCommandReply reply,
				     void *context);


/* Private Message key management */

/****f* silcclient/SilcClientAPI/silc_client_add_private_message_key
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_add_private_message_key(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        SilcClientEntry client_entry,
 *                                        const char *cipher,
 *                                        const char *hmac,
 *                                        unsigned char *key,
 *                                        SilcUInt32 key_len);
 *
 * DESCRIPTION
 *
 *    Adds a static private message key to the client library.  The key
 *    will be used to encrypt all private message between the client and
 *    the remote client indicated by the `client_entry'.  The `key' can
 *    be for example a pre-shared-key, passphrase or similar shared secret
 *    string.  The `cipher' and `hmac' MAY be provided but SHOULD be NULL
 *    to assure that the requirements of the SILC protocol are met. The
 *    API, however, allows to allocate any cipher and HMAC.
 *
 *    If the private message key is added to client without first receiving
 *    a request for it from the remote `client_entry' this function will
 *    send the request to `client_entry'.  Note that, the actual key is
 *    not sent to the network.
 *
 *    It is not necessary to set key for normal private message usage. If the
 *    key is not set then the private messages are encrypted using normal
 *    session keys.  Setting the private key, however, increases security.
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
					     SilcUInt32 key_len);

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
 *                                            SilcSKEKeyMaterial key);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_add_private_message_key but takes the key material
 *    from the SKE key material structure.  This structure is received if
 *    the application uses the silc_client_send_key_agreement to negotiate
 *    the key material.  The `cipher' and `hmac' SHOULD be provided as it is
 *    negotiated also in the SKE protocol.
 *
 ***/
SilcBool silc_client_add_private_message_key_ske(SilcClient client,
						 SilcClientConnection conn,
						 SilcClientEntry client_entry,
						 const char *cipher,
						 const char *hmac,
						 SilcSKEKeyMaterial key);

/****f* silcclient/SilcClientAPI/silc_client_del_private_message_key
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_del_private_message_key(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        SilcClientEntry client_entry);
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

/****f* silcclient/SilcClientAPI/silc_client_private_message_key_is_set
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_private_message_key_is_set(SilcClient client,
 *                                           SilcClientConnection conn,
 *                                           SilcClientEntry client_entry);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the private message key has been set for the client
 *    entry indicated by `client_entry'.
 *
 ***/
SilcBool
silc_client_private_message_key_is_set(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry);


/* Channel private key management */

/****f* silcclient/SilcClientAPI/silc_client_add_channel_private_key
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_client_add_channel_private_key(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        SilcChannelEntry channel,
 *                                        const char *name,
 *                                        char *cipher,
 *                                        char *hmac,
 *                                        unsigned char *key,
 *                                        SilcUInt32 key_len,
 *                                        SilcChannelPrivateKey *ret_key);
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
 *                                                  SilcClientConnection conn,
 *                                                  SilcChannelEntry channel);
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
 *                                                 SilcClientConnection conn,
 *                                                 SilcChannelEntry channel,
 *                                                 SilcChannelPrivateKey key);
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
 *    SilcDList
 *    silc_client_list_channel_private_keys(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          SilcChannelEntry channel);
 *
 * DESCRIPTION
 *
 *    Returns list of private keys associated to the `channel'.  The caller
 *    must free the returned list with silc_dlist_uninit.  The pointers in
 *    the list may be used to delete the specific key by giving the pointer
 *    as argument to the function silc_client_del_channel_private_key.  Each
 *    entry in the list is SilcChannelPrivateKey.
 *
 ***/
SilcDList silc_client_list_channel_private_keys(SilcClient client,
						SilcClientConnection conn,
						SilcChannelEntry channel);

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


/* Key Agreement routines */

/****f* silcclient/SilcClientAPI/silc_client_send_key_agreement
 *
 * SYNOPSIS
 *
 *    void silc_client_send_key_agreement(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        SilcClientEntry client_entry,
 *                                        SilcClientConnectionParams *params,
 *                                        SilcPublicKey public_key,
 *                                        SilcPrivateKey private_key,
 *                                        SilcKeyAgreementCallback completion,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Sends key agreement request to the remote client indicated by the
 *    `client_entry'.
 *
 *    If `params' is non-NULL and it has the `local_ip' and `local_port' set
 *    the caller will provide the connection endpoint for the key agreement
 *    connection.  The `bind_ip' can be used to bind to that IP instead of
 *    `local_ip'.  If the `udp' is set to TRUE the connection will be UDP
 *    instead of TCP.  Caller may also set the `repository', `verify_notfound'
 *    and `timeout_secs' fields in `params'.  Other fields are ignored.
 *    If `params' is NULL, then the `client_entry' is expected to provide
 *    the connection endpoint for us.  It is recommended the `timeout_secs'
 *    is specified in case the remote client does not reply anything to
 *    the request.
 *
 *    The `public_key' and `private_key' is our identity in the key agreement.
 *
 *    In case we do not provide the connection endpoint, we will receive
 *    the `key_agreement' client operation when the remote send its own
 *    key agreement request packet.  We may then there start the key
 *    agreement with silc_client_perform_key_agreement.  If we provided the
 *    the connection endpoint, the client operation will not be called.
 *
 *    There can be only one active key agreement for `client_entry'.  Old
 *    key agreement may be aborted by calling silc_client_abort_key_agreement.
 *
 * EXAMPLE
 *
 *    // Send key agreement request (we don't provide connection endpoint)
 *    silc_client_send_key_agreement(client, conn, remote_client,
 *                                   NULL, public_key, private_key,
 *                                   my_keyagr_completion, my_context);
 *
 *    // Another example where we provide connection endpoint (TCP).
 *    SilcClientConnectionParams params;
 *    memset(&params, 0, sizeof(params));
 *    params.local_ip = local_ip;
 *    params.local_port = local_port;
 *    params.timeout_secs = 60;
 *    silc_client_send_key_agreement(client, conn, remote_client,
 *                                   &params, public_key, private_key,
 *                                   my_keyagr_completion, my_context);
 *
 ***/
void silc_client_send_key_agreement(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry,
				    SilcClientConnectionParams *params,
				    SilcPublicKey public_key,
				    SilcPrivateKey private_key,
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
 *                                      SilcClientConnectionParams *params,
 *                                      SilcPublicKey public_key,
 *                                      SilcPrivateKey private_key,
 *                                      char *hostname, int port,
 *                                      SilcKeyAgreementCallback completion,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Performs the key agreement protocol.  Application may use this to
 *    initiate the key agreement protocol.  Usually this is called after
 *    receiving the `key_agreement' client operation.
 *
 *    The `hostname' is the remote hostname (or IP address) and the `port'
 *    is the remote port.  The `completion' callback with the `context' will
 *    be called after the key agreement protocol.
 *
 *    The `params' is connection parameters and it may be used to define
 *    the key agreement connection related parameters.  It may be NULL.
 *
 ***/
void silc_client_perform_key_agreement(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry,
				       SilcClientConnectionParams *params,
				       SilcPublicKey public_key,
				       SilcPrivateKey private_key,
				       char *hostname, int port,
				       SilcKeyAgreementCallback completion,
				       void *context);

/****f* silcclient/SilcClientAPI/silc_client_perform_key_agreement_stream
 *
 * SYNOPSIS
 *
 *    void
 *    silc_client_perform_key_agreement_stream(
 *                                      SilcClient client,
 *                                      SilcClientConnection conn,
 *                                      SilcClientEntry client_entry,
 *                                      SilcClientConnectionParams *params,
 *                                      SilcPublicKey public_key,
 *                                      SilcPrivateKey private_key,
 *                                      SilcStream stream,
 *                                      SilcKeyAgreementCallback completion,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_client_perform_key_agreement but the caller has created
 *    the connection to remote client.  The `stream' is the created
 *    connection.
 *
 ***/
void
silc_client_perform_key_agreement_stream(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 SilcClientConnectionParams *params,
					 SilcPublicKey public_key,
					 SilcPrivateKey private_key,
					 SilcStream stream,
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
 *    SilcBool silc_client_set_away_message(SilcClient client,
 *                                          SilcClientConnection conn,
 *                                          char *message);
 *
 * DESCRIPTION
 *
 *    Sets away `message'.  The away message may be set when the client's
 *    mode is changed to SILC_UMODE_GONE and the client whishes to reply
 *    to anyone who sends private message.  The `message' will be sent
 *    automatically back to the the client who send private message.  If
 *    away message is already set this replaces the old message with the
 *    new one.  If `message' is NULL the old away message is removed.
 *    The sender may freely free the memory of the `message'.  Returns
 *    FALSE on error.
 *
 ***/
SilcBool silc_client_set_away_message(SilcClient client,
				      SilcClientConnection conn,
				      char *message);

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
 *    The SILC_CLIENT_FILE_MONITOR_KEY_AGREEMENT is called when session
 *    is key exchange phase.
 *
 *    The SILC_CLIENT_FILE_MONITOR_SEND is called when data is being sent
 *    to remote client.
 *
 *    The SILC_CLIENT_FILE_MONITOR_RECEIVE is called when data is being
 *    recieved from remote client.
 *
 *    The SILC_CLIENT_FILE_MONITOR_CLOSED will be called when the user
 *    issues silc_client_file_close.  If needed, it may be ignored in the
 *    monitor callback.
 *
 *    The SILC_CLIENT_FILE_MONITOR_DISCONNECT will be called if remote
 *    disconnects the session connection.  The silc_client_file_close must
 *    be called when this status is received.  The session is over when
 *    this is received.
 *
 *    The SILC_CLIENLT_FILE_MONITOR_ERROR is called in case some error
 *    occured.  The SilcClientFileError will indicate more detailed error
 *    condition.  The silc_client_file_close must be called when this status
 *    is received.  The session is over when this is received.
 *
 * SOURCE
 */
typedef enum {
  SILC_CLIENT_FILE_MONITOR_KEY_AGREEMENT,    /* In key agreemenet phase */
  SILC_CLIENT_FILE_MONITOR_SEND,	     /* Sending file */
  SILC_CLIENT_FILE_MONITOR_RECEIVE,	     /* Receiving file */
  SILC_CLIENT_FILE_MONITOR_GET,		     /* Unsupported */
  SILC_CLIENT_FILE_MONITOR_PUT,		     /* Unsupported */
  SILC_CLIENT_FILE_MONITOR_CLOSED,	     /* Session closed */
  SILC_CLIENT_FILE_MONITOR_DISCONNECT,	     /* Session disconnected */
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
  SILC_CLIENT_FILE_ERROR,	             /* Generic error */
  SILC_CLIENT_FILE_UNKNOWN_SESSION,	     /* Unknown session ID */
  SILC_CLIENT_FILE_ALREADY_STARTED,	     /* Session already started */
  SILC_CLIENT_FILE_NO_SUCH_FILE,	     /* No such file */
  SILC_CLIENT_FILE_PERMISSION_DENIED,	     /* Permission denied */
  SILC_CLIENT_FILE_KEY_AGREEMENT_FAILED,     /* Key exchange failed */
  SILC_CLIENT_FILE_CONNECT_FAILED,	     /* Error during connecting */
  SILC_CLIENT_FILE_TIMEOUT,	             /* Connecting timedout */
  SILC_CLIENT_FILE_NO_MEMORY,		     /* System out of memory */
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
 *    `filepath'.  The `conn' is NULL if the connection to remote client
 *    does not exist yet.
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
 *    File name asking callback that is called if it is given to the
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
 *                          SilcClientEntry client_entry,
 *                          SilcClientConnectionParams *params,
 *                          SilcPublicKey public_key,
 *                          SilcPrivateKey private_key,
 *                          SilcClientFileMonitor monitor,
 *                          void *monitor_context,
 *                          const char *filepath,
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
 *    If `params' is non-NULL and it has the `local_ip' and `local_port' set
 *    the caller will provide the connection endpoint for the key agreement
 *    connection.  The `bind_ip' can be used to bind to that IP instead of
 *    `local_ip'.  Caller may also set the `repository', `verify_notfound'
 *    and `timeout_secs' fields in `params'.  Other fields are ignored.
 *    If `params' is NULL, then the `client_entry' is expected to provide
 *    the connection endpoint for us.  It is recommended the `timeout_secs'
 *    is specified in case the remote client does not reply anything to
 *    the request.
 *
 *    The `public_key' and `private_key' is our identity in the key agreement.
 *
 *    If error will occur during the file transfer process the error status
 *    will be returned in the monitor callback.  In this case the application
 *    must call silc_client_file_close to close the session.
 *
 ***/
SilcClientFileError
silc_client_file_send(SilcClient client,
		      SilcClientConnection conn,
		      SilcClientEntry client_entry,
		      SilcClientConnectionParams *params,
		      SilcPublicKey public_key,
		      SilcPrivateKey private_key,
		      SilcClientFileMonitor monitor,
		      void *monitor_context,
		      const char *filepath,
		      SilcUInt32 *session_id);

/****f* silcclient/SilcClientAPI/silc_client_file_receive
 *
 * SYNOPSIS
 *
 *    SilcClientFileError
 *    silc_client_file_receive(SilcClient client,
 *                             SilcClientConnection conn,
 *                             SilcClientConnectionParams *params,
 *                             SilcPublicKey public_key,
 *                             SilcPrivateKey private_key,
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
 *    received in the `ftp' client operation callback.  This will actually
 *    perform the key agreement protocol with the remote client before
 *    actually starting the file transmission.  The `monitor' callback
 *    will be called to monitor the transmission.  If `path' is non-NULL
 *    the file will be saved into that directory.  If NULL the file is
 *    saved in the current working directory, unless the 'ask_name'
 *    callback is non-NULL.  In this case the callback is called to ask
 *    the path and filename from application.
 *
 *    The `params' is the connection related parameters.  If the remote client
 *    provided connection point the `params' will be used when creating
 *    connection to the remote client.  If remote client did not provide
 *    connection point the `params' is used to provide connection point
 *    locally for the remote client.  See silc_client_file_send for more
 *    information on providing connection point for remote client.
 *
 *    The `public_key' and `private_key' is our identity in the key agreement.
 *
 *    If error will occur during the file transfer process the error status
 *    will be returned in the monitor callback.  In this case the application
 *    must call silc_client_file_close to close the session.
 *
 ***/
SilcClientFileError
silc_client_file_receive(SilcClient client,
			 SilcClientConnection conn,
			 SilcClientConnectionParams *params,
			 SilcPublicKey public_key,
			 SilcPrivateKey private_key,
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

/****f* silcclient/SilcClientAPI/silc_client_nickname_format
 *
 * SYNOPSIS
 *
 *    SilcClientEntry
 *    silc_client_nickname_format(SilcClient client,
 *                                SilcClientConnection conn,
 *                                SilcClientEntry client_entry,
 *                                SilcBool priority);
 *
 * DESCRIPTION
 *
 *    Formats the nickname of `client_entry' according to the nickname
 *    formatting rules set in SilcClientParams.  If the `priority' is TRUE
 *    then the `client_entry' will always get the unformatted nickname.
 *    If FALSE and there are more than one same nicknames in the client
 *    the nickname will be formatted.
 *
 *    This returns NULL on error.  Otherwise, the client entry that was
 *    formatted is returned.  If `priority' is FALSE this always returns
 *    the `client_entry'.  If it is TRUE, this may return the client entry
 *    that was formatted after giving the `client_entry' the unformatted
 *    nickname.
 *
 *    Usually application does not need to call this function, as the library
 *    automatically formats nicknames.  However, if application wants to
 *    for example force the `client_entry' to always have the unformatted
 *    nickname it may call this function to do so.
 *
 ***/
SilcClientEntry silc_client_nickname_format(SilcClient client,
					    SilcClientConnection conn,
					    SilcClientEntry client_entry,
					    SilcBool priority);

/****f* silcclient/SilcClientAPI/silc_client_nickname_parse
 *
 * SYNOPSIS
 *
 *    SilcBool silc_client_nickname_parse(SilcClient client,
 *                                        SilcClientConnection conn,
 *                                        char *nickname,
 *                                        char **ret_nick);
 *
 * DESCRIPTION
 *
 *    Parses the `nickname' according to the format string given in the
 *    SilcClientParams.  Returns the parsed nickname into the `ret_nick'.
 *    The caller must free the returned pointer.  Returns FALSE if error
 *    occurred during parsing.  Returns TRUE if the nickname was parsed,
 *    it was not formatted or if the format string has not been specified
 *    in SilcClientParams.
 *
 ***/
SilcBool silc_client_nickname_parse(SilcClient client,
				    SilcClientConnection conn,
				    char *nickname,
				    char **ret_nick);

#ifdef __cplusplus
}
#endif

#endif /* SILCCLIENT_H */
