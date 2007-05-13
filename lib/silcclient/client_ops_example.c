/* Predefined stub functions for the SilcClientOperation callbacks.
   You can freely use this template in your application. These are
   the functions that you as an application programmer need to implement
   for the library.  The library may call these functions at any time.

   At the end of this file SilcClientOperation structure is defined, and
   it is the one the you will give as an argument to the silc_client_alloc
   function. See also lib/silcclient/README file, and silcclient.h.

   You may freely use this file in your application. */


/* Message sent to the application by library. `conn' associates the
   message to a specific connection.  `conn', however, may be NULL.
   The `type' indicates the type of the message sent by the library.
   The application can for example filter the message according the
   type.  The variable argument list is arguments to the formatted
   message that `msg' may be. */
void silc_say(SilcClient client, SilcClientConnection conn,
	      SilcClientMessageType type, char *msg, ...);

/* Message for a channel. The `sender' is the sender of the message
   The `channel' is the channel. The `message' is the message.  Note
   that `message' maybe NULL.  The `flags' indicates message flags
   and it is used to determine how the message can be interpreted
   (like it may tell the message is multimedia message). */
void silc_channel_message(SilcClient client, SilcClientConnection conn,
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
void silc_private_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessagePayload payload,
			  SilcMessageFlags flags, const unsigned char *message,
			  SilcUInt32 message_len);

/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it because client library gets the channel entry from
   the Channel ID in the packet's header). */
void silc_notify(SilcClient client, SilcClientConnection conn,
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
void silc_command(SilcClient client, SilcClientConnection conn,
		  SilcBool success, SilcCommand command, SilcStatus status,
		  SilcUInt32 argc, unsigned char **argv);

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
   SilcClientEntry.

   See: http://silcnet.org/docs/toolkit/command_reply_args.html */
void silc_command_reply(SilcClient client, SilcClientConnection conn,
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
void silc_get_auth_method(SilcClient client, SilcClientConnection conn,
			  char *hostname, SilcUInt16 port,
			  SilcAuthMethod auth_method,
			  SilcGetAuthMeth completion, void *context);

/* Verifies received public key. The `conn_type' indicates which entity
   (server or client) has sent the public key. If user decides to trust
   the key the application may save the key as trusted public key for
   later use. The `completion' must be called after the public key has
   been verified. */
void silc_verify_public_key(SilcClient client, SilcClientConnection conn,
			    SilcConnectionType conn_type,
			    SilcPublicKey public_key,
			    SilcVerifyPublicKey completion, void *context);

/* Ask (interact, that is) a passphrase from user. The passphrase is
   returned to the library by calling the `completion' callback with
   the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
   if not then the library will attempt to encode. */
void silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
			 SilcAskPassphrase completion, void *context);

/* Called to indicate that incoming key agreement request has been
   received.  If the application wants to perform key agreement it may
   call silc_client_perform_key_agreement to initiate key agreementn or
   silc_client_send_key_agreement to provide connection point to the
   remote client in case the `hostname' is NULL.  If key agreement is
   not desired this request can be ignored.  The `protocol' is either
   value 0 for TCP or value 1 for UDP. */
void silc_key_agreement(SilcClient client, SilcClientConnection conn,
			SilcClientEntry client_entry,
			const char *hostname, SilcUInt16 protocol,
			SilcUInt16 port);

/* Notifies application that file transfer protocol session is being
   requested by the remote client indicated by the `client_entry' from
   the `hostname' and `port'. The `session_id' is the file transfer
   session and it can be used to either accept or reject the file
   transfer request, by calling the silc_client_file_receive or
   silc_client_file_close, respectively. */
void silc_ftp(SilcClient client, SilcClientConnection conn,
	      SilcClientEntry client_entry, SilcUInt32 session_id,
	      const char *hostname, SilcUInt16 port);

/* The SilcClientOperation structure containing the operation functions.
   You will give this as an argument to silc_client_alloc function. */
SilcClientOperations ops = {
  silc_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_get_auth_method,
  silc_verify_public_key,
  silc_ask_passphrase,
  silc_key_agreement,
  silc_ftp
};
