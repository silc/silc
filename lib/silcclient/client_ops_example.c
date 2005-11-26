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
   type. */

static void
silc_say(SilcClient client, SilcClientConnection conn,
	 SilcClientMessageType type, char *msg, ...)
{

}


/* Message for a channel. The `sender' is the sender of the message
   The `channel' is the channel. The `message' is the message.  Note
   that `message' maybe NULL.  The `flags' indicates message flags
   and it is used to determine how the message can be interpreted
   (like it may tell the message is multimedia message). */

static void
silc_channel_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcChannelEntry channel,
		     SilcMessagePayload payload, SilcChannelPrivateKey key,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len)
{

}


/* Private message to the client. The `sender' is the sender of the
   message. The message is `message'and maybe NULL.  The `flags'
   indicates message flags  and it is used to determine how the message
   can be interpreted (like it may tell the message is multimedia
   message). */

static void
silc_private_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcMessagePayload payload,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len)
{

}


/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it because client library gets the channel entry from
   the Channel ID in the packet's header). */

static void
silc_notify(SilcClient client, SilcClientConnection conn,
	    SilcNotifyType type, ...)
{

}


/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occurred
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

static void
silc_command(SilcClient client, SilcClientConnection conn,
	     SilcClientCommandContext cmd_context, SilcBool success,
	     SilcCommand command, SilcStatus status)
{

}


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
   application (on error they are not sent). */

static void
silc_command_reply(SilcClient client, SilcClientConnection conn,
		   SilcCommandPayload cmd_payload, SilcBool success,
		   SilcCommand command, SilcStatus status, ...)
{

}


/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection objecet which it should save somewhere.
   If the `success' is FALSE the application must always call the function
   silc_client_close_connection. */

static void
silc_connected(SilcClient client, SilcClientConnection conn,
	       SilcClientConnectionStatus status)
{

}


/* Called to indicate that connection was disconnected to the server.
   The `status' may tell the reason of the disconnection, and if the
   `message' is non-NULL it may include the disconnection message
   received from server. */

static void
silc_disconnected(SilcClient client, SilcClientConnection conn,
		  SilcStatus status, const char *message)
{

}


/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. When the authentication
   method has been resolved the `completion' callback with the found
   authentication method and authentication data is called. The `conn'
   may be NULL. */

static void
silc_get_auth_method(SilcClient client, SilcClientConnection conn,
		     char *hostname, SilcUInt16 port, SilcGetAuthMeth completion,
		     void *context)
{

}


/* Verifies received public key. The `conn_type' indicates which entity
   (server, client etc.) has sent the public key. If user decides to trust
   the application may save the key as trusted public key for later
   use. The `completion' must be called after the public key has been
   verified. */

static void
silc_verify_public_key(SilcClient client, SilcClientConnection conn,
		       SilcSocketType conn_type, unsigned char *pk,
		       SilcUInt32 pk_len, SilcSKEPKType pk_type,
		       SilcVerifyPublicKey completion, void *context)
{

}


/* Ask (interact, that is) a passphrase from user. The passphrase is
   returned to the library by calling the `completion' callback with
   the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
   if not then the library will attempt to encode. */

static void
silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
		    SilcAskPassphrase completion, void *context)
{

}


/* Notifies application that failure packet was received.  This is called
   if there is some protocol active in the client.  The `protocol' is the
   protocol context.  The `failure' is opaque pointer to the failure
   indication.  Note, that the `failure' is protocol dependant and
   application must explicitly cast it to correct type.  Usually `failure'
   is 32 bit failure type (see protocol specs for all protocol failure
   types). */

static void
silc_failure(SilcClient client, SilcClientConnection conn,
	     SilcProtocol protocol, void *failure)
{

}


/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). If TRUE is returned also the
   `completion' and `context' arguments must be set by the application. */

static SilcBool
silc_key_agreement(SilcClient client, SilcClientConnection conn,
		   SilcClientEntry client_entry, const char *hostname,
		   SilcUInt16 port, SilcKeyAgreementCallback *completion,
		   void **context)
{

}


/* Notifies application that file transfer protocol session is being
   requested by the remote client indicated by the `client_entry' from
   the `hostname' and `port'. The `session_id' is the file transfer
   session and it can be used to either accept or reject the file
   transfer request, by calling the silc_client_file_receive or
   silc_client_file_close, respectively. */

static void
silc_ftp(SilcClient client, SilcClientConnection conn,
	 SilcClientEntry client_entry, SilcUInt32 session_id,
	 const char *hostname, SilcUInt16 port)
{

}


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

static void
silc_detach(SilcClient client, SilcClientConnection conn,
	    const unsigned char *detach_data, SilcUInt32 detach_data_len)
{

}


/* The SilcClientOperation structure containing the operation functions.
   You will give this as an argument to silc_client_alloc function. */
SilcClientOperations ops = {
  silc_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_connected,
  silc_disconnected,
  silc_get_auth_method,
  silc_verify_public_key,
  silc_ask_passphrase,
  silc_failure,
  silc_key_agreement,
  silc_ftp,
  silc_detach
};
