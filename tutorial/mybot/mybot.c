/*

  mybot.c 

  Author: Pekka Riikonen <priikone@silcnet.org>, November 2002
  This code is Public Domain.

  MyBot

  Example SILC client called "mybot".  It is a robot client which
  connects to SILC Network into silc.silcnet.org server and joins
  channel called "mybot" and says "hello" on the channel.

  This code use the SILC Client Library provided by the SILC
  Toolkit distribution.

  Compilation:

  gcc -o mybot mybot.c -I/usr/local/silc/include -L/usr/local/silc/lib \
      -lsilc -lsilcclient -lpthread -ldl

  The MyBot works as follows (logicly):

  main -> mybot_start -> silc_client_connect_to_server
                v
          silc_client_run (message loop...)
                v
          silc_verify_public_key
                v
          silc_get_auth_method
                v
          silc_connected -> silc_client_send_command (JOIN)
                v
          silc_command_reply -> silc_send_channel_message ("hello")
                v
          message loop...
                v
  main <- mybot_start

*/

#include "silcincludes.h"	/* Mandatory include for SILC applications */
#include "silcclient.h"		/* SILC Client Library API */

SilcClientOperations ops;

/******* MyBot code **********************************************************/

/* This is context for our MyBot client */
typedef struct {
  SilcClient client;		/* The actual SILC Client */
  SilcClientConnection conn;	/* Connection to the server */
} *MyBot;

/* Start the MyBot, by creating the SILC Client entity by using the
   SILC Client Library API. */
int mybot_start(void)
{
  MyBot mybot;

  /* Allocate the MyBot structure */
  mybot = silc_calloc(1, sizeof(*mybot));
  if (!mybot) {
    perror("Out of memory");
    return 1;
  }

  /* Allocate our SILC Client which is the MyBot.  The arguments to the
     function are:

     ops           - our client operations that the library requires
     param         - parameters, but we don't have any so we pass NULL,
     application   - our application, ie. the MyBot of course!
     version       - silc version, provided by the library if we put NULL
  */
  mybot->client = silc_client_alloc(&ops, NULL, mybot, NULL);
  if (!mybot->client) {
    perror("Could not allocate SILC Client");
    return 1;
  }

  /* Now fill the allocated client with mandatory parameters the library
     requires: username, hostname and "real name". */
  mybot->client->username = silc_get_username();
  mybot->client->hostname = silc_net_localhost();
  mybot->client->realname = strdup("I am the MyBot");

  /* Now we initialize the client. */
  if (!silc_client_init(mybot->client)) {
    perror("Could not init client");
    return 1;
  }

  /* Then we load our public key from the file.  The library requires
     the key pair loaded before the client is started.  The SILC Toolkit
     provides nice routines to do just that so we don't have to worry
     about much.

     Oh, and if the key pair doesn't exist, we create one here
     automatically, and save them to files for future. */
  if (!silc_load_key_pair("mybot.pub", "mybot.prv", "",
			  &mybot->client->pkcs,
			  &mybot->client->public_key,
			  &mybot->client->private_key)) {
    /* The keys don't exist.  Let's generate us a key pair then!  There's
       nice ready routine for that too.  Let's do 2048 bit RSA key pair. */
    fprintf(stdout, "MyBot: Key pair does not exist, generating it.\n");
    if (!silc_create_key_pair("rsa", 2048, "mybot.pub", "mybot.prv", NULL, "",
			      &mybot->client->pkcs,
			      &mybot->client->public_key,
			      &mybot->client->private_key, FALSE)) {
      perror("Could not generated key pair");
      return 1;
    }
  }

  /* Start connecting to server.  This is asynchronous connecting so the
     connection is actually created later after we run the client. */
  silc_client_connect_to_server(mybot->client, NULL, 706,
				"silc.silcnet.org", mybot);

  /* And, then we are ready to go.  Since we are really simple client we
     don't have user interface and we don't have to deal with message loops
     or interactivity.  That's why we can just hand over the execution
     to the library by calling silc_client_run.  */
  silc_client_run(mybot->client);

  /* When we get here, we have quit the client, so clean up and exit */
  silc_client_free(mybot->client);
  silc_free(mybot);
  return 0;
}

/******* SILC Client Operations **********************************************/

/* The SILC Client Library requires these "client operations".  They are
   functions that the library may call at any time to indicate to application
   that something happened, like message was received, or authentication
   is required or something else.  Since our MyBot is really simple client
   we don't need most of the operations, so we just define them and don't
   do anything in them. */

/* "say" client operation is a message from the client library to the
   application.  It may include error messages or something else.  We
   just dump them to screen. */

static void
silc_say(SilcClient client, SilcClientConnection conn,
	 SilcClientMessageType type, char *msg, ...)
{
  char str[200];
  va_list va;
  va_start(va, msg);
  vsnprintf(str, sizeof(str) - 1, msg, va);
  fprintf(stdout, "MyBot: %s\n", str);
  va_end(va);
}


/* Message for a channel. The `sender' is the sender of the message
   The `channel' is the channel. The `message' is the message.  Note
   that `message' maybe NULL.  The `flags' indicates message flags
   and it is used to determine how the message can be interpreted
   (like it may tell the message is multimedia message). */

static void
silc_channel_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcChannelEntry channel,
		     SilcMessageFlags flags, const unsigned char *message,
		     SilcUInt32 message_len)
{
  /* Yay! We got a message from channel. */
  fprintf(stdout, "<%s> %s\n", sender->nickname, message);
}


/* Private message to the client. The `sender' is the sender of the
   message. The message is `message'and maybe NULL.  The `flags'  
   indicates message flags  and it is used to determine how the message
   can be interpreted (like it may tell the message is multimedia
   message). */

static void
silc_private_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcMessageFlags flags,
		     const unsigned char *message,
		     SilcUInt32 message_len)
{
  /* MyBot does not support private message receiving */
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
  char *str;
  va_list va;

  va_start(va, type);

  /* Here we can receive all kinds of different data from the server, but
     our simple bot is interested only in receiving the "not-so-important"
     stuff, just for fun. :) */
  switch (type) {
  case SILC_NOTIFY_TYPE_NONE:
    /* Received something that we are just going to dump to screen. */
    str = va_arg(va, char *);
    fprintf(stdout, "--- %s\n", str);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /* Received the Message of the Day from the server. */
    str = va_arg(va, char *);
    fprintf(stdout, "%s", str);
    fprintf(stdout, "\n");
    break;

  default:
    /* Ignore rest */
    break;
  }

  va_end(va);
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
	     SilcClientCommandContext cmd_context, bool success,
	     SilcCommand command, SilcStatus status)
{
  /* If error occurred in client library with our command, print the error */
  if (status != SILC_STATUS_OK)
    fprintf(stderr, "MyBot: COMMAND %s: %s\n",
	    silc_get_command_name(command),
	    silc_get_status_message(status));
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
		   SilcCommandPayload cmd_payload, bool success,
		   SilcCommand command, SilcStatus status, ...)
{
  va_list va;

  /* If error occurred in client library with our command, print the error */
  if (status != SILC_STATUS_OK)
    fprintf(stderr, "MyBot: COMMAND REPLY %s: %s\n",
	    silc_get_command_name(command),
	    silc_get_status_message(status));

  va_start(va, status);

  /* Check for successful JOIN */
  if (command == SILC_COMMAND_JOIN) {
    SilcChannelEntry channel;

    (void)va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    fprintf(stdout, "MyBot: Joined '%s' channel\n", channel->channel_name);

    /* Now send the "hello" to the channel */
    silc_client_send_channel_message(client, conn, channel, NULL, 0,
				     "hello", strlen("hello"), FALSE);
    fprintf(stdout, "MyBot: Sent 'hello' to channel\n");
  }

  va_end(va);
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
  MyBot mybot = client->application;
  SilcBuffer idp;

  if (status == SILC_CLIENT_CONN_ERROR) {
    fprintf(stderr, "MyBot: Could not connect to server\n");
    silc_client_close_connection(client, conn);
    return;
  }

  fprintf(stdout, "MyBot: Connected to server.\n");

  /* Save the connection context */
  mybot->conn = conn;

  /* Now that we are connected, send the JOIN command to the "mybot"
     channel */
  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);
  silc_client_command_send(client, conn, SILC_COMMAND_JOIN, 0, 2,
			   1, "mybot", strlen("mybot"),
			   2, idp->data, idp->len);
  silc_buffer_free(idp);
}


/* Called to indicate that connection was disconnected to the server.
   The `status' may tell the reason of the disconnection, and if the
   `message' is non-NULL it may include the disconnection message
   received from server. */

static void
silc_disconnected(SilcClient client, SilcClientConnection conn,
		  SilcStatus status, const char *message)
{
  MyBot mybot = client->application;

  /* We got disconnected from server */
  mybot->conn = NULL;
  fprintf(stdout, "MyBot: %s:%s\n", silc_get_status_message(status),
	  message);
}


/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. When the authentication
   method has been resolved the `completion' callback with the found
   authentication method and authentication data is called. The `conn'
   may be NULL. */

static void
silc_get_auth_method(SilcClient client, SilcClientConnection conn,
		     char *hostname, SilcUInt16 port,
		     SilcGetAuthMeth completion,
		     void *context)
{
  /* MyBot assumes that there is no authentication requirement in the
     server and sends nothing as authentication.  We just reply with
     TRUE, meaning we know what is the authentication method. :). */
  completion(TRUE, SILC_AUTH_NONE, NULL, 0, context);
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
  /* MyBot is also very trusting, so we just accept the public key
     we get here.  Of course, we would have to verify the authenticity
     of the public key but our bot is too simple for that.  We just
     reply with TRUE, meaning "yeah, we trust it". :) */
  completion(TRUE, context);
}


/* Ask (interact, that is) a passphrase from user. The passphrase is
   returned to the library by calling the `completion' callback with
   the `context'. The returned passphrase SHOULD be in UTF-8 encoded,
   if not then the library will attempt to encode. */

static void
silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
		    SilcAskPassphrase completion, void *context)
{
  /* MyBot does not support asking passphrases from users since there
     is no user in our little client.  We just reply with nothing. */
  completion(NULL, 0, context);
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
  /* Well, something bad must have happened during connecting to the
     server since we got here.  Let's just print that something failed.
     The "failure" would include more information but let's not bother
     with that now. */
  fprintf(stderr, "MyBot: Connecting failed (protocol failure)\n");
}


/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). If TRUE is returned also the
   `completion' and `context' arguments must be set by the application. */

static bool
silc_key_agreement(SilcClient client, SilcClientConnection conn,
		   SilcClientEntry client_entry, const char *hostname,
		   SilcUInt16 port, SilcKeyAgreementCallback *completion,
		   void **context)
{
  /* MyBot does not support incoming key agreement protocols, it's too
     simple for that. */
  return FALSE;
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
  /* MyBot does not support file transfer, it's too simple for that too. */
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
  /* Oh, and MyBot does not support session detaching either. */
}

/* Our client operations for the MyBot.  This structure is filled with
   functions and given as argument to the silc_client_alloc function.
   Even though our little bot does not need all these functions we must
   provide them since the SILC Client Library wants them all. */
/* This structure and all the functions were taken from the
   lib/silcclient/client_ops_example.c. */
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

int main(int argc, char **argv)
{
  /* Start the bot */
  return mybot_start();
}
