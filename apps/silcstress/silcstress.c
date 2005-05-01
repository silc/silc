/*

  silcstress.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/*
  TODO:

  - join to created clients with another client, to get the sent messages
    as reply (channel message).
  - create x clients

*/

/*
  Results:

  SILC Server 0.9.20 (debug), Linux 2.6.11, RAM 512 MB:

    - 3000 channels == silcd size 10 MB (-c 3000 -n)
    - 10000 channels == silcd size 37 MB (-c 10000 -n)
      (Flooding channel creation is very heavy operation for silcd; JOIN
       should be controlled better in silcd)

    - 1 channel, default data flood, QoS == silcd load < 1.0%
    - 10 channels, default data flood, QoS == silcd load < 4.0%
    - 100 channels, default data flood, QoS == silcd load < 5.0%
      (Qos: rate=20, bytes_limit=500B, usec_limit=200000)

*/

#include "silcincludes.h"
#include "silcclient.h"

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  int msize;
  int loops;
  int flood;
  int channels;
  bool nosend;
  SilcMutex m;
} *SilcStress;

typedef struct {
  SilcStress sc;
  SilcChannelEntry channel;
} *SilcStressWorker;

SilcClientOperations ops;

/* Long command line options */
static struct option long_opts[] =
{
  { "server", 1, NULL,'s' },
  { "port", 1, NULL,'p' },
  { "channels", 1, NULL,'c' },
  { "msize", 1, NULL,'m' },
  { "loops", 1, NULL,'l' },
  { "flood", 1, NULL,'f' },
  { "nosend", 0, NULL,'n' },
  { "debug", 2, NULL, 'd' },
  { "help", 0, NULL, 'h' },
  { "version", 0, NULL,'V' },

  { NULL, 0, NULL, 0 }
};

static void silc_stress_usage(void)
{
  printf(""
"Usage: silcstress [options]\n"
"\n"
"  Generic Options:\n"
"  -s  --server=server           Server to connect\n"
"  -p  --port=NUMBER             Server port to connect (def: 706)\n"
"  -c  --channels=NUMBER         Number of channels to create (def: 1)\n"
"  -m  --msize=NUMBER            Size of message in bytes (def: 512)\n"
"  -l  --loops=NUMBER            Number of loops to send data (def: 1024)\n"
"  -f  --flood=NUMBER            Send message in every usec (def: 50000)\n"
"  -n  --nosend                  Don't send any data\n"
"  -d  --debug=string            Enable debugging\n"
"  -h  --help                    Display this message and exit\n"
"  -V  --version                 Display version and exit\n"
"\n");
  exit(0);
}

int main(int argc, char **argv)
{
  int opt, option_index;
  int c = 1, port = 706, b = 512, l = 1024, f = 50000, n = FALSE;
  char *server = NULL;
  SilcStress sc;

  if (argc > 1) {
    while ((opt = getopt_long(argc, argv, "d:hVc:s:p:m:l:f:n",
			      long_opts, &option_index)) != EOF) {
      switch(opt) {
	case 'h':
	  silc_stress_usage();
	  break;
	case 'V':
	  printf("SILC Stress, version %s\n", silc_dist_version);
	  printf("(c) 2005 Pekka Riikonen <priikone@silcnet.org>\n");
	  exit(0);
	  break;
	case 'd':
#ifdef SILC_DEBUG
	  silc_debug = TRUE;
	  silc_debug_hexdump = TRUE;
	  if (optarg)
	    silc_log_set_debug_string(optarg);
	  silc_log_quick = TRUE;
#else
	  fprintf(stderr,
		  "Run-time debugging is not enabled. To enable it recompile\n"
		  "the server with --enable-debug configuration option.\n");
#endif
	  break;
	case 'c':
	  c = atoi(optarg);
	  break;
	case 'l':
	  l = atoi(optarg);
	  break;
	case 'f':
	  f = atoi(optarg);
	  break;
	case 'm':
	  b = atoi(optarg);
	  break;
	case 'p':
	  port = atoi(optarg);
	  break;
	case 's':
	  server = strdup(optarg);
	  break;
	case 'n':
	  n = TRUE;
	  break;
	default:
	  silc_stress_usage();
	  break;
      }
    }
  }

  if (!server)
    silc_stress_usage();

  sc = silc_calloc(1, sizeof(*sc));
  if (!sc)
    return 1;
  sc->channels = c;
  sc->msize = b;
  sc->loops = l;
  sc->flood = f;
  sc->nosend = n;

  sc->client = silc_client_alloc(&ops, NULL, sc, NULL);
  if (!sc->client)
    return 1;

  sc->client->username = silc_get_username();
  sc->client->hostname = silc_net_localhost();
  sc->client->realname = strdup("SILC STRESS");

  if (!silc_client_init(sc->client))
    return 1;

  if (!silc_load_key_pair("silcstress.pub", "silcstress.prv", "",
			  &sc->client->pkcs,
			  &sc->client->public_key,
			  &sc->client->private_key)) {
    if (!silc_create_key_pair("rsa", 2048, "silcstress.pub",
			      "silcstress.prv", NULL, "",
			      &sc->client->pkcs,
			      &sc->client->public_key,
			      &sc->client->private_key, FALSE)) {
      return 1;
    }
  }

  silc_mutex_alloc(&sc->m);

  silc_client_connect_to_server(sc->client, NULL, port, server, sc);

  silc_client_run(sc->client);

  silc_client_free(sc->client);
  silc_free(sc);
  silc_free(server);

  return 0;
}

/* Worker thread */

static void *
silc_stress_worker(void *context)
{
  SilcStressWorker w = context;
  SilcClient client = w->sc->client;
  SilcClientConnection conn = w->sc->conn;
  SilcChannelEntry channel = w->channel;
  char *tmp;
  int i;

  tmp = silc_calloc(w->sc->msize, sizeof(*tmp));
  if (!tmp)
    return NULL;

  memset(tmp, 'M', w->sc->msize);

  for (i = 0; i < w->sc->loops; i++) {
    /* Our packet routines don't like threads, so let's lock :( */
    silc_mutex_lock(w->sc->m);
    if (!w->sc->conn)
      return NULL;
    silc_client_send_channel_message(client, conn, channel, NULL, 0,
				     tmp, w->sc->msize, TRUE);
    silc_mutex_unlock(w->sc->m);
    usleep(w->sc->flood);
  }

  silc_free(tmp);

  return NULL;
}


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
  fprintf(stdout, "%s\n", str);
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
		     SilcMessagePayload payload,
		     SilcChannelPrivateKey key,
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
		     SilcMessageFlags flags,
		     const unsigned char *message,
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
	     SilcClientCommandContext cmd_context, bool success,
	     SilcCommand command, SilcStatus status)
{
  /* If error occurred in client library with our command, print the error */
  if (status != SILC_STATUS_OK)
    fprintf(stderr, "COMMAND %s: %s\n",
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
  SilcStress sc = client->application;
  va_list va;

  /* If error occurred in client library with our command, print the error */
  if (status != SILC_STATUS_OK)
    fprintf(stderr, "COMMAND REPLY %s: %s\n",
	    silc_get_command_name(command),
	    silc_get_status_message(status));

  va_start(va, status);

  /* Check for successful JOIN */
  if (command == SILC_COMMAND_JOIN && sc->nosend == FALSE) {
    /* Create worker thread for data sending */
    SilcThread t;
    SilcChannelEntry channel;
    SilcStressWorker w;

    (void)va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    w = silc_calloc(1, sizeof(*w));
    if (!w)
      exit(1);

    w->sc = sc;
    w->channel = channel;

    t = silc_thread_create(silc_stress_worker, w, FALSE);
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
  SilcStress sc = client->application;
  char tmp[16];
  int i;

  if (status != SILC_CLIENT_CONN_SUCCESS) {
    fprintf(stderr, "Could not connect to server\n");
    silc_client_close_connection(client, conn);
    return;
  }

  fprintf(stdout, "Connected to server.\n");

  /* Save the connection context */
  sc->conn = conn;

  /* Join channels */
  for (i = 0; i < sc->channels; i++) {
    memset(tmp, 0, sizeof(tmp));
    snprintf(tmp, sizeof(tmp) - 1, "JOIN %d", i);
    silc_client_command_call(client, conn, tmp);
  }


}


/* Called to indicate that connection was disconnected to the server.
   The `status' may tell the reason of the disconnection, and if the
   `message' is non-NULL it may include the disconnection message
   received from server. */

static void
silc_disconnected(SilcClient client, SilcClientConnection conn,
		  SilcStatus status, const char *message)
{
  SilcStress sc = client->application;

  /* We got disconnected from server */
  sc->conn = NULL;
  fprintf(stdout, "%s:%s\n", silc_get_status_message(status),
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
  fprintf(stderr, "Connecting failed (protocol failure)\n");
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
