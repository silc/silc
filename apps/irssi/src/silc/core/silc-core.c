/*

  silc-core.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "module.h"
#include "chat-protocols.h"
#include "args.h"

#include "chatnets.h"
#include "servers-setup.h"
#include "channels-setup.h"
#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"
#include "version_internal.h"
#include "version.h"

#include "signals.h"
#include "levels.h"
#include "settings.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"

/* Command line option variables */
static char *opt_server = NULL;
static int opt_port = 0;
static char *opt_nickname = NULL;
static char *opt_channel = NULL;
static char *opt_cipher = NULL;
static char *opt_public_key = NULL;
static char *opt_private_key = NULL;
static char *opt_config_file = NULL;
static bool opt_no_silcrc = FALSE;

static bool opt_create_keypair = FALSE;
static char *opt_pkcs = NULL;
static char *opt_keyfile = NULL;
static int opt_bits = 0;

static int idletag;

SilcClient silc_client = NULL;
SilcClientConfig silc_config = NULL;
extern SilcClientOperations ops;
#ifdef SILC_SIM
/* SIM (SILC Module) table */
SilcSimContext **sims = NULL;
uint32 sims_count = 0;
#endif

static void silc_say(SilcClient client, SilcClientConnection conn,
		     char *msg, ...)
{
  SILC_SERVER_REC *server;
  va_list va;
  char *str;

  server = conn == NULL ? NULL : conn->context;
  
  va_start(va, msg);
  str = g_strdup_vprintf(msg, va);
  printtext(server, "#silc", MSGLEVEL_CRAP, "%s", str);
  g_free(str);
  va_end(va);
}

/* Message for a channel. The `sender' is the nickname of the sender 
   received in the packet. The `channel_name' is the name of the channel. */

static void 
silc_channel_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcChannelEntry channel,
		     SilcMessageFlags flags, char *msg)
{
  SILC_SERVER_REC *server;
  SILC_NICK_REC *nick;
  SILC_CHANNEL_REC *chanrec;
  
  server = conn == NULL ? NULL : conn->context;
  chanrec = silc_channel_find_entry(server, channel);
  
  nick = silc_nicklist_find(chanrec, sender);
  signal_emit("message public", 6, server, msg,
	      nick == NULL ? "(unknown)" : nick->nick,
	      nick == NULL ? NULL : nick->host,
	      chanrec->name, nick);
}

/* Private message to the client. The `sender' is the nickname of the
   sender received in the packet. */

static void 
silc_private_message(SilcClient client, SilcClientConnection conn,
		     SilcClientEntry sender, SilcMessageFlags flags,
			  char *msg)
{
  SILC_SERVER_REC *server;
  
  server = conn == NULL ? NULL : conn->context;
  signal_emit("message private", 4, server, msg,
	      sender->nickname ? sender->nickname : "(unknown)",
	      sender->username ? sender->username : NULL);
}

/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it). */

typedef struct {
  int type;
  const char *name;
} NOTIFY_REC;

#define MAX_NOTIFY (sizeof(notifies)/sizeof(notifies[0]))
static NOTIFY_REC notifies[] = {
  { SILC_NOTIFY_TYPE_NONE,		NULL },
  { SILC_NOTIFY_TYPE_INVITE,		"invite" },
  { SILC_NOTIFY_TYPE_JOIN,		"join" },
  { SILC_NOTIFY_TYPE_LEAVE,		"leave" },
  { SILC_NOTIFY_TYPE_SIGNOFF,		"signoff" },
  { SILC_NOTIFY_TYPE_TOPIC_SET,		"topic" },
  { SILC_NOTIFY_TYPE_NICK_CHANGE,		"nick" },
  { SILC_NOTIFY_TYPE_CMODE_CHANGE,	"cmode" },
  { SILC_NOTIFY_TYPE_CUMODE_CHANGE,	"cumode" },
  { SILC_NOTIFY_TYPE_MOTD,		"motd" }
};

static void silc_notify(SilcClient client, SilcClientConnection conn,
			SilcNotifyType type, ...)
{
  SILC_SERVER_REC *server;
  va_list va;
  
  server = conn == NULL ? NULL : conn->context;
  va_start(va, type);
  
  if (type == SILC_NOTIFY_TYPE_NONE) {
    /* some generic notice from server */
    printtext(server, NULL, MSGLEVEL_CRAP, "%s",
	      (char *) va_arg(va, char *));
  } else if (type < MAX_NOTIFY) {
    /* send signal about the notify event */
    char signal[50];
    
    g_snprintf(signal, sizeof(signal), "silc event %s",
	       notifies[type].name);
    signal_emit(signal, 2, server, va);
  } else {
    /* unknown notify */
    printtext(server, NULL, MSGLEVEL_CRAP,
	      "Unknown notify %d", type);
  }
  va_end(va);
}

/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection objecet which it should save somewhere. */

static void 
silc_connect(SilcClient client, SilcClientConnection conn, int success)
{
  SILC_SERVER_REC *server = conn->context;
  
  if (success) {
    server->connected = TRUE;
    signal_emit("event connected", 1, server);
  } else {
    server->connection_lost = TRUE;
    server->conn->context = NULL;
    server_disconnect(SERVER(server));
  }
}

/* Called to indicate that connection was disconnected to the server. */

static void 
silc_disconnect(SilcClient client, SilcClientConnection conn)
{
	SILC_SERVER_REC *server = conn->context;

	server->conn->context = NULL;
	server->conn = NULL;
	server->connection_lost = TRUE;
	server_disconnect(SERVER(server));
}

/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occured
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

static void 
silc_command(SilcClient client, SilcClientConnection conn, 
	     SilcClientCommandContext cmd_context, int success,
	     SilcCommand command)
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
   thus the payload can be ignored. `success' is FALSE if error occured.
   In this case arguments are not sent to the application. `command' is the
   command reply being processed. The function has variable argument list
   and each command defines the number and type of arguments it passes to the
   application (on error they are not sent). */

static void 
silc_command_reply(SilcClient client, SilcClientConnection conn,
		   SilcCommandPayload cmd_payload, int success,
		   SilcCommand command, SilcCommandStatus status, ...)

{
  SILC_SERVER_REC *server = conn->context;
  SILC_CHANNEL_REC *chanrec;
  va_list va;

  va_start(va, status);

  /*g_snprintf(signal, sizeof(signal), "silc command reply %s",
    silc_commands[type]);
    signal_emit(signal, 2, server, va);*/

  switch(command) {
  case SILC_COMMAND_JOIN: 
    {
      char *channel, *mode;
      uint32 modei;
      SilcChannelEntry channel_entry;
      
      channel = va_arg(va, char *);
      channel_entry = va_arg(va, SilcChannelEntry);
      modei = va_arg(va, uint32);
      mode = silc_client_chmode(modei, channel_entry);
      
      chanrec = silc_channel_find(server, channel);
      if (chanrec != NULL && !success)
	channel_destroy(CHANNEL(chanrec));
      else if (chanrec == NULL && success)
	chanrec = silc_channel_create(server, channel, TRUE);
      
      g_free_not_null(chanrec->mode);
      chanrec->mode = g_strdup(mode == NULL ? "" : mode);
      signal_emit("channel mode changed", 1, chanrec);
      break;
    }
  case SILC_COMMAND_NICK: 
    {
      SilcClientEntry client = va_arg(va, SilcClientEntry);
      char *old;
      
      old = g_strdup(server->nick);
      server_change_nick(SERVER(server), client->nickname);
      nicklist_rename_unique(SERVER(server),
			     server->conn->local_entry, server->nick,
			     client, client->nickname);
      
      signal_emit("message own_nick", 4,
		  server, server->nick, old, "");
      g_free(old);
      break;
    }
  case SILC_COMMAND_USERS: 
    {
      SilcChannelEntry channel;
      SilcChannelUser user;
      NICK_REC *ownnick;
      
      channel = va_arg(va, SilcChannelEntry);
      chanrec = silc_channel_find_entry(server, channel);
      if (chanrec == NULL)
	break;
      
      silc_list_start(channel->clients);
      while ((user = silc_list_get(channel->clients)) != NULL)
	silc_nicklist_insert(chanrec, user, FALSE);
      
      ownnick = NICK(silc_nicklist_find(chanrec, conn->local_entry));
      nicklist_set_own(CHANNEL(chanrec), ownnick);
      signal_emit("channel joined", 1, chanrec);
      fe_channels_nicklist(CHANNEL(chanrec),
			   CHANNEL_NICKLIST_FLAG_ALL);
      break;
    }
  }
  
  va_end(va);
}

/* Verifies received public key. If user decides to trust the key it is
   saved as public server key for later use. If user does not trust the
   key this returns FALSE. */

static int silc_verify_public_key(SilcClient client,
				  SilcClientConnection conn, 
				  SilcSocketType conn_type,
				  unsigned char *pk, uint32 pk_len,
				  SilcSKEPKType pk_type)
{
  return TRUE;
}

/* Asks passphrase from user on the input line. */

static unsigned char *silc_ask_passphrase(SilcClient client,
					  SilcClientConnection conn)
{
	return NULL;
}

/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. The found authentication
   method and authentication data is returned to `auth_meth', `auth_data'
   and `auth_data_len'. The function returns TRUE if authentication method
   is found and FALSE if not. `conn' may be NULL. */

static int 
silc_get_auth_method(SilcClient client, SilcClientConnection conn,
		     char *hostname, uint16 port,
		     SilcProtocolAuthMeth *auth_meth,
		     unsigned char **auth_data,
		     uint32 *auth_data_len)
{
  return FALSE;
}

/* Notifies application that failure packet was received.  This is called
   if there is some protocol active in the client.  The `protocol' is the
   protocol context.  The `failure' is opaque pointer to the failure
   indication.  Note, that the `failure' is protocol dependant and application
   must explicitly cast it to correct type.  Usually `failure' is 32 bit
   failure type (see protocol specs for all protocol failure types). */

static void 
silc_failure(SilcClient client, SilcClientConnection conn, 
	     SilcProtocol protocol, void *failure)
{
  if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_KEY_EXCHANGE) {
    SilcSKEStatus status = (SilcSKEStatus)failure;
    
    if (status == SILC_SKE_STATUS_BAD_VERSION)
      silc_say(client, conn, 
	       "You are running incompatible client version (it may be "
	       "too old or too new)");
    if (status == SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY)
      silc_say(client, conn, "Server does not support your public key type");
    if (status == SILC_SKE_STATUS_UNKNOWN_GROUP)
      silc_say(client, conn, 
	       "Server does not support one of your proposed KE group");
    if (status == SILC_SKE_STATUS_UNKNOWN_CIPHER)
      silc_say(client, conn, 
	       "Server does not support one of your proposed cipher");
    if (status == SILC_SKE_STATUS_UNKNOWN_PKCS)
      silc_say(client, conn, 
	       "Server does not support one of your proposed PKCS");
    if (status == SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION)
      silc_say(client, conn, 
	       "Server does not support one of your proposed hash function");
    if (status == SILC_SKE_STATUS_UNKNOWN_HMAC)
      silc_say(client, conn, 
	       "Server does not support one of your proposed HMAC");
    if (status == SILC_SKE_STATUS_INCORRECT_SIGNATURE)
      silc_say(client, conn, "Incorrect signature");
  }

  if (protocol->protocol->type == SILC_PROTOCOL_CLIENT_CONNECTION_AUTH) {
    uint32 err = (uint32)failure;

    if (err == SILC_AUTH_FAILED)
      silc_say(client, conn, "Authentication failed");
  }
}

/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). */

static int 
silc_key_agreement(SilcClient client, SilcClientConnection conn,
		   SilcClientEntry client_entry, char *hostname,
		   int port,
		   SilcKeyAgreementCallback *completion,
		   void **context)
{
  char host[256];

  /* We will just display the info on the screen and return FALSE and user
     will have to start the key agreement with a command. */

  if (hostname) {
    memset(host, 0, sizeof(host));
    snprintf(host, sizeof(host) - 1, "(%s on port %d)", hostname, port); 
  }

  silc_say(client, conn, "%s wants to perform key agreement %s",
	   client_entry->nickname, hostname ? host : "");

  *completion = NULL;
  *context = NULL;

  return FALSE;
}

/* SILC client operations */
SilcClientOperations ops = {
  silc_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_connect,
  silc_disconnect,
  silc_get_auth_method,
  silc_verify_public_key,
  silc_ask_passphrase,
  silc_failure,
  silc_key_agreement,
};

static int my_silc_scheduler(void)
{
  silc_schedule_one(0);
  return 1;
}

static CHATNET_REC *create_chatnet(void)
{
  return g_malloc0(sizeof(CHATNET_REC));
}

static SERVER_SETUP_REC *create_server_setup(void)
{
  return g_malloc0(sizeof(SERVER_SETUP_REC));
}

static CHANNEL_SETUP_REC *create_channel_setup(void)
{
  return g_malloc0(sizeof(CHANNEL_SETUP_REC));
}

static SERVER_CONNECT_REC *create_server_connect(void)
{
  return g_malloc0(sizeof(SILC_SERVER_CONNECT_REC));
}

/* Init SILC. Called from src/fe-text/silc.c */

void silc_core_init(void)
{
  static struct poptOption options[] = {
    { "create-key-pair", 'C', POPT_ARG_NONE, &opt_create_keypair, 0, 
      "Create new public key pair", NULL },
    { "pkcs", 0, POPT_ARG_STRING, &opt_pkcs, 0, 
      "Set the PKCS of the public key pair", "PKCS" },
    { "bits", 0, POPT_ARG_INT, &opt_bits, 0, 
      "Set the length of the public key pair", "VALUE" },
    { "show-key", 'S', POPT_ARG_STRING, &opt_keyfile, 0, 
      "Show the contents of the public key", "FILE" },
    { NULL, '\0', 0, NULL }
  };

  args_register(options);
}

/* Finalize init. Called from src/fe-text/silc.c */

void silc_core_init_finish(void)
{
  CHAT_PROTOCOL_REC *rec;

  if (opt_create_keypair == TRUE) {
    /* Create new key pair and exit */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_create_key_pair(opt_pkcs, opt_bits, 
				NULL, NULL, NULL, NULL, NULL);
    silc_free(opt_pkcs);
    exit(0);
  }

  if (opt_keyfile) {
    /* Dump the key */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_show_key(opt_keyfile);
    silc_free(opt_keyfile);
    exit(0);
  }

  /* Allocate SILC client */
  silc_client = silc_client_alloc(&ops, NULL);

  /* Load local config file */
  silc_config = silc_client_config_alloc(SILC_CLIENT_HOME_CONFIG_FILE);

  /* Get user information */
  silc_client->username = g_strdup(settings_get_str("user_name"));
  silc_client->hostname = silc_net_localhost();
  silc_client->realname = g_strdup(settings_get_str("real_name"));

  /* Register all configured ciphers, PKCS and hash functions. */
  if (silc_config) {
    silc_config->client = silc_client;
    if (!silc_client_config_register_ciphers(silc_config))
      silc_cipher_register_default();
    if (!silc_client_config_register_pkcs(silc_config))
      silc_pkcs_register_default();
    if (!silc_client_config_register_hashfuncs(silc_config))
      silc_hash_register_default();
    if (!silc_client_config_register_hmacs(silc_config))
      silc_hmac_register_default();
  } else {
    /* Register default ciphers, pkcs, hash funtions and hmacs. */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
  }

  /* Check ~/.silc directory and public and private keys */
  if (silc_client_check_silc_dir() == FALSE) {
    idletag = -1;
    return;
  }

  /* Load public and private key */
  if (silc_client_load_keys(silc_client) == FALSE) {
    idletag = -1;
    return;
  }

  /* Initialize the SILC client */
  if (!silc_client_init(silc_client)) {
    idletag = -1;
    return;
  }

  /* Register SILC to the irssi */
  rec = g_new0(CHAT_PROTOCOL_REC, 1);
  rec->name = "SILC";
  rec->fullname = "Secure Internet Live Conferencing";
  rec->chatnet = "silcnet";
  rec->create_chatnet = create_chatnet;
  rec->create_server_setup = create_server_setup;
  rec->create_channel_setup = create_channel_setup;
  rec->create_server_connect = create_server_connect;
  rec->server_connect = (SERVER_REC *(*) (SERVER_CONNECT_REC *))
    silc_server_connect; 
  rec->channel_create = (CHANNEL_REC *(*) (SERVER_REC *, const char *, int))
    silc_channel_create;
  rec->query_create = (QUERY_REC *(*) (const char *, const char *, int))
    silc_query_create;
  
  chat_protocol_register(rec);
  g_free(rec);

  silc_server_init();
  silc_channels_init();
  silc_queries_init();

  idletag = g_timeout_add(100, (GSourceFunc) my_silc_scheduler, NULL);
}

/* Deinit SILC. Called from src/fe-text/silc.c */

void silc_core_deinit(void)
{
  if (idletag != -1) {
    signal_emit("chat protocol deinit", 1,
		chat_protocol_find("SILC"));
    
    silc_server_deinit();
    silc_channels_deinit();
    silc_queries_deinit();
    
    chat_protocol_unregister("SILC");
    
    g_source_remove(idletag);
  }
  
  g_free(silc_client->username);
  g_free(silc_client->realname);
  silc_client_free(silc_client);
}
