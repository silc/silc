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
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

/* Command line option variables */
static bool opt_create_keypair = FALSE;
static bool opt_list_ciphers = FALSE;
static bool opt_list_hash = FALSE;
static bool opt_list_hmac = FALSE;
static bool opt_list_pkcs = FALSE;
static bool opt_version = FALSE;
static char *opt_debug = FALSE;
static char *opt_pkcs = NULL;
static char *opt_keyfile = NULL;
static int opt_bits = 0;

static int idletag;

SilcClient silc_client = NULL;
SilcClientConfig silc_config = NULL;
extern SilcClientOperations ops;
extern bool silc_debug;
extern bool silc_debug_hexdump;
#ifdef SILC_SIM
/* SIM (SILC Module) table */
SilcSimContext **sims = NULL;
uint32 sims_count = 0;
#endif

static int my_silc_scheduler(void)
{
  silc_schedule_one(silc_client->schedule, 0);
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

/* Checks user information and saves them to the config file it they
   do not exist there already. */

static void silc_init_userinfo(void)
{
  const char *set, *nick, *user_name;
  char *str;   
        
  /* check if nick/username/realname wasn't read from setup.. */
  set = settings_get_str("real_name");
  if (set == NULL || *set == '\0') {
    str = g_getenv("SILCNAME");
    if (!str)
      str = g_getenv("IRCNAME");
    settings_set_str("real_name",
		     str != NULL ? str : g_get_real_name());
  }
 
  /* username */
  user_name = settings_get_str("user_name");
  if (user_name == NULL || *user_name == '\0') {
    str = g_getenv("SILCUSER");
    if (!str)
      str = g_getenv("IRCUSER");
    settings_set_str("user_name",
		     str != NULL ? str : g_get_user_name());
    
    user_name = settings_get_str("user_name");
  }
         
  /* nick */
  nick = settings_get_str("nick");
  if (nick == NULL || *nick == '\0') {
    str = g_getenv("SILCNICK");
    if (!str)
      str = g_getenv("IRCNICK");
    settings_set_str("nick", str != NULL ? str : user_name);
    
    nick = settings_get_str("nick");
  }
                
  /* alternate nick */
  set = settings_get_str("alternate_nick");
  if (set == NULL || *set == '\0') {
    if (strlen(nick) < 9)
      str = g_strconcat(nick, "_", NULL);
    else { 
      str = g_strdup(nick);
      str[strlen(str)-1] = '_';
    }
    settings_set_str("alternate_nick", str);
    g_free(str);
  }

  /* host name */
  set = settings_get_str("hostname");
  if (set == NULL || *set == '\0') {
    str = g_getenv("SILCHOST");
    if (!str)
      str = g_getenv("IRCHOST");
    if (str != NULL)
      settings_set_str("hostname", str);
  }
}

/* Log callbacks */

static void silc_log_info(char *message)
{
  fprintf(stderr, "%s\n", message);
}

static void silc_log_warning(char *message)
{
  fprintf(stderr, "%s\n", message);
}

static void silc_log_error(char *message)
{
  fprintf(stderr, "%s\n", message);
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
    { "list-ciphers", 'C', POPT_ARG_NONE, &opt_list_ciphers, 0,
      "List supported ciphers", NULL },
    { "list-hash-funcs", 'H', POPT_ARG_NONE, &opt_list_hash, 0,
      "List supported hash functions", NULL },
    { "list-hmacs", 'H', POPT_ARG_NONE, &opt_list_hmac, 0,
      "List supported HMACs", NULL },
    { "list-pkcs", 'P', POPT_ARG_NONE, &opt_list_pkcs, 0,
      "List supported PKCSs", NULL },
    { "debug", 'd', POPT_ARG_STRING, &opt_debug, 0,
      "Enable debugging", NULL },
    { "version", 'V', POPT_ARG_NONE, &opt_version, 0,
      "Show version", NULL },
    { NULL, '\0', 0, NULL }
  };

  args_register(options);
}

static void silc_nickname_format_parse(const char *nickname,
				       char **ret_nickname)
{
  silc_parse_userfqdn(nickname, ret_nickname, NULL);
}

/* Finalize init. Called from src/fe-text/silc.c */

void silc_core_init_finish(void)
{
  CHAT_PROTOCOL_REC *rec;
  SilcClientParams params;

  if (opt_create_keypair == TRUE) {
    /* Create new key pair and exit */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_create_key_pair(opt_pkcs, opt_bits, 
				NULL, NULL, NULL, NULL, NULL);
    exit(0);
  }

  if (opt_keyfile) {
    /* Dump the key */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_show_key(opt_keyfile);
    exit(0);
  }

  if (opt_list_ciphers) {
    silc_cipher_register_default();
    silc_client_list_ciphers();
    exit(0);
  }

  if (opt_list_hash) {
    silc_hash_register_default();
    silc_client_list_hash_funcs();
    exit(0);
  }

  if (opt_list_hmac) {
    silc_hmac_register_default();
    silc_client_list_hmacs();
    exit(0);
  }

  if (opt_list_pkcs) {
    silc_pkcs_register_default();
    silc_client_list_pkcs();
    exit(0);
  }

  if (opt_version) {
    printf("SILC Secure Internet Live Conferencing, version %s "
	   "(base: SILC Toolkit %s)\n", silc_dist_version, silc_version);
    printf("(c) 1997 - 2001 Pekka Riikonen <priikone@silcnet.org>\n");
    exit(0); 
  }

  if (opt_debug) {
    silc_debug = TRUE;
    silc_debug_hexdump = TRUE;
    silc_log_set_debug_string(opt_debug);
    silc_log_set_callbacks(silc_log_info, silc_log_warning,
			   silc_log_error, NULL);
  }

  /* Do some irssi initializing */
  settings_add_bool("server", "skip_motd", FALSE);
  settings_add_str("server", "alternate_nick", NULL);
  
  /* Initialize the auto_addr variables Is "server" the best choice for
   * this?  No existing category seems to apply.
   */
  
  settings_add_bool("server", "use_auto_addr", FALSE);
  settings_add_str("server", "auto_bind_ip", "");
  settings_add_str("server", "auto_public_ip", "");
  settings_add_int("server", "auto_bind_port", 0);
        	    	    	
  silc_init_userinfo();

  /* Initialize client parameters */
  memset(&params, 0, sizeof(params));
  strcat(params.nickname_format, "%n@%h%a");
  params.nickname_parse = silc_nickname_format_parse;

  /* Allocate SILC client */
  silc_client = silc_client_alloc(&ops, &params, NULL, silc_version_string);

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

  idletag = g_timeout_add(5, (GSourceFunc) my_silc_scheduler, NULL);
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
