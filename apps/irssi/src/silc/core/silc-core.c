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
#include "silcversion.h"

#include "signals.h"
#include "levels.h"
#include "settings.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

/* Command line option variables */
static bool opt_create_keypair = FALSE;
static char *opt_pkcs = NULL;
static int opt_bits = 0;

static int idletag;

SilcClient silc_client = NULL;
extern SilcClientOperations ops;
extern bool silc_debug;
extern bool silc_debug_hexdump;

void silc_expandos_init(void);
void silc_expandos_deinit(void);

static int my_silc_scheduler(void)
{
  silc_client_run_one(silc_client);
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

static void destroy_server_connect(SERVER_CONNECT_REC *conn)
{

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

static bool silc_log_misc(SilcLogType type, char *message, void *context)
{
  fprintf(stderr, "%s\n", message);
  return TRUE;
}

static void silc_nickname_format_parse(const char *nickname,
				       char **ret_nickname)
{
  silc_parse_userfqdn(nickname, ret_nickname, NULL);
}

static void silc_register_cipher(SilcClient client, const char *cipher)
{
  int i;

  if (cipher) {
    for (i = 0; silc_default_ciphers[i].name; i++)
      if (!strcmp(silc_default_ciphers[i].name, cipher)) {
	silc_cipher_register((SilcCipherObject *)&silc_default_ciphers[i]);
	break;
      }
    
    if (!silc_cipher_is_supported(cipher)) {
      SILC_LOG_ERROR(("Unknown cipher `%s'", cipher));
      exit(1);
    }
  }

  /* Register other defaults */
  silc_cipher_register_default();
}

static void silc_register_hash(SilcClient client, const char *hash)
{
  int i;

  if (hash) {
    for (i = 0; silc_default_hash[i].name; i++)
      if (!strcmp(silc_default_hash[i].name, hash)) {
	silc_hash_register((SilcHashObject *)&silc_default_hash[i]);
	break;
      }
    
    if (!silc_hash_is_supported(hash)) {
      SILC_LOG_ERROR(("Unknown hash function `%s'", hash));
      exit(1);
    }
  }

  /* Register other defaults */
  silc_hash_register_default();
}

static void silc_register_hmac(SilcClient client, const char *hmac)
{
  int i;

  if (hmac) {
    for (i = 0; silc_default_hmacs[i].name; i++)
      if (!strcmp(silc_default_hmacs[i].name, hmac)) {
	silc_hmac_register((SilcHmacObject *)&silc_default_hmacs[i]);
	break;
      }
    
    if (!silc_hmac_is_supported(hmac)) {
      SILC_LOG_ERROR(("Unknown HMAC `%s'", hmac));
      exit(1);
    }
  }

  /* Register other defaults */
  silc_hmac_register_default();
}

/* Finalize init. Init finish signal calls this. */

void silc_opt_callback(poptContext con, 
		       enum poptCallbackReason reason,
		       const struct poptOption *opt,
		       const char *arg, void *data)
{
  if (strcmp(opt->longName, "show-key") == 0) {
    /* Dump the key */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_show_key((char *)arg);
    exit(0);
  }

  if (strcmp(opt->longName, "list-ciphers") == 0) {
    silc_cipher_register_default();
    silc_client_list_ciphers();
    exit(0);
  }

  if (strcmp(opt->longName, "list-hash-funcs") == 0) {
    silc_hash_register_default();
    silc_client_list_hash_funcs();
    exit(0);
  }

  if (strcmp(opt->longName, "list-hmacs") == 0) {
    silc_hmac_register_default();
    silc_client_list_hmacs();
    exit(0);
  }

  if (strcmp(opt->longName, "list-pkcs") == 0) {
    silc_pkcs_register_default();
    silc_client_list_pkcs();
    exit(0);
  }

  if (strcmp(opt->longName, "debug") == 0) {
    silc_debug = TRUE;
    silc_debug_hexdump = TRUE;
    silc_log_set_debug_string(arg);
    silc_log_set_callback(SILC_LOG_INFO, silc_log_misc, NULL);
    silc_log_set_callback(SILC_LOG_WARNING, silc_log_misc, NULL);
    silc_log_set_callback(SILC_LOG_ERROR, silc_log_misc, NULL);
    silc_log_set_callback(SILC_LOG_FATAL, silc_log_misc, NULL);
#ifndef SILC_DEBUG
    fprintf(stdout, 
	    "Run-time debugging is not enabled. To enable it recompile\n"
	    "the client with --enable-debug configuration option.\n");
    sleep(1);
#endif
  }
}

static void sig_init_read_settings(void)
{
  if (opt_create_keypair) {
    /* Create new key pair and exit */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_create_key_pair(opt_pkcs, opt_bits, 
				NULL, NULL, NULL, NULL, NULL);
    exit(0);
  }
}

/* Init SILC. Called from src/fe-text/silc.c */

void silc_core_init(void)
{
  static struct poptOption silc_options[] = {
    { NULL, '\0', POPT_ARG_CALLBACK, (void *)&silc_opt_callback, '\0', NULL },
    { "show-key", 'S', POPT_ARG_STRING, NULL, 0,
      "Show the contents of the public key", "FILE" },
    { "list-ciphers", 'c', POPT_ARG_NONE, NULL, 0,
      "List supported ciphers", NULL },
    { "list-hash-funcs", 'H', POPT_ARG_NONE, NULL, 0,
      "List supported hash functions", NULL },
    { "list-hmacs", 'M', POPT_ARG_NONE, NULL, 0,
      "List supported HMACs", NULL },
    { "list-pkcs", 'P', POPT_ARG_NONE, NULL, 0,
      "List supported PKCSs", NULL },
    { "debug", 'd', POPT_ARG_STRING, NULL, 0,
      "Enable debugging", "STRING" },
    { NULL, '\0', 0, NULL }
  };

  static struct poptOption options[] = {
    { NULL, '\0', POPT_ARG_INCLUDE_TABLE, silc_options, 0, NULL, NULL },
    { "create-key-pair", 'C', POPT_ARG_NONE, &opt_create_keypair, 0,
      "Create new public key pair", NULL },
    { "pkcs", 0, POPT_ARG_STRING, &opt_pkcs, 0,
      "Set the PKCS of the public key pair", "PKCS" },
    { "bits", 0, POPT_ARG_INT, &opt_bits, 0,
      "Set the length of the public key pair", "VALUE" },
    { NULL, '\0', 0, NULL }
  };

  CHAT_PROTOCOL_REC *rec;
  SilcClientParams params;
  const char *def_cipher, *def_hash, *def_hmac;

  args_register(options);
  signal_add("irssi init read settings", (SIGNAL_FUNC) sig_init_read_settings);

  /* Settings */
  settings_add_bool("server", "skip_motd", FALSE);
  settings_add_str("server", "alternate_nick", NULL);
  settings_add_bool("server", "use_auto_addr", FALSE);
  settings_add_str("server", "auto_bind_ip", "");
  settings_add_str("server", "auto_public_ip", "");
  settings_add_int("server", "auto_bind_port", 0);
  settings_add_str("server", "crypto_default_cipher", SILC_DEFAULT_CIPHER);
  settings_add_str("server", "crypto_default_hash", SILC_DEFAULT_HASH);
  settings_add_str("server", "crypto_default_hmac", SILC_DEFAULT_HMAC);
  settings_add_int("server", "key_exchange_timeout_secs", 120);
  settings_add_int("server", "key_exchange_rekey_secs", 3600);
  settings_add_int("server", "connauth_request_secs", 2);

  silc_init_userinfo();

  /* Initialize client parameters */
  memset(&params, 0, sizeof(params));
  strcat(params.nickname_format, "%n@%h%a");
  params.nickname_parse = silc_nickname_format_parse;
  params.rekey_secs = settings_get_int("key_exchange_rekey_secs");
  params.connauth_request_secs = settings_get_int("connauth_request_secs");

  /* Allocate SILC client */
  silc_client = silc_client_alloc(&ops, &params, NULL, silc_version_string);

  /* Get the ciphers and stuff from config file */
  def_cipher = settings_get_str("crypto_default_cipher");
  def_hash = settings_get_str("crypto_default_hash");
  def_hmac = settings_get_str("crypto_default_hmac");
  silc_register_cipher(silc_client, def_cipher);
  silc_register_hash(silc_client, def_hash);
  silc_register_hmac(silc_client, def_hmac);
  silc_pkcs_register_default();

  /* Get user information */
  silc_client->username = g_strdup(settings_get_str("user_name"));
  silc_client->nickname = g_strdup(settings_get_str("nick"));
  silc_client->hostname = silc_net_localhost();
  silc_client->realname = g_strdup(settings_get_str("real_name"));

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
  rec->destroy_server_connect = destroy_server_connect;
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
  silc_expandos_init();

  idletag = g_timeout_add(5, (GSourceFunc) my_silc_scheduler, NULL);

  module_register("silc", "core");
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
    silc_expandos_deinit();
    
    chat_protocol_unregister("SILC");
    
    g_source_remove(idletag);
  }
  
  g_free(silc_client->username);
  g_free(silc_client->realname);
  silc_client_free(silc_client);
}
