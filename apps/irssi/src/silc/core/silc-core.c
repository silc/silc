/*

  silc-core.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

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
#include "silc-chatnets.h"
#include "silc-cmdqueue.h"
#include "silc-commands.h"

#include "signals.h"
#include "levels.h"
#include "settings.h"
#include "commands.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

#ifndef SILC_PLUGIN
/* Command line option variables */
static char *opt_pkcs = NULL;
static int opt_bits = 0;
#else
static int init_failed = 0;
#endif

static int idletag = -1;
static int running = 0;

/* SILC Client */
SilcClient silc_client = NULL;
extern SilcClientOperations ops;

/* Our keypair */
SilcPublicKey irssi_pubkey = NULL;
SilcPrivateKey irssi_privkey = NULL;

char *opt_nickname = NULL;
char *opt_hostname = NULL;

/* Default hash function */
SilcHash sha1hash = NULL;

void silc_expandos_init(void);
void silc_expandos_deinit(void);

void silc_lag_init(void);
void silc_lag_deinit(void);

#ifdef SILC_PLUGIN
void silc_core_deinit(void);
#endif

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
  const char *set, *nick, *user_name, *str;
  char *tmp;

  /* check if nick/username/realname wasn't read from setup.. */
  set = settings_get_str("real_name");
  if (set == NULL || *set == '\0') {
    str = g_getenv("SILCNAME");
    if (!str)
      str = g_getenv("IRCNAME");
    settings_set_str("real_name",
		     str != NULL ? str : silc_get_real_name());
  }

  /* Check that real name is UTF-8 encoded */
  set = settings_get_str("real_name");
  if (!silc_utf8_valid(set, strlen(set))) {
    int len = silc_utf8_encoded_len(set, strlen(set), SILC_STRING_LOCALE);
    tmp = silc_calloc(len, sizeof(*tmp));
    if (tmp) {
      silc_utf8_encode(set, strlen(set), SILC_STRING_LOCALE, tmp, len);
      settings_set_str("real_name", tmp);
      silc_free(tmp);
    }
  }

  /* username */
  user_name = settings_get_str("user_name");
  if (user_name == NULL || *user_name == '\0') {
    str = g_getenv("SILCUSER");
    if (!str)
      str = g_getenv("IRCUSER");
    settings_set_str("user_name",
		     str != NULL ? str : silc_get_username());

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
    tmp = g_strconcat(nick, "_", NULL);
    settings_set_str("alternate_nick", tmp);
    g_free(tmp);
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

#if defined(SILC_DEBUG) || defined(SILC_PLUGIN)
static bool i_debug;
#endif

#ifdef SILC_DEBUG
static bool silc_irssi_debug_print(char *file, char *function, int line,
				   char *message, void *context)
{
  printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
	    "DEBUG: %s:%d: %s", function, line, message);
  return TRUE;
}
#endif

static void sig_setup_changed(void)
{
#ifdef SILC_DEBUG
  bool debug = settings_get_bool("debug");
  if (debug) {
    const char *debug_string = settings_get_str("debug_string");
    i_debug = TRUE;
    silc_log_debug(TRUE);
    if (strlen(debug_string))
      silc_log_set_debug_string(debug_string);
    silc_log_set_debug_callbacks(silc_irssi_debug_print, NULL, NULL, NULL);
    return;
  }
  if (i_debug)
    silc_log_debug(FALSE);
#endif
}

/* Log callbacks */

static bool silc_log_misc(SilcLogType type, char *message, void *context)
{
  printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP, "%s: %s",
	    (type == SILC_LOG_INFO ? "[Info]" :
	     type == SILC_LOG_WARNING ? "[Warning]" : "[Error]"), message);
  return TRUE;
}

static bool silc_log_stderr(SilcLogType type, char *message, void *context)
{
  fprintf(stderr, "%s: %s\n",
	  (type == SILC_LOG_INFO ? "[Info]" :
	   type == SILC_LOG_WARNING ? "[Warning]" : "[Error]"), message);
  return TRUE;
}

static void silc_register_cipher(SilcClient client, const char *cipher)
{
  int i;

  if (cipher) {
    for (i = 0; silc_default_ciphers[i].name; i++)
      if (!strcmp(silc_default_ciphers[i].name, cipher)) {
	silc_cipher_register(&(silc_default_ciphers[i]));
	break;
      }

    if (!silc_cipher_is_supported(cipher)) {
      SILC_LOG_ERROR(("Unknown cipher `%s'", cipher));
#ifdef SILC_PLUGIN
      init_failed = -1;
      return;
#else
      exit(1);
#endif
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
	silc_hash_register(&(silc_default_hash[i]));
	break;
      }

    if (!silc_hash_is_supported(hash)) {
      SILC_LOG_ERROR(("Unknown hash function `%s'", hash));
#ifdef SILC_PLUGIN
      init_failed = -1;
      return;
#else
      exit(1);
#endif
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
	silc_hmac_register(&(silc_default_hmacs[i]));
	break;
      }

    if (!silc_hmac_is_supported(hmac)) {
      SILC_LOG_ERROR(("Unknown HMAC `%s'", hmac));
#ifdef SILC_PLUGIN
      init_failed = -1;
      return;
#else
      exit(1);
#endif
    }
  }

  /* Register other defaults */
  silc_hmac_register_default();
}

/* Finalize init. Init finish signal calls this. */

#ifdef SILC_PLUGIN
#define FUNCTION_EXIT goto out
void silc_opt_callback(const char *data, SERVER_REC *server,
			WI_ITEM_REC *item)
#else
#define FUNCTION_EXIT exit(0)
void silc_opt_callback(poptContext con,
		       enum poptCallbackReason reason,
		       const struct poptOption *opt,
		       const char *arg, void *data)
#endif
{
#ifdef SILC_PLUGIN
  unsigned char **argv=NULL, *tmp;
  SilcUInt32 *argv_lens=NULL, *argv_types=NULL, argc=0;
  int i;
  unsigned char privkey[128], pubkey[128];

  memset(privkey, 0, sizeof(privkey));
  memset(pubkey, 0, sizeof(pubkey));
  snprintf(pubkey, sizeof(pubkey) - 1, "%s/%s", get_irssi_dir(),
	   SILC_CLIENT_PUBLIC_KEY_NAME);
  snprintf(privkey, sizeof(privkey) - 1, "%s/%s", get_irssi_dir(),
	   SILC_CLIENT_PRIVATE_KEY_NAME);

  tmp = g_strconcat("SILC", " ", data, NULL);
  silc_parse_command_line(tmp, &argv, &argv_lens, &argv_types, &argc, 6);
  g_free(tmp);

  if (argc < 2)
    goto err;
#else
  if (strcmp(opt->longName, "nick") == 0) {
    g_free(opt_nickname);
    opt_nickname = g_strdup(arg);
  }

  if (strcmp(opt->longName, "hostname") == 0) {
    silc_free(opt_hostname);
    opt_hostname = strdup(arg);
  }
#endif

#ifdef SILC_PLUGIN
  if ((argc == 2) && (strcasecmp(argv[1], "list-ciphers") == 0)) {
#else
  if (strcmp(opt->longName, "list-ciphers") == 0) {
    silc_cipher_register_default();
#endif
    silc_client_list_ciphers();
    FUNCTION_EXIT;
  }

#ifdef SILC_PLUGIN
  if ((argc == 2) && (strcasecmp(argv[1], "list-hash-funcs") == 0)) {
#else
  if (strcmp(opt->longName, "list-hash-funcs") == 0) {
    silc_hash_register_default();
#endif
    silc_client_list_hash_funcs();
    FUNCTION_EXIT;
  }

#ifdef SILC_PLUGIN
  if ((argc == 2) && (strcasecmp(argv[1], "list-hmacs") == 0)) {
#else
  if (strcmp(opt->longName, "list-hmacs") == 0) {
    silc_hmac_register_default();
#endif
    silc_client_list_hmacs();
    FUNCTION_EXIT;
  }

#ifdef SILC_PLUGIN
  if ((argc == 2) && (strcasecmp(argv[1], "list-pkcs") == 0)) {
#else
  if (strcmp(opt->longName, "list-pkcs") == 0) {
    silc_pkcs_register_default();
#endif
    silc_client_list_pkcs();
    FUNCTION_EXIT;
  }

#ifdef SILC_PLUGIN
  if ((argc < 5) && (strcasecmp(argv[1], "debug") == 0)) {
#else
  if (strcmp(opt->longName, "debug") == 0) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string(arg);
#endif
#ifdef SILC_PLUGIN
    if (argc == 2) {
      printformat_module("fe-common/silc", NULL, NULL,
		         MSGLEVEL_CRAP, SILCTXT_CONFIG_DEBUG,
			 (i_debug == TRUE ? "enabled" : "disabled"));
      goto out;
    }
#endif
#ifndef SILC_DEBUG
#ifdef SILC_PLUGIN
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_NODEBUG);
#else
    fprintf(stdout,
	    "Run-time debugging is not enabled. To enable it recompile\n"
	    "the client with --enable-debug configuration option.\n");
    sleep(1);
#endif
#else
#ifdef SILC_PLUGIN
    if (strcasecmp(argv[2], "on") == 0) {
      settings_set_bool("debug", TRUE);
      if (argc == 4)
	 settings_set_str("debug_string", argv[3]);
    } else if ((argc == 3) && (strcasecmp(argv[2], "off") == 0)) {
      settings_set_bool("debug", FALSE);
    } else
      goto err;
    sig_setup_changed();
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_DEBUG,
		       (settings_get_bool("debug") == TRUE ?
			"enabled" : "disabled"));
    goto out;
#endif
#endif
  }

#ifdef SILC_PLUGIN
  if (strcasecmp(argv[1], "create-key-pair") == 0) {
#else
  if (strcmp(opt->longName, "create-key-pair") == 0) {
#endif
    /* Create new key pair and exit */
#ifdef SILC_PLUGIN
    char *endptr, *pkcs=NULL;
    long int val;
    int bits=0;
    CREATE_KEY_REC *rec;

    if ((argc == 3) || (argc == 5))
      goto err;

    for (i=2; i<argc-1; i+=2)
      if (strcasecmp(argv[i], "-pkcs") == 0) {
	if (pkcs == NULL)
	  pkcs = argv[i+1];
	else
	  goto err;
      } else if (strcasecmp(argv[i], "-bits") == 0) {
	if (bits == 0) {
	  val = strtol(argv[i+1], &endptr, 10);
	  if ((*endptr != '\0') || (val <= 0) || (val >= INT_MAX))
	    goto err;
          bits = val;
	} else
	  goto err;
      } else
	goto err;

    rec = g_new0(CREATE_KEY_REC, 1);
    rec->pkcs = (pkcs == NULL ? NULL : g_strdup(pkcs));
    rec->bits = bits;

    keyboard_entry_redirect((SIGNAL_FUNC) create_key_passphrase,
		    	    format_get_text("fe-common/silc", NULL, NULL,
				    	    NULL, SILCTXT_CONFIG_PASS_ASK2),
			    ENTRY_REDIRECT_FLAG_HIDDEN, rec);
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_NEXTTIME);
    goto out;
#else
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_create_key_pair(opt_pkcs, opt_bits, NULL, NULL,
			 NULL, NULL, NULL, NULL, TRUE);
    exit(0);
#endif
  }

#ifdef SILC_PLUGIN
  if ((argc < 4) && (strcasecmp(argv[1], "passphrase-change") == 0)) {
#else
  if (strcmp(opt->longName, "passphrase-change") == 0) {
#endif
    /* Change the passphrase of the private key file */
#ifdef SILC_PLUGIN
    CREATE_KEY_REC *rec;

    rec = g_new0(CREATE_KEY_REC, 1);
    rec->file = g_strdup((argc == 3 ? argv[2] : privkey));

    keyboard_entry_redirect((SIGNAL_FUNC) change_private_key_passphrase,
		    	    format_get_text("fe-common/silc", NULL, NULL,
				    	    NULL, SILCTXT_CONFIG_PASS_ASK1),
			    ENTRY_REDIRECT_FLAG_HIDDEN, rec);
    goto out;
#else
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_change_private_key_passphrase(arg, NULL, NULL);
    exit(0);
#endif
  }

#ifndef SILC_PLUGIN
  if (strcmp(opt->longName, "show-key") == 0) {
    /* Dump the key */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_show_public_key_file((char *)arg);
    exit(0);
  }
#endif

#ifdef SILC_PLUGIN
err:
  printformat_module("fe-common/silc", NULL, NULL,
		     MSGLEVEL_CRAP, SILCTXT_CONFIG_UNKNOWN,
		     data);

out:
  for (i=0; i<argc; i++)
    silc_free(argv[i]);

  silc_free(argv);
  silc_free(argv_lens);
  silc_free(argv_types);
#endif
}
#undef FUNCTION_EXIT

/* Called to indicate the client library has stopped. */
static void
silc_stopped(SilcClient client, void *context)
{
  SILC_LOG_DEBUG(("Client library has stopped"));
  *(int*)context = -1;
}

/* Called to indicate the client library is running. */

static void
silc_running(SilcClient client, void *context)
{
  running = 1;
  SILC_LOG_DEBUG(("Client library is running"));
}

static void sig_init_finished(void)
{
  /* Check ~/.silc directory and public and private keys */
  if (!silc_client_check_silc_dir()) {
#ifdef SILC_PLUGIN
    init_failed = -1;
#else
    sleep(1);
    exit(1);
#endif
    return;
  }

  /* Load public and private key */
  if (!silc_client_load_keys(silc_client)) {
#ifdef SILC_PLUGIN
    init_failed = -1;
#else
    sleep(1);
    exit(1);
#endif
    return;
  }

  /* Initialize the SILC client */
  opt_hostname = (opt_hostname ? opt_hostname : silc_net_localhost());
  if (!silc_client_init(silc_client, settings_get_str("user_name"),
			opt_hostname, settings_get_str("real_name"),
			silc_running, NULL)) {
#ifdef SILC_PLUGIN
    init_failed = -1;
#else
    sleep(1);
    exit(1);
#endif
    return;
  }

  silc_log_set_callback(SILC_LOG_INFO, silc_log_misc, NULL);
  silc_log_set_callback(SILC_LOG_WARNING, silc_log_misc, NULL);
  silc_log_set_callback(SILC_LOG_ERROR, silc_log_misc, NULL);
  silc_log_set_callback(SILC_LOG_FATAL, silc_log_misc, NULL);

  silc_hash_alloc("sha1", &sha1hash);

  /* register SILC scheduler */
  idletag = g_timeout_add(5, (GSourceFunc) my_silc_scheduler, NULL);
}

/* Init SILC. Called from src/fe-text/silc.c */

void silc_core_init(void)
{
#ifndef SILC_PLUGIN
  static struct poptOption silc_options[] = {
    { NULL, '\0', POPT_ARG_CALLBACK, (void *)&silc_opt_callback, '\0', NULL },
    { "list-ciphers", 0, POPT_ARG_NONE, NULL, 0,
      "List supported ciphers", NULL },
    { "list-hash-funcs", 0, POPT_ARG_NONE, NULL, 0,
      "List supported hash functions", NULL },
    { "list-hmacs", 0, POPT_ARG_NONE, NULL, 0,
      "List supported HMACs", NULL },
    { "list-pkcs", 0, POPT_ARG_NONE, NULL, 0,
      "List supported PKCSs", NULL },
#ifdef SILC_DEBUG
    { "debug", 'd', POPT_ARG_STRING, NULL, 0,
      "Enable debugging", "STRING" },
#endif /* SILC_DEBUG */
    { "create-key-pair", 'C', POPT_ARG_NONE, NULL, 0,
      "Create new public key pair", NULL },
    { "pkcs", 0, POPT_ARG_STRING, &opt_pkcs, 0,
      "Set the PKCS of the public key pair (-C)", "PKCS" },
    { "bits", 0, POPT_ARG_INT, &opt_bits, 0,
      "Set the length of the public key pair (-C)", "VALUE" },
    { "passphrase-change", 'P', POPT_ARG_STRING, NULL, 0,
      "Change the passphrase of private key file", "FILE" },
    { "show-key", 'S', POPT_ARG_STRING, NULL, 0,
      "Show the contents of the public key", "FILE" },
    { NULL, '\0', 0, NULL }
  };
#endif

  CHAT_PROTOCOL_REC *rec;
  SilcClientParams params;
  const char *def_cipher, *def_hash, *def_hmac;

#ifndef SILC_PLUGIN
  args_register(silc_options);
#endif

  /* Settings */
#ifndef SILC_PLUGIN
  settings_add_bool("server", "skip_motd", FALSE);
  settings_add_str("server", "alternate_nick", NULL);
#endif
  settings_add_bool("server", "use_auto_addr", FALSE);
  settings_add_str("server", "auto_bind_ip", "");
  settings_add_str("server", "auto_public_ip", "");
  settings_add_int("server", "auto_bind_port", 0);
  settings_add_str("server", "crypto_default_cipher", SILC_DEFAULT_CIPHER);
  settings_add_str("server", "crypto_default_hash", SILC_DEFAULT_HASH);
  settings_add_str("server", "crypto_default_hmac", SILC_DEFAULT_HMAC);
  settings_add_int("server", "key_exchange_timeout_secs", 120);
  settings_add_int("server", "key_exchange_rekey_secs", 3600);
  settings_add_bool("server", "key_exchange_rekey_pfs", FALSE);
  settings_add_int("server", "heartbeat", 300);
  settings_add_bool("server", "ignore_message_signatures", FALSE);
  settings_add_str("server", "session_filename", "session.$chatnet");
  settings_add_bool("server", "sign_channel_messages", FALSE);
  settings_add_bool("server", "sign_private_messages", FALSE);
  settings_add_str("silc", "nickname_format", "%n#%a");

  /* Requested Attributes settings */
  settings_add_bool("silc", "attr_allow", TRUE);
  settings_add_str("silc", "attr_vcard", "");
  settings_add_str("silc", "attr_services", "");
  settings_add_str("silc", "attr_status_mood", "NORMAL");
  settings_add_str("silc", "attr_status_text", "");
  settings_add_str("silc", "attr_status_message", NULL);
  settings_add_str("silc", "attr_preferred_language", "");
  settings_add_str("silc", "attr_preferred_contact", "CHAT");
  settings_add_bool("silc", "attr_timezone", TRUE);
  settings_add_str("silc", "attr_geolocation", "");
  settings_add_str("silc", "attr_device_info", NULL);
  settings_add_str("silc", "attr_public_keys", "");

#ifdef SILC_DEBUG
  settings_add_bool("debug", "debug", FALSE);
  settings_add_str("debug", "debug_string", "");
#endif

  signal_add("setup changed", (SIGNAL_FUNC) sig_setup_changed);
#ifndef SILC_PLUGIN
  signal_add("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
#endif

#if defined (SILC_PLUGIN) && defined (SILC_DEBUG)
  if (settings_get_bool("debug") == TRUE)
    sig_setup_changed();
#endif

  silc_init_userinfo();

  silc_log_set_callback(SILC_LOG_INFO, silc_log_stderr, NULL);
  silc_log_set_callback(SILC_LOG_WARNING, silc_log_stderr, NULL);
  silc_log_set_callback(SILC_LOG_ERROR, silc_log_stderr, NULL);
  silc_log_set_callback(SILC_LOG_FATAL, silc_log_stderr, NULL);

  /* Initialize client parameters */
  memset(&params, 0, sizeof(params));
  strcat(params.nickname_format, settings_get_str("nickname_format"));

  /* Allocate SILC client */
  silc_client = silc_client_alloc(&ops, &params, NULL, silc_version_string);

  /* Get the ciphers and stuff from config file */
  def_cipher = settings_get_str("crypto_default_cipher");
  def_hash = settings_get_str("crypto_default_hash");
  def_hmac = settings_get_str("crypto_default_hmac");
  silc_register_cipher(silc_client, def_cipher);
#ifdef SILC_PLUGIN
  if (init_failed)
    return;
#endif
  silc_register_hash(silc_client, def_hash);
#ifdef SILC_PLUGIN
  if (init_failed)
    return;
#endif
  silc_register_hmac(silc_client, def_hmac);
#ifdef SILC_PLUGIN
  if (init_failed)
    return;
#endif
  silc_pkcs_register_default();

#ifdef SILC_PLUGIN
  command_bind("silc", MODULE_NAME, (SIGNAL_FUNC) silc_opt_callback);
#endif

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
  rec->server_init_connect = silc_server_init_connect;
  rec->server_connect = silc_server_connect;
  rec->channel_create = (CHANNEL_REC *(*) (SERVER_REC *, const char *,
					   const char *, int))
    silc_channel_create;
  rec->query_create = (QUERY_REC *(*) (const char *, const char *, int))
    silc_query_create;

  chat_protocol_register(rec);
  g_free(rec);

  silc_queue_init();
  silc_server_init();
  silc_channels_init();
  silc_queries_init();
  silc_expandos_init();
  silc_lag_init();
  silc_chatnets_init();

#ifdef SILC_PLUGIN
  sig_init_finished();
  if (init_failed) {
    silc_core_deinit();
    return;
  }
#endif

  module_register("silc", "core");
}

/* Deinit SILC. Called from src/fe-text/silc.c */

void silc_core_deinit(void)
{
  if (idletag != -1)
    g_source_remove(idletag);

  if (running) {
    volatile int stopped = 0;
    silc_client_stop(silc_client, silc_stopped, &stopped);
    while (!stopped)
      silc_client_run_one(silc_client);
  }

  if (opt_hostname)
    silc_free(opt_hostname);
  if (opt_nickname)
    g_free(opt_nickname);

  signal_remove("setup changed", (SIGNAL_FUNC) sig_setup_changed);
#ifdef SILC_PLUGIN
  command_unbind("silc", (SIGNAL_FUNC) silc_opt_callback);
#else
  signal_remove("irssi init finished", (SIGNAL_FUNC) sig_init_finished);
#endif

  signal_emit("chat protocol deinit", 1, chat_protocol_find("SILC"));

  silc_hash_free(sha1hash);

  silc_queue_deinit();
  silc_server_deinit();
  silc_channels_deinit();
  silc_queries_deinit();
  silc_expandos_deinit();
  silc_lag_deinit();
  silc_chatnets_deinit();

  chat_protocol_unregister("SILC");

  if (irssi_pubkey)
    silc_pkcs_public_key_free(irssi_pubkey);
  if (irssi_privkey)
    silc_pkcs_private_key_free(irssi_privkey);
  silc_client_free(silc_client);
}
