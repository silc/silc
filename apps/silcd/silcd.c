/*

  silcd.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Created: Wed Mar 19 00:17:12 1997
 *
 * This is the main program for the SILC daemon. This parses command
 * line arguments and creates the server object.
 */
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"
#include "silcversion.h"

/* For now, we'll have this one server context global for this module. */
static SilcServer silcd;

static void silc_usage(void);
static char *silc_server_create_identifier(void);
static int
silc_server_create_key_pair(char *pkcs_name, int bits, char *path,
			    char *identifier,
			    SilcPublicKey *ret_pub_key,
			    SilcPrivateKey *ret_prv_key);

/* Long command line options */
static struct option long_opts[] =
{
  { "config-file", 1, NULL, 'f' },
  { "passphrase", 1, NULL, 'p' },
  { "debug", 1, NULL, 'd' },
  { "help", 0, NULL, 'h' },
  { "foreground", 0, NULL, 'F' },
  { "version", 0, NULL,'V' },

  /* Key management options */
  { "create-key-pair", 1, NULL, 'C' },
  { "pkcs", 1, NULL, 10 },
  { "bits", 1, NULL, 11 },
  { "identifier", 1, NULL, 12 },

  { NULL, 0, NULL, 0 }
};

/* Command line option variables */
static bool opt_create_keypair = FALSE;
static char *opt_keypath = NULL;
static char *opt_pkcs = "rsa";
static char *opt_identifier = NULL;
static int opt_bits = 1024;

/* Prints out the usage of silc client */

static void silc_usage(void)
{
  printf("\
Usage: silcd [options]\n\
\n\
  Generic Options:\n\
  -f  --config-file=FILE        Alternate configuration file\n\
  -d  --debug=string            Enable debugging (Implies --foreground)\n\
  -h  --help                    Display this message\n\
  -F  --foreground              Dont fork\n\
  -V  --version                 Display version\n\
\n\
  Key Management Options:\n\
  -C, --create-key-pair=PATH    Create new public key pair\n\
      --pkcs=PKCS               Set the PKCS of the public key pair\n\
      --bits=VALUE              Set length of the public key pair\n\
      --identifier=IDENTIFIER   Public key identifier\n\
\n\
      The public key identifier may be of the following format:\n\
\n\
      UN=<username>, HN=<hostname or IP>, RN=<real name>, E=<email>,\n\
      O=<organization>, C=<country>\n\
\n\
      The UN and HN must be provided, the others are optional.  If the\n\
      --identifier option is not used an identifier will be created for\n\
      the public key automatically.\n\
\n\
      Example identifier: \"UN=foobar, HN=foo.bar.com, RN=Foo T. Bar, \n\
                           E=foo@bar.com, C=FI\"\n\
\n");
  exit(0);
}

/* Dies if a *valid* pid file exists already */

static void silc_server_checkpid(SilcServer silcd)
{
  if (silcd->config->server_info->pid_file) {
    int oldpid;
    char *buf;
    SilcUInt32 buf_len;

    SILC_LOG_DEBUG(("Checking for another silcd running"));
    buf = silc_file_readfile(silcd->config->server_info->pid_file, &buf_len);
    if (!buf)
      return;
    oldpid = atoi(buf);
    silc_free(buf);
    if (oldpid <= 0)
      return;
    kill(oldpid, SIGCHLD); /* this signal does nothing, check if alive */
    if (errno != ESRCH) {
      fprintf(stderr, "\nI detected another daemon running with the "
	      "same pid file.\n");
      fprintf(stderr, "Please change the config file, or erase the %s\n",
	silcd->config->server_info->pid_file);
      exit(1);
    }
  }
}

static void signal_handler(int sig)
{
  /* Mark the signal to be caller after this signal is over. */
  silc_schedule_signal_call(silcd->schedule, sig);
}

SILC_TASK_CALLBACK(got_hup)
{
  /* First, reset all log files (they might have been deleted) */
  silc_log_reset_all();
  silc_log_flush_all();
}

SILC_TASK_CALLBACK(stop_server)
{
  /* Stop scheduler, the program will stop eventually after noticing
     that the scheduler is down. */
  silc_schedule_stop(silcd->schedule); 
}

int main(int argc, char **argv)
{
  int ret, opt, option_index;
  char *config_file = NULL;
  bool foreground = FALSE;
  struct sigaction sa;

  /* Parse command line arguments */
  if (argc > 1) {
    while ((opt = getopt_long(argc, argv, "f:d:hFVC:",
			      long_opts, &option_index)) != EOF) {
      switch(opt)
	{
	case 'h':
	  silc_usage();
	  break;
	case 'V':
	  printf("SILCd Secure Internet Live Conferencing daemon, "
		 "version %s (base: SILC Toolkit %s)\n",
                 silc_dist_version, silc_version);
	  printf("(c) 1997 - 2002 Pekka Riikonen "
		 "<priikone@silcnet.org>\n");
	  exit(0);
	  break;
	case 'd':
#ifdef SILC_DEBUG
	  silc_debug = TRUE;
	  silc_debug_hexdump = TRUE;
	  silc_log_set_debug_string(optarg);
	  foreground = TRUE;
	  silc_log_quick = TRUE;
#else
	  fprintf(stdout,
		  "Run-time debugging is not enabled. To enable it recompile\n"
		  "the server with --enable-debug configuration option.\n");
#endif
	  break;
	case 'f':
	  config_file = strdup(optarg);
	  break;
	case 'F':
	  foreground = TRUE;
	  break;

	  /*
	   * Key management options
	   */
	case 'C':
	  opt_create_keypair = TRUE;
	  if (optarg)
	    opt_keypath = strdup(optarg);
	  break;
	case 10:
	  if (optarg)
	    opt_pkcs = strdup(optarg);
	  break;
	case 11:
	  if (optarg)
	    opt_bits = atoi(optarg);
	  break;
	case 12:
	  if (optarg)
	    opt_identifier = strdup(optarg);
	  break;

	default:
	  silc_usage();
	  break;
	}
    }
  }

  if (opt_create_keypair == TRUE) {
    /* Create new key pair and exit */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_server_create_key_pair(opt_pkcs, opt_bits, opt_keypath,
				opt_identifier, NULL, NULL);
    exit(0);
  }

  /* Default configuration file */
  if (!config_file)
    config_file = strdup(SILC_SERVER_CONFIG_FILE);

  /* Create SILC Server object */
  ret = silc_server_alloc(&silcd);
  if (ret == FALSE)
    goto fail;

  /* Read configuration files */
  silcd->config = silc_server_config_alloc(config_file);
  if (silcd->config == NULL)
    goto fail;

  /* Check for another silcd running */
  silc_server_checkpid(silcd);

  /* Initialize the server */
  ret = silc_server_init(silcd);
  if (ret == FALSE)
    goto fail;

  /* Ignore SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGPIPE, &sa, NULL);
  sa.sa_handler = signal_handler;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGHUP, got_hup, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGTERM, stop_server, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGINT, stop_server, NULL);

  /* Before running the server, fork to background. */
  if (!foreground)
    silc_server_daemonise(silcd);

  /* If set, write pid to file */
  if (silcd->config->server_info->pid_file) {
    char buf[10], *pidfile = silcd->config->server_info->pid_file;
    unlink(pidfile);
    snprintf(buf, sizeof(buf) - 1, "%d\n", getpid());
    silc_file_writefile(pidfile, buf, strlen(buf));
  }

  /* Drop root. */
  silc_server_drop(silcd);

  /* Run the server. When this returns the server has been stopped
     and we will exit. */
  silc_server_run(silcd);
  
  /* Stop the server and free it. */
  silc_server_stop(silcd);
  silc_server_free(silcd);

  /* Flush the logging system */
  silc_log_flush_all();

  exit(0);
 fail:
  exit(1);
}

/* Returns identifier string for public key generation. */

static char *silc_server_create_identifier(void)
{
  char *username = NULL, *realname = NULL;
  char hostname[256], email[256];
  
  /* Get realname */
  realname = silc_get_real_name();

  /* Get hostname */
  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname));

  /* Get username (mandatory) */
  username = silc_get_username();
  if (!username)
    return NULL;

  /* Create default email address, whether it is right or not */
  snprintf(email, sizeof(email), "%s@%s", username, hostname);

  return silc_pkcs_encode_identifier(username, hostname, realname, email,
				     NULL, NULL);
}

/* Creates new public key and private key pair. This is used only
   when user wants to create new key pair from command line. */

static int 
silc_server_create_key_pair(char *pkcs_name, int bits, char *path,
			    char *identifier, 
			    SilcPublicKey *ret_pub_key,
			    SilcPrivateKey *ret_prv_key)
{
  SilcPKCS pkcs;
  SilcPublicKey pub_key;
  SilcPrivateKey prv_key;
  SilcRng rng;
  unsigned char *key;
  SilcUInt32 key_len;
  char pkfile[256], prvfile[256];

  if (!pkcs_name || !path)
    return FALSE;

  if (!silc_pkcs_is_supported(pkcs_name)) {
    fprintf(stderr, "Unsupported PKCS `%s'", pkcs_name);
    return FALSE;
  }

  if (!bits)
    bits = 1024;

  if (!identifier)
    identifier = silc_server_create_identifier();

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_rng_global_init(rng);

  snprintf(pkfile, sizeof(pkfile) - 1, "%s%s", path,
	   SILC_SERVER_PUBLIC_KEY_NAME);
  snprintf(prvfile, sizeof(prvfile) - 1, "%s%s", path,
	   SILC_SERVER_PRIVATE_KEY_NAME);

  /* Generate keys */
  silc_pkcs_alloc(pkcs_name, &pkcs);
  silc_pkcs_generate_key(pkcs, bits, rng);

  /* Save public key into file */
  key = silc_pkcs_get_public_key(pkcs, &key_len);
  pub_key = silc_pkcs_public_key_alloc(pkcs->pkcs->name, identifier,
				       key, key_len);
  silc_pkcs_save_public_key(pkfile, pub_key, SILC_PKCS_FILE_PEM);
  if (ret_pub_key)
    *ret_pub_key = pub_key;
  else
    silc_pkcs_public_key_free(pub_key);

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  /* Save private key into file */
  key = silc_pkcs_get_private_key(pkcs, &key_len);
  prv_key = silc_pkcs_private_key_alloc(pkcs->pkcs->name, key, key_len);
  silc_pkcs_save_private_key(prvfile, prv_key, NULL, SILC_PKCS_FILE_BIN);
  if (ret_prv_key)
    *ret_prv_key = prv_key;
  else
    silc_pkcs_private_key_free(prv_key);

  printf("Public key has been saved into `%s'\n", pkfile);
  printf("Private key has been saved into `%s'\n", prvfile);

  memset(key, 0, sizeof(key_len));
  silc_free(key);

  silc_rng_free(rng);
  silc_pkcs_free(pkcs);

  return TRUE;
}
