/*

  silcd.c
  
  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
#include "version.h"

static void silc_usage();
static char *silc_server_create_identifier();
static int 
silc_server_create_key_pair(char *pkcs_name, int bits, char *path,
			    char *identifier, 
			    SilcPublicKey *ret_pub_key,
			    SilcPrivateKey *ret_prv_key);

/* Long command line options */
static struct option long_opts[] = 
{
  { "config-file", 1, NULL, 'f' },
  { "debug", 0, NULL, 'd' },
  { "help", 0, NULL, 'h' },
  { "version", 0, NULL,'V' },

  /* Key management options */
  { "create-key-pair", 1, NULL, 'C' },
  { "pkcs", 1, NULL, 10 },
  { "bits", 1, NULL, 11 },

  { NULL, 0, NULL, 0 }
};

/* Command line option variables */
static bool opt_create_keypair = FALSE;
static char *opt_keypath = NULL;
static char *opt_pkcs = "rsa";
static int opt_bits = 1024;

/* Prints out the usage of silc client */

static void silc_usage()
{
  printf("\
Usage: silcd [options]\n\
\n\
  Generic Options:\n\
  -f  --config-file=FILE        Alternate configuration file\n\
  -d  --debug                   Enable debugging (no daemon)\n\
  -h  --help                    Display this message\n\
  -V  --version                 Display version\n\
\n\
  Key Management Options:\n\
  -C, --create-key-pair=PATH    Create new public key pair\n\
      --pkcs=PKCS               Set the PKCS of the public key pair\n\
      --bits=VALUE              Set length of the public key pair\n\
\n");
  exit(0);
}

int main(int argc, char **argv)
{
  int ret;
  int opt, option_index;
  char *config_file = NULL;
  SilcServer silcd;

  silc_debug = FALSE;

  /* Parse command line arguments */
  if (argc > 1) {
    while ((opt = getopt_long(argc, argv, "cf:dhVC:",
			      long_opts, &option_index)) != EOF) {
      switch(opt) 
	{
	case 'h':
	  silc_usage();
	  break;
	case 'V':
	  printf("SILCd Secure Internet Live Conferencing daemon, "
		 "version %s\n", silc_version);
	  printf("(c) 1997 - 2001 Pekka Riikonen "
		 "<priikone@poseidon.pspt.fi>\n");
	  exit(0);
	  break;
	case 'd':
	  silc_debug = TRUE;
	  break;
	case 'f':
	  config_file = strdup(optarg);
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

	default:
	  silc_usage();
	  break;
	}
    }
  }

  if (opt_create_keypair == TRUE) {
    /* Create new key pair and exit */
    silc_server_create_key_pair(opt_pkcs, opt_bits, opt_keypath,
				NULL, NULL, NULL);
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

  /* Initialize the server */
  ret = silc_server_init(silcd);
  if (ret == FALSE)
    goto fail;

  if (silc_debug == FALSE)
    /* Before running the server, fork to background and set
       both user and group no non-root */    
    silc_server_daemonise(silcd);
  
  /* Run the server. When this returns the server has been stopped
     and we will exit. */
  silc_server_run(silcd);
  
  /* Stop the server. This probably has been done already but it
     doesn't hurt to do it here again. */
  silc_server_stop(silcd);
  silc_server_free(silcd);
  
  exit(0);
 fail:
  exit(1);
}

/* Returns identifier string for public key generation. */

static char *silc_server_create_identifier()
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
  uint32 key_len;
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
  pkcs->pkcs->init(pkcs->context, bits, rng);

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
