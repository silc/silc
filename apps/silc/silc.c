/*

  silc.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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
 * $Id$
 * $Log$
 * Revision 1.1  2000/06/27 11:36:56  priikone
 * Initial revision
 *
 *
 */

#include "clientincludes.h"
#include "version.h"

/* Long command line options */
static struct option long_opts[] = 
{
  /* Generic options */
  { "server", 1, NULL, 's' },
  { "port", 1, NULL, 'p' },
  { "nickname", 1, NULL, 'n' },
  { "channel", 1, NULL, 'c' },
  { "cipher", 1, NULL, 'r' },
  { "public-key", 1, NULL, 'b' },
  { "private-key", 1, NULL, 'k' },
  { "config-file", 1, NULL, 'f' },
  { "no-silcrc", 0, NULL, 'q' },
  { "help", 0, NULL, 'h' },
  { "version", 0, NULL, 'V' },
  { "list-ciphers", 0, NULL, 1 },
  { "list-hash-funcs", 0, NULL, 2 },
  { "list-pkcs", 0, NULL, 3 },

  /* Key management options */
  { "create-key-pair", 0, NULL, 'C' },
  { "pkcs", 1, NULL, 10 },
  { "bits", 1, NULL, 11 },

  { NULL, 0, NULL, 0 }
};

/* Command line option variables */
static char *opt_server = NULL;
static int opt_port = 0;
static char *opt_nickname = NULL;
static char *opt_channel = NULL;
static char *opt_cipher = NULL;
static char *opt_public_key = NULL;
static char *opt_private_key = NULL;
static char *opt_config_file = NULL;
static int opt_no_silcrc = FALSE;

static int opt_create_keypair = FALSE;
static char *opt_pkcs = NULL;
static int opt_bits = 0;

/* Prints out the usage of silc client */

void usage()
{
  printf("\
Usage: silc [options]\n\
\n\
  Generic Options:\n\
  -s, --server=HOST            Open connection to server HOST\n\
  -p, --port=PORT              Set PORT as default port to connect\n\
  -n, --nickname=STRING        Set default nickname on startup\n\
  -c, --channel=STRING         Join channel on startup\n\
  -r, --cipher=CIPHER          Use CIPHER as default cipher in SILC\n\
  -b, --public-key=FILE        Public key used in SILC\n\
  -k, --private-key=FILE       Private key used in SILC\n\
  -f, --config-file=FILE       Alternate configuration file\n\
  -q, --no-silcrc              Don't load ~/.silcrc on startup\n\
  -h, --help                   Display this help message\n\
  -V, --version                Display version\n\
      --list-ciphers           List supported ciphers\n\
      --list-hash-funcs        List supported hash functions\n\
      --list-pkcs              List supported PKCS's\n\
\n\
  Key Management Options:\n\
  -C, --create-key-pair        Create new public key pair\n\
      --pkcs=PKCS              Set the PKCS of the public key pair\n\
      --bits=VALUE             Set length of the public key pair\n\
\n");
}

int main(int argc, char **argv)
{
  int opt, option_index = 1;
  int ret;
  SilcClient silc = NULL;
  SilcClientConfig config = NULL;
  
  if (argc > 1) 
    {
      while ((opt = 
	      getopt_long(argc, argv,
			  "s:p:n:c:b:k:f:qhVC",
			  long_opts, &option_index)) != EOF)
	{
	  switch(opt) 
	    {
	      /* 
	       * Generic options
	       */
	    case 's':
	      if (optarg)
		opt_server = strdup(optarg);
	      break;
	    case 'p':
	      if (optarg)
		opt_port = atoi(optarg);
	      break;
	    case 'n':
	      if (optarg)
		opt_nickname = strdup(optarg);
	      break;
	    case 'c':
	      if (optarg)
		opt_channel = strdup(optarg);
	      break;
	    case 'r':
	      if (optarg)
		opt_cipher = strdup(optarg);
	      break;
	    case 'b':
	      if (optarg)
		opt_public_key = strdup(optarg);
	      break;
	    case 'k':
	      if (optarg)
		opt_private_key = strdup(optarg);
	      break;
	    case 'f':
	      if (optarg)
		opt_config_file = strdup(optarg);
	      break;
	    case 'q':
	      opt_no_silcrc = TRUE;
	      break;
	    case 'h':
	      usage();
	      exit(0);
	      break;
	    case 'V':
	      printf("\
SILC Secure Internet Live Conferencing, version %s\n", 
		     silc_version);
	      printf("\
(c) 1997 - 2000 Pekka Riikonen <priikone@poseidon.pspt.fi>\n");
	      exit(0);
	      break;
	    case 1:
	      silc_client_list_ciphers();
	      exit(0);
	      break;
	    case 2:
	      silc_client_list_hash_funcs();
	      exit(0);
	      break;
	    case 3:
	      silc_client_list_pkcs();
	      exit(0);
	      break;

	      /*
	       * Key management options
	       */
	    case 'C':
	      opt_create_keypair = TRUE;
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
	      exit(0);
	      break;
	    }
	}
    }

  /* Init signals */
  signal(SIGHUP, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_DFL);
  signal(SIGALRM, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGSEGV, SIG_DFL);
  signal(SIGBUS, SIG_DFL);
  signal(SIGFPE, SIG_DFL);
  //  signal(SIGINT, SIG_IGN);
  
  /* Default configuration file */
  if (!opt_config_file)
    opt_config_file = strdup(SILC_CLIENT_CONFIG_FILE);

  /* Read global configuration file. */
  config = silc_client_config_alloc(opt_config_file);
  if (config == NULL)
    goto fail;

  if (opt_create_keypair == TRUE) {
    /* Create new key pair and exit */
    silc_client_create_key_pair(opt_pkcs, opt_bits);
    exit(0);
  }

  /* Read local configuration file */


  /* Allocate new client */
  ret = silc_client_alloc(&silc);
  if (ret == FALSE)
    goto fail;

  /* Initialize the client */
  silc->config = config;
  ret = silc_client_init(silc);
  if (ret == FALSE)
    goto fail;

  /* Run the client */
  silc_client_run(silc);

  /* Stop the client. This probably has been done already but it
     doesn't hurt to do it here again. */
  silc_client_stop(silc);
  silc_client_free(silc);
  
  exit(0);

 fail:
  if (config)
    silc_client_config_free(config);
  if (silc)
    silc_client_free(silc);
  exit(1);
}
