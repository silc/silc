/*

  silcd.c
  
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
 * Created: Wed Mar 19 00:17:12 1997
 *
 * This is the main program for the SILC daemon. This parses command
 * line arguments and creates the server object.
 */
/*
 * $Id$
 * $Log$
 * Revision 1.2  2000/07/05 06:14:01  priikone
 * 	Global costemic changes.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "serverincludes.h"
#include "server_internal.h"
#include "version.h"

/* Long command line options */
static struct option long_opts[] = 
{
  { "config-file", 1, NULL, 'f' },
  { "generate-config-file", 0, NULL, 'c' },
  { "help", 0, NULL, 'h' },
  { "version", 0, NULL,'V' },
  { NULL, 0, NULL, 0 }
};

/* Prints out the usage of silc client */

void silc_usage()
{
  printf("Usage: silcd [options]\n");
  printf("Options:\n");
  printf("  -f  --config-file=FILE        Alternate configuration file\n");
  printf("  -c  --generate-config-file    Generate example configuration "
	 "file\n");
  printf("  -h  --help                    Display this message\n");
  printf("  -V  --version                 Display version\n");
  exit(0);
}

int main(int argc, char **argv)
{
  int ret;
  int opt, option_index;
  char *config_file = NULL;
  SilcServer silcd;

  /* Parse command line arguments */
  if (argc > 1) {
    while ((opt = getopt_long(argc, argv, "cf:hV",
			      long_opts, &option_index)) != EOF) {
      switch(opt) 
	{
	case 'h':
	  silc_usage();
	  break;
	case 'V':
	  printf("SILCd Secure Internet Live Conferencing daemon, "
		 "version %s\n", silc_version);
	  printf("(c) 1997 - 2000 Pekka Riikonen "
		 "<priikone@poseidon.pspt.fi>\n");
	  exit(0);
	  break;
	case 'c':
	  /* Print out example configuration file */
	  silc_config_server_print();
	  exit(0);
	  break;
	case 'f':
	  config_file = strdup(optarg);
	  break;
	default:
	  silc_usage();
	  break;
	}
    }
  }

  /* Default configuration file */
  if (!config_file)
    config_file = strdup(SILC_SERVER_CONFIG_FILE);

  /* Create SILC Server object */
  ret = silc_server_alloc(&silcd);
  if (ret == FALSE)
    goto fail;

  /* Read configuration files */
  silcd->config = silc_config_server_alloc(config_file);
  if (silcd->config == NULL)
    goto fail;

  /* Initialize the server */
  ret = silc_server_init(silcd);
  if (ret == FALSE)
    goto fail;
  
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
