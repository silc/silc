/*

  silcmap.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"
#include "silcclient.h"
#include "silcversion.h"
#include "silcmap.h"

/* Allocates new SilcMap context and the SilcClient in it. */

SilcMap silc_map_alloc(const char *conffile)
{
  SilcMap map = silc_calloc(1, sizeof(*map));
  if (!map)
    return NULL;

  /* Allocate client */
  map->client = silc_client_alloc(&silc_map_client_ops, NULL, NULL, NULL);
  if (!map->client) {
    silc_free(map);
    return NULL;
  }

  map->client->username = strdup("silcmap");
  map->client->hostname = silc_net_localhost();
  map->client->realname = strdup("silcmap");

  /* Init the client */
  if (!silc_client_init(map->client)) {
    silc_client_free(map->client);
    silc_free(map);
    return NULL;
  }

  /* Load new key pair if it exists, create if it doesn't. */
  if (!silc_load_key_pair("silcmap.pub", "silcmap.prv", "",
			  &map->client->pkcs,
			  &map->client->public_key,
			  &map->client->private_key)) {
    /* The keys don't exist.  Let's generate us a key pair then!  There's
       nice ready routine for that too.  Let's do 1024 bit RSA key pair. */
    if (!silc_create_key_pair("rsa", 1024, "silcmap.pub",
			      "silcmap.prv", NULL, "",
			      &map->client->pkcs,
			      &map->client->public_key,
			      &map->client->private_key, FALSE)) {
      fprintf(stderr, "Could not create new key pair");
      silc_client_free(map->client);
      silc_free(map);
      return NULL;
    }
  }

  map->conffile = strdup(conffile);

  return map;
}

/* Free the SilcMap context and all data in it. */

void silc_map_free(SilcMap map)
{
  SilcMapConnection mapconn;
  SilcMapCommand cmd;
  char *h;

  silc_free(map->conffile);
  silc_free(map->bitmap);

  if (map->client) {
    silc_free(map->client->username);
    silc_free(map->client->realname);
    silc_free(map->client->hostname);
    silc_client_free(map->client);
  }

  if (map->conns) {
    silc_dlist_start(map->conns);
    while ((mapconn = silc_dlist_get(map->conns)) != SILC_LIST_END) {
      silc_dlist_start(mapconn->hostnames);
      while ((h = silc_dlist_get(mapconn->hostnames)) != SILC_LIST_END)
	silc_free(h);
      silc_dlist_uninit(mapconn->hostnames);

      silc_dlist_start(mapconn->ips);
      while ((h = silc_dlist_get(mapconn->ips)) != SILC_LIST_END)
	silc_free(h);
      silc_dlist_uninit(mapconn->ips);

      silc_dlist_start(mapconn->commands);
      while ((cmd = silc_dlist_get(mapconn->commands)) != SILC_LIST_END) {
	silc_free(cmd->filename);
	silc_free(cmd->text);
	silc_free(cmd);
      }
      silc_dlist_uninit(mapconn->commands);

      silc_free(mapconn->public_key);
      silc_free(mapconn->country);
      silc_free(mapconn->city);
      silc_free(mapconn->admin);
      silc_free(mapconn->description);
      silc_free(mapconn->writemaphtml_url);
      silc_free(mapconn->up_color);
      silc_free(mapconn->up_text_color);
      silc_free(mapconn->down_color);
      silc_free(mapconn->down_text_color);
      silc_free(mapconn->data.motd);
      silc_free(mapconn);
    }
    silc_dlist_uninit(map->conns);
  }

  silc_free(map->writemap.filename);
  silc_free(map->writehtml.filename);
  silc_free(map->writehtml.text);
  silc_free(map->writemaphtml.filename);
  silc_free(map->writemaphtml.text);
  silc_free(map->cut.filename);

  silc_free(map);
}

/* Starts the actual silcmap by parsing the commands script. */

SILC_TASK_CALLBACK(silc_map_start)
{
  SilcMap map = context;

  /* Load default font */
  silc_map_load_font(map, "default.fnt");

  /* Start command parsing.  Most of the commands are executed when they
     are parsed so most of the real magic happens here. */
  if (!silc_map_commands_parse(map, map->conffile)) {
    /* Program stops */
    silc_schedule_stop(map->client->schedule);
  }
}

/* Long command line options */
static struct option long_opts[] =
{
  { "config-file", 1, NULL, 'f' },
  { "debug", 2, NULL, 'd' },
  { "help", 0, NULL, 'h' },
  { "version", 0, NULL,'V' },

  { NULL, 0, NULL, 0 }
};

static void silc_map_usage(void)
{
  printf(""
"Usage: silcmap [options]\n"
"\n"
"  Generic Options:\n"
"  -f  --config-file=FILE        Alternate SILC Map configuration file\n"
"  -d  --debug=string            Enable debugging\n"
"  -h  --help                    Display this message and exit\n"
"  -V  --version                 Display version and exit\n"
"\n");
  exit(0);
}

int main(int argc, char **argv)
{
  SilcMap map;
  int opt, option_index;
  char *filename = NULL;

  if (argc > 1) {
    while ((opt = getopt_long(argc, argv, "f:d:hV",
			      long_opts, &option_index)) != EOF) {
      switch(opt) {
	case 'h':
	  silc_map_usage();
	  break;
	case 'V':
	  printf("SILC Map, version %s\n", silc_dist_version);
	  printf("(c) 2003 Pekka Riikonen <priikone@silcnet.org>\n");
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
	case 'f':
	  filename = strdup(optarg);
	  break;
	default:
	  silc_map_usage();
	  break;
      }
    }
  }

  /* Allocate map context */
  if (!filename)
    filename = strdup("silcmap.conf");
  map = silc_map_alloc(filename);
  if (!map)
    return 1;

  /* Schedule for command script parsing */
  silc_schedule_task_add(map->client->schedule, 0,
			 silc_map_start, map, 0, 1,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  /* Run the silcmap client */
  silc_client_run(map->client);

  /* Cleanup */
  silc_client_stop(map->client);
  silc_map_free(map);
  silc_free(filename);

  return 0;
}
