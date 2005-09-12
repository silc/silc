/*

  silcd.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

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

#ifdef HAVE_GETOPT_LONG
/* Long command line options */
static struct option long_opts[] =
{
  { "config-file", 1, NULL, 'f' },
  { "passphrase", 1, NULL, 'p' },
  { "debug", 2, NULL, 'd' },
  { "debug-level", 1, NULL, 'D' },
  { "hexdump", 0, NULL, 'x' },
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
#endif /* HAVE_GETOPT_LONG */

/* Command line option variables */
static char *opt_keypath = NULL;
static char *opt_pkcs = "rsa";
static char *opt_identifier = NULL;
static int opt_bits = 2048;

/* Prints out the usage of silc client */

static void silc_usage(void)
{
  printf(""
"Usage: silcd [options]\n"
"\n"
"  Generic Options:\n"
"  -f  --config-file=FILE        Alternate configuration file\n"
"  -d  --debug=string            Enable debugging (Implies --foreground)\n"
"  -D  --debug-level=level       Enable debugging (Implies --foreground)\n"
"  -x  --hexdump                 Enable hexdumps (Implies --debug)\n"
"  -h  --help                    Display this message\n"
"  -F  --foreground              Dont fork\n"
"  -V  --version                 Display version\n"
"\n"
"  Key Management Options:\n"
"  -C, --create-key-pair=PATH    Create new public key pair\n"
"      --pkcs=PKCS               Set the PKCS of the public key pair\n"
"      --bits=VALUE              Set length of the public key pair\n"
"      --identifier=IDENTIFIER   Public key identifier\n"
"\n"
"      The public key identifier may be of the following format:\n"
"\n"
"      UN=<username>, HN=<hostname or IP>, RN=<real name>, E=<email>,\n"
"      O=<organization>, C=<country>\n"
"\n"
"      The UN and HN must be provided, the others are optional.  If the\n"
"      --identifier option is not used an identifier will be created for\n"
"      the public key automatically.\n"
"\n"
"      Example identifier: \"UN=foobar, HN=foo.bar.com, RN=Foo T. Bar, \n"
"                           E=foo@bar.com, C=FI\"\n"
"\n");
  exit(0);
}

/* Die if a *valid* pid file exists already */

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

/* Drop root privileges. If some system call fails, die. */

static void silc_server_drop_privs(SilcServer server)
{
  /* Are we executing silcd as root or a regular user? */
  if (geteuid()) {
    SILC_LOG_DEBUG(("Server started as user"));
  }
  else {
    struct passwd *pw;
    struct group *gr;
    char *user, *group;

    SILC_LOG_DEBUG(("Server started as root. Dropping privileges."));

    /* Get the values given for user and group in configuration file */
    user = server->config->server_info->user;
    group = server->config->server_info->group;

    if (!user || !group) {
      fprintf(stderr, "Error:"
       "\tSILC server must not be run as root.  For the security of your\n"
       "\tsystem it is strongly suggested that you run SILC under dedicated\n"
       "\tuser account.  Modify the ServerInfo configuration section to run\n"
       "\tthe server as non-root user.\n");
      exit(1);
    }

    /* Check whether the user/group does not begin with a number */
    if (isdigit(user[0]) || isdigit(group[0])) {
      SILC_LOG_DEBUG(("User and/or group starts with a number"));
      fprintf(stderr, "Invalid user and/or group information\n");
      fprintf(stderr, "Please assign them as names, not numbers\n");
      exit(1);
    }

    if (!(pw = getpwnam(user))) {
      fprintf(stderr, "Error: No such user %s found.\n", user);
      exit(1);
    }
    if (!(gr = getgrnam(group))) {
      fprintf(stderr, "Error: No such group %s found.\n", group);
      exit(1);
    }

    /* Check whether user and/or group is set to root. If yes, exit
       immediately. Otherwise, setgid and setuid server to user.group */
    if ((gr->gr_gid == 0) || (pw->pw_uid == 0)) {
      fprintf(stderr, "Error:"
       "\tSILC server must not be run as root.  For the security of your\n"
       "\tsystem it is strongly suggested that you run SILC under dedicated\n"
       "\tuser account.  Modify the ServerInfo configuration section to run\n"
       "\tthe server as non-root user.\n");
      exit(1);
    }

    SILC_LOG_DEBUG(("Changing to group %s (gid=%u)", group, gr->gr_gid));
    if (setgid(gr->gr_gid) != 0) {
      fprintf(stderr, "Error: Failed setgid() to %s (gid=%u). Exiting.\n",
	      group, gr->gr_gid);
      exit(1);
    }
#if defined HAVE_SETGROUPS && defined HAVE_INITGROUPS
    SILC_LOG_DEBUG(("Removing supplementary groups"));
    if (setgroups(0, NULL) != 0) {
      fprintf(stderr, "Error: Failed setgroups() to NULL. Exiting.\n");
      exit(1);
    }
    SILC_LOG_DEBUG(("Setting supplementary groups for user %s", user));
    if (initgroups(user, gr->gr_gid) != 0) {
      fprintf(stderr, "Error: Failed initgroups() for user %s (gid=%u). "
	      "Exiting.\n", user, gr->gr_gid);
      exit(1);
    }
#endif
    SILC_LOG_DEBUG(("Changing to user %s (uid=%u)", user, pw->pw_uid));
    if (setuid(pw->pw_uid) != 0) {
      fprintf(stderr, "Error: Failed to setuid() to %s (gid=%u). Exiting.\n",
              user, pw->pw_uid);
      exit(1);
    }
  }
}

/* Fork server to background */

static void silc_server_daemonise(SilcServer server)
{
  int i;

  SILC_LOG_DEBUG(("Forking SILC server to background"));

  if ((i = fork()) < 0) {
    fprintf(stderr, "Error: fork() failed: %s\n", strerror(errno));
    exit(1);
  }

  if (i) /* Kill the parent */
    exit(0);

  server->background = TRUE;
  setsid();

  /* XXX close stdin, stdout, stderr -- before this, check that all writes
     to stderr are changed to SILC_SERVER_LOG_ERROR() */
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

  /* Rehash the configuration file */
  silc_server_rehash(silcd);
}

SILC_TASK_CALLBACK(stop_server)
{
  /* Stop scheduler, the program will stop eventually after noticing
     that the scheduler is down. */
  silc_schedule_stop(silcd->schedule);
}

/* Dump server statistics into a file into /tmp directory */

SILC_TASK_CALLBACK(dump_stats)
{
  FILE *fdd;
  int fild;
  char filename[256];

  memset(filename, 0, sizeof(filename));
  snprintf(filename, sizeof(filename) - 1, "/tmp/silcd.%d.stats-XXXXXX", getpid());
  fild = mkstemp(filename);
  if (fild == -1)
    return;

  fdd = fdopen(fild, "w");
  if (fdd == NULL) {
    close(fild);
    unlink(filename);
    return;
  }

#define STAT_OUTPUT(fmt, stat) fprintf(fdd, fmt "\n", (int)stat);

  fprintf(fdd, "SILC Server %s Statistics\n\n", silcd->server_name);
  fprintf(fdd, "Local Stats:\n");
  STAT_OUTPUT("  My clients              : %d", silcd->stat.my_clients);
  STAT_OUTPUT("  My servers              : %d", silcd->stat.my_servers);
  STAT_OUTPUT("  My routers              : %d", silcd->stat.my_routers);
  STAT_OUTPUT("  My channels             : %d", silcd->stat.my_channels);
  STAT_OUTPUT("  My joined users         : %d", silcd->stat.my_chanclients);
  STAT_OUTPUT("  My aways                : %d", silcd->stat.my_aways);
  STAT_OUTPUT("  My detached clients     : %d", silcd->stat.my_detached);
  STAT_OUTPUT("  My server operators     : %d", silcd->stat.my_server_ops);
  STAT_OUTPUT("  My router operators     : %d", silcd->stat.my_router_ops);
  fprintf(fdd, "\nGlobal Stats:\n");
  STAT_OUTPUT("  Cell clients            : %d", silcd->stat.cell_clients);
  STAT_OUTPUT("  Cell servers            : %d", silcd->stat.cell_servers);
  STAT_OUTPUT("  Cell channels           : %d", silcd->stat.cell_channels);
  STAT_OUTPUT("  Cell joined users       : %d", silcd->stat.cell_chanclients);
  STAT_OUTPUT("  All clients             : %d", silcd->stat.clients);
  STAT_OUTPUT("  All servers             : %d", silcd->stat.servers);
  STAT_OUTPUT("  All routers             : %d", silcd->stat.routers);
  STAT_OUTPUT("  All channels            : %d", silcd->stat.channels);
  STAT_OUTPUT("  All joined users        : %d", silcd->stat.chanclients);
  STAT_OUTPUT("  All aways               : %d", silcd->stat.aways);
  STAT_OUTPUT("  All detached clients    : %d", silcd->stat.detached);
  STAT_OUTPUT("  All server operators    : %d", silcd->stat.server_ops);
  STAT_OUTPUT("  All router operators    : %d", silcd->stat.router_ops);
  fprintf(fdd, "\nGeneral Stats:\n");
  STAT_OUTPUT("  Connection attempts     : %d", silcd->stat.conn_attempts);
  STAT_OUTPUT("  Connection failures     : %d", silcd->stat.conn_failures);
  STAT_OUTPUT("  Authentication attempts : %d", silcd->stat.auth_attempts);
  STAT_OUTPUT("  Authentication failures : %d", silcd->stat.auth_failures);
  STAT_OUTPUT("  Packets sent            : %d", silcd->stat.packets_sent);
  STAT_OUTPUT("  Packets received        : %d", silcd->stat.packets_received);
  STAT_OUTPUT("  Commands sent           : %d", silcd->stat.commands_sent);
  STAT_OUTPUT("  Commands received       : %d", silcd->stat.commands_received);
  STAT_OUTPUT("  Connections             : %d", silcd->stat.conn_num);

#undef STAT_OUTPUT

#ifdef SILC_DEBUG
  /* Dump internal flags */
  fprintf(fdd, "\nDumping internal flags\n");
  fprintf(fdd, "  server_type            : %d\n", silcd->server_type);
  fprintf(fdd, "  standalone             : %d\n", silcd->standalone);
  fprintf(fdd, "  listenning             : %d\n", silcd->listenning);
  fprintf(fdd, "  background             : %d\n", silcd->background);
  fprintf(fdd, "  backup_router          : %d\n", silcd->backup_router);
  fprintf(fdd, "  backup_primary         : %d\n", silcd->backup_primary);
  fprintf(fdd, "  backup_noswitch        : %d\n", silcd->backup_noswitch);
  fprintf(fdd, "  backup_closed          : %d\n", silcd->backup_closed);
  fprintf(fdd, "  wait_backup            : %d\n", silcd->wait_backup);
  if (silcd->router)
    fprintf(fdd, "  primary router         : %s\n",
      silcd->router->server_name ? silcd->router->server_name : "");

  /* Dump socket connections */
  {
    int i;
    SilcSocketConnection s;

    fprintf(fdd, "\nDumping socket connections\n");
    for (i = 0; i < silcd->config->param.connections_max; i++) {
      s = silcd->sockets[i];
      if (!s)
        continue;
      fprintf(fdd, "  %d: host %s ip %s port %d type %d flags 0x%x\n",
	      s->sock, s->hostname ? s->hostname : "N/A",
	      s->ip ? s->ip : "N/A", s->port, s->type,
	      (unsigned int)s->flags);
    }
  }

  /* Dump lists */
  {
    SilcIDCacheList list = NULL;
    SilcIDCacheEntry id_cache = NULL;
    SilcServerEntry server_entry;
    SilcClientEntry client_entry;
    SilcChannelEntry channel_entry;
    int c;

    fprintf(fdd, "\nDumping databases\n");

    if (silc_idcache_get_all(silcd->local_list->servers, &list)) {
      if (silc_idcache_list_first(list, &id_cache)) {
	fprintf(fdd, "\nServers in local-list:\n");
	c = 1;
	while (id_cache) {
	  server_entry = (SilcServerEntry)id_cache->context;
	  fprintf(fdd, "  %d: name %s id %s status 0x%x\n", c,
		  server_entry->server_name ? server_entry->server_name :
		  "N/A", server_entry->id ?
		  silc_id_render(server_entry->id, SILC_ID_SERVER) : "N/A",
		  server_entry->data.status);
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  c++;
	}
      }
      silc_idcache_list_free(list);
    }
    if (silc_idcache_get_all(silcd->global_list->servers, &list)) {
      if (silc_idcache_list_first(list, &id_cache)) {
	fprintf(fdd, "\nServers in global-list:\n");
	c = 1;
	while (id_cache) {
	  server_entry = (SilcServerEntry)id_cache->context;
	  fprintf(fdd, "  %d: name %s id %s status 0x%x\n", c,
		  server_entry->server_name ? server_entry->server_name :
		  "N/A", server_entry->id ?
		  silc_id_render(server_entry->id, SILC_ID_SERVER) : "N/A",
		  server_entry->data.status);
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  c++;
	}
      }
      silc_idcache_list_free(list);
    }
    if (silc_idcache_get_all(silcd->local_list->clients, &list)) {
      if (silc_idcache_list_first(list, &id_cache)) {
	fprintf(fdd, "\nClients in local-list:\n");
	c = 1;
	while (id_cache) {
	  client_entry = (SilcClientEntry)id_cache->context;
	  server_entry = client_entry->router;
	  fprintf(fdd, "  %d: name %s id %s status 0x%x from %s\n", c,
		  client_entry->nickname ? client_entry->nickname :
		  (unsigned char *)"N/A", client_entry->id ?
		  silc_id_render(client_entry->id, SILC_ID_CLIENT) : "N/A",
		  client_entry->data.status, server_entry ?
		  server_entry->server_name ? server_entry->server_name :
		  "N/A" : "local");
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  c++;
	}
      }
      silc_idcache_list_free(list);
    }
    if (silc_idcache_get_all(silcd->global_list->clients, &list)) {
      if (silc_idcache_list_first(list, &id_cache)) {
	fprintf(fdd, "\nClients in global-list:\n");
	c = 1;
	while (id_cache) {
	  client_entry = (SilcClientEntry)id_cache->context;
	  server_entry = client_entry->router;
	  fprintf(fdd, "  %d: name %s id %s status 0x%x from %s\n", c,
		  client_entry->nickname ? client_entry->nickname :
		  (unsigned char *)"N/A", client_entry->id ?
		  silc_id_render(client_entry->id, SILC_ID_CLIENT) : "N/A",
		  client_entry->data.status, server_entry ?
		  server_entry->server_name ? server_entry->server_name :
		  "N/A" : "local");
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  c++;
	}
      }
      silc_idcache_list_free(list);
    }
    if (silc_idcache_get_all(silcd->local_list->channels, &list)) {
      if (silc_idcache_list_first(list, &id_cache)) {
	fprintf(fdd, "\nChannels in local-list:\n");
	c = 1;
	while (id_cache) {
	  channel_entry = (SilcChannelEntry)id_cache->context;
	  fprintf(fdd, "  %d: name %s id %s\n", c,
		  channel_entry->channel_name ? channel_entry->channel_name :
		  "N/A", channel_entry->id ?
		  silc_id_render(channel_entry->id, SILC_ID_CHANNEL) : "N/A");
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  c++;
	}
      }
      silc_idcache_list_free(list);
    }
    if (silc_idcache_get_all(silcd->global_list->channels, &list)) {
      if (silc_idcache_list_first(list, &id_cache)) {
	fprintf(fdd, "\nChannels in global-list:\n");
	c = 1;
	while (id_cache) {
	  channel_entry = (SilcChannelEntry)id_cache->context;
	  fprintf(fdd, "  %d: name %s id %s\n", c,
		  channel_entry->channel_name ? channel_entry->channel_name :
		  "N/A", channel_entry->id ?
		  silc_id_render(channel_entry->id, SILC_ID_CHANNEL) : "N/A");
	  if (!silc_idcache_list_next(list, &id_cache))
	    break;
	  c++;
	}
      }
      silc_idcache_list_free(list);
    }
  }
#endif

  fflush(fdd);
  fclose(fdd);
}

#ifdef SILC_DEBUG

typedef struct {
  int level;
  const char *string;
} DebugLevel;

static DebugLevel debug_levels[] = {
  /* Very basic stuff from silcd/ */
  { 3, "silcd\\.c,server\\.c" },

  /* More stuff from silcd/ */
  { 7, "silcd\\.c,server\\.c,command\\.c,server_backup\\.c,packet_send\\.c" },

  /* All basic stuff from silcd/ */
  { 10, "silc_server_*" },

  /* All from silcd/ */
  { 15, "*silcd*,*serverid*,silc_server_*,*idlist*" },

  /* All from silcd/ and basic stuff from libs */
  { 20, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,*silcske*" },

  /* All from silcd/ and more stuff from libs */
  { 25, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*" },

  /* All from silcd/ and even more stuff from libs */
  { 30, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*,*command*,*channel*,*private*,*notify*" },

  /* All from silcd/ and even more stuff from libs + all from silccore */
  { 35, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*,*command*,*channel*,*private*,*notify*"
    "*silcid*,*argument*" },

  /* All from silcd/, all from silccore, silccrypt and silcmath */
  { 40, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*,*command*,*channel*,*private*,*notify*"
    "*silcid*,*argument*,*pkcs*,*hmac*,*hash*,*cipher*,silc_math*" },

  /* All from silcd/, all from silccore, silccrypt and silcmath + stuff
     from silcutil */
  { 45, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*,*command*,*channel*,*private*,*notify*"
    "*silcid*,*argument*,*pkcs*,*hmac*,*hash*,*cipher*,silc_math*,*sim*"
    "*sockconn*" },

  /* All from silcd/, all from silccore, silccrypt and silcmath + more stuff
     from silcutil */
  { 50, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*,*command*,*channel*,*private*,*notify*"
    "*silcid*,*argument*,*pkcs*,*hmac*,*hash*,*cipher*,silc_math*,*sim*"
    "*sockconn*,*net*" },

  /* All from silcd/, all from silccore, silccrypt and silcmath + more stuff
     from silcutil */
  { 55, "*silcd*,*serverid*,silc_server_*,*idlist*,*silcauth*,"
    "*silcpacket*,*ske*,*silcrng*,*command*,*channel*,*private*,*notify*"
    "*silcid*,*argument*,*pkcs*,*hmac*,*hash*,*cipher*,silc_math*,*sim*"
    "*sockconn*,*net*,*log*,*config*" },

  /* All */
  { 90, "*" },

  { -1, NULL },
};

static void silc_get_debug_level(int level)
{
  int i;

  if (level < 0)
    return;

  for (i = 0; debug_levels[i].string; i++)
    if (level <= debug_levels[i].level) {
      silc_log_set_debug_string(debug_levels[i].string);
      break;
    }
}
#endif /* SILC_DEBUG */

/* This function should not be called directly but through the appropriate
   wrapper macro defined in server.h */

void silc_server_stderr(SilcLogType type, char *message)
{
  if (silcd->background) {
    char *p, *n = message;

    /* remove newlines if we are going to output it to a log file */
    for (p = n; *p; p++) {
      if (*p != '\n') {
	if (p != n)
	  *n = *p;
	n++;
      }
    }
    *n = 0;

    /* the message is freed inside the logging function */
    silc_log_output(type, message);
  }
  else {
    fprintf(stderr, "%s\n", message);
    silc_free(message);
  }
}

int main(int argc, char **argv)
{
  int ret, opt, option_index;
  bool foreground = FALSE;
  bool opt_create_keypair = FALSE;
  char *silcd_config_file = NULL;
  struct sigaction sa;

  /* Parse command line arguments */
  if (argc > 1) {
#ifdef HAVE_GETOPT_LONG
    while ((opt = getopt_long(argc, argv, "f:p:d:D:xhFVC:",
			      long_opts, &option_index)) != EOF) {
#else
    while ((opt = getopt(argc, argv, "f:p:d:D:xhFVC:")) != EOF) {
#endif /* HAVE_GETOPT_LONG */
      switch(opt) {
	case 'h':
	  silc_usage();
	  break;
	case 'V':
	  printf("SILCd Secure Internet Live Conferencing daemon, "
		 "version %s (base: SILC Toolkit %s)\n",
		 silc_dist_version, silc_version);
	  printf("(c) 1997 - 2005 Pekka Riikonen "
		 "<priikone@silcnet.org>\n");
	  exit(0);
	  break;
	case 'd':
#ifdef SILC_DEBUG
	  silc_log_debug(TRUE);
	  silc_log_quick(TRUE);
	  if (optarg)
	    silc_log_set_debug_string(optarg);
	  foreground = TRUE;	    /* implied */
#else
	  fprintf(stderr,
		  "Run-time debugging is not enabled. To enable it recompile\n"
		  "the server with --enable-debug configuration option.\n");
#endif
	  break;
	case 'D':
#ifdef SILC_DEBUG
	  silc_log_debug(TRUE);
	  silc_log_quick(TRUE);
	  if (optarg)
	    silc_get_debug_level(atoi(optarg));
	  foreground = TRUE;	    /* implied */
#else
	  fprintf(stderr,
		  "Run-time debugging is not enabled. To enable it recompile\n"
		  "the server with --enable-debug configuration option.\n");
#endif
	  break;
	case 'x':
#ifdef SILC_DEBUG
	  silc_log_debug(TRUE);
	  silc_log_debug_hexdump(TRUE);
	  silc_log_quick(TRUE);
	  foreground = TRUE; /* implied */
#else
	  fprintf(stderr,
		  "Run-time debugging is not enabled. To enable it recompile\n"
		  "the server with --enable-debug configuration option.\n");
#endif
	  break;
	case 'f':
	  silcd_config_file = strdup(optarg);
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
    char pubfile[256], prvfile[256];

    memset(pubfile, 0, sizeof(pubfile));
    memset(prvfile, 0, sizeof(prvfile));
    snprintf(pubfile, sizeof(pubfile) - 1, "%s/silcd.pub", opt_keypath);
    snprintf(prvfile, sizeof(prvfile) - 1, "%s/silcd.prv", opt_keypath);

    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_create_key_pair(opt_pkcs, opt_bits, pubfile, prvfile,
			 opt_identifier, "", NULL, NULL, NULL, FALSE);
    exit(0);
  }

  /* Default configuration file */
  if (!silcd_config_file)
    silcd_config_file = strdup(SILC_SERVER_CONFIG_FILE);

  /* Create SILC Server object */
  ret = silc_server_alloc(&silcd);
  if (ret == FALSE)
    goto fail;

  /* Register default crypto stuff since we are going to need them
     in the configuration file parsing phase */
  silc_cipher_register_default();
  silc_pkcs_register_default();
  silc_hash_register_default();
  silc_hmac_register_default();

  /* Read configuration files */
  silcd->config = silc_server_config_alloc(silcd_config_file);
  if (silcd->config == NULL)
    goto fail;
  silcd->config_file = silcd_config_file;

  /* Unregister the default crypto stuff so that configuration takes effect */
  silc_cipher_unregister_all();
  silc_pkcs_unregister_all();
  silc_hash_unregister_all();
  silc_hmac_unregister_all();

  /* Check for another silcd running */
  silc_server_checkpid(silcd);

  /* Initialize the server */
  if (silc_server_init(silcd) == FALSE)
    goto fail;

  /* Ignore some signals */
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
#if defined(SIGPIPE)
  sigaction(SIGPIPE, &sa, NULL);      /* Ignore broken pipes */
#endif /* SIGPIPE*/
#if defined(SIGXFSZ)
  sigaction(SIGXFSZ, &sa, NULL);      /* Ignore file limit exceeds */
#endif /* SIGXFSZ */
#if defined(SIGXCPU)
  sigaction(SIGXCPU, &sa, NULL);      /* Ignore CPU time limit exceeds */
#endif /* SIGXCPU */

  /* Handle specificly some other signals. */
  sa.sa_handler = signal_handler;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGUSR1, &sa, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGHUP, got_hup, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGTERM, stop_server, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGINT, stop_server, NULL);
  silc_schedule_signal_register(silcd->schedule, SIGUSR1, dump_stats, NULL);

  if (!foreground) {
    /* Before running the server, fork to background. */
    silc_server_daemonise(silcd);

    /* If set, write pid to file */
    if (silcd->config->server_info->pid_file) {
      char buf[10], *pidfile = silcd->config->server_info->pid_file;
      unlink(pidfile);
      snprintf(buf, sizeof(buf) - 1, "%d\n", getpid());
      silc_file_writefile(pidfile, buf, strlen(buf));
    }

    silc_server_drop_privs(silcd);
  }

  /* Run the server. When this returns the server has been stopped
     and we will exit. */
  silc_server_run(silcd);

  /* Stop the server and free it. */
  silc_server_stop(silcd);
  silc_server_config_destroy(silcd->config);
  silc_server_free(silcd);

  /* Flush the logging system */
  silc_log_flush_all();

  silc_free(silcd_config_file);
  silc_free(opt_identifier);
  silc_free(opt_keypath);
  exit(0);

 fail:
  silc_free(silcd_config_file);
  silc_free(opt_identifier);
  silc_free(opt_keypath);
  exit(1);
}
