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
/* $Id$ */

#include "clientincludes.h"
#include "version.h"

/* Static function prototypes */
static int silc_client_bad_keys(unsigned char key);
static void silc_client_clear_input(SilcClientInternal app);
static void silc_client_process_message(SilcClientInternal app);
static char *silc_client_parse_command(unsigned char *buffer);

void silc_client_create_main_window(SilcClientInternal app);

/* Static task callback prototypes */
SILC_TASK_CALLBACK(silc_client_update_clock);
SILC_TASK_CALLBACK(silc_client_run_commands);
SILC_TASK_CALLBACK(silc_client_process_key_press);

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
  { "debug", 0, NULL, 'd' },
  { "help", 0, NULL, 'h' },
  { "version", 0, NULL, 'V' },
  { "list-ciphers", 0, NULL, 1 },
  { "list-hash-funcs", 0, NULL, 2 },
  { "list-pkcs", 0, NULL, 3 },

  /* Key management options */
  { "create-key-pair", 0, NULL, 'C' },
  { "pkcs", 1, NULL, 10 },
  { "bits", 1, NULL, 11 },
  { "show-key", 1, NULL, 'S' },

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
static bool opt_no_silcrc = FALSE;

static bool opt_create_keypair = FALSE;
static bool opt_show_key = FALSE;
static char *opt_pkcs = NULL;
static char *opt_keyfile = NULL;
static int opt_bits = 0;

/* SILC Client operations */
extern SilcClientOperations ops;

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
  -d, --debug                  Enable debugging\n\
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
  -S, --show-key=FILE          Show the contents of the public key\n\
\n");
}

int main(int argc, char **argv)
{
  int opt, option_index = 1;
  int ret;
  SilcClient silc = NULL;
  SilcClientInternal app = NULL;

  silc_debug = FALSE;

  if (argc > 1) 
    {
      while ((opt = 
	      getopt_long(argc, argv,
			  "s:p:n:c:b:k:f:qdhVCS:",
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
	    case 'd':
	      silc_debug = TRUE;
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
	    case 'S':
	      opt_show_key = TRUE;
	      if (optarg)
		opt_keyfile = strdup(optarg);
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
  
#ifdef SOCKS
  /* Init SOCKS */
  SOCKSinit(argv[0]);
#endif

  if (opt_create_keypair == TRUE) {
    /* Create new key pair and exit */
    silc_client_create_key_pair(opt_pkcs, opt_bits, 
				NULL, NULL, NULL, NULL, NULL);
    silc_free(opt_pkcs);
    exit(0);
  }

  if (opt_show_key == TRUE) {
    /* Dump the key */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
    silc_client_show_key(opt_keyfile);
    silc_free(opt_keyfile);
    exit(0);
  }

  /* Default configuration file */
  if (!opt_config_file)
    opt_config_file = strdup(SILC_CLIENT_CONFIG_FILE);

  /* Allocate internal application context */
  app = silc_calloc(1, sizeof(*app));

  /* Allocate new client */
  app->client = silc = silc_client_alloc(&ops, app);
  if (!silc)
    goto fail;

  /* Read global configuration file. */
  app->config = silc_client_config_alloc(opt_config_file);

  /* XXX Read local configuration file */

  /* Check ~/.silc directory and public and private keys */
  if (silc_client_check_silc_dir() == FALSE)
    goto fail;

  /* Get user information */
  silc->username = silc_get_username();
  silc->hostname = silc_net_localhost();
  silc->realname = silc_get_real_name();

  /* Register all configured ciphers, PKCS and hash functions. */
  if (app->config) {
    app->config->client = (void *)app;
    if (!silc_client_config_register_ciphers(app->config))
      silc_cipher_register_default();
    if (!silc_client_config_register_pkcs(app->config))
      silc_pkcs_register_default();
    if (!silc_client_config_register_hashfuncs(app->config))
      silc_hash_register_default();
    if (!silc_client_config_register_hmacs(app->config))
      silc_hmac_register_default();
  } else {
    /* Register default ciphers, pkcs, hash funtions and hmacs. */
    silc_cipher_register_default();
    silc_pkcs_register_default();
    silc_hash_register_default();
    silc_hmac_register_default();
  }

  /* Load public and private key */
  if (silc_client_load_keys(silc) == FALSE)
    goto fail;

  /* Initialize the client. This initializes the client library and
     sets everything ready for silc_client_run. */
  ret = silc_client_init(silc);
  if (ret == FALSE)
    goto fail;

  /* Register the main task that is used in client. This receives
     the key pressings. */
  silc_task_register(silc->io_queue, fileno(stdin), 
		     silc_client_process_key_press,
		     (void *)silc, 0, 0, 
		     SILC_TASK_FD,
		     SILC_TASK_PRI_NORMAL);

  /* Register timeout task that updates clock every minute. */
  silc_task_register(silc->timeout_queue, 0,
		     silc_client_update_clock,
		     (void *)silc, 
		     silc_client_time_til_next_min(), 0,
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_LOW);

  if (app->config && app->config->commands) {
    /* Run user configured commands with timeout */
    silc_task_register(silc->timeout_queue, 0,
		       silc_client_run_commands,
		       (void *)silc, 0, 1,
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_LOW);
  }

  /* Allocate the input buffer used to save typed characters */
  app->input_buffer = silc_buffer_alloc(SILC_SCREEN_INPUT_WIN_SIZE);
  silc_buffer_pull_tail(app->input_buffer, 
			SILC_BUFFER_END(app->input_buffer));

  /* Initialize the screen */
  silc_client_create_main_window(app);
  silc_screen_print_coordinates(app->screen, 0);

  /* Run the client. When this returns the application will be
     terminated. */
  silc_client_run(silc);

  /* Stop the client. This probably has been done already but it
     doesn't hurt to do it here again. */
  silc_client_stop(silc);
  silc_client_free(silc);
  
  exit(0);

 fail:
  if (opt_config_file)
    silc_free(opt_config_file);
  if (app->config)
    silc_client_config_free(app->config);
  if (silc)
    silc_client_free(silc);
  exit(1);
}

/* Creates the main window used in SILC client. This is called always
   at the initialization of the client. If user wants to create more
   than one windows a new windows are always created by calling 
   silc_client_add_window. */

void silc_client_create_main_window(SilcClientInternal app)
{
  void *screen;

  SILC_LOG_DEBUG(("Creating main window"));

  app->screen = silc_screen_init();
  app->screen->input_buffer = app->input_buffer->data;
  app->screen->u_stat_line.program_name = silc_name;
  app->screen->u_stat_line.program_version = silc_version;

  /* Create the actual screen */
  screen = (void *)silc_screen_create_output_window(app->screen);
  silc_screen_create_input_window(app->screen);
  silc_screen_init_upper_status_line(app->screen);
  silc_screen_init_output_status_line(app->screen);

  app->screen->bottom_line->nickname = silc_get_username();
  silc_screen_print_bottom_line(app->screen, 0);
}

/* The main task on SILC client. This processes the key pressings user
   has made. */

SILC_TASK_CALLBACK(silc_client_process_key_press)
{
  SilcClient client = (SilcClient)context;
  SilcClientInternal app = (SilcClientInternal)client->application;
  int c;

  /* There is data pending in stdin, this gets it directly */
  c = wgetch(app->screen->input_win);
  if (silc_client_bad_keys(c))
    return;

  SILC_LOG_DEBUG(("Pressed key: %d", c));

  switch(c) {
    /* 
     * Special character handling
     */
  case KEY_UP: 
  case KEY_DOWN:
    break;
  case KEY_RIGHT:
    /* Right arrow */
    SILC_LOG_DEBUG(("RIGHT"));
    silc_screen_input_cursor_right(app->screen);
    break;
  case KEY_LEFT:
    /* Left arrow */
    SILC_LOG_DEBUG(("LEFT"));
    silc_screen_input_cursor_left(app->screen);
    break;
  case KEY_BACKSPACE:
  case KEY_DC:
  case '\177':
  case '\b':
    /* Backspace */
    silc_screen_input_backspace(app->screen);
    break;
  case '\011':
    /* Tabulator */
    break;
  case KEY_IC:
    /* Insert switch. Turns on/off insert on input window */
    silc_screen_input_insert(app->screen);
    break;
  case CTRL('j'):
  case '\r':
    /* Enter, Return. User pressed enter we are ready to
       process the message. */
    silc_client_process_message(app);
    break;
  case CTRL('l'):
    /* Refresh screen, Ctrl^l */
    silc_screen_refresh_all(app->screen);
    break;
  case CTRL('a'):
  case KEY_HOME:
#ifdef KEY_BEG
  case KEY_BEG:
#endif
    /* Beginning, Home */
    silc_screen_input_cursor_home(app->screen);
    break;
  case CTRL('e'):
#ifdef KEY_END
  case KEY_END:
#endif
  case KEY_LL:
    /* End */
    silc_screen_input_cursor_end(app->screen);
    break;
  case CTRL('g'):
    /* Bell, Ctrl^g */
    beep();
    break;
  case KEY_DL:
  case CTRL('u'):
    /* Delete line */
    silc_client_clear_input(app);
    break;
  default:
    /* 
     * Other characters 
     */
    if (c < 32) {
      /* Control codes are printed as reversed */
      c = (c & 127) | 64;
      wattron(app->screen->input_win, A_REVERSE);
      silc_screen_input_print(app->screen, c);
      wattroff(app->screen->input_win, A_REVERSE);
    } else  {
      /* Normal character */
      silc_screen_input_print(app->screen, c);
    }
  }

  silc_screen_print_coordinates(app->screen, 0);
  silc_screen_refresh_win(app->screen->input_win);
}

static int silc_client_bad_keys(unsigned char key)
{
  /* these are explained in curses.h */
  switch(key) {
  case KEY_SF:
  case KEY_SR:
  case KEY_NPAGE:
  case KEY_PPAGE:
  case KEY_PRINT:
  case KEY_A1:
  case KEY_A3:
  case KEY_B2:
  case KEY_C1:
  case KEY_C3:
#ifdef KEY_UNDO
  case KEY_UNDO:
#endif
#ifdef KEY_EXIT
  case KEY_EXIT:
#endif
  case '\v':           /* VT */
  case '\E':           /* we ignore ESC */
    return TRUE;
  default: 
    return FALSE; 
  }
}

/* Clears input buffer */

static void silc_client_clear_input(SilcClientInternal app)
{
  silc_buffer_clear(app->input_buffer);
  silc_buffer_pull_tail(app->input_buffer,
 		        SILC_BUFFER_END(app->input_buffer));
  silc_screen_input_reset(app->screen);
}

/* Processes messages user has typed on the screen. This either sends
   a packet out to network or if command were written executes it. */

static void silc_client_process_message(SilcClientInternal app)
{
  unsigned char *data;
  uint32 len;

  SILC_LOG_DEBUG(("Start"));

  data = app->input_buffer->data;
  len = strlen(data);

  if (data[0] == '/' && data[1] != ' ') {
    /* Command */
    uint32 argc = 0;
    unsigned char **argv, *tmpcmd;
    uint32 *argv_lens, *argv_types;
    SilcClientCommand *cmd;
    SilcClientCommandContext ctx;

    /* Get the command */
    tmpcmd = silc_client_parse_command(data);
    cmd = silc_client_local_command_find(tmpcmd);
    if (!cmd && (cmd = silc_client_command_find(tmpcmd)) == NULL) {
      silc_say(app->client, app->current_win, "Invalid command: %s", tmpcmd);
      silc_free(tmpcmd);
      goto out;
    }

    /* Now parse all arguments */
    silc_parse_command_line(data + 1, &argv, &argv_lens, 
			    &argv_types, &argc, cmd->max_args);
    silc_free(tmpcmd);

    SILC_LOG_DEBUG(("Executing command: %s", cmd->name));

    /* Allocate command context. This and its internals must be free'd 
       by the command routine receiving it. */
    ctx = silc_client_command_alloc();
    ctx->client = app->client;
    ctx->conn = app->conn;
    ctx->command = cmd;
    ctx->argc = argc;
    ctx->argv = argv;
    ctx->argv_lens = argv_lens;
    ctx->argv_types = argv_types;

    /* Execute command */
    (*cmd->cb)(ctx);

  } else {
    /* Normal message to a channel */
    if (len && app->conn && app->conn->current_channel &&
	app->conn->current_channel->on_channel == TRUE) {
      silc_print(app->client, "> %s", data);
      silc_client_send_channel_message(app->client, 
				       app->conn,
				       app->conn->current_channel, NULL,
				       0, data, strlen(data), TRUE);
    }
  }

 out:
  /* Clear the input buffer */
  silc_client_clear_input(app);
}

/* Returns the command fetched from user typed command line */

static char *silc_client_parse_command(unsigned char *buffer)
{
  char *ret;
  const char *cp = buffer;
  int len;

  len = strcspn(cp, " ");
  ret = silc_to_upper((char *)++cp);
  ret[len - 1] = 0;

  return ret;
}

/* Updates clock on the screen every minute. */

SILC_TASK_CALLBACK(silc_client_update_clock)
{
  SilcClient client = (SilcClient)context;
  SilcClientInternal app = (SilcClientInternal)client->application;

  /* Update the clock on the screen */
  silc_screen_print_clock(app->screen);

  /* Re-register this same task */
  silc_task_register(qptr, 0, silc_client_update_clock, context, 
		     silc_client_time_til_next_min(), 0,
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_LOW);

  silc_screen_refresh_win(app->screen->input_win);
}

/* Runs commands user configured in configuration file. This is
   called when initializing client. */

SILC_TASK_CALLBACK(silc_client_run_commands)
{
  SilcClient client = (SilcClient)context;
  SilcClientInternal app = (SilcClientInternal)client->application;
  SilcClientConfigSectionCommand *cs;

  SILC_LOG_DEBUG(("Start"));

  cs = app->config->commands;
  while(cs) {
    uint32 argc = 0;
    unsigned char **argv, *tmpcmd;
    uint32 *argv_lens, *argv_types;
    SilcClientCommand *cmd;
    SilcClientCommandContext ctx;

    /* Get the command */
    tmpcmd = silc_client_parse_command(cs->command);
    cmd = silc_client_local_command_find(tmpcmd);
    if (!cmd && (cmd = silc_client_command_find(tmpcmd)) == NULL) {
      silc_say(client, app->conn, "Invalid command: %s", tmpcmd);
      silc_free(tmpcmd);
      continue;
    }
    
    /* Now parse all arguments */
    silc_parse_command_line(cs->command + 1, &argv, &argv_lens, 
			    &argv_types, &argc, cmd->max_args);
    silc_free(tmpcmd);

    SILC_LOG_DEBUG(("Executing command: %s", cmd->name));

    /* Allocate command context. This and its internals must be free'd 
       by the command routine receiving it. */
    ctx = silc_client_command_alloc();
    ctx->client = client;
    ctx->conn = app->conn;
    ctx->command = cmd;
    ctx->argc = argc;
    ctx->argv = argv;
    ctx->argv_lens = argv_lens;
    ctx->argv_types = argv_types;

    /* Execute command */
    (*cmd->cb)(ctx);

    cs = cs->next;
  }
}
