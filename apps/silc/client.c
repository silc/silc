/*

  client.c

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
 * Revision 1.6  2000/07/07 06:54:16  priikone
 * 	Print channel name when receiving channel message to non-current
 * 	channel.
 *
 * Revision 1.5  2000/07/06 07:14:36  priikone
 * 	Fixes to NAMES command handling.
 * 	Fixes when leaving from channel.
 *
 * Revision 1.4  2000/07/05 06:12:05  priikone
 * 	Global cosmetic changes.
 *
 * Revision 1.3  2000/07/04 08:29:12  priikone
 * 	Added support for PING command. The ping times are calculated
 * 	and showed to the user.
 *
 * Revision 1.2  2000/07/03 05:49:48  priikone
 * 	Implemented LEAVE command.  Minor bug fixes.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "clientincludes.h"

/* Static function prototypes */
static int silc_client_bad_keys(unsigned char key);
static void silc_client_process_message(SilcClient client);
static char *silc_client_parse_command(unsigned char *buffer);

/* Static task callback prototypes */
SILC_TASK_CALLBACK(silc_client_update_clock);
SILC_TASK_CALLBACK(silc_client_run_commands);
SILC_TASK_CALLBACK(silc_client_process_key_press);
SILC_TASK_CALLBACK(silc_client_connect_to_server_start);
SILC_TASK_CALLBACK(silc_client_connect_to_server_second);
SILC_TASK_CALLBACK(silc_client_connect_to_server_final);
SILC_TASK_CALLBACK(silc_client_packet_process);
SILC_TASK_CALLBACK(silc_client_packet_parse);

SilcClientWindow silc_client_create_main_window(SilcClient client);
SilcClientWindow silc_client_add_window(SilcClient client,
					int is_current);
void silc_client_packet_parse_type(SilcClient client, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet);
void silc_client_private_message_process(SilcClient client,
					 SilcSocketConnection sock,
					 SilcPacketContext *packet);

/* Definitions from version.h */
extern char *silc_version;
extern char *silc_name;
extern char *silc_fullname;

/* Allocates new client object. This has to be done before client may
   work. After calling this one must call silc_client_init to initialize
   the client. */

int silc_client_alloc(SilcClient *new_client)
{

  *new_client = silc_calloc(1, sizeof(**new_client));
  (*new_client)->input_buffer = NULL;
  (*new_client)->screen = NULL;
  (*new_client)->windows = NULL;
  (*new_client)->windows_count = 0;
  (*new_client)->current_win = NULL;

  return TRUE;
}

/* Free's client object */

void silc_client_free(SilcClient client)
{
  if (client) {
    silc_free(client);
  }
}

/* Initializes the client. This makes all the necessary steps to make
   the client ready to be run. One must call silc_client_run to run the
   client. */

int silc_client_init(SilcClient client)
{

  SILC_LOG_DEBUG(("Initializing client"));
  assert(client);

  client->username = silc_get_username();
  client->realname = silc_get_real_name();

  /* Register all configured ciphers, PKCS and hash functions. */
  client->config->client = (void *)client;
  silc_client_config_register_ciphers(client->config);
  silc_client_config_register_pkcs(client->config);
  silc_client_config_register_hashfuncs(client->config);

  /* Initialize hash functions for client to use */
  silc_hash_alloc("md5", &client->md5hash);
  silc_hash_alloc("sha1", &client->sha1hash);

  /* Initialize none cipher */
  silc_cipher_alloc("none", &client->none_cipher);

  /* Initialize random number generator */
  client->rng = silc_rng_alloc();
  silc_rng_init(client->rng);
  silc_math_primegen_init(); /* XXX */

  /* Load public and private key */
  if (silc_client_load_keys(client) == FALSE)
    goto err0;

  /* Register the task queues. In SILC we have by default three task queues. 
     One task queue for non-timeout tasks which perform different kind of 
     I/O on file descriptors, timeout task queue for timeout tasks, and,
     generic non-timeout task queue whose tasks apply to all connections. */
  silc_task_queue_alloc(&client->io_queue, TRUE);
  if (!client->io_queue) {
    goto err0;
  }
  silc_task_queue_alloc(&client->timeout_queue, TRUE);
  if (!client->timeout_queue) {
    goto err1;
  }
  silc_task_queue_alloc(&client->generic_queue, TRUE);
  if (!client->generic_queue) {
    goto err1;
  }

  /* Initialize the scheduler */
  silc_schedule_init(client->io_queue, client->timeout_queue, 
		     client->generic_queue, 5000);

  /* Register the main task that is used in client. This received
     the key pressings. */
  if (silc_task_register(client->io_queue, fileno(stdin), 
			 silc_client_process_key_press,
			 (void *)client, 0, 0, 
			 SILC_TASK_FD,
			 SILC_TASK_PRI_NORMAL) == NULL) {
    goto err2;
  }

  /* Register timeout task that updates clock every minute. */
  if (silc_task_register(client->timeout_queue, 0,
			 silc_client_update_clock,
			 (void *)client, 
			 silc_client_time_til_next_min(), 0,
			 SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_LOW) == NULL) {
    goto err2;
  }

  if (client->config->commands) {
    /* Run user configured commands with timeout */
    if (silc_task_register(client->timeout_queue, 0,
			   silc_client_run_commands,
			   (void *)client, 0, 1,
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_LOW) == NULL) {
      goto err2;
    }
  }

  /* Allocate the input buffer used to save typed characters */
  client->input_buffer = silc_buffer_alloc(SILC_SCREEN_INPUT_WIN_SIZE);
  silc_buffer_pull_tail(client->input_buffer, 
			SILC_BUFFER_END(client->input_buffer));

  /* Initialize the screen */
  client->screen = silc_screen_init();
  silc_client_create_main_window(client);
  client->screen->input_buffer = client->input_buffer->data;
  silc_screen_print_coordinates(client->screen, 0);

  return TRUE;

 err0:
  silc_task_queue_free(client->timeout_queue);
 err1:
  silc_task_queue_free(client->io_queue);
 err2:
  return FALSE;
}

/* Stops the client. This is called to stop the client and thus to stop
   the program. */

void silc_client_stop(SilcClient client)
{
  SILC_LOG_DEBUG(("Stopping client"));

  /* Stop the scheduler, although it might be already stopped. This
     doesn't hurt anyone. This removes all the tasks and task queues,
     as well. */
  silc_schedule_stop();
  silc_schedule_uninit();

  SILC_LOG_DEBUG(("Client client"));
}

/* Runs the client. */

void silc_client_run(SilcClient client)
{
  SILC_LOG_DEBUG(("Running client"));

  /* Start the scheduler, the heart of the SILC client. When this returns
     the program will be terminated. */
  silc_schedule();
}

/* Creates the main window used in SILC client. This is called always
   at the initialization of the client. If user wants to create more
   than one windows a new windows are always created by calling 
   silc_client_add_window. */

SilcClientWindow silc_client_create_main_window(SilcClient client)
{
  SilcClientWindow win;
  void *screen;

  SILC_LOG_DEBUG(("Creating main window"));

  assert(client->screen != NULL);

  win = silc_calloc(1, sizeof(*win));

  client->screen->u_stat_line.program_name = silc_name;
  client->screen->u_stat_line.program_version = silc_version;

  /* Add the pointers */
  win->nickname = silc_get_username();
  win->local_id = NULL;
  win->local_id_data = NULL;
  win->local_id_data_len = 0;
  win->remote_host = NULL;
  win->remote_port = -1;
  win->sock = NULL;

  /* Create the actual screen */
  screen = (void *)silc_screen_create_output_window(client->screen);
  silc_screen_create_input_window(client->screen);
  silc_screen_init_upper_status_line(client->screen);
  silc_screen_init_output_status_line(client->screen);
  win->screen = screen;

  client->screen->bottom_line->nickname = win->nickname;
  silc_screen_print_bottom_line(client->screen, 0);

  /* Add the window to windows table */
  client->windows = silc_calloc(1, sizeof(*client->windows));
  client->windows[client->windows_count] = win;
  client->windows_count = 1;

  /* Automatically becomes the current active window */
  client->current_win = win;

  return win;
}

/* Allocates and adds new window to the client. This allocates new
   physical window and internal window for connection specific data. 
   All the connection specific data is always saved into a window
   since connection is always associated to a active window. */

SilcClientWindow silc_client_add_window(SilcClient client,
					int is_current)
{
  SilcClientWindow win;

  assert(client->screen != NULL);

  win = silc_calloc(1, sizeof(*win));

  /* Add the pointers */
  win->screen = silc_screen_add_output_window(client->screen);
  win->sock = NULL;

  /* Add the window to windows table */
  client->windows = silc_realloc(client->windows, sizeof(*client->windows)
				 * (client->windows_count + 1));
  client->windows[client->windows_count] = win;
  client->windows_count++;

  if (is_current == TRUE)
    client->current_win = win;

  return win;
}

/* The main task on SILC client. This processes the key pressings user
   has made. */

SILC_TASK_CALLBACK(silc_client_process_key_press)
{
  SilcClient client = (SilcClient)context;
  int c;

  /* There is data pending in stdin, this gets it directly */
  c = wgetch(client->screen->input_win);
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
    silc_screen_input_cursor_right(client->screen);
    break;
  case KEY_LEFT:
    /* Left arrow */
    SILC_LOG_DEBUG(("LEFT"));
    silc_screen_input_cursor_left(client->screen);
    break;
  case KEY_BACKSPACE:
  case KEY_DC:
  case '\177':
  case '\b':
    /* Backspace */
    silc_screen_input_backspace(client->screen);
    break;
  case '\011':
    /* Tabulator */
    break;
  case KEY_IC:
    /* Insert switch. Turns on/off insert on input window */
    silc_screen_input_insert(client->screen);
    break;
  case CTRL('j'):
  case '\r':
    /* Enter, Return. User pressed enter we are ready to
       process the message. */
    silc_client_process_message(client);
    silc_screen_input_reset(client->screen);
    break;
  case CTRL('l'):
    /* Refresh screen, Ctrl^l */
    silc_screen_refresh_all(client->screen);
    break;
  case CTRL('a'):
  case KEY_HOME:
  case KEY_BEG:
    /* Beginning, Home */
    silc_screen_input_cursor_home(client->screen);
    break;
  case CTRL('e'):
  case KEY_END:
    /* End */
    silc_screen_input_cursor_end(client->screen);
    break;
  case KEY_LL:
    /* End */
    break;
  case CTRL('g'):
    /* Bell, Ctrl^g */
    beep();
    break;
  case KEY_DL:
  case CTRL('u'):
    /* Delete line */
    break;
  default:
    /* 
     * Other characters 
     */
    if (c < 32) {
      /* Control codes are printed as reversed */
      c = (c & 127) | 64;
      wattron(client->screen->input_win, A_REVERSE);
      silc_screen_input_print(client->screen, c);
      wattroff(client->screen->input_win, A_REVERSE);
    } else  {
      /* Normal character */
      silc_screen_input_print(client->screen, c);
    }
  }

  silc_screen_print_coordinates(client->screen, 0);
  silc_screen_refresh_win(client->screen->input_win);
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
  case KEY_UNDO:
  case KEY_EXIT:
  case '\v':           /* VT */
  case '\E':           /* we ignore ESC */
    return TRUE;
  default: 
    return FALSE; 
  }
}

/* Processes messages user has typed on the screen. This either sends
   a packet out to network or if command were written executes it. */

static void silc_client_process_message(SilcClient client)
{
  unsigned char *data;
  unsigned int len;

  SILC_LOG_DEBUG(("Start"));

  data = client->input_buffer->data;
  len = strlen(data);

  if (data[0] == '/' && data[1] != ' ') {
    /* Command */
    unsigned int argc = 0;
    unsigned char **argv, *tmpcmd;
    unsigned int *argv_lens, *argv_types;
    SilcClientCommand *cmd;
    SilcClientCommandContext ctx;

    /* Get the command */
    tmpcmd = silc_client_parse_command(data);

    /* Find command match */
    for (cmd = silc_command_list; cmd->name; cmd++) {
      if (!strcmp(cmd->name, tmpcmd))
	break;
    }

    if (cmd->name == NULL) {
      silc_say(client, "Invalid command: %s", tmpcmd);
      silc_free(tmpcmd);
      goto out;
    }

    /* Now parse all arguments */
    silc_client_parse_command_line(data, &argv, &argv_lens, 
				   &argv_types, &argc, cmd->max_args);
    silc_free(tmpcmd);

    SILC_LOG_DEBUG(("Exeuting command: %s", cmd->name));

    /* Allocate command context. This and its internals must be free'd 
       by the command routine receiving it. */
    ctx = silc_calloc(1, sizeof(*ctx));
    ctx->client = client;
    ctx->sock = client->current_win->sock;
    ctx->argc = argc;
    ctx->argv = argv;
    ctx->argv_lens = argv_lens;
    ctx->argv_types = argv_types;

    /* Execute command */
    (*cmd->cb)(ctx);

  } else {
    /* Normal message to a channel */
    if (len && client->current_win->current_channel &&
	client->current_win->current_channel->on_channel == TRUE) {
      silc_print(client, "> %s", data);
      silc_client_packet_send_to_channel(client, 
					 client->current_win->sock,
					 client->current_win->current_channel,
					 data, strlen(data), TRUE);
    }
  }

 out:
  /* Clear the input buffer */
  silc_buffer_clear(client->input_buffer);
  silc_buffer_pull_tail(client->input_buffer, 
			SILC_BUFFER_END(client->input_buffer));
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

/* Parses user typed command line. At most `max_args' is taken. Rest
   of the line will be allocated as the last argument if there are more
   than `max_args' arguments in the line. Note that the command name
   is counted as one argument and is saved. */

void silc_client_parse_command_line(unsigned char *buffer, 
				    unsigned char ***parsed,
				    unsigned int **parsed_lens,
				    unsigned int **parsed_types,
				    unsigned int *parsed_num,
				    unsigned int max_args)
{
  int i, len = 0;
  int argc = 0;
  const char *cp = buffer;

  /* Take the '/' away */
  cp++;

  *parsed = silc_calloc(1, sizeof(**parsed));
  *parsed_lens = silc_calloc(1, sizeof(**parsed_lens));

  /* Get the command first */
  len = strcspn(cp, " ");
  (*parsed)[0] = silc_to_upper((char *)cp);
  (*parsed_lens)[0] = len;
  cp += len + 1;
  argc++;

  /* Parse arguments */
  if (strchr(cp, ' ') || strlen(cp) != 0) {
    for (i = 1; i < max_args; i++) {

      if (i != max_args - 1)
	len = strcspn(cp, " ");
      else
	len = strlen(cp);
      
      *parsed = silc_realloc(*parsed, sizeof(**parsed) * (argc + 1));
      *parsed_lens = silc_realloc(*parsed_lens, 
				  sizeof(**parsed_lens) * (argc + 1));
      (*parsed)[argc] = silc_calloc(len + 1, sizeof(char));
      memcpy((*parsed)[argc], cp, len);
      (*parsed_lens)[argc] = len;
      argc++;

      cp += len;
      if (strlen(cp) == 0)
	break;
      else
	cp++;
    }
  }

  /* Save argument types. Protocol defines all argument types but
     this implementation makes sure that they are always in correct
     order hence this simple code. */
  *parsed_types = silc_calloc(argc, sizeof(**parsed_types));
  for (i = 0; i < argc; i++)
    (*parsed_types)[i] = i;

  *parsed_num = argc;
}

/* Updates clock on the screen every minute. */

SILC_TASK_CALLBACK(silc_client_update_clock)
{
  SilcClient client = (SilcClient)context;

  /* Update the clock on the screen */
  silc_screen_print_clock(client->screen);

  /* Re-register this same task */
  silc_task_register(qptr, 0, silc_client_update_clock, context, 
		     silc_client_time_til_next_min(), 0,
		     SILC_TASK_TIMEOUT,
		     SILC_TASK_PRI_LOW);

  silc_screen_refresh_win(client->screen->input_win);
}

/* Runs commands user configured in configuration file. This is
   called when initializing client. */

SILC_TASK_CALLBACK(silc_client_run_commands)
{
  SilcClient client = (SilcClient)context;
  SilcClientConfigSectionCommand *cs;

  SILC_LOG_DEBUG(("Start"));

  cs = client->config->commands;
  while(cs) {
    unsigned int argc = 0;
    unsigned char **argv, *tmpcmd;
    unsigned int *argv_lens, *argv_types;
    SilcClientCommand *cmd;
    SilcClientCommandContext ctx;

    /* Get the command */
    tmpcmd = silc_client_parse_command(cs->command);

    for (cmd = silc_command_list; cmd->name; cmd++) {
      if (!strcmp(cmd->name, tmpcmd))
	break;
    }
    
    if (cmd->name == NULL) {
      silc_say(client, "Invalid command: %s", tmpcmd);
      silc_free(tmpcmd);
      continue;
    }
    
    /* Now parse all arguments */
    silc_client_parse_command_line(cs->command, &argv, &argv_lens, 
				   &argv_types, &argc, cmd->max_args);
    silc_free(tmpcmd);

    SILC_LOG_DEBUG(("Exeuting command: %s", cmd->name));

    /* Allocate command context. This and its internals must be free'd 
       by the command routine receiving it. */
    ctx = silc_calloc(1, sizeof(*ctx));
    ctx->client = client;
    ctx->sock = client->current_win->sock;
    ctx->argc = argc;
    ctx->argv = argv;
    ctx->argv_lens = argv_lens;
    ctx->argv_types = argv_types;

    /* Execute command */
    (*cmd->cb)(ctx);

    cs = cs->next;
  }
}

/* Internal context for connection process. This is needed as we
   doing asynchronous connecting. */
typedef struct {
  SilcClient client;
  SilcTask task;
  int sock;
  char *host;
  int port;
  int tries;
} SilcClientInternalConnectContext;

static int 
silc_client_connect_to_server_internal(SilcClientInternalConnectContext *ctx)
{
  int sock;

  /* XXX In the future we should give up this non-blocking connect all
     together and use threads instead. */
  /* Create connection to server asynchronously */
  sock = silc_net_create_connection_async(ctx->port, ctx->host);
  if (sock < 0)
    return -1;

  /* Register task that will receive the async connect and will
     read the result. */
  ctx->task = silc_task_register(ctx->client->io_queue, sock, 
				 silc_client_connect_to_server_start,
				 (void *)ctx, 0, 0, 
				 SILC_TASK_FD,
				 SILC_TASK_PRI_NORMAL);
  silc_task_reset_iotype(ctx->task, SILC_TASK_WRITE);
  silc_schedule_set_listen_fd(sock, ctx->task->iomask);

  ctx->sock = sock;

  return sock;
}

/* Connects to remote server */

int silc_client_connect_to_server(SilcClient client, int port,
				  char *host)
{
  SilcClientInternalConnectContext *ctx;

  SILC_LOG_DEBUG(("Connecting to port %d of server %s",
		  port, host));

  silc_say(client, "Connecting to port %d of server %s", port, host);

  client->current_win->remote_host = strdup(host);
  client->current_win->remote_port = port;

  /* Allocate internal context for connection process. This is
     needed as we are doing async connecting. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->client = client;
  ctx->host = strdup(host);
  ctx->port = port;
  ctx->tries = 0;

  /* Do the actual connecting process */
  return silc_client_connect_to_server_internal(ctx);
}

/* Start of the connection to the remote server. This is called after
   succesful TCP/IP connection has been established to the remote host. */

SILC_TASK_CALLBACK(silc_client_connect_to_server_start)
{
  SilcClientInternalConnectContext *ctx =
    (SilcClientInternalConnectContext *)context;
  SilcClient client = ctx->client;
  SilcProtocol protocol;
  SilcClientKEInternalContext *proto_ctx;
  int opt, opt_len = sizeof(opt);

  SILC_LOG_DEBUG(("Start"));

  /* Check the socket status as it might be in error */
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &opt_len);
  if (opt != 0) {
    if (ctx->tries < 2) {
      /* Connection failed but lets try again */
      silc_say(ctx->client, "Could not connect to server %s: %s",
	       ctx->host, strerror(opt));
      silc_say(client, "Connecting to port %d of server %s resumed", 
	       ctx->port, ctx->host);

      /* Unregister old connection try */
      silc_schedule_unset_listen_fd(fd);
      silc_net_close_connection(fd);
      silc_task_unregister(client->io_queue, ctx->task);

      /* Try again */
      silc_client_connect_to_server_internal(ctx);
      ctx->tries++;
    } else {
      /* Connection failed and we won't try anymore */
      silc_say(ctx->client, "Could not connect to server %s: %s",
	       ctx->host, strerror(opt));
      silc_schedule_unset_listen_fd(fd);
      silc_net_close_connection(fd);
      silc_task_unregister(client->io_queue, ctx->task);
      silc_free(ctx);
    }
    return;
  }

  silc_schedule_unset_listen_fd(fd);
  silc_task_unregister(client->io_queue, ctx->task);
  silc_free(ctx);

  /* Allocate new socket connection object */
  silc_socket_alloc(fd, SILC_SOCKET_TYPE_SERVER, 
		    (void *)client->current_win, 
		    &client->current_win->sock);
  if (client->current_win->sock == NULL) {
    silc_say(client, "Error: Could not allocate connection socket");
    silc_net_close_connection(fd);
    return;
  }
  client->current_win->sock->hostname = client->current_win->remote_host;
  client->current_win->sock->port = client->current_win->remote_port;

  /* Allocate internal Key Exchange context. This is sent to the
     protocol as context. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = client->current_win->sock;
  proto_ctx->rng = client->rng;
  proto_ctx->responder = FALSE;

  /* Perform key exchange protocol. silc_client_connect_to_server_final
     will be called after the protocol is finished. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
		      &protocol, (void *)proto_ctx,
		      silc_client_connect_to_server_second);
  if (!protocol) {
    silc_say(client, "Error: Could not start authentication protocol");
    return;
  }
  client->current_win->sock->protocol = protocol;

  /* Register the connection for network input and output. This sets
     that scheduler will listen for incoming packets for this connection 
     and sets that outgoing packets may be sent to this connection as well.
     However, this doesn't set the scheduler for outgoing traffic, it will 
     be set separately by calling SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT,
     later when outgoing data is available. */
  context = (void *)client;
  SILC_CLIENT_REGISTER_CONNECTION_FOR_IO(fd);

  /* Execute the protocol */
  protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
}

/* Second part of the connecting to the server. This executed 
   authentication protocol. */

SILC_TASK_CALLBACK(silc_client_connect_to_server_second)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcSocketConnection sock = NULL;
  SilcClientConnAuthInternalContext *proto_ctx;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR) {
    /* Error occured during protocol */
    SILC_LOG_DEBUG(("Error during KE protocol"));
    silc_protocol_free(protocol);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    ctx->sock->protocol = NULL;
    silc_free(ctx);
    return;
  }

  /* Allocate internal context for the authentication protocol. This
     is sent as context for the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->client = (void *)client;
  proto_ctx->sock = sock = ctx->sock;
  proto_ctx->ske = ctx->ske;	/* Save SKE object from previous protocol */
  proto_ctx->dest_id_type = ctx->dest_id_type;
  proto_ctx->dest_id = ctx->dest_id;

  /* Resolve the authentication method to be used in this connection */
  proto_ctx->auth_meth = SILC_PROTOCOL_CONN_AUTH_NONE;
  if (client->config->conns) {
    SilcClientConfigSectionConnection *conn = NULL;

    /* Check if we find a match from user configured connections */
    conn = silc_client_config_find_connection(client->config,
					      sock->hostname,
					      sock->port);
    if (conn) {
      /* Match found. Use the configured authentication method */
      proto_ctx->auth_meth = conn->auth_meth;
      if (conn->auth_data) {
	proto_ctx->auth_data = strdup(conn->auth_data);
	proto_ctx->auth_data_len = strlen(conn->auth_data);
      }
    } else {
      /* No match found. Resolve by sending AUTH_REQUEST to server */
      proto_ctx->auth_meth = SILC_PROTOCOL_CONN_AUTH_NONE;
    }
  } else {
    /* XXX Resolve by sending AUTH_REQUEST to server */
    proto_ctx->auth_meth = SILC_PROTOCOL_CONN_AUTH_NONE;
  }

  /* Free old protocol as it is finished now */
  silc_protocol_free(protocol);
  if (ctx->packet)
    silc_buffer_free(ctx->packet);
  silc_free(ctx);
  /* silc_free(ctx->keymat....); */
  sock->protocol = NULL;

  /* Allocate the authentication protocol. This is allocated here
     but we won't start it yet. We will be receiving party of this
     protocol thus we will wait that connecting party will make
     their first move. */
  silc_protocol_alloc(SILC_PROTOCOL_CLIENT_CONNECTION_AUTH, 
		      &sock->protocol, (void *)proto_ctx, 
		      silc_client_connect_to_server_final);

  /* Execute the protocol */
  sock->protocol->execute(client->timeout_queue, 0, sock->protocol, fd, 0, 0);
}

/* Finalizes the connection to the remote SILC server. This is called
   after authentication protocol has been completed. This send our
   user information to the server to receive our client ID from
   server. */

SILC_TASK_CALLBACK(silc_client_connect_to_server_final)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientConnAuthInternalContext *ctx = 
    (SilcClientConnAuthInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientWindow win = (SilcClientWindow)ctx->sock->user_data;
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_ERROR) {
    /* Error occured during protocol */
    SILC_LOG_DEBUG(("Error during authentication protocol"));
    silc_protocol_free(protocol);
    if (ctx->auth_data)
      silc_free(ctx->auth_data);
    if (ctx->ske)
      silc_ske_free(ctx->ske);
    if (ctx->dest_id)
      silc_free(ctx->dest_id);
    silc_free(ctx);
    win->sock->protocol = NULL;
    return;
  }

  /* Send NEW_CLIENT packet to the server. We will become registered
     to the SILC network after sending this packet and we will receive
     client ID from the server. */
  packet = silc_buffer_alloc(2 + 2 + strlen(client->username) + 
			     strlen(client->realname));
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(strlen(client->username)),
		     SILC_STR_UI_XNSTRING(client->username,
					  strlen(client->username)),
		     SILC_STR_UI_SHORT(strlen(client->realname)),
		     SILC_STR_UI_XNSTRING(client->realname,
					  strlen(client->realname)),
		     SILC_STR_END);

  /* Send the packet */
  silc_client_packet_send(client, ctx->sock, SILC_PACKET_NEW_CLIENT,
			  NULL, 0, NULL, NULL, 
			  packet->data, packet->len, TRUE);
  silc_buffer_free(packet);

  /* Save remote ID. */
  win->remote_id = ctx->dest_id;
  win->remote_id_data = silc_id_id2str(ctx->dest_id, SILC_ID_CHANNEL);
  win->remote_id_data_len = SILC_ID_CHANNEL_LEN;

  silc_say(client, "Connected to port %d of host %s",
	   win->remote_port, win->remote_host);

  client->screen->bottom_line->connection = win->remote_host;
  silc_screen_print_bottom_line(client->screen, 0);

  silc_protocol_free(protocol);
  if (ctx->auth_data)
    silc_free(ctx->auth_data);
  if (ctx->ske)
    silc_ske_free(ctx->ske);
  if (ctx->dest_id)
    silc_free(ctx->dest_id);
  silc_free(ctx);
  win->sock->protocol = NULL;
}

typedef struct {
  SilcPacketContext *packetdata;
  SilcSocketConnection sock;
  SilcClient client;
} SilcClientInternalPacket;

SILC_TASK_CALLBACK(silc_client_packet_process)
{
  SilcClient client = (SilcClient)context;
  SilcSocketConnection sock = NULL;
  int ret, packetlen, paddedlen;

  SILC_LOG_DEBUG(("Processing packet"));

  SILC_CLIENT_GET_SOCK(client, fd, sock);
  if (sock == NULL)
    return;

  /* Packet sending */
  if (type == SILC_TASK_WRITE) {
    SILC_LOG_DEBUG(("Writing data to connection"));

    if (sock->outbuf->data - sock->outbuf->head)
      silc_buffer_push(sock->outbuf, 
		       sock->outbuf->data - sock->outbuf->head);

    /* Write the packet out to the connection */
    ret = silc_packet_write(fd, sock->outbuf);

    /* If returned -2 could not write to connection now, will do
       it later. */
    if (ret == -2)
      return;
    
    /* Error */
    if (ret == -1)
      SILC_LOG_ERROR(("Packet dropped"));

    /* The packet has been sent and now it is time to set the connection
       back to only for input. When there is again some outgoing data 
       available for this connection it will be set for output as well. 
       This call clears the output setting and sets it only for input. */
    SILC_CLIENT_SET_CONNECTION_FOR_INPUT(fd);
    SILC_UNSET_OUTBUF_PENDING(sock);

    return;
  }

  /* Packet receiving */
  if (type == SILC_TASK_READ) {
    SILC_LOG_DEBUG(("Reading data from connection"));

    /* Allocate the incoming data buffer if not done already. */
    if (!sock->inbuf)
      sock->inbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);

    /* Read some data from connection */
    ret = silc_packet_read(fd, sock->inbuf);
    
    /* If returned -2 data was not available now, will read it later. */
    if (ret == -2)
      return;
    
    /* Error */
    if (ret == -1) {
      SILC_LOG_ERROR(("Packet dropped"));
      return;
    }
    
    /* EOF */
    if (ret == 0) {
      SILC_LOG_DEBUG(("Read EOF"));

      /* If connection is disconnecting already we will finally
	 close the connection */
      if (SILC_IS_DISCONNECTING(sock)) {
	silc_client_close_connection(client, sock);
	return;
      }
      
      silc_say(client, "Connection closed: premature EOF");
      SILC_LOG_DEBUG(("Premature EOF from connection %d", sock->sock));

      silc_client_close_connection(client, sock);
      return;
    }

    /* Check whether we received a whole packet. If reading went without
       errors we either read a whole packet or the read packet is 
       incorrect and will be dropped. */
    SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);
    if (sock->inbuf->len < paddedlen || (packetlen < SILC_PACKET_MIN_LEN)) {
      SILC_LOG_DEBUG(("Received incorrect packet, dropped"));
      silc_buffer_clear(sock->inbuf);
      return;
    }
    
    /* Decrypt a packet coming from server connection */
    if (sock->type == SILC_SOCKET_TYPE_SERVER ||
	sock->type == SILC_SOCKET_TYPE_ROUTER) {
      SilcClientWindow win = (SilcClientWindow)sock->user_data;
      SilcClientInternalPacket *packet;
      int mac_len = 0;

      if (win->hmac)
	mac_len = win->hmac->hash->hash->hash_len;

      if (sock->inbuf->len - 2 > (paddedlen + mac_len)) {
	/* Received possibly many packets at once */

	while(sock->inbuf->len > 0) {
	  SILC_PACKET_LENGTH(sock->inbuf, packetlen, paddedlen);
	  if (sock->inbuf->len < paddedlen) {
	    SILC_LOG_DEBUG(("Received incorrect packet, dropped"));
	    return;
	  }

	  paddedlen += 2;
	  packet = silc_calloc(1, sizeof(*packet));
	  packet->client = client;
	  packet->sock = sock;
	  packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
	  packet->packetdata->buffer = silc_buffer_alloc(paddedlen + mac_len);
	  silc_buffer_pull_tail(packet->packetdata->buffer, 
				SILC_BUFFER_END(packet->packetdata->buffer));
	  silc_buffer_put(packet->packetdata->buffer, sock->inbuf->data, 
			  paddedlen + mac_len);

	  SILC_LOG_HEXDUMP(("Incoming packet, len %d", 
			    packet->packetdata->buffer->len),
			   packet->packetdata->buffer->data, 
			   packet->packetdata->buffer->len);
	  SILC_LOG_DEBUG(("Packet from server %s, "
			  "server type %d, packet length %d", 
			  win->remote_host, win->remote_type, paddedlen));

	  /* If this packet is for the current active connection we will
	     parse the packet right away to get it quickly on the screen.
	     Otherwise, it will be parsed with a timeout as the data is
	     for inactive window (which might not be visible at all). */
	  if (SILC_CLIENT_IS_CURRENT_WIN(client, win)) {
	    /* Parse it real soon */
	    silc_task_register(client->timeout_queue, fd, 
			       silc_client_packet_parse,
			       (void *)packet, 0, 1, 
			       SILC_TASK_TIMEOUT,
			       SILC_TASK_PRI_NORMAL);
	  } else {
	    /* Parse the packet with timeout */
	    silc_task_register(client->timeout_queue, fd, 
			       silc_client_packet_parse,
			       (void *)packet, 0, 200000, 
			       SILC_TASK_TIMEOUT,
			       SILC_TASK_PRI_NORMAL);
	  }

	  /* Pull the packet from inbuf thus we'll get the next one
	     in the inbuf. */
	  silc_buffer_pull(sock->inbuf, paddedlen);
	  if (win->hmac)
	    silc_buffer_pull(sock->inbuf, mac_len);
	}
	silc_buffer_clear(sock->inbuf);
	return;
      } else {
	/* Received one packet */
	
	SILC_LOG_HEXDUMP(("An incoming packet, len %d", sock->inbuf->len),
			 sock->inbuf->data, sock->inbuf->len);
	SILC_LOG_DEBUG(("Packet from server %s, "
			"server type %d, packet length %d", 
			win->remote_host, win->remote_type, paddedlen));
	
	packet = silc_calloc(1, sizeof(*packet));
	packet->client = client;
	packet->sock = sock;
	packet->packetdata = silc_calloc(1, sizeof(*packet->packetdata));
	packet->packetdata->buffer = silc_buffer_copy(sock->inbuf);
	silc_buffer_clear(sock->inbuf);

	/* If this packet is for the current active connection we will
	   parse the packet right away to get it quickly on the screen.
	   Otherwise, it will be parsed with a timeout as the data is
	   for inactive window (which might not be visible at all). */
	if (SILC_CLIENT_IS_CURRENT_WIN(client, win)) {
	  /* Parse it real soon */
	  silc_task_register(client->timeout_queue, fd, 
			     silc_client_packet_parse,
			     (void *)packet, 0, 1, 
			     SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
	  return;
	} else {
	  /* Parse the packet with timeout */
	  silc_task_register(client->timeout_queue, fd, 
			     silc_client_packet_parse,
			     (void *)packet, 0, 200000, 
			     SILC_TASK_TIMEOUT,
			     SILC_TASK_PRI_NORMAL);
	  return;
	}
      }
    }
  }
  
  SILC_LOG_ERROR(("Weird, nothing happened - ignoring"));
}

/* Checks MAC in the packet. Returns TRUE if MAC is Ok. This is called
   after packet has been totally decrypted and parsed. */

static int silc_client_packet_check_mac(SilcClient client,
					SilcSocketConnection sock,
					SilcBuffer buffer)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;

  /* Check MAC */
  if (win->hmac) {
    int headlen = buffer->data - buffer->head, mac_len;
    unsigned char *packet_mac, mac[32];
    
    SILC_LOG_DEBUG(("Verifying MAC"));

    mac_len = win->hmac->hash->hash->hash_len;

    silc_buffer_push(buffer, headlen);

    /* Take mac from packet */
    packet_mac = buffer->tail;
    
    /* Make MAC and compare */
    memset(mac, 0, sizeof(mac));
    silc_hmac_make_with_key(win->hmac, 
			    buffer->data, buffer->len,
			    win->hmac_key, win->hmac_key_len, mac);
#if 0
    SILC_LOG_HEXDUMP(("PMAC"), packet_mac, mac_len);
    SILC_LOG_HEXDUMP(("CMAC"), mac, mac_len);
#endif
    if (memcmp(mac, packet_mac, mac_len)) {
      SILC_LOG_DEBUG(("MAC failed"));
      return FALSE;
    }
    
    SILC_LOG_DEBUG(("MAC is Ok"));
    memset(mac, 0, sizeof(mac));

    silc_buffer_pull(buffer, headlen);
  }
  
  return TRUE;
}

/* Decrypts rest of the packet (after decrypting just the SILC header).
   After calling this function the packet is ready to be parsed by calling 
   silc_packet_parse. */

static int silc_client_packet_decrypt_rest(SilcClient client, 
					   SilcSocketConnection sock,
					   SilcBuffer buffer)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  unsigned int mac_len = 0;
  
  /* Decrypt */
  if (win && win->receive_key) {

    /* Pull MAC from packet before decryption */
    if (win->hmac) {
      mac_len = win->hmac->hash->hash->hash_len;
      if ((buffer->len - mac_len) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, mac_len);
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }

    SILC_LOG_DEBUG(("Decrypting rest of the packet"));

    /* Decrypt rest of the packet */
    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    silc_packet_decrypt(win->receive_key, buffer, buffer->len);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);

    SILC_LOG_HEXDUMP(("Fully decrypted packet, len %d", buffer->len),
		     buffer->data, buffer->len);
  }

  return TRUE;
}

/* Decrypts rest of the SILC Packet header that has been decrypted partly
   already. This decrypts the padding of the packet also.  After calling 
   this function the packet is ready to be parsed by calling function 
   silc_packet_parse. This is used in special packet reception. */

static int silc_client_packet_decrypt_rest_special(SilcClient client, 
						  SilcSocketConnection sock,
						  SilcBuffer buffer)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  unsigned int mac_len = 0;

  /* Decrypt rest of the header plus padding */
  if (win && win->receive_key) {
    unsigned short truelen, len1, len2, padlen;

    /* Pull MAC from packet before decryption */
    if (win->hmac) {
      mac_len = win->hmac->hash->hash->hash_len;
      if ((buffer->len - mac_len) > SILC_PACKET_MIN_LEN) {
	silc_buffer_push_tail(buffer, mac_len);
      } else {
	SILC_LOG_DEBUG(("Bad MAC length in packet, packet dropped"));
	return FALSE;
      }
    }
  
    SILC_LOG_DEBUG(("Decrypting rest of the header"));

    SILC_GET16_MSB(len1, &buffer->data[4]);
    SILC_GET16_MSB(len2, &buffer->data[6]);

    truelen = SILC_PACKET_HEADER_LEN + len1 + len2;
    padlen = SILC_PACKET_PADLEN(truelen);
    len1 = (truelen + padlen) - (SILC_PACKET_MIN_HEADER_LEN - 2);

    silc_buffer_pull(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    SILC_LOG_HEXDUMP(("XXX"), buffer->data, buffer->len);
    silc_packet_decrypt(win->receive_key, buffer, len1);
    silc_buffer_push(buffer, SILC_PACKET_MIN_HEADER_LEN - 2);
    SILC_LOG_HEXDUMP(("XXX"), buffer->data, buffer->len);
  }

  return TRUE;
}

/* Parses whole packet, received earlier. */

SILC_TASK_CALLBACK(silc_client_packet_parse)
{
  SilcClientInternalPacket *packet = (SilcClientInternalPacket *)context;
  SilcBuffer buffer = packet->packetdata->buffer;
  SilcClient client = packet->client;
  SilcSocketConnection sock = packet->sock;
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Decrypt start of the packet header */
  if (win && win->receive_key)
    silc_packet_decrypt(win->receive_key, buffer, SILC_PACKET_MIN_HEADER_LEN);

  /* If the packet type is not any special type lets decrypt rest
     of the packet here. */
  if (buffer->data[3] != SILC_PACKET_CHANNEL_MESSAGE &&
      buffer->data[3] != SILC_PACKET_PRIVATE_MESSAGE) {
  normal:
    /* Normal packet, decrypt rest of the packet */
    if (!silc_client_packet_decrypt_rest(client, sock, buffer))
      goto out;

    /* Parse the packet. Packet type is returned. */
    ret = silc_packet_parse(packet->packetdata);
    if (ret == SILC_PACKET_NONE)
      goto out;

    /* Check MAC */
    if (!silc_client_packet_check_mac(client, sock, buffer))
      goto out;
  } else {
    /* If private message key is not set for private message it is
       handled as normal packet. Go back up. */
    if (buffer->data[3] == SILC_PACKET_PRIVATE_MESSAGE &&
	!(buffer->data[2] & SILC_PACKET_FLAG_PRIVMSG_KEY))
      goto normal;

    /* Packet requires special handling, decrypt rest of the header.
       This only decrypts. This does not do any MAC checking, it must
       be done individually later when doing the special processing. */
    silc_client_packet_decrypt_rest_special(client, sock, buffer);

    /* Parse the packet header in special way as this is "special"
       packet type. */
    ret = silc_packet_parse_special(packet->packetdata);
    if (ret == SILC_PACKET_NONE)
      goto out;
  }

  /* Parse the incoming packet type */
  silc_client_packet_parse_type(client, sock, packet->packetdata);

 out:
  silc_buffer_clear(packet->packetdata->buffer);
  silc_free(packet->packetdata);
  silc_free(packet);
}

/* Parses the packet type and calls what ever routines the packet type
   requires. This is done for all incoming packets. */

void silc_client_packet_parse_type(SilcClient client, 
				   SilcSocketConnection sock,
				   SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcPacketType type = packet->type;

  SILC_LOG_DEBUG(("Parsing packet type %d", type));

  /* Parse the packet type */
  switch(type) {
  case SILC_PACKET_DISCONNECT:
    silc_client_disconnected_by_server(client, sock, buffer);
    break;
  case SILC_PACKET_SUCCESS:
    /*
     * Success received for something. For now we can have only
     * one protocol for connection executing at once hence this
     * success message is for whatever protocol is executing currently.
     */
    if (sock->protocol) {
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    }
    break;
  case SILC_PACKET_FAILURE:
    /*
     * Failure received for some protocol. Set the protocol state to 
     * error and call the protocol callback. This fill cause error on
     * protocol and it will call the final callback.
     */
    if (sock->protocol) {
      sock->protocol->state = SILC_PROTOCOL_STATE_ERROR;
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    }
    break;
  case SILC_PACKET_REJECT:
    break;

  case SILC_PACKET_NOTIFY:
    /*
     * Received notify message 
     */
    silc_client_notify_by_server(client, sock, buffer);
    break;

  case SILC_PACKET_ERROR:
    /*
     * Received error message
     */
    silc_client_error_by_server(client, sock, buffer);
    break;

  case SILC_PACKET_CHANNEL_MESSAGE:
    /*
     * Received message to (from, actually) a channel
     */
    silc_client_channel_message(client, sock, packet);
    break;
  case SILC_PACKET_CHANNEL_KEY:
    /*
     * Received key for a channel. By receiving this key the client will be
     * able to talk to the channel it has just joined. This can also be
     * a new key for existing channel as keys expire peridiocally.
     */
    silc_client_receive_channel_key(client, sock, buffer);
    break;

  case SILC_PACKET_PRIVATE_MESSAGE:
    /*
     * Received private message
     */
    {
      SilcClientCommandReplyContext ctx;
      ctx = silc_calloc(1, sizeof(*ctx));
      ctx->client = client;
      ctx->sock = sock;
      ctx->context = buffer;	/* kludge */
      silc_client_command_reply_msg((void *)ctx);
    }
    break;
  case SILC_PACKET_PRIVATE_MESSAGE_KEY:
    /*
     * Received private message key
     */
    break;

  case SILC_PACKET_COMMAND_REPLY:
    /*
     * Recived reply for a command
     */
    silc_client_command_reply_process(client, sock, packet);
    break;

  case SILC_PACKET_KEY_EXCHANGE:
    if (sock->protocol) {
      SilcClientKEInternalContext *proto_ctx = 
	(SilcClientKEInternalContext *)sock->protocol->context;

      proto_ctx->packet = buffer;
      proto_ctx->dest_id_type = packet->src_id_type;
      proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_type);

      /* Let the protocol handle the packet */
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange packet but no key exchange "
		      "protocol active, packet dropped."));

      /* XXX Trigger KE protocol?? Rekey actually! */
    }
    break;

  case SILC_PACKET_KEY_EXCHANGE_1:
    if (sock->protocol) {

    } else {
      SILC_LOG_ERROR(("Received Key Exchange 1 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;
  case SILC_PACKET_KEY_EXCHANGE_2:
    if (sock->protocol) {
      SilcClientKEInternalContext *proto_ctx = 
	(SilcClientKEInternalContext *)sock->protocol->context;

      if (proto_ctx->packet)
	silc_buffer_free(proto_ctx->packet);

      proto_ctx->packet = buffer;
      proto_ctx->dest_id_type = packet->src_id_type;
      proto_ctx->dest_id = silc_id_str2id(packet->src_id, packet->src_id_type);

      /* Let the protocol handle the packet */
      sock->protocol->execute(client->timeout_queue, 0,
			      sock->protocol, sock->sock, 0, 0);
    } else {
      SILC_LOG_ERROR(("Received Key Exchange 2 packet but no key exchange "
		      "protocol active, packet dropped."));
    }
    break;

  case SILC_PACKET_NEW_ID:
    {
      /*
       * Received new ID from server. This packet is received at
       * the connection to the server.  New ID is also received when 
       * user changes nickname but in that case the new ID is received
       * as command reply and not as this packet type.
       */
      unsigned char *id_string;
      unsigned short id_type;
      
      silc_buffer_unformat(buffer,
			   SILC_STR_UI_SHORT(&id_type),
			   SILC_STR_UI16_STRING_ALLOC(&id_string),
			   SILC_STR_END);
      
      if ((SilcIdType)id_type != SILC_ID_CLIENT)
	break;

      silc_client_receive_new_id(client, sock, id_string);
      silc_free(id_string);
      break;
    }

  default:
    SILC_LOG_DEBUG(("Incorrect packet type %d, packet dropped", type));
    break;
  }
}

/* Internal routine that sends packet or marks packet to be sent. This
   is used directly only in special cases. Normal cases should use
   silc_server_packet_send. Returns < 0 on error. */

static int silc_client_packet_send_real(SilcClient client,
					SilcSocketConnection sock,
					int force_send)
{
  /* Send now if forced to do so */
  if (force_send == TRUE) {
    int ret;
    SILC_LOG_DEBUG(("Forcing packet send, packet sent immediately"));
    ret = silc_packet_write(sock->sock, sock->outbuf);

    if (ret == -1)
      SILC_LOG_ERROR(("Packet dropped"));
    if (ret != -2)
      return ret;

    SILC_LOG_DEBUG(("Could not force the send, packet put to queue"));
  }  

  SILC_LOG_DEBUG(("Packet in queue"));

  /* Mark that there is some outgoing data available for this connection. 
     This call sets the connection both for input and output (the input
     is set always and this call keeps the input setting, actually). 
     Actual data sending is performed by silc_client_packet_process. */
  SILC_CLIENT_SET_CONNECTION_FOR_OUTPUT(sock->sock);

  /* Mark to socket that data is pending in outgoing buffer. This flag
     is needed if new data is added to the buffer before the earlier
     put data is sent to the network. */
  SILC_SET_OUTBUF_PENDING(sock);

  return 0;
}

/* Prepare outgoing data buffer for packet sending. */

static void silc_client_packet_send_prepare(SilcClient client,
					    SilcSocketConnection sock,
					    unsigned int header_len,
					    unsigned int padlen,
					    unsigned int data_len)
{
  int totlen, oldlen;

  totlen = header_len + padlen + data_len;

  /* Prepare the outgoing buffer for packet sending. */
  if (!sock->outbuf) {
    /* Allocate new buffer. This is done only once per connection. */
    SILC_LOG_DEBUG(("Allocating outgoing data buffer"));
    
    sock->outbuf = silc_buffer_alloc(SILC_PACKET_DEFAULT_SIZE);
    silc_buffer_pull_tail(sock->outbuf, totlen);
    silc_buffer_pull(sock->outbuf, header_len + padlen);
  } else {
    if (SILC_IS_OUTBUF_PENDING(sock)) {
      /* There is some pending data in the buffer. */

      if ((sock->outbuf->end - sock->outbuf->tail) < data_len) {
	SILC_LOG_DEBUG(("Reallocating outgoing data buffer"));
	/* XXX: not done yet */
      }
      oldlen = sock->outbuf->len;
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen + oldlen);
    } else {
      /* Buffer is free for use */
      silc_buffer_clear(sock->outbuf);
      silc_buffer_pull_tail(sock->outbuf, totlen);
      silc_buffer_pull(sock->outbuf, header_len + padlen);
    }
  }
}

/* Sends packet. This doesn't actually send the packet instead it assembles
   it and marks it to be sent. However, if force_send is TRUE the packet
   is sent immediately. if dst_id, cipher and hmac are NULL those parameters
   will be derived from sock argument. Otherwise the valid arguments sent
   are used. */

void silc_client_packet_send(SilcClient client, 
			     SilcSocketConnection sock,
			     SilcPacketType type, 
			     void *dst_id,
			     SilcIdType dst_id_type,
			     SilcCipher cipher,
			     SilcHmac hmac,
			     unsigned char *data, 
			     unsigned int data_len, 
			     int force_send)
{
  SilcPacketContext packetdata;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;

  SILC_LOG_DEBUG(("Sending packet, type %d", type));

  /* Get data used in the packet sending, keys and stuff */
  if ((!cipher || !hmac || !dst_id) && sock->user_data) {
    if (!cipher && ((SilcClientWindow)sock->user_data)->send_key)
      cipher = ((SilcClientWindow)sock->user_data)->send_key;
    if (!hmac && ((SilcClientWindow)sock->user_data)->hmac) {
      hmac = ((SilcClientWindow)sock->user_data)->hmac;
      mac_len = hmac->hash->hash->hash_len;
      hmac_key = ((SilcClientWindow)sock->user_data)->hmac_key;
      hmac_key_len = ((SilcClientWindow)sock->user_data)->hmac_key_len;
    }
    if (!dst_id && ((SilcClientWindow)sock->user_data)->remote_id) {
      dst_id = ((SilcClientWindow)sock->user_data)->remote_id;
      dst_id_type = SILC_ID_SERVER;
    }
  }

  /* Set the packet context pointers */
  packetdata.flags = 0;
  packetdata.type = type;
  if (((SilcClientWindow)sock->user_data)->local_id_data)
    packetdata.src_id = ((SilcClientWindow)sock->user_data)->local_id_data;
  else 
    packetdata.src_id = silc_calloc(SILC_ID_CLIENT_LEN, sizeof(unsigned char));
  packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  packetdata.src_id_type = SILC_ID_CLIENT;
  if (dst_id) {
    packetdata.dst_id = silc_id_id2str(dst_id, dst_id_type);
    packetdata.dst_id_len = silc_id_get_len(dst_id_type);
    packetdata.dst_id_type = dst_id_type;
  } else {
    packetdata.dst_id = NULL;
    packetdata.dst_id_len = 0;
    packetdata.dst_id_type = SILC_ID_NONE;
  }
  packetdata.rng = client->rng;
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN(packetdata.truelen);

  /* Prepare outgoing data buffer for packet sending */
  silc_client_packet_send_prepare(client, sock, 
				  SILC_PACKET_HEADER_LEN +
				  packetdata.src_id_len + 
				  packetdata.dst_id_len,
				  packetdata.padlen,
				  data_len);

  SILC_LOG_DEBUG(("Putting data to outgoing buffer, len %d", data_len));

  packetdata.buffer = sock->outbuf;

  /* Put the data to the buffer */
  if (data && data_len)
    silc_buffer_put(sock->outbuf, data, data_len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  /* Compute MAC of the packet */
  if (hmac) {
    silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			    hmac_key, hmac_key_len, mac);
    silc_buffer_put_tail(sock->outbuf, mac, mac_len);
    memset(mac, 0, sizeof(mac));
  }

  /* Encrypt the packet */
  if (cipher)
    silc_packet_encrypt(cipher, sock->outbuf, sock->outbuf->len);

  /* Pull MAC into the visible data area */
  if (hmac)
    silc_buffer_pull_tail(sock->outbuf, mac_len);

  SILC_LOG_HEXDUMP(("Packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);
}

/* Sends packet to a channel. Packet to channel is always encrypted
   differently from "normal" packets. SILC header of the packet is 
   encrypted with the next receiver's key and the rest of the packet is
   encrypted with the channel specific key. Padding and HMAC is computed
   with the next receiver's key. */

void silc_client_packet_send_to_channel(SilcClient client, 
					SilcSocketConnection sock,
					SilcChannelEntry channel,
					unsigned char *data, 
					unsigned int data_len, 
					int force_send)
{
  int i;
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  SilcBuffer payload;
  SilcPacketContext packetdata;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;
  unsigned char *id_string;
  SilcCipher cipher;
  SilcHmac hmac;

  SILC_LOG_DEBUG(("Sending packet to channel"));

  if (!channel || !channel->key) {
    silc_say(client, "Cannot talk to channel: key does not exist");
    return;
  }

  /* Generate IV */
  if (!channel->iv)
    for (i = 0; i < 16; i++)
      channel->iv[i] = silc_rng_get_byte(client->rng);
  else
    silc_hash_make(client->md5hash, channel->iv, 16, channel->iv);

  /* Encode the channel payload */
  payload = silc_channel_encode_payload(strlen(win->nickname), win->nickname,
					data_len, data, 16, channel->iv, 
					client->rng);
  if (!payload) {
    silc_say(client, 
	     "Error: Could not create packet to be sent to the channel");
    return;
  }

  /* Get data used in packet header encryption, keys and stuff. Rest
     of the packet (the payload) is, however, encrypted with the 
     specified channel key. */
  cipher = win->send_key;
  hmac = win->hmac;
  mac_len = hmac->hash->hash->hash_len;
  hmac_key = win->hmac_key;
  hmac_key_len = win->hmac_key_len;
  id_string = silc_id_id2str(channel->id, SILC_ID_CHANNEL);

  /* Set the packet context pointers. The destination ID is always
     the Channel ID of the channel. Server and router will handle the
     distribution of the packet. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_CHANNEL_MESSAGE;
  packetdata.src_id = win->local_id_data;
  packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  packetdata.src_id_type = SILC_ID_CLIENT;
  packetdata.dst_id = id_string;
  packetdata.dst_id_len = SILC_ID_CHANNEL_LEN;
  packetdata.dst_id_type = SILC_ID_CHANNEL;
  packetdata.rng = client->rng;
  packetdata.truelen = payload->len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* Prepare outgoing data buffer for packet sending */
  silc_client_packet_send_prepare(client, sock, 
				  SILC_PACKET_HEADER_LEN +
				  packetdata.src_id_len + 
				  packetdata.dst_id_len,
				  packetdata.padlen,
				  payload->len);

  packetdata.buffer = sock->outbuf;

  /* Encrypt payload of the packet. This is encrypted with the channel key. */
  channel->channel_key->cipher->encrypt(channel->channel_key->context,
					payload->data, payload->data,
					payload->len - 16, /* -IV_LEN */
					channel->iv);

  SILC_LOG_HEXDUMP(("XXX"), payload->data, payload->len);
      
  /* Put the actual encrypted payload data into the buffer. */
  silc_buffer_put(sock->outbuf, payload->data, payload->len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  /* Compute MAC of the packet */
  silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			  hmac_key, hmac_key_len, mac);
  silc_buffer_put_tail(sock->outbuf, mac, mac_len);
  memset(mac, 0, sizeof(mac));

      SILC_LOG_HEXDUMP(("XXX"), sock->outbuf->data, sock->outbuf->len);
      
  /* Encrypt the header and padding of the packet. This is encrypted 
     with normal session key shared with our server. */
  silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
		      packetdata.src_id_len + packetdata.dst_id_len +
		      packetdata.padlen);

  /* Pull MAC into the visible data area */
  silc_buffer_pull_tail(sock->outbuf, mac_len);

  SILC_LOG_HEXDUMP(("Packet to channel, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);
  silc_buffer_free(payload);
  silc_free(id_string);
}

/* Sends private message to remote client. If private message key has
   not been set with this client then the message will be encrypted using
   normal session keys. Private messages are special packets in SILC
   network hence we need this own function for them. This is similiar
   to silc_client_packet_send_to_channel except that we send private
   message. */

void silc_client_packet_send_private_message(SilcClient client,
					     SilcSocketConnection sock,
					     SilcClientEntry client_entry,
					     unsigned char *data, 
					     unsigned int data_len, 
					     int force_send)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  SilcBuffer buffer;
  SilcPacketContext packetdata;
  unsigned char *hmac_key = NULL;
  unsigned int hmac_key_len = 0;
  unsigned char mac[32];
  unsigned int mac_len = 0;
  unsigned int nick_len;
  SilcCipher cipher;
  SilcHmac hmac;

  SILC_LOG_DEBUG(("Sending private message"));

  /* Create private message payload */
  nick_len = strlen(client->current_win->nickname);
  buffer = silc_buffer_alloc(2 + nick_len + data_len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(nick_len),
		     SILC_STR_UI_XNSTRING(client->current_win->nickname,
					  nick_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_END);

  /* If we don't have private message specific key then private messages
     are just as any normal packet thus call normal packet sending.  If
     the key exist then the encryption process is a bit different and
     will be done in the rest of this function. */
  if (!client_entry->send_key) {
    silc_client_packet_send(client, sock, SILC_PACKET_PRIVATE_MESSAGE,
			    client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			    buffer->data, buffer->len, force_send);
    goto out;
  }

  /* We have private message specific key */

  /* Get data used in the encryption */
  cipher = client_entry->send_key;
  hmac = win->hmac;
  mac_len = hmac->hash->hash->hash_len;
  hmac_key = win->hmac_key;
  hmac_key_len = win->hmac_key_len;

  /* Set the packet context pointers. */
  packetdata.flags = 0;
  packetdata.type = SILC_PACKET_PRIVATE_MESSAGE;
  packetdata.src_id = win->local_id_data;
  packetdata.src_id_len = SILC_ID_CLIENT_LEN;
  packetdata.src_id_type = SILC_ID_CLIENT;
  if (client_entry)
    packetdata.dst_id = silc_id_id2str(client_entry->id, SILC_ID_CLIENT);
  else
    packetdata.dst_id = win->local_id_data;
  packetdata.dst_id_len = SILC_ID_CLIENT_LEN;
  packetdata.dst_id_type = SILC_ID_CLIENT;
  packetdata.rng = client->rng;
  packetdata.truelen = buffer->len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* Prepare outgoing data buffer for packet sending */
  silc_client_packet_send_prepare(client, sock, 
				  SILC_PACKET_HEADER_LEN +
				  packetdata.src_id_len + 
				  packetdata.dst_id_len,
				  packetdata.padlen,
				  buffer->len);

  packetdata.buffer = sock->outbuf;

  /* Encrypt payload of the packet. Encrypt with private message specific
     key if it exist, otherwise with session key. */
  cipher->cipher->encrypt(cipher->context, buffer->data, buffer->data,
			  buffer->len, cipher->iv);
      
  /* Put the actual encrypted payload data into the buffer. */
  silc_buffer_put(sock->outbuf, buffer->data, buffer->len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  /* Compute MAC of the packet */
  silc_hmac_make_with_key(hmac, sock->outbuf->data, sock->outbuf->len,
			  hmac_key, hmac_key_len, mac);
  silc_buffer_put_tail(sock->outbuf, mac, mac_len);
  memset(mac, 0, sizeof(mac));

  SILC_LOG_HEXDUMP(("XXX"), sock->outbuf->data, sock->outbuf->len);
      
  /* Encrypt the header and padding of the packet. */
  silc_packet_encrypt(cipher, sock->outbuf, SILC_PACKET_HEADER_LEN + 
		      packetdata.src_id_len + packetdata.dst_id_len +
		      packetdata.padlen);

  /* Pull MAC into the visible data area */
  silc_buffer_pull_tail(sock->outbuf, mac_len);

  SILC_LOG_HEXDUMP(("Private message packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);
  silc_free(packetdata.dst_id);

 out:
  silc_free(buffer);
}     

/* Closes connection to remote end. Free's all allocated data except
   for some information such as nickname etc. that are valid at all time. */

void silc_client_close_connection(SilcClient client,
				  SilcSocketConnection sock)
{
  SilcClientWindow win;
  int i;

  /* We won't listen for this connection anymore */
  silc_schedule_unset_listen_fd(sock->sock);

  /* Unregister all tasks */
  silc_task_unregister_by_fd(client->io_queue, sock->sock);
  silc_task_unregister_by_fd(client->timeout_queue, sock->sock);

  /* Close the actual connection */
  silc_net_close_connection(sock->sock);

  silc_say(client, "Closed connection to host %s", sock->hostname ?
	   sock->hostname : sock->ip);

  /* Free everything */
  if (sock->user_data) {
    win = (SilcClientWindow)sock->user_data;

    /* XXX Free all client entries and channel entries. */

    /* Clear ID caches */
    for (i = 0; i < 96; i++)
      silc_idcache_del_all(&win->client_id_cache[i], 
			   win->client_id_cache_count[i]);
    for (i = 0; i < 96; i++)
      silc_idcache_del_all(&win->channel_id_cache[i], 
			   win->channel_id_cache_count[i]);

    /* Free data */
    if (win->remote_host)
      silc_free(win->remote_host);
    if (win->local_id)
      silc_free(win->local_id);
    if (win->local_id_data)
      silc_free(win->local_id_data);
    if (win->send_key)
      silc_cipher_free(win->send_key);
    if (win->receive_key)
      silc_cipher_free(win->receive_key);
    if (win->hmac)
      silc_hmac_free(win->hmac);
    if (win->hmac_key) {
      memset(win->hmac_key, 0, win->hmac_key_len);
      silc_free(win->hmac_key);
    }

    win->sock = NULL;
    win->remote_port = 0;
    win->remote_type = 0;
    win->send_key = NULL;
    win->receive_key = NULL;
    win->hmac = NULL;
    win->hmac_key = NULL;
    win->hmac_key_len = 0;
    win->local_id = NULL;
    win->local_id_data = NULL;
    win->remote_host = NULL;
    win->current_channel = NULL;
  }

  if (sock->protocol) {
    silc_protocol_free(sock->protocol);
    sock->protocol = NULL;
  }
  silc_socket_free(sock);
}

/* Called when we receive disconnection packet from server. This 
   closes our end properly and displays the reason of the disconnection
   on the screen. */

void silc_client_disconnected_by_server(SilcClient client,
					SilcSocketConnection sock,
					SilcBuffer message)
{
  char *msg;

  SILC_LOG_DEBUG(("Server disconnected us, sock %d", sock->sock));

  msg = silc_calloc(message->len + 1, sizeof(char));
  memcpy(msg, message->data, message->len);
  silc_say(client, msg);
  silc_free(msg);

  SILC_SET_DISCONNECTED(sock);
  silc_client_close_connection(client, sock);
}

/* Received error message from server. Display it on the screen. 
   We don't take any action what so ever of the error message. */

void silc_client_error_by_server(SilcClient client,
				 SilcSocketConnection sock,
				 SilcBuffer message)
{
  char *msg;

  msg = silc_calloc(message->len + 1, sizeof(char));
  memcpy(msg, message->data, message->len);
  silc_say(client, msg);
  silc_free(msg);
}

/* Received notify message from server */

void silc_client_notify_by_server(SilcClient client,
				  SilcSocketConnection sock,
				  SilcBuffer message)
{
  char *msg;

  msg = silc_calloc(message->len + 1, sizeof(char));
  memcpy(msg, message->data, message->len);
  silc_say(client, msg);
  silc_free(msg);
}

/* Processes the received new Client ID from server. Old Client ID is
   deleted from cache and new one is added. */

void silc_client_receive_new_id(SilcClient client,
				SilcSocketConnection sock,
				unsigned char *id_string)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  char *nickname = win->nickname;

#define CIDC(x) win->client_id_cache[(x) - 32]
#define CIDCC(x) win->client_id_cache_count[(x) - 32]

  /* Delete old ID from ID cache */
  silc_idcache_del_by_id(CIDC(nickname[0]), CIDCC(nickname[0]),
			 SILC_ID_CLIENT, win->local_id);
  
  /* Save the new ID */
  if (win->local_id)
    silc_free(win->local_id);
  win->local_id = silc_id_str2id(id_string, SILC_ID_CLIENT);
  if (win->local_id_data)
    silc_free(win->local_id_data);
  win->local_id_data = 
    silc_calloc(SILC_ID_CLIENT_LEN, sizeof(unsigned char));
  memcpy(win->local_id_data, id_string, SILC_ID_CLIENT_LEN);
  win->local_id_data_len = SILC_ID_CLIENT_LEN;
  if (!win->local_entry)
    win->local_entry = silc_calloc(1, sizeof(*win->local_entry));
  win->local_entry->nickname = win->nickname;
  win->local_entry->id = win->local_id;
  
  /* Put it to the ID cache */
  CIDCC(nickname[0]) = silc_idcache_add(&CIDC(nickname[0]), 
					CIDCC(nickname[0]),
					win->nickname, SILC_ID_CLIENT, 
					win->local_id, 
					(void *)win->local_entry);
#undef CIDC
#undef CIDCC
}

/* Processed received Channel ID for a channel. This is called when client
   joins to channel and server replies with channel ID. The ID is cached. */

void silc_client_new_channel_id(SilcClient client,
				SilcSocketConnection sock,
				char *channel_name,
				unsigned int mode,
				unsigned char *id_string)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  SilcChannelID *id;
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("New channel ID"));

#define CIDC(x) win->channel_id_cache[(x) - 32]
#define CIDCC(x) win->channel_id_cache_count[(x) - 32]

  id = silc_id_str2id(id_string, SILC_ID_CHANNEL);
  channel = silc_calloc(1, sizeof(*channel));
  channel->channel_name = channel_name;
  channel->id = id;
  channel->mode = mode;
  win->current_channel = channel;
  
  /* Put it to the ID cache */
  CIDCC(channel_name[0]) = silc_idcache_add(&CIDC(channel_name[0]), 
					    CIDCC(channel_name[0]),
					    channel_name, SILC_ID_CHANNEL, 
					    id, (void *)channel);
#undef CIDC
#undef CIDCC
}

/* Processes received key for channel. The received key will be used
   to protect the traffic on the channel for now on. Client must receive
   the key to the channel before talking on the channel is possible. 
   This is the key that server has generated, this is not the channel
   private key, it is entirely local setting. */

void silc_client_receive_channel_key(SilcClient client,
				     SilcSocketConnection sock,
				     SilcBuffer packet)
{
  int i;
  unsigned char *id_string, *key, *cipher;
  unsigned int key_len;
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  SilcChannelID *id;
  SilcIDCache *id_cache = NULL;
  SilcChannelEntry channel;
  SilcChannelKeyPayload payload;

  SILC_LOG_DEBUG(("Received key for channel"));
  
#define CIDC(x) win->channel_id_cache[(x)]
#define CIDCC(x) win->channel_id_cache_count[(x)]

  payload = silc_channel_key_parse_payload(packet);
  if (!payload)
    return;

  id_string = silc_channel_key_get_id(payload, NULL);
  if (!id_string) {
    silc_channel_key_free_payload(payload);
    return;
  }
  id = silc_id_str2id(id_string, SILC_ID_CHANNEL);

  /* Find channel. XXX: This is bad and slow. */ 
  for (i = 0; i < 96; i++) {
    if (CIDC(i) == NULL)
      continue;
    if (silc_idcache_find_by_id(CIDC(i), CIDCC(i), (void *)id, 
				SILC_ID_CHANNEL, &id_cache))
      break;
  }

 if (!id_cache)
    goto out;

  /* Save the key */
  key = silc_channel_key_get_key(payload, &key_len);
  cipher = silc_channel_key_get_cipher(payload, NULL);

  channel = (SilcChannelEntry)id_cache->context;
  channel->key_len = key_len;
  channel->key = silc_calloc(key_len, sizeof(*channel->key));
  memcpy(channel->key, key, key_len);

  silc_cipher_alloc(cipher, &channel->channel_key);
  if (!channel->channel_key) {
    silc_say(client, "Cannot talk to channel: unsupported cipher %s", cipher);
    goto out;
  }
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					key, key_len);

  /* Client is now joined to the channel */
  channel->on_channel = TRUE;

 out:
  silc_free(id);
  silc_channel_key_free_payload(payload);
#undef CIDC
#undef CIDCC
}

/* Process received message to a channel (or from a channel, really). This
   decrypts the channel message with channel specific key and parses the
   channel payload. Finally it displays the message on the screen. */

void silc_client_channel_message(SilcClient client, 
				 SilcSocketConnection sock, 
				 SilcPacketContext *packet)
{
  int i;
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  SilcBuffer buffer = packet->buffer;
  SilcChannelPayload payload = NULL;
  SilcChannelID *id = NULL;
  SilcChannelEntry channel;
  SilcIDCache *id_cache = NULL;

#define CIDC(x) win->channel_id_cache[(x)]
#define CIDCC(x) win->channel_id_cache_count[(x)]

  /* Sanity checks */
  if (packet->dst_id_type != SILC_ID_CHANNEL)
    goto out;

  id = silc_id_str2id(packet->dst_id, SILC_ID_CHANNEL);

  /* Find the channel entry from channels on this window */
  for (i = 0; i < 96; i++) {
    if (CIDC(i) == NULL)
      continue;
    if (silc_idcache_find_by_id(CIDC(i), CIDCC(i), (void *)id, 
				SILC_ID_CHANNEL, &id_cache))
      break;
  }

  if (!id_cache)
    goto out;

  channel = (SilcChannelEntry)id_cache->context;

  /* Decrypt the channel message payload. Push the IV out of the way,
     since it is not encrypted (after pushing buffer->tail has the IV). */
  silc_buffer_push_tail(buffer, 16);
  channel->channel_key->cipher->decrypt(channel->channel_key->context,
					buffer->data, buffer->data,
					buffer->len, buffer->tail);
  silc_buffer_pull_tail(buffer, 16);

  /* Parse the channel message payload */
  payload = silc_channel_parse_payload(buffer);
  if (!payload)
    goto out;

  /* Display the message on screen */
  if (packet->src_id_type == SILC_ID_CLIENT) {
    /* Message from client */
    if (channel == win->current_channel)
      silc_print(client, "<%s> %s", 
		 silc_channel_get_nickname(payload, NULL),
		 silc_channel_get_data(payload, NULL));
    else
      silc_print(client, "<%s:%s> %s", 
		 silc_channel_get_nickname(payload, NULL),
		 channel->channel_name,
		 silc_channel_get_data(payload, NULL));
  } else {
    /* Message from server */
    silc_say(client, "%s", silc_channel_get_data(payload, NULL));
  }

 out:
  if (id)
    silc_free(id);
  if (payload)
    silc_channel_free_payload(payload);
#undef CIDC
#undef CIDCC
}
