/*

  client_ops.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "clientincludes.h"

/* Prints a message with three star (*) sign before the actual message
   on the current output window. This is used to print command outputs
   and error messages. */

void silc_say(SilcClient client, SilcClientConnection conn, 
	      char *msg, ...)
{
  va_list vp;
  char message[2048];
  SilcClientInternal app = (SilcClientInternal)client->application;

  memset(message, 0, sizeof(message));
  strncat(message, "\n***  ", 5);

  va_start(vp, msg);
  vsprintf(message + 5, msg, vp);
  va_end(vp);
  
  /* Print the message */
  silc_print_to_window(app->screen->output_win[0], message);
}

/* Message for a channel. The `sender' is the nickname of the sender 
   received in the packet. The `channel_name' is the name of the channel. */

void silc_channel_message(SilcClient client, SilcClientConnection conn,
			  char *sender, char *channel_name, char *msg)
{
  /* Message from client */
  if (!strcmp(conn->current_channel->channel_name, channel_name))
    silc_print(client, "<%s> %s", sender, msg);
  else
    silc_print(client, "<%s:%s> %s", sender, channel_name, msg);
}

/* Private message to the client. The `sender' is the nickname of the
   sender received in the packet. */

void silc_private_message(SilcClient client, SilcClientConnection conn,
			  char *sender, char *msg)
{
  silc_print(client, "*%s* %s", sender, msg);
}


/* Notify message to the client.  The `type' is the notify type received
   from server.  The `msg' is a human readable message sent by the server. */

void silc_notify(SilcClient client, SilcClientConnection conn, 
		 SilcNotifyType type, char *msg)
{
  silc_print(client, "*** %s", msg);
}

/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occured
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

void silc_command(SilcClient client, SilcClientConnection conn, 
		  SilcClientCommandContext cmd_context, int success,
		  SilcCommand command)
{
  SilcClientInternal app = (SilcClientInternal)client->application;

  if (!success)
    return;

  switch(command)
    {
    case SILC_COMMAND_QUIT:
      app->screen->bottom_line->channel = NULL;
      silc_screen_print_bottom_line(app->screen, 0);
      break;

    case SILC_COMMAND_LEAVE:
#if 0
      if (!strncmp(conn->current_channel->channel_name, name, strlen(name))) {
	app->screen->bottom_line->channel = NULL;
	silc_screen_print_bottom_line(app->screen, 0);
      }
#endif
      break;

    }
}

/* Command reply handler. This function is called always in the command reply
   function. If error occurs it will be called as well. Normal scenario
   is that it will be called after the received command data has been parsed
   and processed. The function is used to pass the received command data to
   the application. 

   `conn' is the associated client connection. `cmd_payload' is the command
   payload data received from server and it can be ignored. It is provided
   if the application would like to re-parse the received command data,
   however, it must be noted that the data is parsed already by the library
   thus the payload can be ignored. `success' is FALSE if error occured.
   In this case arguments are not sent to the application. `command' is the
   command reply being processed. The function has variable argument list
   and each command defines the number and type of arguments it passes to the
   application (on error they are not sent). */

void silc_command_reply(SilcClient client, SilcClientConnection conn,
			SilcCommandPayload cmd_payload, int success,
			SilcCommandStatus status, SilcCommand command, ...)
{
  SilcClientInternal app = (SilcClientInternal)client->application;
  va_list vp;

  if (!success)
    return;

  va_start(vp, command);

  switch(command)
    {

    case SILC_COMMAND_JOIN:
      app->screen->bottom_line->channel = va_arg(vp, char *);
      silc_screen_print_bottom_line(app->screen, 0);
      break;

    case SILC_COMMAND_NICK:
      app->screen->bottom_line->nickname = va_arg(vp, char *);
      silc_screen_print_bottom_line(app->screen, 0);
      break;

    }
}

/* Called to indicate that connection was either successfully established
   or connecting failed.  This is also the first time application receives
   the SilcClientConnection objecet which it should save somewhere. */

void silc_connect(SilcClient client, SilcClientConnection conn, int success)
{
  SilcClientInternal app = (SilcClientInternal)client->application;

  if (success) {
    app->screen->bottom_line->connection = conn->remote_host;
    silc_screen_print_bottom_line(app->screen, 0);
    app->conn = conn;
  }
}

/* Called to indicate that connection was disconnected to the server. */

void silc_disconnect(SilcClient client, SilcClientConnection conn)
{
  SilcClientInternal app = (SilcClientInternal)client->application;

  app->screen->bottom_line->connection = NULL;
  silc_screen_print_bottom_line(app->screen, 0);
}

/* Asks passphrase from user on the input line. */

unsigned char *silc_ask_passphrase(SilcClient client, 
				   SilcClientConnection conn)
{
  SilcClientInternal app = (SilcClientInternal)conn->client->application;
  char pass1[256], pass2[256];
  char *ret;
  int try = 3;

  while(try) {

    /* Print prompt */
    wattroff(app->screen->input_win, A_INVIS);
    silc_screen_input_print_prompt(app->screen, "Passphrase: ");
    wattron(app->screen->input_win, A_INVIS);
    
    /* Get string */
    memset(pass1, 0, sizeof(pass1));
    wgetnstr(app->screen->input_win, pass1, sizeof(pass1));
    
    /* Print retype prompt */
    wattroff(app->screen->input_win, A_INVIS);
    silc_screen_input_print_prompt(app->screen, "Retype passphrase: ");
    wattron(app->screen->input_win, A_INVIS);
    
    /* Get string */
    memset(pass2, 0, sizeof(pass2));
    wgetnstr(app->screen->input_win, pass2, sizeof(pass2));

    if (!strncmp(pass1, pass2, strlen(pass2)))
      break;

    try--;
  }

  ret = silc_calloc(strlen(pass1), sizeof(char));
  memcpy(ret, pass1, strlen(pass1));

  memset(pass1, 0, sizeof(pass1));
  memset(pass2, 0, sizeof(pass2));

  wattroff(app->screen->input_win, A_INVIS);
  silc_screen_input_reset(app->screen);

  return ret;
}

/* Verifies received public key. If user decides to trust the key it is
   saved as trusted server key for later use. If user does not trust the
   key this returns FALSE. */

int silc_verify_server_key(SilcClient client,
			   SilcClientConnection conn, 
			   unsigned char *pk, unsigned int pk_len,
			   SilcSKEPKType pk_type)
{
  SilcSocketConnection sock = conn->sock;
  char filename[256];
  char file[256];
  char *hostname, *fingerprint;
  struct passwd *pw;
  struct stat st;

  hostname = sock->hostname ? sock->hostname : sock->ip;

  if (pk_type != SILC_SKE_PK_TYPE_SILC) {
    silc_say(client, conn, "We don't support server %s key type", hostname);
    return FALSE;
  }

  pw = getpwuid(getuid());
  if (!pw)
    return FALSE;

  memset(filename, 0, sizeof(filename));
  memset(file, 0, sizeof(file));
  snprintf(file, sizeof(file) - 1, "serverkey_%s_%d.pub", hostname,
	   sock->port);
  snprintf(filename, sizeof(filename) - 1, "%s/.silc/serverkeys/%s", 
	   pw->pw_dir, file);

  /* Check wheter this key already exists */
  if (stat(filename, &st) < 0) {

    fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
    silc_say(client, conn, "Received server %s public key", hostname);
    silc_say(client, conn, "Fingerprint for the server %s key is", hostname);
    silc_say(client, conn, "%s", fingerprint);
    silc_free(fingerprint);

    /* Ask user to verify the key and save it */
    if (silc_client_ask_yes_no(client, 
       "Would you like to accept the key (y/n)? "))
      {
	/* Save the key for future checking */
	silc_pkcs_save_public_key_data(filename, pk, pk_len, 
				       SILC_PKCS_FILE_PEM);
	return TRUE;
      }
  } else {
    /* The key already exists, verify it. */
    SilcPublicKey public_key;
    unsigned char *encpk;
    unsigned int encpk_len;

    /* Load the key file */
    if (!silc_pkcs_load_public_key(filename, &public_key, 
				   SILC_PKCS_FILE_PEM))
      if (!silc_pkcs_load_public_key(filename, &public_key, 
				     SILC_PKCS_FILE_BIN)) {
	fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
	silc_say(client, conn, "Received server %s public key", hostname);
	silc_say(client, conn, "Fingerprint for the server %s key is", hostname);
	silc_say(client, conn, "%s", fingerprint);
	silc_free(fingerprint);
	silc_say(client, conn, "Could not load your local copy of the server %s key",
		 hostname);
	if (silc_client_ask_yes_no(client, 
	   "Would you like to accept the key anyway (y/n)? "))
	  {
	    /* Save the key for future checking */
	    unlink(filename);
	    silc_pkcs_save_public_key_data(filename, pk, pk_len,
					   SILC_PKCS_FILE_PEM);
	    return TRUE;
	  }
	
	return FALSE;
      }
  
    /* Encode the key data */
    encpk = silc_pkcs_public_key_encode(public_key, &encpk_len);
    if (!encpk) {
      fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
      silc_say(client, conn, "Received server %s public key", hostname);
      silc_say(client, conn, "Fingerprint for the server %s key is", hostname);
      silc_say(client, conn, "%s", fingerprint);
      silc_free(fingerprint);
      silc_say(client, conn, "Your local copy of the server %s key is malformed",
	       hostname);
      if (silc_client_ask_yes_no(client, 
         "Would you like to accept the key anyway (y/n)? "))
	{
	  /* Save the key for future checking */
	  unlink(filename);
	  silc_pkcs_save_public_key_data(filename, pk, pk_len,
					 SILC_PKCS_FILE_PEM);
	  return TRUE;
	}

      return FALSE;
    }

    if (memcmp(encpk, pk, encpk_len)) {
      fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
      silc_say(client, conn, "Received server %s public key", hostname);
      silc_say(client, conn, "Fingerprint for the server %s key is", hostname);
      silc_say(client, conn, "%s", fingerprint);
      silc_free(fingerprint);
      silc_say(client, conn, "Server %s key does not match with your local copy",
	       hostname);
      silc_say(client, conn, "It is possible that the key has expired or changed");
      silc_say(client, conn, "It is also possible that some one is performing "
	               "man-in-the-middle attack");
      
      /* Ask user to verify the key and save it */
      if (silc_client_ask_yes_no(client, 
         "Would you like to accept the key anyway (y/n)? "))
	{
	  /* Save the key for future checking */
	  unlink(filename);
	  silc_pkcs_save_public_key_data(filename, pk, pk_len,
					 SILC_PKCS_FILE_PEM);
	  return TRUE;
	}

      silc_say(client, conn, "Will not accept server %s key", hostname);
      return FALSE;
    }

    /* Local copy matched */
    return TRUE;
  }

  silc_say(client, conn, "Will not accept server %s key", hostname);
  return FALSE;
}

/* Find authentication method and authentication data by hostname and
   port. The hostname may be IP address as well. The found authentication
   method and authentication data is returned to `auth_meth', `auth_data'
   and `auth_data_len'. The function returns TRUE if authentication method
   is found and FALSE if not. `conn' may be NULL. */

int silc_get_auth_method(SilcClient client, SilcClientConnection conn,
			 char *hostname, unsigned short port,
			 SilcProtocolAuthMeth *auth_meth,
			 unsigned char **auth_data,
			 unsigned int *auth_data_len)
{
  SilcClientInternal app = (SilcClientInternal)client->application;

  if (app->config->conns) {
    SilcClientConfigSectionConnection *conn = NULL;

    /* Check if we find a match from user configured connections */
    conn = silc_client_config_find_connection(app->config,
					      hostname,
					      port);
    if (conn) {
      /* Match found. Use the configured authentication method */
      *auth_meth = conn->auth_meth;

      if (conn->auth_data) {
	*auth_data = strdup(conn->auth_data);
	*auth_data_len = strlen(conn->auth_data);
      }

      return TRUE;
    }
  }

  return FALSE;
}

/* SILC client operations */
SilcClientOperations ops = {
  say:                  silc_say,
  channel_message:      silc_channel_message,
  private_message:      silc_private_message,
  notify:               silc_notify,
  command:              silc_command,
  command_reply:        silc_command_reply,
  connect:              silc_connect,
  disconnect:           silc_disconnect,
  get_auth_method:      silc_get_auth_method,
  verify_server_key:    silc_verify_server_key,
  ask_passphrase:       silc_ask_passphrase,
};
