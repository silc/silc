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
			  SilcClientEntry sender, SilcChannelEntry channel
			  , char *msg)
{
  /* Message from client */
  if (conn && !strcmp(conn->current_channel->channel_name, 
		      channel->channel_name))
    silc_print(client, "<%s> %s", sender ? sender->nickname : "[<unknown>]", 
	       msg);
  else
    silc_print(client, "<%s:%s> %s", sender ? sender->nickname : "[<unknown>]",
	       channel->channel_name, msg);
}

/* Private message to the client. The `sender' is the nickname of the
   sender received in the packet. */

void silc_private_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, char *msg)
{
  silc_print(client, "*%s* %s", sender->nickname, msg);
}


/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it). */

void silc_notify(SilcClient client, SilcClientConnection conn, 
		 SilcNotifyType type, ...)
{
  SilcClientInternal app = (SilcClientInternal)client->application;
  va_list vp;
  char message[4096];
  SilcClientEntry client_entry, client_entry2;
  SilcChannelEntry channel_entry;
  char *tmp = NULL;
  unsigned int tmp_int;

  va_start(vp, type);

  memset(message, 0, sizeof(message));

  /* Get arguments (defined by protocol in silc-pp-01 -draft) */
  switch(type) {
  case SILC_NOTIFY_TYPE_NONE:
    tmp = va_arg(vp, char *);
    if (!tmp)
      return;
    strcpy(message, tmp);
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    client_entry = va_arg(vp, SilcClientEntry);
    channel_entry = va_arg(vp, SilcChannelEntry);
    snprintf(message, sizeof(message), "%s invites you to channel %s", 
	     client_entry->nickname, channel_entry->channel_name);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    client_entry = va_arg(vp, SilcClientEntry);
    channel_entry = va_arg(vp, SilcChannelEntry);
    snprintf(message, sizeof(message), "%s (%s) has joined channel %s", 
	     client_entry->nickname, client_entry->username, 
	     channel_entry->channel_name);
    if (client_entry == conn->local_entry) {
      SilcChannelUser chu;

      silc_list_start(channel_entry->clients);
      while ((chu = silc_list_get(channel_entry->clients)) != SILC_LIST_END) {
	if (chu->client == client_entry) {
	  if (app->screen->bottom_line->mode)
	    silc_free(app->screen->bottom_line->mode);
	  app->screen->bottom_line->mode = silc_client_chumode_char(chu->mode);
	  silc_screen_print_bottom_line(app->screen, 0);
	  break;
	}
      }
    }
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    client_entry = va_arg(vp, SilcClientEntry);
    channel_entry = va_arg(vp, SilcChannelEntry);
    if (client_entry->server)
      snprintf(message, sizeof(message), "%s@%s has left channel %s", 
	       client_entry->nickname, client_entry->server, 
	       channel_entry->channel_name);
    else
      snprintf(message, sizeof(message), "%s has left channel %s", 
	       client_entry->nickname, channel_entry->channel_name);
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    client_entry = va_arg(vp, SilcClientEntry);
    tmp = va_arg(vp, char *);
    if (client_entry->server)
      snprintf(message, sizeof(message), "Signoff: %s@%s %s%s%s", 
	       client_entry->nickname, client_entry->server,
	       tmp ? "(" : "", tmp ? tmp : "", tmp ? ")" : "");
    else
      snprintf(message, sizeof(message), "Signoff: %s %s%s%s", 
	       client_entry->nickname,
	       tmp ? "(" : "", tmp ? tmp : "", tmp ? ")" : "");
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    client_entry = va_arg(vp, SilcClientEntry);
    tmp = va_arg(vp, char *);
    channel_entry = va_arg(vp, SilcChannelEntry);
    if (client_entry->server)
      snprintf(message, sizeof(message), "%s@%s set topic on %s: %s", 
	       client_entry->nickname, client_entry->server,
	       channel_entry->channel_name, tmp);
    else
      snprintf(message, sizeof(message), "%s set topic on %s: %s", 
	       client_entry->nickname, channel_entry->channel_name, tmp);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    client_entry = va_arg(vp, SilcClientEntry);
    client_entry2 = va_arg(vp, SilcClientEntry);
    if (client_entry->server && client_entry2->server)
      snprintf(message, sizeof(message), "%s@%s is known as %s@%s", 
	       client_entry->nickname, client_entry->server,
	       client_entry2->nickname, client_entry2->server);
    else
      snprintf(message, sizeof(message), "%s is known as %s", 
	       client_entry->nickname, client_entry2->nickname);
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    client_entry = va_arg(vp, SilcClientEntry);
    tmp = silc_client_chmode(va_arg(vp, unsigned int));
    channel_entry = va_arg(vp, SilcChannelEntry);
    if (tmp)
      snprintf(message, sizeof(message), "%s changed channel mode to +%s", 
	       client_entry->nickname, tmp);
    else
      snprintf(message, sizeof(message), "%s removed all channel modes", 
	       client_entry->nickname);
    if (app->screen->bottom_line->channel_mode)
      silc_free(app->screen->bottom_line->channel_mode);
    app->screen->bottom_line->channel_mode = tmp;
    silc_screen_print_bottom_line(app->screen, 0);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    client_entry = va_arg(vp, SilcClientEntry);
    tmp_int = va_arg(vp, unsigned int);
    tmp = silc_client_chumode(tmp_int);
    client_entry2 = va_arg(vp, SilcClientEntry);
    channel_entry = va_arg(vp, SilcChannelEntry);
    if (tmp)
      snprintf(message, sizeof(message), "%s changed %s's mode to +%s", 
	       client_entry->nickname, client_entry2->nickname, tmp);
    else
      snprintf(message, sizeof(message), "%s removed %s's modes", 
	       client_entry->nickname, client_entry2->nickname);
    if (client_entry2 == conn->local_entry) {
      if (app->screen->bottom_line->mode)
	silc_free(app->screen->bottom_line->mode);
      app->screen->bottom_line->mode = silc_client_chumode_char(tmp_int);
      silc_screen_print_bottom_line(app->screen, 0);
    }
    silc_free(tmp);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    {
      char line[256];
      int i;
      tmp = va_arg(vp, unsigned char *);

      i = 0;
      while(tmp[i] != 0) {
	if (tmp[i++] == '\n') {
	  memset(line, 0, sizeof(line));
	  strncat(line, tmp, i - 1);
	  tmp += i;
	  
	  silc_say(client, conn, "%s", line);
	  
	  if (!strlen(tmp))
	    break;
	  i = 0;
	}
      }
    }
    return;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    break;

  case SILC_NOTIFY_TYPE_KICKED:
    client_entry = va_arg(vp, SilcClientEntry);
    tmp = va_arg(vp, char *);
    channel_entry = va_arg(vp, SilcChannelEntry);

    if (client_entry == conn->local_entry) {
      snprintf(message, sizeof(message), 
	       "You have been kicked off channel %s %s%s%s", 
	       conn->current_channel->channel_name,
	       tmp ? "(" : "", tmp ? tmp : "", tmp ? ")" : "");
    } else {
      snprintf(message, sizeof(message), 
	       "%s%s%s has been kicked off channel %s %s%s%s", 
	       client_entry->nickname, 
	       client_entry->server ? "@" : "",
	       client_entry->server ? client_entry->server : "",
	       conn->current_channel->channel_name,
	       tmp ? "(" : "", tmp ? tmp : "", tmp ? ")" : "");
    }
    break;

  case SILC_NOTIFY_TYPE_KILLED:
    client_entry = va_arg(vp, SilcClientEntry);
    tmp = va_arg(vp, char *);
    channel_entry = va_arg(vp, SilcChannelEntry);

    if (client_entry == conn->local_entry) {
      snprintf(message, sizeof(message), 
	       "You have been killed from the SILC Network %s%s%s", 
	       tmp ? "(" : "", tmp ? tmp : "", tmp ? ")" : "");
    } else {
      snprintf(message, sizeof(message), 
	       "%s%s%s has been killed from the SILC Network %s%s%s", 
	       client_entry->nickname, 
	       client_entry->server ? "@" : "",
	       client_entry->server ? client_entry->server : "",
	       tmp ? "(" : "", tmp ? tmp : "", tmp ? ")" : "");
    }
    break;

  default:
    break;
  }

  silc_print(client, "*** %s", message);
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

/* We've resolved all clients we don't know about, now just print the
   users from the channel on the screen. */

void silc_client_show_users(SilcClient client,
			    SilcClientConnection conn,
			    SilcClientEntry *clients,
			    unsigned int clients_count,
			    void *context)
{
  SilcChannelEntry channel = (SilcChannelEntry)context;
  SilcChannelUser chu;
  int k = 0, len1 = 0, len2 = 0;
  char *name_list = NULL;

  if (!clients)
    return;

  silc_list_start(channel->clients);
  while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
    char *m, *n = chu->client->nickname;
    if (!n)
      continue;

    len2 = strlen(n);
    len1 += len2;
    
    name_list = silc_realloc(name_list, sizeof(*name_list) * (len1 + 3));
    
    m = silc_client_chumode_char(chu->mode);
    if (m) {
      memcpy(name_list + (len1 - len2), m, strlen(m));
      len1 += strlen(m);
      silc_free(m);
    }
    
    memcpy(name_list + (len1 - len2), n, len2);
    name_list[len1] = 0;
    
    if (k == silc_list_count(channel->clients) - 1)
      break;
    memcpy(name_list + len1, " ", 1);
    len1++;
    k++;
  }

  client->ops->say(client, conn, "Users on %s: %s", channel->channel_name, 
		   name_list);
  silc_free(name_list);
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
			SilcCommand command, SilcCommandStatus status, ...)
{
  SilcClientInternal app = (SilcClientInternal)client->application;
  SilcChannelUser chu;
  va_list vp;

  va_start(vp, status);

  switch(command)
    {
    case SILC_COMMAND_WHOIS:
      {
	char buf[1024], *nickname, *username, *realname;
	int len;
	unsigned int idle;

	if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
	  char *tmp;
	  tmp = silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
					   3, NULL);
	  if (tmp)
	    client->ops->say(client, conn, "%s: %s", tmp,
			     silc_client_command_status_message(status));
	  else
	    client->ops->say(client, conn, "%s",
			     silc_client_command_status_message(status));
	  break;
	}

	if (!success)
	  return;

	(void)va_arg(vp, SilcClientEntry);
	nickname = va_arg(vp, char *);
	username = va_arg(vp, char *);
	realname = va_arg(vp, char *);
	(void)va_arg(vp, void *);
	idle = va_arg(vp, unsigned int);

	memset(buf, 0, sizeof(buf));

	if (nickname) {
	  len = strlen(nickname);
	  strncat(buf, nickname, len);
	  strncat(buf, " is ", 4);
	}
	
	if (username) {
	  strncat(buf, username, strlen(username));
	}
	
	if (realname) {
	  strncat(buf, " (", 2);
	  strncat(buf, realname, strlen(realname));
	  strncat(buf, ")", 1);
	}

	client->ops->say(client, conn, "%s", buf);
	if (idle && nickname)
	  client->ops->say(client, conn, "%s has been idle %d %s",
			   nickname,
			   idle > 60 ? (idle / 60) : idle,
			   idle > 60 ? "minutes" : "seconds");
      }
      break;

    case SILC_COMMAND_WHOWAS:
      {
	char buf[1024], *nickname, *username, *realname;
	int len;

	if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
	  char *tmp;
	  tmp = silc_argument_get_arg_type(silc_command_get_args(cmd_payload),
					   3, NULL);
	  if (tmp)
	    client->ops->say(client, conn, "%s: %s", tmp,
			     silc_client_command_status_message(status));
	  else
	    client->ops->say(client, conn, "%s",
			     silc_client_command_status_message(status));
	  break;
	}

	if (!success)
	  return;

	(void)va_arg(vp, SilcClientEntry);
	nickname = va_arg(vp, char *);
	username = va_arg(vp, char *);
	realname = va_arg(vp, char *);

	memset(buf, 0, sizeof(buf));

	if (nickname) {
	  len = strlen(nickname);
	  strncat(buf, nickname, len);
	  strncat(buf, " was ", 5);
	}
	
	if (username) {
	  strncat(buf, username, strlen(nickname));
	}
	
	if (realname) {
	  strncat(buf, " (", 2);
	  strncat(buf, realname, strlen(realname));
	  strncat(buf, ")", 1);
	}

	client->ops->say(client, conn, "%s", buf);
      }
      break;

    case SILC_COMMAND_JOIN:
      {
	unsigned int mode;
	char *topic;
	SilcBuffer client_id_list;
	unsigned int list_count;
	SilcChannelEntry channel;

	if (!success)
	  return;

	app->screen->bottom_line->channel = va_arg(vp, char *);
	channel = va_arg(vp, SilcChannelEntry);
	mode = va_arg(vp, unsigned int);
	(void)va_arg(vp, unsigned int);
	(void)va_arg(vp, unsigned char *);
	(void)va_arg(vp, unsigned char *);
	(void)va_arg(vp, unsigned char *);
	topic = va_arg(vp, char *);
	(void)va_arg(vp, unsigned char *);
	list_count = va_arg(vp, unsigned int);
	client_id_list = va_arg(vp, SilcBuffer);

	if (topic)
	  client->ops->say(client, conn, "Topic for %s: %s", 
			   app->screen->bottom_line->channel, topic);
	
	app->screen->bottom_line->channel_mode = silc_client_chmode(mode);
	silc_screen_print_bottom_line(app->screen, 0);

	/* Resolve the client information */
	silc_client_get_clients_by_list(client, conn, list_count,
					client_id_list,
					silc_client_show_users, channel);
      }
      break;

    case SILC_COMMAND_NICK:
      {
	SilcClientEntry entry;

	if (!success)
	  return;

	entry = va_arg(vp, SilcClientEntry);
	silc_say(client, conn, "Your current nickname is %s", entry->nickname);
	app->screen->bottom_line->nickname = entry->nickname;
	silc_screen_print_bottom_line(app->screen, 0);
      }
      break;

    case SILC_COMMAND_UMODE:
      {
	unsigned int mode;

	if (!success)
	  return;

	mode = va_arg(vp, unsigned int);

	if (!mode && app->screen->bottom_line->umode) {
	  silc_free(app->screen->bottom_line->umode);
	  app->screen->bottom_line->umode = NULL;
	}

	if (mode & SILC_UMODE_SERVER_OPERATOR) {
	  if (app->screen->bottom_line->umode)
	    silc_free(app->screen->bottom_line->umode);
	  app->screen->bottom_line->umode = strdup("Server Operator");;
	}

	if (mode & SILC_UMODE_ROUTER_OPERATOR) {
	  if (app->screen->bottom_line->umode)
	    silc_free(app->screen->bottom_line->umode);
	  app->screen->bottom_line->umode = strdup("SILC Operator");;
	}

	silc_screen_print_bottom_line(app->screen, 0);
      }
      break;

    case SILC_COMMAND_OPER:
      if (status == SILC_STATUS_OK) {
	conn->local_entry->mode |= SILC_UMODE_SERVER_OPERATOR;
	if (app->screen->bottom_line->umode)
	  silc_free(app->screen->bottom_line->umode);
	app->screen->bottom_line->umode = strdup("Server Operator");;
	silc_screen_print_bottom_line(app->screen, 0);
      }
      break;

    case SILC_COMMAND_SILCOPER:
      if (status == SILC_STATUS_OK) {
	conn->local_entry->mode |= SILC_UMODE_ROUTER_OPERATOR;
	if (app->screen->bottom_line->umode)
	  silc_free(app->screen->bottom_line->umode);
	app->screen->bottom_line->umode = strdup("SILC Operator");;
	silc_screen_print_bottom_line(app->screen, 0);
      }
      break;

    case SILC_COMMAND_USERS:
      if (!success)
	return;

      silc_list_start(conn->current_channel->clients);
      while ((chu = silc_list_get(conn->current_channel->clients)) 
	     != SILC_LIST_END) {
	if (chu->client == conn->local_entry) {
	  if (app->screen->bottom_line->mode)
	    silc_free(app->screen->bottom_line->mode);
	  app->screen->bottom_line->mode = silc_client_chumode_char(chu->mode);
	  silc_screen_print_bottom_line(app->screen, 0);
	  break;
	}
      break;
      }
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
  app->conn = NULL;
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

/* Notifies application that failure packet was received.  This is called
   if there is some protocol active in the client.  The `protocol' is the
   protocol context.  The `failure' is opaque pointer to the failure
   indication.  Note, that the `failure' is protocol dependant and application
   must explicitly cast it to correct type.  Usually `failure' is 32 bit
   failure type (see protocol specs for all protocol failure types). */

void silc_failure(SilcClient client, SilcClientConnection conn, 
		  SilcProtocol protocol, void *failure)
{

}

/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). */

int silc_key_agreement(SilcClient client, SilcClientConnection conn,
		       SilcClientEntry client_entry, char *hostname,
		       int port,
		       SilcKeyAgreementCallback *completion,
		       void **context)
{

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
  failure:              silc_failure,
  key_agreement:        silc_key_agreement,
};
