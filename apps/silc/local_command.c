/*

  local_command.c

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
#include "client_internal.h"

/* Local commands. */
SilcClientCommand silc_local_command_list[] =
{
  SILC_CLIENT_LCMD(help, HELP, "HELP", 0, 2),
  SILC_CLIENT_LCMD(clear, CLEAR, "CLEAR", 0, 1),
  SILC_CLIENT_LCMD(version, VERSION, "VERSION", 0, 1),
  SILC_CLIENT_LCMD(server, SERVER, "SERVER", 0, 2),
  SILC_CLIENT_LCMD(msg, MSG, "MSG", 0, 3),
  SILC_CLIENT_LCMD(away, AWAY, "AWAY", 0, 2),
  SILC_CLIENT_LCMD(key, KEY, "KEY", 0, 7),
  SILC_CLIENT_LCMD(me, ME, "ME", 0, 3),
  SILC_CLIENT_LCMD(notice, NOTICE, "NOTICE", 0, 3),

  { NULL, 0, NULL, 0, 0 },
};

/* Finds and returns a pointer to the command list. Return NULL if the
   command is not found. */

SilcClientCommand *silc_client_local_command_find(const char *name)
{
  SilcClientCommand *cmd;

  for (cmd = silc_local_command_list; cmd->name; cmd++) {
    if (!strcmp(cmd->name, name))
      return cmd;
  }

  return NULL;
}

/* HELP command. This is local command and shows help on SILC */

SILC_CLIENT_LCMD_FUNC(help)
{

}

/* CLEAR command. This is local command and clears current output window */

SILC_CLIENT_LCMD_FUNC(clear)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;

  silc_client_command_free(cmd);
}

/* VERSION command. This is local command and shows version of the client */

SILC_CLIENT_LCMD_FUNC(version)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  extern char *silc_version;
  extern char *silc_name;
  extern char *silc_fullname;

  silc_say(client, cmd->conn,
	   "%s (%s) version %s", silc_name, silc_fullname,
	   silc_version);

  silc_client_command_free(cmd);
}

/* Command MSG. Sends private message to user or list of users. Note that
   private messages are not really commands, they are message packets,
   however, on user interface it is convenient to show them as commands
   as that is the common way of sending private messages (like in IRC). */
/* XXX supports only one destination */

SILC_CLIENT_LCMD_FUNC(msg)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientEntry client_entry = NULL;
  unsigned int num = 0;
  char *nickname = NULL, *server = NULL;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc < 3) {
    silc_say(client, conn, "Usage: /MSG <nickname> <message>");
    goto out;
  }

  /* Parse the typed nickname. */
  if (!silc_parse_nickname(cmd->argv[1], &nickname, &server, &num)) {
    silc_say(client, conn, "Bad nickname");
    goto out;
  }

  /* Find client entry */
  client_entry = silc_idlist_get_client(client, conn, nickname, server, num,
					TRUE);
  if (!client_entry) {
    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, conn->cmd_ident, 
				NULL, silc_client_local_command_msg, context);
    return;
  }

  /* Display the message for our eyes. */
  silc_print(client, "-> *%s* %s", cmd->argv[1], cmd->argv[2]);

  /* Send the private message */
  silc_client_send_private_message(client, conn, client_entry, 0,
				   cmd->argv[2], cmd->argv_lens[2],
				   TRUE);

 out:
  silc_client_command_free(cmd);
}


/* Command SERVER. Connects to remote SILC server. This is local command. */

SILC_CLIENT_LCMD_FUNC(server)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  int i = 0, len, port;
  char *hostname;

  if (cmd->argc < 2) {
    /* Show current servers */

    if (!cmd->conn) {
      silc_say(client, conn, "You are not connected to any server");
      silc_say(client, conn, "Usage: /SERVER [<server>[:<port>]]");
      goto out;
    }

    silc_say(client, conn, "Current server: %s on %d %s", 
	     conn->remote_host, conn->remote_port,
	     conn->remote_info ? conn->remote_info : "");
    
    silc_say(client, conn, "Server list:");
    for (i = 0; i < client->conns_count; i++) {
      silc_say(client, conn, " [%d] %s on %d %s", i + 1,
	       client->conns[i]->remote_host, 
	       client->conns[i]->remote_port,
	       client->conns[i]->remote_info ? 
	       client->conns[i]->remote_info : "");
    }

    goto out;
  }

  /* See if port is included and then extract it */
  if (strchr(cmd->argv[1], ':')) {
    len = strcspn(cmd->argv[1], ":");
    hostname = silc_calloc(len + 1, sizeof(char));
    memcpy(hostname, cmd->argv[1], len);
    port = atoi(cmd->argv[1] + 1 + len);
  } else {
    hostname = cmd->argv[1];
    port = 706;
  }

#if 0
  if (conn && conn->remote_host) {
    if (!strcmp(hostname, conn->remote_host) && port == conn->remote_port) {
      silc_say(client, conn, "You are already connected to that server");
      goto out;
    }

    /* Close connection */
    cmd->client->ops->disconnect(cmd->client, cmd->conn);
    silc_client_close_connection(cmd->client, cmd->conn->sock);
  }
#endif

  /* Connect asynchronously to not to block user interface */
  silc_client_connect_to_server(cmd->client, port, hostname, NULL);

 out:
  silc_client_command_free(cmd);
}

/* Local command AWAY. Client replies with away message to whomever sends
   private message to the client if the away message is set. If this is
   given without arguments the away message is removed. */

SILC_CLIENT_LCMD_FUNC(away)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientInternal app = (SilcClientInternal)client->application;
  unsigned char modebuf[4];
  SilcBuffer idp, buffer;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc == 1) {
    conn->local_entry->mode &= ~SILC_UMODE_GONE;

    if (conn->away) {
      silc_free(conn->away->away);
      silc_free(conn->away);
      conn->away = NULL;
      app->screen->bottom_line->away = FALSE;

      silc_say(client, conn, "Away message removed");
      silc_screen_print_bottom_line(app->screen, 0);
    }
  } else {
    conn->local_entry->mode |= SILC_UMODE_GONE;
  
    if (conn->away)
      silc_free(conn->away->away);
    else
      conn->away = silc_calloc(1, sizeof(*conn->away));
    
    app->screen->bottom_line->away = TRUE;
    conn->away->away = strdup(cmd->argv[1]);

    silc_say(client, conn, "Away message set: %s", conn->away->away);
    silc_screen_print_bottom_line(app->screen, 0);
  }

  /* Send the UMODE command to se myself as gone */
  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);
  SILC_PUT32_MSB(conn->local_entry->mode, modebuf);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_UMODE, 
					  ++conn->cmd_ident, 2, 
					  1, idp->data, idp->len, 
					  2, modebuf, sizeof(modebuf));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, 
			  NULL, 0, NULL, NULL, buffer->data, 
			  buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

 out:
  silc_client_command_free(cmd);
}

typedef struct {
  int type;			/* 1 = msg, 2 = channel */
} *KeyInternal;

static SilcSKEKeyMaterial *curr_key = NULL;

/* Key agreement callback that is called after the key agreement protocol
   has been performed. This is called also if error occured during the
   key agreement protocol. The `key' is the allocated key material and
   the caller is responsible of freeing it. The `key' is NULL if error
   has occured. The application can freely use the `key' to whatever
   purpose it needs. See lib/silcske/silcske.h for the definition of
   the SilcSKEKeyMaterial structure. */

static void keyagr_completion(SilcClient client,
			      SilcClientConnection conn,
			      SilcClientEntry client_entry,
			      SilcKeyAgreementStatus status,
			      SilcSKEKeyMaterial *key,
			      void *context)
{
  KeyInternal i = (KeyInternal)context;

  curr_key = NULL;

  switch(status) {
  case SILC_KEY_AGREEMENT_OK:
    silc_say(client, conn, "Key agreement compeleted successfully with %s",
	     client_entry->nickname);;

    if (i->type == 1) {
      if (!silc_client_ask_yes_no(client, 
         "Would you like to use the key with private messages (y/n)? ")) {
	silc_say(client, conn, "You can set the key material into use later by giving /KEY msg set command");
	curr_key = key;
	break;
      }
      
      /* Set the private key for this client */
      silc_client_del_private_message_key(client, conn, client_entry);
      silc_client_add_private_message_key_ske(client, conn, client_entry,
					      NULL, key);
      silc_say(client, conn, "The private messages with the %s are now protected with the private key", client_entry->nickname);
      silc_ske_free_key_material(key);
    }
    
    break;
    
  case SILC_KEY_AGREEMENT_ERROR:
    silc_say(client, conn, "Error occured during key agreement with %s",
	     client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_FAILURE:
    silc_say(client, conn, "The key agreement failed with %s",
	     client_entry->nickname);
    break;
    
  case SILC_KEY_AGREEMENT_TIMEOUT:
    silc_say(client, conn, "Timeout during key agreement. The key agreement was not performed with %s",
	     client_entry->nickname);
    break;
    
  default:
    break;
  } 

  if (i)
    silc_free(i);
}

/* Local command KEY. This command is used to set and unset private
   keys for channels, set and unset private keys for private messages
   with remote clients and to send key agreement requests and
   negotiate the key agreement protocol with remote client.  The
   key agreement is supported only to negotiate private message keys,
   it currently cannot be used to negotiate private keys for channels,
   as it is not convenient for that purpose. */

SILC_CLIENT_LCMD_FUNC(key)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel_entry = NULL;
  unsigned int num = 0;
  char *nickname = NULL, *server = NULL;
  int command = 0, port = 0, type = 0;
  char *hostname = NULL;
  KeyInternal internal = NULL;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc < 4) {
    silc_say(client, conn, "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    goto out;
  }

  /* Get type */
  if (!strcasecmp(cmd->argv[1], "msg"))
    type = 1;
  if (!strcasecmp(cmd->argv[1], "channel"))
    type = 2;

  if (type == 0) {
    silc_say(client, conn, "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    goto out;
  }

  if (type == 1) {
    if (cmd->argv[2][0] == '*') {
      nickname = "*";
    } else {
      /* Parse the typed nickname. */
      if (!silc_parse_nickname(cmd->argv[2], &nickname, &server, &num)) {
	silc_say(client, conn, "Bad nickname");
	goto out;
      }
      
      /* Find client entry */
      client_entry = silc_idlist_get_client(client, conn, nickname, 
					    server, num, TRUE);
      if (!client_entry) {
	/* Client entry not found, it was requested thus mark this to be
	   pending command. */
	silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY, 
				    conn->cmd_ident, 
				    NULL, silc_client_local_command_key, 
				    context);
	return;
      }
    }
  }

  if (type == 2) {
    /* Get channel entry */
    char *name;

    if (cmd->argv[2][0] == '*') {
      if (!conn->current_channel) {
	cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
	goto out;
      }
      name = conn->current_channel->channel_name;
    } else {
      name = cmd->argv[2];
    }

    channel_entry = silc_client_get_channel(client, conn, name);
    if (!channel_entry) {
      silc_say(client, conn, "You are not on that channel");
      goto out;
    }
  }

  /* Set command */
  if (!strcasecmp(cmd->argv[3], "set")) {
    command = 1;

    if (cmd->argc == 4) {
      if (curr_key && type == 1 && client_entry) {
	silc_client_del_private_message_key(client, conn, client_entry);
	silc_client_add_private_message_key_ske(client, conn, client_entry,
						NULL, curr_key);
	goto out;
      }
    }

    if (cmd->argc >= 5) {
      if (type == 1 && client_entry) {
	/* Set private message key */
	
	silc_client_del_private_message_key(client, conn, client_entry);

	if (cmd->argc >= 6)
	  silc_client_add_private_message_key(client, conn, client_entry,
					      cmd->argv[5], cmd->argv[4],
					      cmd->argv_lens[4],
					      (cmd->argv[4][0] == '*' ?
					       TRUE : FALSE));
	else
	  silc_client_add_private_message_key(client, conn, client_entry,
					      NULL, cmd->argv[4],
					      cmd->argv_lens[4],
					      (cmd->argv[4][0] == '*' ?
					       TRUE : FALSE));

	/* Send the key to the remote client so that it starts using it
	   too. */
	silc_client_send_private_message_key(client, conn, client_entry, TRUE);
      } else if (type == 2) {
	/* Set private channel key */
	char *cipher = NULL, *hmac = NULL;

	if (!(channel_entry->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
	  silc_say(client, conn, 
		   "Private key mode is not set on this channel");
	  goto out;
	}

	if (cmd->argc >= 6)
	  cipher = cmd->argv[5];
	if (cmd->argc >= 7)
	  hmac = cmd->argv[6];

	if (!silc_client_add_channel_private_key(client, conn, channel_entry,
						 cipher, hmac,
						 cmd->argv[4],
						 cmd->argv_lens[4])) {
	  silc_say(client, conn, "Could not add channel private key");
	  goto out;
	}
      }
    }

    goto out;
  }
  
  /* Unset command */
  if (!strcasecmp(cmd->argv[3], "unset")) {
    command = 2;

    if (type == 1 && client_entry) {
      /* Unset private message key */
      silc_client_del_private_message_key(client, conn, client_entry);
    } else if (type == 2) {
      /* Unset channel key(s) */
      SilcChannelPrivateKey *keys;
      unsigned int keys_count;
      int number;

      if (cmd->argc == 4)
	silc_client_del_channel_private_keys(client, conn, channel_entry);

      if (cmd->argc > 4) {
	number = atoi(cmd->argv[4]);
	keys = silc_client_list_channel_private_keys(client, conn, 
						     channel_entry,
						     &keys_count);
	if (!keys)
	  goto out;

	if (!number || number > keys_count) {
	  silc_client_free_channel_private_keys(keys, keys_count);
	  goto out;
	}

	silc_client_del_channel_private_key(client, conn, channel_entry,
					    keys[number - 1]);
	silc_client_free_channel_private_keys(keys, keys_count);
      }

      goto out;
    }
  }

  /* List command */
  if (!strcasecmp(cmd->argv[3], "list")) {
    command = 3;

    if (type == 1) {
      SilcPrivateMessageKeys keys;
      unsigned int keys_count;
      int k, i, len;
      char buf[1024];

      keys = silc_client_list_private_message_keys(client, conn, 
						   &keys_count);
      if (!keys)
	goto out;

      /* list the private message key(s) */
      if (nickname[0] == '*') {
	silc_say(client, conn, "Private message keys");
	silc_say(client, conn, 
		 "  Client                         Cipher         Key");
	for (k = 0; k < keys_count; k++) {
	  memset(buf, 0, sizeof(buf));
	  strncat(buf, "  ", 2);
	  len = strlen(keys[k].client_entry->nickname);
	  strncat(buf, keys[k].client_entry->nickname, len > 30 ? 30 : len);
	  if (len < 30)
	    for (i = 0; i < 30 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");
	  
	  len = strlen(keys[k].cipher);
	  strncat(buf, keys[k].cipher, len > 14 ? 14 : len);
	  if (len < 14)
	    for (i = 0; i < 14 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");

	  if (keys[k].key)
	    strcat(buf, "<hidden>");
	  else
	    strcat(buf, "*generated*");

	  silc_say(client, conn, "%s", buf);
	}
      } else {
	silc_say(client, conn, "Private message key", 
		 client_entry->nickname);
	silc_say(client, conn, 
		 "  Client                         Cipher         Key");
	for (k = 0; k < keys_count; k++) {
	  if (keys[k].client_entry != client_entry)
	    continue;

	  memset(buf, 0, sizeof(buf));
	  strncat(buf, "  ", 2);
	  len = strlen(keys[k].client_entry->nickname);
	  strncat(buf, keys[k].client_entry->nickname, len > 30 ? 30 : len);
	  if (len < 30)
	    for (i = 0; i < 30 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");
	  
	  len = strlen(keys[k].cipher);
	  strncat(buf, keys[k].cipher, len > 14 ? 14 : len);
	  if (len < 14)
	    for (i = 0; i < 14 - len; i++)
	      strcat(buf, " ");
	  strcat(buf, " ");

	  if (keys[k].key)
	    strcat(buf, "<hidden>");
	  else
	    strcat(buf, "*generated*");

	  silc_say(client, conn, "%s", buf);
	}
      }

      silc_client_free_private_message_keys(keys, keys_count);
    } else if (type == 2) {
      SilcChannelPrivateKey *keys;
      unsigned int keys_count;
      int k, i, len;
      char buf[1024];

      keys = silc_client_list_channel_private_keys(client, conn, channel_entry,
						   &keys_count);
      if (!keys)
	goto out;

      silc_say(client, conn, "Channel %s private keys", 
	       channel_entry->channel_name);
      silc_say(client, conn, 
	       "  Cipher           Hmac             Key");
      for (k = 0; k < keys_count; k++) {
	memset(buf, 0, sizeof(buf));
	strncat(buf, "  ", 2);

	len = strlen(keys[k]->cipher->cipher->name);
	strncat(buf, keys[k]->cipher->cipher->name, len > 16 ? 16 : len);
	if (len < 16)
	  for (i = 0; i < 16 - len; i++)
	    strcat(buf, " ");
	strcat(buf, " ");
	
	len = strlen(keys[k]->hmac->hmac->name);
	strncat(buf, keys[k]->hmac->hmac->name, len > 16 ? 16 : len);
	if (len < 16)
	  for (i = 0; i < 16 - len; i++)
	    strcat(buf, " ");
	strcat(buf, " ");
	
	strcat(buf, "<hidden>");

	silc_say(client, conn, "%s", buf);
      }
      
      silc_client_free_channel_private_keys(keys, keys_count);
    }

    goto out;
  }

  /* Send command is used to send key agreement */
  if (!strcasecmp(cmd->argv[3], "agreement")) {
    command = 4;

    if (cmd->argc >= 5)
      hostname = cmd->argv[4];
    if (cmd->argc >= 6)
      port = atoi(cmd->argv[5]);

    internal = silc_calloc(1, sizeof(*internal));
    internal->type = type;
  }

  /* Start command is used to start key agreement (after receiving the
     key_agreement client operation). */
  if (!strcasecmp(cmd->argv[3], "negotiate")) {
    command = 5;

    if (cmd->argc >= 5)
      hostname = cmd->argv[4];
    if (cmd->argc >= 6)
      port = atoi(cmd->argv[5]);

    internal = silc_calloc(1, sizeof(*internal));
    internal->type = type;
  }

  if (command == 0) {
    silc_say(client, conn, "Usage: /KEY msg|channel <nickname|channel> "
	     "set|unset|agreement|negotiate [<arguments>]");
    goto out;
  }

  if (command == 4 && client_entry) {
    silc_say(client, conn, "Sending key agreement to %s", cmd->argv[2]);
    silc_client_send_key_agreement(client, conn, client_entry, hostname, 
				   port, 120, keyagr_completion, internal);
    goto out;
  }

  if (command == 5 && client_entry) {
    silc_say(client, conn, "Starting key agreement with %s", cmd->argv[2]);
    silc_client_perform_key_agreement(client, conn, client_entry, hostname, 
				      port, keyagr_completion, internal);
    goto out;
  }

 out:
  if (nickname)
    silc_free(nickname);
  if (server)
    silc_free(server);
  silc_client_command_free(cmd);
}

/* Sends an action to the channel.  Equals CTCP's ACTION (IRC's /ME) 
   command. */

SILC_CLIENT_LCMD_FUNC(me)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcChannelEntry channel_entry;
  char *name;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc < 3) {
    silc_say(client, conn, "Usage: /ME <channel> <action message>");
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  channel_entry = silc_client_get_channel(client, conn, name);
  if (!channel_entry) {
    silc_say(client, conn, "You are not on that channel");
    goto out;
  }

  /* Send the action message */
  silc_client_send_channel_message(client, conn, channel_entry, NULL,
				   SILC_MESSAGE_FLAG_ACTION, 
				   cmd->argv[2], cmd->argv_lens[2], TRUE);

  silc_print(client, "* %s %s", conn->nickname, cmd->argv[2]);

 out:
  silc_client_command_free(cmd);
}

/* Sends an notice to the channel.  */

SILC_CLIENT_LCMD_FUNC(notice)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcChannelEntry channel_entry;
  char *name;

  if (!cmd->conn) {
    silc_say(client, conn,
	     "You are not connected to a server, use /SERVER to connect");
    goto out;
  }

  if (cmd->argc < 3) {
    silc_say(client, conn, "Usage: /NOTICE <channel> <message>");
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      cmd->client->ops->say(cmd->client, conn, "You are not on any channel");
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  channel_entry = silc_client_get_channel(client, conn, name);
  if (!channel_entry) {
    silc_say(client, conn, "You are not on that channel");
    goto out;
  }

  /* Send the action message */
  silc_client_send_channel_message(client, conn, channel_entry, NULL,
				   SILC_MESSAGE_FLAG_NOTICE, 
				   cmd->argv[2], cmd->argv_lens[2], TRUE);

  silc_print(client, "- %s %s", conn->nickname, cmd->argv[2]);

 out:
  silc_client_command_free(cmd);
}
