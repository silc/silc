/*

  command.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

#define SILC_NOT_CONNECTED(x, c) \
  x->internal->ops->say((x), (c), SILC_CLIENT_MESSAGE_ERROR, \
	   "You are not connected to a server, please connect to server");

/* Command operation that is called at the end of all commands.
   Usage: COMMAND(status); */
#define COMMAND(status) cmd->client->internal->ops->command(cmd->client, \
  cmd->conn, cmd, TRUE, cmd->command->cmd, (status))

/* Error to application. Usage: COMMAND_ERROR(status); */
#define COMMAND_ERROR(status) 				\
  cmd->client->internal->ops->command(cmd->client,	\
  cmd->conn, cmd, FALSE, cmd->command->cmd, (status))

#define SAY cmd->client->internal->ops->say

/* Generic function to send any command. The arguments must be sent already
   encoded into correct form and in correct order. */

void silc_client_command_send(SilcClient client, SilcClientConnection conn,
			      SilcCommand command, SilcUInt16 ident,
			      SilcUInt32 argc, ...)
{
  SilcBuffer packet;
  va_list ap;

  assert(client && conn);

  va_start(ap, argc);

  packet = silc_command_payload_encode_vap(command, ident, argc, ap);
  silc_client_packet_send(client, conn->sock, SILC_PACKET_COMMAND,
			  NULL, 0, NULL, NULL, packet->data,
			  packet->len, TRUE);
  silc_buffer_free(packet);
}

/* Finds and returns a pointer to the command list. Return NULL if the
   command is not found. */

SilcClientCommand silc_client_command_find(SilcClient client,
					   const char *name)
{
  SilcClientCommand cmd;

  assert(client);

  silc_list_start(client->internal->commands);
  while ((cmd = silc_list_get(client->internal->commands)) != SILC_LIST_END) {
    if (cmd->name && !strcasecmp(cmd->name, name))
      return cmd;
  }

  return NULL;
}

/* Executes a command */

bool silc_client_command_call(SilcClient client,
			      SilcClientConnection conn,
			      const char *command_line, ...)
{
  va_list va;
  SilcUInt32 argc = 0;
  unsigned char **argv = NULL;
  SilcUInt32 *argv_lens = NULL, *argv_types = NULL;
  SilcClientCommand cmd;
  SilcClientCommandContext ctx;
  char *arg;

  assert(client);

  /* Parse arguments */
  va_start(va, command_line);
  if (command_line) {
    char *command_name;

    /* Get command name */
    command_name = silc_memdup(command_line, strcspn(command_line, " "));
    if (!command_name)
      return FALSE;

    /* Find command by name */
    cmd = silc_client_command_find(client, command_name);
    if (!cmd) {
      silc_free(command_name);
      return FALSE;
    }

    /* Parse command line */
    silc_parse_command_line((char *)command_line, &argv, &argv_lens,
			    &argv_types, &argc, cmd->max_args);

    silc_free(command_name);
  } else {
    arg = va_arg(va, char *);
    if (!arg)
      return FALSE;

    /* Find command by name */
    cmd = silc_client_command_find(client, arg);
    if (!cmd)
      return FALSE;

    while (arg) {
      argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
      argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) * (argc + 1));
      argv_types = silc_realloc(argv_types, sizeof(*argv_types) * (argc + 1));
      argv[argc] = silc_memdup(arg, strlen(arg));
      argv_lens[argc] = strlen(arg);
      argv_types[argc] = argc;
      argc++;
      arg = va_arg(va, char *);
    }
  }

  /* Allocate command context. */
  ctx = silc_client_command_alloc();
  ctx->client = client;
  ctx->conn = conn;
  ctx->command = cmd;
  ctx->argc = argc;
  ctx->argv = argv;
  ctx->argv_lens = argv_lens;
  ctx->argv_types = argv_types;

  /* Call the command */
  cmd->command(ctx, NULL);

  va_end(va);

  return TRUE;
}

/* Add new pending command to be executed when reply to a command has been
   received. The `reply_cmd' is the command that will call the `callback'
   with `context' when reply has been received.  It can be SILC_COMMAND_NONE
   to match any command with the `ident'.  If `ident' is non-zero
   the `callback' will be executed when received reply with command
   identifier `ident'. If there already exists pending command for the
   specified command, ident, callback and context this function has no
   effect. */

void silc_client_command_pending(SilcClientConnection conn,
				 SilcCommand reply_cmd,
				 SilcUInt16 ident,
				 SilcCommandCb callback,
				 void *context)
{
  SilcClientCommandPending *reply;

  assert(conn);
  reply = silc_calloc(1, sizeof(*reply));
  reply->reply_cmd = reply_cmd;
  reply->ident = ident;
  reply->context = context;
  reply->callback = callback;
  silc_dlist_add(conn->internal->pending_commands, reply);
}

/* Deletes pending command by reply command type. */

void silc_client_command_pending_del(SilcClientConnection conn,
				     SilcCommand reply_cmd,
				     SilcUInt16 ident)
{
  SilcClientCommandPending *r;

  if (!conn->internal->pending_commands)
    return;

  silc_dlist_start(conn->internal->pending_commands);
  while ((r = silc_dlist_get(conn->internal->pending_commands))
	 != SILC_LIST_END) {
    if ((r->reply_cmd == reply_cmd || (r->reply_cmd == SILC_COMMAND_NONE &&
				       r->reply_check))
	&& r->ident == ident) {
      silc_dlist_del(conn->internal->pending_commands, r);
      silc_free(r);
    }
  }
}

/* Checks for pending commands and marks callbacks to be called from
   the command reply function. */

SilcClientCommandPendingCallbacks
silc_client_command_pending_check(SilcClientConnection conn,
				  SilcClientCommandReplyContext ctx,
				  SilcCommand command,
				  SilcUInt16 ident,
				  SilcUInt32 *callbacks_count)
{
  SilcClientCommandPending *r;
  SilcClientCommandPendingCallbacks callbacks = NULL;
  int i = 0;

  silc_dlist_start(conn->internal->pending_commands);
  while ((r = silc_dlist_get(conn->internal->pending_commands))
	 != SILC_LIST_END) {
    if ((r->reply_cmd == command || r->reply_cmd == SILC_COMMAND_NONE)
	&& r->ident == ident) {
      callbacks = silc_realloc(callbacks, sizeof(*callbacks) * (i + 1));
      callbacks[i].context = r->context;
      callbacks[i].callback = r->callback;
      r->reply_check = TRUE;
      ctx->ident = ident;
      i++;
    }
  }

  *callbacks_count = i;
  return callbacks;
}

/* Allocate Command Context */

SilcClientCommandContext silc_client_command_alloc(void)
{
  SilcClientCommandContext ctx = silc_calloc(1, sizeof(*ctx));
  ctx->users++;
  return ctx;
}

/* Free command context and its internals */

void silc_client_command_free(SilcClientCommandContext ctx)
{
  ctx->users--;
  SILC_LOG_DEBUG(("Command context %p refcnt %d->%d", ctx, ctx->users + 1,
		  ctx->users));
  if (ctx->users < 1) {
    int i;

    for (i = 0; i < ctx->argc; i++)
      silc_free(ctx->argv[i]);
    silc_free(ctx->argv);
    silc_free(ctx->argv_lens);
    silc_free(ctx->argv_types);
    silc_free(ctx);
  }
}

/* Duplicate Command Context by adding reference counter. The context won't
   be free'd untill it hits zero. */

SilcClientCommandContext silc_client_command_dup(SilcClientCommandContext ctx)
{
  ctx->users++;
  SILC_LOG_DEBUG(("Command context %p refcnt %d->%d", ctx, ctx->users - 1,
		  ctx->users));
  return ctx;
}

/* Command WHOIS. This command is used to query information about
   specific user. */

SILC_CLIENT_CMD_FUNC(whois)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, attrs = NULL;
  unsigned char count[4], *tmp = NULL;
  int i;
  bool details = FALSE, nick = FALSE;
  unsigned char *pubkey = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  /* Given without arguments fetches client's own information */
  if (cmd->argc < 2) {
    buffer = silc_id_payload_encode(cmd->conn->local_id, SILC_ID_CLIENT);
    silc_client_command_send(cmd->client, cmd->conn, SILC_COMMAND_WHOIS,
			     ++conn->cmd_ident,
			     1, 4, buffer->data, buffer->len);
    silc_buffer_free(buffer);
    goto out;
  }

  for (i = 1; i < cmd->argc; i++) {
    if (!strcasecmp(cmd->argv[i], "-details")) {
	details = TRUE;
    } else if (!strcasecmp(cmd->argv[i], "-pubkey") && cmd->argc > i + 1) {
	pubkey = cmd->argv[i + 1];
	i++;
    } else {
      /* We assume that the first parameter is the nickname, if it isn't
         -details or -pubkey. The last parameter should always be the count */
      if (i == 1) {
	nick = TRUE;
      } else if (i == cmd->argc - 1) {
	int c = atoi(cmd->argv[i]);
	SILC_PUT32_MSB(c, count);
	tmp = count;
      }
    }
  }

  if (details) {
    /* if pubkey is set, add all attributes to the
       attrs buffer, except public key */
    if (pubkey) {
      attrs = silc_client_attributes_request(SILC_ATTRIBUTE_USER_INFO,
                                             SILC_ATTRIBUTE_SERVICE,
                                             SILC_ATTRIBUTE_STATUS_MOOD,
                                             SILC_ATTRIBUTE_STATUS_FREETEXT,
                                             SILC_ATTRIBUTE_STATUS_MESSAGE,
                                             SILC_ATTRIBUTE_PREFERRED_LANGUAGE,
                                             SILC_ATTRIBUTE_PREFERRED_CONTACT,
                                             SILC_ATTRIBUTE_TIMEZONE,
                                             SILC_ATTRIBUTE_GEOLOCATION,
                                             SILC_ATTRIBUTE_DEVICE_INFO, 0);
    } else {
      attrs = silc_client_attributes_request(0);
    }
  }

  if (pubkey) {
    SilcAttributeObjPk obj;
    SilcPublicKey pk;

    if (!silc_pkcs_load_public_key(pubkey, &pk, SILC_PKCS_FILE_PEM)) {
      if (!silc_pkcs_load_public_key(pubkey, &pk, SILC_PKCS_FILE_BIN)) {
	SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	    "Could not load public key %s, check the filename",
	    pubkey);
	COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }
    }

    obj.type = "silc-rsa";
    obj.data = silc_pkcs_public_key_encode(pk, &obj.data_len);

    attrs = silc_attribute_payload_encode(attrs,
                                          SILC_ATTRIBUTE_USER_PUBLIC_KEY,
                                          SILC_ATTRIBUTE_FLAG_VALID,
                                          &obj, sizeof(obj));
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_WHOIS,
                                          ++conn->cmd_ident, 3,
                                          1, nick ? cmd->argv[1] : NULL,
                                          nick ? cmd->argv_lens[1] : 0,
                                          2, tmp ? tmp : NULL, tmp ? 4 : 0,
                                          3, attrs ? attrs->data : NULL,
                                          attrs ? attrs->len : 0);

  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command WHOWAS. This command is used to query history information about
   specific user that used to exist in the network. */

SILC_CLIENT_CMD_FUNC(whowas)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  unsigned char count[4];

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2 || cmd->argc > 3) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /WHOWAS <nickname>[@<server>] [<count>]");
    COMMAND_ERROR((cmd->argc < 2 ? SILC_STATUS_ERR_NOT_ENOUGH_PARAMS :
		   SILC_STATUS_ERR_TOO_MANY_PARAMS));
    goto out;
  }

  if (cmd->argc == 2) {
    buffer = silc_command_payload_encode_va(SILC_COMMAND_WHOWAS,
					    ++conn->cmd_ident, 1,
					    1, cmd->argv[1],
					    cmd->argv_lens[1]);
  } else {
    int c = atoi(cmd->argv[2]);
    memset(count, 0, sizeof(count));
    SILC_PUT32_MSB(c, count);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_WHOWAS,
					    ++conn->cmd_ident, 2,
					    1, cmd->argv[1], cmd->argv_lens[1],
					    2, count, sizeof(count));
  }
  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command IDENTIFY. This command is used to query information about
   specific user, especially ID's.

   NOTE: This command is used only internally by the client library
   and application MUST NOT call this command directly. */

SILC_CLIENT_CMD_FUNC(identify)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  unsigned char count[4];

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2 || cmd->argc > 3)
    goto out;

  if (cmd->argc == 2) {
    buffer = silc_command_payload_encode_va(SILC_COMMAND_IDENTIFY,
					    ++conn->cmd_ident, 1,
					    1, cmd->argv[1],
					    cmd->argv_lens[1]);
  } else {
    int c = atoi(cmd->argv[2]);
    memset(count, 0, sizeof(count));
    SILC_PUT32_MSB(c, count);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_IDENTIFY,
					    ++conn->cmd_ident, 2,
					    1, cmd->argv[1],
					    cmd->argv_lens[1],
					    4, count, sizeof(count));
  }

  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

 out:
  silc_client_command_free(cmd);
}

/* Command NICK. Shows current nickname/sets new nickname on current
   window. */

SILC_CLIENT_CMD_FUNC(nick)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /NICK <nickname>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (!strcmp(conn->nickname, cmd->argv[1]))
    goto out;

  /* Show current nickname */
  if (cmd->argc < 2) {
    if (cmd->conn) {
      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	  "Your nickname is %s on server %s",
	  conn->nickname, conn->remote_host);
    } else {
      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	  "Your nickname is %s", conn->nickname);
    }

    COMMAND(SILC_STATUS_OK);
    goto out;
  }

  if (cmd->argv_lens[1] > 128)
    cmd->argv_lens[1] = 128;

  /* Send the NICK command */
  buffer = silc_command_payload_encode(SILC_COMMAND_NICK, 1,
				       &cmd->argv[1],
				       &cmd->argv_lens[1],
				       &cmd->argv_types[1],
				       ++cmd->conn->cmd_ident);
  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

 out:
  silc_client_command_free(cmd);
}

/* Command LIST. Lists channels on the current server. */

SILC_CLIENT_CMD_FUNC(list)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp = NULL;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc == 2) {
    name = cmd->argv[1];

    /* Get the Channel ID of the channel */
    if (silc_idcache_find_by_name_one(conn->internal->channel_cache,
				      name, &id_cache)) {
      channel = (SilcChannelEntry)id_cache->context;
      idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
    }
  }

  if (!idp)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_LIST,
					    ++conn->cmd_ident, 0);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_LIST,
					    ++conn->cmd_ident, 1,
					    1, idp->data, idp->len);

  silc_client_packet_send(cmd->client, cmd->conn->sock,
			  SILC_PACKET_COMMAND, NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  if (idp)
    silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command TOPIC. Sets/shows topic on a channel. */

SILC_CLIENT_CMD_FUNC(topic)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2 || cmd->argc > 3) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /TOPIC <channel> [<topic>]");
    COMMAND_ERROR((cmd->argc < 2 ? SILC_STATUS_ERR_NOT_ENOUGH_PARAMS :
		   SILC_STATUS_ERR_TOO_MANY_PARAMS));
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_name_one(conn->internal->channel_cache,
				     name, &id_cache)) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Send TOPIC command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  if (cmd->argc > 2)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_TOPIC,
					    ++conn->cmd_ident, 2,
					    1, idp->data, idp->len,
					    2, cmd->argv[2],
					    strlen(cmd->argv[2]));
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_TOPIC,
					    ++conn->cmd_ident, 1,
					    1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command INVITE. Invites specific client to join a channel. This is
   also used to mange the invite list of the channel. */

SILC_CLIENT_CMD_FUNC(invite)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, clidp, chidp, args = NULL;
  SilcPublicKey pubkey = NULL;
  char *nickname = NULL, *name;
  char *invite = NULL;
  unsigned char action[1];

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /INVITE <channel> [<nickname>[@server>]"
	"[+|-[<nickname>[@<server>[!<username>[@hostname>]]]]]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (cmd->argc == 3) {
    if (cmd->argv[2][0] != '+' && cmd->argv[2][0] != '-') {
      if (client->internal->params->nickname_parse)
	client->internal->params->nickname_parse(cmd->argv[2], &nickname);
      else
	nickname = strdup(cmd->argv[2]);

      /* Find client entry */
      client_entry = silc_idlist_get_client(client, conn, nickname,
					    cmd->argv[2], TRUE);
      if (!client_entry) {
	if (cmd->pending) {
	  COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
	  goto out;
	}

	/* Client entry not found, it was requested thus mark this to be
	   pending command. */
	silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY,
				    conn->cmd_ident,
				    silc_client_command_invite,
				    silc_client_command_dup(cmd));
	cmd->pending = 1;
	goto out;
      }
    } else {
      if (cmd->argv[2][0] == '+')
	action[0] = 0x00;
      else
	action[0] = 0x01;

      /* Check if it is public key file to be added to invite list */
      if (!silc_pkcs_load_public_key(cmd->argv[2] + 1, &pubkey,
				     SILC_PKCS_FILE_PEM))
	silc_pkcs_load_public_key(cmd->argv[2] + 1, &pubkey,
				  SILC_PKCS_FILE_BIN);
      invite = cmd->argv[2];
      if (!pubkey)
	invite++;
    }
  }

  if (invite) {
    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    if (pubkey) {
      chidp = silc_pkcs_public_key_payload_encode(pubkey);
      args = silc_argument_payload_encode_one(args, chidp->data,
					      chidp->len, 2);
      silc_buffer_free(chidp);
      silc_pkcs_public_key_free(pubkey);
    } else {
      args = silc_argument_payload_encode_one(args, invite, strlen(invite), 1);
    }
  }

  /* Send the command */
  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  if (client_entry) {
    clidp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);
    buffer = silc_command_payload_encode_va(SILC_COMMAND_INVITE,
					    ++conn->cmd_ident, 4,
					    1, chidp->data, chidp->len,
					    2, clidp->data, clidp->len,
					    3, args ? action : NULL,
					    args ? 1 : 0,
					    4, args ? args->data : NULL,
					    args ? args->len : 0);
    silc_buffer_free(clidp);
  } else {
    buffer = silc_command_payload_encode_va(SILC_COMMAND_INVITE,
					    ++conn->cmd_ident, 3,
					    1, chidp->data, chidp->len,
					    3, args ? action : NULL,
					    args ? 1 : 0,
					    4, args ? args->data : NULL,
					    args ? args->len : 0);
  }

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  silc_buffer_free(args);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
} *QuitInternal;

SILC_TASK_CALLBACK(silc_client_command_quit_cb)
{
  QuitInternal q = (QuitInternal)context;

  /* Close connection */
  q->client->internal->ops->disconnected(q->client, q->conn, 0, NULL);
  silc_client_close_connection(q->client, q->conn->sock->user_data);

  silc_free(q);
}

/* Command QUIT. Closes connection with current server. */

SILC_CLIENT_CMD_FUNC(quit)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcBuffer buffer;
  QuitInternal q;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc > 1)
    buffer = silc_command_payload_encode(SILC_COMMAND_QUIT, cmd->argc - 1,
					 &cmd->argv[1], &cmd->argv_lens[1],
					 &cmd->argv_types[1],
					 ++cmd->conn->cmd_ident);
  else
    buffer = silc_command_payload_encode(SILC_COMMAND_QUIT, 0,
					 NULL, NULL, NULL,
					 ++cmd->conn->cmd_ident);
  silc_client_packet_send(cmd->client, cmd->conn->sock, SILC_PACKET_COMMAND,
			  NULL, 0, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  q = silc_calloc(1, sizeof(*q));
  q->client = cmd->client;
  q->conn = cmd->conn;

  /* Sleep for a while */
  sleep(2);

  /* We quit the connection with little timeout */
  silc_schedule_task_add(cmd->client->schedule, cmd->conn->sock->sock,
			 silc_client_command_quit_cb, (void *)q,
			 1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Timeout callback to remove the killed client from cache */

SILC_TASK_CALLBACK(silc_client_command_kill_remove_later)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcClientEntry target;
  char *nickname = NULL;

  /* Parse the typed nickname. */
  if (client->internal->params->nickname_parse)
    client->internal->params->nickname_parse(cmd->argv[1], &nickname);
  else
    nickname = strdup(cmd->argv[1]);

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname,
				  cmd->argv[1], FALSE);
  if (target)
    /* Remove the client from all channels and free it */
    silc_client_del_client(client, conn, target);

  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* Kill command's pending command callback to actually remove the killed
   client from our local cache. */

SILC_CLIENT_CMD_FUNC(kill_remove)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientCommandReplyContext reply =
    (SilcClientCommandReplyContext)context2;
  SilcStatus status;

  silc_command_get_status(reply->payload, &status, NULL);
  if (status == SILC_STATUS_OK) {
    /* Remove with timeout */
    silc_schedule_task_add(cmd->client->schedule, cmd->conn->sock->sock,
			   silc_client_command_kill_remove_later, context,
			   1, 0, SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    return;
  }

  silc_client_command_free(cmd);
}

/* Command KILL. Router operator can use this command to remove an client
   fromthe SILC Network. */

SILC_CLIENT_CMD_FUNC(kill)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp, auth = NULL;
  SilcClientEntry target;
  char *nickname = NULL, *comment = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /KILL <nickname> [<comment>] [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Parse the typed nickname. */
  if (client->internal->params->nickname_parse)
    client->internal->params->nickname_parse(cmd->argv[1], &nickname);
  else
    nickname = strdup(cmd->argv[1]);

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname,
				  cmd->argv[1], TRUE);
  if (!target) {
    if (cmd->pending) {
      COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
      goto out;
    }

    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY,
				conn->cmd_ident,
				silc_client_command_kill,
				silc_client_command_dup(cmd));
    cmd->pending = 1;
    goto out;
  }

  if (cmd->argc >= 3) {
    if (strcasecmp(cmd->argv[2], "-pubkey"))
      comment = cmd->argv[2];

    if (!strcasecmp(cmd->argv[2], "-pubkey") ||
	(cmd->argc >= 4 && !strcasecmp(cmd->argv[3], "-pubkey"))) {
      /* Encode the public key authentication payload */
      auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
						cmd->client->private_key,
						cmd->client->rng,
						client->sha1hash,
						target->id, SILC_ID_CLIENT);
    }
  }

  /* Send the KILL command to the server */
  idp = silc_id_payload_encode(target->id, SILC_ID_CLIENT);
  buffer =
    silc_command_payload_encode_va(SILC_COMMAND_KILL,
				   ++conn->cmd_ident, 3,
				   1, idp->data, idp->len,
				   2, comment, comment ? strlen(comment) : 0,
				   3, auth ? auth->data : NULL,
				   auth ? auth->len : 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);
  silc_buffer_free(auth);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /* Register a pending callback that will actually remove the killed
     client from our cache. */
  silc_client_command_pending(conn, SILC_COMMAND_KILL, conn->cmd_ident,
			      silc_client_command_kill_remove,
			      silc_client_command_dup(cmd));

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* Command INFO. Request information about specific server. If specific
   server is not provided the current server is used. */

SILC_CLIENT_CMD_FUNC(info)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  char *name = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc == 2)
    name = strdup(cmd->argv[1]);

  /* Send the command */
  if (name)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_INFO,
    					    ++conn->cmd_ident, 1,
					    1, name, strlen(name));
  else
    buffer = silc_command_payload_encode(SILC_COMMAND_INFO, 0,
					 NULL, NULL, NULL, ++conn->cmd_ident);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  if (name)
    silc_free(name);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command STATS. Shows server and network statistics. */

SILC_CLIENT_CMD_FUNC(stats)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  idp = silc_id_payload_encode(conn->remote_id, SILC_ID_SERVER);

  /* Send the command */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_STATS,
					  ++conn->cmd_ident, 1,
					  SILC_ID_SERVER, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command PING. Sends ping to server. This is used to test the
   communication channel. */

SILC_CLIENT_CMD_FUNC(ping)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp;
  void *id;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  idp = silc_id_payload_encode(conn->remote_id, SILC_ID_SERVER);

  /* Send the command */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_PING,
  					  ++conn->cmd_ident, 1,
					  1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  id = silc_id_str2id(conn->remote_id_data, conn->remote_id_data_len,
		      SILC_ID_SERVER);
  if (!id) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  /* Start counting time */
  for (i = 0; i < conn->internal->ping_count; i++) {
    if (conn->internal->ping[i].dest_id == NULL) {
      conn->internal->ping[i].start_time = time(NULL);
      conn->internal->ping[i].dest_id = id;
      conn->internal->ping[i].dest_name = strdup(conn->remote_host);
      break;
    }
  }
  if (i >= conn->internal->ping_count) {
    i = conn->internal->ping_count;
    conn->internal->ping =
      silc_realloc(conn->internal->ping,
		   sizeof(*conn->internal->ping) * (i + 1));
    conn->internal->ping[i].start_time = time(NULL);
    conn->internal->ping[i].dest_id = id;
    conn->internal->ping[i].dest_name = strdup(conn->remote_host);
    conn->internal->ping_count++;
  }

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command JOIN. Joins to a channel. */

SILC_CLIENT_CMD_FUNC(join)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp, auth = NULL, cauth = NULL;
  char *name, *passphrase = NULL, *pu8, *cipher = NULL, *hmac = NULL;
  int i, passphrase_len = 0;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* See if we have joined to the requested channel already */
  channel = silc_client_get_channel(cmd->client, conn, cmd->argv[1]);
  if (channel && silc_client_on_channel(channel, conn->local_entry))
    goto out;

  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);

  if (cmd->argv_lens[1] > 256)
    cmd->argv_lens[1] = 256;

  name = cmd->argv[1];

  for (i = 2; i < cmd->argc; i++) {
    if (!strcasecmp(cmd->argv[i], "-cipher") && cmd->argc > i + 1) {
      cipher = cmd->argv[i + 1];
      i++;
    } else if (!strcasecmp(cmd->argv[i], "-hmac") && cmd->argc > i + 1) {
      hmac = cmd->argv[i + 1];
      i++;
    } else if (!strcasecmp(cmd->argv[i], "-founder")) {
      auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
						cmd->client->private_key,
						cmd->client->rng,
						cmd->client->sha1hash,
						conn->local_id,
						SILC_ID_CLIENT);
      i++;
    } else if (!strcasecmp(cmd->argv[i], "-auth")) {
      SilcPublicKey pubkey = cmd->client->public_key;
      SilcPrivateKey privkey = cmd->client->private_key;
      unsigned char *pk, pkhash[20], *pubdata;
      SilcUInt32 pk_len;

      if (cmd->argc >= i + 3) {
	char *pass = "";
	if (cmd->argc >= i + 4) {
	  pass = cmd->argv[i + 3];
	  i++;
	}
	if (!silc_load_key_pair(cmd->argv[i + 1], cmd->argv[i + 2], pass,
				NULL, &pubkey, &privkey)) {
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	      "Could not load key pair, check your arguments");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	i += 2;
      }

      pk = silc_pkcs_public_key_encode(pubkey, &pk_len);
      silc_hash_make(cmd->client->sha1hash, pk, pk_len, pkhash);
      silc_free(pk);
      pubdata = silc_rng_get_rn_data(cmd->client->rng, 128);
      memcpy(pubdata, pkhash, 20);
      cauth = silc_auth_public_key_auth_generate_wpub(pubkey, privkey,
						      pubdata, 128,
						      cmd->client->sha1hash,
						      conn->local_id,
						      SILC_ID_CLIENT);
      memset(pubdata, 0, 128);
      silc_free(pubdata);
      i++;
    } else {
      /* Passphrases must be UTF-8 encoded, so encode if it is not */
      if (!silc_utf8_valid(cmd->argv[i], cmd->argv_lens[i])) {
	passphrase_len = silc_utf8_encoded_len(cmd->argv[i],
					       cmd->argv_lens[i], 0);
	pu8 = silc_calloc(passphrase_len, sizeof(*pu8));
	passphrase_len = silc_utf8_encode(cmd->argv[i], cmd->argv_lens[i],
					  0, pu8, passphrase_len);
	passphrase = pu8;
      } else {
	passphrase = strdup(cmd->argv[i]);
	passphrase_len = cmd->argv_lens[i];
      }
    }
  }

  /* Send JOIN command to the server */
  buffer =
    silc_command_payload_encode_va(SILC_COMMAND_JOIN, ++conn->cmd_ident, 7,
				   1, name, strlen(name),
				   2, idp->data, idp->len,
				   3, passphrase, passphrase_len,
				   4, cipher, cipher ? strlen(cipher) : 0,
				   5, hmac, hmac ? strlen(hmac) : 0,
				   6, auth ? auth->data : NULL,
				   auth ? auth->len : 0,
				   7, cauth ? cauth->data : NULL,
				   cauth ? cauth->len : 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);
  silc_buffer_free(auth);
  silc_buffer_free(cauth);
  if (passphrase)
    memset(passphrase, 0, strlen(passphrase));
  silc_free(passphrase);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* MOTD command. Requests motd from server. */

SILC_CLIENT_CMD_FUNC(motd)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 1 || cmd->argc > 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /MOTD [<server>]");
    COMMAND_ERROR((cmd->argc < 1 ? SILC_STATUS_ERR_NOT_ENOUGH_PARAMS :
		   SILC_STATUS_ERR_TOO_MANY_PARAMS));
    goto out;
  }

  /* Send TOPIC command to the server */
  if (cmd->argc == 1)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_MOTD,
    					    ++conn->cmd_ident, 1,
					    1, conn->remote_host,
					    strlen(conn->remote_host));
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_MOTD,
    					    ++conn->cmd_ident, 1,
					    1, cmd->argv[1],
					    cmd->argv_lens[1]);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* UMODE. Set/unset user mode in SILC. This is used mainly to unset the
   modes as client cannot set itself server/router operator privileges. */

SILC_CLIENT_CMD_FUNC(umode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp;
  unsigned char *cp, modebuf[4];
  SilcUInt32 mode, add, len;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /UMODE +|-<modes>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  mode = conn->local_entry->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[1][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Parse mode */
  cp = cmd->argv[1] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'a':
      if (add) {
	mode = 0;
	mode |= SILC_UMODE_SERVER_OPERATOR;
	mode |= SILC_UMODE_ROUTER_OPERATOR;
	mode |= SILC_UMODE_GONE;
	mode |= SILC_UMODE_INDISPOSED;
	mode |= SILC_UMODE_BUSY;
	mode |= SILC_UMODE_PAGE;
	mode |= SILC_UMODE_HYPER;
	mode |= SILC_UMODE_ROBOT;
	mode |= SILC_UMODE_BLOCK_PRIVMSG;
	mode |= SILC_UMODE_REJECT_WATCHING;
      } else {
	mode = SILC_UMODE_NONE;
      }
      break;
    case 's':
      if (add)
	mode |= SILC_UMODE_SERVER_OPERATOR;
      else
	mode &= ~SILC_UMODE_SERVER_OPERATOR;
      break;
    case 'r':
      if (add)
	mode |= SILC_UMODE_ROUTER_OPERATOR;
      else
	mode &= ~SILC_UMODE_ROUTER_OPERATOR;
      break;
    case 'g':
      if (add)
	mode |= SILC_UMODE_GONE;
      else
	mode &= ~SILC_UMODE_GONE;
      break;
    case 'i':
      if (add)
	mode |= SILC_UMODE_INDISPOSED;
      else
	mode &= ~SILC_UMODE_INDISPOSED;
      break;
    case 'b':
      if (add)
	mode |= SILC_UMODE_BUSY;
      else
	mode &= ~SILC_UMODE_BUSY;
      break;
    case 'p':
      if (add)
	mode |= SILC_UMODE_PAGE;
      else
	mode &= ~SILC_UMODE_PAGE;
      break;
    case 'h':
      if (add)
	mode |= SILC_UMODE_HYPER;
      else
	mode &= ~SILC_UMODE_HYPER;
      break;
    case 't':
      if (add)
	mode |= SILC_UMODE_ROBOT;
      else
	mode &= ~SILC_UMODE_ROBOT;
      break;
    case 'P':
      if (add)
	mode |= SILC_UMODE_BLOCK_PRIVMSG;
      else
	mode &= ~SILC_UMODE_BLOCK_PRIVMSG;
      break;
    case 'w':
      if (add)
	mode |= SILC_UMODE_REJECT_WATCHING;
      else
	mode &= ~SILC_UMODE_REJECT_WATCHING;
      break;
    case 'I':
      if (add)
	mode |= SILC_UMODE_BLOCK_INVITE;
      else
	mode &= ~SILC_UMODE_BLOCK_INVITE;
      break;
    default:
      COMMAND_ERROR(SILC_STATUS_ERR_UNKNOWN_MODE);
      goto out;
      break;
    }
  }

  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);
  SILC_PUT32_MSB(mode, modebuf);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  buffer =
    silc_command_payload_encode_va(SILC_COMMAND_UMODE, ++conn->cmd_ident, 2,
				   1, idp->data, idp->len,
				   2, modebuf, sizeof(modebuf));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* CMODE command. Sets channel mode. Modes that does not require any arguments
   can be set several at once. Those modes that require argument must be set
   separately (unless set with modes that does not require arguments). */

SILC_CLIENT_CMD_FUNC(cmode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, chidp, auth = NULL, pk = NULL;
  unsigned char *name, *cp, modebuf[4], tmp[4], *arg = NULL;
  SilcUInt32 mode, add, type, len, arg_len = 0;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 3) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  mode = channel->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[2][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Argument type to be sent to server */
  type = 0;

  /* Parse mode */
  cp = cmd->argv[2] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'p':
      if (add)
	mode |= SILC_CHANNEL_MODE_PRIVATE;
      else
	mode &= ~SILC_CHANNEL_MODE_PRIVATE;
      break;
    case 's':
      if (add)
	mode |= SILC_CHANNEL_MODE_SECRET;
      else
	mode &= ~SILC_CHANNEL_MODE_SECRET;
      break;
    case 'k':
      if (add)
	mode |= SILC_CHANNEL_MODE_PRIVKEY;
      else
	mode &= ~SILC_CHANNEL_MODE_PRIVKEY;
      break;
    case 'i':
      if (add)
	mode |= SILC_CHANNEL_MODE_INVITE;
      else
	mode &= ~SILC_CHANNEL_MODE_INVITE;
      break;
    case 't':
      if (add)
	mode |= SILC_CHANNEL_MODE_TOPIC;
      else
	mode &= ~SILC_CHANNEL_MODE_TOPIC;
      break;
    case 'm':
      if (add)
	mode |= SILC_CHANNEL_MODE_SILENCE_USERS;
      else
	mode &= ~SILC_CHANNEL_MODE_SILENCE_USERS;
      break;
    case 'M':
      if (add)
	mode |= SILC_CHANNEL_MODE_SILENCE_OPERS;
      else
	mode &= ~SILC_CHANNEL_MODE_SILENCE_OPERS;
      break;
    case 'l':
      if (add) {
	int ll;
	mode |= SILC_CHANNEL_MODE_ULIMIT;
	type = 3;
	if (cmd->argc < 4) {
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	ll = atoi(cmd->argv[3]);
	SILC_PUT32_MSB(ll, tmp);
	arg = tmp;
	arg_len = 4;
      } else {
	mode &= ~SILC_CHANNEL_MODE_ULIMIT;
      }
      break;
    case 'a':
      if (add) {
	mode |= SILC_CHANNEL_MODE_PASSPHRASE;
	type = 4;
	if (cmd->argc < 4) {
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_PASSPHRASE;
      }
      break;
    case 'c':
      if (add) {
	mode |= SILC_CHANNEL_MODE_CIPHER;
	type = 5;
	if (cmd->argc < 4) {
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_CIPHER;
      }
      break;
    case 'h':
      if (add) {
	mode |= SILC_CHANNEL_MODE_HMAC;
	type = 6;
	if (cmd->argc < 4) {
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_HMAC;
      }
      break;
    case 'f':
      if (add) {
	SilcPublicKey pubkey = cmd->client->public_key;
	SilcPrivateKey privkey = cmd->client->private_key;

	mode |= SILC_CHANNEL_MODE_FOUNDER_AUTH;
	type = 7;

	if (cmd->argc >= 5) {
	  char *pass = "";
	  if (cmd->argc >= 6)
	    pass = cmd->argv[5];
	  if (!silc_load_key_pair(cmd->argv[3], cmd->argv[4], pass,
				  NULL, &pubkey, &privkey)) {
	    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
		"Could not load key pair, check your arguments");
	    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	    goto out;
	  }
	}

	pk = silc_pkcs_public_key_payload_encode(pubkey);
	auth = silc_auth_public_key_auth_generate(pubkey, privkey,
						  cmd->client->rng,
						  cmd->client->sha1hash,
						  conn->local_id,
						  SILC_ID_CLIENT);
	arg = auth->data;
	arg_len = auth->len;
      } else {
	mode &= ~SILC_CHANNEL_MODE_FOUNDER_AUTH;
      }
      break;
    case 'C':
      if (add) {
	int k;
	bool chadd = FALSE;
	SilcPublicKey chpk = NULL;

	mode |= SILC_CHANNEL_MODE_CHANNEL_AUTH;
	type = 9;

	if (cmd->argc == 3) {
	  /* Send empty command to receive the public key list. */
	  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
	  silc_client_command_send(cmd->client, conn, SILC_COMMAND_CMODE,
				   0, 1, 1, chidp->data, chidp->len);
	  silc_buffer_free(chidp);

	  /* Notify application */
	  COMMAND(SILC_STATUS_OK);
	  goto out;
	}

	if (cmd->argc >= 4) {
	  auth = silc_buffer_alloc_size(2);
	  silc_buffer_format(auth,
			     SILC_STR_UI_SHORT(cmd->argc - 3),
			     SILC_STR_END);
	}

	for (k = 3; k < cmd->argc; k++) {
	  if (cmd->argv[k][0] == '+')
	    chadd = TRUE;
	  if (!silc_pkcs_load_public_key(cmd->argv[k] + 1, &chpk,
					 SILC_PKCS_FILE_PEM))
	    if (!silc_pkcs_load_public_key(cmd->argv[k] + 1, &chpk,
					   SILC_PKCS_FILE_BIN)) {
	      SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
		  "Could not load public key %s, check the filename",
		  cmd->argv[k]);
	      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	      silc_buffer_free(auth);
	      goto out;
	    }

	  if (chpk) {
	    pk = silc_pkcs_public_key_payload_encode(chpk);
	    auth = silc_argument_payload_encode_one(auth, pk->data, pk->len,
						    chadd ? 0x00 : 0x01);
	    silc_pkcs_public_key_free(chpk);
	    silc_buffer_free(pk);
	    pk = NULL;
	  }
	}

	arg = auth->data;
	arg_len = auth->len;
      } else {
	mode &= ~SILC_CHANNEL_MODE_CHANNEL_AUTH;
      }
      break;
    default:
      COMMAND_ERROR(SILC_STATUS_ERR_UNKNOWN_MODE);
      goto out;
      break;
    }
  }

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(mode, modebuf);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  if (type && arg) {
    buffer =
      silc_command_payload_encode_va(SILC_COMMAND_CMODE, ++conn->cmd_ident, 4,
				     1, chidp->data, chidp->len,
				     2, modebuf, sizeof(modebuf),
				     type, arg, arg_len,
				     8, pk ? pk->data : NULL,
				     pk ? pk->len : 0);
  } else {
    buffer =
      silc_command_payload_encode_va(SILC_COMMAND_CMODE, ++conn->cmd_ident, 2,
				     1, chidp->data, chidp->len,
				     2, modebuf, sizeof(modebuf));
  }

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  silc_buffer_free(auth);
  silc_buffer_free(pk);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* CUMODE command. Changes client's mode on a channel. */

SILC_CLIENT_CMD_FUNC(cumode)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcClientEntry client_entry;
  SilcBuffer buffer, clidp, chidp, auth = NULL;
  unsigned char *name, *cp, modebuf[4];
  SilcUInt32 mode = 0, add, len;
  char *nickname = NULL;
  int i;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 4) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /CUMODE <channel> +|-<modes> <nickname>[@<server>]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (client->internal->params->nickname_parse)
    client->internal->params->nickname_parse(cmd->argv[3], &nickname);
  else
    nickname = strdup(cmd->argv[3]);

  /* Find client entry */
  client_entry = silc_idlist_get_client(cmd->client, conn, nickname,
					cmd->argv[3], TRUE);
  if (!client_entry) {
    if (cmd->pending) {
      COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
      goto out;
    }

    /* Client entry not found, it was requested thus mark this to be
       pending command. */
    silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY,
				conn->cmd_ident,
				silc_client_command_cumode,
				silc_client_command_dup(cmd));
    cmd->pending = 1;
    goto out;
  }

  /* Get the current mode */
  chu = silc_client_on_channel(channel, client_entry);
  if (chu)
    mode = chu->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[2][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Parse mode */
  cp = cmd->argv[2] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'a':
      if (add) {
	mode |= SILC_CHANNEL_UMODE_CHANFO;
	mode |= SILC_CHANNEL_UMODE_CHANOP;
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      } else {
	mode = SILC_CHANNEL_UMODE_NONE;
      }
      break;
    case 'f':
      if (add) {
	SilcPublicKey pubkey = cmd->client->public_key;
	SilcPrivateKey privkey = cmd->client->private_key;

	if (cmd->argc >= 6) {
	  char *pass = "";
	  if (cmd->argc >= 7)
	    pass = cmd->argv[6];
	  if (!silc_load_key_pair(cmd->argv[4], cmd->argv[5], pass,
				  NULL, &pubkey, &privkey)) {
	    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
		"Could not load key pair, check your arguments");
	    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	    goto out;
	  }
	}

	auth = silc_auth_public_key_auth_generate(pubkey, privkey,
						  cmd->client->rng,
						  cmd->client->sha1hash,
						  conn->local_id,
						  SILC_ID_CLIENT);
	mode |= SILC_CHANNEL_UMODE_CHANFO;
      } else {
	mode &= ~SILC_CHANNEL_UMODE_CHANFO;
      }
      break;
    case 'o':
      if (add)
	mode |= SILC_CHANNEL_UMODE_CHANOP;
      else
	mode &= ~SILC_CHANNEL_UMODE_CHANOP;
      break;
    case 'b':
      if (add)
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
      else
	mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
      break;
    case 'u':
      if (add)
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
      else
	mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
      break;
    case 'r':
      if (add)
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      else
	mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      break;
    case 'q':
      if (add)
	mode |= SILC_CHANNEL_UMODE_QUIET;
      else
	mode &= ~SILC_CHANNEL_UMODE_QUIET;
      break;
    default:
      COMMAND_ERROR(SILC_STATUS_ERR_UNKNOWN_MODE);
      goto out;
      break;
    }
  }

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(mode, modebuf);
  clidp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_CUMODE,
  					  ++conn->cmd_ident,
					  auth ? 4 : 3,
					  1, chidp->data, chidp->len,
					  2, modebuf, 4,
					  3, clidp->data, clidp->len,
					  4, auth ? auth->data : NULL,
					  auth ? auth->len : 0);

  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  silc_buffer_free(clidp);
  if (auth)
    silc_buffer_free(auth);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* KICK command. Kicks a client out of channel. */

SILC_CLIENT_CMD_FUNC(kick)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClient client = cmd->client;
  SilcClientConnection conn = cmd->conn;
  SilcIDCacheEntry id_cache = NULL;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp, idp2;
  SilcClientEntry target;
  char *name;
  char *nickname = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 3) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /KICK <channel> <nickname> [<comment>]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get the Channel ID of the channel */
  if (!silc_idcache_find_by_name_one(conn->internal->channel_cache,
				     name, &id_cache)) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  channel = (SilcChannelEntry)id_cache->context;

  /* Parse the typed nickname. */
  if (client->internal->params->nickname_parse)
    client->internal->params->nickname_parse(cmd->argv[2], &nickname);
  else
    nickname = strdup(cmd->argv[2]);

  /* Get the target client */
  target = silc_idlist_get_client(cmd->client, conn, nickname,
				  cmd->argv[2], FALSE);
  if (!target) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"No such client: %s", cmd->argv[2]);
    COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
    goto out;
  }

  /* Send KICK command to the server */
  idp = silc_id_payload_encode(id_cache->id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode(target->id, SILC_ID_CLIENT);
  if (cmd->argc == 3)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_KICK,
    					    ++conn->cmd_ident, 2,
					    1, idp->data, idp->len,
					    2, idp2->data, idp2->len);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_KICK,
    					    ++conn->cmd_ident, 3,
					    1, idp->data, idp->len,
					    2, idp2->data, idp2->len,
					    3, cmd->argv[3],
					    strlen(cmd->argv[3]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);
  silc_buffer_free(idp2);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

static void silc_client_command_oper_send(unsigned char *data,
					  SilcUInt32 data_len, void *context)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, auth;

  if (cmd->argc >= 3) {
    /* Encode the public key authentication payload */
    auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
					      cmd->client->private_key,
					      cmd->client->rng,
					      conn->internal->hash,
					      conn->local_id,
					      SILC_ID_CLIENT);
  } else {
    /* Encode the password authentication payload */
    auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
				    data, data_len);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_OPER,
  					  ++conn->cmd_ident, 2,
					  1, cmd->argv[1],
					  strlen(cmd->argv[1]),
					  2, auth ? auth->data : NULL,
					  auth ? auth->len : 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);

  silc_buffer_free(buffer);
  silc_buffer_clear(auth);
  silc_buffer_free(auth);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);
}

/* OPER command. Used to obtain server operator privileges. */

SILC_CLIENT_CMD_FUNC(oper)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /OPER <username> [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argc < 3) {
    /* Get passphrase */
    cmd->client->internal->ops->ask_passphrase(cmd->client, conn,
				     silc_client_command_oper_send,
				     context);
    return;
  }

  silc_client_command_oper_send(NULL, 0, context);

 out:
  silc_client_command_free(cmd);
}

static void silc_client_command_silcoper_send(unsigned char *data,
					      SilcUInt32 data_len,
					      void *context)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, auth;

  if (cmd->argc >= 3) {
    /* Encode the public key authentication payload */
    auth = silc_auth_public_key_auth_generate(cmd->client->public_key,
					      cmd->client->private_key,
					      cmd->client->rng,
					      conn->internal->hash,
					      conn->local_id,
					      SILC_ID_CLIENT);
  } else {
    /* Encode the password authentication payload */
    auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
				    data, data_len);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_SILCOPER,
  					  ++conn->cmd_ident, 2,
					  1, cmd->argv[1],
					  strlen(cmd->argv[1]),
					  2, auth ? auth->data : NULL,
					  auth ? auth->len : 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);

  silc_buffer_free(buffer);
  silc_buffer_clear(auth);
  silc_buffer_free(auth);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);
}

/* SILCOPER command. Used to obtain router operator privileges. */

SILC_CLIENT_CMD_FUNC(silcoper)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /SILCOPER <username> [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argc < 3) {
    /* Get passphrase */
    cmd->client->internal->ops->ask_passphrase(cmd->client, conn,
				     silc_client_command_silcoper_send,
				     context);
    return;
  }

  silc_client_command_silcoper_send(NULL, 0, context);

 out:
  silc_client_command_free(cmd);
}

/* Command BAN. This is used to manage the ban list of the channel. */

SILC_CLIENT_CMD_FUNC(ban)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, chidp, args = NULL;
  char *name, *ban = NULL;
  unsigned char action[1];
  SilcPublicKey pubkey = NULL;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /BAN <channel> "
	"[+|-[<nickname>[@<server>[!<username>[@hostname>]]]]]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(cmd->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  if (cmd->argc == 3) {
    if (cmd->argv[2][0] == '+')
      action[0] = 0x00;
    else
      action[0] = 0x01;

    /* Check if it is public key file to be added to invite list */
    if (!silc_pkcs_load_public_key(cmd->argv[2] + 1, &pubkey,
				   SILC_PKCS_FILE_PEM))
      silc_pkcs_load_public_key(cmd->argv[2] + 1, &pubkey,
				SILC_PKCS_FILE_BIN);
    ban = cmd->argv[2];
    if (!pubkey)
      ban++;
  }

  if (ban) {
    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    if (pubkey) {
      chidp = silc_pkcs_public_key_payload_encode(pubkey);
      args = silc_argument_payload_encode_one(args, chidp->data,
					      chidp->len, 2);
      silc_buffer_free(chidp);
      silc_pkcs_public_key_free(pubkey);
    } else {
      args = silc_argument_payload_encode_one(args, ban, strlen(ban), 1);
    }
  }

  chidp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);

  /* Send the command */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_BAN,
					  ++conn->cmd_ident, 3,
					  1, chidp->data, chidp->len,
					  2, args ? action : NULL,
					  args ? 1 : 0,
					  3, args ? args->data : NULL,
					  args ? args->len : 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(chidp);
  silc_buffer_free(args);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command DETACH. This is used to detach from the server */

SILC_CLIENT_CMD_FUNC(detach)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_DETACH,
					  ++conn->cmd_ident, 0);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command WATCH. */

SILC_CLIENT_CMD_FUNC(watch)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer, idp = NULL, args = NULL;
  int type = 0;
  const char *pubkey = NULL;
  bool pubkey_add = TRUE;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 3) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  idp = silc_id_payload_encode(conn->local_id, SILC_ID_CLIENT);

  if (!strcasecmp(cmd->argv[1], "-add")) {
    type = 2;
  } else if (!strcasecmp(cmd->argv[1], "-del")) {
    type = 3;
  } else if (!strcasecmp(cmd->argv[1], "-pubkey") && cmd->argc >= 3) {
    type = 4;
    pubkey = cmd->argv[2] + 1;
    if (cmd->argv[2][0] == '-')
      pubkey_add = FALSE;
  } else {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (pubkey) {
    SilcPublicKey pk;

    if (!silc_pkcs_load_public_key(pubkey, &pk, SILC_PKCS_FILE_PEM)) {
      if (!silc_pkcs_load_public_key(pubkey, &pk, SILC_PKCS_FILE_BIN)) {
	SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR,
	    "Could not load public key %s, check the filename",
	    pubkey);
	COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	goto out;
      }
    }

    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    buffer = silc_pkcs_public_key_payload_encode(pk);
    args = silc_argument_payload_encode_one(args, buffer->data, buffer->len,
					    pubkey_add ? 0x00 : 0x01);
    silc_buffer_free(buffer);
    silc_pkcs_public_key_free(pk);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_WATCH,
					  ++conn->cmd_ident, 2,
					  1, idp->data, idp->len,
					  type,
					  pubkey ? args->data : cmd->argv[2],
					  pubkey ? args->len :
					  cmd->argv_lens[2]);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(args);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  if (idp)
    silc_buffer_free(idp);
  silc_client_command_free(cmd);
}

/* LEAVE command. Leaves a channel. Client removes itself from a channel. */

SILC_CLIENT_CMD_FUNC(leave)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcChannelEntry channel;
  SilcBuffer buffer, idp;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc != 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /LEAVE <channel>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  /* Get the channel entry */
  channel = silc_client_get_channel(cmd->client, conn, name);
  if (!channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Send LEAVE command to the server */
  idp = silc_id_payload_encode(channel->id, SILC_ID_CHANNEL);
  buffer = silc_command_payload_encode_va(SILC_COMMAND_LEAVE,
  					  ++conn->cmd_ident, 1,
					  1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  if (conn->current_channel == channel)
    conn->current_channel = NULL;

 out:
  silc_client_command_free(cmd);
}

/* Command USERS. Requests the USERS of the clients joined on requested
   channel. */

SILC_CLIENT_CMD_FUNC(users)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  char *name;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc != 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /USERS <channel>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  /* Send USERS command to the server */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_USERS,
					  ++conn->cmd_ident, 1,
					  2, name, strlen(name));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND,
			  NULL, 0, NULL, NULL, buffer->data,
			  buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Command GETKEY. Used to fetch remote client's public key. */

SILC_CLIENT_CMD_FUNC(getkey)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = cmd->client;
  SilcClientEntry client_entry = NULL;
  SilcServerEntry server_entry = NULL;
  char *nickname = NULL;
  SilcBuffer idp, buffer;

  SILC_LOG_DEBUG(("Start"));

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_INFO,
		     "Usage: /GETKEY <nickname or server name>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* Parse the typed nickname. */
  if (client->internal->params->nickname_parse)
    client->internal->params->nickname_parse(cmd->argv[1], &nickname);
  else
    nickname = strdup(cmd->argv[1]);

  /* Find client entry */
  client_entry = silc_idlist_get_client(client, conn, nickname, cmd->argv[1],
					FALSE);
  if (!client_entry) {
    /* Check whether user requested server actually */
    server_entry = silc_client_get_server(client, conn, cmd->argv[1]);

    if (!server_entry) {
      /* No. what ever user wants we don't have it, so resolve it. We
	 will first try to resolve the client, and if that fails then
	 we'll try to resolve the server. */

      if (!cmd->pending) {
	/* This will send the IDENTIFY command for nickname */
	silc_idlist_get_client(client, conn, nickname, cmd->argv[1], TRUE);
	silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY,
				    conn->cmd_ident,
				    silc_client_command_getkey,
				    silc_client_command_dup(cmd));
	cmd->pending = 1;
	goto out;
      } else {
	SilcClientCommandReplyContext reply =
	  (SilcClientCommandReplyContext)context2;
	SilcStatus error;

	/* If nickname was not found, then resolve the server. */
	silc_command_get_status(reply->payload, NULL, &error);
	if (error == SILC_STATUS_ERR_NO_SUCH_NICK) {
	  /* This sends the IDENTIFY command to resolve the server. */
	  silc_client_command_register(client, SILC_COMMAND_IDENTIFY,
				       NULL, NULL,
				       silc_client_command_reply_identify_i, 0,
				       ++conn->cmd_ident);
	  silc_client_command_send(client, conn, SILC_COMMAND_IDENTIFY,
				   conn->cmd_ident, 1,
				   2, cmd->argv[1], cmd->argv_lens[1]);
	  silc_client_command_pending(conn, SILC_COMMAND_IDENTIFY,
				      conn->cmd_ident,
				      silc_client_command_getkey,
				      silc_client_command_dup(cmd));
	  goto out;
	}

	/* If server was not found, then we've resolved both nickname and
	   server and did not find anybody. */
	if (error == SILC_STATUS_ERR_NO_SUCH_SERVER) {
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR, "%s",
	     silc_get_status_message(SILC_STATUS_ERR_NO_SUCH_NICK));
	  SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_ERROR, "%s",
           silc_get_status_message(error));
	  COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
	  goto out;
	}

	COMMAND_ERROR(error);
	goto out;
      }
    }

    idp = silc_id_payload_encode(server_entry->server_id, SILC_ID_SERVER);
  } else {
    idp = silc_id_payload_encode(client_entry->id, SILC_ID_CLIENT);
  }

  buffer = silc_command_payload_encode_va(SILC_COMMAND_GETKEY,
  					  ++conn->cmd_ident, 1,
					  1, idp->data, idp->len);
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);
  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_free(nickname);
  silc_client_command_free(cmd);
}

/* Register a new command indicated by the `command' to the SILC client.
   The `name' is optional command name.  If provided the command may be
   searched using the silc_client_command_find by that name.  The
   `command_function' is the function to be called when the command is
   executed, and the `command_reply_function' is the function to be
   called after the server has sent reply back to the command.

   The `ident' is optional identifier for the command.  If non-zero
   the `command_reply_function' for the command type `command' will be
   called only if the command reply sent by server includes the
   command identifier `ident'. Application usually does not need it
   and set it to zero value. */

bool silc_client_command_register(SilcClient client,
				  SilcCommand command,
				  const char *name,
				  SilcCommandCb command_function,
				  SilcCommandCb command_reply_function,
				  SilcUInt8 max_args,
				  SilcUInt16 ident)
{
  SilcClientCommand cmd;

  cmd = silc_calloc(1, sizeof(*cmd));
  cmd->cmd = command;
  cmd->command = command_function;
  cmd->reply = command_reply_function;
  cmd->name = name ? strdup(name) : NULL;
  cmd->max_args = max_args;
  cmd->ident = ident;

  silc_list_add(client->internal->commands, cmd);

  return TRUE;
}

/* Unregister a command indicated by the `command' with command function
   `command_function' and command reply function `command_reply_function'.
   Returns TRUE if the command was found and unregistered. */

bool silc_client_command_unregister(SilcClient client,
				    SilcCommand command,
				    SilcCommandCb command_function,
				    SilcCommandCb command_reply_function,
				    SilcUInt16 ident)
{
  SilcClientCommand cmd;

  silc_list_start(client->internal->commands);
  while ((cmd = silc_list_get(client->internal->commands)) != SILC_LIST_END) {
    if (cmd->cmd == command && cmd->command == command_function &&
	cmd->reply == command_reply_function && cmd->ident == ident) {
      silc_list_del(client->internal->commands, cmd);
      silc_free(cmd->name);
      silc_free(cmd);
      return TRUE;
    }
  }

  return FALSE;
}

/* Private range commands, specific to this implementation (and compatible
   with SILC Server). */

/* CONNECT command. Connects the server to another server. */

SILC_CLIENT_CMD_FUNC(connect)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  unsigned char port[4];
  SilcUInt32 tmp;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /CONNECT <server> [<port>]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argc == 3) {
    tmp = atoi(cmd->argv[2]);
    SILC_PUT32_MSB(tmp, port);
  }

  if (cmd->argc == 3)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_PRIV_CONNECT,
    					    ++conn->cmd_ident, 2,
					    1, cmd->argv[1],
					    strlen(cmd->argv[1]),
					    2, port, 4);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_PRIV_CONNECT,
    					    ++conn->cmd_ident, 1,
					    1, cmd->argv[1],
					    strlen(cmd->argv[1]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}


/* CLOSE command. Close server connection to the remote server */

SILC_CLIENT_CMD_FUNC(close)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  unsigned char port[4];
  SilcUInt32 tmp;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  if (cmd->argc < 2) {
    SAY(cmd->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /CLOSE <server> [<port>]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argc == 3) {
    tmp = atoi(cmd->argv[2]);
    SILC_PUT32_MSB(tmp, port);
  }

  if (cmd->argc == 3)
    buffer = silc_command_payload_encode_va(SILC_COMMAND_PRIV_CLOSE,
    					    ++conn->cmd_ident, 2,
					    1, cmd->argv[1],
					    strlen(cmd->argv[1]),
					    2, port, 4);
  else
    buffer = silc_command_payload_encode_va(SILC_COMMAND_PRIV_CLOSE,
    					    ++conn->cmd_ident, 1,
					    1, cmd->argv[1],
					    strlen(cmd->argv[1]));
  silc_client_packet_send(cmd->client, conn->sock, SILC_PACKET_COMMAND, NULL,
			  0, NULL, NULL, buffer->data, buffer->len, TRUE);
  silc_buffer_free(buffer);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* SHUTDOWN command. Shutdowns the server. */

SILC_CLIENT_CMD_FUNC(shutdown)
{
  SilcClientCommandContext cmd = (SilcClientCommandContext)context;

  if (!cmd->conn) {
    SILC_NOT_CONNECTED(cmd->client, cmd->conn);
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_REGISTERED);
    goto out;
  }

  /* Send the command */
  silc_client_command_send(cmd->client, cmd->conn,
			   SILC_COMMAND_PRIV_SHUTDOWN, 0, 0);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

 out:
  silc_client_command_free(cmd);
}

/* Register all default commands provided by the client library for the
   application. */

void silc_client_commands_register(SilcClient client)
{
  silc_list_init(client->internal->commands, struct SilcClientCommandStruct,
		 next);

  SILC_CLIENT_CMD(whois, WHOIS, "WHOIS", 5);
  SILC_CLIENT_CMD(whowas, WHOWAS, "WHOWAS", 3);
  SILC_CLIENT_CMD(identify, IDENTIFY, "IDENTIFY", 3);
  SILC_CLIENT_CMD(nick, NICK, "NICK", 2);
  SILC_CLIENT_CMD(list, LIST, "LIST", 2);
  SILC_CLIENT_CMD(topic, TOPIC, "TOPIC", 3);
  SILC_CLIENT_CMD(invite, INVITE, "INVITE", 3);
  SILC_CLIENT_CMD(quit, QUIT, "QUIT", 2);
  SILC_CLIENT_CMD(kill, KILL, "KILL", 4);
  SILC_CLIENT_CMD(info, INFO, "INFO", 2);
  SILC_CLIENT_CMD(stats, STATS, "STATS", 0);
  SILC_CLIENT_CMD(ping, PING, "PING", 2);
  SILC_CLIENT_CMD(oper, OPER, "OPER", 3);
  SILC_CLIENT_CMD(join, JOIN, "JOIN", 9);
  SILC_CLIENT_CMD(motd, MOTD, "MOTD", 2);
  SILC_CLIENT_CMD(umode, UMODE, "UMODE", 2);
  SILC_CLIENT_CMD(cmode, CMODE, "CMODE", 6);
  SILC_CLIENT_CMD(cumode, CUMODE, "CUMODE", 9);
  SILC_CLIENT_CMD(kick, KICK, "KICK", 4);
  SILC_CLIENT_CMD(ban, BAN, "BAN", 3);
  SILC_CLIENT_CMD(detach, DETACH, "DETACH", 0);
  SILC_CLIENT_CMD(watch, WATCH, "WATCH", 3);
  SILC_CLIENT_CMD(silcoper, SILCOPER, "SILCOPER", 3);
  SILC_CLIENT_CMD(leave, LEAVE, "LEAVE", 2);
  SILC_CLIENT_CMD(users, USERS, "USERS", 2);
  SILC_CLIENT_CMD(getkey, GETKEY, "GETKEY", 2);

  SILC_CLIENT_CMD(connect, PRIV_CONNECT, "CONNECT", 3);
  SILC_CLIENT_CMD(close, PRIV_CLOSE, "CLOSE", 3);
  SILC_CLIENT_CMD(shutdown, PRIV_SHUTDOWN, "SHUTDOWN", 1);
}

/* Unregister all commands. */

void silc_client_commands_unregister(SilcClient client)
{
  SILC_CLIENT_CMDU(whois, WHOIS, "WHOIS");
  SILC_CLIENT_CMDU(whowas, WHOWAS, "WHOWAS");
  SILC_CLIENT_CMDU(identify, IDENTIFY, "IDENTIFY");
  SILC_CLIENT_CMDU(nick, NICK, "NICK");
  SILC_CLIENT_CMDU(list, LIST, "LIST");
  SILC_CLIENT_CMDU(topic, TOPIC, "TOPIC");
  SILC_CLIENT_CMDU(invite, INVITE, "INVITE");
  SILC_CLIENT_CMDU(quit, QUIT, "QUIT");
  SILC_CLIENT_CMDU(kill, KILL, "KILL");
  SILC_CLIENT_CMDU(info, INFO, "INFO");
  SILC_CLIENT_CMDU(stats, STATS, "STATS");
  SILC_CLIENT_CMDU(ping, PING, "PING");
  SILC_CLIENT_CMDU(oper, OPER, "OPER");
  SILC_CLIENT_CMDU(join, JOIN, "JOIN");
  SILC_CLIENT_CMDU(motd, MOTD, "MOTD");
  SILC_CLIENT_CMDU(umode, UMODE, "UMODE");
  SILC_CLIENT_CMDU(cmode, CMODE, "CMODE");
  SILC_CLIENT_CMDU(cumode, CUMODE, "CUMODE");
  SILC_CLIENT_CMDU(kick, KICK, "KICK");
  SILC_CLIENT_CMDU(ban, BAN, "BAN");
  SILC_CLIENT_CMDU(detach, DETACH, "DETACH");
  SILC_CLIENT_CMDU(watch, WATCH, "WATCH");
  SILC_CLIENT_CMDU(silcoper, SILCOPER, "SILCOPER");
  SILC_CLIENT_CMDU(leave, LEAVE, "LEAVE");
  SILC_CLIENT_CMDU(users, USERS, "USERS");
  SILC_CLIENT_CMDU(getkey, GETKEY, "GETKEY");

  SILC_CLIENT_CMDU(connect, PRIV_CONNECT, "CONNECT");
  SILC_CLIENT_CMDU(close, PRIV_CLOSE, "CLOSE");
  SILC_CLIENT_CMDU(shutdown, PRIV_SHUTDOWN, "SHUTDOWN");
}

/**** Client side incoming command handling **********************************/

void silc_client_command_process_whois(SilcClient client,
				       SilcSocketConnection sock,
				       SilcCommandPayload payload,
				       SilcArgumentPayload args);

/* Client is able to receive some command packets even though they are
   special case.  Server may send WHOIS command to the client to retrieve
   Requested Attributes information for WHOIS query the server is
   processing. This function currently handles only the WHOIS command,
   but if in the future for commands may arrive then this can be made
   to support other commands too. */

void silc_client_command_process(SilcClient client,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcCommandPayload payload;
  SilcCommand command;
  SilcArgumentPayload args;

  /* Get command payload from packet */
  payload = silc_command_payload_parse(packet->buffer->data,
				       packet->buffer->len);
  if (!payload) {
    /* Silently ignore bad reply packet */
    SILC_LOG_DEBUG(("Bad command packet"));
    return;
  }

  /* Get arguments */
  args = silc_command_get_args(payload);

  /* Get the command */
  command = silc_command_get(payload);
  switch (command) {

  case SILC_COMMAND_WHOIS:
    /* Ignore everything if requested by application */
    if (client->internal->params->ignore_requested_attributes)
      break;

    silc_client_command_process_whois(client, sock, payload, args);
    break;

  default:
    break;
  }

  silc_command_payload_free(payload);
}

void silc_client_command_process_whois(SilcClient client,
				       SilcSocketConnection sock,
				       SilcCommandPayload payload,
				       SilcArgumentPayload args)
{
  SilcDList attrs;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBuffer buffer, packet;

  SILC_LOG_DEBUG(("Received WHOIS command"));

  /* Try to take the Requested Attributes */
  tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
  if (!tmp)
    return;

  attrs = silc_attribute_payload_parse(tmp, tmp_len);
  if (!attrs)
    return;

  /* Process requested attributes */
  buffer = silc_client_attributes_process(client, sock, attrs);
  if (!buffer) {
    silc_attribute_payload_list_free(attrs);
    return;
  }

  /* Send the attributes back */
  packet =
    silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					 SILC_STATUS_OK, 0,
					 silc_command_get_ident(payload),
					 1, 11, buffer->data, buffer->len);
  silc_client_packet_send(client, sock, SILC_PACKET_COMMAND_REPLY,
			  NULL, 0, NULL, NULL, packet->data,
			  packet->len, TRUE);
  silc_buffer_free(packet);
  silc_buffer_free(buffer);
}
