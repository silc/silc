/*

  command_reply.c

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

#include "serverincludes.h"
#include "server_internal.h"
#include "command_reply.h"

#define COMMAND_CHECK_STATUS						  \
do {									  \
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL)); \
  if (status != SILC_STATUS_OK) {					  \
    silc_server_command_reply_free(cmd);				  \
    return;								  \
  }									  \
} while(0)

#define COMMAND_CHECK_STATUS_LIST					  \
do {									  \
  SILC_GET16_MSB(status, silc_argument_get_arg_type(cmd->args, 1, NULL)); \
  if (status != SILC_STATUS_OK && 					  \
      status != SILC_STATUS_LIST_START &&				  \
      status != SILC_STATUS_LIST_ITEM &&				  \
      status != SILC_STATUS_LIST_END) {					  \
    silc_server_command_reply_free(cmd);				  \
    return;								  \
  }									  \
} while(0)

/* Server command reply list. Not all commands have reply function as
   they are never sent by server. More maybe added later if need appears. */
SilcServerCommandReply silc_command_reply_list[] =
{
  SILC_SERVER_CMD_REPLY(join, JOIN),
  SILC_SERVER_CMD_REPLY(identify, WHOIS),
  SILC_SERVER_CMD_REPLY(identify, IDENTIFY),

  { NULL, 0 },
};

/* Process received command reply. */

void silc_server_command_reply_process(SilcServer server,
				       SilcSocketConnection sock,
				       SilcBuffer buffer)
{
  SilcServerCommandReply *cmd;
  SilcServerCommandReplyContext ctx;
  SilcCommandPayload payload;
  SilcCommand command;
  unsigned short ident;

  SILC_LOG_DEBUG(("Start"));

  /* Get command reply payload from packet */
  payload = silc_command_payload_parse(buffer);
  if (!payload) {
    /* Silently ignore bad reply packet */
    SILC_LOG_DEBUG(("Bad command reply packet"));
    return;
  }
  
  /* Allocate command reply context. This must be free'd by the
     command reply routine receiving it. */
  ctx = silc_calloc(1, sizeof(*ctx));
  ctx->server = server;
  ctx->sock = sock;
  ctx->payload = payload;
  ctx->args = silc_command_get_args(ctx->payload);
  ident = silc_command_get_ident(ctx->payload);
      
  /* Check for pending commands and mark to be exeucted */
  silc_server_command_pending_check(server, ctx, 
				    silc_command_get(ctx->payload), ident);

  /* Execute command reply */
  command = silc_command_get(ctx->payload);
  for (cmd = silc_command_reply_list; cmd->cb; cmd++)
    if (cmd->cmd == command)
      break;

  if (cmd == NULL) {
    silc_free(ctx);
    return;
  }

  cmd->cb(ctx);
}

/* Free command reply context and its internals. */

void silc_server_command_reply_free(SilcServerCommandReplyContext cmd)
{
  if (cmd) {
    silc_command_free_payload(cmd->payload);
    silc_free(cmd);
  }
}

/* Caches the received WHOIS information. If we are normal server currently
   we cache global information only for short period of time.  If we are
   router we want to cache them a bit longer since we can receive information
   if any of the information becomes invalid. Normal server cannot receive
   that information. Returns FALSE if something was wrong with the reply. */

static char
silc_server_command_reply_whois_save(SilcServerCommandReplyContext cmd)
{
  int len, id_len;
  unsigned char *id_data;
  char *nickname, *username, *realname;
  SilcClientID *client_id;

  id_data = silc_argument_get_arg_type(cmd->args, 2, &id_len);
  nickname = silc_argument_get_arg_type(cmd->args, 3, &len);
  username = silc_argument_get_arg_type(cmd->args, 4, &len);
  realname = silc_argument_get_arg_type(cmd->args, 5, &len);
  if (!id_data || !nickname || !username || !realname) 
    return FALSE;

  client_id = silc_id_payload_parse_id(id_data, id_len);


  return TRUE;
}

/* Reiceved reply for WHOIS command. We sent the whois request to our
   primary router, if we are normal server, and thus has now received reply
   to the command. We will figure out what client originally sent us the
   command and will send the reply to it.  If we are router we will figure
   out who server sent us the command and send reply to that one. */

SILC_SERVER_CMD_REPLY_FUNC(whois)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;

  SILC_LOG_DEBUG(("Start"));

  COMMAND_CHECK_STATUS_LIST;

  /* Process one identify reply */
  if (status == SILC_STATUS_OK) {

  }

  if (status == SILC_STATUS_LIST_START) {

  }

  if (status == SILC_STATUS_LIST_ITEM) {

  }

  if (status == SILC_STATUS_LIST_END) {

  }

  /* Execute any pending commands */
  SILC_SERVER_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_WHOIS);

 out:
  silc_server_command_reply_free(cmd);
}

/* Received reply for forwarded IDENTIFY command. We have received the
   requested identify information now and we will cache it. After this we
   will call the pending command so that the requestee gets the information
   after all. */

SILC_SERVER_CMD_REPLY_FUNC(identify)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;

  SILC_LOG_DEBUG(("Start"));

  COMMAND_CHECK_STATUS_LIST;

  /* Process one identify reply */
  if (status == SILC_STATUS_OK) {
    SilcClientID *client_id;
    unsigned int len;
    unsigned char *id_data;
    char *nickname, *username;

    id_data = silc_argument_get_arg_type(cmd->args, 2, &len);
    nickname = silc_argument_get_arg_type(cmd->args, 3, NULL);
    if (!id_data || !nickname)
      goto out;

    username = silc_argument_get_arg_type(cmd->args, 4, NULL);
    client_id = silc_id_payload_parse_id(id_data, len);

    /* Add the client always to our global list. If normal or router server
       ever gets here it means they don't have this client's information
       in their cache. */
    silc_idlist_add_client(server->global_list, strdup(nickname),
			   username, NULL, client_id, NULL, NULL);
  }

  if (status == SILC_STATUS_LIST_START) {

  }

  if (status == SILC_STATUS_LIST_ITEM) {

  }

  if (status == SILC_STATUS_LIST_END) {

  }

  /* Execute any pending commands */
  SILC_SERVER_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_IDENTIFY);

 out:
  silc_server_command_reply_free(cmd);
}

/* Received reply for forwarded JOIN command. Router has created or joined
   the client to the channel. We save some channel information locally
   for future use. */

SILC_SERVER_CMD_REPLY_FUNC(join)
{
  SilcServerCommandReplyContext cmd = (SilcServerCommandReplyContext)context;
  SilcServer server = cmd->server;
  SilcCommandStatus status;
  SilcChannelID *id;
  SilcChannelEntry entry;
  unsigned int len;
  unsigned char *id_string;
  char *channel_name, *tmp;

  SILC_LOG_DEBUG(("Start"));

  COMMAND_CHECK_STATUS;

  /* Get channel name */
  tmp = silc_argument_get_arg_type(cmd->args, 2, NULL);
  if (!tmp)
    goto out;

  /* Get channel ID */
  id_string = silc_argument_get_arg_type(cmd->args, 3, &len);
  if (!id_string)
    goto out;

  channel_name = strdup(tmp);
  id = silc_id_payload_parse_id(id_string, len);

  /* XXX We should check that we have sent JOIN command to the router
     in the first place. Also should check that we don't have the channel
     already in the cache. These checks must be made because of possible
     buggy routers. */

  SILC_LOG_DEBUG(("Adding new channel %s id(%s)", channel_name,
		  silc_id_render(id, SILC_ID_CHANNEL)));

  /* Add the channel to our local list. */
  entry = silc_idlist_add_channel(server->local_list, channel_name, 
				  SILC_CHANNEL_MODE_NONE, id, 
				  server->router, NULL);
  if (!entry) {
    silc_free(channel_name);
    silc_free(id);
    goto out;
  }

  //entry->global_users = TRUE;

  /* Execute any pending commands */
  SILC_SERVER_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_JOIN);

 out:
  silc_server_command_reply_free(cmd);
}
