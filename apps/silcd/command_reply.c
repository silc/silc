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
/*
 * $Id$
 * $Log$
 * Revision 1.4  2000/07/12 05:59:41  priikone
 * 	Major rewrite of ID Cache system. Support added for the new
 * 	ID cache system. Major rewrite of ID List stuff on server.  All
 * 	SilcXXXList's are now called SilcXXXEntry's and they are pointers
 * 	by default. A lot rewritten ID list functions.
 *
 * Revision 1.3  2000/07/05 06:14:01  priikone
 * 	Global costemic changes.
 *
 * Revision 1.2  2000/07/03 05:52:22  priikone
 * 	Implemented LEAVE command.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "serverincludes.h"
#include "server_internal.h"
#include "command_reply.h"

/* Server command reply list. Not all commands have reply function as
   they are never sent by server. More maybe added later if need appears. */
SilcServerCommandReply silc_command_reply_list[] =
{
  SILC_SERVER_CMD_REPLY(join, JOIN),
  SILC_SERVER_CMD_REPLY(identify, IDENTIFY),

  { NULL, 0 },
};

/* Process received command reply. */

void silc_server_command_reply_process(SilcServer server,
				       SilcSocketConnection sock,
				       SilcBuffer buffer)
{
  SilcServerCommandReplyContext ctx;
  SilcCommandPayload payload;

  /* Get command reply payload from packet */
  payload = silc_command_parse_payload(buffer);
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
      
  /* Check for pending commands and mark to be exeucted */
  SILC_SERVER_COMMAND_CHECK_PENDING(ctx);
  
  /* Execute command reply */
  SILC_SERVER_COMMAND_REPLY_EXEC(ctx);
}

/* Free command reply context and its internals. */

void silc_server_command_reply_free(SilcServerCommandReplyContext cmd)
{
  if (cmd) {
    silc_command_free_payload(cmd->payload);
    silc_free(cmd);
  }
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
  unsigned char *id_string;
  char *channel_name, *tmp;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK)
    goto out;

  /* Get channel name */
  tmp = silc_command_get_arg_type(cmd->payload, 2, NULL);
  if (!tmp)
    goto out;

  /* Get channel ID */
  id_string = silc_command_get_arg_type(cmd->payload, 3, NULL);
  if (!id_string)
    goto out;

  channel_name = strdup(tmp);

  /* Add the channel to our local list. */
  id = silc_id_str2id(id_string, SILC_ID_CHANNEL);
  entry = silc_idlist_add_channel(server->local_list, channel_name, 
				  SILC_CHANNEL_MODE_NONE, id, 
				  server->id_entry->router, NULL);
  if (!entry)
    goto out;

  entry->global_users = TRUE;

  /* Execute pending JOIN command so that the client who originally
     wanted to join the channel will be joined after all. */
  SILC_SERVER_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_JOIN);

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
  unsigned char *tmp;

  SILC_LOG_DEBUG(("Start"));

  tmp = silc_command_get_arg_type(cmd->payload, 1, NULL);
  SILC_GET16_MSB(status, tmp);
  if (status != SILC_STATUS_OK)
    goto out;

  /* Process one identify reply */
  if (status == SILC_STATUS_OK) {
    unsigned char *id_data;
    char *nickname;

    id_data = silc_command_get_arg_type(cmd->payload, 2, NULL);
    nickname = silc_command_get_arg_type(cmd->payload, 3, NULL);
    if (!id_data || !nickname)
      goto out;

#if 0
    /* Allocate client entry */
    client_entry = silc_calloc(1, sizeof(*client_entry));
    client_entry->id = silc_id_str2id(id_data, SILC_ID_CLIENT);
    client_entry->nickname = strdup(nickname);

    /* Save received Client ID to ID cache */
    silc_idcache_add(win->client_cache, client_entry->nickname,
		     SILC_ID_CLIENT, client_entry->id, client_entry, TRUE);
#endif
  }

  if (status == SILC_STATUS_LIST_START) {

  }

  if (status == SILC_STATUS_LIST_END) {

  }

  /* Execute pending IDENTIFY command so that the client who originally
     requested the identify information will get it after all. */
  SILC_SERVER_COMMAND_EXEC_PENDING(cmd, SILC_COMMAND_IDENTIFY);

 out:
  silc_server_command_reply_free(cmd);
}
