/*

  command_reply.h

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

#ifndef COMMAND_REPLY_H
#define COMMAND_REPLY_H

/* Structure holding one command reply and pointer to its function. */
typedef struct {
  SilcCommandCb cb;
  SilcCommand cmd;
} SilcServerCommandReply;

/* All server command replys */
extern SilcServerCommandReply silc_command_reply_list[];

/* Context sent as argument to all command reply functions */
typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  SilcCommandPayload payload;

  /* If defined this executes the pending command. */
  void *context;
  SilcCommandCb callback;
} *SilcServerCommandReplyContext;

/* Macros */

/* Macro used for command declaration in command reply list structure */
#define SILC_SERVER_CMD_REPLY(func, cmd ) \
{ silc_server_command_reply_##func, SILC_COMMAND_##cmd }

/* Macro used to declare command reply functions */
#define SILC_SERVER_CMD_REPLY_FUNC(func) \
void silc_server_command_reply_##func(void *context)

/* Macro used to execute command replies */
#define SILC_SERVER_COMMAND_REPLY_EXEC(ctx)		\
do {							\
  SilcServerCommandReply *cmd;				\
							\
  for (cmd = silc_command_reply_list; cmd->cb; cmd++)	\
    if (cmd->cmd == silc_command_get(ctx->payload)) {	\
      cmd->cb(ctx);					\
      break;						\
    }							\
							\
  if (cmd == NULL) {					\
    silc_free(ctx);					\
    return;						\
  }							\
} while(0)

/* Prototypes */
void silc_server_command_reply_process(SilcServer server,
				       SilcSocketConnection sock,
				       SilcBuffer buffer);
SILC_SERVER_CMD_REPLY_FUNC(join);
SILC_SERVER_CMD_REPLY_FUNC(identify);

#endif
