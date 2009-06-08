/*

  command_reply.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2003 Pekka Riikonen

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

#include "command.h"

/* Structure holding one command reply and pointer to its function. */
typedef struct {
  SilcCommandCb cb;
  SilcCommand cmd;
} SilcServerCommandReply;

/* All server command replys */
extern SilcServerCommandReply silc_command_reply_list[];

/* Context holding pending command callbacks. */
typedef struct {
  SilcCommandCb callback;
  void *context;
} *SilcServerCommandPendingCallbacks;

/* Context sent as argument to all command reply functions */
typedef struct {
  SilcServer server;
  SilcPacketStream sock;
  SilcCommandPayload payload;
  SilcArgumentPayload args;

  /* If defined this executes the pending command. */
  SilcServerCommandPendingCallbacks callbacks;
  SilcUInt32 callbacks_count;
  SilcUInt16 ident;
  unsigned int pending : 1;
} *SilcServerCommandReplyContext;

/* Macros */

/* Macro used for command declaration in command reply list structure */
#define SILC_SERVER_CMD_REPLY(func, cmd ) \
{ silc_server_command_reply_##func, SILC_COMMAND_##cmd }

/* Macro used to declare command reply functions */
#define SILC_SERVER_CMD_REPLY_FUNC(func) \
void silc_server_command_reply_##func(void *context, void *context2)

/* Prototypes */
void silc_server_command_reply_free(SilcServerCommandReplyContext cmd);
void silc_server_command_reply_process(SilcServer server,
				       SilcPacketStream sock,
				       SilcBuffer buffer);
SILC_SERVER_CMD_REPLY_FUNC(whois);
SILC_SERVER_CMD_REPLY_FUNC(whowas);
SILC_SERVER_CMD_REPLY_FUNC(identify);
SILC_SERVER_CMD_REPLY_FUNC(info);
SILC_SERVER_CMD_REPLY_FUNC(motd);
SILC_SERVER_CMD_REPLY_FUNC(join);
SILC_SERVER_CMD_REPLY_FUNC(stats);
SILC_SERVER_CMD_REPLY_FUNC(users);
SILC_SERVER_CMD_REPLY_FUNC(getkey);
SILC_SERVER_CMD_REPLY_FUNC(list);
SILC_SERVER_CMD_REPLY_FUNC(watch);
SILC_SERVER_CMD_REPLY_FUNC(ping);

#endif
