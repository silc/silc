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
} SilcClientCommandReply;

/* All client command replys */
extern SilcClientCommandReply silc_command_reply_list[];

/* Context sent as argument to all command reply functions */
typedef struct {
  SilcClient client;
  SilcSocketConnection sock;
  SilcCommandPayload payload;
  SilcArgumentPayload args;
  SilcPacketContext *packet;

  /* If defined this executes the pending command. */
  void *context;
  SilcCommandCb callback;
  unsigned short ident;
} *SilcClientCommandReplyContext;

/* Macros */

/* Macro used for command declaration in command reply list structure */
#define SILC_CLIENT_CMD_REPLY(func, cmd ) \
{ silc_client_command_reply_##func, SILC_COMMAND_##cmd }

/* Macro used to declare command reply functions */
#define SILC_CLIENT_CMD_REPLY_FUNC(func) \
void silc_client_command_reply_##func(void *context)

/* Prototypes */
void silc_client_command_reply_process(SilcClient client,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet);
SILC_CLIENT_CMD_REPLY_FUNC(whois);
SILC_CLIENT_CMD_REPLY_FUNC(whowas);
SILC_CLIENT_CMD_REPLY_FUNC(identify);
SILC_CLIENT_CMD_REPLY_FUNC(nick);
SILC_CLIENT_CMD_REPLY_FUNC(list);
SILC_CLIENT_CMD_REPLY_FUNC(topic);
SILC_CLIENT_CMD_REPLY_FUNC(invite);
SILC_CLIENT_CMD_REPLY_FUNC(quit);
SILC_CLIENT_CMD_REPLY_FUNC(kill);
SILC_CLIENT_CMD_REPLY_FUNC(info);
SILC_CLIENT_CMD_REPLY_FUNC(links);
SILC_CLIENT_CMD_REPLY_FUNC(stats);
SILC_CLIENT_CMD_REPLY_FUNC(users);
SILC_CLIENT_CMD_REPLY_FUNC(connect);
SILC_CLIENT_CMD_REPLY_FUNC(ping);
SILC_CLIENT_CMD_REPLY_FUNC(pong);
SILC_CLIENT_CMD_REPLY_FUNC(oper);
SILC_CLIENT_CMD_REPLY_FUNC(join);
SILC_CLIENT_CMD_REPLY_FUNC(motd);
SILC_CLIENT_CMD_REPLY_FUNC(umode);
SILC_CLIENT_CMD_REPLY_FUNC(cmode);
SILC_CLIENT_CMD_REPLY_FUNC(cumode);
SILC_CLIENT_CMD_REPLY_FUNC(kick);
SILC_CLIENT_CMD_REPLY_FUNC(restart);
SILC_CLIENT_CMD_REPLY_FUNC(close);
SILC_CLIENT_CMD_REPLY_FUNC(die);
SILC_CLIENT_CMD_REPLY_FUNC(silcoper);
SILC_CLIENT_CMD_REPLY_FUNC(leave);
SILC_CLIENT_CMD_REPLY_FUNC(users);

#endif
