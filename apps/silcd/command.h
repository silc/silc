/*

  servercommand.h

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

#ifndef COMMAND_H
#define COMMAND_H

#include "command_reply.h"

/* 
   Structure holding one command and pointer to its function. 

   SilcCommandCb cb

       Callback function called when this command is executed.

   SilcCommand cmd

       The actual command. Defined in silccore/silccommand.h

   SilcCommandFlag flags

       Flags for the command. These set how command behaves on different
       situations. 

*/
typedef struct {
  SilcCommandCb cb;
  SilcCommand cmd;
  SilcCommandFlag flags;
} SilcServerCommand;

/* All server commands */
extern SilcServerCommand silc_command_list[];

/* Context sent as argument to all commands */
typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  SilcCommandPayload payload;
  SilcArgumentPayload args;
  SilcPacketContext *packet;
  int pending;
} *SilcServerCommandContext;

/* Structure holding pending commands. If command is pending it will be
   executed after command reply has been received and executed. */
typedef struct SilcServerCommandPendingStruct {
  SilcCommand reply_cmd;
  SilcCommandCb callback;
  void *context;
  unsigned short ident;
  struct SilcServerCommandPendingStruct *next;
} SilcServerCommandPending;

/* Macros */

/* Macro used for command declaration in command list structure */
#define SILC_SERVER_CMD(func, cmd, flags) \
{ silc_server_command_##func, SILC_COMMAND_##cmd, flags }

/* Macro used to declare command functions */
#define SILC_SERVER_CMD_FUNC(func) \
void silc_server_command_##func(void *context)

/* Executed pending command */
#define SILC_SERVER_COMMAND_EXEC_PENDING(ctx, cmd)	\
do {							\
  if (ctx->callback) {					\
    (*ctx->callback)(ctx->context);			\
    silc_server_command_pending_del(cmd, ctx->ident);	\
  }							\
} while(0)

/* Prototypes */
void silc_server_command_process(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
void silc_server_command_pending(SilcCommand reply_cmd,
				 unsigned short ident,
				 SilcCommandCb callback,
				 void *context);
void silc_server_command_pending_del(SilcCommand reply_cmd,
				     unsigned short ident);
int silc_server_command_pending_check(SilcServerCommandReplyContext ctx,
				      SilcCommand command, 
				      unsigned short ident);
SILC_SERVER_CMD_FUNC(whois);
SILC_SERVER_CMD_FUNC(whowas);
SILC_SERVER_CMD_FUNC(identify);
SILC_SERVER_CMD_FUNC(newuser);
SILC_SERVER_CMD_FUNC(nick);
SILC_SERVER_CMD_FUNC(list);
SILC_SERVER_CMD_FUNC(topic);
SILC_SERVER_CMD_FUNC(invite);
SILC_SERVER_CMD_FUNC(quit);
SILC_SERVER_CMD_FUNC(kill);
SILC_SERVER_CMD_FUNC(info);
SILC_SERVER_CMD_FUNC(connect);
SILC_SERVER_CMD_FUNC(ping);
SILC_SERVER_CMD_FUNC(oper);
SILC_SERVER_CMD_FUNC(pass);
SILC_SERVER_CMD_FUNC(admin);
SILC_SERVER_CMD_FUNC(join);
SILC_SERVER_CMD_FUNC(motd);
SILC_SERVER_CMD_FUNC(umode);
SILC_SERVER_CMD_FUNC(cmode);
SILC_SERVER_CMD_FUNC(cumode);
SILC_SERVER_CMD_FUNC(kick);
SILC_SERVER_CMD_FUNC(ignore);
SILC_SERVER_CMD_FUNC(restart);
SILC_SERVER_CMD_FUNC(close);
SILC_SERVER_CMD_FUNC(die);
SILC_SERVER_CMD_FUNC(silcoper);
SILC_SERVER_CMD_FUNC(leave);
SILC_SERVER_CMD_FUNC(names);

#endif
