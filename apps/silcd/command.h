/*

  servercommand.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
  int pending;			/* Command is being re-processed when TRUE */
  int users;			/* Reference counter */
} *SilcServerCommandContext;

/* Pending Command callback destructor. This is called after calling the
   pending callback or if error occurs while processing the pending command.
   If error occurs then the callback won't be called at all, and only this
   destructor is called. The `context' is the context given for the function
   silc_server_command_pending. */
typedef void (*SilcServerPendingDestructor)(void *context);

/* Structure holding pending commands. If command is pending it will be
   executed after command reply has been received and executed. */
typedef struct SilcServerCommandPendingStruct {
  SilcServer server;
  SilcCommand reply_cmd;
  SilcCommandCb callback;
  SilcServerPendingDestructor destructor;
  void *context;
  uint16 ident;
  struct SilcServerCommandPendingStruct *next;
} SilcServerCommandPending;

#include "command_reply.h"

/* Macros */

/* Macro used for command declaration in command list structure */
#define SILC_SERVER_CMD(func, cmd, flags) \
{ silc_server_command_##func, SILC_COMMAND_##cmd, flags }

/* Macro used to declare command functions. The `context' will be the
   SilcServerCommandContext and the `context2' is the 
   SilcServerCommandReplyContext if this function is called from the
   command reply as pending command callback. Otherwise `context2' 
   is NULL. */
#define SILC_SERVER_CMD_FUNC(func) \
void silc_server_command_##func(void *context, void *context2)

/* Executed pending command. The first argument to the callback function
   is the user specified context. The second argument is always the
   SilcServerCommandReply context. */
#define SILC_SERVER_PENDING_EXEC(ctx, cmd)	\
do {						\
  if (ctx->callback)				\
    (*ctx->callback)(ctx->context, ctx);	\
} while(0)

/* Execute destructor for pending command */
#define SILC_SERVER_PENDING_DESTRUCTOR(ctx, cmd)			\
do {									\
  silc_server_command_pending_del(ctx->server, cmd, ctx->ident);	\
  if (ctx->destructor)							\
    (*ctx->destructor)(ctx->context);					\
} while(0)

/* Prototypes */
void silc_server_command_process(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet);
SilcServerCommandContext silc_server_command_alloc();
void silc_server_command_free(SilcServerCommandContext ctx);
SilcServerCommandContext 
silc_server_command_dup(SilcServerCommandContext ctx);
void silc_server_command_pending(SilcServer server,
				 SilcCommand reply_cmd,
				 uint16 ident,
				 SilcServerPendingDestructor destructor,
				 SilcCommandCb callback,
				 void *context);
void silc_server_command_pending_del(SilcServer server,
				     SilcCommand reply_cmd,
				     uint16 ident);
int silc_server_command_pending_check(SilcServer server,
				      SilcServerCommandReplyContext ctx,
				      SilcCommand command, 
				      uint16 ident);
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
SILC_SERVER_CMD_FUNC(ban);
SILC_SERVER_CMD_FUNC(close);
SILC_SERVER_CMD_FUNC(shutdown);
SILC_SERVER_CMD_FUNC(silcoper);
SILC_SERVER_CMD_FUNC(leave);
SILC_SERVER_CMD_FUNC(users);
SILC_SERVER_CMD_FUNC(getkey);

#endif
