/*

  command.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef COMMAND_H
#define COMMAND_H

/* Forward declarations */
typedef struct SilcClientCommandStruct *SilcClientCommand;
typedef struct SilcClientCommandContextStruct *SilcClientCommandContext;

#include "silcapi.h"
#include "command_reply.h"

/* Structure holding one command and pointer to its function. This
   structure is allocate into the commands list, and is returned
   for example by silc_client_command_find function.

   To call a command: command->command(cmd, NULL);
   To call a command reply: command->reply(cmd, NULL);

*/
struct SilcClientCommandStruct {
  SilcCommand cmd;		   /* Command type */
  SilcCommandCb command;	   /* Command function */
  SilcCommandCb reply;		   /* Command reply callback */
  char *name;			   /* Name of the command (optional) */
  uint8 max_args;		   /* Maximum arguments (optional)  */
  uint16 ident;			   /* Identifier for command (optional)  */
  struct SilcClientCommandStruct *next;
};

/* Context sent as argument to all commands. This is used by the library
   and application should use this as well. However, application may
   choose to use some own context for its own local command. All library
   commands, however, must use this context. */
struct SilcClientCommandContextStruct {
  SilcClient client;
  SilcClientConnection conn;
  SilcClientCommand command;
  uint32 argc;
  unsigned char **argv;
  uint32 *argv_lens;
  uint32 *argv_types;
  int pending;			/* Command is being re-processed when TRUE */
  int users;			/* Reference counter */
};

/* Structure holding pending commands. If command is pending it will be
   executed after command reply has been executed. */
typedef struct SilcClientCommandPendingStruct {
  SilcCommand reply_cmd;
  SilcCommandCb callback;
  SilcClientPendingDestructor destructor;
  void *context;
  uint16 ident;
  struct SilcClientCommandPendingStruct *next;
} SilcClientCommandPending;

/* List of pending commands */
extern SilcClientCommandPending *silc_command_pending;


/* Macros */

/* Macro used for command registering and unregistering */
#define SILC_CLIENT_CMD(func, cmd, name, args)				\
silc_client_command_register(client, SILC_COMMAND_##cmd, name, 		\
			     silc_client_command_##func,		\
			     silc_client_command_reply_##func, args, 0)
#define SILC_CLIENT_CMDU(func, cmd, name)				\
silc_client_command_unregister(client, SILC_COMMAND_##cmd,		\
			       silc_client_command_##func,		\
			       silc_client_command_reply_##func, 0)

/* Macro used to declare command functions */
#define SILC_CLIENT_CMD_FUNC(func)				\
void silc_client_command_##func(void *context, void *context2)

/* Executed pending command callback */
#define SILC_CLIENT_PENDING_EXEC(ctx, cmd)	\
do {						\
  if ((ctx)->callback)				\
    (*ctx->callback)(ctx->context, ctx);	\
} while(0)

/* Execute destructor for pending command */
#define SILC_CLIENT_PENDING_DESTRUCTOR(ctx, cmd)			\
do {									\
  silc_client_command_pending_del((ctx)->sock->user_data, (cmd),	\
				  (ctx)->ident);			\
  if (ctx->destructor)							\
    (*ctx->destructor)(ctx->context);					\
} while(0)

bool silc_client_command_register(SilcClient client,
				  SilcCommand command,
				  const char *name,
				  SilcCommandCb command_function,
				  SilcCommandCb command_reply_function,
				  uint8 max_args,
				  uint16 ident);
bool silc_client_command_unregister(SilcClient client,
				    SilcCommand command,
				    SilcCommandCb command_function,
				    SilcCommandCb command_reply_function,
				    uint16 ident);
void silc_client_commands_register(SilcClient client);
void silc_client_commands_unregister(SilcClient client);
void silc_client_command_pending_del(SilcClientConnection conn,
				     SilcCommand reply_cmd,
				     uint16 ident);
int silc_client_command_pending_check(SilcClientConnection conn,
				      SilcClientCommandReplyContext ctx,
				      SilcCommand command, 
				      uint16 ident);

SILC_CLIENT_CMD_FUNC(whois);
SILC_CLIENT_CMD_FUNC(whowas);
SILC_CLIENT_CMD_FUNC(identify);
SILC_CLIENT_CMD_FUNC(nick);
SILC_CLIENT_CMD_FUNC(list);
SILC_CLIENT_CMD_FUNC(topic);
SILC_CLIENT_CMD_FUNC(invite);
SILC_CLIENT_CMD_FUNC(quit);
SILC_CLIENT_CMD_FUNC(kill);
SILC_CLIENT_CMD_FUNC(info);
SILC_CLIENT_CMD_FUNC(connect);
SILC_CLIENT_CMD_FUNC(ping);
SILC_CLIENT_CMD_FUNC(oper);
SILC_CLIENT_CMD_FUNC(join);
SILC_CLIENT_CMD_FUNC(motd);
SILC_CLIENT_CMD_FUNC(umode);
SILC_CLIENT_CMD_FUNC(cmode);
SILC_CLIENT_CMD_FUNC(cumode);
SILC_CLIENT_CMD_FUNC(kick);
SILC_CLIENT_CMD_FUNC(ban);
SILC_CLIENT_CMD_FUNC(close);
SILC_CLIENT_CMD_FUNC(shutdown);
SILC_CLIENT_CMD_FUNC(silcoper);
SILC_CLIENT_CMD_FUNC(leave);
SILC_CLIENT_CMD_FUNC(users);
SILC_CLIENT_CMD_FUNC(getkey);

#endif
