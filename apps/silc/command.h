/*

  command.h

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

/* 
   Structure holding one command and pointer to its function. 

   SilcCommandCb cb

       Callback function called when this command is executed.

   SilcCommand cmd

       The actual command. These are defined in silccore/silccommand.h

   char *name

       Logical name of the command. This is the visible command name
       that user uses when calling command. Eg. NICK.

   SilcCommandFlag flags

       Flags for the command. These set how command behaves on different
       situations. Server sets these flags as well, but to be sure
       that our client never sends wrong commands we preserve the
       flags on client side as well.

       XXX: We preserve these so that we define them but currently we
       don't check the flags at all.

*/
typedef struct {
  SilcCommandCb cb;
  SilcCommand cmd;
  char *name;
  SilcCommandFlag flags;
  unsigned int max_args;
} SilcClientCommand;

/* All client commands */
extern SilcClientCommand silc_command_list[];

/* Client command callback function. This included into Command Context, 
   and if it is defined it will be executed when executing the command. */
typedef void (*SilcClientCommandCallback)(void *context);

/* Context sent as argument to all commands */
typedef struct {
  SilcClient client;
  SilcSocketConnection sock;
  unsigned int argc;
  unsigned char **argv;
  unsigned int *argv_lens;
  unsigned int *argv_types;
} *SilcClientCommandContext;

/* Structure holding pending commands. If command is pending it will be
   executed after command reply has been executed. */
/* XXX This support may added for commands as well and not just command
   replies, if needed later. */
typedef struct SilcClientCommandPendingStruct {
  SilcCommand reply_cmd;
  void *context;
  SilcClientCommandCallback callback;

  struct SilcClientCommandPendingStruct *next;
} SilcClientCommandPending;

/* List of pending commands */
extern SilcClientCommandPending *silc_command_pending;

/* Macros */

/* Macro used for command declaration in command list structure */
#define SILC_CLIENT_CMD(func, cmd, name, flags, args) \
{ silc_client_command_##func, SILC_COMMAND_##cmd, name, flags, args }

/* Macro used to declare command functions */
#define SILC_CLIENT_CMD_FUNC(func) \
void silc_client_command_##func(void *context)

/* Checks for pending commands */
#define SILC_CLIENT_COMMAND_CHECK_PENDING(ctx)		\
do {							\
  if (silc_command_pending) {				\
    SilcClientCommandPending *r;			\
    SilcCommand cmd;					\
							\
    cmd = silc_command_get(payload);			\
    for (r = silc_command_pending; r; r = r->next) {	\
      if (r->reply_cmd == cmd) {			\
	ctx->context = r->context;			\
	ctx->callback = r->callback;			\
	break;						\
      }							\
    }							\
  }							\
} while(0)

/* Executed pending command */
#define SILC_CLIENT_COMMAND_EXEC_PENDING(ctx, cmd)	\
do {							\
  if (ctx->callback) {					\
    (*ctx->callback)(ctx->context);			\
    silc_client_command_pending_del((cmd));		\
  }							\
} while(0)

/* Prototypes */
void silc_client_command_pending(SilcCommand reply_cmd,
				 SilcClientCommandCallback callback,
				 void *context);
void silc_client_command_pending_del(SilcCommand reply_cmd);
SILC_CLIENT_CMD_FUNC(whois);
SILC_CLIENT_CMD_FUNC(whowas);
SILC_CLIENT_CMD_FUNC(identify);
SILC_CLIENT_CMD_FUNC(nick);
SILC_CLIENT_CMD_FUNC(server);
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
SILC_CLIENT_CMD_FUNC(kick);
SILC_CLIENT_CMD_FUNC(restart);
SILC_CLIENT_CMD_FUNC(close);
SILC_CLIENT_CMD_FUNC(die);
SILC_CLIENT_CMD_FUNC(silcoper);
SILC_CLIENT_CMD_FUNC(leave);
SILC_CLIENT_CMD_FUNC(names);
SILC_CLIENT_CMD_FUNC(help);
SILC_CLIENT_CMD_FUNC(clear);
SILC_CLIENT_CMD_FUNC(version);
SILC_CLIENT_CMD_FUNC(msg);
SILC_CLIENT_CMD_FUNC(away);

#endif
