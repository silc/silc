/*

  command_reply.h 

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

#ifndef COMMAND_REPLY_H
#define COMMAND_REPLY_H

/* Structure holding one command reply and pointer to its function. */
typedef struct {
  SilcCommandCb cb;
  SilcCommand cmd;
} SilcClientCommandReply;

/* Context holding pending command callbacks. */
typedef struct {
  SilcCommandCb callback;
  void *context;
} *SilcClientCommandPendingCallbacks;

/* Context sent as argument to all command reply functions */
struct SilcClientCommandReplyContextStruct {
  SilcClient client;
  SilcSocketConnection sock;
  SilcCommandPayload payload;
  SilcCommandStatus status;
  SilcCommandStatus error;
  SilcArgumentPayload args;
  SilcPacketContext *packet;

  /* If defined this executes the pending command. */
  SilcClientCommandPendingCallbacks callbacks;
  SilcUInt32 callbacks_count;
  SilcUInt16 ident;
};

/* Macros */

/* Command reply operation that is called at the end of all command replys. 
   Usage: COMMAND_REPLY((ARGS, argument1, argument2, etc...)), */
#define COMMAND_REPLY(args) cmd->client->internal->ops->command_reply args
#define ARGS cmd->client, cmd->sock->user_data,				\
             cmd->payload, TRUE, silc_command_get(cmd->payload), cmd->status

/* Error reply to application. Usage: COMMAND_REPLY_ERROR; */
#define COMMAND_REPLY_ERROR cmd->client->internal->ops->		\
  command_reply(cmd->client, cmd->sock->user_data, cmd->payload,	\
  FALSE, silc_command_get(cmd->payload), cmd->status)

/* Macro used to declare command reply functions */
#define SILC_CLIENT_CMD_REPLY_FUNC(func)				\
void silc_client_command_reply_##func(void *context, void *context2)

/* Status message structure. Messages are defined below. */
typedef struct {
  SilcCommandStatus status;
  char *message;
} SilcCommandStatusMessage;

/* Status messages returned by the server */
#define STAT(x) SILC_STATUS_ERR_##x
DLLAPI extern const SilcCommandStatusMessage silc_command_status_messages[];

/* Prototypes */

void silc_client_command_reply_process(SilcClient client,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet);
char *silc_client_command_status_message(SilcCommandStatus status);
void silc_client_command_reply_free(SilcClientCommandReplyContext cmd);
SILC_CLIENT_CMD_REPLY_FUNC(whois);
SILC_CLIENT_CMD_REPLY_FUNC(whowas);
SILC_CLIENT_CMD_REPLY_FUNC(identify);
SILC_CLIENT_CMD_REPLY_FUNC(nick);
SILC_CLIENT_CMD_REPLY_FUNC(list);
SILC_CLIENT_CMD_REPLY_FUNC(topic);
SILC_CLIENT_CMD_REPLY_FUNC(invite);
SILC_CLIENT_CMD_REPLY_FUNC(kill);
SILC_CLIENT_CMD_REPLY_FUNC(info);
SILC_CLIENT_CMD_REPLY_FUNC(stats);
SILC_CLIENT_CMD_REPLY_FUNC(ping);
SILC_CLIENT_CMD_REPLY_FUNC(oper);
SILC_CLIENT_CMD_REPLY_FUNC(join);
SILC_CLIENT_CMD_REPLY_FUNC(motd);
SILC_CLIENT_CMD_REPLY_FUNC(umode);
SILC_CLIENT_CMD_REPLY_FUNC(cmode);
SILC_CLIENT_CMD_REPLY_FUNC(cumode);
SILC_CLIENT_CMD_REPLY_FUNC(kick);
SILC_CLIENT_CMD_REPLY_FUNC(ban);
SILC_CLIENT_CMD_REPLY_FUNC(detach);
SILC_CLIENT_CMD_REPLY_FUNC(silcoper);
SILC_CLIENT_CMD_REPLY_FUNC(leave);
SILC_CLIENT_CMD_REPLY_FUNC(users);
SILC_CLIENT_CMD_REPLY_FUNC(getkey);
SILC_CLIENT_CMD_REPLY_FUNC(quit);

/* Internal command reply functions */
SILC_CLIENT_CMD_REPLY_FUNC(whois_i);
SILC_CLIENT_CMD_REPLY_FUNC(identify_i);
SILC_CLIENT_CMD_REPLY_FUNC(info_i);
SILC_CLIENT_CMD_REPLY_FUNC(users_i);

SILC_CLIENT_CMD_REPLY_FUNC(connect);
SILC_CLIENT_CMD_REPLY_FUNC(close);
SILC_CLIENT_CMD_REPLY_FUNC(shutdown);

#endif
