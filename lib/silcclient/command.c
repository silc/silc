/*

  command.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************** Types and definitions ***************************/

/* Command operation that is called at the end of all commands.
   Usage: COMMAND(status); */
#define COMMAND(status) cmd->conn->client->internal->ops->command(	\
  cmd->conn->client, cmd->conn, TRUE, cmd->cmd, (status), cmd->argc, cmd->argv)

/* Error to application. Usage: COMMAND_ERROR(status); */
#define COMMAND_ERROR(status)					\
  cmd->conn->client->internal->ops->command(cmd->conn->client,	\
  cmd->conn, FALSE, cmd->cmd, (status), cmd->argc, cmd->argv)

/* Used to register new command */
#define SILC_CLIENT_CMD(func, cmd, name, args)				\
silc_client_command_register(client, SILC_COMMAND_##cmd, name, 		\
			     silc_client_command_##func,		\
			     silc_client_command_reply_##func, args)

/* Used to unregister command */
#define SILC_CLIENT_CMDU(func, cmd, name)				\
silc_client_command_unregister(client, SILC_COMMAND_##cmd,		\
			       silc_client_command_##func,		\
			       silc_client_command_reply_##func)

#define SAY cmd->conn->client->internal->ops->say

/************************ Static utility functions **************************/

/* Return next available command identifier. */

static SilcUInt16 silc_client_cmd_ident(SilcClientConnection conn)
{
  SilcUInt16 cmd_ident;

  cmd_ident = silc_atomic_add_int16(&conn->internal->cmd_ident, 1);
  if (!cmd_ident)
    cmd_ident = silc_atomic_add_int16(&conn->internal->cmd_ident, 1);

  return cmd_ident;
}

/* State to finish command thread after an error in resolving command */

SILC_FSM_STATE(silc_client_command_continue_error)
{
  /* Destructor will free all resources */
  return SILC_FSM_FINISH;
}

/* Command reply callback to continue with the execution of a command.
   This will continue when first successful reply is received, and ignores
   the rest.  On the other hand, if only errors are received it will
   wait for all errors before continuing. */

static SilcBool silc_client_command_continue(SilcClient client,
					     SilcClientConnection conn,
					     SilcCommand command,
					     SilcStatus status,
					     SilcStatus error,
					     void *context,
					     va_list ap)
{
  SilcClientCommandContext cmd = context;

  /* Continue immediately when successful reply is received */
  if (status == SILC_STATUS_OK || !SILC_STATUS_IS_ERROR(error)) {
    SILC_FSM_CALL_CONTINUE(&cmd->thread);
    return FALSE;
  }

  /* Error */
  COMMAND_ERROR(error);

  /* Continue after last error is received */
  if (SILC_STATUS_IS_ERROR(status) ||
      (status == SILC_STATUS_LIST_END && SILC_STATUS_IS_ERROR(error))) {
    silc_fsm_next(&cmd->thread, silc_client_command_continue_error);
    SILC_FSM_CALL_CONTINUE(&cmd->thread);
    return FALSE;
  }

  return TRUE;
}

/* Continues after resolving completed. */

static void silc_client_command_resolve_continue(SilcClient client,
						 SilcClientConnection conn,
						 SilcStatus status,
						 SilcDList clients,
						 void *context)
{
  SilcClientCommandContext cmd = context;

  if (status != SILC_STATUS_OK)
    silc_fsm_next(&cmd->thread, silc_client_command_continue_error);

  /* Continue with the command */
  SILC_FSM_CALL_CONTINUE(&cmd->thread);
}

/* Dummy command callback.  Nothing interesting to do here.  Use this when
   you just send command but don't care about reply. */

SilcBool silc_client_command_called_dummy(SilcClient client,
					  SilcClientConnection conn,
					  SilcCommand command,
					  SilcStatus status,
					  SilcStatus error,
					  void *context,
					  va_list ap)
{
  return FALSE;
}

/* Dummy resolving callback.  Nothing interesting to do here.  Use this
   when you just resolve entires but don't care about reply. */

void silc_client_command_resolve_dummy(SilcClient client,
				       SilcClientConnection conn,
				       SilcStatus status,
				       SilcDList clients,
				       void *context)
{
  /* Nothing */
}

/* Register command to client */

static SilcBool
silc_client_command_register(SilcClient client,
			     SilcCommand command,
			     const char *name,
			     SilcFSMStateCallback command_func,
			     SilcFSMStateCallback command_reply_func,
			     SilcUInt8 max_args)
{
  SilcClientCommand cmd;

  cmd = silc_calloc(1, sizeof(*cmd));
  if (!cmd)
    return FALSE;
  cmd->cmd = command;
  cmd->command = command_func;
  cmd->reply = command_reply_func;
  cmd->max_args = max_args;
  cmd->name = name ? strdup(name) : NULL;
  if (!cmd->name) {
    silc_free(cmd);
    return FALSE;
  }

  silc_list_add(client->internal->commands, cmd);

  return TRUE;
}

/* Unregister command from client */

static SilcBool
silc_client_command_unregister(SilcClient client,
			       SilcCommand command,
			       SilcFSMStateCallback command_func,
			       SilcFSMStateCallback command_reply_func)
{
  SilcClientCommand cmd;

  silc_list_start(client->internal->commands);
  while ((cmd = silc_list_get(client->internal->commands)) != SILC_LIST_END) {
    if (cmd->cmd == command && cmd->command == command_func &&
	cmd->reply == command_reply_func) {
      silc_list_del(client->internal->commands, cmd);
      silc_free(cmd->name);
      silc_free(cmd);
      return TRUE;
    }
  }

  return FALSE;
}

/* Finds and returns a pointer to the command list. Return NULL if the
   command is not found. */

static SilcClientCommand silc_client_command_find(SilcClient client,
						  const char *name)
{
  SilcClientCommand cmd;

  silc_list_start(client->internal->commands);
  while ((cmd = silc_list_get(client->internal->commands)) != SILC_LIST_END) {
    if (cmd->name && !strcasecmp(cmd->name, name))
      return cmd;
  }

  return NULL;
}

/* Command thread destructor */

static void silc_client_command_destructor(SilcFSMThread thread,
					   void *fsm_context,
					   void *destructor_context)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  /* Removes commands that aren't waiting for reply but are waiting
     for something.  They may not have been removed yet. */
  silc_list_del(conn->internal->pending_commands, cmd);

  silc_client_command_free(cmd);
}

/* Add a command pending a command reply.  Used internally by the library. */

static SilcBool
silc_client_command_add_pending(SilcClientConnection conn,
				SilcClientCommandContext cmd,
				SilcClientCommandReply reply,
				void *context)
{
  SilcClientCommandReplyCallback cb;

  silc_mutex_lock(conn->internal->lock);

  /* Add pending callback, if defined */
  if (reply) {
    cb = silc_calloc(1, sizeof(*cb));
    if (!cb) {
      silc_mutex_unlock(conn->internal->lock);
      return FALSE;
    }
    cb->reply = reply;
    cb->context = context;
    silc_list_add(cmd->reply_callbacks, cb);
  }

  /* Add pending reply */
  silc_list_add(conn->internal->pending_commands, cmd);

  silc_mutex_unlock(conn->internal->lock);

  return TRUE;
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct format and in correct order.  Arguments come from
   variable argument list pointer. */

static SilcUInt16 silc_client_command_send_vap(SilcClient client,
					       SilcClientConnection conn,
					       SilcClientCommandContext cmd,
					       SilcCommand command,
					       SilcClientCommandReply reply,
					       void *reply_context,
					       SilcUInt32 argc, va_list ap)
{
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Send command %s", silc_get_command_name(command)));

  if (conn->internal->disconnected)
    return 0;

  if (!cmd->cmd_ident)
    cmd->cmd_ident = silc_client_cmd_ident(conn);

  /* Encode command payload */
  packet = silc_command_payload_encode_vap(command, cmd->cmd_ident, argc, ap);
  if (!packet)
    return 0;

  /* Send the command */
  if (!silc_packet_send(conn->stream, SILC_PACKET_COMMAND, 0,
			silc_buffer_datalen(packet))) {
    silc_buffer_free(packet);
    return 0;
  }

  /* Add the command pending command reply */
  silc_client_command_add_pending(conn, cmd, reply, reply_context);

  silc_buffer_free(packet);

  return cmd->cmd_ident;
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct format and in correct order.  Arguments come from
   arrays. */

static SilcUInt16
silc_client_command_send_arg_array(SilcClient client,
				   SilcClientConnection conn,
				   SilcClientCommandContext cmd,
				   SilcCommand command,
				   SilcClientCommandReply reply,
				   void *reply_context,
				   SilcUInt32 argc,
				   unsigned char **argv,
				   SilcUInt32 *argv_lens,
				   SilcUInt32 *argv_types)
{
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Send command %s", silc_get_command_name(command)));

  if (conn->internal->disconnected)
    return 0;

  if (!cmd->cmd_ident)
    cmd->cmd_ident = silc_client_cmd_ident(conn);

  /* Encode command payload */
  packet = silc_command_payload_encode(command, argc, argv, argv_lens,
				       argv_types, cmd->cmd_ident);
  if (!packet)
    return 0;

  /* Send the command */
  if (!silc_packet_send(conn->stream, SILC_PACKET_COMMAND, 0,
			silc_buffer_datalen(packet))) {
    silc_buffer_free(packet);
    return 0;
  }

  /* Add the command pending command reply */
  silc_client_command_add_pending(conn, cmd, reply, reply_context);

  silc_buffer_free(packet);

  return cmd->cmd_ident;
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct format and in correct order.  This is used internally
   by the library.  */

static SilcUInt16 silc_client_command_send_va(SilcClientConnection conn,
					      SilcClientCommandContext cmd,
					      SilcCommand command,
					      SilcClientCommandReply reply,
					      void *reply_context,
					      SilcUInt32 argc, ...)
{
  va_list ap;
  SilcUInt16 cmd_ident;

  va_start(ap, argc);
  cmd_ident = silc_client_command_send_vap(conn->client, conn, cmd, command,
					   reply, reply_context, argc, ap);
  va_end(ap);

  return cmd_ident;
}

/****************************** Command API *********************************/

/* Free command context and its internals */

void silc_client_command_free(SilcClientCommandContext cmd)
{
  SilcClientCommandReplyCallback cb;
  int i;

  for (i = 0; i < cmd->argc; i++)
    silc_free(cmd->argv[i]);
  silc_free(cmd->argv);
  silc_free(cmd->argv_lens);
  silc_free(cmd->argv_types);

  silc_list_start(cmd->reply_callbacks);
  while ((cb = silc_list_get(cmd->reply_callbacks)))
    silc_free(cb);

  silc_free(cmd);
}

/* Executes a command */

SilcUInt16 silc_client_command_call(SilcClient client,
				    SilcClientConnection conn,
				    const char *command_line, ...)
{
  va_list va;
  SilcUInt32 argc = 0;
  unsigned char **argv = NULL;
  SilcUInt32 *argv_lens = NULL, *argv_types = NULL;
  SilcClientCommand command;
  SilcClientCommandContext cmd;
  char *arg;

  if (!conn) {
    client->internal->ops->say(client, NULL, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
      "You are not connected to a server, please connect to server");
    return 0;
  }

  /* Parse arguments */
  va_start(va, command_line);
  if (command_line) {
    char *command_name;

    /* Get command name */
    command_name = silc_memdup(command_line, strcspn(command_line, " "));
    if (!command_name)
      return 0;

    /* Find command by name */
    command = silc_client_command_find(client, command_name);
    if (!command) {
      silc_free(command_name);
      return 0;
    }

    /* Parse command line */
    silc_parse_command_line((char *)command_line, &argv, &argv_lens,
			    &argv_types, &argc, command->max_args);

    silc_free(command_name);
  } else {
    arg = va_arg(va, char *);
    if (!arg)
      return 0;

    /* Find command by name */
    command = silc_client_command_find(client, arg);
    if (!command)
      return 0;

    while (arg) {
      argv = silc_realloc(argv, sizeof(*argv) * (argc + 1));
      argv_lens = silc_realloc(argv_lens, sizeof(*argv_lens) * (argc + 1));
      argv_types = silc_realloc(argv_types, sizeof(*argv_types) * (argc + 1));
      if (!argv || !argv_lens || !argv_types)
	return 0;
      argv[argc] = silc_memdup(arg, strlen(arg));
      if (!argv[argc])
	return 0;
      argv_lens[argc] = strlen(arg);
      argv_types[argc] = argc;
      argc++;
      arg = va_arg(va, char *);
    }
  }
  va_end(va);

  /* Allocate command context */
  cmd = silc_calloc(1, sizeof(*cmd));
  if (!cmd)
    return 0;
  cmd->conn = conn;
  cmd->cmd = command->cmd;
  cmd->argc = argc;
  cmd->argv = argv;
  cmd->argv_lens = argv_lens;
  cmd->argv_types = argv_types;
  cmd->cmd_ident = silc_client_cmd_ident(conn);
  cmd->called = TRUE;
  cmd->verbose = TRUE;
  silc_list_init(cmd->reply_callbacks,
		 struct SilcClientCommandReplyCallbackStruct, next);

  /*** Call command */
  SILC_LOG_DEBUG(("Calling %s command", silc_get_command_name(cmd->cmd)));
  silc_fsm_thread_init(&cmd->thread, &conn->internal->fsm, cmd,
		       silc_client_command_destructor, NULL, FALSE);
  silc_fsm_start_sync(&cmd->thread, command->command);

  return cmd->cmd_ident;
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct format and in correct order. */

SilcUInt16 silc_client_command_send(SilcClient client,
				    SilcClientConnection conn,
				    SilcCommand command,
				    SilcClientCommandReply reply,
				    void *reply_context,
				    SilcUInt32 argc, ...)
{
  SilcClientCommandContext cmd;
  va_list ap;

  if (!conn || !reply)
    return 0;

  /* Allocate command context */
  cmd = silc_calloc(1, sizeof(*cmd));
  if (!cmd)
    return 0;
  cmd->conn = conn;
  cmd->cmd = command;
  silc_list_init(cmd->reply_callbacks,
		 struct SilcClientCommandReplyCallbackStruct, next);

  /* Send the command */
  va_start(ap, argc);
  cmd->cmd_ident =
    silc_client_command_send_vap(client, conn, cmd, command, reply,
				 reply_context, argc, ap);
  va_end(ap);

  if (!cmd->cmd_ident) {
    silc_client_command_free(cmd);
    return 0;
  }

  /*** Wait for command reply */
  silc_fsm_thread_init(&cmd->thread, &conn->internal->fsm, cmd,
		       silc_client_command_destructor, NULL, FALSE);
  silc_fsm_start_sync(&cmd->thread, silc_client_command_reply_wait);

  return cmd->cmd_ident;
}

/* Generic function to send any command. The arguments must be sent already
   encoded into correct format and in correct order.  Arguments come from
   arrays. */

SilcUInt16 silc_client_command_send_argv(SilcClient client,
					 SilcClientConnection conn,
					 SilcCommand command,
					 SilcClientCommandReply reply,
					 void *reply_context,
					 SilcUInt32 argc,
					 unsigned char **argv,
					 SilcUInt32 *argv_lens,
					 SilcUInt32 *argv_types)
{
  SilcClientCommandContext cmd;

  if (!conn || !reply)
    return 0;

  /* Allocate command context */
  cmd = silc_calloc(1, sizeof(*cmd));
  if (!cmd)
    return 0;
  cmd->conn = conn;
  cmd->cmd = command;

  /* Send the command */
  cmd->cmd_ident =
    silc_client_command_send_arg_array(client, conn, cmd, command, reply,
				       reply_context, argc, argv, argv_lens,
				       argv_types);
  if (!cmd->cmd_ident) {
    silc_client_command_free(cmd);
    return 0;
  }

  /*** Wait for command reply */
  silc_fsm_thread_init(&cmd->thread, &conn->internal->fsm, cmd,
		       silc_client_command_destructor, NULL, FALSE);
  silc_fsm_start_sync(&cmd->thread, silc_client_command_reply_wait);

  return cmd->cmd_ident;
}

/* Attach to a command and command identifier to receive command reply. */

SilcBool silc_client_command_pending(SilcClientConnection conn,
				     SilcCommand command,
				     SilcUInt16 ident,
				     SilcClientCommandReply reply,
				     void *context)
{
  SilcClientCommandContext cmd;
  SilcClientCommandReplyCallback cb;

  if (!conn || !reply)
    return FALSE;

  SILC_LOG_DEBUG(("Add pending command reply for ident %d", ident));

  silc_mutex_lock(conn->internal->lock);

  /* Find the pending command */
  silc_list_start(conn->internal->pending_commands);
  while ((cmd = silc_list_get(conn->internal->pending_commands)))
    if ((cmd->cmd == command || command == SILC_COMMAND_NONE)
	&& cmd->cmd_ident == ident) {

      /* Add the callback */
      cb = silc_calloc(1, sizeof(*cb));
      if (!cb)
	continue;
      cb->reply = reply;
      cb->context = context;
      silc_list_add(cmd->reply_callbacks, cb);
    }

  silc_mutex_unlock(conn->internal->lock);

  return TRUE;
}

/******************************** WHOIS *************************************/

/* Command WHOIS. This command is used to query information about
   specific user. */

SILC_FSM_STATE(silc_client_command_whois)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcBuffer attrs = NULL;
  unsigned char count[4], *tmp = NULL;
  SilcBool details = FALSE, nick = FALSE;
  unsigned char *pubkey = NULL;
  char *nickname = NULL;
  int i;

  /* Given without arguments fetches client's own information */
  if (cmd->argc < 2) {
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1, 4,
				silc_buffer_data(conn->internal->local_idp),
				silc_buffer_len(conn->internal->local_idp));

    /* Notify application */
    COMMAND(SILC_STATUS_OK);

    /** Wait for command reply */
    silc_fsm_next(fsm, silc_client_command_reply_wait);
    return SILC_FSM_CONTINUE;
  }

  for (i = 1; i < cmd->argc; i++) {
    if (!strcasecmp(cmd->argv[i], "-details")) {
      details = TRUE;
    } else if (!strcasecmp(cmd->argv[i], "-pubkey") && cmd->argc > i + 1) {
      pubkey = cmd->argv[i + 1];
      i++;
    } else {
      /* We assume that the first parameter is the nickname, if it isn't
         -details or -pubkey. The last parameter should always be the count */
      if (i == 1) {
	nick = TRUE;
      } else if (i == cmd->argc - 1) {
	int c = atoi(cmd->argv[i]);
	SILC_PUT32_MSB(c, count);
	tmp = count;
      }
    }
  }

  if (details) {
    /* If pubkey is set, add all attributes to the attrs buffer, except
       public key */
    if (pubkey) {
      attrs = silc_client_attributes_request(SILC_ATTRIBUTE_USER_INFO,
                                             SILC_ATTRIBUTE_SERVICE,
                                             SILC_ATTRIBUTE_STATUS_MOOD,
                                             SILC_ATTRIBUTE_STATUS_FREETEXT,
                                             SILC_ATTRIBUTE_STATUS_MESSAGE,
                                             SILC_ATTRIBUTE_PREFERRED_LANGUAGE,
                                             SILC_ATTRIBUTE_PREFERRED_CONTACT,
                                             SILC_ATTRIBUTE_TIMEZONE,
                                             SILC_ATTRIBUTE_GEOLOCATION,
                                             SILC_ATTRIBUTE_DEVICE_INFO,
					     SILC_ATTRIBUTE_USER_ICON, 0);
    } else {
      attrs = silc_client_attributes_request(0);
    }
  }

  if (pubkey) {
    SilcAttributeObjPk obj;
    SilcPublicKey pk;

    if (!silc_pkcs_load_public_key(pubkey, &pk)) {
      SAY(client, conn, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
	  "Could not load public key %s, check the filename",
	  pubkey);
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }

    switch (silc_pkcs_get_type(pk)) {
    case SILC_PKCS_SILC:
      obj.type = "silc-rsa";
      break;
    case SILC_PKCS_SSH2:
      obj.type = "ssh-rsa";
      break;
    case SILC_PKCS_X509V3:
      obj.type = "x509v3-sign-rsa";
      break;
    case SILC_PKCS_OPENPGP:
      obj.type = "pgp-sign-rsa";
      break;
    default:
      goto out;
      break;
    }
    obj.data = silc_pkcs_public_key_encode(pk, &obj.data_len);

    attrs = silc_attribute_payload_encode(attrs,
                                          SILC_ATTRIBUTE_USER_PUBLIC_KEY,
                                          SILC_ATTRIBUTE_FLAG_VALID,
                                          &obj, sizeof(obj));
    silc_free(obj.data);
  }

  if (nick) {
    silc_client_nickname_parse(client, conn, cmd->argv[1], &nickname);
    if (!nickname)
      nickname = strdup(cmd->argv[1]);
  }

  /* Send command */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
			      3, 1, nick ? nickname : NULL,
			      nick ? strlen(nickname) : 0,
			      2, tmp ? tmp : NULL, tmp ? 4 : 0,
			      3, silc_buffer_datalen(attrs));
  silc_free(nickname);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/******************************** WHOWAS ************************************/

/* Command WHOWAS. This command is used to query history information about
   specific user that used to exist in the network. */

SILC_FSM_STATE(silc_client_command_whowas)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  unsigned char count[4];
  int c;

  if (cmd->argc < 2 || cmd->argc > 3) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /WHOWAS <nickname>[@<server>] [<count>]");
    COMMAND_ERROR((cmd->argc < 2 ? SILC_STATUS_ERR_NOT_ENOUGH_PARAMS :
		   SILC_STATUS_ERR_TOO_MANY_PARAMS));
    return SILC_FSM_FINISH;
  }

  if (cmd->argc == 2) {
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
				1, 1, cmd->argv[1], cmd->argv_lens[1]);
  } else {
    c = atoi(cmd->argv[2]);
    SILC_PUT32_MSB(c, count);
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
				2, 1, cmd->argv[1], cmd->argv_lens[1],
				2, count, sizeof(count));
  }

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/******************************** IDENTIFY **********************************/

/* Command IDENTIFY. This command is used to query information about
   specific user, especially ID's. */

SILC_FSM_STATE(silc_client_command_identify)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  unsigned char count[4];
  int c;

  if (cmd->argc < 2 || cmd->argc > 3)
    return SILC_FSM_FINISH;

  if (cmd->argc == 2) {
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
				1, 1, cmd->argv[1], cmd->argv_lens[1]);
  } else {
    c = atoi(cmd->argv[2]);
    SILC_PUT32_MSB(c, count);
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
				2, 1, cmd->argv[1], cmd->argv_lens[1],
				4, count, sizeof(count));
  }

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** NICK ************************************/

/* Command NICK. Shows current nickname/sets new nickname on current
   window. */

SILC_FSM_STATE(silc_client_command_nick)
{
  SilcClientCommandContext cmd2, cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /NICK <nickname>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (silc_utf8_strcasecmp(conn->local_entry->nickname, cmd->argv[1]))
    goto out;

  /* Show current nickname */
  if (cmd->argc < 2) {
    if (cmd->conn) {
      SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	  "Your nickname is %s on server %s",
	  conn->local_entry->nickname, conn->remote_host);
    } else {
      SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	  "Your nickname is %s", conn->local_entry->nickname);
    }

    COMMAND(SILC_STATUS_OK);
    goto out;
  }

  /* If JOIN command is active, wait for it to finish before sending NICK.
     To avoid problems locally with changing IDs while joining, we do this. */
  silc_mutex_lock(conn->internal->lock);
  silc_list_start(conn->internal->pending_commands);
  while ((cmd2 = silc_list_get(conn->internal->pending_commands))) {
    if (cmd2->cmd == SILC_COMMAND_JOIN) {
      silc_mutex_unlock(conn->internal->lock);
      silc_fsm_next_later(fsm, silc_client_command_nick, 0, 300000);
      return SILC_FSM_WAIT;
    }
  }
  silc_mutex_unlock(conn->internal->lock);

  if (cmd->argv_lens[1] > 128)
    cmd->argv_lens[1] = 128;

  /* Send the NICK command */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
			      1, 1, cmd->argv[1], cmd->argv_lens[1]);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/********************************** LIST ************************************/

/* Command LIST. Lists channels on the current server. */

SILC_FSM_STATE(silc_client_command_list)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel = NULL;
  SilcBuffer idp = NULL;

  if (cmd->argc == 2) {
    /* Get the Channel ID of the channel */
    channel = silc_client_get_channel(conn->client, cmd->conn, cmd->argv[1]);
    if (channel)
      idp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);
  }

  if (!idp)
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 0);
  else
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL,
				1, 1, silc_buffer_datalen(idp));

  silc_buffer_free(idp);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** TOPIC ***********************************/

/* Command TOPIC. Sets/shows topic on a channel. */

SILC_FSM_STATE(silc_client_command_topic)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel;
  SilcBuffer idp;
  char *name;

  if (cmd->argc < 2 || cmd->argc > 3) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /TOPIC <channel> [<topic>]");
    COMMAND_ERROR((cmd->argc < 2 ? SILC_STATUS_ERR_NOT_ENOUGH_PARAMS :
		   SILC_STATUS_ERR_TOO_MANY_PARAMS));
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get the Channel ID of the channel */
  channel = silc_client_get_channel(conn->client, conn, name);
  if (!channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  idp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);

  /* Send TOPIC command to the server */
  if (cmd->argc > 2)
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 2,
				1, silc_buffer_datalen(idp),
				2, cmd->argv[2], strlen(cmd->argv[2]));
  else
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
				1, silc_buffer_datalen(idp));

  silc_buffer_free(idp);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/********************************* INVITE ***********************************/

/* Command INVITE. Invites specific client to join a channel. This is
   also used to mange the invite list of the channel. */

SILC_FSM_STATE(silc_client_command_invite)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel = NULL;
  SilcBuffer clidp, chidp, args = NULL;
  SilcPublicKey pubkey = NULL;
  SilcDList clients = NULL;
  char *nickname = NULL, *name;
  char *invite = NULL;
  unsigned char action[1];

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /INVITE <channel> [<nickname>[@server>]"
	"[+|-[<nickname>[@<server>[!<username>[@hostname>]]]]]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
    silc_client_ref_channel(client, conn, channel);
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(conn->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  /* Parse the typed nickname. */
  if (cmd->argc == 3) {
    if (cmd->argv[2][0] != '+' && cmd->argv[2][0] != '-') {
      silc_client_nickname_parse(client, conn, cmd->argv[2], &nickname);

      /* Find client entry */
      clients = silc_client_get_clients_local(client, conn, cmd->argv[2],
					      FALSE);
      if (!clients)
	/* Resolve client information */
	SILC_FSM_CALL(silc_client_get_clients(
				      client, conn, nickname, NULL,
				      silc_client_command_resolve_continue,
				      cmd));

      client_entry = silc_dlist_get(clients);
    } else {
      if (cmd->argv[2][0] == '+')
	action[0] = 0x00;
      else
	action[0] = 0x01;

      /* Check if it is public key file to be added to invite list */
      silc_pkcs_load_public_key(cmd->argv[2] + 1, &pubkey);
      invite = cmd->argv[2];
      if (!pubkey)
	invite++;
    }
  }

  if (invite) {
    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    if (pubkey) {
      chidp = silc_public_key_payload_encode(pubkey);
      args = silc_argument_payload_encode_one(args, silc_buffer_data(chidp),
					      silc_buffer_len(chidp), 2);
      silc_buffer_free(chidp);
      silc_pkcs_public_key_free(pubkey);
    } else {
      args = silc_argument_payload_encode_one(args, invite, strlen(invite), 1);
    }
  }

  /* Send the command */
  chidp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);
  if (client_entry) {
    clidp = silc_id_payload_encode(&client_entry->id, SILC_ID_CLIENT);
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 4,
				1, silc_buffer_datalen(chidp),
				2, silc_buffer_datalen(clidp),
				3, args ? action : NULL, args ? 1 : 0,
				4, silc_buffer_datalen(args));
    silc_buffer_free(clidp);
  } else {
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 3,
				1, silc_buffer_datalen(chidp),
				3, args ? action : NULL, args ? 1 : 0,
				4, silc_buffer_datalen(args));
  }

  silc_buffer_free(chidp);
  silc_buffer_free(args);
  silc_free(nickname);
  silc_client_list_free(client, conn, clients);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  silc_free(nickname);
  return SILC_FSM_FINISH;
}

/********************************** QUIT ************************************/

/* Close the connection */

SILC_FSM_STATE(silc_client_command_quit_final)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  SILC_LOG_DEBUG(("Quitting"));

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /* Signal to close connection */
  conn->internal->status = SILC_CLIENT_CONN_DISCONNECTED;
  if (!conn->internal->disconnected) {
    conn->internal->disconnected = TRUE;
    SILC_FSM_EVENT_SIGNAL(&conn->internal->wait_event);
  }

  return SILC_FSM_FINISH;
}

/* Command QUIT. Closes connection with current server. */

SILC_FSM_STATE(silc_client_command_quit)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  if (cmd->argc > 1)
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
				1, cmd->argv[1], cmd->argv_lens[1]);
  else
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 0);

  /* Sleep for a while */
  sleep(1);

  /* We close the connection with a little timeout */
  silc_fsm_next_later(fsm, silc_client_command_quit_final, 2, 0);
  return SILC_FSM_WAIT;
}

/********************************** KILL ************************************/

/* Command KILL. Router operator can use this command to remove an client
   fromthe SILC Network. */

SILC_FSM_STATE(silc_client_command_kill)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcBuffer idp, auth = NULL;
  SilcClientEntry target;
  SilcDList clients;
  char *nickname = NULL, *comment = NULL;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /KILL <nickname> [<comment>] [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  /* Parse the typed nickname. */
  if (!silc_client_nickname_parse(client, conn, cmd->argv[1], &nickname))
    return SILC_FSM_FINISH;

  /* Get the target client */
  clients = silc_client_get_clients_local(client, conn, cmd->argv[1], FALSE);
  if (!clients)
    /* Resolve client information */
    SILC_FSM_CALL(silc_client_get_clients(client, conn, nickname, NULL,
					  silc_client_command_resolve_continue,
					  cmd));

  target = silc_dlist_get(clients);

  if (cmd->argc >= 3) {
    if (strcasecmp(cmd->argv[2], "-pubkey"))
      comment = cmd->argv[2];

    if (!strcasecmp(cmd->argv[2], "-pubkey") ||
	(cmd->argc >= 4 && !strcasecmp(cmd->argv[3], "-pubkey"))) {
      /* Encode the public key authentication payload */
      auth = silc_auth_public_key_auth_generate(conn->public_key,
						conn->private_key,
						conn->client->rng,
						conn->internal->sha1hash,
						&target->id, SILC_ID_CLIENT);
    }
  }

  /* Send the KILL command to the server */
  idp = silc_id_payload_encode(&target->id, SILC_ID_CLIENT);
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 3,
			      1, silc_buffer_datalen(idp),
			      2, comment, comment ? strlen(comment) : 0,
			      3, silc_buffer_datalen(auth));
  silc_buffer_free(idp);
  silc_buffer_free(auth);
  silc_free(nickname);
  silc_client_list_free(client, conn, clients);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** INFO ************************************/

/* Command INFO. Request information about specific server. If specific
   server is not provided the current server is used. */

SILC_FSM_STATE(silc_client_command_info)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  /* Send the command */
  if (cmd->argc == 2)
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
				1, cmd->argv[1], cmd->argv_lens[1]);
  else
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 0);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** STATS ***********************************/

/* Command STATS. Shows server and network statistics. */

SILC_FSM_STATE(silc_client_command_stats)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  /* Send the command */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
			      1, silc_buffer_datalen(conn->internal->
						     remote_idp));

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** PING ************************************/

/* Command PING. Sends ping to server. */

SILC_FSM_STATE(silc_client_command_ping)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  if (cmd->argc < 2) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  /* Send the command */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
			      1, silc_buffer_datalen(conn->internal->
						     remote_idp));

  /* Save ping time */
  cmd->context = SILC_64_TO_PTR(silc_time());

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** JOIN ************************************/

/* Command JOIN. Joins to a channel. */

SILC_FSM_STATE(silc_client_command_join)
{
  SilcClientCommandContext cmd2, cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel = NULL;
  SilcBuffer auth = NULL, cauth = NULL;
  char *name, *passphrase = NULL, *pu8, *cipher = NULL, *hmac = NULL;
  int i, passphrase_len = 0;

  if (cmd->argc < 2) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  /* See if we have joined to the requested channel already */
  channel = silc_client_get_channel(conn->client, conn, cmd->argv[1]);
  if (channel && silc_client_on_channel(channel, conn->local_entry))
    goto out;

  /* If NICK command is active, wait for it to finish before sending JOIN.
     To avoid problems locally with changing IDs while joining, we do this. */
  silc_mutex_lock(conn->internal->lock);
  silc_list_start(conn->internal->pending_commands);
  while ((cmd2 = silc_list_get(conn->internal->pending_commands))) {
    if (cmd2->cmd == SILC_COMMAND_NICK) {
      silc_mutex_unlock(conn->internal->lock);
      silc_fsm_next_later(fsm, silc_client_command_join, 0, 300000);
      return SILC_FSM_WAIT;
    }
  }
  silc_mutex_unlock(conn->internal->lock);

  if (cmd->argv_lens[1] > 256)
    cmd->argv_lens[1] = 256;

  name = cmd->argv[1];

  for (i = 2; i < cmd->argc; i++) {
    if (!strcasecmp(cmd->argv[i], "-cipher") && cmd->argc > i + 1) {
      cipher = cmd->argv[++i];
    } else if (!strcasecmp(cmd->argv[i], "-hmac") && cmd->argc > i + 1) {
      hmac = cmd->argv[++i];
    } else if (!strcasecmp(cmd->argv[i], "-founder")) {
      auth = silc_auth_public_key_auth_generate(conn->public_key,
						conn->private_key,
						conn->client->rng,
						conn->internal->sha1hash,
						conn->local_id,
						SILC_ID_CLIENT);
    } else if (!strcasecmp(cmd->argv[i], "-auth")) {
      SilcPublicKey pubkey = conn->public_key;
      SilcPrivateKey privkey = conn->private_key;
      unsigned char *pk, pkhash[SILC_HASH_MAXLEN], *pubdata;
      SilcUInt32 pk_len;

      if (cmd->argc >= i + 3) {
	char *pass = "";
	if (cmd->argc >= i + 4) {
	  pass = cmd->argv[i + 3];
	  i++;
	}
	if (!silc_load_key_pair(cmd->argv[i + 1], cmd->argv[i + 2], pass,
				&pubkey, &privkey)) {
	  SAY(conn->client, conn, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
	      "Could not load key pair, check your arguments");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	i += 2;
      }

      pk = silc_pkcs_public_key_encode(pubkey, &pk_len);
      silc_hash_make(conn->internal->sha1hash, pk, pk_len, pkhash);
      silc_free(pk);
      pubdata = silc_rng_get_rn_data(conn->client->rng, 128);
      memcpy(pubdata, pkhash, 20);
      cauth = silc_auth_public_key_auth_generate_wpub(pubkey, privkey,
						      pubdata, 128,
						      conn->internal->sha1hash,
						      conn->local_id,
						      SILC_ID_CLIENT);
      memset(pubdata, 0, 128);
      silc_free(pubdata);
    } else {
      /* Passphrases must be UTF-8 encoded, so encode if it is not */
      if (!silc_utf8_valid(cmd->argv[i], cmd->argv_lens[i])) {
	passphrase_len = silc_utf8_encoded_len(cmd->argv[i],
					       cmd->argv_lens[i], 0);
	pu8 = silc_calloc(passphrase_len, sizeof(*pu8));
	passphrase_len = silc_utf8_encode(cmd->argv[i], cmd->argv_lens[i],
					  0, pu8, passphrase_len);
	passphrase = pu8;
      } else {
	passphrase = strdup(cmd->argv[i]);
	passphrase_len = cmd->argv_lens[i];
      }
    }
  }

  /* Send JOIN command to the server */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 7,
			      1, name, strlen(name),
			      2, silc_buffer_datalen(conn->internal->
						     local_idp),
			      3, passphrase, passphrase_len,
			      4, cipher, cipher ? strlen(cipher) : 0,
			      5, hmac, hmac ? strlen(hmac) : 0,
			      6, silc_buffer_datalen(auth),
			      7, silc_buffer_datalen(cauth));

  silc_buffer_free(auth);
  silc_buffer_free(cauth);
  if (passphrase)
    memset(passphrase, 0, strlen(passphrase));
  silc_free(passphrase);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  silc_client_unref_channel(client, conn, channel);
  return SILC_FSM_FINISH;
}

/********************************** MOTD ************************************/

/* MOTD command. Requests motd from server. */

SILC_FSM_STATE(silc_client_command_motd)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  if (cmd->argc < 1 || cmd->argc > 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /MOTD [<server>]");
    COMMAND_ERROR((cmd->argc < 1 ? SILC_STATUS_ERR_NOT_ENOUGH_PARAMS :
		   SILC_STATUS_ERR_TOO_MANY_PARAMS));
    return SILC_FSM_FINISH;
  }

  /* Send the command */
  if (cmd->argc == 1)
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
				1, conn->remote_host,
				strlen(conn->remote_host));
  else
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
				1, cmd->argv[1], cmd->argv_lens[1]);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** UMODE ***********************************/

/* UMODE. Set/unset user mode in SILC. This is used mainly to unset the
   modes as client cannot set itself server/router operator privileges. */

SILC_FSM_STATE(silc_client_command_umode)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  unsigned char *cp, modebuf[4];
  SilcUInt32 mode, add, len;
  int i;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /UMODE +|-<modes>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  mode = conn->local_entry->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[1][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Parse mode */
  cp = cmd->argv[1] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'a':
      if (add) {
	mode = 0;
	mode |= SILC_UMODE_SERVER_OPERATOR;
	mode |= SILC_UMODE_ROUTER_OPERATOR;
	mode |= SILC_UMODE_GONE;
	mode |= SILC_UMODE_INDISPOSED;
	mode |= SILC_UMODE_BUSY;
	mode |= SILC_UMODE_PAGE;
	mode |= SILC_UMODE_HYPER;
	mode |= SILC_UMODE_ROBOT;
	mode |= SILC_UMODE_BLOCK_PRIVMSG;
	mode |= SILC_UMODE_REJECT_WATCHING;
      } else {
	mode = SILC_UMODE_NONE;
      }
      break;
    case 's':
      if (add)
	mode |= SILC_UMODE_SERVER_OPERATOR;
      else
	mode &= ~SILC_UMODE_SERVER_OPERATOR;
      break;
    case 'r':
      if (add)
	mode |= SILC_UMODE_ROUTER_OPERATOR;
      else
	mode &= ~SILC_UMODE_ROUTER_OPERATOR;
      break;
    case 'g':
      if (add)
	mode |= SILC_UMODE_GONE;
      else
	mode &= ~SILC_UMODE_GONE;
      break;
    case 'i':
      if (add)
	mode |= SILC_UMODE_INDISPOSED;
      else
	mode &= ~SILC_UMODE_INDISPOSED;
      break;
    case 'b':
      if (add)
	mode |= SILC_UMODE_BUSY;
      else
	mode &= ~SILC_UMODE_BUSY;
      break;
    case 'p':
      if (add)
	mode |= SILC_UMODE_PAGE;
      else
	mode &= ~SILC_UMODE_PAGE;
      break;
    case 'h':
      if (add)
	mode |= SILC_UMODE_HYPER;
      else
	mode &= ~SILC_UMODE_HYPER;
      break;
    case 't':
      if (add)
	mode |= SILC_UMODE_ROBOT;
      else
	mode &= ~SILC_UMODE_ROBOT;
      break;
    case 'P':
      if (add)
	mode |= SILC_UMODE_BLOCK_PRIVMSG;
      else
	mode &= ~SILC_UMODE_BLOCK_PRIVMSG;
      break;
    case 'w':
      if (add)
	mode |= SILC_UMODE_REJECT_WATCHING;
      else
	mode &= ~SILC_UMODE_REJECT_WATCHING;
      break;
    case 'I':
      if (add)
	mode |= SILC_UMODE_BLOCK_INVITE;
      else
	mode &= ~SILC_UMODE_BLOCK_INVITE;
      break;
    default:
      COMMAND_ERROR(SILC_STATUS_ERR_UNKNOWN_MODE);
      return SILC_FSM_FINISH;
      break;
    }
  }

  SILC_PUT32_MSB(mode, modebuf);

  /* Send the command */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 2,
			      1, silc_buffer_datalen(conn->internal->
						     local_idp),
			      2, modebuf, sizeof(modebuf));

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** CMODE ***********************************/

/* CMODE command. Sets channel mode. Modes that does not require any arguments
   can be set several at once. Those modes that require argument must be set
   separately (unless set with modes that does not require arguments). */

SILC_FSM_STATE(silc_client_command_cmode)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel = NULL;
  SilcBuffer chidp, auth = NULL, pk = NULL;
  unsigned char *name, *cp, modebuf[4], tmp[4], *arg = NULL;
  SilcUInt32 mode, add, type, len, arg_len = 0;
  int i;

  if (cmd->argc < 3) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
    silc_client_ref_channel(client, conn, channel);
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(conn->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  mode = channel->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[2][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Argument type to be sent to server */
  type = 0;

  /* Parse mode */
  cp = cmd->argv[2] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'p':
      if (add)
	mode |= SILC_CHANNEL_MODE_PRIVATE;
      else
	mode &= ~SILC_CHANNEL_MODE_PRIVATE;
      break;
    case 's':
      if (add)
	mode |= SILC_CHANNEL_MODE_SECRET;
      else
	mode &= ~SILC_CHANNEL_MODE_SECRET;
      break;
    case 'k':
      if (add)
	mode |= SILC_CHANNEL_MODE_PRIVKEY;
      else
	mode &= ~SILC_CHANNEL_MODE_PRIVKEY;
      break;
    case 'i':
      if (add)
	mode |= SILC_CHANNEL_MODE_INVITE;
      else
	mode &= ~SILC_CHANNEL_MODE_INVITE;
      break;
    case 't':
      if (add)
	mode |= SILC_CHANNEL_MODE_TOPIC;
      else
	mode &= ~SILC_CHANNEL_MODE_TOPIC;
      break;
    case 'm':
      if (add)
	mode |= SILC_CHANNEL_MODE_SILENCE_USERS;
      else
	mode &= ~SILC_CHANNEL_MODE_SILENCE_USERS;
      break;
    case 'M':
      if (add)
	mode |= SILC_CHANNEL_MODE_SILENCE_OPERS;
      else
	mode &= ~SILC_CHANNEL_MODE_SILENCE_OPERS;
      break;
    case 'l':
      if (add) {
	int ll;
	mode |= SILC_CHANNEL_MODE_ULIMIT;
	type = 3;
	if (cmd->argc < 4) {
	  SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	ll = atoi(cmd->argv[3]);
	SILC_PUT32_MSB(ll, tmp);
	arg = tmp;
	arg_len = 4;
      } else {
	mode &= ~SILC_CHANNEL_MODE_ULIMIT;
      }
      break;
    case 'a':
      if (add) {
	mode |= SILC_CHANNEL_MODE_PASSPHRASE;
	type = 4;
	if (cmd->argc < 4) {
	  SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_PASSPHRASE;
      }
      break;
    case 'c':
      if (add) {
	mode |= SILC_CHANNEL_MODE_CIPHER;
	type = 5;
	if (cmd->argc < 4) {
	  SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_CIPHER;
      }
      break;
    case 'h':
      if (add) {
	mode |= SILC_CHANNEL_MODE_HMAC;
	type = 6;
	if (cmd->argc < 4) {
	  SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	      "Usage: /CMODE <channel> +|-<modes> [{ <arguments>}]");
	  COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	  goto out;
	}
	arg = cmd->argv[3];
	arg_len = cmd->argv_lens[3];
      } else {
	mode &= ~SILC_CHANNEL_MODE_HMAC;
      }
      break;
    case 'f':
      if (add) {
	SilcPublicKey pubkey = conn->public_key;
	SilcPrivateKey privkey = conn->private_key;

	mode |= SILC_CHANNEL_MODE_FOUNDER_AUTH;
	type = 7;

	if (cmd->argc >= 5) {
	  char *pass = "";
	  if (cmd->argc >= 6)
	    pass = cmd->argv[5];
	  if (!silc_load_key_pair(cmd->argv[3], cmd->argv[4], pass,
				  &pubkey, &privkey)) {
	    SAY(client, conn, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
		"Could not load key pair, check your arguments");
	    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	    goto out;
	  }
	}

	pk = silc_public_key_payload_encode(pubkey);
	auth = silc_auth_public_key_auth_generate(pubkey, privkey,
						  conn->client->rng,
						  conn->internal->sha1hash,
						  conn->local_id,
						  SILC_ID_CLIENT);
	arg = silc_buffer_data(auth);
	arg_len = silc_buffer_len(auth);
      } else {
	mode &= ~SILC_CHANNEL_MODE_FOUNDER_AUTH;
      }
      break;
    case 'C':
      if (add) {
	int k;
	SilcBool chadd = FALSE;
	SilcPublicKey chpk = NULL;

	mode |= SILC_CHANNEL_MODE_CHANNEL_AUTH;
	type = 9;

	if (cmd->argc == 3) {
	  /* Send empty command to receive the public key list. */
	  chidp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);
	  silc_client_command_send_va(conn, cmd, SILC_COMMAND_CMODE,
				      NULL, NULL, 1,
				      1, silc_buffer_datalen(chidp));
	  silc_buffer_free(chidp);

	  /* Notify application */
	  COMMAND(SILC_STATUS_OK);
	  goto out;
	}

	if (cmd->argc >= 4) {
	  auth = silc_buffer_alloc_size(2);
	  silc_buffer_format(auth,
			     SILC_STR_UI_SHORT(cmd->argc - 3),
			     SILC_STR_END);
	}

	for (k = 3; k < cmd->argc; k++) {
	  if (cmd->argv[k][0] == '+')
	    chadd = TRUE;
	  if (!silc_pkcs_load_public_key(cmd->argv[k] + 1, &chpk)) {
	    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
		"Could not load public key %s, check the filename",
		cmd->argv[k]);
	    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	    silc_buffer_free(auth);
	    goto out;
	  }

	  if (chpk) {
	    pk = silc_public_key_payload_encode(chpk);
	    auth = silc_argument_payload_encode_one(auth,
						    silc_buffer_datalen(pk),
						    chadd ? 0x00 : 0x01);
	    silc_pkcs_public_key_free(chpk);
	    silc_buffer_free(pk);
	    pk = NULL;
	  }
	}

	arg = silc_buffer_data(auth);
	arg_len = silc_buffer_len(auth);
      } else {
	mode &= ~SILC_CHANNEL_MODE_CHANNEL_AUTH;
      }
      break;
    default:
      COMMAND_ERROR(SILC_STATUS_ERR_UNKNOWN_MODE);
      goto out;
      break;
    }
  }

  chidp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(mode, modebuf);

  /* Send the command. We support sending only one mode at once that
     requires an argument. */
  if (type && arg) {
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 4,
				1, silc_buffer_datalen(chidp),
				2, modebuf, sizeof(modebuf),
				type, arg, arg_len,
				8, silc_buffer_datalen(pk));
  } else {
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 2,
				1, silc_buffer_datalen(chidp),
				2, modebuf, sizeof(modebuf));
  }

  silc_buffer_free(chidp);
  silc_buffer_free(auth);
  silc_buffer_free(pk);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  silc_client_unref_channel(client, conn, channel);
  return SILC_FSM_FINISH;
}

/********************************* CUMODE ***********************************/

/* CUMODE command. Changes client's mode on a channel. */

SILC_FSM_STATE(silc_client_command_cumode)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel = NULL;
  SilcChannelUser chu;
  SilcClientEntry client_entry;
  SilcBuffer clidp, chidp, auth = NULL;
  SilcDList clients = NULL;
  unsigned char *name, *cp, modebuf[4];
  SilcUInt32 mode = 0, add, len;
  char *nickname = NULL;
  int i;

  if (cmd->argc < 4) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /CUMODE <channel> +|-<modes> <nickname>[@<server>]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
    silc_client_ref_channel(client, conn, channel);
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(conn->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  /* Parse the typed nickname. */
  silc_client_nickname_parse(client, conn, cmd->argv[3], &nickname);

  /* Find client entry */
  clients = silc_client_get_clients_local(client, conn, cmd->argv[3], FALSE);
  if (!clients)
    /* Resolve client information */
    SILC_FSM_CALL(silc_client_get_clients(client, conn, nickname, NULL,
					  silc_client_command_resolve_continue,
					  cmd));

  client_entry = silc_dlist_get(clients);

  /* Get the current mode */
  chu = silc_client_on_channel(channel, client_entry);
  if (chu)
    mode = chu->mode;

  /* Are we adding or removing mode */
  if (cmd->argv[2][0] == '-')
    add = FALSE;
  else
    add = TRUE;

  /* Parse mode */
  cp = cmd->argv[2] + 1;
  len = strlen(cp);
  for (i = 0; i < len; i++) {
    switch(cp[i]) {
    case 'a':
      if (add) {
	mode |= SILC_CHANNEL_UMODE_CHANFO;
	mode |= SILC_CHANNEL_UMODE_CHANOP;
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      } else {
	mode = SILC_CHANNEL_UMODE_NONE;
      }
      break;
    case 'f':
      if (add) {
	SilcPublicKey pubkey = conn->public_key;
	SilcPrivateKey privkey = conn->private_key;

	if (cmd->argc >= 6) {
	  char *pass = "";
	  if (cmd->argc >= 7)
	    pass = cmd->argv[6];
	  if (!silc_load_key_pair(cmd->argv[4], cmd->argv[5], pass,
				  &pubkey, &privkey)) {
	    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
		"Could not load key pair, check your arguments");
	    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
	    goto out;
	  }
	}

	auth = silc_auth_public_key_auth_generate(pubkey, privkey,
						  conn->client->rng,
						  conn->internal->sha1hash,
						  conn->local_id,
						  SILC_ID_CLIENT);
	mode |= SILC_CHANNEL_UMODE_CHANFO;
      } else {
	mode &= ~SILC_CHANNEL_UMODE_CHANFO;
      }
      break;
    case 'o':
      if (add)
	mode |= SILC_CHANNEL_UMODE_CHANOP;
      else
	mode &= ~SILC_CHANNEL_UMODE_CHANOP;
      break;
    case 'b':
      if (add)
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
      else
	mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES;
      break;
    case 'u':
      if (add)
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
      else
	mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS;
      break;
    case 'r':
      if (add)
	mode |= SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      else
	mode &= ~SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS;
      break;
    case 'q':
      if (add)
	mode |= SILC_CHANNEL_UMODE_QUIET;
      else
	mode &= ~SILC_CHANNEL_UMODE_QUIET;
      break;
    default:
      COMMAND_ERROR(SILC_STATUS_ERR_UNKNOWN_MODE);
      goto out;
      break;
    }
  }

  chidp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);
  SILC_PUT32_MSB(mode, modebuf);
  clidp = silc_id_payload_encode(&client_entry->id, SILC_ID_CLIENT);

  /* Send the command packet. We support sending only one mode at once
     that requires an argument. */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, auth ? 4 : 3,
			      1, silc_buffer_datalen(chidp),
			      2, modebuf, 4,
			      3, silc_buffer_datalen(clidp),
			      4, silc_buffer_datalen(auth));

  silc_buffer_free(chidp);
  silc_buffer_free(clidp);
  if (auth)
    silc_buffer_free(auth);
  silc_free(nickname);
  silc_client_list_free(client, conn, clients);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  silc_client_unref_channel(client, conn, channel);
  silc_client_list_free(client, conn, clients);
  silc_free(nickname);
  return SILC_FSM_FINISH;
}

/********************************** KICK ************************************/

/* KICK command. Kicks a client out of channel. */

SILC_FSM_STATE(silc_client_command_kick)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel = NULL;
  SilcBuffer idp, idp2;
  SilcClientEntry target;
  SilcDList clients = NULL;
  char *name;

  if (cmd->argc < 3) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /KICK <channel> <nickname> [<comment>]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  if (!conn->current_channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get the Channel ID of the channel */
  channel = silc_client_get_channel(conn->client, conn, name);
  if (!channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  /* Get the target client */
  clients = silc_client_get_clients_local(client, conn, cmd->argv[2], FALSE);
  if (!clients) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"No such client: %s", cmd->argv[2]);
    COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
    goto out;
  }
  target = silc_dlist_get(clients);

  /* Send KICK command to the server */
  idp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);
  idp2 = silc_id_payload_encode(&target->id, SILC_ID_CLIENT);
  if (cmd->argc == 3)
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 2,
				1, silc_buffer_datalen(idp),
				2, silc_buffer_datalen(idp2));
  else
    silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 3,
				1, silc_buffer_datalen(idp),
				2, silc_buffer_datalen(idp2),
				3, cmd->argv[3], strlen(cmd->argv[3]));

  silc_buffer_free(idp);
  silc_buffer_free(idp2);
  silc_client_list_free(client, conn, clients);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  silc_client_unref_channel(client, conn, channel);
  return SILC_FSM_FINISH;
}

/***************************** OPER & SILCOPER ******************************/

typedef struct {
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
} *SilcClientCommandOper;

/* Ask passphrase callback */

static void silc_client_command_oper_cb(unsigned char *data,
					SilcUInt32 data_len, void *context)
{
  SilcClientCommandContext cmd = context;
  SilcClientCommandOper oper = cmd->context;

  if (data && data_len)
    oper->passphrase = silc_memdup(data, data_len);
  oper->passphrase_len = data_len;

  /* Continue */
  SILC_FSM_CALL_CONTINUE(&cmd->thread);
}

/* Send OPER/SILCOPER command */

SILC_FSM_STATE(silc_client_command_oper_send)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClientCommandOper oper = cmd->context;
  SilcBuffer auth;

  if (!oper || !oper->passphrase) {
    /* Encode the public key authentication payload */
    auth = silc_auth_public_key_auth_generate(conn->public_key,
					      conn->private_key,
					      conn->client->rng,
					      conn->internal->hash,
					      conn->local_id,
					      SILC_ID_CLIENT);
  } else {
    /* Encode the password authentication payload */
    auth = silc_auth_payload_encode(SILC_AUTH_PASSWORD, NULL, 0,
				    oper->passphrase, oper->passphrase_len);
  }

  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 2,
			      1, cmd->argv[1], strlen(cmd->argv[1]),
			      2, silc_buffer_datalen(auth));

  silc_buffer_clear(auth);
  silc_buffer_free(auth);
  if (oper) {
    silc_free(oper->passphrase);
    silc_free(oper);
  }

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/* OPER command. Used to obtain server operator privileges. */

SILC_FSM_STATE(silc_client_command_oper)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClientCommandOper oper;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /OPER <username> [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  silc_fsm_next(fsm, silc_client_command_oper_send);

  /* Get passphrase */
  if (cmd->argc < 3) {
    oper = silc_calloc(1, sizeof(*oper));
    if (!oper)
      return SILC_FSM_FINISH;
    cmd->context = oper;
    SILC_FSM_CALL(conn->client->internal->
		  ops->ask_passphrase(conn->client, conn,
				      silc_client_command_oper_cb, cmd));
  }

  return SILC_FSM_CONTINUE;
}

/* SILCOPER command. Used to obtain router operator privileges. */

SILC_FSM_STATE(silc_client_command_silcoper)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClientCommandOper oper;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /SILCOPER <username> [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  silc_fsm_next(fsm, silc_client_command_oper_send);

  /* Get passphrase */
  if (cmd->argc < 3) {
    oper = silc_calloc(1, sizeof(*oper));
    if (!oper)
      return SILC_FSM_FINISH;
    cmd->context = oper;
    SILC_FSM_CALL(conn->client->internal->
		  ops->ask_passphrase(conn->client, conn,
				      silc_client_command_oper_cb, cmd));
  }

  return SILC_FSM_CONTINUE;
}

/*********************************** BAN ************************************/

/* Command BAN. This is used to manage the ban list of the channel. */

SILC_FSM_STATE(silc_client_command_ban)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel;
  SilcBuffer chidp, args = NULL;
  char *name, *ban = NULL;
  unsigned char action[1];
  SilcPublicKey pubkey = NULL;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /BAN <channel> "
	"[+|-[<nickname>[@<server>[!<username>[@hostname>]]]]]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }

    channel = conn->current_channel;
    silc_client_ref_channel(client, conn, channel);
  } else {
    name = cmd->argv[1];

    channel = silc_client_get_channel(conn->client, conn, name);
    if (!channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
  }

  if (cmd->argc == 3) {
    if (cmd->argv[2][0] == '+')
      action[0] = 0x00;
    else
      action[0] = 0x01;

    /* Check if it is public key file to be added to invite list */
    silc_pkcs_load_public_key(cmd->argv[2] + 1, &pubkey);
    ban = cmd->argv[2];
    if (!pubkey)
      ban++;
  }

  if (ban) {
    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    if (pubkey) {
      chidp = silc_public_key_payload_encode(pubkey);
      args = silc_argument_payload_encode_one(args,
					      silc_buffer_datalen(chidp), 2);
      silc_buffer_free(chidp);
      silc_pkcs_public_key_free(pubkey);
    } else {
      args = silc_argument_payload_encode_one(args, ban, strlen(ban), 1);
    }
  }

  chidp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);

  /* Send the command */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 3,
			      1, silc_buffer_datalen(chidp),
			      2, args ? action : NULL, args ? 1 : 0,
			      3, silc_buffer_datalen(args));

  silc_buffer_free(chidp);
  silc_buffer_free(args);
  silc_client_unref_channel(client, conn, channel);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/********************************* DETACH ***********************************/

/* Command DETACH. This is used to detach from the server */

SILC_FSM_STATE(silc_client_command_detach)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;

  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 0);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************** WATCH ***********************************/

/* Command WATCH. */

SILC_FSM_STATE(silc_client_command_watch)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcBuffer args = NULL;
  int type = 0;
  const char *pubkey = NULL;
  SilcBool pubkey_add = TRUE;

  if (cmd->argc < 3) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (!strcasecmp(cmd->argv[1], "-add")) {
    type = 2;
  } else if (!strcasecmp(cmd->argv[1], "-del")) {
    type = 3;
  } else if (!strcasecmp(cmd->argv[1], "-pubkey") && cmd->argc >= 3) {
    type = 4;
    pubkey = cmd->argv[2] + 1;
    if (cmd->argv[2][0] == '-')
      pubkey_add = FALSE;
  } else {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (pubkey) {
    SilcPublicKey pk;
    SilcBuffer buffer;

    if (!silc_pkcs_load_public_key(pubkey, &pk)) {
      SAY(conn->client, conn, SILC_CLIENT_MESSAGE_COMMAND_ERROR,
	  "Could not load public key %s, check the filename", pubkey);
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
      goto out;
    }

    args = silc_buffer_alloc_size(2);
    silc_buffer_format(args,
		       SILC_STR_UI_SHORT(1),
		       SILC_STR_END);
    buffer = silc_public_key_payload_encode(pk);
    args = silc_argument_payload_encode_one(args, silc_buffer_datalen(buffer),
					    pubkey_add ? 0x00 : 0x01);
    silc_buffer_free(buffer);
    silc_pkcs_public_key_free(pk);
  }

  /* If watching by nickname, resolve all users with that nickname so that
     we get their information immediately. */
  if (type == 2)
    silc_client_get_clients(conn->client, conn, cmd->argv[2], NULL,
			    silc_client_command_resolve_dummy, NULL);

  /* Send the commmand */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 2,
			      1, silc_buffer_datalen(conn->internal->
						     local_idp),
			      type, pubkey ? args->data : cmd->argv[2],
			      pubkey ? silc_buffer_len(args) :
			      cmd->argv_lens[2]);

  silc_buffer_free(args);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/********************************** LEAVE ***********************************/

/* LEAVE command. Leaves a channel. Client removes itself from a channel. */

SILC_FSM_STATE(silc_client_command_leave)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcChannelEntry channel;
  SilcBuffer idp;
  char *name;

  if (cmd->argc != 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /LEAVE <channel>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  /* Get the channel entry */
  channel = silc_client_get_channel(conn->client, conn, name);
  if (!channel) {
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
    goto out;
  }

  idp = silc_id_payload_encode(&channel->id, SILC_ID_CHANNEL);

  /* Send LEAVE command to the server */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
			      1, silc_buffer_datalen(idp));

  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  if (conn->current_channel == channel)
    conn->current_channel = NULL;

  silc_client_unref_channel(client, conn, channel);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/********************************** USERS ***********************************/

/* Command USERS. Requests the USERS of the clients joined on requested
   channel. */

SILC_FSM_STATE(silc_client_command_users)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  char *name;

  if (cmd->argc != 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /USERS <channel>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    goto out;
  }

  if (cmd->argv[1][0] == '*') {
    if (!conn->current_channel) {
      COMMAND_ERROR(SILC_STATUS_ERR_NOT_ON_CHANNEL);
      goto out;
    }
    name = conn->current_channel->channel_name;
  } else {
    name = cmd->argv[1];
  }

  /* Send USERS command to the server */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
			      2, name, strlen(name));

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;

 out:
  return SILC_FSM_FINISH;
}

/********************************* GETKEY ***********************************/

/* Command GETKEY. Used to fetch remote client's public key. */

SILC_FSM_STATE(silc_client_command_getkey)
{
  SilcClientCommandContext cmd = fsm_context;
  SilcClientConnection conn = cmd->conn;
  SilcClient client = conn->client;
  SilcClientEntry client_entry;
  SilcServerEntry server_entry;
  SilcDList clients;
  SilcBuffer idp;

  if (cmd->argc < 2) {
    client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_INFO,
		     "Usage: /GETKEY <nickname or server name>");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  /* Find client entry */
  clients = silc_client_get_clients_local(client, conn, cmd->argv[1], FALSE);
  if (!clients) {
    /* Check whether user requested server */
    server_entry = silc_client_get_server(client, conn, cmd->argv[1]);
    if (!server_entry) {
      if (cmd->resolved) {
	/* Resolving didn't find anything.  We should never get here as
	   errors are handled in the resolving callback. */
	COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_NICK);
	COMMAND_ERROR(SILC_STATUS_ERR_NO_SUCH_SERVER);
	return SILC_FSM_FINISH;
      }

      /* No client or server exist with this name, query for both. */
      cmd->resolved = TRUE;
      SILC_FSM_CALL(silc_client_command_send(client, conn,
					     SILC_COMMAND_IDENTIFY,
					     silc_client_command_continue,
					     cmd, 2,
					     1, cmd->argv[1],
					     strlen(cmd->argv[1]),
					     2, cmd->argv[1],
					     strlen(cmd->argv[1])));
      /* NOT REACHED */
    }
    idp = silc_id_payload_encode(&server_entry->id, SILC_ID_SERVER);
    silc_client_unref_server(client, conn, server_entry);
  } else {
    client_entry = silc_dlist_get(clients);
    idp = silc_id_payload_encode(&client_entry->id, SILC_ID_CLIENT);
    silc_client_list_free(client, conn, clients);
  }

  /* Send the commmand */
  silc_client_command_send_va(conn, cmd, cmd->cmd, NULL, NULL, 1,
			      1, silc_buffer_datalen(idp));

  silc_buffer_free(idp);

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/********************************* SERVICE **********************************/

/* Command SERVICE.  Negotiates service agreement with server. */
/* XXX incomplete */

SILC_FSM_STATE(silc_client_command_service)
{
  SilcClientCommandContext cmd = fsm_context;
#if 0
  SilcClientConnection conn = cmd->conn;
  SilcBuffer buffer;
  char *name;

  if (cmd->argc < 2) {
    SAY(conn->client, conn, SILC_CLIENT_MESSAGE_INFO,
	"Usage: /SERVICE [<service name>] [-pubkey]");
    COMMAND_ERROR(SILC_STATUS_ERR_NOT_ENOUGH_PARAMS);
    return SILC_FSM_FINISH;
  }

  name = cmd->argv[1];

  /* Send SERVICE command to the server */
  buffer = silc_command_payload_encode_va(SILC_COMMAND_SERVICE,
					  ++conn->cmd_ident, 1,
					  1, name, strlen(name));
  silc_client_packet_send(conn->client, conn->sock, SILC_PACKET_COMMAND,
			  NULL, 0, NULL, NULL, buffer->data,
			  buffer->len, TRUE);
  silc_buffer_free(buffer);
#endif /* 0 */

  /* Notify application */
  COMMAND(SILC_STATUS_OK);

  /** Wait for command reply */
  silc_fsm_next(fsm, silc_client_command_reply_wait);
  return SILC_FSM_CONTINUE;
}

/* Register all default commands provided by the client library for the
   application. */

void silc_client_commands_register(SilcClient client)
{
  silc_list_init(client->internal->commands, struct SilcClientCommandStruct,
		 next);

  SILC_CLIENT_CMD(whois, WHOIS, "WHOIS", 5);
  SILC_CLIENT_CMD(whowas, WHOWAS, "WHOWAS", 3);
  SILC_CLIENT_CMD(identify, IDENTIFY, "IDENTIFY", 3);
  SILC_CLIENT_CMD(nick, NICK, "NICK", 2);
  SILC_CLIENT_CMD(list, LIST, "LIST", 2);
  SILC_CLIENT_CMD(topic, TOPIC, "TOPIC", 3);
  SILC_CLIENT_CMD(invite, INVITE, "INVITE", 3);
  SILC_CLIENT_CMD(quit, QUIT, "QUIT", 2);
  SILC_CLIENT_CMD(kill, KILL, "KILL", 4);
  SILC_CLIENT_CMD(info, INFO, "INFO", 2);
  SILC_CLIENT_CMD(stats, STATS, "STATS", 0);
  SILC_CLIENT_CMD(ping, PING, "PING", 2);
  SILC_CLIENT_CMD(oper, OPER, "OPER", 3);
  SILC_CLIENT_CMD(join, JOIN, "JOIN", 9);
  SILC_CLIENT_CMD(motd, MOTD, "MOTD", 2);
  SILC_CLIENT_CMD(umode, UMODE, "UMODE", 2);
  SILC_CLIENT_CMD(cmode, CMODE, "CMODE", 6);
  SILC_CLIENT_CMD(cumode, CUMODE, "CUMODE", 9);
  SILC_CLIENT_CMD(kick, KICK, "KICK", 4);
  SILC_CLIENT_CMD(ban, BAN, "BAN", 3);
  SILC_CLIENT_CMD(detach, DETACH, "DETACH", 0);
  SILC_CLIENT_CMD(watch, WATCH, "WATCH", 3);
  SILC_CLIENT_CMD(silcoper, SILCOPER, "SILCOPER", 3);
  SILC_CLIENT_CMD(leave, LEAVE, "LEAVE", 2);
  SILC_CLIENT_CMD(users, USERS, "USERS", 2);
  SILC_CLIENT_CMD(getkey, GETKEY, "GETKEY", 2);
  SILC_CLIENT_CMD(service, SERVICE, "SERVICE", 10);
}

/* Unregister all commands. */

void silc_client_commands_unregister(SilcClient client)
{
  SILC_CLIENT_CMDU(whois, WHOIS, "WHOIS");
  SILC_CLIENT_CMDU(whowas, WHOWAS, "WHOWAS");
  SILC_CLIENT_CMDU(identify, IDENTIFY, "IDENTIFY");
  SILC_CLIENT_CMDU(nick, NICK, "NICK");
  SILC_CLIENT_CMDU(list, LIST, "LIST");
  SILC_CLIENT_CMDU(topic, TOPIC, "TOPIC");
  SILC_CLIENT_CMDU(invite, INVITE, "INVITE");
  SILC_CLIENT_CMDU(quit, QUIT, "QUIT");
  SILC_CLIENT_CMDU(kill, KILL, "KILL");
  SILC_CLIENT_CMDU(info, INFO, "INFO");
  SILC_CLIENT_CMDU(stats, STATS, "STATS");
  SILC_CLIENT_CMDU(ping, PING, "PING");
  SILC_CLIENT_CMDU(oper, OPER, "OPER");
  SILC_CLIENT_CMDU(join, JOIN, "JOIN");
  SILC_CLIENT_CMDU(motd, MOTD, "MOTD");
  SILC_CLIENT_CMDU(umode, UMODE, "UMODE");
  SILC_CLIENT_CMDU(cmode, CMODE, "CMODE");
  SILC_CLIENT_CMDU(cumode, CUMODE, "CUMODE");
  SILC_CLIENT_CMDU(kick, KICK, "KICK");
  SILC_CLIENT_CMDU(ban, BAN, "BAN");
  SILC_CLIENT_CMDU(detach, DETACH, "DETACH");
  SILC_CLIENT_CMDU(watch, WATCH, "WATCH");
  SILC_CLIENT_CMDU(silcoper, SILCOPER, "SILCOPER");
  SILC_CLIENT_CMDU(leave, LEAVE, "LEAVE");
  SILC_CLIENT_CMDU(users, USERS, "USERS");
  SILC_CLIENT_CMDU(getkey, GETKEY, "GETKEY");
  SILC_CLIENT_CMDU(service, SERVICE, "SERVICE");
}

/****************** Client Side Incoming Command Handling *******************/

/* Reply to WHOIS command from server */

static void silc_client_command_process_whois(SilcClient client,
					      SilcClientConnection conn,
					      SilcCommandPayload payload,
					      SilcArgumentPayload args)
{
  SilcDList attrs;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBuffer buffer, packet;

  SILC_LOG_DEBUG(("Received WHOIS command"));

  /* Try to take the Requested Attributes */
  tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
  if (!tmp)
    return;

  attrs = silc_attribute_payload_parse(tmp, tmp_len);
  if (!attrs)
    return;

  /* Process requested attributes */
  buffer = silc_client_attributes_process(client, conn, attrs);
  if (!buffer) {
    silc_attribute_payload_list_free(attrs);
    return;
  }

  /* Send the attributes back in COMMAND_REPLY packet */
  packet =
    silc_command_reply_payload_encode_va(SILC_COMMAND_WHOIS,
					 SILC_STATUS_OK, 0,
					 silc_command_get_ident(payload),
					 1, 11, buffer->data,
					 silc_buffer_len(buffer));
  if (!packet) {
    silc_buffer_free(buffer);
    return;
  }

  SILC_LOG_DEBUG(("Sending back requested WHOIS attributes"));

  silc_packet_send(conn->stream, SILC_PACKET_COMMAND_REPLY, 0,
		   silc_buffer_datalen(packet));

  silc_buffer_free(packet);
  silc_buffer_free(buffer);
}

/* Client is able to receive some command packets even though they are
   special case.  Server may send WHOIS command to the client to retrieve
   Requested Attributes information for WHOIS query the server is
   processing. This function currently handles only the WHOIS command,
   but if in the future more commands may arrive then this can be made
   to support other commands too. */

SILC_FSM_STATE(silc_client_command)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcCommandPayload payload;
  SilcCommand command;
  SilcArgumentPayload args;

  /* Get command payload from packet */
  payload = silc_command_payload_parse(packet->buffer.data,
				       silc_buffer_len(&packet->buffer));
  if (!payload) {
    SILC_LOG_DEBUG(("Bad command packet"));
    return SILC_FSM_FINISH;
  }

  /* Get arguments */
  args = silc_command_get_args(payload);

  /* Get the command */
  command = silc_command_get(payload);
  switch (command) {

  case SILC_COMMAND_WHOIS:
    /* Ignore everything if requested by application */
    if (conn->internal->params.ignore_requested_attributes)
      break;

    silc_client_command_process_whois(client, conn, payload, args);
    break;

  default:
    break;
  }

  silc_command_payload_free(payload);
  return SILC_FSM_FINISH;
}
