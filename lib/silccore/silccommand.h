/*

  silccommand.h

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

#ifndef SILCCOMMAND_H
#define SILCCOMMAND_H

/* Command function callback. The actual command function pointer. */
typedef void (*SilcCommandCb)(void *context);

/* Typedefinition for SILC commands. */
typedef unsigned char SilcCommand;

/* Forward declaration for Command Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcCommandPayloadStruct *SilcCommandPayload;

/* Command flags. These set how the commands behave on different
   situations. These can be OR'ed together to set multiple flags. */
typedef enum {
  SILC_CF_NONE = 0,

  /* Command may only be used once per (about) 2 seconds */
  SILC_CF_LAG = (1L << 1),

  /* Command is available for registered connections (connections
     whose ID has been created. */
  SILC_CF_REG = (1L << 2),

  /* Command is available only for server operators */
  SILC_CF_OPER = (1L << 3),

  /* Command is available only for SILC (router) operators. If this 
     is set SILC_CF_OPER is not necessary to be set. */
  SILC_CF_SILC_OPER = (1L << 4),

} SilcCommandFlag;

/* All SILC commands. These are commands that have client and server
   counterparts. These are pretty much the same as in IRC. */
#define SILC_COMMAND_NONE               0
#define SILC_COMMAND_WHOIS		2
#define SILC_COMMAND_WHOWAS		3
#define SILC_COMMAND_IDENTIFY           4
#define SILC_COMMAND_NICK		5
#define SILC_COMMAND_LIST		6
#define SILC_COMMAND_TOPIC		7
#define SILC_COMMAND_INVITE		8
#define SILC_COMMAND_QUIT		9
#define SILC_COMMAND_KILL		10
#define SILC_COMMAND_INFO		11
#define SILC_COMMAND_CONNECT	        12
#define SILC_COMMAND_PING		13
#define SILC_COMMAND_OPER		14
#define SILC_COMMAND_JOIN		15
#define SILC_COMMAND_MOTD		16
#define SILC_COMMAND_UMODE		17
#define SILC_COMMAND_CMODE		18
#define SILC_COMMAND_KICK		19
#define	SILC_COMMAND_RESTART	        20
#define	SILC_COMMAND_CLOSE		21
#define	SILC_COMMAND_DIE		22
#define SILC_COMMAND_SILCOPER	        23
#define SILC_COMMAND_LEAVE		24
#define SILC_COMMAND_NAMES		25

/* Local commands. Local commands are unofficial commands and
   are implementation specific commands. These are used only by the
   SILC client to extend user commands. */
#define SILC_COMMAND_HELP		100
#define SILC_COMMAND_CLEAR		101
#define SILC_COMMAND_VERSION		102
#define SILC_COMMAND_SERVER             103
#define SILC_COMMAND_MSG 	        104
#define SILC_COMMAND_AWAY		105

/* Reserved */
#define SILC_COMMAND_RESERVED           255

/* Command Status type */
typedef unsigned short SilcCommandStatus;

/* Command Status messages */
#define SILC_STATUS_OK                      0
#define SILC_STATUS_LIST_START              1
#define SILC_STATUS_LIST_END                2
#define SILC_STATUS_ERR_NO_SUCH_NICK        10
#define SILC_STATUS_ERR_NO_SUCH_CHANNEL     11
#define SILC_STATUS_ERR_NO_SUCH_SERVER      12
#define SILC_STATUS_ERR_TOO_MANY_TARGETS    13
#define SILC_STATUS_ERR_NO_RECIPIENT        14
#define SILC_STATUS_ERR_UNKNOWN_COMMAND     15
#define SILC_STATUS_ERR_WILDCARDS           16
#define SILC_STATUS_ERR_NO_CLIENT_ID        17
#define SILC_STATUS_ERR_NO_CHANNEL_ID       18
#define SILC_STATUS_ERR_BAD_CLIENT_ID       19
#define SILC_STATUS_ERR_BAD_CHANNEL_ID      20
#define SILC_STATUS_ERR_NO_SUCH_CLIENT_ID   21
#define SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID  22
#define SILC_STATUS_ERR_NICKNAME_IN_USE     23
#define SILC_STATUS_ERR_NOT_ON_CHANNEL      24
#define SILC_STATUS_ERR_USER_ON_CHANNEL     25
#define SILC_STATUS_ERR_NOT_REGISTERED      26
#define SILC_STATUS_ERR_NOT_ENOUGH_PARAMS   27
#define SILC_STATUS_ERR_TOO_MANY_PARAMS     28
#define SILC_STATUS_ERR_PERM_DENIED         29
#define SILC_STATUS_ERR_BANNED_FROM_SERVER  30
#define SILC_STATUS_ERR_BAD_PASSWORD        31
#define SILC_STATUS_ERR_CHANNEL_IS_FULL     32
#define SILC_STATUS_ERR_NOT_INVITED         33
#define SILC_STATUS_ERR_BANNED_FROM_CHANNEL 34
#define SILC_STATUS_ERR_UNKNOWN_MODE        35
#define SILC_STATUS_ERR_NOT_YOU             36
#define SILC_STATUS_ERR_NO_CHANNEL_PRIV     37
#define SILC_STATUS_ERR_NO_SERVER_PRIV      38
#define SILC_STATUS_ERR_NO_ROUTER_PRIV      39
#define SILC_STATUS_ERR_BAD_NICKNAME        40
#define SILC_STATUS_ERR_BAD_CHANNEL         41
#define SILC_STATUS_ERR_AUTH_FAILED         42

/* Prototypes */
SilcCommandPayload silc_command_parse_payload(SilcBuffer buffer);
SilcBuffer silc_command_encode_payload(SilcCommand cmd,
				       unsigned int argc,
				       unsigned char **argv,
				       unsigned int *argv_lens,
				       unsigned int *argv_types);
SilcBuffer silc_command_encode_payload_va(SilcCommand cmd, 
					  unsigned int argc, ...);
void silc_command_free_payload(SilcCommandPayload payload);
SilcCommand silc_command_get(SilcCommandPayload payload);
unsigned int silc_command_get_arg_num(SilcCommandPayload payload);
unsigned char *silc_command_get_first_arg(SilcCommandPayload payload,
					  unsigned int *ret_len);
unsigned char *silc_command_get_next_arg(SilcCommandPayload payload,
					 unsigned int *ret_len);
unsigned char *silc_command_get_arg_type(SilcCommandPayload payload,
					 unsigned int type,
					 unsigned int *ret_len);
SilcBuffer silc_command_encode_status_payload(SilcCommandStatus status,
					      unsigned char *data,
					      unsigned int len);

#endif
