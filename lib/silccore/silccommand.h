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
  SILC_CF_NONE           = 0,

  /* Command may only be used once per (about) 2 seconds */
  SILC_CF_LAG            = (1L << 1),

  /* Command is available for registered connections (connections
     whose ID has been created. */
  SILC_CF_REG            = (1L << 2),

  /* Command is available only for server operators */
  SILC_CF_OPER           = (1L << 3),

  /* Command is available only for SILC (router) operators. If this 
     is set SILC_CF_OPER is not necessary to be set. */
  SILC_CF_SILC_OPER      = (1L << 4),

} SilcCommandFlag;

/* All SILC commands. These are commands that have client and server
   counterparts. These are pretty much the same as in IRC. */
#define SILC_COMMAND_NONE               0
#define SILC_COMMAND_WHOIS		1
#define SILC_COMMAND_WHOWAS		2
#define SILC_COMMAND_IDENTIFY           3
#define SILC_COMMAND_NICK		4
#define SILC_COMMAND_LIST		5
#define SILC_COMMAND_TOPIC		6
#define SILC_COMMAND_INVITE		7
#define SILC_COMMAND_QUIT		8
#define SILC_COMMAND_KILL		9
#define SILC_COMMAND_INFO		10
#define SILC_COMMAND_CONNECT	        11
#define SILC_COMMAND_PING		12
#define SILC_COMMAND_OPER		13
#define SILC_COMMAND_JOIN		14
#define SILC_COMMAND_MOTD		15
#define SILC_COMMAND_UMODE		16
#define SILC_COMMAND_CMODE		17
#define SILC_COMMAND_CUMODE		18
#define SILC_COMMAND_KICK		19
#define	SILC_COMMAND_RESTART	        20
#define	SILC_COMMAND_CLOSE		21
#define	SILC_COMMAND_DIE		22
#define SILC_COMMAND_SILCOPER	        23
#define SILC_COMMAND_LEAVE		24
#define SILC_COMMAND_NAMES		25

/* Reserved */
#define SILC_COMMAND_RESERVED           255

/* Command Status type */
typedef unsigned short SilcCommandStatus;

/* Command Status messages */
#define SILC_STATUS_OK                      0
#define SILC_STATUS_LIST_START              1
#define SILC_STATUS_LIST_ITEM               2
#define SILC_STATUS_LIST_END                3
#define SILC_STATUS_ERR_NO_SUCH_NICK        10
#define SILC_STATUS_ERR_NO_SUCH_CHANNEL     11
#define SILC_STATUS_ERR_NO_SUCH_SERVER      12
#define SILC_STATUS_ERR_TOO_MANY_TARGETS    13
#define SILC_STATUS_ERR_NO_RECIPIENT        14
#define SILC_STATUS_ERR_UNKNOWN_COMMAND     15
#define SILC_STATUS_ERR_WILDCARDS           16
#define SILC_STATUS_ERR_NO_CLIENT_ID        17
#define SILC_STATUS_ERR_NO_CHANNEL_ID       18
#define SILC_STATUS_ERR_NO_SERVER_ID        19
#define SILC_STATUS_ERR_BAD_CLIENT_ID       20
#define SILC_STATUS_ERR_BAD_CHANNEL_ID      21
#define SILC_STATUS_ERR_NO_SUCH_CLIENT_ID   22
#define SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID  23
#define SILC_STATUS_ERR_NICKNAME_IN_USE     24
#define SILC_STATUS_ERR_NOT_ON_CHANNEL      25
#define SILC_STATUS_ERR_USER_NOT_ON_CHANNEL 26
#define SILC_STATUS_ERR_USER_ON_CHANNEL     27
#define SILC_STATUS_ERR_NOT_REGISTERED      28
#define SILC_STATUS_ERR_NOT_ENOUGH_PARAMS   29
#define SILC_STATUS_ERR_TOO_MANY_PARAMS     30
#define SILC_STATUS_ERR_PERM_DENIED         31
#define SILC_STATUS_ERR_BANNED_FROM_SERVER  32
#define SILC_STATUS_ERR_BAD_PASSWORD        33
#define SILC_STATUS_ERR_CHANNEL_IS_FULL     34
#define SILC_STATUS_ERR_NOT_INVITED         35
#define SILC_STATUS_ERR_BANNED_FROM_CHANNEL 36
#define SILC_STATUS_ERR_UNKNOWN_MODE        37
#define SILC_STATUS_ERR_NOT_YOU             38
#define SILC_STATUS_ERR_NO_CHANNEL_PRIV     39
#define SILC_STATUS_ERR_NO_SERVER_PRIV      40
#define SILC_STATUS_ERR_NO_ROUTER_PRIV      41
#define SILC_STATUS_ERR_BAD_NICKNAME        42
#define SILC_STATUS_ERR_BAD_CHANNEL         43
#define SILC_STATUS_ERR_AUTH_FAILED         44

/* Prototypes */
SilcCommandPayload silc_command_payload_parse(SilcBuffer buffer);
SilcBuffer silc_command_payload_encode(SilcCommand cmd,
				       unsigned int argc,
				       unsigned char **argv,
				       unsigned int *argv_lens,
				       unsigned int *argv_types,
				       unsigned short ident);
SilcBuffer silc_command_payload_encode_va(SilcCommand cmd, 
					  unsigned short ident, 
					  unsigned int argc, ...);
SilcBuffer silc_command_payload_encode_vap(SilcCommand cmd, 
					   unsigned short ident, 
					   unsigned int argc, va_list ap);
SilcBuffer 
silc_command_reply_payload_encode_va(SilcCommand cmd, 
				     SilcCommandStatus status,
				     unsigned short ident,
				     unsigned int argc, ...);
void silc_command_free_payload(SilcCommandPayload payload);
SilcCommand silc_command_get(SilcCommandPayload payload);
SilcArgumentPayload silc_command_get_args(SilcCommandPayload payload);
unsigned short silc_command_get_ident(SilcCommandPayload payload);

#endif
