/*

  local_command.h

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

#ifndef LOCAL_COMMAND_H
#define LOCAL_COMMAND_H

/* All local commands */
extern SilcClientCommand silc_local_command_list[];

/* Local commands */
#define SILC_LOCAL_COMMAND_HELP		1
#define SILC_LOCAL_COMMAND_CLEAR	2
#define SILC_LOCAL_COMMAND_VERSION	3
#define SILC_LOCAL_COMMAND_SERVER       4
#define SILC_LOCAL_COMMAND_MSG 	        5
#define SILC_LOCAL_COMMAND_AWAY		6
#define SILC_LOCAL_COMMAND_KEY      	7

/* Macros */

/* Macro used for command declaration in command list structure */
#define SILC_CLIENT_LCMD(func, cmd, name, flags, args) \
{ silc_client_local_command_##func, SILC_LOCAL_COMMAND_##cmd, \
  name, flags, args }

/* Macro used to declare command functions */
#define SILC_CLIENT_LCMD_FUNC(func) \
void silc_client_local_command_##func(void *context)

/* Prototypes */
SilcClientCommand *silc_client_local_command_find(const char *name);
SILC_CLIENT_LCMD_FUNC(help);
SILC_CLIENT_LCMD_FUNC(clear);
SILC_CLIENT_LCMD_FUNC(version);
SILC_CLIENT_LCMD_FUNC(msg);
SILC_CLIENT_LCMD_FUNC(server);
SILC_CLIENT_LCMD_FUNC(away);
SILC_CLIENT_LCMD_FUNC(key);

#endif
