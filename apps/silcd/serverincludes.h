/*

  serverincludes.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVERINCLUDES_H
#define SERVERINCLUDES_H

/* Generic includes */
#include "silc.h"

/* Forward declaration for SILC Server object. The actual object is
   defined in internal header file for server routines. I want to keep
   the object private hence this declaration. */
typedef struct SilcServerStruct *SilcServer;

/* SILC Server includes */
#include "serverconfig.h"
#include "server.h"
#include "idlist.h"
#include "serverid.h"
#include "server_util.h"
#include "packet_send.h"
#include "packet_receive.h"
#include "route.h"
#include "command.h"
#include "command_reply.h"
#include "server_query.h"
#include "silcd.h"
#include "server_backup.h"

#endif
