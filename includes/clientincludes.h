/*

  clientincludes.h

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

#ifndef CLIENTINCLUDES_H
#define CLIENTINCLUDES_H

#include <curses.h>
#include <sys/param.h>
#include <pwd.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

/* Generic includes */
#include "silcincludes.h"

/* SILC Client includes */
#include "screen.h"
#include "clientconfig.h"
#include "client.h"
#include "command.h"
#include "command_reply.h"
#include "idlist.h"
#include "clientutil.h"
#include "protocol.h"
#include "silc.h"

#endif
