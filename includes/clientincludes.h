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

#include "silcdefs.h"

#include <curses.h>
#include <sys/param.h>
#include <pwd.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

/* Generic includes */
#include "silcincludes.h"
#include "clientlibincludes.h"

/* SILC Client includes */
#include "screen.h"
#include "clientconfig.h"
#include "local_command.h"
#include "clientutil.h"
#include "silc.h"
#include "client_ops.h"

#endif
