/*

  silcwin32.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* Native WIN32 specific includes and definitions. */

#ifndef SILCWIN32_H
#define SILCWIN32_H

#include <windows.h>
#include <io.h>
#include <process.h>

#define snprintf _snprintf
#define vsnprintf _vsnprintf

#undef inline
#define inline __inline

#endif
