/*

  silcwin32.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

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
#include <fcntl.h>
#include <assert.h>

#if defined(HAVE_SILCDEFS_H)
#include "regexpr.h"
#endif /* HAVE_SILCDEFS_H */

#define snprintf silc_snprintf
#define vsnprintf silc_vsnprintf

#ifdef WIN32
#define strcasecmp stricmp
#define strncasecmp strncmp
#endif

#ifdef WIN32
#ifndef DLL
#ifndef _LIB
#define DLLAPI __declspec(dllimport)
#else
#define DLLAPI	/* Nada, we use .DEF */
#endif
#else
#define DLLAPI	/* Nada, we use .DEF */
#endif
#endif

/* Some winsock compatiblity requirements */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x400
#else
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x400
#endif /* _WIN32_WINNT */
#if !defined(SO_SYNCHRONOUS_NONALERT)
#define SO_SYNCHRONOUS_NONALERT 0x20
#endif
#if !defined(SO_OPENTYPE)
#define SO_OPENTYPE 0x7008
#endif

#undef inline
#define inline __inline

#undef sleep
#define sleep(x) Sleep((x) * 1000)

#if _MSC_VER < 1300
#define SetWindowLongPtr SetWindowLong
#define GetWindowLongPtr GetWindowLong
#endif /* _MSC_VER < 1300 */

#endif
