/*

  silcwin32util.c

  Author: Pekka Riikonen <priikone@sillcnet.org>

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
/* $Id$ */

#include "silcincludes.h"

#define FILETIME_1970 0x019db1ded53e8000
const BYTE DWLEN = sizeof(DWORD) * 8;

/* Return current time in struct timeval. Code ripped from some xntp
   implementation on http://src.openresources.com. */

int silc_gettimeofday(struct timeval *tv)
{
  FILETIME ft;
  __int64 msec;
  
  GetSystemTimeAsFileTime(&ft);
  msec = (__int64) ft.dwHighDateTime << DWLEN | ft.dwLowDateTime;
  msec = (msec - FILETIME_1970) / 10;
  tv->tv_sec  = (long) (msec / 1000000);
  tv->tv_usec = (long) (msec % 1000000);

  return 0;
}
