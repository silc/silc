/*

  silcos2util.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

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

char *silc_string_regexify(const char *string)
{
  return strdup(string);
}

char *silc_string_regex_combine(const char *string1, const char *string2)
{
  return strdup(string1);
}

int silc_string_regex_match(const char *regex, const char *string)
{
  return TRUE;
}

int silc_string_match(const char *string1, const char *string2)
{
  return TRUE;
}

#define FILETIME_1970 0x019db1ded53e8000
const BYTE DWLEN = sizeof(DWORD) * 8;

/* Return current time in struct timeval. Code ripped from some xntp
   implementation on http://src.openresources.com. */

int silc_gettimeofday(struct timeval *tv)
{
  FILETIME ft;
  __SilcInt64 msec;
  
  GetSystemTimeAsFileTime(&ft);
  msec = (__SilcInt64) ft.dwHighDateTime << DWLEN | ft.dwLowDateTime;
  msec = (msec - FILETIME_1970) / 10;
  tv->tv_sec  = (long) (msec / 1000000);
  tv->tv_usec = (long) (msec % 1000000);

  return 0;
}
