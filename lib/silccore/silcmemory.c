/*

  silcmemory.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1999 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.1  2000/06/27 11:36:55  priikone
 * Initial revision
 *
 *
 */

#include "silcincludes.h"

void *silc_malloc(size_t size)
{
#ifdef HAVE_MLOCK
  void *addr = malloc(size);
  mlock(addr, size);
  return addr;
#else
  return malloc(size);
#endif
}

void *silc_calloc(size_t items, size_t size)
{
#ifdef HAVE_MLOCK
  void *addr = calloc(items, size);
  mlock(addr, size);
  return addr;
#else
  return calloc(items, size);
#endif
}

void *silc_realloc(void *ptr, size_t size)
{
#ifdef HAVE_MLOCK
  void *addr = realloc(ptr, size);
  mlock(addr, size);
  return addr;
#else
  return realloc(ptr, size);
#endif
}

void silc_free(void *ptr)
{
  free(ptr);
}







