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
 * Revision 1.2  2000/07/05 06:05:56  priikone
 * 	Assert if system is out of memory.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

void *silc_malloc(size_t size)
{
  void *addr;
#ifdef HAVE_MLOCK
  addr = malloc(size);
  assert(addr != NULL);
  mlock(addr, size);
  return addr;
#else
  addr = malloc(size);
  assert(addr != NULL);
  return addr;
#endif
}

void *silc_calloc(size_t items, size_t size)
{
  void *addr;
#ifdef HAVE_MLOCK
  addr = calloc(items, size);
  assert(addr != NULL);
  mlock(addr, size);
  return addr;
#else
  addr = calloc(items, size);
  assert(addr != NULL);
  return addr;
#endif
}

void *silc_realloc(void *ptr, size_t size)
{
  void *addr;
#ifdef HAVE_MLOCK
  addr = realloc(ptr, size);
  assert(addr != NULL);
  mlock(addr, size);
  return addr;
#else
  addr = realloc(ptr, size);
  assert(addr != NULL);
  return addr;
#endif
}

void silc_free(void *ptr)
{
  free(ptr);
}







