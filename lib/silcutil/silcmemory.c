/*

  silcmemory.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2005 Pekka Riikonen

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

#ifndef SILC_STACKTRACE

#define SILC_MAX_ALLOC (1024 * 1024L * 1024L)

void *silc_malloc(size_t size)
{
  void *addr;
  if (size <= 0 || size >= SILC_MAX_ALLOC) {
    SILC_LOG_ERROR(("Invalid memory allocation"));
    return NULL;
  }
  addr = malloc(size);
  if (!addr)
    SILC_LOG_ERROR(("System out of memory"));
  return addr;
}

void *silc_calloc(size_t items, size_t size)
{
  void *addr;
  if (size * items <= 0 || size * items >= SILC_MAX_ALLOC) {
    SILC_LOG_ERROR(("Invalid memory allocation"));
    return NULL;
  }
  addr = calloc(items, size);
  if (!addr)
    SILC_LOG_ERROR(("System out of memory"));
  return addr;
}

void *silc_realloc(void *ptr, size_t size)
{
  void *addr;
  if (size <= 0 || size >= SILC_MAX_ALLOC) {
    SILC_LOG_ERROR(("Invalid memory allocation"));
    return NULL;
  }
  addr = realloc(ptr, size);
  if (!addr)
    SILC_LOG_ERROR(("System out of memory"));
  return addr;
}

void silc_free(void *ptr)
{
  free(ptr);
}

void *silc_memdup(const void *ptr, size_t size)
{
  unsigned char *addr;
  addr = silc_malloc(size + 1);
  if (!addr) {
    SILC_LOG_ERROR(("System out of memory"));
    return NULL;
  }
  memcpy((void *)addr, ptr, size);
  addr[size] = '\0';
  return (void *)addr;
}

#endif /* !SILC_STACKTRACE */

/* SilcStack aware routines */

void *silc_smalloc(SilcStack stack, SilcUInt32 size)
{
  return stack ? silc_stack_malloc(stack, size, TRUE) : silc_malloc(size);
}

void *silc_smalloc_ua(SilcStack stack, SilcUInt32 size)
{
  return stack ? silc_stack_malloc(stack, size, FALSE) : silc_malloc(size);
}

void *silc_scalloc(SilcStack stack, SilcUInt32 items, SilcUInt32 size)
{
  unsigned char *addr;

  if (!stack)
    return silc_calloc(items, size);

  addr = silc_stack_malloc(stack, items * size, TRUE);
  if (!addr)
    return NULL;
  memset(addr, 0, items * size);
  return (void *)addr;
}

void *silc_srealloc(SilcStack stack, SilcUInt32 old_size,
		    void *ptr, SilcUInt32 size)
{
  return stack ? silc_stack_realloc(stack, old_size, ptr, size, TRUE) :
    silc_realloc(ptr, size);
}

void *silc_srealloc_ua(SilcStack stack, SilcUInt32 old_size,
		       void *ptr, SilcUInt32 size)
{
  return stack ? silc_stack_realloc(stack, old_size, ptr, size, FALSE) :
    silc_realloc(ptr, size);
}

void *silc_smemdup(SilcStack stack, const void *ptr, SilcUInt32 size)
{
  unsigned char *addr;

  if (!stack)
    return silc_memdup(ptr, size);

  addr = silc_stack_malloc(stack, size + 1, TRUE);
  if (!addr)
    return NULL;
  memcpy((void *)addr, ptr, size);
  addr[size] = '\0';
  return (void *)addr;
}

char *silc_sstrdup(SilcStack stack, const char *str)
{
  SilcInt32 size = strlen(str);
  char *addr;

  if (!stack)
    return silc_memdup(str, size);

  addr = silc_stack_malloc(stack, size + 1, FALSE);
  if (!addr)
    return NULL;
  memcpy((void *)addr, str, size);
  addr[size] = '\0';
  return addr;
}
