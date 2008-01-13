/*

  silcmemory.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2008 Pekka Riikonen

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

  if (silc_unlikely(size <= 0 || size >= SILC_MAX_ALLOC)) {
    if (size == 0)
      silc_set_errno_nofail(SILC_ERR_ZERO_ALLOCATION);
    else
      silc_set_errno_reason_nofail(SILC_ERR_TOO_LARGE_ALLOCATION,
				   "Allocation by %d", size);
    return NULL;
  }

  addr = malloc(size);
  if (silc_unlikely(!addr))
    silc_set_errno_nofail(SILC_ERR_OUT_OF_MEMORY);

  return addr;
}

void *silc_calloc(size_t items, size_t size)
{
  void *addr;

  if (silc_unlikely(size * items <= 0 || size * items >= SILC_MAX_ALLOC)) {
    if (size == 0)
      silc_set_errno_nofail(SILC_ERR_ZERO_ALLOCATION);
    else
      silc_set_errno_reason_nofail(SILC_ERR_TOO_LARGE_ALLOCATION,
				   "Allocation by %d", size);
    return NULL;
  }

  addr = calloc(items, size);
  if (silc_unlikely(!addr))
    silc_set_errno_nofail(SILC_ERR_OUT_OF_MEMORY);

  return addr;
}

void *silc_realloc(void *ptr, size_t size)
{
  void *addr;
  if (silc_unlikely(size <= 0 || size >= SILC_MAX_ALLOC)) {
    if (size == 0)
      silc_set_errno_nofail(SILC_ERR_ZERO_ALLOCATION);
    else
      silc_set_errno_reason_nofail(SILC_ERR_TOO_LARGE_ALLOCATION,
				   "Allocation by %d", size);
    return NULL;
  }

  addr = realloc(ptr, size);
  if (silc_unlikely(!addr))
    silc_set_errno_nofail(SILC_ERR_OUT_OF_MEMORY);

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
  if (silc_unlikely(!addr)) {
    silc_set_errno_nofail(SILC_ERR_OUT_OF_MEMORY);
    return NULL;
  }
  memcpy((void *)addr, ptr, size);
  addr[size] = '\0';
  return (void *)addr;
}

char *silc_strdup(const char *str)
{
  return silc_memdup(str, strlen(str));
}

#endif /* !SILC_STACKTRACE */

/* SilcStack aware routines */

void *silc_smalloc(SilcStack stack, SilcUInt32 size)
{
  return stack ? silc_stack_malloc(stack, size) : silc_malloc(size);
}

void silc_sfree(SilcStack stack, void *ptr)
{
  if (stack) {
#ifdef SILC_DEBUG
    if (ptr)
      *(unsigned char *)ptr = 'F';
#endif /* SILC_DEBUG */
    return;
  }
  silc_free(ptr);
}

void *silc_scalloc(SilcStack stack, SilcUInt32 items, SilcUInt32 size)
{
  unsigned char *addr;

  if (!stack)
    return silc_calloc(items, size);

  addr = silc_stack_malloc(stack, items * size);
  if (silc_unlikely(!addr))
    return NULL;
  memset(addr, 0, items * size);
  return (void *)addr;
}

void *silc_srealloc(SilcStack stack, SilcUInt32 old_size,
		    void *ptr, SilcUInt32 size)
{
  void *new_ptr;

  if (!stack)
    return silc_realloc(ptr, size);

  new_ptr = silc_stack_realloc(stack, old_size, ptr, size);
  if (!new_ptr) {
    new_ptr = silc_smalloc(stack, size);
    if (!new_ptr)
      return NULL;
    memcpy(new_ptr, ptr, old_size > size ? size : old_size);
  }

  return new_ptr;
}

void *silc_smemdup(SilcStack stack, const void *ptr, SilcUInt32 size)
{
  unsigned char *addr;

  if (!stack)
    return silc_memdup(ptr, size);

  addr = silc_stack_malloc(stack, size + 1);
  if (silc_unlikely(!addr))
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

  addr = silc_stack_malloc(stack, size + 1);
  if (silc_unlikely(!addr))
    return NULL;
  memcpy((void *)addr, str, size);
  addr[size] = '\0';
  return addr;
}
