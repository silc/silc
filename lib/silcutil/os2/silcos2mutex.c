/*

  silcos2mutex.c 

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
/* I used Apache's APR code as a reference here. */
/* $Id$ */

#include "silc.h"

#ifdef SILC_THREADS

/* SILC Mutex structure */
struct SilcMutexStruct {
  HMTX mutex;
};

SilcBool silc_mutex_alloc(SilcMutex *mutex)
{
  char name[64];

  *mutex = silc_calloc(1, sizeof(**mutex));
  if (*mutex == NULL)
    return FALSE;

  /* Create the lock. Is the name working? :) */
  memset(name, 0, sizeof(name));
  snprintf(name, sizeof(name) - 1, "%p/SEM32/SILC1234$", *mutex);
  if (!DosCreateMutexSem(name, &(*mutex)->mutex, DC_SEM_SHARED, FALSE)) {
    silc_free(*mutex);
    return FALSE;
  }

  return TRUE;
}

void silc_mutex_free(SilcMutex mutex)
{
  DosCloseMutexSem(mutex->mutex);
  silc_free(mutex);
}

void silc_mutex_lock(SilcMutex mutex)
{
  if (!DosRequestMutexSem(mutex->mutex, SEM_INDEFINITE_WAIT))
    assert(FALSE);
}

void silc_mutex_unlock(SilcMutex mutex)
{
  if (!DosReleaseMutexSem(mutex->mutex)
    assert(FALSE);
}

#endif /* SILC_THREADS */
