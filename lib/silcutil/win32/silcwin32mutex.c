/*

  silcwin32mutex.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2005 Pekka Riikonen

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

/* SILC Mutex structure */
struct SilcMutexStruct {
#ifdef SILC_THREADS
  CRITICAL_SECTION mutex;
  BOOL locked;
#else
  void *tmp;
#endif /* SILC_THREADS */
};

SilcBool silc_mutex_alloc(SilcMutex *mutex)
{
#ifdef SILC_THREADS
  *mutex = silc_calloc(1, sizeof(**mutex));
  if (!(*mutex))
    return FALSE;
  InitializeCriticalSection(&((*mutex)->mutex));
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS */
}

void silc_mutex_free(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    DeleteCriticalSection(&mutex->mutex);
    silc_free(mutex);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_lock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    EnterCriticalSection(&mutex->mutex);
    assert(mutex->locked == FALSE);
    mutex->locked = TRUE;
  }
#endif /* SILC_THREADS */
}

void silc_mutex_unlock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    assert(mutex->locked == TRUE);
    mutex->locked = FALSE;
    LeaveCriticalSection(&mutex->mutex);
  }
#endif /* SILC_THREADS */
}
