/*

  silcwin32mutex.c

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
/* $Id$ */

#include "silcincludes.h"

#ifdef SILC_THREADS

/* SILC Mutex structure */
struct SilcMutexStruct {
  HANDLE mutex;
};

bool silc_mutex_alloc(SilcMutex *mutex)
{
  *mutex = silc_calloc(1, sizeof(**mutex));
  (*mutex)->mutex = CreateMutex(NULL, FALSE, NULL);
  if (!(*mutex)->mutex) {
    silc_free(*mutex);
    return FALSE;
  }
  return TRUE;
}

void silc_mutex_free(SilcMutex mutex)
{
  CloseHandle(mutex->mutex);
  silc_free(mutex);
}

void silc_mutex_lock(SilcMutex mutex)
{
  WaitForSingleObject(mutex->mutex, INFINITE);
}

void silc_mutex_unlock(SilcMutex mutex)
{
  ReleaseMutex(mutex->mutex);
}

#endif /* SILC_THREADS */
