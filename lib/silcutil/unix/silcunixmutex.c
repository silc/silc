/*

  silcunixmutex.c

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
/* $Id: */

#include "silcincludes.h"

#ifdef SILC_THREADS

/* SILC Mutex structure */
struct SilcMutexStruct {
  pthread_mutex_t mutex;
};

SilcMutex silc_mutex_alloc(void)
{
  SilcMutex mutex = silc_calloc(1, sizeof(*mutex));
  pthread_mutex_init(&mutex->mutex, NULL);
}

void silc_mutex_free(SilcMutex mutex)
{
  pthread_mutex_destroy(&mutex->mutex);
  silc_free(mutex);
}

void silc_mutex_lock(SilcMutex mutex)
{
  if (pthread_mutex_lock(&mutex->mutex))
    assert(FALSE);
}

void silc_mutex_unlock(SilcMutex mutex)
{
  if (pthread_mutex_unlock(&mutex->mutex))
    assert(FALSE);
}

#endif /* SILC_THREADS */
