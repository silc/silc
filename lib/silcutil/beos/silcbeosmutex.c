/*

  silcbeosmutex.c 

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

#include "silcincludes.h"

#ifdef SILC_THREADS

/* SILC Mutex structure */
struct SilcMutexStruct {
  int sema_count;
  sem_id sema;
};

bool silc_mutex_alloc(SilcMutex *mutex)
{
  int ret;

  *mutex = silc_calloc(1, sizeof(**mutex));
  if (*mutex == NULL)
    return FALSE;

  ret = create_sem(0, "SILC_MUTEX");
  if (ret < B_NO_ERROR) {
    silc_free(*mutex);
    return FALSE;
  }

  (*mutex)->sema_count = 0;
  (*mutex)->sema = ret;

  return TRUE;
}

void silc_mutex_free(SilcMutex mutex)
{
  delete_sem(mutex->sema);
  silc_free(mutex);
}

void silc_mutex_lock(SilcMutex mutex)
{
  if (atomic_add(&mutex->sema_count, 1) > 0) {
    if (acquire_sem(mutex->sema) < B_NO_ERROR)
      assert(FALSE);
  }
}

void silc_mutex_unlock(SilcMutex mutex)
{
  if (atomic_add(&mutes->sema_count, -1) > 1) {
    if (release_sem(mutex->sema) < B_NO_ERROR)
      assert(FALSE);
  }
}

#endif /* SILC_THREADS */
