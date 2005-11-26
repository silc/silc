/*

  silcos2thread.c 

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

/* XXX This leaks memory. Perhaps the SilcThread API should be changed
   since the silc_thread_self() causes that BeOS and OS/2 is hard to
   do to support this SilcThread API */

#ifdef SILC_THREADS

/* Thread structure for OS/2 */
typedef struct {
  unsigned long thread;
  SilcThreadStart start_func;
  void *context;
  SilcBool waitable;
} *SilcOs2Thread;

/* Actual routine that is called by OS/2 when the thread is created.
   We will call the start_func from here. When this returns the thread
   is destroyed. */

static void silc_thread_os2_start(void *context)
{
  SilcOs2Thread thread = (SilcOs2Thread)context;
  silc_thread_exit((*thread->start_func)(thread->context));
}

#endif

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable)
{
#ifdef SILC_THREADS
  int ret;
  SilcOs2Thread thread = silc_calloc(1, sizeof(*thread));
  if (!thread)
    return NULL;

  thread->start_func = start_func;
  thread->context = context;
  thread->waitable = waitable;

  /* Create the thread, and run it */
  thread->thread = _beginthread(silc_thread_os2_start, NULL, 65536, thread);
  if (thread->thread < 0) {
    SILC_LOG_ERROR(("Could not create new thread"));
    silc_free(thread);
    return NULL;
  }

  return (SilcThread)thread->thread;
#else
  /* Call thread callback immediately */
  (*start_func)(context);
  return NULL;
#endif
}

void silc_thread_exit(void *exit_value)
{
#ifdef SILC_THREADS
  _endthread();
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  PIB *pib;
  TIB *tib;
  DosGetInfoBlocks(&tib, &pib);
  return (SilcThread)tib->tib_ptib2->tib2_ultid;
#else
  return NULL;
#endif
}

SilcBool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS

  if (DosWaitThread((unsigned long)thread, DCWW_WAIT) !=
      ERROR_INVALID_THREADID) {
    if (exit_value)
      *exit_value = NULL;
    return TRUE;
  }

  return FALSE;
#else
  return FALSE;
#endif
}
