/*

  silcepocthread.cpp

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
/* $Id$ */

#include "silcincludes.h"

#ifdef SILC_THREADS

/* Thread structure for EPOC */
typedef struct {
  RThread *thread;
  SilcThreadStart start_func;
  void *context;
  bool waitable;
} *SilcEpocThread;

/* The actual thread function */

TInt silc_thread_epoc_start(TAny *context)
{
  SilcEpocThread thread = (SilcEpocThread)context;

  thread->start_func(thread->context);
  silc_thread_exit(NULL);

  return 0;
}

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      bool waitable)
{
#ifdef SILC_THREADS
  SilcEpocThread thread;
  TInt ret;

  SILC_LOG_DEBUG(("Creating new thread"));

  thread = silc_calloc(1, sizeof(*thread));
  thread->start_func = start_func;
  thread->context = context;
  thread->waitable = waitable;

  /* Create the thread */
  /* XXX Unique name should be given for the thread */
  thread->thread = new RThread();
  ret = thread->thread->Create(NULL, silc_thread_epoc_start, 0, 0, 0,
			       (TAny *)thread, EOwnerProcess);
  if (ret != KErrNone) {
    SILC_LOG_ERROR(("Could not create new thread"));
    delete thread->thread;
    silc_free(thread);
    return NULL;
  }

  return (SilcThread)thread;
#else
  /* Call thread callback immediately */
  (*start_func)(context);
  return NULL;
#endif
}

void silc_thread_exit(void *exit_value)
{
#ifdef SILC_THREADS
  /* XXX */
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  /* XXX */
  return NULL;
#else
  return NULL;
#endif
}

bool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  /* XXX */
  return TRUE;
#else
  return FALSE;
#endif
}
