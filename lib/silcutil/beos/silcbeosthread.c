/*

  silcbeosthread.c 

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

/* XXX This leaks memory. Perhaps the SilcThread API should be changed
   since the silc_thread_self() causes that BeOS and OS/2 is hard to
   do to support this SilcThread API */

#include "silcincludes.h"

#ifdef SILC_THREADS

/* Thread structure for BeOS */
typedef struct {
  thread_id thread;
  SilcThreadStart start_func;
  void *context;
  SilcBool waitable;
} *SilcBeosThread;

/* Actual routine that is called by BeOS when the thread is created.
   We will call the start_func from here. */

static void *silc_thread_beos_start(void *context)
{
  SilcBeosThread thread = (SilcBeosThread)context;
  return (*thread->start_func)(thread->context);
}

#endif

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable)
{
#ifdef SILC_THREADS
  int ret;
  SilcBeosThread thread = silc_calloc(1, sizeof(*thread));
  if (!thread)
    return NULL;

  thread->start_func = start_func;
  thread->context = context;
  thread->waitable = waitable;

  /* Create the thread, and run it */
  thread->thread = spawn_thread((thread_func)silc_thread_beos_start,
				B_NORMAL_PRIORITY, thread);
  ret = resume_thread(thread->thread);
  if (ret < B_NO_ERROR) {
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
  exit_thread((status_t)exit_value);
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  return (SilcThread)find_thread(NULL);
#else
  return NULL;
#endif
}

SilcBool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  status_t ret, retval;

  ret = wait_for_thread((thread_id)thread, &retval);
  if (ret == B_NO_ERROR) {
    if (exit_value)
      *exit_value = retval;
    return TRUE;
  }

  return FALSE;
#else
  return FALSE;
#endif
}
