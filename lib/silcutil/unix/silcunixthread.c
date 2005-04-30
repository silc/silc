/*

  silcunixthread.c

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

#include "silcincludes.h"

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      bool waitable)
{
#ifdef SILC_THREADS
  pthread_attr_t attr;
  pthread_t thread;
  int ret;

  SILC_LOG_DEBUG(("Creating new thread"));

  if (!start_func)
    return NULL;

  if (pthread_attr_init(&attr)) {
    SILC_LOG_ERROR(("Thread error: %s", strerror(errno)));
    return NULL;
  }

  if (pthread_attr_setdetachstate(&attr,
				  waitable ? PTHREAD_CREATE_JOINABLE : 
				  PTHREAD_CREATE_DETACHED)) {
    SILC_LOG_ERROR(("Thread error: %s", strerror(errno)));
    pthread_attr_destroy(&attr);
    return NULL;
  }

  ret = pthread_create(&thread, &attr, (void * (*)(void *))start_func, 
		       context);
  if (ret) {
    SILC_LOG_ERROR(("Thread error: %s", strerror(errno)));
    pthread_attr_destroy(&attr);
    return NULL;
  }

  pthread_attr_destroy(&attr);

  SILC_LOG_DEBUG(("Created thread %p", (SilcThread)thread));

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
  pthread_exit(exit_value);
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  pthread_t self = pthread_self();
  return (SilcThread)self;
#else
  return NULL;
#endif
}

bool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  SILC_LOG_DEBUG(("Waiting for thread %p", thread));
  if (!pthread_join(*(pthread_t *)thread, exit_value))
    return TRUE;
  return FALSE;
#else
  return FALSE;
#endif
}
