/*

  silcunixthread.c

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

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      bool waitable)
{
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

  SILC_LOG_DEBUG(("Created thread %p", (SilcThread)ret));

  return (SilcThread)ret;
}

void silc_thread_exit(void *exit_value)
{
  pthread_exit(exit_value);
}

SilcThread silc_thread_self(void)
{
  pthread_t self = pthread_self();
  return (SilcThread)self;
}

bool silc_thread_wait(SilcThread thread, void **exit_value)
{
  SILC_LOG_DEBUG(("Waiting for thread %p", thread));
  if (!pthread_join(*(pthread_t *)thread, exit_value))
    return TRUE;
  return FALSE;
}

#endif /* SILC_THREADS */
