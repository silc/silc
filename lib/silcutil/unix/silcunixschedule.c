/*

  silcunixschedule.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2001 Pekka Riikonen

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

/* Calls normal select() system call. */

int silc_select(int n, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
  return select(n, readfds, writefds, exceptfds, timeout);
}

#ifdef SILC_THREADS

/* Internal wakeup context. */
typedef struct {
  int wakeup_pipe[2];
  SilcTask wakeup_task;
} *SilcUnixWakeup;

SILC_TASK_CALLBACK(silc_schedule_wakeup_cb)
{
  SilcUnixWakeup wakeup = (SilcUnixWakeup)context;
  unsigned char c;

  read(wakeup->wakeup_pipe[0], &c, 1);
}

#endif /* SILC_THREADS */

/* Initializes the wakeup of the scheduler. In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues. This will initialize the wakeup for the scheduler.
   Any tasks that needs to be registered must be registered to the `queue'.
   It is quaranteed that the scheduler will automatically free any
   registered tasks in this queue. This is system specific routine. */

void *silc_schedule_wakeup_init(void *queue)
{
#ifdef SILC_THREADS
  SilcUnixWakeup wakeup;

  wakeup = silc_calloc(1, sizeof(*wakeup));

  if (pipe(wakeup->wakeup_pipe)) {
    silc_free(wakeup);
    return NULL;
  }

  wakeup->wakeup_task = silc_task_register(queue, wakeup->wakeup_pipe[0],
					   silc_schedule_wakeup_cb, wakeup,
					   0, 0, SILC_TASK_FD, 
					   SILC_TASK_PRI_NORMAL);
  if (!wakeup->wakeup_task) {
    close(wakeup->wakeup_pipe[0]);
    close(wakeup->wakeup_pipe[1]);
    silc_free(wakeup);
    return NULL;
  }

  return (void *)wakeup;
#endif
  return NULL;
}

/* Uninitializes the system specific wakeup. */

void silc_schedule_wakeup_uninit(void *context)
{
#ifdef SILC_THREADS
  SilcUnixWakeup wakeup = (SilcUnixWakeup)context;

  if (!wakeup)
    return;

  close(wakeup->wakeup_pipe[0]);
  close(wakeup->wakeup_pipe[1]);
  silc_free(wakeup);
#endif
}

/* Wakes up the scheduler */

void silc_schedule_wakeup_internal(void *context)
{
#ifdef SILC_THREADS
  SilcUnixWakeup wakeup = (SilcUnixWakeup)context;

  if (!wakeup)
    return;

  write(wakeup->wakeup_pipe[1], "!", 1);
#endif
}
