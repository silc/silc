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
#include "silcschedule_i.h"

/* Calls normal select() system call. */

int silc_select(SilcScheduleFd fds, SilcUInt32 fds_count, 
		struct timeval *timeout)
{
  fd_set in, out;
  int ret, i, max_fd = 0;

  FD_ZERO(&in);
  FD_ZERO(&out);

  for (i = 0; i < fds_count; i++) {
    if (!fds[i].events)
      continue;

    if (fds[i].fd > max_fd)
      max_fd = fds[i].fd;

    if (fds[i].events & SILC_TASK_READ)
      FD_SET(fds[i].fd, &in);
    if (fds[i].events & SILC_TASK_WRITE)
      FD_SET(fds[i].fd, &out);

    fds[i].revents = 0;
  }

  ret = select(max_fd + 1, &in, &out, NULL, timeout);
  if (ret <= 0)
    return ret;

  for (i = 0; i < fds_count; i++) {
    if (!fds[i].events)
      continue;

    if (FD_ISSET(fds[i].fd, &in))
      fds[i].revents |= SILC_TASK_READ;
    if (FD_ISSET(fds[i].fd, &out))
      fds[i].revents |= SILC_TASK_WRITE;
  }

  return ret;
}

/* Internal context. */
typedef struct {
  int wakeup_pipe[2];
  SilcTask wakeup_task;
  sigset_t signals;
  sigset_t signals_blocked;
} *SilcUnixScheduler;

#ifdef SILC_THREADS

SILC_TASK_CALLBACK(silc_schedule_wakeup_cb)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  unsigned char c;

  read(internal->wakeup_pipe[0], &c, 1);
}

#endif /* SILC_THREADS */

/* Initializes the platform specific scheduler.  This for example initializes
   the wakeup mechanism of the scheduler.  In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues.  Returns context to the platform specific scheduler. */

void *silc_schedule_internal_init(SilcSchedule schedule)
{
  SilcUnixScheduler internal;

  internal = silc_calloc(1, sizeof(*internal));
  if (!internal)
    return NULL;

  sigemptyset(&internal->signals);

#ifdef SILC_THREADS
  if (pipe(internal->wakeup_pipe)) {
    silc_free(internal);
    return NULL;
  }

  internal->wakeup_task = 
    silc_schedule_task_add(schedule, internal->wakeup_pipe[0],
			   silc_schedule_wakeup_cb, internal,
			   0, 0, SILC_TASK_FD, 
			   SILC_TASK_PRI_NORMAL);
  if (!internal->wakeup_task) {
    close(internal->wakeup_pipe[0]);
    close(internal->wakeup_pipe[1]);
    silc_free(internal);
    return NULL;
  }
#endif

  return (void *)internal;
}

/* Uninitializes the platform specific scheduler context. */

void silc_schedule_internal_uninit(void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

#ifdef SILC_THREADS
  close(internal->wakeup_pipe[0]);
  close(internal->wakeup_pipe[1]);
#endif

  silc_free(internal);
}

/* Wakes up the scheduler */

void silc_schedule_internal_wakeup(void *context)
{
#ifdef SILC_THREADS
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

  write(internal->wakeup_pipe[1], "!", 1);
#endif
}

void silc_schedule_internal_signal_register(void *context,
					    SilcUInt32 signal)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  sigaddset(&internal->signals, signal);
}

void silc_schedule_internal_signal_unregister(void *context,
					      SilcUInt32 signal)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  sigdelset(&internal->signals, signal);
}

/* Block registered signals in scheduler. */

void silc_schedule_internal_signals_block(void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  sigprocmask(SIG_BLOCK, &internal->signals, &internal->signals_blocked);
}

/* Unblock registered signals in schedule. */

void silc_schedule_internal_signals_unblock(void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  sigprocmask(SIG_SETMASK, &internal->signals_blocked, NULL);
}
