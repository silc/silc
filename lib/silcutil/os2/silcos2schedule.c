/*

  silcos2schedule.c 

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

/* XXX TODO */

#include "silcincludes.h"
#include "silcschedule_i.h"

/* Calls normal select() system call. */

int silc_select(SilcScheduleFd fds, SilcUInt32 fds_count, struct timeval *timeout)
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

  /*  ret = select(max_fd + 1, &in, &out, NULL, timeout); */
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

#ifdef SILC_THREADS

/* XXX Do this like it's done in win32/ */

/* Internal wakeup context. */
typedef struct {

} *SilcOs2Wakeup;

SILC_TASK_CALLBACK(silc_schedule_wakeup_cb)
{

}

#endif /* SILC_THREADS */

/* Initializes the platform specific scheduler.  This for example initializes
   the wakeup mechanism of the scheduler.  In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues.  Returns context to the platform specific scheduler. */

void *silc_schedule_internal_init(SilcSchedule schedule, void *context)
{
#ifdef SILC_THREADS
  return NULL;

#endif
  return NULL;
}

/* Uninitializes the platform specific scheduler context. */

void silc_schedule_internal_uninit(void *context)
{
#ifdef SILC_THREADS

#endif
}

/* Wakes up the scheduler */

void silc_schedule_internal_wakeup(void *context)
{
#ifdef SILC_THREADS

#endif
}

/* Register signal */

void silc_schedule_internal_signal_register(void *context,
                                            SilcUInt32 signal,
                                            SilcTaskCallback callback,
                                            void *callback_context)
{

}

/* Unregister signal */

void silc_schedule_internal_signal_unregister(void *context,
                                              SilcUInt32 signal,
                                              SilcTaskCallback callback,
                                              void *callback_context)
{

}

/* Mark signal to be called later. */

void silc_schedule_internal_signal_call(void *context, SilcUInt32 signal)
{

}

/* Call all signals */

void silc_schedule_internal_signals_call(void *context,
                                         SilcSchedule schedule)
{

}

/* Block registered signals in scheduler. */

void silc_schedule_internal_signals_block(void *context)
{

}

/* Unblock registered signals in schedule. */

void silc_schedule_internal_signals_unblock(void *context)
{

}
