/*

  silcunixschedule.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2004 Pekka Riikonen

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

#define SIGNAL_COUNT 32

typedef struct {
  SilcUInt32 signal;
  SilcTaskCallback callback;
  void *context;
  bool call;
} SilcUnixSignal;

/* Internal context. */
typedef struct {
  void *app_context;
  int wakeup_pipe[2];
  SilcTask wakeup_task;
  sigset_t signals;
  sigset_t signals_blocked;
  SilcUnixSignal signal_call[SIGNAL_COUNT];
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

void *silc_schedule_internal_init(SilcSchedule schedule,
				  void *app_context)
{
  SilcUnixScheduler internal;

  internal = silc_calloc(1, sizeof(*internal));
  if (!internal)
    return NULL;

  sigemptyset(&internal->signals);

#ifdef SILC_THREADS
  if (pipe(internal->wakeup_pipe)) {
    SILC_LOG_ERROR(("pipe() fails: %s", strerror(errno)));
    silc_free(internal);
    return NULL;
  }

  internal->wakeup_task =
    silc_schedule_task_add(schedule, internal->wakeup_pipe[0],
			   silc_schedule_wakeup_cb, internal,
			   0, 0, SILC_TASK_FD,
			   SILC_TASK_PRI_NORMAL);
  if (!internal->wakeup_task) {
    SILC_LOG_ERROR(("Could not add a wakeup task, threads won't work"));
    close(internal->wakeup_pipe[0]);
    close(internal->wakeup_pipe[1]);
    silc_free(internal);
    return NULL;
  }
#endif

  internal->app_context = app_context;

  return (void *)internal;
}

void silc_schedule_internal_signals_block(void *context);
void silc_schedule_internal_signals_unblock(void *context);

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
					    SilcUInt32 signal,
                                            SilcTaskCallback callback,
                                            void *callback_context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  if (!internal)
    return;

  SILC_LOG_DEBUG(("Registering signal %d", signal));

  silc_schedule_internal_signals_block(context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (!internal->signal_call[i].signal) {
      internal->signal_call[i].signal = signal;
      internal->signal_call[i].callback = callback;
      internal->signal_call[i].context = callback_context;
      internal->signal_call[i].call = FALSE;
      break;
    }
  }

  silc_schedule_internal_signals_unblock(context);
  sigaddset(&internal->signals, signal);
}

void silc_schedule_internal_signal_unregister(void *context,
					      SilcUInt32 signal,
                                              SilcTaskCallback callback,
                                              void *callback_context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  if (!internal)
    return;

  SILC_LOG_DEBUG(("Unregistering signal %d", signal));

  silc_schedule_internal_signals_block(context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (internal->signal_call[i].signal == signal &&
	internal->signal_call[i].callback == callback &&
	internal->signal_call[i].context == callback_context) {
      internal->signal_call[i].signal = 0;
      internal->signal_call[i].callback = NULL;
      internal->signal_call[i].context = NULL;
      internal->signal_call[i].call = FALSE;
    }
  }

  silc_schedule_internal_signals_unblock(context);
  sigdelset(&internal->signals, signal);
}

/* Mark signal to be called later. */

void silc_schedule_internal_signal_call(void *context, SilcUInt32 signal)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  if (!internal)
    return;

  silc_schedule_internal_signals_block(context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (internal->signal_call[i].signal == signal) {
      internal->signal_call[i].call = TRUE;
      SILC_LOG_DEBUG(("Scheduling signal %d to be called",
		      internal->signal_call[i].signal));
    }
  }

  silc_schedule_internal_signals_unblock(context);
}

/* Call all signals */

void silc_schedule_internal_signals_call(void *context,
                                         SilcSchedule schedule)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  SILC_LOG_DEBUG(("Start"));

  if (!internal)
    return;

  silc_schedule_internal_signals_block(context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (internal->signal_call[i].call &&
        internal->signal_call[i].callback) {
      SILC_LOG_DEBUG(("Calling signal %d callback",
		      internal->signal_call[i].signal));
      internal->signal_call[i].callback(schedule, internal->app_context,
					SILC_TASK_INTERRUPT,
					internal->signal_call[i].signal,
					internal->signal_call[i].context);
      internal->signal_call[i].call = FALSE;
    }
  }

  silc_schedule_internal_signals_unblock(context);
}

/* Block registered signals in scheduler. */

void silc_schedule_internal_signals_block(void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

  sigprocmask(SIG_BLOCK, &internal->signals, &internal->signals_blocked);
}

/* Unblock registered signals in schedule. */

void silc_schedule_internal_signals_unblock(void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

  sigprocmask(SIG_SETMASK, &internal->signals_blocked, NULL);
}
