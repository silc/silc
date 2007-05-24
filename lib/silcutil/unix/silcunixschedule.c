/*

  silcunixschedule.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"

#if defined(HAVE_EPOLL_WAIT)
#include <sys/epoll.h>
#elif defined(HAVE_POLL) && defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
#include <poll.h>
#endif

const SilcScheduleOps schedule_ops;

/* Internal context. */
typedef struct {
#if defined(HAVE_EPOLL_WAIT)
  struct epoll_event *fds;
  SilcUInt32 fds_count;
  int epfd;
#elif defined(HAVE_POLL) && defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
  struct rlimit nofile;
  struct pollfd *fds;
  SilcUInt32 fds_count;
#endif /* HAVE_POLL && HAVE_SETRLIMIT && RLIMIT_NOFILE */
  void *app_context;
  int wakeup_pipe[2];
  SilcTask wakeup_task;
  sigset_t signals;
  sigset_t signals_blocked;
} *SilcUnixScheduler;

typedef struct {
  SilcUInt32 sig;
  SilcTaskCallback callback;
  void *context;
  SilcBool call;
  SilcSchedule schedule;
} SilcUnixSignal;

#define SIGNAL_COUNT 32
SilcUnixSignal signal_call[SIGNAL_COUNT];

#if defined(HAVE_EPOLL_WAIT)

/* Linux's fast epoll system (level triggered) */

int silc_epoll(SilcSchedule schedule, void *context)
{
  SilcUnixScheduler internal = context;
  SilcTaskFd task;
  struct epoll_event *fds = internal->fds;
  SilcUInt32 fds_count = internal->fds_count;
  int ret, i, timeout = -1;

  /* Allocate larger fd table if needed */
  i = silc_hash_table_count(schedule->fd_queue);
  if (i > fds_count) {
    fds = silc_realloc(internal->fds, sizeof(*internal->fds) *
		       (fds_count + (i / 2)));
    if (silc_likely(fds)) {
      internal->fds = fds;
      internal->fds_count = fds_count = fds_count + (i / 2);
    }
  }

  if (schedule->has_timeout)
    timeout = ((schedule->timeout.tv_sec * 1000) +
	       (schedule->timeout.tv_usec / 1000));

  SILC_SCHEDULE_UNLOCK(schedule);
  ret = epoll_wait(internal->epfd, fds, fds_count, timeout);
  SILC_SCHEDULE_LOCK(schedule);
  if (ret <= 0)
    return ret;

  silc_list_init(schedule->fd_dispatch, struct SilcTaskStruct, next);

  for (i = 0; i < ret; i++) {
    task = fds[i].data.ptr;
    task->revents = 0;
    if (!task->header.valid || !task->events) {
      epoll_ctl(internal->epfd, EPOLL_CTL_DEL, task->fd, &fds[i]);
      continue;
    }
    if (fds[i].events & (EPOLLIN | EPOLLPRI | EPOLLHUP | EPOLLERR))
      task->revents |= SILC_TASK_READ;
    if (fds[i].events & EPOLLOUT)
      task->revents |= SILC_TASK_WRITE;
    silc_list_add(schedule->fd_dispatch, task);
  }

  return ret;
}

#elif defined(HAVE_POLL) && defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)

/* Calls normal poll() system call. */

int silc_poll(SilcSchedule schedule, void *context)
{
  SilcUnixScheduler internal = context;
  SilcHashTableList htl;
  SilcTaskFd task;
  struct pollfd *fds = internal->fds;
  SilcUInt32 fds_count = internal->fds_count;
  int fd, ret, i = 0, timeout = -1;

  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, (void *)&fd, (void *)&task)) {
    if (!task->events)
      continue;

    /* Allocate larger fd table if needed */
    if (i >= fds_count) {
      struct rlimit nofile;

      fds = silc_realloc(internal->fds, sizeof(*internal->fds) *
			 (fds_count + (fds_count / 2)));
      if (silc_unlikely(!fds))
	break;
      internal->fds = fds;
      internal->fds_count = fds_count = fds_count + (fds_count / 2);
      internal->nofile.rlim_cur = fds_count;
      if (fds_count > internal->nofile.rlim_max)
	internal->nofile.rlim_max = fds_count;
      if (setrlimit(RLIMIT_NOFILE, &nofile) < 0)
	break;
    }

    fds[i].fd = fd;
    fds[i].events = 0;
    task->revents = fds[i].revents = 0;

    if (task->events & SILC_TASK_READ)
      fds[i].events |= (POLLIN | POLLPRI);
    if (task->events & SILC_TASK_WRITE)
      fds[i].events |= POLLOUT;
    i++;
  }
  silc_hash_table_list_reset(&htl);
  silc_list_init(schedule->fd_dispatch, struct SilcTaskStruct, next);

  if (schedule->has_timeout)
    timeout = ((schedule->timeout.tv_sec * 1000) +
	       (schedule->timeout.tv_usec / 1000));

  fds_count = i;
  SILC_SCHEDULE_UNLOCK(schedule);
  ret = poll(fds, fds_count, timeout);
  SILC_SCHEDULE_LOCK(schedule);
  if (ret <= 0)
    return ret;

  for (i = 0; i < fds_count; i++) {
    if (!fds[i].revents)
      continue;
    if (!silc_hash_table_find(schedule->fd_queue, SILC_32_TO_PTR(fds[i].fd),
			      NULL, (void *)&task))
      continue;
    if (!task->header.valid || !task->events)
      continue;

    fd = fds[i].revents;
    if (fd & (POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL))
      task->revents |= SILC_TASK_READ;
    if (fd & POLLOUT)
      task->revents |= SILC_TASK_WRITE;
    silc_list_add(schedule->fd_dispatch, task);
  }

  return ret;
}

#else

/* Calls normal select() system call. */

int silc_select(SilcSchedule schedule, void *context)
{
  SilcHashTableList htl;
  SilcTaskFd task;
  fd_set in, out;
  int fd, max_fd = 0, ret;

  FD_ZERO(&in);
  FD_ZERO(&out);

  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, (void *)&fd, (void *)&task)) {
    if (!task->events)
      continue;

#ifdef FD_SETSIZE
    if (fd >= FD_SETSIZE)
      break;
#endif /* FD_SETSIZE */

    if (fd > max_fd)
      max_fd = fd;

    if (task->events & SILC_TASK_READ)
      FD_SET(fd, &in);
    if (task->events & SILC_TASK_WRITE)
      FD_SET(fd, &out);

    task->revents = 0;
  }
  silc_hash_table_list_reset(&htl);
  silc_list_init(schedule->fd_dispatch, struct SilcTaskStruct, next);

  SILC_SCHEDULE_UNLOCK(schedule);
  ret = select(max_fd + 1, &in, &out, NULL, (schedule->has_timeout ?
					     &schedule->timeout : NULL));
  SILC_SCHEDULE_LOCK(schedule);
  if (ret <= 0)
    return ret;

  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, (void *)&fd, (void *)&task)) {
    if (!task->header.valid || !task->events)
      continue;

#ifdef FD_SETSIZE
    if (fd >= FD_SETSIZE)
      break;
#endif /* FD_SETSIZE */

    if (FD_ISSET(fd, &in))
      task->revents |= SILC_TASK_READ;
    if (FD_ISSET(fd, &out))
      task->revents |= SILC_TASK_WRITE;
    silc_list_add(schedule->fd_dispatch, task);
  }
  silc_hash_table_list_reset(&htl);

  return ret;
}

#endif /* HAVE_POLL && HAVE_SETRLIMIT && RLIMIT_NOFILE */

/* Schedule `task' with events `event_mask'. Zero `event_mask' unschedules. */

SilcBool silc_schedule_internal_schedule_fd(SilcSchedule schedule,
					    void *context,
					    SilcTaskFd task,
					    SilcTaskEvent event_mask)
{
#if defined(HAVE_EPOLL_WAIT)
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  struct epoll_event event;

  if (!internal)
    return TRUE;

  SILC_LOG_DEBUG(("Scheduling fd %lu, mask %x", task->fd, event_mask));

  memset(&event, 0, sizeof(event));
  if (event_mask & SILC_TASK_READ)
    event.events |= (EPOLLIN | EPOLLPRI);
  if (event_mask & SILC_TASK_WRITE)
    event.events |= EPOLLOUT;

  /* Zero mask unschedules task */
  if (silc_unlikely(!event.events)) {
    if (epoll_ctl(internal->epfd, EPOLL_CTL_DEL, task->fd, &event)) {
      SILC_LOG_DEBUG(("epoll_ctl (DEL): %s", strerror(errno)));
      return FALSE;
    }
    return TRUE;
  }

  /* Schedule the task */
  if (silc_unlikely(!task->scheduled)) {
    event.data.ptr = task;
    if (epoll_ctl(internal->epfd, EPOLL_CTL_ADD, task->fd, &event)) {
      SILC_LOG_DEBUG(("epoll_ctl (ADD): %s", strerror(errno)));
      return FALSE;
    }
    task->scheduled = TRUE;
    return TRUE;
  }

  /* Schedule for specific mask */
  event.data.ptr = task;
  if (epoll_ctl(internal->epfd, EPOLL_CTL_MOD, task->fd, &event)) {
    SILC_LOG_DEBUG(("epoll_ctl (MOD): %s", strerror(errno)));
    return FALSE;
  }
#endif /* HAVE_EPOLL_WAIT */
  return TRUE;
}

#ifdef SILC_THREADS

SILC_TASK_CALLBACK(silc_schedule_wakeup_cb)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  unsigned char c;

  SILC_LOG_DEBUG(("Wokeup"));

  read(internal->wakeup_pipe[0], &c, 1);
}

#endif /* SILC_THREADS */

/* Initializes the platform specific scheduler.  This for example initializes
   the wakeup mechanism of the scheduler.  In multi-threaded environment
   the scheduler needs to be woken up when tasks are added or removed from
   the task queues.  Returns context to the platform specific scheduler. */

void *silc_schedule_internal_init(SilcSchedule schedule,
				  void *app_context)
{
  SilcUnixScheduler internal;
  int i;

  internal = silc_calloc(1, sizeof(*internal));
  if (!internal)
    return NULL;

#if defined(HAVE_EPOLL_WAIT)
  internal->epfd = epoll_create(4);
  if (internal->epfd < 0) {
    SILC_LOG_ERROR(("epoll_create() failed: %s", strerror(errno)));
    return NULL;
  }
  internal->fds = silc_calloc(4, sizeof(*internal->fds));
  if (!internal->fds) {
    close(internal->epfd);
    return NULL;
  }
  internal->fds_count = 4;
#elif defined(HAVE_POLL) && defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
  getrlimit(RLIMIT_NOFILE, &internal->nofile);

  if (schedule->max_tasks > 0) {
    internal->nofile.rlim_cur = schedule->max_tasks;
    if (schedule->max_tasks > internal->nofile.rlim_max)
      internal->nofile.rlim_max = schedule->max_tasks;
    setrlimit(RLIMIT_NOFILE, &internal->nofile);
    getrlimit(RLIMIT_NOFILE, &internal->nofile);
    schedule->max_tasks = internal->nofile.rlim_max;
  }

  internal->fds = silc_calloc(internal->nofile.rlim_cur,
			      sizeof(*internal->fds));
  if (!internal->fds)
    return NULL;
  internal->fds_count = internal->nofile.rlim_cur;
#endif /* HAVE_POLL && HAVE_SETRLIMIT && RLIMIT_NOFILE */

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
			   0, 0, SILC_TASK_FD);
  if (!internal->wakeup_task) {
    SILC_LOG_ERROR(("Could not add a wakeup task, threads won't work"));
    close(internal->wakeup_pipe[0]);
    close(internal->wakeup_pipe[1]);
    silc_free(internal);
    return NULL;
  }
  silc_schedule_internal_schedule_fd(schedule, internal,
				     (SilcTaskFd)internal->wakeup_task,
				     SILC_TASK_READ);
#endif /* SILC_THREADS */

  internal->app_context = app_context;

  for (i = 0; i < SIGNAL_COUNT; i++) {
    signal_call[i].sig = 0;
    signal_call[i].call = FALSE;
    signal_call[i].schedule = schedule;
  }

  return (void *)internal;
}

void silc_schedule_internal_signals_block(SilcSchedule schedule,
					  void *context);
void silc_schedule_internal_signals_unblock(SilcSchedule schedule,
					    void *context);

/* Uninitializes the platform specific scheduler context. */

void silc_schedule_internal_uninit(SilcSchedule schedule, void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

#ifdef SILC_THREADS
  close(internal->wakeup_pipe[0]);
  close(internal->wakeup_pipe[1]);
#endif

#if defined(HAVE_EPOLL_WAIT)
  close(internal->epfd);
  silc_free(internal->fds);
#elif defined(HAVE_POLL) && defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
  silc_free(internal->fds);
#endif /* HAVE_POLL && HAVE_SETRLIMIT && RLIMIT_NOFILE */

  silc_free(internal);
}

/* Wakes up the scheduler */

void silc_schedule_internal_wakeup(SilcSchedule schedule, void *context)
{
#ifdef SILC_THREADS
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal || !internal->wakeup_task)
    return;

  SILC_LOG_DEBUG(("Wakeup"));

  write(internal->wakeup_pipe[1], "!", 1);
#endif
}

/* Signal handler */

static void silc_schedule_internal_sighandler(int signal)
{
  int i;

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (signal_call[i].sig == signal) {
      signal_call[i].call = TRUE;
      signal_call[i].schedule->signal_tasks = TRUE;
      SILC_LOG_DEBUG(("Scheduling signal %d to be called",
		      signal_call[i].sig));
      break;
    }
  }
}

void silc_schedule_internal_signal_register(SilcSchedule schedule,
					    void *context,
					    SilcUInt32 sig,
                                            SilcTaskCallback callback,
                                            void *callback_context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  if (!internal)
    return;

  SILC_LOG_DEBUG(("Registering signal %d", sig));

  silc_schedule_internal_signals_block(schedule, context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (!signal_call[i].sig) {
      signal_call[i].sig = sig;
      signal_call[i].callback = callback;
      signal_call[i].context = callback_context;
      signal_call[i].call = FALSE;
      signal(sig, silc_schedule_internal_sighandler);
      break;
    }
  }

  silc_schedule_internal_signals_unblock(schedule, context);
  sigaddset(&internal->signals, sig);
}

void silc_schedule_internal_signal_unregister(SilcSchedule schedule,
					      void *context,
					      SilcUInt32 sig)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  if (!internal)
    return;

  SILC_LOG_DEBUG(("Unregistering signal %d", sig));

  silc_schedule_internal_signals_block(schedule, context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (signal_call[i].sig == sig) {
      signal_call[i].sig = 0;
      signal_call[i].callback = NULL;
      signal_call[i].context = NULL;
      signal_call[i].call = FALSE;
      signal(sig, SIG_DFL);
    }
  }

  silc_schedule_internal_signals_unblock(schedule, context);
  sigdelset(&internal->signals, sig);
}

/* Call all signals */

void silc_schedule_internal_signals_call(SilcSchedule schedule, void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;
  int i;

  SILC_LOG_DEBUG(("Start"));

  if (!internal)
    return;

  silc_schedule_internal_signals_block(schedule, context);

  for (i = 0; i < SIGNAL_COUNT; i++) {
    if (signal_call[i].call &&
        signal_call[i].callback) {
      SILC_LOG_DEBUG(("Calling signal %d callback",
		      signal_call[i].sig));
      signal_call[i].callback(schedule, internal->app_context,
			      SILC_TASK_INTERRUPT,
			      signal_call[i].sig,
			      signal_call[i].context);
      signal_call[i].call = FALSE;
    }
  }

  silc_schedule_internal_signals_unblock(schedule, context);
}

/* Block registered signals in scheduler. */

void silc_schedule_internal_signals_block(SilcSchedule schedule, void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

  sigprocmask(SIG_BLOCK, &internal->signals, &internal->signals_blocked);
}

/* Unblock registered signals in schedule. */

void silc_schedule_internal_signals_unblock(SilcSchedule schedule,
					    void *context)
{
  SilcUnixScheduler internal = (SilcUnixScheduler)context;

  if (!internal)
    return;

  sigprocmask(SIG_SETMASK, &internal->signals_blocked, NULL);
}

const SilcScheduleOps schedule_ops =
{
  silc_schedule_internal_init,
  silc_schedule_internal_uninit,
#if defined(HAVE_EPOLL_WAIT)
  silc_epoll,
#elif defined(HAVE_POLL) && defined(HAVE_SETRLIMIT) && defined(RLIMIT_NOFILE)
  silc_poll,
#else
  silc_select,
#endif /* HAVE_POLL && HAVE_SETRLIMIT && RLIMIT_NOFILE */
  silc_schedule_internal_schedule_fd,
  silc_schedule_internal_wakeup,
  silc_schedule_internal_signal_register,
  silc_schedule_internal_signal_unregister,
  silc_schedule_internal_signals_call,
  silc_schedule_internal_signals_block,
  silc_schedule_internal_signals_unblock,
};
