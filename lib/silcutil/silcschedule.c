/*

  silcschedule.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2006 Pekka Riikonen

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

/* Platform specific implementation */
extern const SilcScheduleOps schedule_ops;

static void silc_schedule_task_remove(SilcSchedule schedule, SilcTask task);
static void silc_schedule_dispatch_fd(SilcSchedule schedule);
static void silc_schedule_dispatch_timeout(SilcSchedule schedule,
					   SilcBool dispatch_all);

/* Fd task hash table destructor */

static void silc_schedule_fd_destructor(void *key, void *context,
					void *user_context)
{
  silc_free(context);
}

/* Initializes the scheduler. This returns the scheduler context that
   is given as arugment usually to all silc_schedule_* functions.
   The `max_tasks' indicates the number of maximum tasks that the
   scheduler can handle. The `app_context' is application specific
   context that is delivered to task callbacks. */

SilcSchedule silc_schedule_init(int max_tasks, void *app_context)
{
  SilcSchedule schedule;

  SILC_LOG_DEBUG(("Initializing scheduler"));

  schedule = silc_calloc(1, sizeof(*schedule));
  if (!schedule)
    return NULL;

  schedule->fd_queue =
    silc_hash_table_alloc(0, silc_hash_uint, NULL, NULL, NULL,
			  silc_schedule_fd_destructor, NULL, TRUE);
  if (!schedule->fd_queue)
    return NULL;

  silc_list_init(schedule->timeout_queue, struct SilcTaskTimeoutStruct, next);

  schedule->app_context = app_context;
  schedule->valid = TRUE;
  schedule->max_tasks = max_tasks;

  /* Allocate scheduler lock */
  silc_mutex_alloc(&schedule->lock);

  /* Initialize the platform specific scheduler. */
  schedule->internal = schedule_ops.init(schedule, app_context);

  return schedule;
}

/* Uninitializes the schedule. This is called when the program is ready
   to end. This removes all tasks and task queues. Returns FALSE if the
   scheduler could not be uninitialized. This happens when the scheduler
   is still valid and silc_schedule_stop has not been called. */

SilcBool silc_schedule_uninit(SilcSchedule schedule)
{
  SILC_LOG_DEBUG(("Uninitializing scheduler"));

  if (schedule->valid == TRUE)
    return FALSE;

  /* Dispatch all timeouts before going away */
  SILC_SCHEDULE_LOCK(schedule);
  silc_schedule_dispatch_timeout(schedule, TRUE);
  SILC_SCHEDULE_UNLOCK(schedule);

  /* Deliver signals before going away */
  if (schedule->signal_tasks) {
    schedule_ops.signals_call(schedule, schedule->internal);
    schedule->signal_tasks = FALSE;
  }

  /* Unregister all tasks */
  silc_schedule_task_remove(schedule, SILC_ALL_TASKS);
  silc_schedule_task_remove(schedule, SILC_ALL_TASKS);

  /* Unregister all task queues */
  silc_hash_table_free(schedule->fd_queue);

  /* Uninit the platform specific scheduler. */
  schedule_ops.uninit(schedule, schedule->internal);

  silc_mutex_free(schedule->lock);
  silc_free(schedule);

  return TRUE;
}

/* Stops the schedule even if it is not supposed to be stopped yet.
   After calling this, one should call silc_schedule_uninit (after the
   silc_schedule has returned). */

void silc_schedule_stop(SilcSchedule schedule)
{
  SILC_LOG_DEBUG(("Stopping scheduler"));
  SILC_SCHEDULE_LOCK(schedule);
  schedule->valid = FALSE;
  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Executes file descriptor tasks. Invalid tasks are removed here. */

static void silc_schedule_dispatch_fd(SilcSchedule schedule)
{
  SilcHashTableList htl;
  SilcTask t;
  SilcTaskFd task;
  SilcUInt32 fd;

  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, (void **)&fd, (void **)&task)) {
    t = (SilcTask)task;

    if (!t->valid) {
      silc_schedule_task_remove(schedule, t);
      continue;
    }
    if (!task->events || !task->revents)
      continue;

    /* Is the task ready for reading */
    if (task->revents & SILC_TASK_READ) {
      SILC_SCHEDULE_UNLOCK(schedule);
      t->callback(schedule, schedule->app_context, SILC_TASK_READ,
		  task->fd, t->context);
      SILC_SCHEDULE_LOCK(schedule);
    }

    /* Is the task ready for writing */
    if (t->valid && task->revents & SILC_TASK_WRITE) {
      SILC_SCHEDULE_UNLOCK(schedule);
      t->callback(schedule, schedule->app_context, SILC_TASK_WRITE,
		  task->fd, t->context);
      SILC_SCHEDULE_LOCK(schedule);
    }

    /* Remove if task was invalidated in the task callback */
    if (!t->valid)
      silc_schedule_task_remove(schedule, t);
  }
  silc_hash_table_list_reset(&htl);
}

/* Executes all tasks whose timeout has expired. The task is removed from
   the task queue after the callback function has returned. Also, invalid
   tasks are removed here. */

static void silc_schedule_dispatch_timeout(SilcSchedule schedule,
					   SilcBool dispatch_all)
{
  SilcTask t;
  SilcTaskTimeout task;
  struct timeval curtime;
  int count = 0;

  SILC_LOG_DEBUG(("Running timeout tasks"));

  silc_gettimeofday(&curtime);

  /* First task in the task queue has always the earliest timeout. */
  silc_list_start(schedule->timeout_queue);
  while ((task = silc_list_get(schedule->timeout_queue)) != SILC_LIST_END) {
    t = (SilcTask)task;

    /* Remove invalid task */
    if (!t->valid) {
      silc_schedule_task_remove(schedule, t);
      continue;
    }

    /* Execute the task if the timeout has expired */
    if (dispatch_all || silc_compare_timeval(&task->timeout, &curtime)) {
      t->valid = FALSE;
      SILC_SCHEDULE_UNLOCK(schedule);
      t->callback(schedule, schedule->app_context, SILC_TASK_EXPIRE, 0,
		  t->context);
      SILC_SCHEDULE_LOCK(schedule);

      /* Remove the expired task */
      silc_schedule_task_remove(schedule, t);

      /* Balance when we have lots of small timeouts */
      if ((++count) > 50)
	break;
    }
  }
}

/* Calculates next timeout. This is the timeout value when at earliest some
   of the timeout tasks expire. If this is in the past, they will be
   dispatched now. */

static void silc_schedule_select_timeout(SilcSchedule schedule)
{
  SilcTask t;
  SilcTaskTimeout task;
  struct timeval curtime;
  SilcBool dispatch = TRUE;

  /* Get the current time */
  silc_gettimeofday(&curtime);
  schedule->has_timeout = FALSE;

  /* First task in the task queue has always the earliest timeout. */
  silc_list_start(schedule->timeout_queue);
  while ((task = silc_list_get(schedule->timeout_queue)) != SILC_LIST_END) {
    t = (SilcTask)task;

    /* Remove invalid task */
    if (!t->valid) {
      silc_schedule_task_remove(schedule, t);
      continue;
    }

    /* If the timeout is in past, we will run the task and all other
       timeout tasks from the past. */
    if (silc_compare_timeval(&task->timeout, &curtime) && dispatch) {
      silc_schedule_dispatch_timeout(schedule, FALSE);
      if (!schedule->valid)
	return;

      /* Start selecting new timeout again after dispatch */
      silc_list_start(schedule->timeout_queue);
      dispatch = FALSE;
      continue;
    }

    /* Calculate the next timeout */
    curtime.tv_sec = task->timeout.tv_sec - curtime.tv_sec;
    curtime.tv_usec = task->timeout.tv_usec - curtime.tv_usec;
    if (curtime.tv_sec < 0)
      curtime.tv_sec = 0;

    /* We wouldn't want to go under zero, check for it. */
    if (curtime.tv_usec < 0) {
      curtime.tv_sec -= 1;
      if (curtime.tv_sec < 0)
	curtime.tv_sec = 0;
      curtime.tv_usec += 1000000L;
    }

    break;
  }

  /* Save the timeout */
  if (task) {
    schedule->timeout = curtime;
    schedule->has_timeout = TRUE;
    SILC_LOG_DEBUG(("timeout: sec=%d, usec=%d", schedule->timeout.tv_sec,
		    schedule->timeout.tv_usec));
  }
}

/* Runs the scheduler once and then returns. */

SilcBool silc_schedule_one(SilcSchedule schedule, int timeout_usecs)
{
  struct timeval timeout;
  int ret;

  SILC_LOG_DEBUG(("In scheduler loop"));

  if (!schedule->is_locked)
    SILC_SCHEDULE_LOCK(schedule);

  /* Deliver signals if any has been set to be called */
  if (schedule->signal_tasks) {
    SILC_SCHEDULE_UNLOCK(schedule);
    schedule_ops.signals_call(schedule, schedule->internal);
    schedule->signal_tasks = FALSE;
    SILC_SCHEDULE_LOCK(schedule);
  }

  /* Check if scheduler is valid */
  if (schedule->valid == FALSE) {
    SILC_LOG_DEBUG(("Scheduler not valid anymore, exiting"));
    if (!schedule->is_locked)
      SILC_SCHEDULE_UNLOCK(schedule);
    return FALSE;
  }

  /* Calculate next timeout for silc_select().  This is the timeout value
     when at earliest some of the timeout tasks expire.  This may dispatch
     already expired timeouts. */
  silc_schedule_select_timeout(schedule);

  /* Check if scheduler is valid */
  if (schedule->valid == FALSE) {
    SILC_LOG_DEBUG(("Scheduler not valid anymore, exiting"));
    if (!schedule->is_locked)
      SILC_SCHEDULE_UNLOCK(schedule);
    return FALSE;
  }

  if (timeout_usecs >= 0) {
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_usecs;
    schedule->timeout = timeout;
    schedule->has_timeout = TRUE;
  }

  /* This is the main silc_select(). The program blocks here until some
     of the selected file descriptors change status or the selected
     timeout expires. */
  SILC_LOG_DEBUG(("Select"));
  ret = schedule_ops.select(schedule, schedule->internal);

  switch (ret) {
  case 0:
    /* Timeout */
    SILC_LOG_DEBUG(("Running timeout tasks"));
    silc_schedule_dispatch_timeout(schedule, FALSE);
    break;
  case -1:
    /* Error */
    if (errno == EINTR)
      break;
    SILC_LOG_ERROR(("Error in select(): %s", strerror(errno)));
    break;
  default:
    /* There is some data available now */
    SILC_LOG_DEBUG(("Running fd tasks"));
    silc_schedule_dispatch_fd(schedule);
    break;
  }

  if (!schedule->is_locked)
    SILC_SCHEDULE_UNLOCK(schedule);

  return TRUE;
}

/* The SILC scheduler. This is actually the main routine in SILC programs.
   When this returns the program is to be ended. Before this function can
   be called, one must call silc_schedule_init function. */

void silc_schedule(SilcSchedule schedule)
{
  SILC_LOG_DEBUG(("Running scheduler"));

  if (schedule->valid == FALSE) {
    SILC_LOG_ERROR(("Scheduler is not valid, stopping"));
    return;
  }

  SILC_SCHEDULE_LOCK(schedule);
  schedule->is_locked = TRUE;

  /* Start the scheduler loop */
  while (silc_schedule_one(schedule, -1))
    ;

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Wakes up the scheduler. This is used only in multi-threaded
   environments where threads may add new tasks or remove old tasks
   from task queues. This is called to wake up the scheduler in the
   main thread so that it detects the changes in the task queues.
   If threads support is not compiled in this function has no effect.
   Implementation of this function is platform specific. */

void silc_schedule_wakeup(SilcSchedule schedule)
{
#ifdef SILC_THREADS
  SILC_LOG_DEBUG(("Wakeup scheduler"));
  SILC_SCHEDULE_LOCK(schedule);
  schedule_ops.wakeup(schedule, schedule->internal);
  SILC_SCHEDULE_UNLOCK(schedule);
#endif
}

/* Returns the application specific context that was saved into the
   scheduler in silc_schedule_init function.  The context is also
   returned to application in task callback functions, but this function
   may be used to get it as well if needed. */

void *silc_schedule_get_context(SilcSchedule schedule)
{
  return schedule->app_context;
}

/* Add new task to the scheduler */

SilcTask silc_schedule_task_add(SilcSchedule schedule, SilcUInt32 fd,
				SilcTaskCallback callback, void *context,
				long seconds, long useconds,
				SilcTaskType type)
{
  SilcTask task = NULL;

  if (!schedule->valid)
    return NULL;

  SILC_SCHEDULE_LOCK(schedule);

  if (type == SILC_TASK_TIMEOUT) {
    SilcTaskTimeout tmp, prev, ttask = silc_calloc(1, sizeof(*ttask));
    if (!ttask)
      goto out;

    ttask->header.type = 1;
    ttask->header.callback = callback;
    ttask->header.context = context;
    ttask->header.valid = TRUE;

    /* Add timeout */
    if ((seconds + useconds) > 0) {
      silc_gettimeofday(&ttask->timeout);
      ttask->timeout.tv_sec += seconds + (useconds / 1000000L);
      ttask->timeout.tv_usec += (useconds % 1000000L);
      if (ttask->timeout.tv_usec >= 1000000L) {
	ttask->timeout.tv_sec += 1;
	ttask->timeout.tv_usec -= 1000000L;
      }
    }

    SILC_LOG_DEBUG(("New timeout task %p: sec=%d, usec=%d", ttask,
		    seconds, useconds));

    /* Add task to correct spot so that the first task in the list has
       the earliest timeout. */
    silc_list_start(schedule->timeout_queue);
    prev = NULL;
    while ((tmp = silc_list_get(schedule->timeout_queue)) != SILC_LIST_END) {
      /* If we have shorter timeout, we have found our spot */
      if (silc_compare_timeval(&ttask->timeout, &tmp->timeout)) {
	silc_list_insert(schedule->timeout_queue, prev, ttask);
	break;
      }
      prev = tmp;
    }
    if (!tmp)
      silc_list_add(schedule->timeout_queue, ttask);

    task = (SilcTask)ttask;
  } else {
    /* Check if fd is already added */
    if (silc_hash_table_find(schedule->fd_queue, SILC_32_TO_PTR(fd),
			     NULL, (void **)&task))
      goto out;

    /* Check max tasks */
    if (schedule->max_tasks > 0 &&
	silc_hash_table_count(schedule->fd_queue) >= schedule->max_tasks) {
      SILC_LOG_WARNING(("Scheduler task limit reached: cannot add new task"));
      goto out;
    }

    SilcTaskFd ftask = silc_calloc(1, sizeof(*ftask));
    if (!ftask)
      goto out;

    SILC_LOG_DEBUG(("New fd task %p fd=%d", ftask, fd));

    ftask->header.type = 0;
    ftask->header.callback = callback;
    ftask->header.context = context;
    ftask->header.valid = TRUE;
    ftask->events = SILC_TASK_READ;
    ftask->fd = fd;

    /* Add task */
    silc_hash_table_add(schedule->fd_queue, SILC_32_TO_PTR(fd), ftask);

    task = (SilcTask)ftask;
  }

 out:
  SILC_SCHEDULE_UNLOCK(schedule);
  return task;
}

/* Invalidates task */

void silc_schedule_task_del(SilcSchedule schedule, SilcTask task)
{
  if (task == SILC_ALL_TASKS) {
    SilcTask task;
    SilcHashTableList htl;

    SILC_LOG_DEBUG(("Unregister all tasks"));

    SILC_SCHEDULE_LOCK(schedule);

    /* Delete from fd queue */
    silc_hash_table_list(schedule->fd_queue, &htl);
    while (silc_hash_table_get(&htl, NULL, (void **)&task))
      task->valid = FALSE;
    silc_hash_table_list_reset(&htl);

    /* Delete from timeout queue */
    silc_list_start(schedule->timeout_queue);
    while ((task = (SilcTask)silc_list_get(schedule->timeout_queue))
	   != SILC_LIST_END)
      task->valid = FALSE;

    SILC_SCHEDULE_UNLOCK(schedule);
    return;
  }

  SILC_LOG_DEBUG(("Unregistering task %p", task));
  SILC_SCHEDULE_LOCK(schedule);
  task->valid = FALSE;
  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Invalidate task by fd */

void silc_schedule_task_del_by_fd(SilcSchedule schedule, SilcUInt32 fd)
{
  SilcTask task;

  SILC_LOG_DEBUG(("Unregister task by fd %d", fd));

  SILC_SCHEDULE_LOCK(schedule);

  /* fd is unique, so there is only one task with this fd in the table */
  if (silc_hash_table_find(schedule->fd_queue, SILC_32_TO_PTR(fd), NULL,
			   (void **)&task))
    task->valid = FALSE;

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Invalidate task by task callback. */

void silc_schedule_task_del_by_callback(SilcSchedule schedule,
					SilcTaskCallback callback)
{
  SilcTask task;
  SilcHashTableList htl;

  SILC_LOG_DEBUG(("Unregister task by callback"));

  SILC_SCHEDULE_LOCK(schedule);

  /* Delete from fd queue */
  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&task)) {
    if (task->callback == callback)
      task->valid = FALSE;
  }
  silc_hash_table_list_reset(&htl);

  /* Delete from timeout queue */
  silc_list_start(schedule->timeout_queue);
  while ((task = (SilcTask)silc_list_get(schedule->timeout_queue))
	 != SILC_LIST_END) {
    if (task->callback == callback)
      task->valid = FALSE;
  }

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Invalidate task by context. */

void silc_schedule_task_del_by_context(SilcSchedule schedule, void *context)
{
  SilcTask task;
  SilcHashTableList htl;

  SILC_LOG_DEBUG(("Unregister task by context"));

  SILC_SCHEDULE_LOCK(schedule);

  /* Delete from fd queue */
  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, NULL, (void **)&task)) {
    if (task->context == context)
      task->valid = FALSE;
  }
  silc_hash_table_list_reset(&htl);

  /* Delete from timeout queue */
  silc_list_start(schedule->timeout_queue);
  while ((task = (SilcTask)silc_list_get(schedule->timeout_queue))
	 != SILC_LIST_END) {
    if (task->context == context)
      task->valid = FALSE;
  }

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Invalidate task by all */

void silc_schedule_task_del_by_all(SilcSchedule schedule, int fd,
				   SilcTaskCallback callback, void *context)
{
  SilcTask task;

  SILC_LOG_DEBUG(("Unregister task by fd, callback and context"));

  /* For fd task, callback and context is irrelevant as fd is unique */
  if (fd)
    silc_schedule_task_del_by_fd(schedule, fd);

  SILC_SCHEDULE_LOCK(schedule);

  /* Delete from timeout queue */
  silc_list_start(schedule->timeout_queue);
  while ((task = (SilcTask)silc_list_get(schedule->timeout_queue))
	 != SILC_LIST_END) {
    if (task->callback == callback && task->context == context)
      task->valid = FALSE;
  }

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Removes task from the scheduler.  This must be called with scheduler
   locked. */

static void silc_schedule_task_remove(SilcSchedule schedule, SilcTask task)
{
  SilcTaskFd ftask;
  SilcTaskTimeout ttask;

  if (task == SILC_ALL_TASKS) {
    SilcTask task;
    SilcHashTableList htl;
    SilcUInt32 fd;

    /* Delete from fd queue */
    silc_hash_table_list(schedule->fd_queue, &htl);
    while (silc_hash_table_get(&htl, (void **)&fd, (void **)&task))
      silc_hash_table_del(schedule->fd_queue, SILC_32_TO_PTR(fd));
    silc_hash_table_list_reset(&htl);

    /* Delete from timeout queue */
    silc_list_start(schedule->timeout_queue);
    while ((task = (SilcTask)silc_list_get(schedule->timeout_queue))
	   != SILC_LIST_END) {
      silc_list_del(schedule->timeout_queue, task);
      silc_free(task);
    }

    return;
  }

  /* Delete from timeout queue */
  if (task->type == 1) {
    silc_list_start(schedule->timeout_queue);
    while ((ttask = silc_list_get(schedule->timeout_queue)) != SILC_LIST_END) {
      if (ttask == (SilcTaskTimeout)task) {
	silc_list_del(schedule->timeout_queue, ttask);
	silc_free(ttask);
	break;
      }
    }

    return;
  }

  /* Delete from fd queue */
  ftask = (SilcTaskFd)task;
  silc_hash_table_del(schedule->fd_queue, SILC_32_TO_PTR(ftask->fd));
}

/* Sets a file descriptor to be listened by scheduler. One can call this
   directly if wanted. This can be called multiple times for one file
   descriptor to set different iomasks. */

void silc_schedule_set_listen_fd(SilcSchedule schedule, SilcUInt32 fd,
				 SilcTaskEvent mask, SilcBool send_events)
{
  SilcTaskFd task;

  if (!schedule->valid)
    return;

  SILC_SCHEDULE_LOCK(schedule);

  if (silc_hash_table_find(schedule->fd_queue, SILC_32_TO_PTR(fd),
			   NULL, (void **)&task)) {
    task->events = mask;
    if (send_events) {
      task->revents = mask;
      silc_schedule_dispatch_fd(schedule);
    }
  }

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Removes a file descriptor from listen list. */

void silc_schedule_unset_listen_fd(SilcSchedule schedule, SilcUInt32 fd)
{
  silc_schedule_set_listen_fd(schedule, fd, 0, FALSE);
}

/* Register a new signal */

void silc_schedule_signal_register(SilcSchedule schedule, SilcUInt32 signal,
				   SilcTaskCallback callback, void *context)
{
  schedule_ops.signal_register(schedule, schedule->internal, signal,
				callback, context);
}

/* Unregister a new signal */

void silc_schedule_signal_unregister(SilcSchedule schedule, SilcUInt32 signal,
				     SilcTaskCallback callback, void *context)
{
  schedule_ops.signal_unregister(schedule, schedule->internal, signal,
				  callback, context);
}

/* Call signal indicated by `signal'. */

void silc_schedule_signal_call(SilcSchedule schedule, SilcUInt32 signal)
{
  /* Mark that signals needs to be delivered later. */
  schedule_ops.signal_call(schedule, schedule->internal, signal);
  schedule->signal_tasks = TRUE;
}
