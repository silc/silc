/*

  silcschedule.c

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

/* Forward declarations */
typedef struct SilcTaskQueueStruct *SilcTaskQueue;

/* System specific routines. Implemented under unix/, win32/ and such. */

/* System specific select(). Returns same values as normal select(). */
int silc_select(SilcScheduleFd fds, SilcUInt32 fds_count, 
		struct timeval *timeout);

/* Initializes the platform specific scheduler.  This for example initializes
   the wakeup mechanism of the scheduler.  In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues.  Returns context to the platform specific scheduler. */
void *silc_schedule_internal_init(SilcSchedule schedule);

/* Uninitializes the platform specific scheduler context. */
void silc_schedule_internal_uninit(void *context);

/* Wakes up the scheduler. This is platform specific routine */
void silc_schedule_internal_wakeup(void *context);

/* Register signal */
void silc_schedule_internal_signal_register(void *context,
                                            SilcUInt32 signal,
                                            SilcTaskCallback callback,
                                            void *callback_context);

/* Unregister signal */
void silc_schedule_internal_signal_unregister(void *context,
                                              SilcUInt32 signal,
                                              SilcTaskCallback callback,
                                              void *callback_context);

/* Mark signal to be called later. */
void silc_schedule_internal_signal_call(void *context, SilcUInt32 signal);

/* Call all signals */
void silc_schedule_internal_signals_call(void *context,
					 SilcSchedule schedule);

/* Block registered signals in scheduler. */
void silc_schedule_internal_signals_block(void *context);

/* Unblock registered signals in schedule. */
void silc_schedule_internal_signals_unblock(void *context);

/* Internal task management routines. */

static void silc_task_queue_alloc(SilcTaskQueue *queue);
static void silc_task_queue_free(SilcTaskQueue queue);
static SilcTask silc_task_find(SilcTaskQueue queue, SilcUInt32 fd);
static SilcTask silc_task_add(SilcTaskQueue queue, SilcTask newtask, 
			      SilcTaskPriority priority);
static SilcTask silc_task_get_first(SilcTaskQueue queue, SilcTask first);
static SilcTask silc_task_add_timeout(SilcTaskQueue queue, SilcTask newtask,
				      SilcTaskPriority priority);
static int silc_schedule_task_remove(SilcTaskQueue queue, SilcTask task);
static int silc_schedule_task_timeout_compare(struct timeval *smaller, 
					      struct timeval *bigger);
static void silc_task_del_by_context(SilcTaskQueue queue, void *context);
static void silc_task_del_by_callback(SilcTaskQueue queue,
				      SilcTaskCallback callback);
static void silc_task_del_by_fd(SilcTaskQueue queue, SilcUInt32 fd);

/* Returns the task queue by task type */
#define SILC_SCHEDULE_GET_QUEUE(type)				\
  (type == SILC_TASK_FD ? schedule->fd_queue :			\
   type == SILC_TASK_TIMEOUT ? schedule->timeout_queue :	\
   schedule->generic_queue)

/* Locks. These also blocks signals that we care about and thus guarantee
   that while we are in scheduler no signals can happen.  This way we can
   synchronise signals with SILC Scheduler. */
#define SILC_SCHEDULE_LOCK(schedule)				\
do {								\
  silc_schedule_internal_signals_block(schedule->internal);	\
  silc_mutex_lock(schedule->lock);				\
} while (0)
#define SILC_SCHEDULE_UNLOCK(schedule)				\
do {								\
  silc_mutex_unlock(schedule->lock);				\
  silc_schedule_internal_signals_unblock(schedule->internal);	\
} while (0)

/* SILC Task object. Represents one task in the scheduler. */
struct SilcTaskStruct {
  SilcUInt32 fd;
  SilcTaskCallback callback;	   /* Task callback */
  void *context;		   /* Task callback context */
  struct timeval timeout;	   /* Set for timeout tasks */
  unsigned int valid : 1;	   /* Set when task is valid */
  unsigned int priority : 2;	   /* Priority of the task */
  unsigned int type : 5;           /* Type of the task */

  /* Pointers forming doubly linked circular list */
  struct SilcTaskStruct *next;
  struct SilcTaskStruct *prev;
};

/* SILC Task Queue object. The queue holds all the tasks in the scheduler.
   There are always three task queues in the scheduler. One for non-timeout
   tasks (fd tasks performing tasks over specified file descriptor), 
   one for timeout tasks and one for generic tasks. */
struct SilcTaskQueueStruct {
  SilcTask task;		/* Pointer to all tasks */
  struct timeval timeout;	/* Current timeout */
  SILC_MUTEX_DEFINE(lock);	/* Queue's lock */
};

/* 
   SILC Scheduler structure.

   This is the actual schedule object in SILC. Both SILC client and server 
   uses this same scheduler. Actually, this scheduler could be used by any
   program needing scheduling.

   Following short description of the fields:

   SilcTaskQueue fd_queue

       Task queue hook for non-timeout tasks. Usually this means that these
       tasks perform different kind of I/O on file descriptors. File 
       descriptors are usually network sockets but they actually can be
       any file descriptors. This hook is initialized in silc_schedule_init
       function. Timeout tasks should not be added to this queue because
       they will never expire.

   SilcTaskQueue timeout_queue

       Task queue hook for timeout tasks. This hook is reserved specificly
       for tasks with timeout. Non-timeout tasks should not be added to this
       queue because they will never get scheduled. This hook is also
       initialized in silc_schedule_init function.

   SilcTaskQueue generic_queue

       Task queue hook for generic tasks. This hook is reserved specificly
       for generic tasks, tasks that apply to all file descriptors, except
       to those that have specificly registered a non-timeout task. This hook
       is also initialized in silc_schedule_init function.

   SilcScheduleFd fd_list

       List of file descriptors the scheduler is supposed to be listenning.
       This is updated internally.

   SilcUInt32 max_fd
   SilcUInt32 last_fd

       Size of the fd_list list. There can be `max_fd' many tasks in
       the scheduler at once. The `last_fd' is the last valid entry
       in the fd_list.

   struct timeval *timeout;

       Pointer to the schedules next timeout. Value of this timeout is
       automatically updated in the silc_schedule function.

   bool valid

       Marks validity of the scheduler. This is a boolean value. When this
       is false the scheduler is terminated and the program will end. This
       set to true when the scheduler is initialized with silc_schedule_init
       function.

   fd_set in
   fd_set out

       File descriptor sets for select(). These are automatically managed
       by the scheduler and should not be touched otherwise.

   void *internal

       System specific scheduler context.

   SILC_MUTEX_DEFINE(lock)
  
       Scheduler lock.

   bool signal_tasks

       TRUE when tasks has been registered from signals.  Next round in
       scheduler will call the callbacks when this is TRUE.

*/
struct SilcScheduleStruct {
  SilcTaskQueue fd_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;
  SilcScheduleFd fd_list;
  SilcUInt32 max_fd;
  SilcUInt32 last_fd;
  struct timeval *timeout;
  bool valid;
  void *internal;
  SILC_MUTEX_DEFINE(lock);
  bool is_locked;
  bool signal_tasks;
};

/* Initializes the scheduler. This returns the scheduler context that
   is given as arugment usually to all silc_schedule_* functions.
   The `max_tasks' indicates the number of maximum tasks that the
   scheduler can handle. */

SilcSchedule silc_schedule_init(int max_tasks)
{
  SilcSchedule schedule;

  SILC_LOG_DEBUG(("Initializing scheduler"));

  schedule = silc_calloc(1, sizeof(*schedule));

  /* Allocate three task queues, one for file descriptor based tasks,
     one for timeout tasks and one for generic tasks. */
  silc_task_queue_alloc(&schedule->fd_queue);
  silc_task_queue_alloc(&schedule->timeout_queue);
  silc_task_queue_alloc(&schedule->generic_queue);

  if (!max_tasks)
    max_tasks = 200;

  /* Initialize the scheduler */
  schedule->fd_list = silc_calloc(max_tasks, sizeof(*schedule->fd_list));
  schedule->max_fd = max_tasks;
  schedule->timeout = NULL;
  schedule->valid = TRUE;

  /* Allocate scheduler lock */
  silc_mutex_alloc(&schedule->lock);

  /* Initialize the platform specific scheduler. */
  schedule->internal = silc_schedule_internal_init(schedule);

  return schedule;
}

/* Uninitializes the schedule. This is called when the program is ready
   to end. This removes all tasks and task queues. Returns FALSE if the
   scheduler could not be uninitialized. This happens when the scheduler
   is still valid and silc_schedule_stop has not been called. */

bool silc_schedule_uninit(SilcSchedule schedule)
{
  SILC_LOG_DEBUG(("Uninitializing scheduler"));

  if (schedule->valid == TRUE)
    return FALSE;

  /* Unregister all tasks */
  silc_schedule_task_remove(schedule->fd_queue, SILC_ALL_TASKS);
  silc_schedule_task_remove(schedule->timeout_queue, SILC_ALL_TASKS);
  silc_schedule_task_remove(schedule->generic_queue, SILC_ALL_TASKS);

  /* Unregister all task queues */
  silc_task_queue_free(schedule->fd_queue);
  silc_task_queue_free(schedule->timeout_queue);
  silc_task_queue_free(schedule->generic_queue);

  silc_free(schedule->fd_list);

  /* Uninit the platform specific scheduler. */
  silc_schedule_internal_uninit(schedule->internal);

  silc_mutex_free(schedule->lock);
  silc_free(schedule);

  return TRUE;
}

/* Enlarge the capabilities of the scheduler to handle tasks to `max_tasks'. */

bool silc_schedule_reinit(SilcSchedule schedule, int max_tasks)
{
  SILC_SCHEDULE_LOCK(schedule);
  if (schedule->max_fd <= max_tasks)
    return FALSE;
  schedule->fd_list = silc_realloc(schedule->fd_list, 
				   (sizeof(*schedule->fd_list) * max_tasks));
  schedule->max_fd = max_tasks;
  SILC_SCHEDULE_UNLOCK(schedule);
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

/* Executes nontimeout tasks. It then checks whether any of ther fd tasks
   was signaled by the silc_select. If some task was not signaled then
   all generic tasks are executed for that task. The generic tasks are
   never executed for task that has explicit fd task set. */
/* This holds the schedule->lock and the queue locks. */

static void silc_schedule_dispatch_nontimeout(SilcSchedule schedule)
{
  SilcTask task;
  int i, last_fd = schedule->last_fd;
  SilcUInt32 fd;

  for (i = 0; i <= last_fd; i++) {
    if (schedule->fd_list[i].events == 0)
      continue;

    fd = schedule->fd_list[i].fd;

    /* First check whether this fd has task in the fd queue */
    silc_mutex_lock(schedule->fd_queue->lock);
    task = silc_task_find(schedule->fd_queue, fd);

    /* If the task was found then execute its callbacks. If not then
       execute all generic tasks for that fd. */
    if (task) {
      /* Validity of the task is checked always before and after
	 execution beacuse the task might have been unregistered
	 in the callback function, ie. it is not valid anymore. */

      /* Is the task ready for reading */
      if (task->valid && schedule->fd_list[i].revents & SILC_TASK_READ) {
	silc_mutex_unlock(schedule->fd_queue->lock);
	SILC_SCHEDULE_UNLOCK(schedule);
	task->callback(schedule, SILC_TASK_READ, task->fd, task->context);
	SILC_SCHEDULE_LOCK(schedule);
	silc_mutex_lock(schedule->fd_queue->lock);
      }

      /* Is the task ready for writing */
      if (task->valid && schedule->fd_list[i].revents & SILC_TASK_WRITE) {
	silc_mutex_unlock(schedule->fd_queue->lock);
	SILC_SCHEDULE_UNLOCK(schedule);
	task->callback(schedule, SILC_TASK_WRITE, task->fd, task->context);
	SILC_SCHEDULE_LOCK(schedule);
	silc_mutex_lock(schedule->fd_queue->lock);
      }

      if (!task->valid)
	silc_schedule_task_remove(schedule->fd_queue, task);

      silc_mutex_unlock(schedule->fd_queue->lock);
    } else {
      /* Run generic tasks for this fd. */

      silc_mutex_unlock(schedule->fd_queue->lock);

      silc_mutex_lock(schedule->generic_queue->lock);
      if (!schedule->generic_queue->task) {
	silc_mutex_unlock(schedule->generic_queue->lock);
	continue;
      }

      task = schedule->generic_queue->task;
      while(1) {
	/* Validity of the task is checked always before and after
	   execution beacuse the task might have been unregistered
	   in the callback function, ie. it is not valid anymore. */

	/* Is the task ready for reading */				
	if (task->valid && schedule->fd_list[i].revents & SILC_TASK_READ) {
	  silc_mutex_unlock(schedule->generic_queue->lock);
	  SILC_SCHEDULE_UNLOCK(schedule);
	  task->callback(schedule, SILC_TASK_READ, fd, task->context);
	  SILC_SCHEDULE_LOCK(schedule);
	  silc_mutex_lock(schedule->generic_queue->lock);
	}

	/* Is the task ready for writing */				
	if (task->valid && schedule->fd_list[i].revents & SILC_TASK_WRITE) {
	  silc_mutex_unlock(schedule->generic_queue->lock);
	  SILC_SCHEDULE_UNLOCK(schedule);
	  task->callback(schedule, SILC_TASK_WRITE, fd, task->context);
	  SILC_SCHEDULE_LOCK(schedule);
	  silc_mutex_lock(schedule->generic_queue->lock);
	}

	if (!task->valid) {
	  /* Invalid (unregistered) tasks are removed from the
	     task queue. */
	  if (schedule->generic_queue->task == task->next) {
	    silc_schedule_task_remove(schedule->generic_queue, task);
	    silc_mutex_unlock(schedule->generic_queue->lock);
	    break;
	  }

	  task = task->next;
	  silc_schedule_task_remove(schedule->generic_queue, task);
	  continue;
	}

	/* Break if there isn't more tasks in the queue */
	if (schedule->generic_queue->task == task->next)
	  break;

	task = task->next;
      }			

      silc_mutex_unlock(schedule->generic_queue->lock);
    }
  }
}

/* Executes all tasks whose timeout has expired. The task is removed from
   the task queue after the callback function has returned. Also, invalid
   tasks are removed here. We don't have to care about priorities because 
   tasks are already sorted in their priority order at the registration 
   phase. */
/* This holds the schedule->lock and the schedule->timeout_queue->lock */

static void silc_schedule_dispatch_timeout(SilcSchedule schedule)
{
  SilcTaskQueue queue = schedule->timeout_queue;
  SilcTask task;
  struct timeval curtime;

  SILC_LOG_DEBUG(("Running timeout tasks"));

  silc_gettimeofday(&curtime);

  queue = schedule->timeout_queue;
  if (queue && queue->task) {
    task = queue->task;

    /* Walk thorugh all tasks in the particular task queue and run all 
       the expired tasks. */
    while(1) {
      /* Execute the task if the timeout has expired */
      if (silc_schedule_task_timeout_compare(&task->timeout, &curtime)) {
        if (task->valid) {
	  silc_mutex_unlock(queue->lock);
	  SILC_SCHEDULE_UNLOCK(schedule);
	  task->callback(schedule, SILC_TASK_EXPIRE, task->fd, task->context);
	  SILC_SCHEDULE_LOCK(schedule);
	  silc_mutex_lock(queue->lock);
	}

        /* Break if there isn't more tasks in the queue */
	if (queue->task == task->next) {
	  silc_schedule_task_remove(queue, task);
	  break;
        }

        task = task->next;

        /* Remove the task from queue */
        silc_schedule_task_remove(queue, task->prev);
      } else {
        /* The timeout hasn't expired, check for next one */

        /* Break if there isn't more tasks in the queue */
        if (queue->task == task->next)
          break;

        task = task->next;
      }
    }
  }
}

/* Calculates next timeout for select(). This is the timeout value
   when at earliest some of the timeout tasks expire. If this is in the
   past, they will be run now. */
/* This holds the schedule->lock and the schedule->timeout_queue->lock */

static void silc_schedule_select_timeout(SilcSchedule schedule)
{
  SilcTaskQueue queue = schedule->timeout_queue;
  SilcTask task;
  struct timeval curtime;

  /* Get the current time */
  silc_gettimeofday(&curtime);
  schedule->timeout = NULL;

  /* First task in the task queue has always the smallest timeout. */
  task = queue->task;
  while(1) {
    if (task && task->valid == TRUE) {
      /* If the timeout is in past, we will run the task and all other
	 timeout tasks from the past. */
      if (silc_schedule_task_timeout_compare(&task->timeout, &curtime)) {
	silc_schedule_dispatch_timeout(schedule);
						
	/* The task(s) has expired and doesn't exist on the task queue
	   anymore. We continue with new timeout. */
	queue = schedule->timeout_queue;
	task = queue->task;
	if (task == NULL || task->valid == FALSE)
	  break;
      }

      /* Calculate the next timeout for select() */
      queue->timeout.tv_sec = task->timeout.tv_sec - curtime.tv_sec;
      queue->timeout.tv_usec = task->timeout.tv_usec - curtime.tv_usec;
      if (queue->timeout.tv_sec < 0)
	queue->timeout.tv_sec = 0;

      /* We wouldn't want to go under zero, check for it. */
      if (queue->timeout.tv_usec < 0) {
	queue->timeout.tv_sec -= 1;
	if (queue->timeout.tv_sec < 0)
	  queue->timeout.tv_sec = 0;
	queue->timeout.tv_usec += 1000000L;
      }

      /* We've got the timeout value */
      break;
    } else {
      /* Task is not valid, remove it and try next one. */
      silc_schedule_task_remove(queue, task);
      task = queue->task;
      if (queue->task == NULL)
	break;
    }
  }

  /* Save the timeout */
  if (task) {
    schedule->timeout = &queue->timeout;
    SILC_LOG_DEBUG(("timeout: sec=%d, usec=%d", schedule->timeout->tv_sec,
		    schedule->timeout->tv_usec));
  }
}

/* Runs the scheduler once and then returns. */

bool silc_schedule_one(SilcSchedule schedule, int timeout_usecs)
{
  struct timeval timeout;
  int ret;

  SILC_LOG_DEBUG(("In scheduler loop"));

  if (!schedule->is_locked)
    SILC_SCHEDULE_LOCK(schedule);

  /* Deliver signals if any has been set to be called */
  if (schedule->signal_tasks) {
    SILC_SCHEDULE_UNLOCK(schedule);
    silc_schedule_internal_signals_call(schedule->internal, schedule);
    schedule->signal_tasks = FALSE;
    SILC_SCHEDULE_LOCK(schedule);
  }

  /* If the task queues aren't initialized or we aren't valid anymore
     we will return */
  if ((!schedule->fd_queue && !schedule->timeout_queue 
       && !schedule->generic_queue) || schedule->valid == FALSE) {
    SILC_LOG_DEBUG(("Scheduler not valid anymore, exiting"));
    if (!schedule->is_locked)
      SILC_SCHEDULE_UNLOCK(schedule);
    return FALSE;
  }

  /* Calculate next timeout for silc_select(). This is the timeout value
     when at earliest some of the timeout tasks expire. */
  silc_mutex_lock(schedule->timeout_queue->lock);
  silc_schedule_select_timeout(schedule);
  silc_mutex_unlock(schedule->timeout_queue->lock);

  if (timeout_usecs >= 0) {
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_usecs;
    schedule->timeout = &timeout;
  }

  SILC_SCHEDULE_UNLOCK(schedule);

  /* This is the main select(). The program blocks here until some
     of the selected file descriptors change status or the selected
     timeout expires. */
  SILC_LOG_DEBUG(("Select"));
  ret = silc_select(schedule->fd_list, schedule->last_fd + 1, 
		    schedule->timeout);

  SILC_SCHEDULE_LOCK(schedule);

  switch (ret) {
  case -1:
    /* Error */
    if (errno == EINTR)
      break;
    SILC_LOG_ERROR(("Error in select(): %s", strerror(errno)));
    break;
  case 0:
    /* Timeout */
    silc_mutex_lock(schedule->timeout_queue->lock);
    silc_schedule_dispatch_timeout(schedule);
    silc_mutex_unlock(schedule->timeout_queue->lock);
    break;
  default:
    /* There is some data available now */
    SILC_LOG_DEBUG(("Running non-timeout tasks"));
    silc_schedule_dispatch_nontimeout(schedule);
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
  silc_schedule_internal_wakeup(schedule->internal);
  SILC_SCHEDULE_UNLOCK(schedule);
#endif
}

/* Add new task to the scheduler */

SilcTask silc_schedule_task_add(SilcSchedule schedule, SilcUInt32 fd,
				SilcTaskCallback callback, void *context, 
				long seconds, long useconds, 
				SilcTaskType type, 
				SilcTaskPriority priority)
{
  SilcTask newtask;
  SilcTaskQueue queue;
  int timeout = FALSE;

  SILC_LOG_DEBUG(("Registering new task, fd=%d type=%d priority=%d", fd, 
		  type, priority));

  queue = SILC_SCHEDULE_GET_QUEUE(type);
    
  /* If the task is generic task, we check whether this task has already
     been registered. Generic tasks are registered only once and after that
     the same task applies to all file descriptors to be registered. */
  if (type == SILC_TASK_GENERIC) {
    silc_mutex_lock(queue->lock);

    if (queue->task) {
      SilcTask task = queue->task;
      while(1) {
	if ((task->callback == callback) && (task->context == context)) {
	  SILC_LOG_DEBUG(("Found matching generic task, using the match"));
	  
	  silc_mutex_unlock(queue->lock);

	  /* Add the fd to be listened, the task found now applies to this
	     fd as well. */
	  silc_schedule_set_listen_fd(schedule, fd, SILC_TASK_READ);
	  return task;
	}
	
	if (queue->task == task->next)
	  break;
	
	task = task->next;
      }
    }

    silc_mutex_unlock(queue->lock);
  }

  newtask = silc_calloc(1, sizeof(*newtask));
  newtask->fd = fd;
  newtask->context = context;
  newtask->callback = callback;
  newtask->valid = TRUE;
  newtask->priority = priority;
  newtask->type = type;
  newtask->next = newtask;
  newtask->prev = newtask;

  /* Create timeout if marked to be timeout task */
  if (((seconds + useconds) > 0) && (type == SILC_TASK_TIMEOUT)) {
    silc_gettimeofday(&newtask->timeout);
    newtask->timeout.tv_sec += seconds + (useconds / 1000000L);
    newtask->timeout.tv_usec += (useconds % 1000000L);
    if (newtask->timeout.tv_usec > 999999L) {
      newtask->timeout.tv_sec += 1;
      newtask->timeout.tv_usec -= 1000000L;
    }
    timeout = TRUE;
  }

  /* If the task is non-timeout task we have to tell the scheduler that we
     would like to have these tasks scheduled at some odd distant future. */
  if (type != SILC_TASK_TIMEOUT)
    silc_schedule_set_listen_fd(schedule, fd, SILC_TASK_READ);

  silc_mutex_lock(queue->lock);

  /* Is this first task of the queue? */
  if (queue->task == NULL) {
    queue->task = newtask;
    silc_mutex_unlock(queue->lock);
    return newtask;
  }

  if (timeout)
    newtask = silc_task_add_timeout(queue, newtask, priority);
  else
    newtask = silc_task_add(queue, newtask, priority);

  silc_mutex_unlock(queue->lock);

  return newtask;
}

/* Removes a task from the scheduler */

void silc_schedule_task_del(SilcSchedule schedule, SilcTask task)
{
  SilcTaskQueue queue = SILC_SCHEDULE_GET_QUEUE(task->type);

  /* Unregister all tasks */
  if (task == SILC_ALL_TASKS) {
    SilcTask next;
    SILC_LOG_DEBUG(("Unregistering all tasks at once"));

    silc_mutex_lock(queue->lock);

    if (!queue->task) {
      silc_mutex_unlock(queue->lock);
      return;
    }

    next = queue->task;
    
    while(1) {
      if (next->valid)
	next->valid = FALSE;
      if (queue->task == next->next)
	break;
      next = next->next;
    }

    silc_mutex_unlock(queue->lock);
    return;
  }

  SILC_LOG_DEBUG(("Unregistering task"));

  silc_mutex_lock(queue->lock);

  /* Unregister the specific task */
  if (task->valid)
    task->valid = FALSE;

  silc_mutex_unlock(queue->lock);
}

/* Remove task by fd */

void silc_schedule_task_del_by_fd(SilcSchedule schedule, SilcUInt32 fd)
{
  SILC_LOG_DEBUG(("Unregister task by fd %d", fd));

  silc_task_del_by_fd(schedule->timeout_queue, fd);
  silc_task_del_by_fd(schedule->fd_queue, fd);
}

/* Remove task by task callback. */

void silc_schedule_task_del_by_callback(SilcSchedule schedule,
					SilcTaskCallback callback)
{
  SILC_LOG_DEBUG(("Unregister task by callback"));

  silc_task_del_by_callback(schedule->timeout_queue, callback);
  silc_task_del_by_callback(schedule->fd_queue, callback);
  silc_task_del_by_callback(schedule->generic_queue, callback);
}

/* Remove task by context. */

void silc_schedule_task_del_by_context(SilcSchedule schedule, void *context)
{
  SILC_LOG_DEBUG(("Unregister task by context"));

  silc_task_del_by_context(schedule->timeout_queue, context);
  silc_task_del_by_context(schedule->fd_queue, context);
  silc_task_del_by_context(schedule->generic_queue, context);
}

/* Sets a file descriptor to be listened by select() in scheduler. One can
   call this directly if wanted. This can be called multiple times for
   one file descriptor to set different iomasks. */

void silc_schedule_set_listen_fd(SilcSchedule schedule,
				 SilcUInt32 fd, SilcTaskEvent iomask)
{
  int i;
  bool found = FALSE;

  SILC_SCHEDULE_LOCK(schedule);

  for (i = 0; i < schedule->max_fd; i++)
    if (schedule->fd_list[i].fd == fd) {
      schedule->fd_list[i].fd = fd;
      schedule->fd_list[i].events = iomask;
      if (i > schedule->last_fd)
	schedule->last_fd = i;
      found = TRUE;
      break;
    }

  if (!found)
    for (i = 0; i < schedule->max_fd; i++)
      if (schedule->fd_list[i].events == 0) {
	schedule->fd_list[i].fd = fd;
	schedule->fd_list[i].events = iomask;
	if (i > schedule->last_fd)
	  schedule->last_fd = i;
	break;
      }

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Removes a file descriptor from listen list. */

void silc_schedule_unset_listen_fd(SilcSchedule schedule, SilcUInt32 fd)
{
  int i;

  SILC_SCHEDULE_LOCK(schedule);

  SILC_LOG_DEBUG(("Unset listen fd %d", fd));

  for (i = 0; i < schedule->max_fd; i++)
    if (schedule->fd_list[i].fd == fd) {
      schedule->fd_list[i].fd = 0;
      schedule->fd_list[i].events = 0;
      if (schedule->last_fd == i)
	schedule->last_fd = schedule->max_fd - 1;
      break;
    }

  SILC_SCHEDULE_UNLOCK(schedule);
}

/* Register a new signal */

void silc_schedule_signal_register(SilcSchedule schedule, SilcUInt32 signal,
				   SilcTaskCallback callback, void *context)
{
  silc_schedule_internal_signal_register(schedule->internal, signal,
					 callback, context);
}

/* Unregister a new signal */

void silc_schedule_signal_unregister(SilcSchedule schedule, SilcUInt32 signal,
				     SilcTaskCallback callback, void *context)
{
  silc_schedule_internal_signal_unregister(schedule->internal, signal,
					   callback, context);
}

/* Call signal indicated by `signal'. */

void silc_schedule_signal_call(SilcSchedule schedule, SilcUInt32 signal)
{
  /* Mark that signals needs to be delivered later. */
  silc_schedule_internal_signal_call(schedule->internal, signal);
  schedule->signal_tasks = TRUE;
}

/* Allocates a newtask task queue into the scheduler */

static void silc_task_queue_alloc(SilcTaskQueue *queue)
{
  *queue = silc_calloc(1, sizeof(**queue));
  silc_mutex_alloc(&(*queue)->lock);
}

/* Free's a task queue. */

static void silc_task_queue_free(SilcTaskQueue queue)
{
  silc_mutex_free(queue->lock);
  memset(queue, 'F', sizeof(*queue));
  silc_free(queue);
}

/* Return task by its fd. */

static SilcTask silc_task_find(SilcTaskQueue queue, SilcUInt32 fd)
{
  SilcTask next;

  if (!queue->task)
    return NULL;

  next = queue->task;

  while (1) {
    if (next->fd == fd)
      return next;
    if (queue->task == next->next)
      return NULL;
    next = next->next;
  }

  return NULL;
}

/* Adds a non-timeout task into the task queue. This function is used
   by silc_task_register function. Returns a pointer to the registered 
   task. */

static SilcTask silc_task_add(SilcTaskQueue queue, SilcTask newtask, 
			      SilcTaskPriority priority)
{
  SilcTask task, next, prev;

  /* Take the first task in the queue */
  task = queue->task;

  switch(priority) {
  case SILC_TASK_PRI_LOW:
    /* Lowest priority. The task is added at the end of the list. */
    prev = task->prev;
    newtask->prev = prev;
    newtask->next = task;
    prev->next = newtask;
    task->prev = newtask;
    break;
  case SILC_TASK_PRI_NORMAL:
    /* Normal priority. The task is added before lower priority tasks
       but after tasks with higher priority. */
    prev = task->prev;
    while(prev != task) {
      if (prev->priority > SILC_TASK_PRI_LOW)
	break;
      prev = prev->prev;
    }
    if (prev == task) {
      /* There are only lower priorities in the list, we will
	 sit before them and become the first task in the queue. */
      prev = task->prev;
      newtask->prev = prev;
      newtask->next = task;
      task->prev = newtask;
      prev->next = newtask;

      /* We are now the first task in queue */
      queue->task = newtask;
    } else {
      /* Found a spot from the list, add the task to the list. */
      next = prev->next;
      newtask->prev = prev;
      newtask->next = next;
      prev->next = newtask;
      next->prev = newtask;
    }
    break;
  default:
    silc_free(newtask);
    return NULL;
  }

  return newtask;
}

/* Return the timeout task with smallest timeout. */

static SilcTask silc_task_get_first(SilcTaskQueue queue, SilcTask first)
{
  SilcTask prev, task;

  prev = first->prev;

  if (first == prev)
    return first;

  task = first;
  while (1) {
    if (first == prev)
      break;

    if (silc_schedule_task_timeout_compare(&prev->timeout, &task->timeout))
      task = prev;

    prev = prev->prev;
  }

  return task;
}

/* Adds a timeout task into the task queue. This function is used by
   silc_task_register function. Returns a pointer to the registered 
   task. Timeout tasks are sorted by their timeout value in ascending
   order. The priority matters if there are more than one task with
   same timeout. */

static SilcTask silc_task_add_timeout(SilcTaskQueue queue, SilcTask newtask,
				      SilcTaskPriority priority)
{
  SilcTask task, prev, next;

  /* Take the first task in the queue */
  task = queue->task;

  /* Take last task from the list */
  prev = task->prev;
    
  switch(priority) {
  case SILC_TASK_PRI_LOW:
    /* Lowest priority. The task is added at the end of the list. */
    while(prev != task) {

      /* If we have longer timeout than with the task head of us
	 we have found our spot. */
      if (silc_schedule_task_timeout_compare(&prev->timeout, 
					     &newtask->timeout))
	break;

      /* If we are equal size of timeout we will be after it. */
      if (!silc_schedule_task_timeout_compare(&newtask->timeout, 
					      &prev->timeout))
	break;

      /* We have shorter timeout, compare to next one. */
      prev = prev->prev;
    }
    /* Found a spot from the list, add the task to the list. */
    next = prev->next;
    newtask->prev = prev;
    newtask->next = next;
    prev->next = newtask;
    next->prev = newtask;
    
    if (prev == task) {
      /* Check if we are going to be the first task in the queue */
      if (silc_schedule_task_timeout_compare(&prev->timeout, 
					     &newtask->timeout))
	break;
      if (!silc_schedule_task_timeout_compare(&newtask->timeout, 
					      &prev->timeout))
	break;

      /* We are now the first task in queue */
      queue->task = newtask;
    }
    break;
  case SILC_TASK_PRI_NORMAL:
    /* Normal priority. The task is added before lower priority tasks
       but after tasks with higher priority. */
    while(prev != task) {

      /* If we have longer timeout than with the task head of us
	 we have found our spot. */
      if (silc_schedule_task_timeout_compare(&prev->timeout, 
					     &newtask->timeout))
	break;

      /* If we are equal size of timeout, priority kicks in place. */
      if (!silc_schedule_task_timeout_compare(&newtask->timeout, 
					      &prev->timeout))
	if (prev->priority >= SILC_TASK_PRI_NORMAL)
	  break;

      /* We have shorter timeout or higher priority, compare to next one. */
      prev = prev->prev;
    }
    /* Found a spot from the list, add the task to the list. */
    next = prev->next;
    newtask->prev = prev;
    newtask->next = next;
    prev->next = newtask;
    next->prev = newtask;
    
    if (prev == task) {
      /* Check if we are going to be the first task in the queue */
      if (silc_schedule_task_timeout_compare(&prev->timeout, 
					     &newtask->timeout))
	break;
      if (!silc_schedule_task_timeout_compare(&newtask->timeout, 
					      &prev->timeout))
	if (prev->priority >= SILC_TASK_PRI_NORMAL)
	  break;

      /* We are now the first task in queue */
      queue->task = newtask;
    }
    break;
  default:
    silc_free(newtask);
    return NULL;
  }

  return newtask;
}

/* Removes (unregisters) a task from particular task queue. This function
   is used internally by scheduler. This must be called holding the 
   queue->lock. */

static int silc_schedule_task_remove(SilcTaskQueue queue, SilcTask task)
{
  SilcTask first, old, next;

  if (!queue || !task)
    return FALSE;

  if (!queue->task) {
    return FALSE;
  }

  first = queue->task;

  /* Unregister all tasks in queue */
  if (task == SILC_ALL_TASKS) {
    SILC_LOG_DEBUG(("Removing all tasks at once"));
    next = first;

    while(1) {
      old = next->next;
      silc_free(next);
      if (old == first)
	break;
      next = old;
    }

    queue->task = NULL;
    return TRUE;
  }

  SILC_LOG_DEBUG(("Removing task"));

  /* Unregister the task */
  old = first;
  while(1) {
    if (old == task) {
      SilcTask prev, next;

      prev = old->prev;
      next = old->next;
      prev->next = next;
      next->prev = prev;

      if (prev == old && next == old)
	queue->task = NULL;
      if (queue->task == old)
	queue->task = silc_task_get_first(queue, next);
      
      silc_free(old);
      return TRUE;
    }
    old = old->prev;

    if (old == first) {
      return FALSE;
    }
  }
}

/* Compare two time values. If the first argument is smaller than the
   second this function returns TRUE. */

static int silc_schedule_task_timeout_compare(struct timeval *smaller, 
					      struct timeval *bigger)
{
  if ((smaller->tv_sec < bigger->tv_sec) ||
      ((smaller->tv_sec == bigger->tv_sec) &&
       (smaller->tv_usec < bigger->tv_usec)))
    return TRUE;

  return FALSE;
}

static void silc_task_del_by_fd(SilcTaskQueue queue, SilcUInt32 fd)
{
  SilcTask next;

  silc_mutex_lock(queue->lock);

  if (!queue->task) {
    silc_mutex_unlock(queue->lock);
    return;
  }

  next = queue->task;

  while(1) {
    if (next->fd == fd)
      next->valid = FALSE;
    if (queue->task == next->next)
      break;
    next = next->next;
  }

  silc_mutex_unlock(queue->lock);
}

static void silc_task_del_by_callback(SilcTaskQueue queue,
				      SilcTaskCallback callback)
{
  SilcTask next;

  silc_mutex_lock(queue->lock);

  if (!queue->task) {
    silc_mutex_unlock(queue->lock);
    return;
  }

  next = queue->task;

  while(1) {
    if (next->callback == callback)
      next->valid = FALSE;
    if (queue->task == next->next)
      break;
    next = next->next;
  }

  silc_mutex_unlock(queue->lock);
}

static void silc_task_del_by_context(SilcTaskQueue queue, void *context)
{
  SilcTask next;

  silc_mutex_lock(queue->lock);

  if (!queue->task) {
    silc_mutex_unlock(queue->lock);
    return;
  }

  next = queue->task;

  while(1) {
    if (next->context == context)
      next->valid = FALSE;
    if (queue->task == next->next)
      break;
    next = next->next;
  }

  silc_mutex_unlock(queue->lock);
}
