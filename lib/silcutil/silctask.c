/*

  silctask.c

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

/* Allocates a new task queue into the Silc. If 'valid' is TRUE the
   queue becomes valid task queue. If it is FALSE scheduler will skip
   the queue. */

void silc_task_queue_alloc(SilcSchedule schedule, SilcTaskQueue *new, 
			   bool valid)
{
  SILC_LOG_DEBUG(("Allocating new task queue"));

  *new = silc_calloc(1, sizeof(**new));

  /* Set the pointers */
  (*new)->schedule = schedule;
  (*new)->valid = valid;
  silc_mutex_alloc(&(*new)->lock);
}

/* Free's a task queue. */

void silc_task_queue_free(SilcTaskQueue queue)
{
  silc_mutex_lock(queue->lock);
  queue->valid = FALSE;
  silc_mutex_unlock(queue->lock);
  silc_mutex_free(queue->lock);
  silc_free(queue);
}

/* Wakes up the task queue. This actually wakes up the scheduler of this
   task queue. This is called in multi-threaded environment to wake up
   the scheduler after adding or removing tasks from the task queue. */

void silc_task_queue_wakeup(SilcTaskQueue queue)
{
  silc_schedule_wakeup(queue->schedule);
}

/* Adds a non-timeout task into the task queue. This function is used
   by silc_task_register function. Returns a pointer to the registered 
   task. */

SilcTask silc_task_add(SilcTaskQueue queue, SilcTask new, 
		       SilcTaskPriority priority)
{
  SilcTask task, next, prev;

  /* Take the first task in the queue */
  task = queue->task;

  switch(priority) {
  case SILC_TASK_PRI_LOW:
    /* Lowest priority. The task is added at the end of the list. */
    prev = task->prev;
    new->prev = prev;
    new->next = task;
    prev->next = new;
    task->prev = new;
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
      new->prev = prev;
      new->next = task;
      task->prev = new;
      prev->next = new;

      /* We are now the first task in queue */
      queue->task = new;
    } else {
      /* Found a spot from the list, add the task to the list. */
      next = prev->next;
      new->prev = prev;
      new->next = next;
      prev->next = new;
      next->prev = new;
    }
    break;
  default:
    silc_free(new);
    return NULL;
  }

  return new;
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

    if (silc_task_timeout_compare(&prev->timeout, &task->timeout))
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

SilcTask silc_task_add_timeout(SilcTaskQueue queue, SilcTask new,
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
      if (silc_task_timeout_compare(&prev->timeout, &new->timeout))
	break;

      /* If we are equal size of timeout we will be after it. */
      if (!silc_task_timeout_compare(&new->timeout, &prev->timeout))
	break;

      /* We have shorter timeout, compare to next one. */
      prev = prev->prev;
    }
    /* Found a spot from the list, add the task to the list. */
    next = prev->next;
    new->prev = prev;
    new->next = next;
    prev->next = new;
    next->prev = new;
    
    if (prev == task) {
      /* Check if we are going to be the first task in the queue */
      if (silc_task_timeout_compare(&prev->timeout, &new->timeout))
	break;
      if (!silc_task_timeout_compare(&new->timeout, &prev->timeout))
	break;

      /* We are now the first task in queue */
      queue->task = new;
    }
    break;
  case SILC_TASK_PRI_NORMAL:
    /* Normal priority. The task is added before lower priority tasks
       but after tasks with higher priority. */
    while(prev != task) {

      /* If we have longer timeout than with the task head of us
	 we have found our spot. */
      if (silc_task_timeout_compare(&prev->timeout, &new->timeout))
	break;

      /* If we are equal size of timeout, priority kicks in place. */
      if (!silc_task_timeout_compare(&new->timeout, &prev->timeout))
	if (prev->priority >= SILC_TASK_PRI_NORMAL)
	  break;

      /* We have shorter timeout or higher priority, compare to next one. */
      prev = prev->prev;
    }
    /* Found a spot from the list, add the task to the list. */
    next = prev->next;
    new->prev = prev;
    new->next = next;
    prev->next = new;
    next->prev = new;
    
    if (prev == task) {
      /* Check if we are going to be the first task in the queue */
      if (silc_task_timeout_compare(&prev->timeout, &new->timeout))
	break;
      if (!silc_task_timeout_compare(&new->timeout, &prev->timeout))
	if (prev->priority >= SILC_TASK_PRI_NORMAL)
	  break;

      /* We are now the first task in queue */
      queue->task = new;
    }
    break;
  default:
    silc_free(new);
    return NULL;
  }

  return new;
}

/* Registers a new task to the task queue. Arguments are as follows:
      
   SilcTaskQueue queue        Queue where the task is to be registered
   int fd                     File descriptor
   SilcTaskCallback cb        Callback function to call
   void *context              Context to be passed to callback function
   long seconds               Seconds to timeout
   long useconds              Microseconds to timeout
   SilcTaskType type          Type of the task
   SilcTaskPriority priority  Priority of the task
   
   The same function is used to register all types of tasks. The type
   argument tells what type of the task is. Note that when registering
   non-timeout tasks one should also pass 0 as timeout as timeout will
   be ignored anyway. Also, note, that one cannot register timeout task
   with 0 timeout. There cannot be zero timeouts, passing zero means
   no timeout is used for the task and SILC_TASK_FD_TASK is used as
   default task type in this case.
   
   One should be careful not to register timeout tasks to the non-timeout
   task queue, because they will never expire. As one should not register
   non-timeout tasks to timeout task queue because they will never get
   scheduled.
   
   There is a one distinct difference between timeout and non-timeout
   tasks when they are executed. Non-timeout tasks remain on the task
   queue after execution. Timeout tasks, however, are removed from the
   task queue after they have expired. It is safe to re-register a task 
   in its own callback function. It is also safe to unregister a task 
   in a callback function.
   
   Generic tasks apply to all file descriptors, however, one still must
   pass the correct file descriptor to the function when registering
   generic tasks. */

SilcTask silc_task_register(SilcTaskQueue queue, int fd, 
			    SilcTaskCallback cb, void *context, 
			    long seconds, long useconds, 
			    SilcTaskType type, SilcTaskPriority priority)
{
  SilcTask new;
  int timeout = FALSE;

  SILC_LOG_DEBUG(("Registering new task, fd=%d type=%d priority=%d", 
		  fd, type, priority));

  /* If the task is generic task, we check whether this task has already
     been registered. Generic tasks are registered only once and after that
     the same task applies to all file descriptors to be registered. */
  if (type == SILC_TASK_GENERIC) {
    silc_mutex_lock(queue->lock);

    if (queue->task) {
      SilcTask task = queue->task;
      while(1) {
	if ((task->callback == cb) && (task->context == context)) {
	  SILC_LOG_DEBUG(("Found matching generic task, using the match"));
	  
	  silc_mutex_unlock(queue->lock);

	  /* Add the fd to be listened, the task found now applies to this
	     fd as well. */
	  silc_schedule_set_listen_fd(queue->schedule, 
				      fd, (1L << SILC_TASK_READ));
	  return task;
	}
	
	if (queue->task == task->next)
	  break;
	
	task = task->next;
      }
    }

    silc_mutex_unlock(queue->lock);
  }

  new = silc_calloc(1, sizeof(*new));
  new->fd = fd;
  new->context = context;
  new->callback = cb;
  new->valid = TRUE;
  new->priority = priority;
  new->iomask = (1L << SILC_TASK_READ);
  new->next = new;
  new->prev = new;

  /* Create timeout if marked to be timeout task */
  if (((seconds + useconds) > 0) && (type == SILC_TASK_TIMEOUT)) {
    silc_gettimeofday(&new->timeout);
    new->timeout.tv_sec += seconds + (useconds / 1000000L);
    new->timeout.tv_usec += (useconds % 1000000L);
    if (new->timeout.tv_usec > 999999L) {
      new->timeout.tv_sec += 1;
      new->timeout.tv_usec -= 1000000L;
    }
    timeout = TRUE;
  }

  /* If the task is non-timeout task we have to tell the scheduler that we
     would like to have these tasks scheduled at some odd distant future. */
  if (type != SILC_TASK_TIMEOUT)
    silc_schedule_set_listen_fd(queue->schedule, fd, (1L << SILC_TASK_READ));

  silc_mutex_lock(queue->lock);

  /* Is this first task of the queue? */
  if (queue->task == NULL) {
    queue->task = new;
    silc_mutex_unlock(queue->lock);
    return new;
  }

  if (timeout)
    new = silc_task_add_timeout(queue, new, priority);
  else
    new = silc_task_add(queue, new, priority);

  silc_mutex_unlock(queue->lock);

  return new;
}

/* Removes (unregisters) a task from particular task queue. This function
   is used internally by scheduler. This must be called holding the 
   queue->lock. */

int silc_task_remove(SilcTaskQueue queue, SilcTask task)
{
  SilcTask first, old, next;

  if (!queue)
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
      next = next->next;
      silc_free(next->prev);
      if (next == first)
	break;
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

/* Unregisters a task already in the queue. Arguments are as follows:
   
   SilcTaskQueue queue      Queue where from the task is unregistered
   SilcTask task            Task to be unregistered
   
   The same function is used to unregister timeout and non-timeout 
   tasks. One can also unregister all tasks from the queue by passing
   SILC_ALL_TASKS as task to the function. It is safe to unregister
   a task in a callback function. */

void silc_task_unregister(SilcTaskQueue queue, SilcTask task)
{

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

/* Unregister a task by file descriptor. This invalidates the task. */

void silc_task_unregister_by_fd(SilcTaskQueue queue, int fd)
{
  SilcTask next;

  SILC_LOG_DEBUG(("Unregister task by fd"));

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

/* Unregister a task by callback function. This invalidates the task. */

void silc_task_unregister_by_callback(SilcTaskQueue queue, 
				      SilcTaskCallback callback)
{
  SilcTask next;

  SILC_LOG_DEBUG(("Unregister task by callback"));

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

/* Unregister a task by context. This invalidates the task. */

void silc_task_unregister_by_context(SilcTaskQueue queue, void *context)
{
  SilcTask next;

  SILC_LOG_DEBUG(("Unregister task by context"));

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

/* Sets the I/O type of the task. The scheduler checks for this value
   and a task must always have at least one of the I/O types set at 
   all time. When registering new task the type is set by default to
   SILC_TASK_READ. If the task doesn't perform reading one must reset
   the value to SILC_TASK_WRITE.
   
   The type sent as argumenet is masked into the task. If the tasks 
   I/O mask already includes this type this function has no effect. 
   Only one I/O type can be added at once. If the task must perform
   both reading and writing one must call this function for value
   SILC_TASK_WRITE as well. */

void silc_task_set_iotype(SilcTask task, int type)
{
  task->iomask |= (1L << type);
}

/* Resets the mask to the type sent as argument. Note that this resets
   the previous values to zero and then adds the type sent as argument.
   This function can be used to remove one of the types masked earlier
   to the task. */

void silc_task_reset_iotype(SilcTask task, int type)
{
  task->iomask = (1L << type);
}

/* Compare two time values. If the first argument is smaller than the
   second this function returns TRUE. */

int silc_task_timeout_compare(struct timeval *smaller, 
			      struct timeval *bigger)
{
  if ((smaller->tv_sec < bigger->tv_sec) ||
      ((smaller->tv_sec == bigger->tv_sec) &&
       (smaller->tv_usec < bigger->tv_usec)))
    return TRUE;

  return FALSE;
}
