/*

  silctask.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1998 - 2000 Pekka Riikonen

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

void silc_task_queue_alloc(SilcTaskQueue *new, int valid)
{

  SILC_LOG_DEBUG(("Allocating new task queue"));

  *new = silc_calloc(1, sizeof(**new));

  /* Set the pointers */
  (*new)->valid = valid;
  (*new)->task = NULL;
  (*new)->register_task = silc_task_register;
  (*new)->unregister_task = silc_task_unregister;
  (*new)->set_iotype = silc_task_set_iotype;
  (*new)->reset_iotype = silc_task_reset_iotype;
}

/* Free's a task queue. */

void silc_task_queue_free(SilcTaskQueue old)
{
  if (old)
    silc_free(old);
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
      if (prev->priority > SILC_TASK_PRI_LOW &&
	  prev->priority <= SILC_TASK_PRI_REALTIME)
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
  case SILC_TASK_PRI_HIGH:
    /* High priority. The task is added before lower priority tasks
       but after tasks with higher priority. */
    prev = task->prev;
    while(prev != task) {
      if (prev->priority > SILC_TASK_PRI_NORMAL &&
	  prev->priority <= SILC_TASK_PRI_REALTIME)
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
  case SILC_TASK_PRI_REALTIME:
    /* Highest priority. The task is added at the head of the list. 
       The last registered task is added to the very head of the list
       thus we get the LIFO (Last-In-First-Out) order. */
    prev = task->prev;
    new->prev = prev;
    new->next = task;
    prev->next = new;
    task->prev = new;

    /* We are the first task in the queue */
    queue->task = new;
    break;
  default:
    silc_free(new);
    return NULL;
  }

  return new;
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
  case SILC_TASK_PRI_HIGH:
    /* High priority. The task is added before lower priority tasks
       but after tasks with higher priority. */
    while(prev != task) {

      /* If we have longer timeout than with the task head of us
	 we have found our spot. */
      if (silc_task_timeout_compare(&prev->timeout, &new->timeout))
	break;

      /* If we are equal size of timeout, priority kicks in place. */
      if (!silc_task_timeout_compare(&new->timeout, &prev->timeout))
	if (prev->priority >= SILC_TASK_PRI_HIGH)
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
	if (prev->priority >= SILC_TASK_PRI_HIGH)
	  break;

      /* We are now the first task in queue */
      queue->task = new;
    }
    break;
  case SILC_TASK_PRI_REALTIME:
    /* Highest priority. The task is added at the head of the list. 
       The last registered task is added to the very head of the list
       thus we get the LIFO (Last-In-First-Out) order. */
    next = task->next;
    while(next != task) {

      /* If we have shorter timeout than the next task we've found
	 our spot. */
      if (silc_task_timeout_compare(&new->timeout, &next->timeout))
	break;

      /* If we are equal size of timeout we will be first. */
      if (!silc_task_timeout_compare(&next->timeout, &new->timeout))
	break;

      /* We have longer timeout, compare to next one. */
      next = next->next;
    }
    /* Found a spot from the list, add the task to the list. */
    prev = next->prev;
    new->next = next;
    new->prev = prev;
    prev->next = new;
    next->prev = new;
    
    if (next == task) {
      /* Check if we are going to be the first task in the queue */
      if (silc_task_timeout_compare(&next->timeout, &new->timeout))
	break;

      /* We are now the first task in queue */
      queue->task = new;
    }
  default:
    silc_free(new);
    return NULL;
  }

  return new;
}

/* Registers a new task into the task queue. The task becomes valid
   automatically when it is registered. Returns a pointer to the 
   registered task. */

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
  if ((type == SILC_TASK_GENERIC) && queue->task) {
    SilcTask task;

    task = queue->task;
    while(1) {
      if ((task->callback == cb) && (task->context == context)) {
	SILC_LOG_DEBUG(("Found matching generic task, using the match"));

	/* Add the fd to be listened, the task found now applies to this
	   fd as well. */
	silc_schedule_set_listen_fd(fd, (1L << SILC_TASK_READ));
	return task;
      }

      if (queue->task == task->next)
	break;
      
      task = task->next;
    }
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

  /* If the task is non-timeout task we have to tell the scheduler that we
     would like to have these tasks scheduled at some odd distant future. */
  if (type != SILC_TASK_TIMEOUT)
    silc_schedule_set_listen_fd(fd, (1L << SILC_TASK_READ));

  /* Create timeout if marked to be timeout task */
  if (((seconds + useconds) > 0) && (type == SILC_TASK_TIMEOUT)) {
    gettimeofday(&new->timeout, NULL);
    new->timeout.tv_sec += seconds + (useconds / 1000000L);
    new->timeout.tv_usec += (useconds % 1000000L);
    if (new->timeout.tv_usec > 999999L) {
      new->timeout.tv_sec += 1;
      new->timeout.tv_usec -= 1000000L;
    }
    timeout = TRUE;
  }

  /* Is this first task of the queue? */
  if (queue->task == NULL) {
    queue->task = new;
    return new;
  }

  if (timeout)
    return silc_task_add_timeout(queue, new, priority);
  else
    return silc_task_add(queue, new, priority);
}

/* Removes (unregisters) a task from particular task queue. This function
   is used internally by scheduler. One should not call this function
   to unregister tasks, instead silc_task_unregister_task function
   should be used. */

int silc_task_remove(SilcTaskQueue queue, SilcTask task)
{
  SilcTask first, old, next;

  if (!queue || !queue->task)
    return FALSE;

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
	queue->task = next;

      silc_free(old);
      return TRUE;
    }
    old = old->next;

    if (old == first)
      return FALSE;
  }
}

/* Unregisters a task from the task queue. This is the unregister_task
   function pointer in task queue object. One should use this function
   to unregister tasks. This function invalidates the task. */

void silc_task_unregister(SilcTaskQueue queue, SilcTask task)
{

  /* Unregister all tasks */
  if (task == SILC_ALL_TASKS) {
    SilcTask next;
    SILC_LOG_DEBUG(("Unregistering all tasks at once"));

    if (queue->task == NULL)
      return;

    next = queue->task;
    
    while(1) {
      if (next->valid)
	next->valid = FALSE;
      if (queue->task == next->next)
	break;
      next = next->next;
    }
    return;
  }

  SILC_LOG_DEBUG(("Unregistering task"));

  /* Unregister the specific task */
  if (task->valid)
    task->valid = FALSE;
}

/* Unregister a task by file descriptor. This invalidates the task. */

void silc_task_unregister_by_fd(SilcTaskQueue queue, int fd)
{
  SilcTask next;

  SILC_LOG_DEBUG(("Unregister task by fd"));

  if (queue->task == NULL)
    return;

  next = queue->task;

  while(1) {
    if (next->fd == fd)
      next->valid = FALSE;
    if (queue->task == next->next)
      break;
    next = next->next;
  }
}

/* Sets the I/O mask for the task. Only one I/O type can be set at a
   time. */

void silc_task_set_iotype(SilcTask task, int type)
{
  task->iomask |= (1L << type);
}

/* Resets the I/O mask to the type sent as argument. */

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
