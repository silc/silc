/*

  silcschedule.c

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
/*
 * $Id$
 * $Log$
 * Revision 1.3  2000/07/18 06:51:58  priikone
 * 	Debug version bug fixes.
 *
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

/* The actual schedule object. */
static SilcSchedule schedule;

/* Initializes the schedule. Sets the non-timeout task queue hook and
   the timeout task queue hook. This must be called before the schedule
   is able to work. */

void silc_schedule_init(SilcTaskQueue fd_queue,
			SilcTaskQueue timeout_queue,
			SilcTaskQueue generic_queue,
			int max_fd)
{
  int i;

  SILC_LOG_DEBUG(("Initializing scheduler"));

  /* Initialize the schedule */
  memset(&schedule, 0, sizeof(schedule));
  schedule.fd_queue = fd_queue;
  schedule.timeout_queue = timeout_queue;
  schedule.generic_queue = generic_queue;
  schedule.fd_list.fd = silc_calloc(max_fd, sizeof(int));
  schedule.fd_list.last_fd = 0;
  schedule.fd_list.max_fd = max_fd;
  schedule.timeout = NULL;
  schedule.valid = TRUE;
  FD_ZERO(&schedule.in);
  FD_ZERO(&schedule.out);
  schedule.max_fd = -1;
  for (i = 0; i < max_fd; i++)
    schedule.fd_list.fd[i] = -1;
}

/* Uninitializes the schedule. This is called when the program is ready
   to end. This removes all tasks and task queues. */

int silc_schedule_uninit()
{

  SILC_LOG_DEBUG(("Uninitializing scheduler"));

  if (schedule.valid == TRUE)
    return FALSE;

  /* Unregister all tasks */
  if (schedule.fd_queue)
    silc_task_remove(schedule.fd_queue, SILC_ALL_TASKS);
  if (schedule.timeout_queue)
    silc_task_remove(schedule.timeout_queue, SILC_ALL_TASKS);
  if (schedule.generic_queue)
    silc_task_remove(schedule.generic_queue, SILC_ALL_TASKS);

  /* Unregister all task queues */
  if (schedule.fd_queue)
    silc_task_queue_free(schedule.fd_queue);
  if (schedule.timeout_queue)
    silc_task_queue_free(schedule.timeout_queue);
  if (schedule.generic_queue)
    silc_task_queue_free(schedule.generic_queue);

  /* Clear the fd list */
  if (schedule.fd_list.fd) {
    memset(schedule.fd_list.fd, -1, schedule.fd_list.max_fd);
    silc_free(schedule.fd_list.fd);
  }

  memset(&schedule, 'F', sizeof(schedule));
  return TRUE;
}

/* Stops the schedule even if it is not supposed to be stopped yet. 
   After calling this, one should call silc_schedule_uninit (after the 
   silc_schedule has returned). */

void silc_schedule_stop()
{
  SILC_LOG_DEBUG(("Stopping scheduler"));

  if (schedule.valid == TRUE)
    schedule.valid = FALSE;
}

/* Sets a file descriptor to be listened by select() in scheduler. One can
   call this directly if wanted. This can be called multiple times for
   one file descriptor to set different iomasks. */

void silc_schedule_set_listen_fd(int fd, unsigned int iomask)
{
  assert(schedule.valid != FALSE);
  assert(fd < schedule.fd_list.max_fd);

  schedule.fd_list.fd[fd] = iomask;
  
  if (fd > schedule.fd_list.last_fd)
    schedule.fd_list.last_fd = fd;
}

/* Removes a file descriptor from listen list. */

void silc_schedule_unset_listen_fd(int fd)
{
  assert(schedule.valid != FALSE);
  assert(fd < schedule.fd_list.max_fd);

  schedule.fd_list.fd[fd] = -1;
  
  if (fd == schedule.fd_list.last_fd) {
    int i;

    for (i = fd; i >= 0; i--)
      if (schedule.fd_list.fd[i] != -1)
	break;

    schedule.fd_list.last_fd = i;
  }
}

/* Executes tasks matching the file descriptor set by select(). The task
   remains on the task queue after execution. Invalid tasks are removed 
   here from the task queue. This macro is used by silc_schedule function. 
   We don't have to care about the tasks priority here because the tasks
   are sorted in their priority order already at the registration phase. */

#define SILC_SCHEDULE_RUN_TASKS						   \
do {									   \
  queue = schedule.fd_queue;						   \
  if (queue && queue->valid == TRUE && queue->task) {			   \
    task = queue->task;							   \
 									   \
    /* Walk thorugh all tasks in the particular task queue and	   	   \
       execute the callback functions of those tasks matching the  	   \
       fd set by select(). */					   	   \
    while(1) {							   	   \
      /* Validity of the task is checked always before and after   	   \
	 execution beacuse the task might have been unregistered 	   \
	 in the callback function, ie. it is not valid anymore. */	   \
								           \
      if (task->valid) {					           \
	/* Task ready for reading */				      	   \
	if ((FD_ISSET(task->fd, &schedule.in)) &&		      	   \
	    (task->iomask & (1L << SILC_TASK_READ))) {     	           \
	  task->callback(queue, SILC_TASK_READ, task->context, task->fd);  \
          is_run = TRUE; 						   \
	} 								   \
      }   								   \
									   \
      if (task->valid) {						   \
	/* Task ready for writing */					   \
	if ((FD_ISSET(task->fd, &schedule.out)) &&	       	      	   \
	    (task->iomask & (1L << SILC_TASK_WRITE))) {		      	   \
	  task->callback(queue, SILC_TASK_WRITE, task->context, task->fd); \
          is_run = TRUE; 						   \
	} 								   \
      }									   \
									   \
      if (!task->valid) {					  	   \
	/* Invalid (unregistered) tasks are removed from the 	      	   \
	   task queue. */						   \
	if (queue->task == task->next) {				   \
	  silc_task_remove(queue, task);				   \
          break;							   \
        }								   \
									   \
        task = task->next;						   \
        silc_task_remove(queue, task->prev);			      	   \
        continue;						      	   \
      }								      	   \
								      	   \
      /* Break if there isn't more tasks in the queue */	      	   \
      if (queue->task == task->next)       				   \
        break;								   \
	  								   \
      task = task->next;						   \
    }									   \
  }									   \
} while(0)

/* Selects tasks to be listened by select(). These are the non-timeout
   tasks. This checks the scheduler's fd list. This macro is used by 
   silc_schedule function. */

#define SILC_SCHEDULE_SELECT_TASKS				\
do {								\
  for (i = 0; i <= schedule.fd_list.last_fd; i++) {	       	\
    if (schedule.fd_list.fd[i] != -1) {				\
								\
      /* Set the max fd value for select() to listen */		\
      if (i > schedule.max_fd)					\
	schedule.max_fd = i;					\
								\
      /* Add tasks for reading */				\
      if ((schedule.fd_list.fd[i] & (1L << SILC_TASK_READ)))	\
	FD_SET(i, &schedule.in);				\
								\
      /* Add tasks for writing */				\
      if ((schedule.fd_list.fd[i] & (1L << SILC_TASK_WRITE)))	\
	FD_SET(i, &schedule.out);				\
    }								\
  }                                                             \
} while(0)

/* Executes all tasks whose timeout has expired. The task is removed from
   the task queue after the callback function has returned. Also, invalid
   tasks are removed here. The current time must be get before calling this
   macro. This macro is used by silc_schedule function. We don't have to
   care about priorities because tasks are already sorted in their priority
   order at the registration phase. */

#define SILC_SCHEDULE_RUN_TIMEOUT_TASKS					\
do {									\
  queue = schedule.timeout_queue;					\
  if (queue && queue->valid == TRUE && queue->task) {			\
    task = queue->task;							\
									\
    /* Walk thorugh all tasks in the particular task queue		\
       and run all the expired tasks. */				\
    while(1) {								\
      /* Execute the task if the timeout has expired */			\
      if (silc_task_timeout_compare(&task->timeout, &curtime)) {	\
									\
        /* Task ready for reading */					\
        if (task->valid) {						\
          if ((task->iomask & (1L << SILC_TASK_READ)))			\
	    task->callback(queue, SILC_TASK_READ,			\
	                   task->context, task->fd);			\
	}								\
									\
        /* Task ready for writing */					\
        if (task->valid) {						\
          if ((task->iomask & (1L << SILC_TASK_WRITE)))			\
            task->callback(queue, SILC_TASK_WRITE,			\
		           task->context, task->fd);			\
        }								\
									\
        /* Break if there isn't more tasks in the queue */		\
	if (queue->task == task->next) {				\
	  /* Remove the task from queue */				\
	  silc_task_remove(queue, task);				\
	  break;							\
        }								\
									\
        task = task->next;						\
									\
        /* Remove the task from queue */				\
        silc_task_remove(queue, task->prev);				\
      } else {								\
        /* The timeout hasn't expired, check for next one */		\
									\
        /* Break if there isn't more tasks in the queue */		\
        if (queue->task == task->next)					\
          break;							\
									\
        task = task->next;						\
      }									\
    }									\
  }									\
} while(0)

/* Calculates next timeout for select(). This is the timeout value
   when at earliest some of the timeout tasks expire. If this is in the
   past, they will be run now. This macro is used by the silc_schedule
   function. */

#define SILC_SCHEDULE_SELECT_TIMEOUT					    \
do {									    \
  if (schedule.timeout_queue && schedule.timeout_queue->valid == TRUE) {    \
    queue = schedule.timeout_queue;					    \
    task = NULL;							    \
									    \
    /* Get the current time */						    \
    gettimeofday(&curtime, NULL);					    \
    schedule.timeout = NULL;						    \
									    \
    /* First task in the task queue has always the smallest timeout. */	    \
    task = queue->task;							    \
    while(1) {								    \
      if (task && task->valid == TRUE) {				    \
									    \
	/* If the timeout is in past, we will run the task and all other    \
	   timeout tasks from the past. */				    \
	if (silc_task_timeout_compare(&task->timeout, &curtime)) {	    \
	  SILC_SCHEDULE_RUN_TIMEOUT_TASKS;				    \
									    \
	  /* The task(s) has expired and doesn't exist on the task queue    \
	     anymore. We continue with new timeout. */			    \
          queue = schedule.timeout_queue;				    \
          task = queue->task;						    \
          if (task == NULL || task->valid == FALSE)			    \
            break;							    \
	  goto cont;							    \
        } else {							    \
 cont:									    \
          /* Calculate the next timeout for select() */			    \
          queue->timeout.tv_sec = task->timeout.tv_sec - curtime.tv_sec;    \
          queue->timeout.tv_usec = task->timeout.tv_usec - curtime.tv_usec; \
									    \
          /* We wouldn't want to go under zero, check for it. */	    \
          if (queue->timeout.tv_usec < 0) {				    \
            queue->timeout.tv_sec -= 1;					    \
            queue->timeout.tv_usec += 1000000L;				    \
          }								    \
        }								    \
        /* We've got the timeout value */				    \
	break;								    \
      }	else {								    \
        /* Task is not valid, remove it and try next one. */		    \
	silc_task_remove(queue, task);					    \
        task = queue->task;						    \
        if (queue->task == NULL)					    \
          break;							    \
      }									    \
    }									    \
    /* Save the timeout */						    \
    if (task)								    \
      schedule.timeout = &queue->timeout;				    \
  }									    \
} while(0)

/* Execute generic tasks. These are executed only and only if for the
   specific fd there wasn't other non-timeout tasks. This checks the earlier
   set fd list, thus the generic tasks apply to all specified fd's. All the
   generic tasks are executed at once. */

#define SILC_SCHEDULE_RUN_GENERIC_TASKS					     \
do {									     \
  if (is_run == FALSE) {						     \
    SILC_LOG_DEBUG(("Running generic tasks"));				     \
    for (i = 0; i <= schedule.fd_list.last_fd; i++)			     \
      if (schedule.fd_list.fd[i] != -1) {				     \
									     \
	/* Check whether this fd is select()ed. */			     \
	if ((FD_ISSET(i, &schedule.in)) || (FD_ISSET(i, &schedule.out))) {   \
									     \
	  /* It was selected. Now find the tasks from task queue and execute \
	     all generic tasks. */					     \
	  if (schedule.generic_queue && schedule.generic_queue->valid) {     \
	    queue = schedule.generic_queue;				     \
									     \
	    if (!queue->task)						     \
	      break;							     \
									     \
	    task = queue->task;						     \
									     \
	    while(1) {							     \
	      /* Validity of the task is checked always before and after     \
		 execution beacuse the task might have been unregistered     \
		 in the callback function, ie. it is not valid anymore. */   \
									     \
	      if (task->valid && schedule.fd_list.fd[i] != -1) {	     \
		/* Task ready for reading */				     \
		if ((schedule.fd_list.fd[i] & (1L << SILC_TASK_READ)))	     \
		  task->callback(queue, SILC_TASK_READ,			     \
				 task->context, i);			     \
	      }								     \
									     \
	      if (task->valid && schedule.fd_list.fd[i] != -1) {	     \
		/* Task ready for writing */				     \
		if ((schedule.fd_list.fd[i] & (1L << SILC_TASK_WRITE)))	     \
		  task->callback(queue, SILC_TASK_WRITE,		     \
				 task->context, i);			     \
	      }								     \
									     \
	      if (!task->valid) {					     \
		/* Invalid (unregistered) tasks are removed from the	     \
		   task queue. */					     \
		if (queue->task == task->next) {			     \
		  silc_task_remove(queue, task);			     \
		  break;						     \
		}							     \
									     \
		task = task->next;					     \
		silc_task_remove(queue, task->prev);			     \
		continue;						     \
	      }								     \
									     \
	      /* Break if there isn't more tasks in the queue */	     \
	      if (queue->task == task->next)				     \
		break;							     \
									     \
	      task = task->next;					     \
	    }								     \
	  }								     \
	}								     \
      }									     \
  }									     \
} while(0)

/* The SILC scheduler. This is actually the main routine in SILC programs.
   When this returns the program is to be ended. Before this function can
   be called, one must call silc_schedule_init function. */

void silc_schedule()
{
  int is_run, i;
  SilcTask task;
  SilcTaskQueue queue;
  struct timeval curtime;

  SILC_LOG_DEBUG(("Running scheduler"));

  if (schedule.valid == FALSE) {
    SILC_LOG_ERROR(("Scheduler is not valid, stopping"));
    return;
  }

  /* Start the scheduler loop */
  while(1) {

    SILC_LOG_DEBUG(("In scheduler loop"));

    /* If the task queues aren't initialized or we aren't valid anymore
       we will return */
    if ((!schedule.fd_queue && !schedule.timeout_queue 
	 && !schedule.generic_queue) || schedule.valid == FALSE) {
      SILC_LOG_DEBUG(("Scheduler not valid anymore, exiting"));
      break;
    }

    /* Clear everything */
    FD_ZERO(&schedule.in);
    FD_ZERO(&schedule.out);
    schedule.max_fd = -1;
    is_run = FALSE;

    /* Calculate next timeout for select(). This is the timeout value
       when at earliest some of the timeout tasks expire. */
    SILC_SCHEDULE_SELECT_TIMEOUT;

    /* Add the file descriptors to the fd sets. These are the non-timeout
       tasks. The select() listens to these file descriptors. */
    SILC_SCHEDULE_SELECT_TASKS;

    if (schedule.max_fd == -1) {
      SILC_LOG_ERROR(("Nothing to listen, exiting"));
      break;
    }

    if (schedule.timeout) {
      SILC_LOG_DEBUG(("timeout: sec=%d, usec=%d", schedule.timeout->tv_sec,
		      schedule.timeout->tv_usec));
    }

    /* This is the main select(). The program blocks here until some
       of the selected file descriptors change status or the selected
       timeout expires. */
    SILC_LOG_DEBUG(("Select"));
    switch(select(schedule.max_fd + 1, &schedule.in, 
		  &schedule.out, 0, schedule.timeout)) {
    case -1:
      /* Error */
      SILC_LOG_ERROR(("Error in select(): %s", strerror(errno)));
      break;
    case 0:
      /* Timeout */
      SILC_LOG_DEBUG(("Running timeout tasks"));
      gettimeofday(&curtime, NULL);
      SILC_SCHEDULE_RUN_TIMEOUT_TASKS;
      break;
    default:
      /* There is some data available now */
      SILC_LOG_DEBUG(("Running non-timeout tasks"));
      SILC_SCHEDULE_RUN_TASKS;

      SILC_SCHEDULE_RUN_GENERIC_TASKS;
      break;
    }
  }
}
