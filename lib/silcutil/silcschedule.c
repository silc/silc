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
/* XXX on multi-threads the task queue locking is missing here. */

#include "silcincludes.h"

/* Routine to remove the task. Implemented in silctask.c. */
int silc_task_remove(SilcTaskQueue queue, SilcTask task);

/* System specific routines. Implemented under unix/ and win32/. */

/* System specific select(). */
int silc_select(int n, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout);

/* Initializes the wakeup of the scheduler. In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues. This will initialize the wakeup for the scheduler.
   Any tasks that needs to be registered must be registered to the `queue'.
   It is guaranteed that the scheduler will automatically free any
   registered tasks in this queue. This is system specific routine. */
void *silc_schedule_wakeup_init(void *queue);

/* Uninitializes the system specific wakeup. */
void silc_schedule_wakeup_uninit(void *context);

/* Wakes up the scheduler. This is platform specific routine */
void silc_schedule_wakeup_internal(void *context);

/* Structure holding list of file descriptors, scheduler is supposed to
   be listenning. The max_fd field is the maximum number of possible file
   descriptors in the list. This value is set at the initialization
   of the scheduler and it usually is the maximum number of connections 
   allowed. */
typedef struct {
  int *fd;
  uint32 last_fd;
  uint32 max_fd;
} SilcScheduleFdList;

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

   SilcScheduleFdList fd_list

       List of file descriptors the scheduler is supposed to be listenning.
       This is updated internally.

   struct timeval *timeout;

       Pointer to the schedules next timeout. Value of this timeout is
       automatically updated in the silc_schedule function.

   int valid

       Marks validity of the scheduler. This is a boolean value. When this
       is false the scheduler is terminated and the program will end. This
       set to true when the scheduler is initialized with silc_schedule_init
       function.

   fd_set in
   fd_set out

       File descriptor sets for select(). These are automatically managed
       by the scheduler and should not be touched otherwise.

   int max_fd

       Number of maximum file descriptors for select(). This, as well, is
       managed automatically by the scheduler and should be considered to 
       be read-only field otherwise.

   void *wakeup

       System specific wakeup context. On multi-threaded environments the
       scheduler needs to be wakenup (in the thread) when tasks are added
       or removed. This is initialized by silc_schedule_wakeup_init.

*/
struct SilcScheduleStruct {
  SilcTaskQueue fd_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;
  SilcScheduleFdList fd_list;
  struct timeval *timeout;
  bool valid;
  fd_set in;
  fd_set out;
  int max_fd;
  void *wakeup;
  SILC_MUTEX_DEFINE(lock);
};

/* Initializes the scheduler. Sets the non-timeout task queue hook and
   the timeout task queue hook. This must be called before the scheduler
   is able to work. This will allocate the queue pointers if they are
   not allocated. Returns the scheduler context that must be freed by
   the silc_schedule_uninit function. */

SilcSchedule silc_schedule_init(SilcTaskQueue *fd_queue,
				SilcTaskQueue *timeout_queue,
				SilcTaskQueue *generic_queue,
				int max_fd)
{
  SilcSchedule schedule;
  int i;

  SILC_LOG_DEBUG(("Initializing scheduler"));

  schedule = silc_calloc(1, sizeof(*schedule));

  /* Register the task queues if they are not registered already. In SILC
     we have by default three task queues. One task queue for non-timeout
     tasks which perform different kind of I/O on file descriptors, timeout
     task queue for timeout tasks, and, generic non-timeout task queue whose
     tasks apply to all connections. */
  if (!*fd_queue)
    silc_task_queue_alloc(schedule, fd_queue, TRUE);
  if (!*timeout_queue)
    silc_task_queue_alloc(schedule, timeout_queue, TRUE);
  if (!*generic_queue)
    silc_task_queue_alloc(schedule, generic_queue, TRUE);

  /* Initialize the scheduler */
  schedule->fd_queue = *fd_queue;
  schedule->timeout_queue = *timeout_queue;
  schedule->generic_queue = *generic_queue;
  schedule->fd_list.fd = silc_calloc(max_fd, sizeof(*schedule->fd_list.fd));
  schedule->fd_list.last_fd = 0;
  schedule->fd_list.max_fd = max_fd;
  schedule->timeout = NULL;
  schedule->valid = TRUE;
  FD_ZERO(&schedule->in);
  FD_ZERO(&schedule->out);
  schedule->max_fd = -1;
  for (i = 0; i < max_fd; i++)
    schedule->fd_list.fd[i] = -1;

  silc_mutex_alloc(&schedule->lock);

  /* Initialize the wakeup */
  schedule->wakeup = silc_schedule_wakeup_init(schedule->fd_queue);

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
  if (schedule->fd_queue)
    silc_task_remove(schedule->fd_queue, SILC_ALL_TASKS);
  if (schedule->timeout_queue)
    silc_task_remove(schedule->timeout_queue, SILC_ALL_TASKS);
  if (schedule->generic_queue)
    silc_task_remove(schedule->generic_queue, SILC_ALL_TASKS);

  /* Unregister all task queues */
  if (schedule->fd_queue)
    silc_task_queue_free(schedule->fd_queue);
  if (schedule->timeout_queue)
    silc_task_queue_free(schedule->timeout_queue);
  if (schedule->generic_queue)
    silc_task_queue_free(schedule->generic_queue);

  /* Clear the fd list */
  if (schedule->fd_list.fd) {
    memset(schedule->fd_list.fd, -1, schedule->fd_list.max_fd);
    silc_free(schedule->fd_list.fd);
  }

  /* Uninit the wakeup */
  silc_schedule_wakeup_uninit(schedule->wakeup);

  silc_mutex_free(schedule->lock);

  return TRUE;
}

/* Stops the schedule even if it is not supposed to be stopped yet. 
   After calling this, one should call silc_schedule_uninit (after the 
   silc_schedule has returned). */

void silc_schedule_stop(SilcSchedule schedule)
{
  SILC_LOG_DEBUG(("Stopping scheduler"));
  schedule->valid = FALSE;
}

/* Sets a file descriptor to be listened by select() in scheduler. One can
   call this directly if wanted. This can be called multiple times for
   one file descriptor to set different iomasks. */

void silc_schedule_set_listen_fd(SilcSchedule schedule, int fd, uint32 iomask)
{
  silc_mutex_lock(schedule->lock);

  schedule->fd_list.fd[fd] = iomask;
  
  if (fd > schedule->fd_list.last_fd)
    schedule->fd_list.last_fd = fd;

  silc_mutex_unlock(schedule->lock);
}

/* Removes a file descriptor from listen list. */

void silc_schedule_unset_listen_fd(SilcSchedule schedule, int fd)
{
  silc_mutex_lock(schedule->lock);

  schedule->fd_list.fd[fd] = -1;
  
  if (fd == schedule->fd_list.last_fd) {
    int i;

    for (i = fd; i >= 0; i--)
      if (schedule->fd_list.fd[i] != -1)
	break;

    schedule->fd_list.last_fd = i < 0 ? 0 : i;
  }

  silc_mutex_unlock(schedule->lock);
}

/* Executes tasks matching the file descriptor set by select(). The task
   remains on the task queue after execution. Invalid tasks are removed 
   here from the task queue. This macro is used by silc_schedule function. 
   We don't have to care about the tasks priority here because the tasks
   are sorted in their priority order already at the registration phase. */

#define SILC_SCHEDULE_RUN_TASKS						   \
do {									   \
  queue = schedule->fd_queue;						   \
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
	if ((FD_ISSET(task->fd, &schedule->in)) &&		      	   \
	    (task->iomask & (1L << SILC_TASK_READ))) {     	           \
	  task->callback(queue, SILC_TASK_READ, task->context, task->fd);  \
          is_run = TRUE; 						   \
	} 								   \
      }   								   \
									   \
      if (task->valid) {						   \
	/* Task ready for writing */					   \
	if ((FD_ISSET(task->fd, &schedule->out)) &&	       	      	   \
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
  for (i = 0; i <= schedule->fd_list.last_fd; i++) {		\
    if (schedule->fd_list.fd[i] != -1) {			\
								\
      /* Set the max fd value for select() to listen */		\
      if (i > schedule->max_fd)					\
	schedule->max_fd = i;					\
								\
      /* Add tasks for reading */				\
      if ((schedule->fd_list.fd[i] & (1L << SILC_TASK_READ)))	\
	FD_SET(i, &schedule->in);				\
								\
      /* Add tasks for writing */				\
      if ((schedule->fd_list.fd[i] & (1L << SILC_TASK_WRITE)))	\
	FD_SET(i, &schedule->out);				\
    }								\
  }								\
} while(0)

/* Executes all tasks whose timeout has expired. The task is removed from
   the task queue after the callback function has returned. Also, invalid
   tasks are removed here. The current time must be get before calling this
   macro. This macro is used by silc_schedule function. We don't have to
   care about priorities because tasks are already sorted in their priority
   order at the registration phase. */

#define SILC_SCHEDULE_RUN_TIMEOUT_TASKS					\
do {									\
  queue = schedule->timeout_queue;					\
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
  if (schedule->timeout_queue && schedule->timeout_queue->valid == TRUE) {  \
    queue = schedule->timeout_queue;					    \
    task = NULL;							    \
									    \
    /* Get the current time */						    \
    silc_gettimeofday(&curtime);					    \
    schedule->timeout = NULL;						    \
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
          queue = schedule->timeout_queue;				    \
          task = queue->task;						    \
          if (task == NULL || task->valid == FALSE)			    \
            break;							    \
	  goto cont;							    \
        } else {							    \
 cont:									    \
          /* Calculate the next timeout for select() */			    \
          queue->timeout.tv_sec = task->timeout.tv_sec - curtime.tv_sec;    \
          queue->timeout.tv_usec = task->timeout.tv_usec - curtime.tv_usec; \
	  if (queue->timeout.tv_sec < 0)				    \
            queue->timeout.tv_sec = 0;					    \
									    \
          /* We wouldn't want to go under zero, check for it. */	    \
          if (queue->timeout.tv_usec < 0) {				    \
            queue->timeout.tv_sec -= 1;					    \
	    if (queue->timeout.tv_sec < 0)				    \
              queue->timeout.tv_sec = 0;				    \
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
      schedule->timeout = &queue->timeout;				    \
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
    silc_mutex_lock(schedule->lock);					     \
    for (i = 0; i <= schedule->fd_list.last_fd; i++)			     \
      if (schedule->fd_list.fd[i] != -1) {				     \
									     \
	/* Check whether this fd is select()ed. */			     \
	if ((FD_ISSET(i, &schedule->in)) || (FD_ISSET(i, &schedule->out))) { \
									     \
	  /* It was selected. Now find the tasks from task queue and execute \
	     all generic tasks. */					     \
	  if (schedule->generic_queue && schedule->generic_queue->valid) {   \
	    queue = schedule->generic_queue;				     \
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
	      if (task->valid && schedule->fd_list.fd[i] != -1) {	     \
		/* Task ready for reading */				     \
		if ((schedule->fd_list.fd[i] & (1L << SILC_TASK_READ))) {    \
                  silc_mutex_unlock(schedule->lock);			     \
		  task->callback(queue, SILC_TASK_READ,			     \
				 task->context, i);			     \
                  silc_mutex_lock(schedule->lock);			     \
	        }							     \
	      }								     \
									     \
	      if (task->valid && schedule->fd_list.fd[i] != -1) {	     \
		/* Task ready for writing */				     \
		if ((schedule->fd_list.fd[i] & (1L << SILC_TASK_WRITE))) {   \
                  silc_mutex_unlock(schedule->lock);			     \
		  task->callback(queue, SILC_TASK_WRITE,		     \
				 task->context, i);			     \
                  silc_mutex_lock(schedule->lock);			     \
	        }							     \
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
    silc_mutex_unlock(schedule->lock);					     \
  }									     \
} while(0)

bool silc_schedule_one(SilcSchedule schedule, int timeout_usecs)
{
  struct timeval timeout;
  int is_run, i;
  SilcTask task;
  SilcTaskQueue queue;
  struct timeval curtime;
  int ret;

  SILC_LOG_DEBUG(("In scheduler loop"));

  /* If the task queues aren't initialized or we aren't valid anymore
     we will return */
  if ((!schedule->fd_queue && !schedule->timeout_queue 
       && !schedule->generic_queue) || schedule->valid == FALSE) {
    SILC_LOG_DEBUG(("Scheduler not valid anymore, exiting"));
    return FALSE;
  }

  /* Clear everything */
  FD_ZERO(&schedule->in);
  FD_ZERO(&schedule->out);
  schedule->max_fd = -1;
  is_run = FALSE;

  /* Calculate next timeout for select(). This is the timeout value
     when at earliest some of the timeout tasks expire. */
  SILC_SCHEDULE_SELECT_TIMEOUT;

  silc_mutex_lock(schedule->lock);

  /* Add the file descriptors to the fd sets. These are the non-timeout
     tasks. The select() listens to these file descriptors. */
  SILC_SCHEDULE_SELECT_TASKS;

  if (schedule->max_fd == -1 && !schedule->timeout)
    return FALSE;

  if (schedule->timeout) {
    SILC_LOG_DEBUG(("timeout: sec=%d, usec=%d", schedule->timeout->tv_sec,
		    schedule->timeout->tv_usec));
  }

  if (timeout_usecs >= 0) {
    timeout.tv_sec = 0;
    timeout.tv_usec = timeout_usecs;
    schedule->timeout = &timeout;
  }

  silc_mutex_unlock(schedule->lock);

  /* This is the main select(). The program blocks here until some
     of the selected file descriptors change status or the selected
     timeout expires. */
  SILC_LOG_DEBUG(("Select"));
  ret = silc_select(schedule->max_fd + 1, &schedule->in,
		    &schedule->out, 0, schedule->timeout);

  switch (ret) {
  case -1:
    /* Error */
    if (errno == EINTR)
      break;
    SILC_LOG_ERROR(("Error in select(): %s", strerror(errno)));
    break;
  case 0:
    /* Timeout */
    SILC_LOG_DEBUG(("Running timeout tasks"));
    silc_gettimeofday(&curtime);
    SILC_SCHEDULE_RUN_TIMEOUT_TASKS;
    break;
  default:
    /* There is some data available now */
    SILC_LOG_DEBUG(("Running non-timeout tasks"));
    SILC_SCHEDULE_RUN_TASKS;

    SILC_SCHEDULE_RUN_GENERIC_TASKS;
    break;
  }

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

  /* Start the scheduler loop */
  while (silc_schedule_one(schedule, -1)) 
    ;
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
  silc_mutex_lock(schedule->lock);
  silc_schedule_wakeup_internal(schedule->wakeup);
  silc_mutex_unlock(schedule->lock);
#endif
}
