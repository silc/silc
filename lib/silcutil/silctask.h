/*

  silctask.h

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

#ifndef SILCTASK_H
#define SILCTASK_H

typedef struct SilcTaskQueueStruct *SilcTaskQueue;
typedef struct SilcTaskStruct *SilcTask;
typedef void (*SilcTaskCallback)(void *, int, void *, int);

#include "silcschedule.h"

/* 
   SILC Task object. 

   int fd

       File descriptor. This usually is a network socket but can be
       any file descriptor. On generic tasks, that applies to all file
       descriptors, this is set to -1.

   struct timeval timeout
  
       The timeout when this task is supposed to be run. This is defined
       only if the task is a timeout task.

   void *context;

       Context structure passed to callback function as argument.

   SilcTaskCallback callback

       The callback function Silc scheduler calls when this task is scheduled
       to be run. First argument is the task queue this task belongs to. This
       is a void pointer and the task queue has to casted out of it. Second
       argument is the type of the event just occured inside the scheduler 
       (SILC_TASK_READ or SILC_TASK_WRITE). Third argument is the context 
       structure of the task. Last argument is the file descriptor of the
       task.

   bool valid

       Marks for validity of the task. Task that is not valid scheduler 
       will skip. This is boolean value.

   int priority

       Priority of the task. This field is used internally only and it
       should not be touched otherwise.

   int iomask

       I/O mask which tells to the scheduler for what kind of I/O this 
       task is ready. If the task is ready for both reading and writing
       SILC_TASK_READ and SILC_TASK_WRITE are masked into this variable.
       Masking is done by OR'ing (1 << SILC_TASK_*) values. One can check
       the mask by AND'ing (1L << SILC_TASK_*) against the mask. At the
       registering of a new task this mask is set to SILC_TASK_READ by
       default. If a task doesn't perform reading this value must be
       reset to SILC_TASK_WRITE. If it performs both reading and writing
       SILC_TASK_WRITE must be added to the mask. A task must always be 
       ready for at least for one I/O type.

   struct SilcTaskStruct *next
   struct SilcTaskStruct *prev

       Next and previous task. If the task is first in the list, prev is
       set to the last task in the list. If the task is last in the list, 
       next is set to the first task in the list (forms a circular list).

*/

struct SilcTaskStruct {
  int fd;
  struct timeval timeout;
  void *context;
  SilcTaskCallback callback;
  bool valid;
  int priority;
  int iomask;

  struct SilcTaskStruct *next;
  struct SilcTaskStruct *prev;
};

/* 
   SILC Task types.

   SILC has three types of tasks, non-timeout tasks (tasks that perform
   over file descriptors), timeout tasks and generic tasks (tasks that apply
   to every file descriptor). This type is sent as argument for the 
   task registering function.

*/
typedef enum {
  SILC_TASK_FD,
  SILC_TASK_TIMEOUT,
  SILC_TASK_GENERIC,
} SilcTaskType;

/* 
   SILC Task priorities.

   Following description of the priorities uses timeout tasks as example
   how the priority behaves. However, non-timeout tasks behaves same as
   timeout tasks with following priorities.

   SILC_TASK_PRI_LOW

       Lowest priority. The task is scheduled to run after its timeout
       has expired only and only when every other task with higher priority 
       has already been run. For non-timeout tasks this priority behaves
       same way. Life is not fair for tasks with this priority.

   SILC_TASK_PRI_NORMAL

       Normal priority that is used mostly in Silc. This is priority that
       should always be used unless you specificly need some other priority.
       The scheduler will run this task as soon as its timeout has expired.
       For non-timeout tasks this priority behaves same way. Tasks are run 
       in FIFO (First-In-First-Out) order.

*/
typedef enum {
  SILC_TASK_PRI_LOW,
  SILC_TASK_PRI_NORMAL,
} SilcTaskPriority;

/* 
   SILC Task Queue object. 
   
   Usually there are three task queues in SILC. Tasks with timeouts
   has their own queue, tasks without timeout has one as well and generic
   tasks has their own also. Scheduler has timeout queue hooks and 
   non-timeout queue hooks in the scheduler and it does not check for 
   timeouts in non-timeout hooks and vice versa, respectively. Ie. Register 
   timeout queues to their own SilcTaskQueue pointer and non-timeout queues 
   to their own pointer. 

   Generic tasks, mentioned earlier, has their own task queue. These tasks 
   are non-timeout tasks and they apply to all file descriptors, except to 
   those that have explicitly registered a non-timeout task. These tasks
   are there to make it simpler and faster to execute common code that
   applies to all connections. These are, for example, receiving packets
   from network and sending packets to network. It doesn't make much sense
   to register a task that receives a packet from network to every connection
   when you can have one task that applies to all connections. This is what
   generic tasks are for. Generic tasks are not bound to any specific file
   descriptor, however, the correct file descriptor must be passed as
   argument to task registering function.

   Short description of the field following:

   SilcSchedule schedule

       A back pointer to the scheduler.

   SilcTask task

       Pointer to the current (first) task in the queue.

   int valid

       Marks for validity of the queue. If the task queue is not valid 
       scheduler will skip it. This is boolean value.

   struct timeval timeout

       Timeout when earliest some tasks in this queue should expire. The
       value of this timeout is updated automatically by schedule. This 
       is used only and only if this queue is a timeout queue. For normal
       task queue this is not defined. This is meant only for internal
       use and it should be considered to be read-only field.

*/

struct SilcTaskQueueStruct {
  SilcSchedule schedule;
  SilcTask task;
  int valid;
  struct timeval timeout;
  SILC_MUTEX_DEFINE(lock);
};

/* Marks for all tasks in a task queue. This can be passed to 
   unregister_task function to cancel all tasks at once. */
#define SILC_ALL_TASKS ((SilcTask)1)

/* Marks for all task queues. This can be passed to 
   silc_task_queue_unregister function to cancel all task queues at once. */
#define SILC_ALL_TASK_QUEUES ((SilcTaskQueue)1)

/* Silc Task event types. One of these are passed to the task callback
   function from the schedule. These values are also masked into a task
   so that scheduler knows for what kind of I/O it needs to perform
   for that task. */
#define SILC_TASK_READ 0
#define SILC_TASK_WRITE 1

/* Macros */

/* These can be used instead of calling directly the registering function. 
   XXX: These are not used currently, maybe they should be :) */
#define SILC_REGISTER_FD_TASK(queue, fd, cb, ctx, pri) \
  (silc_task_register((queue), (fd), (cb), (ctx), 0, 0, \
		      SILC_TASK_FD, (pri)))
#define SILC_REGISTER_TIMEOUT_TASK(queue, fd, cb, ctx, sec, usec, pri) \
  (silc_task_register((queue), (fd), (cb), (ctx), (sec), (usec), \
		      SILC_TASK_TIMEOUT, (pri)))
#define SILC_REGISTER_GENERIC_TASK(queue, fd, cb, ctx, pri) \
  (silc_task_register((queue), (fd), (cb), (ctx), 0, 0, \
		      SILC_TASK_GENERIC, (pri)))

/* Generic macro to define task callback functions. This defines a function
   with name 'func' as a task callback function. */
#define SILC_TASK_CALLBACK(func) \
static void func(void *qptr, int type, void *context, int fd)
#define SILC_TASK_CALLBACK_GLOBAL(func) \
void func(void *qptr, int type, void *context, int fd)

/* Prototypes */
void silc_task_queue_alloc(SilcSchedule schedule, SilcTaskQueue *queue, 
			   bool valid);
void silc_task_queue_free(SilcTaskQueue queue);
void silc_task_queue_wakeup(SilcTaskQueue queue);
SilcTask silc_task_add(SilcTaskQueue queue, SilcTask task, 
		       SilcTaskPriority priority);
SilcTask silc_task_add_timeout(SilcTaskQueue queue, SilcTask task,
			       SilcTaskPriority priority);
SilcTask silc_task_register(SilcTaskQueue queue, int fd, 
			    SilcTaskCallback cb, void *context, 
			    long seconds, long useconds, 
			    SilcTaskType type, 
			    SilcTaskPriority priority);
void silc_task_unregister(SilcTaskQueue queue, SilcTask task);
void silc_task_unregister_by_fd(SilcTaskQueue queue, int fd);
void silc_task_unregister_by_callback(SilcTaskQueue queue, 
				      SilcTaskCallback callback);
void silc_task_unregister_by_context(SilcTaskQueue queue, void *context);
void silc_task_set_iotype(SilcTask task, int type);
void silc_task_reset_iotype(SilcTask task, int type);
int silc_task_timeout_compare(struct timeval *smaller, 
			      struct timeval *bigger);

#endif
