/*

  silctask.h

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

#ifndef SILCTASK_H
#define SILCTASK_H

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

   int valid

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

typedef void (*SilcTaskCallback)(void *, int, void *, int);

typedef struct SilcTaskStruct {
  int fd;
  struct timeval timeout;
  void *context;
  SilcTaskCallback callback;
  int valid;
  int priority;
  int iomask;

  struct SilcTaskStruct *next;
  struct SilcTaskStruct *prev;
} SilcTaskObject;

typedef SilcTaskObject *SilcTask;

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

   SILC_TASK_PRI_HIGH
   
       High priority for important tasks. This priority should be used only
       for important tasks. Life is very fair for tasks with this priority.
       These tasks are run as soon as its timeout has expired. They are run 
       before normal or lower tasks, respectively. For non-timeout tasks
       this priority behaves same way. Tasks are run in FIFO order.

   SILC_TASK_PRI_REALTIME

       Highest priority. This priority should be used very carefully because
       it can make the scheduler extremely unfair to other tasks. The task
       will be run as soon as its timeout has expired. The task is run before
       any other task. It is also quaranteed that the last registered task
       with this priority is the first task to be run when its timeout
       expires. Tasks are run in LIFO (Last-In-First-Out) order. To make
       scheduler fair there should never be more than one task in the queue
       with this priority. Currently none of the tasks in SILC are important
       enough to use this priority. For non-timeout tasks this priority
       behaves same way.

*/
typedef enum {
  SILC_TASK_PRI_LOW,
  SILC_TASK_PRI_NORMAL,
  SILC_TASK_PRI_HIGH,
  SILC_TASK_PRI_REALTIME,
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

   SilcTask task

       Pointer to the tasks in the queue.

   int valid

       Marks for validity of the queue. If the task queue is not valid 
       scheduler will skip it. This is boolean value.

   struct timeval timeout

       Timeout when earliest some tasks in this queue should expire. The
       value of this timeout is updated automatically by schedule. This 
       is used only and only if this queue is a timeout queue. For normal
       task queue this is not defined. This is meant only for internal
       use and it should be considered to be read-only field.

   SilcTask (*register_task)(SilcTaskQueue, int, 
                             SilcTaskCallback, void *, 
			     long, long, 
			     SilcTaskType,
			     SilcTaskPriority)

       Registers a new task to the task queue. Arguments are as follows:

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
       generic tasks.

   void (*unregister_task)(SilcTaskQueue, SilcTask)

       Unregisters a task already in the queue. Arguments are as follows:

       SilcTaskQueue queue      Queue where from the task is unregistered
       SilcTask task            Task to be unregistered

       The same function is used to unregister timeout and non-timeout 
       tasks. One can also unregister all tasks from the queue by passing
       SILC_ALL_TASKS as task to the function. It is safe to unregister
       a task in a callback function.

   void (*set_iotype)(SilcTask, int type)

       Sets the I/O type of the task. The scheduler checks for this value
       and a task must always have at least one of the I/O types set at 
       all time. When registering new task the type is set by default to
       SILC_TASK_READ. If the task doesn't perform reading one must reset
       the value to SILC_TASK_WRITE.

       The type sent as argumenet is masked into the task. If the tasks 
       I/O mask already includes this type this function has no effect. 
       Only one I/O type can be added at once. If the task must perform
       both reading and writing one must call this function for value
       SILC_TASK_WRITE as well.

   void (*reset_iotype)(SilcTask, int type)

       Resets the mask to the type sent as argument. Note that this resets
       the previous values to zero and then adds the type sent as argument.
       This function can be used to remove one of the types masked earlier
       to the task.

*/

typedef struct SilcTaskQueueStruct {
  SilcTask task;
  int valid;
  struct timeval timeout;

  /* Method functions */
  SilcTask (*register_task)(struct SilcTaskQueueStruct *, int, 
			    SilcTaskCallback, void *, long, long, 
			    SilcTaskType, SilcTaskPriority);
  void (*unregister_task)(struct SilcTaskQueueStruct *, SilcTask);
  void (*set_iotype)(SilcTask, int type);
  void (*reset_iotype)(SilcTask, int type);
} SilcTaskQueueObject;

typedef SilcTaskQueueObject *SilcTaskQueue;

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

/* Prototypes */
void silc_task_queue_alloc(SilcTaskQueue *new, int valid);
void silc_task_queue_free(SilcTaskQueue old);
SilcTask silc_task_add(SilcTaskQueue queue, SilcTask new, 
		       SilcTaskPriority priority);
SilcTask silc_task_add_timeout(SilcTaskQueue queue, SilcTask new,
			       SilcTaskPriority priority);
SilcTask silc_task_register(SilcTaskQueue queue, int fd, 
			    SilcTaskCallback cb, void *context, 
			    long seconds, long useconds, 
			    SilcTaskType type, 
			    SilcTaskPriority priority);
int silc_task_remove(SilcTaskQueue queue, SilcTask task);
void silc_task_unregister(SilcTaskQueue queue, SilcTask task);
void silc_task_unregister_by_fd(SilcTaskQueue queue, int fd);
void silc_task_set_iotype(SilcTask task, int type);
void silc_task_reset_iotype(SilcTask task, int type);
int silc_task_timeout_compare(struct timeval *smaller, 
			      struct timeval *bigger);

#endif
