/*

  silcschedule.h

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

#ifndef SILCSCHEDULE_H
#define SILCSCHEDULE_H

/* Structure holding list of file descriptors, scheduler is supposed to
   be listenning. The max_fd field is the maximum number of possible file
   descriptors in the list. This value is set at the initialization
   of the scheduler and it usually is the maximum number of connections 
   allowed. */
typedef struct {
  int *fd;
  unsigned int last_fd;
  unsigned int max_fd;
} SilcScheduleFdList;

/* 
   Silc Schedule object. 

   This is the actual schedule object in Silc. Both Silc client and server 
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

*/

typedef struct {
  SilcTaskQueue fd_queue;
  SilcTaskQueue timeout_queue;
  SilcTaskQueue generic_queue;
  SilcScheduleFdList fd_list;
  struct timeval *timeout;
  int valid;
  fd_set in;
  fd_set out;
  int max_fd;
} SilcScheduleObject;

typedef SilcScheduleObject SilcSchedule;

/* Prototypes */
void silc_schedule_init(SilcTaskQueue *fd_queue,
			SilcTaskQueue *timeout_queue,
			SilcTaskQueue *generic_queue,
			int max_fd);
int silc_schedule_uninit();
void silc_schedule_stop();
void silc_schedule_set_listen_fd(int fd, unsigned int iomask);
void silc_schedule_unset_listen_fd(int fd);
void silc_schedule();
int silc_schedule_one(int block);

#endif
