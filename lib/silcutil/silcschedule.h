/****h* silcutil/silcschedule.h
 *
 * NAME
 *
 * silcschedule.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@silcnet.org>
 *
 * Copyright (C) 1998 - 2001 Pekka Riikonen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef SILCSCHEDULE_H
#define SILCSCHEDULE_H

/****s* silcutil/SilcScheduleAPI/SilcSchedule
 *
 * NAME
 * 
 *    typedef struct SilcScheduleStruct *SilcSchedule;
 *
 * DESCRIPTION
 *
 *    This context is the actual Scheduler and is allocated by
 *    the silc_schedule_init funtion.  The context is given as argument
 *    to all silc_schedule_* functions.  It must be freed by the 
 *    silc_schedule_uninit function.
 *
 ***/
typedef struct SilcScheduleStruct *SilcSchedule;

/* Prototypes */

/****f* silcutil/SilcScheduleAPI/silc_schedule_init
 *
 * SYNOPSIS
 *
 *    SilcSchedule silc_schedule_init(SilcTaskQueue *fd_queue,
 *                                    SilcTaskQueue *timeout_queue,
 *                                    SilcTaskQueue *generic_queue,
 *                                    int max_fd);
 *
 * DESCRIPTION
 *
 *    Initializes the scheduler. Sets the non-timeout task queue hook and
 *    the timeout task queue hook. This must be called before the scheduler
 *    is able to work. This will allocate the queue pointers if they are
 *    not allocated. Returns the scheduler context that must be freed by
 *    the silc_schedule_uninit function.
 *
 ***/
SilcSchedule silc_schedule_init(SilcTaskQueue *fd_queue,
				SilcTaskQueue *timeout_queue,
				SilcTaskQueue *generic_queue,
				int max_fd);

/****f* silcutil/SilcScheduleAPI/silc_schedule_uninit
 *
 * SYNOPSIS
 *
 *    bool silc_schedule_uninit(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Uninitializes the schedule. This is called when the program is ready
 *    to end. This removes all tasks and task queues. Returns FALSE if the
 *    scheduler could not be uninitialized. This happens when the scheduler
 *    is still valid and silc_schedule_stop has not been called.
 *
 ***/
bool silc_schedule_uninit(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule_stop
 *
 * SYNOPSIS
 *
 *    void silc_schedule_stop(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Stops the scheduler even if it is not supposed to be stopped yet. 
 *    After calling this, one must call silc_schedule_uninit (after the 
 *    silc_schedule has returned).
 *
 ***/
void silc_schedule_stop(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule_set_listen_fd
 *
 * SYNOPSIS
 *
 *    void silc_schedule_set_listen_fd(SilcSchedule schedule, 
 *                                     int fd, uint32 iomask);
 *
 * DESCRIPTION
 *
 *    Sets a file descriptor to be listened by the scheduler. One can
 *    call this directly if wanted. This can be called multiple times for
 *    one file descriptor to set different iomasks.
 *
 ***/
void silc_schedule_set_listen_fd(SilcSchedule schedule, int fd, uint32 iomask);

/****f* silcutil/SilcScheduleAPI/silc_schedule_unset_listen_fd
 *
 * SYNOPSIS
 *
 *    void silc_schedule_unset_listen_fd(SilcSchedule schedule, int fd);
 *
 * DESCRIPTION
 *
 *    Removes a file descriptor from listen list.  The file descriptor
 *    is not listened by the scheduler after this function.
 *
 ***/
void silc_schedule_unset_listen_fd(SilcSchedule schedule, int fd);

/****f* silcutil/SilcScheduleAPI/silc_schedule
 *
 * SYNOPSIS
 *
 *    void silc_schedule(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    The SILC scheduler. This is actually the main routine in SILC programs.
 *    When this returns the program is to be ended. Before this function can
 *    be called, one must call silc_schedule_init function.
 *
 ***/
void silc_schedule(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule
 *
 * SYNOPSIS
 *
 *    bool silc_schedule_one(SilcSchedule schedule, int block);
 *
 * DESCRIPTION
 *
 *    Same as the silc_schedule but runs the scheduler only one round
 *    and then returns.  This function is handy when the SILC scheduler
 *    is used inside some other external scheduler, for example.  If
 *    the `timeout_usecs' is positive a timeout will be added to the
 *    scheduler.  The function will not return in this timeout unless
 *    some other event occurs.
 *
 ***/
bool silc_schedule_one(SilcSchedule schedule, int timeout_usecs);

/****f* silcutil/SilcScheduleAPI/silc_schedule_wakeup
 *
 * SYNOPSIS
 *
 *    void silc_schedule_wakeup(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Wakes up the scheduler. This is used only in multi-threaded
 *    environments where threads may add new tasks or remove old tasks
 *    from task queues. This is called to wake up the scheduler in the
 *    main thread so that it detects the changes in the task queues.
 *    If threads support is not compiled in this function has no effect.
 *    Implementation of this function may be platform specific.
 *
 ***/
void silc_schedule_wakeup(SilcSchedule schedule);

#endif
