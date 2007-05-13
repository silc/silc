/*

  silcschedule.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Schedule Interface
 *
 * DESCRIPTION
 *
 * The SILC Scheduler is the heart of any application. The scheduler provides
 * the application's main loop that can handle incoming data, outgoing data,
 * timeouts and dispatch different kind of tasks.
 *
 * The SILC Scheduler supports file descriptor based tasks and timeout tasks.
 * File descriptor tasks are tasks that perform some operation over the
 * specified file descriptor. These include network connections, for example.
 * The timeout tasks are timeouts that are executed after the specified
 * timeout has elapsed.
 *
 * The SILC Scheduler is designed to be the sole main loop of the application
 * so that the application does not need any other main loop.  However,
 * SILC Scheduler does support running the scheduler only once, so that the
 * scheduler does not block, and thus providing a possiblity that some
 * external main loop is run over the SILC Scheduler.
 *
 * Typical application first initializes the scheduler and then registers
 * the very first tasks to the scheduler and then run the scheduler.  After
 * the scheduler's run function returns the application is considered to be
 * ended.
 *
 * On WIN32 systems the SILC Scheduler is too designed to work as the main
 * loop of the GUI application. It can handle all Windows messages and
 * it dispatches them from the scheduler, and thus makes it possible to
 * create GUI applications. The scheduler can also handle all kinds of
 * WIN32 handles, this includes sockets created by the SILC Net API routines,
 * WSAEVENT handle objects created by Winsock2 routines and arbitrary
 * WIN32 HANDLE objects.
 *
 * The SILC Scheduler supports multi-threads as well. The actual scheduler
 * must be run in single-thread but other threads may register new tasks
 * and unregister old tasks.  However, it is enforced that the actual
 * task is always run in the main thread.  The scheduler is context based
 * which makes it possible to allocate several schedulers for one application.
 * Since the scheduler must be run in single-thread, a multi-threaded
 * application could be created by allocating own scheduler for each of the
 * worker threads.
 *
 ***/

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

/****s* silcutil/SilcScheduleAPI/SilcTask
 *
 * NAME
 *
 *    typedef struct SilcTaskStruct *SilcTask;
 *
 * DESCRIPTION
 *
 *    This object represents one task in the scheduler.  It is allocated
 *    by the silc_schedule_task_add function and freed by one of the
 *    silc_schedule_task_del* functions.
 *
 ***/
typedef struct SilcTaskStruct *SilcTask;

/****d* silcutil/SilcScheduleAPI/SilcTaskEvent
 *
 * NAME
 *
 *    typedef enum { ... } SilcTaskEvent;
 *
 * DESCRIPTION
 *
 *    SILC Task event types.  The event type indicates the occurred
 *    event of the task.  This type will be given as argument to the
 *    SilcTaskCallback function to indicate the event for the caller.
 *    The SILC_TASK_READ and SILC_TASK_WRITE may be set by the caller
 *    of the silc_schedule_set_listen_fd, if the caller needs to control
 *    the events for the task. The SILC_TASK_EXPIRE is set always only
 *    by the scheduler when timeout expires for timeout task.  The
 *    SILC_TASK_INTERRUPT is set for signal callback.
 *
 * SOURCE
 */
typedef enum {
  SILC_TASK_READ         = 0x0001,	         /* Reading */
  SILC_TASK_WRITE        = 0x0002,		 /* Writing */
  SILC_TASK_EXPIRE       = 0x0004,		 /* Timeout */
  SILC_TASK_INTERRUPT    = 0x0008,		 /* Signal */
} SilcTaskEvent;
/***/

/****f* silcutil/SilcScheduleAPI/SilcTaskCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcTaskCallback)(SilcSchedule schedule,
 *                                     void *app_context,
 *                                     SilcTaskEvent type, SilcUInt32 fd,
 *                                     void *context);
 *
 * DESCRIPTION
 *
 *    The task callback function.  This function will be called by the
 *    scheduler when some event of the task is performed.  For example,
 *    when data is available from the connection this will be called.
 *
 *    The `schedule' is the scheduler context, the `type' is the indicated
 *    event, the `fd' is the file descriptor of the task and the `context'
 *    is a caller specified context. If multiple events occurred this
 *    callback is called separately for all events.  The `app_context'
 *    is application specific context that was given as argument to the
 *    silc_schedule_init function.  If the task is timeout task then `fd'
 *    is zero (0).
 *
 *    To specify task callback function in the application using the
 *    SILC_TASK_CALLBACK macro is recommended.
 *
 *    The callback should not perform lenghty or blocking operations as
 *    this would also block all other waiting tasks.  The task callback
 *    should either handle the operation fast or issue an asynchronous
 *    call (like to register 0 timeout task) to handle it later.
 *
 ***/
typedef void (*SilcTaskCallback)(SilcSchedule schedule, void *app_context,
				 SilcTaskEvent type, SilcUInt32 fd,
				 void *context);

/* Macros */

/****d* silcutil/SilcScheduleAPI/SILC_ALL_TASKS
 *
 * NAME
 *
 *    #define SILC_ALL_TASKS ...
 *
 * DESCRIPTION
 *
 *    Marks for all tasks in the scheduler. This can be passed to
 *    silc_schedule_task_del function to delete all tasks at once.
 *
 * SOURCE
 */
#define SILC_ALL_TASKS ((SilcTask)1)
/***/

/****d* silcutil/SilcScheduleAPI/SILC_TASK_CALLBACK
 *
 * NAME
 *
 *    #define SILC_TASK_CALLBACK ...
 *
 * DESCRIPTION
 *
 *    Generic macro to define task callback functions. This defines a
 *    static function with name `func' as a task callback function.
 *
 * SOURCE
 */
#define SILC_TASK_CALLBACK(func)					\
void func(SilcSchedule schedule, void *app_context, SilcTaskEvent type,	\
	  SilcUInt32 fd, void *context)
/***/

/* Prototypes */

#include "silcschedule_i.h"

/****f* silcutil/SilcScheduleAPI/silc_schedule_init
 *
 * SYNOPSIS
 *
 *    SilcSchedule silc_schedule_init(int max_tasks, void *app_context);
 *
 * DESCRIPTION
 *
 *    Initializes the scheduler. This returns the scheduler context that
 *    is given as argument usually to all silc_schedule_* functions.
 *    The `app_context' is application specific context that is delivered
 *    to all task callbacks. The caller must free that context.  The
 *    'app_context' can be for example the application itself.
 *
 *    The `max_tasks' is the maximum number of file descriptor and socket
 *    tasks in the scheduler.  Set value to 0 to use default.  Operating
 *    system will enforce the final limit.  On some operating systems the
 *    limit can be significantly increased when this function is called in
 *    priviliged mode (as super user).
 *
 ***/
SilcSchedule silc_schedule_init(int max_tasks, void *app_context);

/****f* silcutil/SilcScheduleAPI/silc_schedule_uninit
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_uninit(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Uninitializes the scheduler. This is called when the program is ready
 *    to end. This removes all tasks from the scheduler. Returns FALSE if the
 *    scheduler could not be uninitialized. This happens when the scheduler
 *    is still valid and silc_schedule_stop has not been called.
 *
 ***/
SilcBool silc_schedule_uninit(SilcSchedule schedule);

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
 *    silc_schedule has returned).  After this is called it is guaranteed
 *    that next time the scheduler enters the main loop it will be stopped.
 *    However, untill it enters the main loop it will not detect that
 *    it is stopped for example if this is called from another thread.
 *
 ***/
void silc_schedule_stop(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule
 *
 * SYNOPSIS
 *
 *    void silc_schedule(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    The SILC scheduler. The program will run inside this function.
 *    When this returns the program is to be ended. Before this function can
 *    be called, one must call silc_schedule_init function.
 *
 * NOTES
 *
 *    On Windows this will block the program, but will continue dispatching
 *    window messages, and thus can be used as the main loop of the program.
 *
 *    On Symbian this will return immediately.  On Symbian calling
 *    silc_schedule is same as calling silc_schedule_one.  This also means
 *    the caller must be already running Symbian Active Scheduler.
 *
 ***/
void silc_schedule(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule_one
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_one(SilcSchedule schedule, int timeout_usecs);
 *
 * DESCRIPTION
 *
 *    Same as the silc_schedule but runs the scheduler only one round
 *    and then returns.  This function is handy when the SILC scheduler
 *    is used inside some other external scheduler, for example.  If
 *    the `timeout_usecs' is non-negative a timeout will be added to the
 *    scheduler.  The function will not return in this timeout unless
 *    some other event occurs.
 *
 *    Typically this would be called from a timeout or idle task
 *    periodically (typically from 5-50 ms) to schedule SILC tasks.  In
 *    this case the `timeout_usecs' is usually 0 to make the function
 *    return immediately.
 *
 ***/
SilcBool silc_schedule_one(SilcSchedule schedule, int timeout_usecs);

/****f* silcutil/SilcScheduleAPI/silc_schedule_wakeup
 *
 * SYNOPSIS
 *
 *    void silc_schedule_wakeup(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Wakes up the scheduler. This is may be used in multi-threaded
 *    environments where threads may add new tasks or remove old tasks
 *    from the scheduler. This is called to wake up the scheduler in the
 *    main thread so that it detects the changes in the scheduler.
 *    If threads support is not compiled in this function has no effect.
 *
 ***/
void silc_schedule_wakeup(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule_get_context
 *
 * SYNOPSIS
 *
 *    void *silc_schedule_get_context(SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Returns the application specific context that was saved into the
 *    scheduler in silc_schedule_init function.  The context is also
 *    returned to application in the SilcTaskCallback, but this function
 *    may be used to get it as well if needed.
 *
 ***/
void *silc_schedule_get_context(SilcSchedule schedule);

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_add_fd
 *
 * SYNOPSIS
 *
 *    SilcTask
 *    silc_schedule_task_add_fd(SilcSchedule schedule, SilcUInt32 fd,
 *                              SilcTaskCallback callback, void *context);
 *
 * DESCRIPTION
 *
 *    Add file descriptor task to scheduler.  The `fd' may be either real
 *    file descriptor, socket or on some platforms an opaque file descriptor
 *    handle.  To receive events for the file descriptor set the correct
 *    request events with silc_schedule_set_listen_fd function.
 *
 *    The task will be initially set for SILC_TASK_READ events.  Setting that
 *    event immediately after this call returns is not necessary.
 *
 *    This returns the new task or NULL on error.  If a task with `fd' has
 *    already been added this will return the existing task pointer.
 *
 ***/
#define silc_schedule_task_add_fd(schedule, fd, callback, context)	\
  silc_schedule_task_add(schedule, fd, callback, context, 0, 0,	SILC_TASK_FD)

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_add_timeout
 *
 * SYNOPSIS
 *
 *    SilcTask
 *    silc_schedule_task_add_timeout(SilcSchedule schedule,
 *                                   SilcTaskCallback callback, void *context,
 *                                   long seconds, long useconds);
 *
 * DESCRIPTION
 *
 *    Add timeout task to scheduler.  The `callback' will be called once
 *    the specified timeout has elapsed.  The task will be removed from the
 *    scheduler automatically once the task expires.  The event returned
 *    to the `callback' is SILC_TASK_EXPIRE.  The task added with zero (0)
 *    timeout will be executed immediately next time tasks are scheduled.
 *
 ***/
#define silc_schedule_task_add_timeout(schedule, callback, context, s, u) \
  silc_schedule_task_add(schedule, 0, callback, context, s, u,		\
                         SILC_TASK_TIMEOUT)

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_add_signal
 *
 * SYNOPSIS
 *
 *    SilcTask
 *    silc_schedule_task_add_signal(SilcSchedule schedule, int signal,
 *                                  SilcTaskCallback callback, void *context);
 *
 * DESCRIPTION
 *
 *    Add platform specific process signal handler to scheduler.  On Unix
 *    systems the `signal' is one of the signal specified in signal(7).  On
 *    other platforms this function may not be available at all, and has no
 *    effect when called.  The event delivered to the `callback' is
 *    SILC_TASK_INTERRUPT.
 *
 * NOTES
 *
 *    One signal may be registered only one callback.  Adding second callback
 *    for signal that already has one will fail.
 *
 *    This function always returns NULL.  To remove signal from scheduler by
 *    the signal call silc_schedule_task_del_by_fd.
 *
 ***/
#define silc_schedule_task_add_signal(schedule, sig, callback, context) \
  silc_schedule_task_add(schedule, sig, callback, context, 0, 0,	\
			 SILC_TASK_SIGNAL)

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_del
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_task_del(SilcSchedule schedule, SilcTask task);
 *
 * DESCRIPTION
 *
 *    Deletes the `task' from the scheduler indicated by the `schedule'.
 *    After deleting the task it is guaranteed that the task callback
 *    will not be called. If the `task' is SILC_ALL_TASKS then all
 *    tasks is removed from the scheduler.  Returns always TRUE.
 *
 *    It is safe to call this function in any place. Tasks may be removed
 *    in task callbacks (including in the task's own task callback) and
 *    in multi-threaded environment in other threads as well.
 *
 ***/
SilcBool silc_schedule_task_del(SilcSchedule schedule, SilcTask task);

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_del_by_fd
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_task_del_by_fd(SilcSchedule schedule,
 *                                          SilcUInt32 fd);
 *
 * DESCRIPTION
 *
 *    Deletes a task from the scheduler by the specified `fd'.  Returns
 *    FALSE if such fd task does not exist.
 *
 *    It is safe to call this function in any place. Tasks may be removed
 *    in task callbacks (including in the task's own task callback) and
 *    in multi-threaded environment in other threads as well.
 *
 ***/
SilcBool silc_schedule_task_del_by_fd(SilcSchedule schedule, SilcUInt32 fd);

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_del_by_callback
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_task_del_by_callback(SilcSchedule schedule,
 *                                                SilcTaskCallback callback);
 *
 * DESCRIPTION
 *
 *    Deletes a task from the scheduler by the specified `callback' task
 *    callback function.  Returns FALSE if such task with such callback
 *    does not exist.
 *
 *    It is safe to call this function in any place. Tasks may be removed
 *    in task callbacks (including in the task's own task callback) and
 *    in multi-threaded environment in other threads as well.
 *
 ***/
SilcBool silc_schedule_task_del_by_callback(SilcSchedule schedule,
					    SilcTaskCallback callback);

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_del_by_context
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_task_del_by_context(SilcSchedule schedule,
 *                                               void *context);
 *
 * DESCRIPTION
 *
 *    Deletes a task from the scheduler by the specified `context'.  Returns
 *    FALSE if such task with such context does not exist.
 *
 *    It is safe to call this function in any place. Tasks may be removed
 *    in task callbacks (including in the task's own task callback) and
 *    in multi-threaded environment in other threads as well.
 *
 ***/
SilcBool silc_schedule_task_del_by_context(SilcSchedule schedule,
					   void *context);

/****f* silcutil/SilcScheduleAPI/silc_schedule_task_del_by_all
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_task_del_by_all(SilcSchedule schedule, int fd,
 *                                           SilcTaskCallback callback,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    Deletes a task from the scheduler by the specified `fd', `callback'
 *    and `context'.  Returns FALSE if such task does not exist.
 *
 *    It is safe to call this function in any place. Tasks may be removed
 *    in task callbacks (including in the task's own task callback) and
 *    in multi-threaded environment in other threads as well.
 *
 ***/
SilcBool silc_schedule_task_del_by_all(SilcSchedule schedule, int fd,
				       SilcTaskCallback callback,
				       void *context);

/****f* silcutil/SilcScheduleAPI/silc_schedule_set_listen_fd
 *
 * SYNOPSIS
 *
 *    SilcBool silc_schedule_set_listen_fd(SilcSchedule schedule,
 *                                         SilcUInt32 fd,
 *                                         SilcTaskEvent mask,
 *                                         SilcBool send_events);
 *
 * DESCRIPTION
 *
 *    Sets a file descriptor `fd' to be listened by the scheduler for
 *    `mask' events.  To tell scheduler not to listen anymore for this
 *    file descriptor call the silc_schedule_unset_listen_fd function.
 *    When new task is created with silc_schedule_task_add the event
 *    for the task's fd is initially set to SILC_TASK_READ. If you need
 *    to control the task's fd's events you must call this function
 *    whenever you need to change the events. This can be called multiple
 *    times to change the events.
 *
 *    If the `send_events' is TRUE then this function sends the events
 *    in `mask' to the application.  If FALSE then they are sent only
 *    after the event occurs in reality.  In normal cases the `send_events'
 *    is set to FALSE.
 *
 *    Returns FALSE if the operation could not performed and TRUE if it
 *    was a success.
 *
 ***/
SilcBool silc_schedule_set_listen_fd(SilcSchedule schedule, SilcUInt32 fd,
				     SilcTaskEvent mask, SilcBool send_events);

/****f* silcutil/SilcScheduleAPI/silc_schedule_get_fd_events
 *
 * SYNOPSIS
 *
 *    SilcTaskEvent silc_schedule_get_fd_events(SilcSchedule schedule,
 *                                              SilcUInt32 fd);
 *
 * DESCRIPTION
 *
 *    Returns the file descriptor `fd' current requested events mask,
 *    or 0 on error.
 *
 ***/
SilcTaskEvent silc_schedule_get_fd_events(SilcSchedule schedule,
					  SilcUInt32 fd);

/****f* silcutil/SilcScheduleAPI/silc_schedule_unset_listen_fd
 *
 * SYNOPSIS
 *
 *    void silc_schedule_unset_listen_fd(SilcSchedule schedule, SilcUInt32 fd);
 *
 * DESCRIPTION
 *
 *    Tells the scheduler not to listen anymore for the specified
 *    file descriptor `fd'. No events will be detected for the `fd'
 *    after calling this function.
 *
 ***/
void silc_schedule_unset_listen_fd(SilcSchedule schedule, SilcUInt32 fd);

#endif
