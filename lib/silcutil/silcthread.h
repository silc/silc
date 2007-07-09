/*

  silcmutex.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Thread Interface
 *
 * DESCRIPTION
 *
 * Interface for platform independent thread implementation and thread pool
 * system.  The interface provides routines for applications that need
 * concurrent execution with the application's main thread.  The threads
 * created with this interface executes concurrently with the calling thread.
 *
 * The thread pool system can be used to start many threads and execute code
 * in the threads.  The thread pool manages the threads creation and
 * destruction.
 *
 ***/

#ifndef SILCTHREAD_H
#define SILCTHREAD_H

#include "silcschedule.h"

/* Prototypes */

/****s* silcutil/SilcThreadAPI/SilcThread
 *
 * NAME
 *
 *    typedef struct SilcThreadStruct *SilcThread;
 *
 * DESCRIPTION
 *
 *    This context is the actual SILC Thread and is returned by
 *    the silc_thread_create functions, and given as arguments to
 *    some of the silc_thread_* functions. This context and its
 *    resources are released automatically when the thread exits.
 *
 ***/
typedef void *SilcThread;

/****f* silcutil/SilcThreadAPI/SilcThreadStart
 *
 * SYNOPSIS
 *
 *    typedef void *(*SilcThreadStart)(void *context);
 *
 * DESCRIPTION
 *
 *    A callback function that is called when the thread is created
 *    by the silc_thread_create function.  This returns the return value
 *    of the thread. If another thread is waiting this thread's
 *    destruction with silc_thread_wait the returned value is passed
 *    to that thread. The thread is destroyed when this function
 *    returns.
 *
 ***/
typedef void *(*SilcThreadStart)(void *context);

/****f* silcutil/SilcThreadAPI/silc_thread_create
 *
 * SYNOPSIS
 *
 *    SilcThread silc_thread_create(SilcThreadStart start_func,
 *                                  void *context, SilcBool waitable);
 * DESCRIPTION
 *
 *    Creates a new thread. The `start_func' with `context' will be
 *    called if the thread was created. This function returns a pointer
 *    to the thread or NULL if the thread could not be created.  All
 *    resources of the returned pointer is freed automatically when the
 *    thread exits.
 *
 *    If the `waitable' is set to TRUE then another thread can wait
 *    this thread's destruction with silc_thread_wait. If it is set to
 *    FALSE the thread is not waitable.
 *
 * NOTES
 *
 *    If the `waitable' is TRUE the thread's resources are not freed
 *    when it exits until another thread has issued silc_thread_wait.
 *    If the `waitable' is TRUE then another thread must always issue
 *    silc_thread_wait to avoid memory leaks.
 *
 *    On Symbian Cleanup Stack is created and new Active Scheduler is
 *    installed automatically for the created thread.  The thread also
 *    shares heap with the calling thread.
 *
 ***/
SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable);

/****f* silcutil/SilcThreadAPI/silc_thread_exit
 *
 * SYNOPSIS
 *
 *    void silc_thread_exit(void *exit_value);
 *
 * DESCRIPTION
 *
 *    Exits the current thread. This can be called to explicitly exit
 *    the thread with `exit_value'. Another way to exit (destroy) the
 *    current thread is to return from the SilcThreadStart function
 *    with exit value. The exit value is passed to another thread if it
 *    is waiting it with silc_thread_wait function.
 *
 ***/
void silc_thread_exit(void *exit_value);

/****f* silcutil/SilcThreadAPI/silc_thread_self
 *
 * SYNOPSIS
 *
 *    SilcThread silc_thread_self(void);
 *
 * DESCRIPTION
 *
 *    Returns a pointer to the current thread.
 *
 ***/
SilcThread silc_thread_self(void);

/****f* silcutil/SilcThreadAPI/silc_thread_wait
 *
 * SYNOPSIS
 *
 *    SilcBool silc_thread_wait(SilcThread thread, void **exit_value);
 *
 * DESCRIPTION
 *
 *    Waits until the thread indicated by `thread' finishes. This blocks
 *    the execution of the current thread. The thread is finished if it
 *    calls silc_thread_exit or is destroyed naturally. When the thread
 *    exits its exit value is saved to `exit_value' and TRUE is returned.
 *    If the `thread' is not waitable this will return immediately with
 *    FALSE value.
 *
 ***/
SilcBool silc_thread_wait(SilcThread thread, void **exit_value);

/****f* silcutil/SilcThreadAPI/silc_thread_yield
 *
 * SYNOPSIS
 *
 *    void silc_thread_yield(void);
 *
 * DESCRIPTION
 *
 *    Yield the processor.  The calling thread will yield the processor and
 *    give execution time for other threads, until its turn comes up again.
 *
 ***/
void silc_thread_yield(void);

/****s* silcutil/SilcThreadAPI/SilcThreadPool
 *
 * NAME
 *
 *    typedef struct SilcThreadPoolStruct *SilcThreadPool;
 *
 * DESCRIPTION
 *
 *    This context is the actual SILC Thread Pool and is returned by
 *    the silc_thread_pool_alloc function, and given as arguments to
 *    some of the silc_thread_pool_* functions. This context and its
 *    resources are freed by calling silc_thread_pool_free;
 *
 ***/
typedef struct SilcThreadPoolStruct *SilcThreadPool;

/****f* silcutil/SilcThreadAPI/SilcThreadPoolFunc
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcThreadPoolFunc)(SilcSchedule schedule,
 *                                       void *context);
 *
 * DESCRIPTION
 *
 *    A callback function of this type is given as argument to the
 *    silc_thread_pool_run.  The `schedule' is the scheduler and the
 *    `context' is the `run_context' given as argument to
 *    silc_thread_pool_run.
 *
 ***/
typedef void (*SilcThreadPoolFunc)(SilcSchedule schedule, void *context);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_alloc
 *
 * SYNOPSIS
 *
 *    SilcThreadPool silc_thread_pool_alloc(SilcStack stack,
 *                                          SilcUInt32 min_threads,
 *                                          SilcUInt32 max_threads,
 *                                          SilcBool start_min_threads);
 *
 * DESCRIPTION
 *
 *    Allocate thread pool with at least `min_threads' and at most
 *    `max_threads' many threads. If `start_min_threads' is TRUE this will
 *    start `min_threads' many threads immediately.  Returns the thread
 *    pool context or NULL on error.  If `stack' is non-NULL memory is
 *    allocated from `stack'.  When the thread pool is freed the memory
 *    is returned to `stack'.
 *
 * EXAMPLE
 *
 *    // Start thread pool, by default it has 0 threads.
 *    pool = silc_thread_pool_alloc(NULL, 0, 5, FALSE);
 *
 *    // Function to execute in a thread
 *    void my_func(SilcSchedule schedule, void *context)
 *    {
 *      MyContext mycontext = context;
 *      ...
 *    }
 *
 *    // Execute code in a thread in the pool
 *    silc_thread_pool_run(pool, TRUE, NULL, my_func, my_context, NULL, NULL);
 *
 ***/
SilcThreadPool silc_thread_pool_alloc(SilcStack stack,
				      SilcUInt32 min_threads,
				      SilcUInt32 max_threads,
				      SilcBool start_min_threads);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_free
 *
 * SYNOPSIS
 *
 *    void silc_thread_pool_free(SilcThreadPool tp, SilcBool wait_unfinished);
 *
 * DESCRIPTION
 *
 *     Free the thread pool.  If `wait_unfinished' is TRUE this will block
 *     and waits that all remaining active threads finish before freeing
 *     the pool.
 *
 ***/
void silc_thread_pool_free(SilcThreadPool tp, SilcBool wait_unfinished);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_run
 *
 * SYNOPSIS
 *
 *    SilcBool silc_thread_pool_run(SilcThreadPool tp,
 *                                  SilcBool queueable,
 *                                  SilcSchedule schedule,
 *                                  SilcThreadPoolFunc run,
 *                                  void *run_context,
 *                                  SilcTaskCallback completion,
 *                                  void *completion_context);
 *
 * DESCRIPTION
 *
 *    Run the `run' function with `run_context' in one of the threads in the
 *    thread pool.  Returns FALSE if the thread pool is being freed.  If
 *    there are no free threads left in the pool this will queue the `run'
 *    and call it once a thread becomes free, if `queueable' is TRUE.  If
 *    `queueable' is FALSE and there are no free threads, this returns FALSE
 *    and `run' is not executed.
 *
 *    If `completion' is non-NULL it will be called to indicate completion
 *    of the `run' function.  If `schedule' is non-NULL the `completion'
 *    will be called through the scheduler in the main thread.  If it is
 *    NULL the `completion' is called directly from the thread after the
 *    `run' has returned.
 *
 ***/
SilcBool silc_thread_pool_run(SilcThreadPool tp,
			      SilcBool queue,
			      SilcSchedule schedule,
			      SilcThreadPoolFunc run,
			      void *run_context,
			      SilcTaskCallback completion,
			      void *completion_context);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_set_max_threads
 *
 * SYNOPSIS
 *
 *    void silc_thread_pool_set_max_threads(SilcThreadPool tp,
 *                                          SilcUInt32 max_threads);
 *
 * DESCRIPTION
 *
 *    Modify the amount of maximum threads of the pool.  This call does not
 *    affect any currently active or running thread.
 *
 ***/
void silc_thread_pool_set_max_threads(SilcThreadPool tp,
				      SilcUInt32 max_threads);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_get_max_threads
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_thread_pool_get_max_threads(SilcThreadPool tp);
 *
 * DESCRIPTION
 *
 *    Returns the number of maximum threads to which the pool can grow.
 *
 ***/
SilcUInt32 silc_thread_pool_get_max_threads(SilcThreadPool tp);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_num_free_threads
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_thread_pool_num_free_threads(SilcThreadPool tp);
 *
 * DESCRIPTION
 *
 *    Returns the number of free threads in the pool currently.  Free threads
 *    are threads that are not currently executing any code.
 *
 ***/
SilcUInt32 silc_thread_pool_num_free_threads(SilcThreadPool tp);

/****f* silcutil/SilcThreadAPI/silc_thread_pool_purge
 *
 * SYNOPSIS
 *
 *    void silc_thread_pool_purge(SilcThreadPool tp);
 *
 * DESCRIPTION
 *
 *    Stops all free and started threads.  The minumum amount of threads
 *    specified to silc_thread_pool_alloc always remains.  Any thread that
 *    is currently executing code is not affected by this call.
 *
 ***/
void silc_thread_pool_purge(SilcThreadPool tp);

#endif
