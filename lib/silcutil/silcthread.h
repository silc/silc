/*

  silcmutex.h
 
  Author: Pekka Riikonen <priikone@silcnet.org>
 
  Copyright (C) 2001 Pekka Riikonen
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Thread Interface
 *
 * DESCRIPTION
 *
 * Interface for SILC Thread implementation. This is platform independent
 * interface of threads for applications that need concurrent execution
 * with the application's main thread. The threads created with this 
 * interface executes concurrently with the calling thread.
 *
 ***/

#ifndef SILCTHREAD_H
#define SILCTHREAD_H

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
 *                                  void *context, bool waitable);
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
 ***/
SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      bool waitable);

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
 *    bool silc_thread_wait(SilcThread thread, void **exit_value);
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
bool silc_thread_wait(SilcThread thread, void **exit_value);

#endif
