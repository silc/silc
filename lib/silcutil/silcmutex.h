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

/****h* silcutil/SILC Mutex Interface
 *
 * DESCRIPTION
 *
 * Interface for the SILC Mutex locking implementation. This is platform
 * independent mutual exclusion interface for applications that need 
 * concurrency control.
 *
 ***/

#ifndef SILCMUTEX_H
#define SILCMUTEX_H

#if defined(SILC_THREADS)

/****s* silcutil/SilcMutexAPI/SilcMutex
 *
 * NAME
 * 
 *    typedef struct SilcMutexStruct *SilcMutex;
 *
 * DESCRIPTION
 *
 *    This context is the actual SILC Mutex and is allocated
 *    by silc_mutex_alloc and given as argument to all silc_mutex_*
 *    functions.  It is freed by the silc_mutex_free function.
 *
 ***/
typedef struct SilcMutexStruct *SilcMutex;

/****d* silcutil/SilcMutexAPI/SILC_MUTEX_DEFINE
 *
 * NAME
 * 
 *    #define SILC_MUTEX_DEFINE(name) ...
 *
 * DESCRIPTION
 *
 *    This macro is used to define new mutex.  Use this macro in an
 *    environment that can be compiled with or without the SILC Mutex
 *    API. This is equivalent to defining SilcMutex `name'; directly.
 *
 * SOURCE
 */
#define SILC_MUTEX_DEFINE(name) SilcMutex name
/***/

/****f* silcutil/SilcMutexAPI/silc_mutex_alloc
 *
 * SYNOPSIS
 *
 *    bool silc_mutex_alloc(SilcMutex *mutex);
 *
 * DESCRIPTION
 *
 *    Allocates SILC Mutex object.  The mutex object must be allocated
 *    before it can be used.  It is freed by the silc_mutex_free function.
 *    This returns TRUE and allocated mutex in to the `mutex' and FALSE
 *    on error.
 *
 ***/
bool silc_mutex_alloc(SilcMutex *mutex);

/****f* silcutil/SilcMutexAPI/silc_mutex_free
 *
 * SYNOPSIS
 *
 *    void silc_mutex_free(SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Free SILC Mutex object and frees all allocated memory.
 *
 ***/
void silc_mutex_free(SilcMutex mutex);

/****f* silcutil/SilcMutexAPI/silc_mutex_lock
 *
 * SYNOPSIS
 *
 *    void silc_mutex_lock(SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Locks the mutex. If the mutex is locked by another thread the
 *    current thread will block until the other thread has issued
 *    silc_mutex_unlock for the mutex.
 *
 * NOTES
 *
 *    The caller must not call silc_mutex_lock for mutex that has been
 *    already locked in the current thread.  In this case deadlock will
 *    occur.
 *
 ***/
void silc_mutex_lock(SilcMutex mutex);

/****f* silcutil/SilcMutexAPI/silc_mutex_unlock
 *
 * SYNOPSIS
 *
 *    void silc_mutex_unlock(SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Unlocks the mutex and thus releases it for another thread that
 *    may be waiting for the lock.
 *
 * NOTES
 *
 *    The caller must not call the silc_mutex_unlock for an unlocked
 *    mutex or mutex not locked by the current thread.  It is fatal
 *    error if this occurs.
 *
 ***/
void silc_mutex_unlock(SilcMutex mutex);

#else

#define SILC_MUTEX_DEFINE(name)
#define silc_mutex_alloc(mutex) (void)0
#define silc_mutex_free(mutex) (void)0
#define silc_mutex_lock(mutex) (void)0
#define silc_mutex_unlock(mutex) (void)0

#endif         /* SILC_THREADS */

#endif
