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

/****h* silcutil/SILC Mutex Interface
 *
 * DESCRIPTION
 *
 * Interface for mutual exclusion locks and read/write locks.  This is
 * platform independent interface for applications that need concurrency
 * control.
 *
 ***/

#ifndef SILCMUTEX_H
#define SILCMUTEX_H

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

/****s* silcutil/SilcMutexAPI/SilcRwLock
 *
 * NAME
 *
 *    typedef struct SilcRwLockStruct *SilcRwLock;
 *
 * DESCRIPTION
 *
 *    This context is the actual SILC read/write lock and is allocated
 *    by silc_rwlock_alloc and given as argument to all silc_rwlock_*
 *    functions.  It is freed by the silc_rwlock_free function.
 *
 ***/
typedef struct SilcRwLockStruct *SilcRwLock;

/****f* silcutil/SilcMutexAPI/silc_mutex_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_mutex_alloc(SilcMutex *mutex);
 *
 * DESCRIPTION
 *
 *    Allocates SILC Mutex object.  The mutex object must be allocated
 *    before it can be used.  It is freed by the silc_mutex_free function.
 *    This returns TRUE and allocated mutex in to the `mutex' and FALSE
 *    on error.  If threads support is not compiled in this returns FALSE,
 *    but should not be considered as an error.
 *
 ***/
SilcBool silc_mutex_alloc(SilcMutex *mutex);

/****f* silcutil/SilcMutexAPI/silc_mutex_free
 *
 * SYNOPSIS
 *
 *    void silc_mutex_free(SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Free SILC Mutex object and frees all allocated memory.  If `mutex'
 *    is NULL this function has no effect.
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
 *    silc_mutex_unlock for the mutex.  If `mutex' is NULL this function
 *    has no effect.
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
 *    may be waiting for the lock.  If `mutex' is NULL this function
 *    has no effect.
 *
 * NOTES
 *
 *    The caller must not call the silc_mutex_unlock for an unlocked
 *    mutex or mutex not locked by the current thread.
 *
 ***/
void silc_mutex_unlock(SilcMutex mutex);

/****f* silcutil/SilcMutexAPI/silc_mutex_assert_locked
 *
 * SYNOPSIS
 *
 *    void silc_mutex_assert_locked(SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Asserts that the `mutex' is locked.  It is fatal error if the mutex
 *    is not locked.  If debugging is not compiled in this function has
 *    no effect (SILC_DEBUG define).
 *
 ***/
void silc_mutex_assert_locked(SilcMutex mutex);

/****f* silcutil/SilcMutexAPI/silc_rwlock_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_rwlock_alloc(SilcRwLock *rwlock);
 *
 * DESCRIPTION
 *
 *    Allocates SILC read/write lock.  The read/write lock must be allocated
 *    before it can be used.  It is freed by the silc_rwlock_free function.
 *    This returns TRUE and allocated read/write lock in to the `rwlock' and
 *    FALSE on error.
 *
 ***/
SilcBool silc_rwlock_alloc(SilcRwLock *rwlock);

/****f* silcutil/SilcRwLockAPI/silc_rwlock_free
 *
 * SYNOPSIS
 *
 *    void silc_rwlock_free(SilcRwLock rwlock);
 *
 * DESCRIPTION
 *
 *    Free SILC Rwlock object and frees all allocated memory.  If `rwlock'
 *    is NULL this function has no effect.
 *
 ***/
void silc_rwlock_free(SilcRwLock rwlock);

/****f* silcutil/SilcRwLockAPI/silc_rwlock_rdlock
 *
 * SYNOPSIS
 *
 *    void silc_rwlock_rdlock(SilcRwLock rwlock);
 *
 * DESCRIPTION
 *
 *    Acquires read lock of the read/write lock `rwlock'.  If the `rwlock'
 *    is locked by a writer the current thread will block until the other
 *    thread has issued silc_rwlock_unlock for the `rwlock'.  This function
 *    may be called multiple times to acquire the read lock.  There must be
 *    same amount of silc_rwlock_unlock calls.  If `rwlock' is NULL this
 *    function has no effect.
 *
 ***/
void silc_rwlock_rdlock(SilcRwLock rwlock);

/****f* silcutil/SilcRwLockAPI/silc_rwlock_wrlock
 *
 * SYNOPSIS
 *
 *    void silc_rwlock_wrlock(SilcRwLock rwlock);
 *
 * DESCRIPTION
 *
 *    Acquires write lock of the read/write lock `rwlock'.  If the `rwlock'
 *    is locked by a writer or a reader the current thread will block until
 *    the other thread(s) have issued silc_rwlock_unlock for the `rwlock'.
 *    If `rwlock' is NULL this function has no effect.
 *
 ***/
void silc_rwlock_wrlock(SilcRwLock rwlock);

/****f* silcutil/SilcRwLockAPI/silc_rwlock_unlock
 *
 * SYNOPSIS
 *
 *    void silc_rwlock_unlock(SilcRwLock rwlock);
 *
 * DESCRIPTION
 *
 *    Releases the lock of the read/write lock `rwlock'.  If `rwlock' was
 *    locked by a writer this will release the writer lock.  Otherwise this
 *    releases the reader lock.  If `rwlock' is NULL this function has no
 *    effect.
 *
 ***/
void silc_rwlock_unlock(SilcRwLock rwlock);

#endif
