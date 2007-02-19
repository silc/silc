/*

  silccond.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Condition Variable Interface
 *
 * DESCRIPTION
 *
 * A condition variable interface for multi-thread synchronization.
 * Condition variables enable threads to suspend execution and yield
 * the processors until some predicate on some shared data is satisfied.
 *
 ***/

#ifndef SILCCOND_H
#define SILCCOND_H

/****s* silcutil/SilcCondAPI/SilcCond
 *
 * NAME
 *
 *    typedef struct SilcCondStruct *SilcCond;
 *
 * DESCRIPTION
 *
 *    This context is the actual condition variable and is allocated
 *    by silc_cond_alloc and given as argument to all silc_cond_*
 *    functions.  It is freed by the silc_cond_free function.
 *
 ***/
typedef struct SilcCondStruct *SilcCond;

/****s* silcutil/SilcCondAPI/silc_cond_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cond_alloc(SilcCond *cond);
 *
 * DESCRIPTION
 *
 *    Allocates SILC Condition variable context.  The condition must
 *    be allocated before it can be used.  It is freed by the
 *    silc_cond_free function.  This returns TRUE and allocated
 *    condition in to the `cond' pointer and FALSE on error.
 *
 ***/
SilcBool silc_cond_alloc(SilcCond *cond);

/****s* silcutil/SilcCondAPI/silc_cond_free
 *
 * SYNOPSIS
 *
 *    void silc_cond_free(SilcCond cond);
 *
 * DESCRIPTION
 *
 *    Free condition variable context.  If `cond' is NULL this function
 *    has no effect.
 *
 ***/
void silc_cond_free(SilcCond cond);

/****s* silcutil/SilcCondAPI/silc_cond_wait
 *
 * SYNOPSIS
 *
 *    void silc_cond_wait(SilcCond cond, SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Waits for condition variable `cond' to be signalled.  This function
 *    will block the calling thread until the condition variable is
 *    signalled.  The `mutex' must be locked before calling this function.
 *    The `mutex' will be unlocked inside this function.  After this
 *    function returns the `mutex' is in locked state again.
 *
 * EXAMPLE
 *
 *    silc_mutex_lock(lock);
 *    while (c->a == NULL)
 *      silc_cond_wait(cond, lock);
 *    ...
 *    silc_mutex_unlock(lock);
 *
 ***/
void silc_cond_wait(SilcCond cond, SilcMutex mutex);

/****s* silcutil/SilcCondAPI/silc_cond_timedwait
 *
 * SYNOPSIS
 *
 *    void silc_cond_timedwait(SilcCond cond, SilcMutex mutex, int timeout);
 *
 * DESCRIPTION
 *
 *    Waits for condition variable `cond' to be signalled or for the
 *    `timeout' to expire.  The timeout is in milliseconds.  If it is 0
 *    no timeout exist.  Returns FALSE if timeout expired, TRUE when
 *    signalled.  This function will block the calling thread until the
 *    condition variable is signalled.  The `mutex' must be locked before
 *    calling this function.  The `mutex' will be unlocked inside this
 *    function.  After this function returns the `mutex' is in locked
 *    state again.
 *
 ***/
SilcBool silc_cond_timedwait(SilcCond cond, SilcMutex mutex, int timeout);

/****s* silcutil/SilcCondAPI/silc_cond_signal
 *
 * SYNOPSIS
 *
 *    void silc_cond_signal(SilcCond cond);
 *
 * DESCRIPTION
 *
 *    Signals a waiting thread and wakes it up.  If there are no waiters
 *    this function has no effect.  In case of multiple waiters only one
 *    is signalled.  To signal all of them use silc_cond_broadcast.
 *
 * NOTES
 *
 *    Before calling this function the mutex used with the silc_cond_wait
 *    must be acquired.
 *
 * EXAMPLE
 *
 *    silc_mutex_lock(lock);
 *    c->a = context;
 *    silc_cond_signal(cond);
 *    silc_mutex_unlock(lock);
 *
 ***/
void silc_cond_signal(SilcCond cond);

/****s* silcutil/SilcCondAPI/silc_cond_broadcast
 *
 * SYNOPSIS
 *
 *    void silc_cond_broadcast(SilcCond cond);
 *
 * DESCRIPTION
 *
 *    Signals and wakes up all waiters.  If there are no waiters this
 *    function has no effect.
 *
 * NOTES
 *
 *    Before calling this function the mutex used with the silc_cond_wait
 *    must be acquired.
 *
 ***/
void silc_cond_broadcast(SilcCond cond);

#endif /* SILCCOND_H */
