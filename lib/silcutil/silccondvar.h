/*

  silccondvar.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Conditional Variable Interface
 *
 * DESCRIPTION
 *
 * A conditional variable interface for multi-thread synchronization.
 * Conditional variables enable threads to suspend execution and yield
 * the processors until some predicate on some shared data is satisfied.
 *
 ***/

#ifndef SILCCONDVAR_H
#define SILCCONDVAR_H

/****s* silcutil/SilcCondVarAPI/SilcCondVar
 *
 * NAME
 *
 *    typedef struct SilcCondVarStruct *SilcCondVar;
 *
 * DESCRIPTION
 *
 *    This context is the actual conditional variable and is allocated
 *    by silc_condvar_alloc and given as argument to all silc_condvar_*
 *    functions.  It is freed by the silc_condvar_free function.
 *
 ***/
typedef struct SilcCondVarStruct *SilcCondVar;

/****s* silcutil/SilcCondVarAPI/silc_condvar_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_condvar_alloc(SilcCondVar *cond);
 *
 * DESCRIPTION
 *
 *    Allocates SILC Conditional variable context.  The conditional must
 *    be allocated before it can be used.  It is freed by the
 *    silc_condvar_free function.  This returns TRUE and allocated
 *    conditional in to the `cond' pointer and FALSE on error.
 *
 ***/
SilcBool silc_condvar_alloc(SilcCondVar *cond);

/****s* silcutil/SilcCondVarAPI/silc_condvar_free
 *
 * SYNOPSIS
 *
 *    void silc_condvar_free(SilcCondVar cond);
 *
 * DESCRIPTION
 *
 *    Free conditional variable context.  If `cond' is NULL this function
 *    has no effect.
 *
 ***/
void silc_condvar_free(SilcCondVar cond);

/****s* silcutil/SilcCondVarAPI/silc_condvar_wait
 *
 * SYNOPSIS
 *
 *    void silc_condvar_wait(SilcCondVar cond, SilcMutex mutex);
 *
 * DESCRIPTION
 *
 *    Waits for conditional variable `cond' to be signalled.  This function
 *    will block the calling thread until the conditional variable is
 *    signalled.  The `mutex' must be locked before calling this function.
 *    The `mutex' will be unlocked inside this function.  After this
 *    function returns the `mutex' is in locked state again.
 *
 * EXAMPLE
 *
 *    silc_mutex_lock(lock);
 *    while (c->a == NULL)
 *      silc_condvar_wait(cond, lock);
 *    ...
 *    silc_mutex_unlock(lock);
 *
 ***/
void silc_condvar_wait(SilcCondVar cond, SilcMutex mutex);

/****s* silcutil/SilcCondVarAPI/silc_condvar_timedwait
 *
 * SYNOPSIS
 *
 *    void silc_condvar_timedwait(SilcCondVar cond, SilcMutex mutex,
 *                                struct timespec *timeout);
 *
 * DESCRIPTION
 *
 *    Waits for conditional variable `cond' to be signalled or for the
 *    `timeout' to expire.  The timeout is in milliseconds.  If it is 0
 *    no timeout exist.  Returns FALSE if timeout expired, TRUE when
 *    signalled.  This function will block the calling thread until the
 *    conditional variable is signalled.  The `mutex' must be locked before
 *    calling this function.  The `mutex' will be unlocked inside this
 *    function.  After this function returns the `mutex' is in locked
 *    state again.
 *
 ***/
SilcBool silc_condvar_timedwait(SilcCondVar cond, SilcMutex mutex,
				int timeout);

/****s* silcutil/SilcCondVarAPI/silc_condvar_signal
 *
 * SYNOPSIS
 *
 *    void silc_condvar_signal(SilcCondVar cond);
 *
 * DESCRIPTION
 *
 *    Signals a waiting thread and wakes it up.  If there are no waiters
 *    this function has no effect.  In case of multiple waiters only one
 *    is signalled.  To signal all of them use silc_condvar_broadcast.
 *
 * NOTES
 *
 *    Before calling this function the mutex used with the silc_condvar_wait
 *    must be acquired.
 *
 * EXAMPLE
 *
 *    silc_mutex_lock(lock);
 *    c->a = context;
 *    silc_condvar_signal(cond);
 *    silc_mutex_unlock(lock);
 *
 ***/
void silc_condvar_signal(SilcCondVar cond);

/****s* silcutil/SilcCondVarAPI/silc_condvar_broadcast
 *
 * SYNOPSIS
 *
 *    void silc_condvar_broadcast(SilcCondVar cond);
 *
 * DESCRIPTION
 *
 *    Signals and wakes up all waiters.  If there are no waiters this
 *    function has no effect.
 *
 * NOTES
 *
 *    Before calling this function the mutex used with the silc_condvar_wait
 *    must be acquired.
 *
 ***/
void silc_condvar_broadcast(SilcCondVar cond);

#endif /* SILCCONDVAR_H */
