/*

  silcatomic.h

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

/****h* silcutil/SILC Atomic Operations Interface
 *
 * DESCRIPTION
 *
 * SILC Atomic operations interface provides utility functions to perform
 * simple operations with integers atomically.  This enables fast integer
 * additions and subtractions safely in multithreaded environment.  It is
 * especially suited for reference counters and similar and is much faster
 * than using locking.
 *
 * If threads were not enabled when compiling the source code, the operations
 * are not atomic.  On some platforms this interface actually use mutual
 * exclusion lock instead of true atomic operations, leading into some
 * performace penalty.
 *
 ***/

#ifndef SILCATOMIC_H
#define SILCATOMIC_H

/****s* silcutil/SilcAtomicAPI/SilcAtomic
 *
 * NAME
 *
 *    typedef struct { ... } SilcAtomic;
 *
 * DESCRIPTION
 *
 *    The atomic operation structure given as argument to all atomic
 *    operation functions.  It hols the actual atomic variable.  On most
 *    platforms its size is 32 bits but on some platforms it may be
 *    larger.
 *
 * EXAMPLE
 *
 *    SilcAtomic refcnt;
 *
 *    // Initialize atomic variable
 *    silc_atomic_init(&refcnt, 0);
 *
 *    ...
 *    // Increment referene counter
 *    silc_atomic_add_int(&refcnt, 1);
 *    ...
 *
 *    // Uninitialize atomic variable
 *    silc_atomic_uninit(&refcnt);
 *
 ***/
#if !defined(SILC_THREADS) || defined(SILC_WIN32) || (defined(__GNUC__) &&  \
    (defined(SILC_I486) || defined(SILC_X86_64) || defined(SILC_IA64) ||    \
     defined(SILC_POWERPC)))
typedef struct
{
  volatile SilcUInt32 value;
} SilcAtomic;
#else
#define SILC_ATOMIC_MUTEX
typedef struct
{
  volatile SilcUInt32 value;
  SilcMutex lock;
} SilcAtomic;
#endif

/****f* silcutil/SilcAtomicAPI/silc_atomic_init
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_init(SilcAtomic *atomic, int value);
 *
 * DESCRIPTION
 *
 *    Initializes the atomic variable `atomic', and sets the `value' as its
 *    inital value.  Returns FALSE on error.  To uninitialize call the
 *    silc_atomic_uninit function.
 *
 ***/

static inline
SilcBool silc_atomic_init(SilcAtomic *atomic, int value)
{
  atomic->value = value;

#if defined(SILC_ATOMIC_MUTEX)
  if (!silc_mutex_alloc(&atomic->lock))
    return FALSE;
#endif /* SILC_ATOMIC_MUTEX */

  return TRUE;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_uninit
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_uninit(SilcAtomic *atomic);
 *
 * DESCRIPTION
 *
 *    Uninitializes the atomic variable `atomic'.  This should alwyas be
 *    called after the atomic variable is not used anymore.
 *
 ***/

static inline
void silc_atomic_uninit(SilcAtomic *atomic)
{
  atomic->value = 0;
#if defined(SILC_ATOMIC_MUTEX)
  silc_mutex_free(atomic->lock);
#endif /* SILC_ATOMIC_MUTEX */
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_add_int
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_add_int(SilcAtomic *atomic, int value);
 *
 * DESCRIPTION
 *
 *    Atomically adds `value' to 32-bit integer.  Returns the value after
 *    addition.
 *
 ***/

static inline
SilcUInt32 silc_atomic_add_int(SilcAtomic *atomic, int value)
{
  SilcUInt32 ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  ret = atomic->value;
  atomic->value += value;

#elif defined(SILC_WIN32)
  /* Windows */
  ret = InterlockedExchangeAdd(&atomic->value, (LONG)value);

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
  /* GCC + i486 or x86_64 */
  __asm __volatile("lock; xaddl %0, %1"
		   : "=r" (ret), "+m" (atomic->value)
		   : "0" (value));

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  ret = __sync_fetch_and_add(&atomic->value, value);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC (code adapted from IBM's documentation) */
  /* XXX Hmm.. should I sync and isync this?... */
  __asm __volatile("0: lwarx  %0,  0, %2\n"
		   "   add    %0, %1, %0\n"
		   "   stwcx. %0,  0, %2\n"
		   "   bne-   0b"
		   : "=&r" (ret)
		   : "r" (value), "r" (&atomic->value)
		   : "cc");
  return ret;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = atomic->value;
  atomic->value += value;
  silc_mutex_unlock(atomic->lock);
#endif

  return ret + value;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_sub_int
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_sub_int(SilcAtomic *atomic, int value);
 *
 * DESCRIPTION
 *
 *    Atomically subtracts `value' from 32-bit integer.  Returns the value
 *    after subtraction.
 *
 ***/

static inline
SilcUInt32 silc_atomic_sub_int(SilcAtomic *atomic, int value)
{
  return silc_atomic_add_int(atomic, -value);
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_get_int
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_get_int(SilcAtomic *atomic);
 *
 * DESCRIPTION
 *
 *    Returns the current value of the atomic variable.
 *
 ***/

static inline
SilcUInt32 silc_atomic_get_int(SilcAtomic *atomic)
{
  SilcUInt32 ret;

#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  ret = atomic->value;
  return ret;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  __sync_synchronize();
  ret = atomic->value;
  return ret;

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  __asm("sync" : : : "memory");
  ret = atomic->value;
  return ret;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = atomic->value;
  silc_mutex_unlock(atomic->lock);
  return ret;
#endif
}

#endif /* SILCATOMIC_H */
