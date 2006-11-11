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
 * than using locking.  This interface supports 8, 16 and 32 bit integers
 * and 32 or 64 bit pointers.
 *
 * On some platforms this interface actually use mutual exclusion lock
 * instead of true atomic operations, leading into some performace penalty.
 * Also on some platforms the 8 and 16 bit integers are actually 32 bit
 * integers.
 *
 * Fast operations are supported on: x86, x86_64, ia64, PPC
 *
 ***/

#ifndef SILCATOMIC_H
#define SILCATOMIC_H

/****s* silcutil/SilcAtomicAPI/SilcAtomic32
 *
 * NAME
 *
 *    typedef struct { ... } SilcAtomic32;
 *
 * DESCRIPTION
 *
 *    The atomic operation structure given as argument to all atomic
 *    operation functions.  It hols the actual 32-bit atomic variable.
 *
 * EXAMPLE
 *
 *    SilcAtomic32 refcnt;
 *
 *    // Initialize atomic variable
 *    silc_atomic_init32(&refcnt, 0);
 *
 *    ...
 *    // Increment referene counter
 *    silc_atomic_add_int32(&refcnt, 1);
 *    ...
 *
 *    // Uninitialize atomic variable
 *    silc_atomic_uninit32(&refcnt);
 *
 ***/

/****s* silcutil/SilcAtomicAPI/SilcAtomic16
 *
 * NAME
 *
 *    typedef struct { ... } SilcAtomic16;
 *
 * DESCRIPTION
 *
 *    The atomic operation structure given as argument to all atomic
 *    operation functions.  It hols the actual 16-bit atomic variable.
 *
 * EXAMPLE
 *
 *    SilcAtomic16 refcnt;
 *
 *    // Initialize atomic variable
 *    silc_atomic_init16(&refcnt, 0);
 *
 *    ...
 *    // Increment referene counter
 *    silc_atomic_add_int16(&refcnt, 1);
 *    ...
 *
 *    // Uninitialize atomic variable
 *    silc_atomic_uninit16(&refcnt);
 *
 ***/

/****s* silcutil/SilcAtomicAPI/SilcAtomic8
 *
 * NAME
 *
 *    typedef struct { ... } SilcAtomic8;
 *
 * DESCRIPTION
 *
 *    The atomic operation structure given as argument to all atomic
 *    operation functions.  It hols the actual 8-bit atomic variable.
 *
 * EXAMPLE
 *
 *    SilcAtomic8 refcnt;
 *
 *    // Initialize atomic variable
 *    silc_atomic_init8(&refcnt, 0);
 *
 *    ...
 *    // Increment referene counter
 *    silc_atomic_add_int8(&refcnt, 1);
 *    ...
 *
 *    // Uninitialize atomic variable
 *    silc_atomic_uninit8(&refcnt);
 *
 ***/

/****s* silcutil/SilcAtomicAPI/SilcAtomicPointer
 *
 * NAME
 *
 *    typedef struct { ... } SilcAtomicPointer;
 *
 * DESCRIPTION
 *
 *    The atomic operation structure given as argument to all atomic
 *    operation functions.  It hols the actual pointer variable.
 *
 * EXAMPLE
 *
 *    SilcAtomicPointer ptr;
 *
 *    // Initialize atomic variable
 *    silc_atomic_init_pointer(&ptr, NULL);
 *
 *    ...
 *    // Set pointer
 *    silc_atomic_set_pointer(&ptr, context);
 *    ...
 *
 *    // Uninitialize atomic variable
 *    silc_atomic_uninit_pointer(&ptr);
 *
 ***/

#if !defined(SILC_THREADS) || defined(SILC_WIN32) || (defined(__GNUC__) &&  \
    (defined(SILC_I486) || defined(SILC_X86_64) || defined(SILC_IA64) ||    \
     defined(SILC_POWERPC)))
typedef struct {
  volatile SilcUInt32 value;
} SilcAtomic32;
typedef struct {
  volatile void *pointer;
} SilcAtomicPointer;
#else
#define SILC_ATOMIC_MUTEX
typedef struct {
  SilcMutex lock;
  volatile SilcUInt32 value;
} SilcAtomic32;
typedef struct {
  SilcMutex lock;
  volatile void *pointer;
} SilcAtomicPointer;
#endif

#if !defined(SILC_THREADS) || (defined(__GNUC__) && (defined(SILC_I486) ||  \
						     defined(SILC_X86_64)))
typedef struct {
  volatile SilcUInt16 value;
} SilcAtomic16;
#elif defined(SILC_WIN32) || (defined(__GNUC__) && (defined(SILC_IA64) ||   \
						    defined(SILC_POWERPC)))
typedef struct {
  volatile SilcUInt32 value;
} SilcAtomic16;
#else
typedef struct {
  SilcMutex lock;
  volatile SilcUInt16 value;
} SilcAtomic16;
#endif

#if !defined(SILC_THREADS) || (defined(__GNUC__) && (defined(SILC_I486) ||  \
						     defined(SILC_X86_64)))
typedef struct {
  volatile SilcUInt8 value;
} SilcAtomic8;
#elif defined(SILC_WIN32) || (defined(__GNUC__) && (defined(SILC_IA64) ||   \
						    defined(SILC_POWERPC)))
typedef struct {
  volatile SilcUInt32 value;
} SilcAtomic8;
#else
typedef struct {
  SilcMutex lock;
  volatile SilcUInt8 value;
} SilcAtomic8;
#endif

/****f* silcutil/SilcAtomicAPI/silc_atomic_init32
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_init32(SilcAtomic32 *atomic, SilcUInt32 value);
 *
 * DESCRIPTION
 *
 *    Initializes the atomic variable `atomic', and sets the `value' as its
 *    inital value.  Returns FALSE on error.  To uninitialize call the
 *    silc_atomic_uninit32 function.
 *
 ***/

static inline
SilcBool silc_atomic_init32(SilcAtomic32 *atomic, SilcUInt32 value)
{
  atomic->value = value;

#if defined(SILC_ATOMIC_MUTEX)
  if (!silc_mutex_alloc(&atomic->lock))
    return FALSE;
#endif /* SILC_ATOMIC_MUTEX */

  return TRUE;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_init16
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_init16(SilcAtomic16 *atomic, SilcUInt16 value);
 *
 * DESCRIPTION
 *
 *    Initializes the atomic variable `atomic', and sets the `value' as its
 *    inital value.  Returns FALSE on error.  To uninitialize call the
 *    silc_atomic_uninit32 function.
 *
 ***/

static inline
SilcBool silc_atomic_init16(SilcAtomic16 *atomic, SilcUInt16 value)
{
  atomic->value = value;

#if defined(SILC_ATOMIC_MUTEX)
  if (!silc_mutex_alloc(&atomic->lock))
    return FALSE;
#endif /* SILC_ATOMIC_MUTEX */

  return TRUE;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_init8
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_init8(SilcAtomic8 *atomic, SilcUInt8 value);
 *
 * DESCRIPTION
 *
 *    Initializes the atomic variable `atomic', and sets the `value' as its
 *    inital value.  Returns FALSE on error.  To uninitialize call the
 *    silc_atomic_uninit8 function.
 *
 ***/

static inline
SilcBool silc_atomic_init8(SilcAtomic8 *atomic, SilcUInt8 value)
{
  atomic->value = value;

#if defined(SILC_ATOMIC_MUTEX)
  if (!silc_mutex_alloc(&atomic->lock))
    return FALSE;
#endif /* SILC_ATOMIC_MUTEX */

  return TRUE;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_init_pointer
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_init_pointer(SilcAtomicPointer *atomic,
 *                                      void *pointer);
 *
 * DESCRIPTION
 *
 *    Initializes the atomic pointer variable `atomic', and sets the `pointer'
 *    as its inital pointer.  Returns FALSE on error.  To uninitialize call
 *    the silc_atomic_uninit_pointer function.
 *
 ***/

static inline
SilcBool silc_atomic_init_pointer(SilcAtomicPointer *atomic, void *pointer)
{
  atomic->pointer = pointer;

#if defined(SILC_ATOMIC_MUTEX)
  if (!silc_mutex_alloc(&atomic->lock))
    return FALSE;
#endif /* SILC_ATOMIC_MUTEX */

  return TRUE;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_uninit32
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_uninit32(SilcAtomic32 *atomic);
 *
 * DESCRIPTION
 *
 *    Uninitializes the atomic variable `atomic'.  This should alwyas be
 *    called after the atomic variable is not used anymore.
 *
 ***/

static inline
void silc_atomic_uninit32(SilcAtomic32 *atomic)
{
  atomic->value = 0;
#if defined(SILC_ATOMIC_MUTEX)
  silc_mutex_free(atomic->lock);
#endif /* SILC_ATOMIC_MUTEX */
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_uninit16
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_uninit16(SilcAtomic16 *atomic);
 *
 * DESCRIPTION
 *
 *    Uninitializes the atomic variable `atomic'.  This should alwyas be
 *    called after the atomic variable is not used anymore.
 *
 ***/

static inline
void silc_atomic_uninit16(SilcAtomic16 *atomic)
{
  atomic->value = 0;
#if defined(SILC_ATOMIC_MUTEX)
  silc_mutex_free(atomic->lock);
#endif /* SILC_ATOMIC_MUTEX */
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_uninit8
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_uninit8(SilcAtomic8 *atomic);
 *
 * DESCRIPTION
 *
 *    Uninitializes the atomic variable `atomic'.  This should alwyas be
 *    called after the atomic variable is not used anymore.
 *
 ***/

static inline
void silc_atomic_uninit8(SilcAtomic8 *atomic)
{
  atomic->value = 0;
#if defined(SILC_ATOMIC_MUTEX)
  silc_mutex_free(atomic->lock);
#endif /* SILC_ATOMIC_MUTEX */
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_uninit_pointer
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_uninit_pointer(SilcAtomicPointer *atomic);
 *
 * DESCRIPTION
 *
 *    Uninitializes the atomic variable `atomic'.  This should alwyas be
 *    called after the atomic variable is not used anymore.
 *
 ***/

static inline
void silc_atomic_uninit_pointer(SilcAtomicPointer *atomic)
{
  atomic->pointer = NULL;
#if defined(SILC_ATOMIC_MUTEX)
  silc_mutex_free(atomic->lock);
#endif /* SILC_ATOMIC_MUTEX */
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_set_int32
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_set_int32(SilcAtomic32 *atomic, SilcUInt32 value);
 *
 * DESCRIPTION
 *
 *    Atomically sets `value' to 32-bit integer.
 *
 ***/

static inline
void silc_atomic_set_int32(SilcAtomic32 *atomic, SilcUInt32 value)
{
#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  atomic->value = value;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  atomic->value = value;
  __sync_synchronize();

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  atomic->value = value;
  __asm("sync" : : : "memory");

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  atomic->value = value;
  silc_mutex_unlock(atomic->lock);
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_set_int16
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_set_int16(SilcAtomic16 *atomic, SilcUInt16 value);
 *
 * DESCRIPTION
 *
 *    Atomically sets `value' to 16-bit integer.
 *
 ***/

static inline
void silc_atomic_set_int16(SilcAtomic16 *atomic, SilcUInt16 value)
{
#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  atomic->value = value;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  atomic->value = value;
  __sync_synchronize();

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  atomic->value = value;
  __asm("sync" : : : "memory");

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  atomic->value = value;
  silc_mutex_unlock(atomic->lock);
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_set_int8
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_set_int8(SilcAtomic8 *atomic, SilcUInt8 value);
 *
 * DESCRIPTION
 *
 *    Atomically sets `value' to 8-bit integer.
 *
 ***/

static inline
void silc_atomic_set_int8(SilcAtomic8 *atomic, SilcUInt8 value)
{
#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  atomic->value = value;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  atomic->value = value;
  __sync_synchronize();

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  atomic->value = value;
  __asm("sync" : : : "memory");

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  atomic->value = value;
  silc_mutex_unlock(atomic->lock);
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_set_pointer
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_set_pointer(SilcAtomicPointer *atomic, void *pointer);
 *
 * DESCRIPTION
 *
 *    Atomically sets `pointer' to the atomic variable.
 *
 ***/

static inline
void silc_atomic_set_pointer(SilcAtomicPointer *atomic, void *pointer)
{
#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  atomic->pointer = pointer;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  atomic->pointer = pointer;
  __sync_synchronize();

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  atomic->pointer = pointer;
  __asm("sync" : : : "memory");

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  atomic->pointer = pointer;
  silc_mutex_unlock(atomic->lock);
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_get_int32
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_get_int32(SilcAtomic32 *atomic);
 *
 * DESCRIPTION
 *
 *    Returns the current value of the atomic variable.
 *
 ***/

static inline
SilcUInt32 silc_atomic_get_int32(SilcAtomic32 *atomic)
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

/****f* silcutil/SilcAtomicAPI/silc_atomic_get_int16
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_get_int16(SilcAtomic16 *atomic);
 *
 * DESCRIPTION
 *
 *    Returns the current value of the atomic variable.
 *
 ***/

static inline
SilcUInt16 silc_atomic_get_int16(SilcAtomic16 *atomic)
{
  SilcUInt16 ret;

#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  ret = atomic->value & 0xffff;
  return ret;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  __sync_synchronize();
  ret = atomic->value & 0xffff;
  return ret;

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  __asm("sync" : : : "memory");
  ret = atomic->value & 0xffff;
  return ret;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = atomic->value & 0xffff;
  silc_mutex_unlock(atomic->lock);
  return ret;
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_get_int8
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_get_int8(SilcAtomic8 *atomic);
 *
 * DESCRIPTION
 *
 *    Returns the current value of the atomic variable.
 *
 ***/

static inline
SilcUInt8 silc_atomic_get_int8(SilcAtomic8 *atomic)
{
  SilcUInt8 ret;

#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  ret = atomic->value & 0xff;
  return ret;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  __sync_synchronize();
  ret = atomic->value & 0xff;
  return ret;

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  __asm("sync" : : : "memory");
  ret = atomic->value & 0xff;
  return ret;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = atomic->value & 0xff;
  silc_mutex_unlock(atomic->lock);
  return ret;
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_get_pointer
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt8 silc_atomic_get_pointer(SilcAtomicPointer *atomic)
 *
 * DESCRIPTION
 *
 *    Returns the current pointer value of the atomic variable.
 *
 ***/

static inline
void *silc_atomic_get_pointer(SilcAtomicPointer *atomic)
{
  void *ret;

#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  ret = (void *)atomic->pointer;
  return ret;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  __sync_synchronize();
  ret = (void *)atomic->pointer;
  return ret;

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  __asm("sync" : : : "memory");
  ret = (void *)atomic->pointer;
  return ret;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = (void *)atomic->pointer;
  silc_mutex_unlock(atomic->lock);
  return ret;
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_add_int32
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_add_int32(SilcAtomic32 *atomic, SilcInt32 value);
 *
 * DESCRIPTION
 *
 *    Atomically adds `value' to 32-bit integer.  Returns the value after
 *    addition.
 *
 ***/

static inline
SilcUInt32 silc_atomic_add_int32(SilcAtomic32 *atomic, SilcInt32 value)
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

/****f* silcutil/SilcAtomicAPI/silc_atomic_add_int32
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt16 silc_atomic_add_int16(SilcAtomic16 *atomic, SilcInt16 value);
 *
 * DESCRIPTION
 *
 *    Atomically adds `value' to 16-bit integer.  Returns the value after
 *    addition.
 *
 ***/

static inline
SilcUInt16 silc_atomic_add_int16(SilcAtomic16 *atomic, SilcInt16 value)
{
  SilcUInt16 ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  ret = atomic->value;
  atomic->value += value;

#elif defined(SILC_WIN32)
  /* Windows */
  LONG v = value;
  ret = InterlockedExchangeAdd(&atomic->value, v);

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
  /* GCC + i486 or x86_64 */
  __asm __volatile("lock; xaddw %0, %1"
		   : "=c" (ret), "+m" (atomic->value)
		   : "0" (value));

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  SilcInt32 v = value;
  ret = __sync_fetch_and_add(&atomic->value, v);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC (code adapted from IBM's documentation) */
  SilcUInt32 ret32;
  SilcInt32 v = value;
  __asm __volatile("0: lwarx  %0,  0, %2\n"
		   "   add    %0, %1, %0\n"
		   "   stwcx. %0,  0, %2\n"
		   "   bne-   0b"
		   : "=&r" (ret32)
		   : "r" (v), "r" (&atomic->value)
		   : "cc");
  return ret32 & 0xffff;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = atomic->value;
  atomic->value += value;
  silc_mutex_unlock(atomic->lock);
#endif

  return ret + value;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_add_int8
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt8 silc_atomic_add_int8(SilcAtomic8 *atomic, SilcInt8 value);
 *
 * DESCRIPTION
 *
 *    Atomically adds `value' to 8-bit integer.  Returns the value after
 *    addition.
 *
 ***/

static inline
SilcUInt8 silc_atomic_add_int8(SilcAtomic8 *atomic, SilcInt8 value)
{
  SilcUInt8 ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  ret = atomic->value;
  atomic->value += value;

#elif defined(SILC_WIN32)
  /* Windows */
  LONG v = value;
  ret = InterlockedExchangeAdd(&atomic->value, v);

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
  /* GCC + i486 or x86_64 */
  __asm __volatile("lock; xaddb %0, %1"
		   : "=c" (ret), "+m" (atomic->value)
		   : "0" (value));

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  SilcInt32 v = value;
  ret = __sync_fetch_and_add(&atomic->value, v);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC (code adapted from IBM's documentation) */
  SilcUInt32 ret32;
  SilcInt32 v = value;
  __asm __volatile("0: lwarx  %0,  0, %2\n"
		   "   add    %0, %1, %0\n"
		   "   stwcx. %0,  0, %2\n"
		   "   bne-   0b"
		   : "=&r" (ret32)
		   : "r" (v), "r" (&atomic->value)
		   : "cc");
  return ret32 & 0xff;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = atomic->value;
  atomic->value += value;
  silc_mutex_unlock(atomic->lock);
#endif

  return ret + value;
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_sub_int32
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt32 silc_atomic_sub_int32(SilcAtomic32 *atomic, SilcInt32 value);
 *
 * DESCRIPTION
 *
 *    Atomically subtracts `value' from 32-bit integer.  Returns the value
 *    after subtraction.
 *
 ***/

static inline
SilcUInt32 silc_atomic_sub_int32(SilcAtomic32 *atomic, SilcInt32 value)
{
  return silc_atomic_add_int32(atomic, -value);
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_sub_int16
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt16 silc_atomic_sub_int16(SilcAtomic16 *atomic, SilcInt16 value);
 *
 * DESCRIPTION
 *
 *    Atomically subtracts `value' from 16-bit integer.  Returns the value
 *    after subtraction.
 *
 ***/

static inline
SilcUInt16 silc_atomic_sub_int16(SilcAtomic16 *atomic, SilcInt16 value)
{
  return silc_atomic_add_int16(atomic, -value);
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_sub_int8
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcUInt8 silc_atomic_sub_int8(SilcAtomic8 *atomic, SilcInt8 value);
 *
 * DESCRIPTION
 *
 *    Atomically subtracts `value' from 8-bit integer.  Returns the value
 *    after subtraction.
 *
 ***/

static inline
SilcUInt8 silc_atomic_sub_int8(SilcAtomic8 *atomic, SilcInt8 value)
{
  return silc_atomic_add_int8(atomic, -value);
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_cas32
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_cas32(SilcAtomic32 *atomic, SilcUInt32 old_val,
 *                               SilcUInt32 new_val)
 *
 * DESCRIPTION
 *
 *    Performs compare and swap (CAS).  Atomically compares if the variable
 *    `atomic' has the value `old_val' and in that case swaps it with the
 *    value `new_val'.  Returns TRUE if the old value was same and it was
 *    swapped and FALSE if it differed and was not swapped.
 *
 ***/

static inline
SilcBool silc_atomic_cas32(SilcAtomic32 *atomic, SilcUInt32 old_val,
			   SilcUInt32 new_val)
{
  SilcUInt32 ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  if (atomic->value == old_val) {
    atomic->value = new_val;
    return TRUE;
  }
  return FALSE;

#elif defined(SILC_WIN32)
  /* Windows */
  return InterlockedCompareExchange(&atomic->value, (LONG)new_val,
				    (LONG)old_val) == old_val;

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
  /* GCC + i486 or x86_64 */
  __asm __volatile("lock; cmpxchgl %2, %1"
		   : "=a" (ret), "=m" (atomic->value)
		   : "r" (new_val), "m" (atomic->value), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  return  __sync_bool_compare_and_swap(&atomic->value, old_val, new_val);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC */
  /* XXX TODO */

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  if (atomic->value == old_val) {
    atomic->value = new_val;
    silc_mutex_unlock(atomic->lock);
    return TRUE;
  }
  silc_mutex_unlock(atomic->lock);
  return FALSE;
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_cas16
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_cas16(SilcAtomic16 *atomic, SilcUInt16 old_val,
 *                               SilcUInt16 new_val)
 *
 * DESCRIPTION
 *
 *    Performs compare and swap (CAS).  Atomically compares if the variable
 *    `atomic' has the value `old_val' and in that case swaps it with the
 *    value `new_val'.  Returns TRUE if the old value was same and it was
 *    swapped and FALSE if it differed and was not swapped.
 *
 ***/

static inline
SilcBool silc_atomic_cas16(SilcAtomic16 *atomic, SilcUInt16 old_val,
			   SilcUInt16 new_val)
{
  SilcUInt16 ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  if (atomic->value == old_val) {
    atomic->value = new_val;
    return TRUE;
  }
  return FALSE;

#elif defined(SILC_WIN32)
  /* Windows */
  LONG o = old_val, n = new_val;
  return InterlockedCompareExchange(&atomic->value, n, o) == o;

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
  /* GCC + i486 or x86_64 */
  __asm __volatile("lock; cmpxchgw %2, %1"
		   : "=a" (ret), "=m" (atomic->value)
		   : "c" (new_val), "m" (atomic->value), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  SilcUInt32 o = old_val, n = new_val;
  return  __sync_bool_compare_and_swap(&atomic->value, o, n);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC */
  /* XXX TODO */

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  if (atomic->value == old_val) {
    atomic->value = new_val;
    silc_mutex_unlock(atomic->lock);
    return TRUE;
  }
  silc_mutex_unlock(atomic->lock);
  return FALSE;
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_cas8
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_cas8(SilcAtomic8 *atomic, SilcUInt8 old_val,
 *                              SilcUInt8 new_val)
 *
 * DESCRIPTION
 *
 *    Performs compare and swap (CAS).  Atomically compares if the variable
 *    `atomic' has the value `old_val' and in that case swaps it with the
 *    value `new_val'.  Returns TRUE if the old value was same and it was
 *    swapped and FALSE if it differed and was not swapped.
 *
 ***/

static inline
SilcBool silc_atomic_cas8(SilcAtomic8 *atomic, SilcUInt8 old_val,
			  SilcUInt8 new_val)
{
  SilcUInt8 ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  if (atomic->value == old_val) {
    atomic->value = new_val;
    return TRUE;
  }
  return FALSE;

#elif defined(SILC_WIN32)
  /* Windows */
  LONG o = old_val, n = new_val;
  return InterlockedCompareExchange(&atomic->value, n, o) == o;

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
  /* GCC + i486 or x86_64 */
  __asm __volatile("lock; cmpxchgb %2, %1"
		   : "=a" (ret), "=m" (atomic->value)
		   : "c" (new_val), "m" (atomic->value), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  SilcUInt32 o = old_val, n = new_val;
  return  __sync_bool_compare_and_swap(&atomic->value, o, n);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC */
  /* XXX TODO */

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  if (atomic->value == old_val) {
    atomic->value = new_val;
    silc_mutex_unlock(atomic->lock);
    return TRUE;
  }
  silc_mutex_unlock(atomic->lock);
  return FALSE;
#endif
}

/****f* silcutil/SilcAtomicAPI/silc_atomic_cas_pointer
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_atomic_cas_pointer(SilcAtomicPointer *atomic,
 *                                     void *old_ptr, void *new_ptr);
 *
 * DESCRIPTION
 *
 *    Performs compare and swap (CAS).  Atomically compares if the variable
 *    `atomic' has the pointer `old_ptr' and in that case swaps it with the
 *    pointer `new_ptr'.  Returns TRUE if the old pointer was same and it was
 *    swapped and FALSE if it differed and was not swapped.
 *
 ***/

static inline
SilcBool silc_atomic_cas_pointer(SilcAtomicPointer *atomic, void *old_val,
				 void *new_val)
{
  void *ret;

#if !defined(SILC_THREADS)
  /* No atomic operations */
  if (atomic->pointer == old_val) {
    atomic->pointer = new_val;
    return TRUE;
  }
  return FALSE;

#elif defined(SILC_WIN32)
  /* Windows */
  return InterlockedCompareExchangePointer(&atomic->pointer, n, o) == o;

#elif defined(__GNUC__) && defined(SILC_I486)
  /* GCC + i486 */
  __asm __volatile("lock; cmpxchgl %2, %1"
		   : "=a" (ret), "=m" (atomic->pointer)
		   : "c" (new_val), "m" (atomic->pointer), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_X86_64)
  /* GCC + x86_64 */
  __asm __volatile("lock; cmpxchgq %q2, %1"
		   : "=a" (ret), "=m" (atomic->pointer)
		   : "c" (new_val), "m" (atomic->pointer), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  return  __sync_bool_compare_and_swap((long)&atomic->pointer, (long)old_val,
				       (long)new_val);

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* GCC + PowerPC */
  /* XXX TODO */

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  if (atomic->pointer == old_val) {
    atomic->pointer = new_val;
    silc_mutex_unlock(atomic->lock);
    return TRUE;
  }
  silc_mutex_unlock(atomic->lock);
  return FALSE;
#endif
}

#endif /* SILCATOMIC_H */
