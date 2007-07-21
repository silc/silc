/*

  silcatomic.h

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
 * EXAMPLE
 *
 * SilcAtomic32 refcnt;
 *
 * // Initialize atomic variable
 * silc_atomic_init32(&refcnt, 0);
 *
 * // Increment referene counter by one
 * silc_atomic_add_int32(&refcnt, 1);
 *
 * // Uninitialize atomic variable
 * silc_atomic_uninit32(&refcnt);
 *
 ***/

#ifndef SILCATOMIC_H
#define SILCATOMIC_H

/* For now we always assume SMP */
#define SILC_SMP 1

/* Use lock prefix only on true SMP systems */
#ifdef SILC_SMP
#define SILC_SMP_LOCK "lock; "
#else
#define SILC_SMP_LOCK
#endif /* SILC_SMP */

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
  volatile void *value;
} SilcAtomicPointer;
#else
#define SILC_ATOMIC_MUTEX
typedef struct {
  SilcMutex lock;
  volatile SilcUInt32 value;
} SilcAtomic32;
typedef struct {
  SilcMutex lock;
  volatile void *value;
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

#define SILC_ATOMIC_INIT_F(name, bits, type)				\
static inline								\
SilcBool silc_atomic_init##name(SilcAtomic##bits *atomic, type value)

#if defined(SILC_ATOMIC_MUTEX)
#define SILC_ATOMIC_INIT(name, bits, type)				\
SILC_ATOMIC_INIT_F(name, bits, type)					\
{									\
  atomic->value = value;						\
  return silc_mutex_alloc(&atomic->lock);				\
}
#else
#define SILC_ATOMIC_INIT(name, bits, type)				\
SILC_ATOMIC_INIT_F(name, bits, type)					\
{									\
  atomic->value = value;						\
  return TRUE;								\
}
#endif /* SILC_ATOMIC_MUTEX */

SILC_ATOMIC_INIT(8, 8, SilcUInt8)
SILC_ATOMIC_INIT(16, 16, SilcUInt16)
SILC_ATOMIC_INIT(32, 32, SilcUInt32)
SILC_ATOMIC_INIT(_pointer, Pointer, void *)

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

#define SILC_ATOMIC_UNINIT_F(bits, t)					\
static inline void silc_atomic_uninit##bits(SilcAtomic##t *atomic)

#if defined(SILC_ATOMIC_MUTEX)
#define SILC_ATOMIC_UNINIT(bits, t)					\
SILC_ATOMIC_UNINIT_F(bits, t)						\
{									\
  silc_mutex_free(atomic->lock);					\
}
#else
#define SILC_ATOMIC_UNINIT(bits, t)					\
SILC_ATOMIC_UNINIT_F(bits, t)						\
{									\
  memset(atomic, 0, sizeof(*atomic));					\
}
#endif /* SILC_ATOMIC_MUTEX */

SILC_ATOMIC_UNINIT(8, 8)
SILC_ATOMIC_UNINIT(16, 16)
SILC_ATOMIC_UNINIT(32, 32)
SILC_ATOMIC_UNINIT(_pointer, Pointer)

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

#define SILC_ATOMIC_SET_INT_F(bits)					\
static inline void silc_atomic_set_int##bits(SilcAtomic##bits *atomic,	\
			       		     SilcUInt##bits value)

#if !defined(SILC_THREADS)
#define SILC_ATOMIC_SET_INT(bits, bp, bp2)				\
SILC_ATOMIC_SET_INT_F(bits)						\
{									\
  /* No atomic operations */						\
  atomic->value = value;						\
}

#elif defined(SILC_WIN32)
#define SILC_ATOMIC_SET_INT(bits, bp, bp2)				\
SILC_ATOMIC_SET_INT_F(bits)						\
{									\
  /* Windows */								\
  InterlockedExchange((LONG)&atomic->value, (LONG)value);		\
}

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
#define SILC_ATOMIC_SET_INT(bits, bp, bp2)				\
SILC_ATOMIC_SET_INT_F(bits)						\
{									\
  /* GCC + i486 or x86_64 */						\
  __asm __volatile("xchg" bp " %" bp2 "0, %1"				\
		   : "=r" (value)					\
		   : "m" (atomic->value), "0" (value));			\
}

#elif defined(__GNUC__) && defined(SILC_IA64)
#define SILC_ATOMIC_SET_INT(bits, bp, bp2)				\
SILC_ATOMIC_SET_INT_F(bits)						\
{									\
  /* IA64, memory barrier needed */					\
  atomic->value = value;						\
  __sync_synchronize();							\
}

#elif defined(__GNUC__) && defined(SILC_POWERPC)
#define SILC_ATOMIC_SET_INT(bits, bp, bp2)				\
SILC_ATOMIC_SET_INT_F(bits)						\
{									\
  /* PowerPC, memory barrier needed */					\
  atomic->value = value;						\
  __asm("sync" : : : "memory");						\
}

#else /* SILC_ATOMIC_MUTEX */
#define SILC_ATOMIC_SET_INT(bits, bp, bp2)				\
SILC_ATOMIC_SET_INT_F(bits)						\
{									\
  /* Mutex */								\
  silc_mutex_lock(atomic->lock);					\
  atomic->value = value;						\
  silc_mutex_unlock(atomic->lock);					\
}
#endif /* !SILC_THREADS */

SILC_ATOMIC_SET_INT(8, "b", "b")
SILC_ATOMIC_SET_INT(16, "w", "w")
SILC_ATOMIC_SET_INT(32, "l", "")

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
#if !defined(SILC_THREADS) ||			 \
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */
  atomic->value = pointer;

#elif defined(SILC_WIN32)
  InterlockedExchangePointer(&atomic->value, pointer);

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  atomic->value = pointer;
  __sync_synchronize();

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  atomic->value = pointer;
  __asm("sync" : : : "memory");

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  atomic->value = pointer;
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

#define SILC_ATOMIC_GET_INT_F(bits)					\
static inline								\
SilcUInt##bits silc_atomic_get_int##bits(SilcAtomic##bits *atomic)

#if !defined(SILC_THREADS) || defined(SILC_WIN32) ||			\
     (defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64)))
#define SILC_ATOMIC_GET_INT(bits)					\
SILC_ATOMIC_GET_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
									\
  /* No threads, Windows, i486 or x86_64, no memory barrier needed */	\
  ret = atomic->value;							\
  return ret;								\
}

#elif defined(__GNUC__) && defined(SILC_IA64)
#define SILC_ATOMIC_GET_INT(bits)					\
SILC_ATOMIC_GET_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
									\
  /* IA64, memory barrier needed */					\
  __sync_synchronize();							\
  ret = atomic->value;							\
  return ret;								\
}

#elif defined(__GNUC__) && defined(SILC_POWERPC)
#define SILC_ATOMIC_GET_INT(bits)					\
SILC_ATOMIC_GET_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
									\
  /* PowerPC, memory barrier needed */					\
  __asm("sync" : : : "memory");						\
  ret = atomic->value;							\
  return ret;								\
}

#else /* SILC_ATOMIC_MUTEX */
#define SILC_ATOMIC_GET_INT(bits)					\
SILC_ATOMIC_GET_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
									\
  /* Mutex */								\
  silc_mutex_lock(atomic->lock);					\
  ret = atomic->value;							\
  silc_mutex_unlock(atomic->lock);					\
  return ret;								\
}
#endif /* !SILC_THREADS */

SILC_ATOMIC_GET_INT(8)
SILC_ATOMIC_GET_INT(16)
SILC_ATOMIC_GET_INT(32)

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
  ret = (void *)atomic->value;
  return ret;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* IA64, memory barrier needed */
  __sync_synchronize();
  ret = (void *)atomic->value;
  return ret;

#elif defined(__GNUC__) && defined(SILC_POWERPC)
  /* PowerPC, memory barrier needed */
  __asm("sync" : : : "memory");
  ret = (void *)atomic->value;
  return ret;

#else
  /* Mutex */
  silc_mutex_lock(atomic->lock);
  ret = (void *)atomic->value;
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

/****f* silcutil/SilcAtomicAPI/silc_atomic_add_int16
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

#define SILC_ATOMIC_ADD_INT_F(bits)					\
static inline								\
SilcUInt##bits silc_atomic_add_int##bits(SilcAtomic##bits *atomic,	\
					 SilcInt##bits value)

#if !defined(SILC_THREADS)
#define SILC_ATOMIC_ADD_INT(bits, bp)					\
SILC_ATOMIC_ADD_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
  /* No atomic operations */						\
  ret = atomic->value;							\
  atomic->value += value;						\
  return ret + value;							\
}

#elif defined(SILC_WIN32)
#define SILC_ATOMIC_ADD_INT(bits, bp)					\
SILC_ATOMIC_ADD_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
  LONG val = value;							\
  /* Windows */								\
  ret = InterlockedExchangeAdd(&atomic->value, val);			\
  return ret + value;							\
}

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
#define SILC_ATOMIC_ADD_INT(bits, bp)					\
SILC_ATOMIC_ADD_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
  /* GCC + i486 or x86_64 */						\
  __asm __volatile(SILC_SMP_LOCK "xadd" bp " %0, %1"			\
		   : "=r" (ret), "+m" (atomic->value)			\
		   : "0" (value));					\
  return ret + value;							\
}

#elif defined(__GNUC__) && defined(SILC_IA64)
#define SILC_ATOMIC_ADD_INT(bits, bp)					\
SILC_ATOMIC_ADD_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
  SilcInt32 val = value;						\
  /* GCC + IA64 (GCC builtin atomic operations) */			\
  ret = __sync_fetch_and_add(&atomic->value, val);			\
  return ret + value;							\
}

#elif defined(__GNUC__) && defined(SILC_POWERPC)
#define SILC_ATOMIC_ADD_INT(bits, bp)					\
SILC_ATOMIC_ADD_INT_F(bits)						\
{									\
  SilcUInt32 ret;   							\
  SilcInt32 val = value;						\
  /* GCC + PowerPC (code adapted from IBM's documentation) */		\
  __asm __volatile("0: lwarx  %0,  0, %2\n"				\
		   "   add    %0, %1, %0\n"				\
		   "   stwcx. %0,  0, %2\n"				\
		   "   bne-   0b"					\
		   : "=&r" (ret)					\
		   : "r" (val), "r" (&atomic->value)			\
		   : "cc");						\
  return ret;								\
}

#else /* SILC_ATOMIC_MUTEX */
#define SILC_ATOMIC_ADD_INT(bits, bp)					\
SILC_ATOMIC_ADD_INT_F(bits)						\
{									\
  SilcUInt##bits ret;							\
  /* Mutex */								\
  silc_mutex_lock(atomic->lock);					\
  ret = atomic->value;							\
  atomic->value += value;						\
  silc_mutex_unlock(atomic->lock);					\
  return ret + value;							\
}
#endif /* !SILC_THREADS */

SILC_ATOMIC_ADD_INT(8, "b")
SILC_ATOMIC_ADD_INT(16, "w")
SILC_ATOMIC_ADD_INT(32, "l")

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

#define silc_atomic_sub_int8(a, v) silc_atomic_add_int8(a, (-v))
#define silc_atomic_sub_int16(a, v) silc_atomic_add_int16(a, (-v))
#define silc_atomic_sub_int32(a, v) silc_atomic_add_int32(a, (-v))

/****f* silcutil/SilcAtomicAPI/silc_atomic_inc32
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_inc32(SilcAtomic32 *atomic);
 *
 * DESCRIPTION
 *
 *    Atomically increments 32-bit integer by one.
 *
 ***/

/****f* silcutil/SilcAtomicAPI/silc_atomic_inc16
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_inc16(SilcAtomic16 *atomic);
 *
 * DESCRIPTION
 *
 *    Atomically increments 16-bit integer by one.
 *
 ***/

/****f* silcutil/SilcAtomicAPI/silc_atomic_inc8
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_inc8(SilcAtomic8 *atomic);
 *
 * DESCRIPTION
 *
 *    Atomically increments 8-bit integer by one.
 *
 ***/

#define SILC_ATOMIC_INC_F(bits)						\
static inline void silc_atomic_inc##bits(SilcAtomic##bits *atomic)

#if !defined(SILC_THREADS)
#define SILC_ATOMIC_INC(bits, bp)					\
SILC_ATOMIC_INC_F(bits)				   			\
{									\
  /* No atomic operations */						\
  ++atomic->value;							\
}

#elif defined(SILC_WIN32)
#define SILC_ATOMIC_INC(bits, bp)					\
SILC_ATOMIC_INC_F(bits)				   			\
{									\
  /* Windows */								\
  InterlockedIncrement((LONG)&atomic->value);				\
}

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
#define SILC_ATOMIC_INC(bits, bp)					\
SILC_ATOMIC_INC_F(bits)				   			\
{									\
  /* GCC + i486 or x86_64 */						\
  __asm __volatile(SILC_SMP_LOCK "inc" bp " %0"				\
		   : "+m" (atomic->value));				\
}

#elif defined(__GNUC__) && defined(SILC_IA64)
#define SILC_ATOMIC_INC(bits, bp)					\
SILC_ATOMIC_INC_F(bits)				   			\
{									\
  /* GCC + IA64 (GCC builtin atomic operations) */			\
  __sync_fetch_and_add(&atomic->value, 1);				\
}

#elif defined(__GNUC__) && defined(SILC_POWERPC)
#define SILC_ATOMIC_INC(bits, bp)					\
SILC_ATOMIC_INC_F(bits)				   			\
{									\
  SilcUInt32 ret;   							\
  SilcInt32 val = 1;							\
  /* GCC + PowerPC (code adapted from IBM's documentation) */		\
  __asm __volatile("0: lwarx  %0,  0, %2\n"				\
		   "   add    %0, %1, %0\n"				\
		   "   stwcx. %0,  0, %2\n"				\
		   "   bne-   0b"					\
		   : "=&r" (ret)					\
		   : "r" (val), "r" (&atomic->value)			\
		   : "cc");						\
}

#else /* SILC_ATOMIC_MUTEX */
#define SILC_ATOMIC_INC(bits, bp)					\
SILC_ATOMIC_INC_F(bits)				   			\
{									\
  /* Mutex */								\
  silc_mutex_lock(atomic->lock);					\
  ++atomic->value;							\
  silc_mutex_unlock(atomic->lock);					\
}
#endif /* !SILC_THREADS */

SILC_ATOMIC_INC(8, "b")
SILC_ATOMIC_INC(16, "w")
SILC_ATOMIC_INC(32, "l")

/****f* silcutil/SilcAtomicAPI/silc_atomic_dec32
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_dec32(SilcAtomic32 *atomic);
 *
 * DESCRIPTION
 *
 *    Atomically decrements 32-bit integer by one.
 *
 ***/

/****f* silcutil/SilcAtomicAPI/silc_atomic_dec16
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_dec16(SilcAtomic16 *atomic);
 *
 * DESCRIPTION
 *
 *    Atomically decrements 16-bit integer by one.
 *
 ***/

/****f* silcutil/SilcAtomicAPI/silc_atomic_dec8
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_atomic_dec8(SilcAtomic8 *atomic);
 *
 * DESCRIPTION
 *
 *    Atomically decrements 8-bit integer by one.
 *
 ***/

#define SILC_ATOMIC_DEC_F(bits)						\
static inline void silc_atomic_dec##bits(SilcAtomic##bits *atomic)

#if !defined(SILC_THREADS)
#define SILC_ATOMIC_DEC(bits, bp)					\
SILC_ATOMIC_DEC_F(bits)				   			\
{									\
  /* No atomic operations */						\
  --atomic->value;							\
}

#elif defined(SILC_WIN32)
#define SILC_ATOMIC_DEC(bits, bp)					\
SILC_ATOMIC_DEC_F(bits)				   			\
{									\
  /* Windows */								\
  InterlockedDecrement((LONG)&atomic->value);				\
}

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
#define SILC_ATOMIC_DEC(bits, bp)					\
SILC_ATOMIC_DEC_F(bits)				   			\
{									\
  /* GCC + i486 or x86_64 */						\
  __asm __volatile(SILC_SMP_LOCK "dec" bp " %0"				\
		   : "+m" (atomic->value));				\
}

#elif defined(__GNUC__) && defined(SILC_IA64)
#define SILC_ATOMIC_DEC(bits, bp)					\
SILC_ATOMIC_DEC_F(bits)				   			\
{									\
  /* GCC + IA64 (GCC builtin atomic operations) */			\
  __sync_fetch_and_sub(&atomic->value, 1);				\
}

#elif defined(__GNUC__) && defined(SILC_POWERPC)
#define SILC_ATOMIC_DEC(bits, bp)					\
SILC_ATOMIC_DEC_F(bits)				   			\
{									\
  SilcUInt32 ret;   							\
  SilcInt32 val = -1;							\
  /* GCC + PowerPC (code adapted from IBM's documentation) */		\
  __asm __volatile("0: lwarx  %0,  0, %2\n"				\
		   "   add    %0, %1, %0\n"				\
		   "   stwcx. %0,  0, %2\n"				\
		   "   bne-   0b"					\
		   : "=&r" (ret)					\
		   : "r" (val), "r" (&atomic->value)			\
		   : "cc");						\
}

#else /* SILC_ATOMIC_MUTEX */
#define SILC_ATOMIC_DEC(bits, bp)					\
SILC_ATOMIC_DEC_F(bits)				   			\
{									\
  /* Mutex */								\
  silc_mutex_lock(atomic->lock);					\
  --atomic->value;							\
  silc_mutex_unlock(atomic->lock);					\
}
#endif /* !SILC_THREADS */

SILC_ATOMIC_DEC(8, "b")
SILC_ATOMIC_DEC(16, "w")
SILC_ATOMIC_DEC(32, "l")

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

#define SILC_ATOMIC_CAS_F(bits)						\
static inline SilcBool silc_atomic_cas##bits(SilcAtomic##bits *atomic,  \
					     SilcInt##bits old_val,	\
					     SilcInt##bits new_val)

#if !defined(SILC_THREADS)
#define SILC_ATOMIC_CAS(bits, bp)					\
SILC_ATOMIC_CAS_F(bits)							\
{									\
  /* No atomic operations */						\
  if (atomic->value == (SilcUInt##bits)old_val) {			\
    atomic->value = new_val;						\
    return TRUE;							\
  }									\
  return FALSE;								\
}

#elif defined(SILC_WIN32)
#define SILC_ATOMIC_CAS(bits, bp)					\
SILC_ATOMIC_CAS_F(bits)							\
{									\
  /* Windows */								\
  LONG o = old_val, n = new_val;					\
  return InterlockedCompareExchange(&atomic->value, n, o) == o;		\
}

#elif defined(__GNUC__) && (defined(SILC_I486) || defined(SILC_X86_64))
#define SILC_ATOMIC_CAS(bits, bp)					\
SILC_ATOMIC_CAS_F(bits)							\
{									\
  /* GCC + i486 or x86_64 */						\
  SilcUInt##bits ret;							\
  __asm __volatile(SILC_SMP_LOCK "cmpxchg" bp " %2, %1"			\
		   : "=a" (ret), "=m" (atomic->value)			\
		   : "r" (new_val), "m" (atomic->value), "0" (old_val)); \
  return ret == (SilcUInt##bits)old_val;				\
}

#elif defined(__GNUC__) && defined(SILC_IA64)
#define SILC_ATOMIC_CAS(bits, bp)					\
SILC_ATOMIC_CAS_F(bits)							\
{									\
  /* GCC + IA64 (GCC builtin atomic operations) */			\
  SilcUInt32 o = old_val, n = new_val;					\
  return __sync_bool_compare_and_swap(&atomic->value, o, n);		\
}

#elif defined(__GNUC__) && defined(SILC_POWERPC)
#define SILC_ATOMIC_CAS(bits, bp)					\
SILC_ATOMIC_CAS_F(bits)							\
{									\
  /* GCC + PowerPC */							\
  /* XXX TODO */							\
}

#else /* SILC_ATOMIC_MUTEX */
#define SILC_ATOMIC_CAS(bits, bp)					\
SILC_ATOMIC_CAS_F(bits)							\
{									\
  /* Mutex */								\
  silc_mutex_lock(atomic->lock);					\
  if (atomic->value == (SilcUInt##bits)old_val) {			\
    atomic->value = new_val;						\
    silc_mutex_unlock(atomic->lock);					\
    return TRUE;							\
  }									\
  silc_mutex_unlock(atomic->lock);					\
  return FALSE;								\
}
#endif /* !SILC_THREADS */

SILC_ATOMIC_CAS(8, "b")
SILC_ATOMIC_CAS(16, "w")
SILC_ATOMIC_CAS(32, "l")

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
#if !defined(SILC_THREADS)
  /* No atomic operations */
  if (atomic->value == old_val) {
    atomic->value = new_val;
    return TRUE;
  }
  return FALSE;

#elif defined(SILC_WIN32)
  /* Windows */
  return InterlockedCompareExchangePointer(&atomic->value, new_val, old_val)
    == old_val;

#elif defined(__GNUC__) && defined(SILC_I486)
  /* GCC + i486 */
  void *ret;
  __asm __volatile(SILC_SMP_LOCK "cmpxchgl %2, %1"
		   : "=a" (ret), "=m" (atomic->value)
		   : "c" (new_val), "m" (atomic->value), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_X86_64)
  /* GCC + x86_64 */
  void *ret;
  __asm __volatile(SILC_SMP_LOCK "cmpxchgq %q2, %1"
		   : "=a" (ret), "=m" (atomic->value)
		   : "c" (new_val), "m" (atomic->value), "0" (old_val));
  return ret == old_val;

#elif defined(__GNUC__) && defined(SILC_IA64)
  /* GCC + IA64 (GCC builtin atomic operations) */
  return  __sync_bool_compare_and_swap((long *)&atomic->value, (long)old_val,
				       (long)new_val);

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

#endif /* SILCATOMIC_H */
