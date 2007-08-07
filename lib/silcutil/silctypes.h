/*

  silctypes.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Types
 *
 * DESCRIPTION
 *
 * This header file includes basic types and definitions used in SILC Toolkits.
 * It contains all types, and many utility macros and functions.
 *
 ***/

#ifndef SILCTYPES_H
#define SILCTYPES_H

/****d* silcutil/SILCTypes/SilcBool
 *
 * NAME
 *
 *    typedef unigned char SilcBool;
 *
 * DESCRIPTION
 *
 *    Boolean value, and is always 8-bits.  Represents value 0 or 1.
 *
 ***/
typedef unsigned char SilcBool;

/* The bool macro is deprecated.  Use SilcBool instead. */
#ifdef SILC_MACOSX
#define bool _Bool
#endif
#ifndef __cplusplus
#ifndef bool
#define bool unsigned char
#endif
#endif

/****d* silcutil/SILCTypes/TRUE
 *
 * NAME
 *
 *    #define TRUE ...
 *
 * DESCRIPTION
 *
 *    Boolean true value indicator.
 *
 * SOURCE
 */
#ifndef TRUE
#define TRUE 1
#endif
/***/

/****d* silcutil/SILCTypes/FALSE
 *
 * NAME
 *
 *    #define FALSE ...
 *
 * DESCRIPTION
 *
 *    Boolean false value indicator.
 *
 * SOURCE
 */
#ifndef FALSE
#define FALSE 0
#endif
/***/

/* Our offsetof macro */
#define silc_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/* silc_likely and silc_unlikely GCC branch prediction macros. Use only if
   you have profiled the code first. */
#if __GNUC__ >= 3
#define silc_likely(expr) __builtin_expect(!!(expr), 1)
#define silc_unlikely(expr) __builtin_expect(!!(expr), 0)
#else
#define silc_likely(expr) (expr)
#define silc_unlikely(expr) (expr)
#endif /* __GNUC__ >= 3 */

#if SILC_SIZEOF_SHORT > 2
#error "size of the short must be 2 bytes"
#endif

/****d* silcutil/SILCTypes/SilcUInt8
 *
 * NAME
 *
 *    typedef unsigned char SilcUInt8;
 *
 * DESCRIPTION
 *
 *    8-bit unsigned integer.
 *
 * SOURCE
 */
typedef unsigned char SilcUInt8;
/***/

/****d* silcutil/SILCTypes/SilcInt8
 *
 * NAME
 *
 *    typedef signed char SilcInt8;
 *
 * DESCRIPTION
 *
 *    8-bit signed integer.
 *
 * SOURCE
 */
typedef signed char SilcInt8;
/***/

/****d* silcutil/SILCTypes/SilcUInt16
 *
 * NAME
 *
 *    typedef unsigned short SilcUInt16;
 *
 * DESCRIPTION
 *
 *    16-bit unsigned integer.  Guaranteed to be 16-bits.
 *
 * SOURCE
 */
typedef unsigned short SilcUInt16;
/***/

/****d* silcutil/SILCTypes/SilcInt16
 *
 * NAME
 *
 *    typedef signed short SilcInt16;
 *
 * DESCRIPTION
 *
 *    16-bit signed integer.  Guaranteed to be 16-bits.
 *
 * SOURCE
 */
typedef signed short SilcInt16;
/***/

/****d* silcutil/SILCTypes/SilcUInt32
 *
 * NAME
 *
 *    typedef unsigned long SilcUInt32;
 *
 * DESCRIPTION
 *
 *    32-bit unsigned integer.  Guaranteed to be 32-bits.
 *
 * SOURCE
 */
#if SILC_SIZEOF_LONG == 4
typedef unsigned long SilcUInt32;
typedef signed long SilcInt32;
#else
#if SILC_SIZEOF_INT == 4
typedef unsigned int SilcUInt32;
typedef signed int SilcInt32;
#else
#if SILC_SIZEOF_LONG_LONG >= 4
#ifndef WIN32
typedef unsigned long long SilcUInt32;
typedef signed long long SilcInt32;
#endif
#endif
#endif
#endif
/***/

/****d* silcutil/SILCTypes/SilcInt32
 *
 * NAME
 *
 *    typedef signed long SilcInt32;
 *
 * DESCRIPTION
 *
 *    32-bit signed integer.  Guaranteed to be 32-bits.
 *
 ***/

/****d* silcutil/SILCTypes/SilcUInt64
 *
 * NAME
 *
 *    typedef unsigned long long SilcUInt64;
 *
 * DESCRIPTION
 *
 *    64-bit unsigned integer.  Guaranteed to be 64-bits on systems that
 *    support it.
 *
 * SOURCE
 */
#if SILC_SIZEOF_LONG >= 8
typedef unsigned long SilcUInt64;
typedef signed long SilcInt64;
#else
#if SILC_SIZEOF_LONG_LONG >= 8
#ifndef WIN32
typedef unsigned long long SilcUInt64;
typedef signed long long SilcInt64;
#else
typedef unsigned __int64 SilcUInt64;
typedef signed __int64 SilcInt64;
#endif
#else
typedef SilcUInt32 SilcUInt64;
typedef SilcInt32 SilcInt64;
#endif
#endif
/***/

/****d* silcutil/SILCTypes/SilcInt64
 *
 * NAME
 *
 *    typedef signed long long SilcInt64;
 *
 * DESCRIPTION
 *
 *    64-bit signed integer.  Guaranteed to be 64-bits on systems that
 *    support it.
 *
 ***/

#if SILC_SIZEOF_VOID_P < 4
typedef SilcUInt32 * void *;
#endif

/****d* silcutil/SILCTypes/SilcSocket
 *
 * NAME
 *
 *    SilcSocket
 *
 * DESCRIPTION
 *
 *    Platform specific socket.  On POSIX compliant systems this is simply
 *    an integer, representing the socket. On other systems it is platform
 *    specific socket context.  Access it only through routines that can
 *    handle SilcSocket types, unless you know what you are doing.
 *
 * SOURCE
 */
#if defined(SILC_UNIX)
typedef int SilcSocket;
#elif defined(SILC_WIN32)
typedef SOCKET SilcSocket;
#elif defined(SILC_SYMBIAN)
typedef void * SilcSocket;
#endif
/***/

/* Macros */

#if (defined(SILC_I486) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_GET_WORD(cp)						\
({									\
  SilcUInt32 _result_;							\
  asm volatile ("movl (%1), %0; bswapl %0"				\
		: "=q" (_result_) : "q" (cp));				\
  _result_;								\
})
#else
#define SILC_GET_WORD(cp) ((SilcUInt32)(SilcUInt8)(cp)[0]) << 24	\
		    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 16)		\
		    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 8)		\
		    | ((SilcUInt32)(SilcUInt8)(cp)[3])
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */

/****d* silcutil/SILCTypes/SILC_GET16_MSB
 *
 * NAME
 *
 *    #define SILC_GET16_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Return two 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#if (defined(SILC_I386) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_GET16_MSB(l, cp)				\
asm volatile ("movw (%1), %w0; rolw $8, %w0"		\
	      : "=q" (l) : "q" (cp) : "memory", "cc");
#else
#define SILC_GET16_MSB(l, cp)				\
do {							\
  (l) = ((SilcUInt32)(SilcUInt8)(cp)[0] << 8)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[1]);			\
} while(0)
#endif /* (SILC_I386 || SILC_X86_64) && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_GET32_MSB
 *
 * NAME
 *
 *    #define SILC_GET32_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Return four 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#if (defined(SILC_I486) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_GET32_MSB(l, cp)				\
asm volatile ("movl (%1), %0; bswapl %0"		\
	      : "=q" (l) : "q" (cp) : "memory", "cc");
#else
#define SILC_GET32_MSB(l, cp)				\
do {							\
  (l) = ((SilcUInt32)(SilcUInt8)(cp)[0]) << 24		\
    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 16)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 8)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[3]);			\
} while(0)
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */
/***/

/* Same as upper but XOR the result always. Special purpose macro. */
#if (defined(SILC_I486) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_GET32_X_MSB(l, cp)						\
do {									\
  register volatile SilcUInt32 _x_;					\
  asm volatile ("movl %1, %3; movl (%2), %0;\n\t"			\
		"bswapl %0; xorl %3, %0"				\
		: "=r" (l) : "0" (l), "r" (cp), "r" (_x_)		\
		: "memory", "cc");					\
} while(0)
#else
#define SILC_GET32_X_MSB(l, cp)				\
  (l) ^= ((SilcUInt32)(SilcUInt8)(cp)[0]) << 24		\
    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 16)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 8)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[3]);
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */

/****d* silcutil/SILCTypes/SILC_GET64_MSB
 *
 * NAME
 *
 *    #define SILC_GET64_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Return eight 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#if defined(SILC_X86_64) && defined(__GNUC__)
#define SILC_GET64_MSB(l, cp)					\
asm volatile ("movq (%1), %0; bswapq %0"			\
	      : "=r" (l) : "r" (cp) : "memory", "cc");
#else
#define SILC_GET64_MSB(l, cp)					\
do {								\
  (l) = ((((SilcUInt64)SILC_GET_WORD((cp))) << 32) |		\
	 ((SilcUInt64)SILC_GET_WORD((cp) + 4)));		\
} while(0)
#endif /* SILC_X86_64 && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_GET16_LSB
 *
 * NAME
 *
 *    #define SILC_GET16_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Return two 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#if defined(SILC_I386) || defined(SILC_X86_64)
#define SILC_GET16_LSB(l, cp) (l) = (*(SilcUInt16 *)(cp))
#else
#define SILC_GET16_LSB(l, cp)				\
do {							\
  (l) = ((SilcUInt32)(SilcUInt8)(cp)[0])		\
    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 8);		\
} while(0)
#endif /* SILC_I386 || SILC_X86_64 */
/***/

/****d* silcutil/SILCTypes/SILC_GET32_LSB
 *
 * NAME
 *
 *    #define SILC_GET32_LSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Return four 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#if defined(SILC_I386) || defined(SILC_X86_64)
#define SILC_GET32_LSB(l, cp) (l) = (*(SilcUInt32 *)(cp))
#else
#define SILC_GET32_LSB(l, cp)				\
do {							\
  (l) = ((SilcUInt32)(SilcUInt8)(cp)[0])		\
    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 8)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 16)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[3] << 24);		\
} while(0)
#endif /* SILC_I386 || SILC_X86_64 */
/***/

/* Same as upper but XOR the result always. Special purpose macro. */
#if defined(SILC_I386) || defined(SILC_X86_64)
#define SILC_GET32_X_LSB(l, cp) (l) ^= (*(SilcUInt32 *)(cp))
#else
#define SILC_GET32_X_LSB(l, cp)				\
  (l) ^= ((SilcUInt32)(SilcUInt8)(cp)[0])		\
    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 8)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 16)		\
    | ((SilcUInt32)(SilcUInt8)(cp)[3] << 24)
#endif /* SILC_I386 || SILC_X86_64 */

/****d* silcutil/SILCTypes/SILC_PUT16_MSB
 *
 * NAME
 *
 *    #define SILC_PUT16_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Put two 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#if (defined(SILC_I386) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_PUT16_MSB(l, cp)				\
asm volatile ("rolw $8, %w1; movw %w1, (%0)"		\
	      : : "q" (cp), "q" (l) : "memory", "cc");
#else
#define SILC_PUT16_MSB(l, cp)			\
do {						\
  (cp)[0] = (SilcUInt8)((l) >> 8);		\
  (cp)[1] = (SilcUInt8)(l);			\
} while(0)
#endif /* (SILC_I386 || SILC_X86_64) && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_PUT32_MSB
 *
 * NAME
 *
 *    #define SILC_PUT32_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Put four 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#if (defined(SILC_I486) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_PUT32_MSB(l, cp)				\
asm volatile ("bswapl %1; movl %1, (%0); bswapl %1"	\
	      : : "q" (cp), "q" (l) : "memory", "cc");
#else
#define SILC_PUT32_MSB(l, cp)			\
do {						\
  (cp)[0] = (SilcUInt8)((l) >> 24);		\
  (cp)[1] = (SilcUInt8)((l) >> 16);		\
  (cp)[2] = (SilcUInt8)((l) >> 8);		\
  (cp)[3] = (SilcUInt8)(l);			\
} while(0)
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_PUT64_MSB
 *
 * NAME
 *
 *    #define SILC_PUT64_MSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Put eight 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#if defined(SILC_X86_64) && defined(__GNUC__)
#define SILC_PUT64_MSB(l, cp)				\
asm volatile ("bswapq %1; movq %1, (%0); bswapq %1"	\
	      : : "r" (cp), "r" (l) : "memory", "cc");
#else
#define SILC_PUT64_MSB(l, cp)					\
do {								\
  SILC_PUT32_MSB((SilcUInt32)((SilcUInt64)(l) >> 32), (cp));	\
  SILC_PUT32_MSB((SilcUInt32)(l), (cp) + 4);			\
} while(0)
#endif /* SILC_X86_64 && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_PUT16_LSB
 *
 * NAME
 *
 *    #define SILC_PUT16_LSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Put two 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#if defined(SILC_I386) || defined(SILC_X86_64)
#define SILC_PUT16_LSB(l, cp) (*(SilcUInt16 *)(cp)) = (l)
#else
#define SILC_PUT16_LSB(l, cp)			\
do  {						\
  (cp)[0] = (SilcUInt8)(l);			\
  (cp)[1] = (SilcUInt8)((l) >> 8);		\
} while(0)
#endif /* SILC_I386 || SILC_X86_64 */
/***/

/****d* silcutil/SILCTypes/SILC_PUT32_LSB
 *
 * NAME
 *
 *    #define SILC_PUT32_LSB(dest, src)
 *
 * DESCRIPTION
 *
 *    Put four 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#if defined(SILC_I386) || defined(SILC_X86_64)
#define SILC_PUT32_LSB(l, cp) (*(SilcUInt32 *)(cp)) = (l)
#else
#define SILC_PUT32_LSB(l, cp)			\
do {						\
  (cp)[0] = (SilcUInt8)(l);			\
  (cp)[1] = (SilcUInt8)((l) >> 8);		\
  (cp)[2] = (SilcUInt8)((l) >> 16);		\
  (cp)[3] = (SilcUInt8)((l) >> 24);		\
} while(0)
#endif /* SILC_I386 || SILC_X86_64 */
/***/

/****d* silcutil/SILCTypes/SILC_SWAB_16
 *
 * NAME
 *
 *    #define SILC_SWAB_16(integer)
 *
 * DESCRIPTION
 *
 *    Swabs 16-bit unsigned integer byte order.  Returns the new value.
 *
 * SOURCE
 */
#if (defined(SILC_I386) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_SWAB_16(l)				\
({						\
  SilcUInt16 _result_;				\
  asm volatile ("movw %w1, %w0; rolw $8, %w0"	\
		: "=q" (_result_): "q" (l));	\
  _result_;					\
})
#else
#define SILC_SWAB_16(l)						\
  ((SilcUInt16)(((SilcUInt16)(l) & (SilcUInt16)0x00FFU) << 8) |	\
               (((SilcUInt16)(l) & (SilcUInt16)0xFF00U) >> 8))
#endif /* (SILC_I386 || SILC_X86_64) && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_SWAB_32
 *
 * NAME
 *
 *    #define SILC_SWAB_32(integer)
 *
 * DESCRIPTION
 *
 *    Swabs 32-bit unsigned integer byte order.  Returns the new value.
 *
 * SOURCE
 */
#if (defined(SILC_I486) || defined(SILC_X86_64)) && defined(__GNUC__)
#define SILC_SWAB_32(l)				\
({						\
  SilcUInt32 _result_;				\
  asm volatile ("movl %1, %0; bswapl %0"	\
		: "=q" (_result_): "q" (l));	\
  _result_;					\
})
#else
#define SILC_SWAB_32(l)							\
  ((SilcUInt32)(((SilcUInt32)(l) & (SilcUInt32)0x000000FFUL) << 24) |	\
               (((SilcUInt32)(l) & (SilcUInt32)0x0000FF00UL) << 8)  |	\
               (((SilcUInt32)(l) & (SilcUInt32)0x00FF0000UL) >> 8)  |	\
               (((SilcUInt32)(l) & (SilcUInt32)0xFF000000UL) >> 24))
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */
/***/

/****d* silcutil/SILCTypes/SILC_PTR_TO_32
 *
 * NAME
 *
 *    #define SILC_PTR_TO_32(ptr)
 *
 * DESCRIPTION
 *
 *    Type casts a pointer's value into a 32-bit integer.  Use this to
 *    avoid compiler warnings when type casting pointers to integers
 *    of different size.
 *
 * SOURCE
 */
#if SILC_SIZEOF_VOID_P < 8
#define SILC_PTR_TO_32(_ptr__) ((SilcUInt32)(_ptr__))
#else
#define SILC_PTR_TO_32(_ptr__) 						\
  ((SilcUInt32)((SilcUInt64)(_ptr__) & (SilcUInt32)0xFFFFFFFFUL))
#endif
/***/

/****d* silcutil/SILCTypes/SILC_PTR_TO_64
 *
 * NAME
 *
 *    #define SILC_PTR_TO_64(ptr)
 *
 * DESCRIPTION
 *
 *    Type casts a pointer's value into a 64-bit integer.  Use this to
 *    avoid compiler warnings when type casting pointers to integers
 *    of different size.
 *
 * SOURCE
 */
#if SILC_SIZEOF_VOID_P < 8
#define SILC_PTR_TO_64(_ptr__) ((SilcUInt64)((SilcUInt32)(_ptr__)))
#else
#define SILC_PTR_TO_64(_ptr__) ((SilcUInt64)((SilcUInt64)(_ptr__)))
#endif
/***/

/****d* silcutil/SILCTypes/SILC_32_TO_PTR
 *
 * NAME
 *
 *    #define SILC_32_TO_PTR(ptr)
 *
 * DESCRIPTION
 *
 *    Type casts a 32-bit integer value into a pointer.  Use this to
 *    avoid compiler warnings when type casting integers to pointers of
 *    different size.
 *
 * SOURCE
 */
#if SILC_SIZEOF_VOID_P < 8
#define SILC_32_TO_PTR(_ival__) ((void *)((SilcUInt32)(_ival__)))
#else
#define SILC_32_TO_PTR(_ival__) ((void *)((SilcUInt64)(_ival__)))
#endif
/***/

/****d* silcutil/SILCTypes/SILC_64_TO_PTR
 *
 * NAME
 *
 *    #define SILC_64_TO_PTR(ptr)
 *
 * DESCRIPTION
 *
 *    Type casts a 64-bit integer value into a pointer.  Use this to
 *    avoid compiler warnings when type casting integers to pointers of
 *    different size.
 *
 * SOURCE
 */
#if SILC_SIZEOF_VOID_P < 8
#define SILC_64_TO_PTR(_ival__)						\
  ((void *)((SilcUInt32)((SilcUInt64)(_ival__) & (SilcUInt32)0xFFFFFFFFUL)))
#else
#define SILC_64_TO_PTR(_ival__) ((void *)((SilcUInt64)(_ival__)))
#endif
/***/

/****d* silcutil/SILCTypes/silc_rol
 *
 * NAME
 *
 *    static inline SilcUInt32 silc_rol(SilcUInt32 val, int num);
 *
 * DESCRIPTION
 *
 *    Rotate 32-bit integer's bits to left `num' times.  Bits pushed to the
 *    left will appear from the right side of the integer, thus rotating.
 *    Returns the rotated value.
 *
 ***/
static inline SilcUInt32 silc_rol(SilcUInt32 val, int num)
{
#if (defined(SILC_I386) || defined(SILC_X86_64)) && defined(__GNUC__)
  asm volatile ("roll %%cl, %0"
		: "=q" (val) : "0" (val), "c" (num));
  return val;
#else
  return ((val << (SilcUInt32)num) | (val >> (32 - (SilcUInt32)num)));
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */
}

/****d* silcutil/SILCTypes/silc_ror
 *
 * NAME
 *
 *    static inline SilcUInt32 silc_ror(SilcUInt32 val, int num);
 *
 * DESCRIPTION
 *
 *    Rotate 32-bit integer's bits to right `num' times.  Bits pushed to the
 *    right will appear from the left side of the integer, thus rotating.
 *    Returns the rotated value.
 *
 ***/
static inline SilcUInt32 silc_ror(SilcUInt32 val, int num)
{
#if (defined(SILC_I386) || defined(SILC_X86_64)) && defined(__GNUC__)
  asm volatile ("rorl %%cl, %0"
		: "=q" (val) : "0" (val), "c" (num));
  return val;
#else
  return ((val >> (SilcUInt32)num) | (val << (32 - (SilcUInt32)num)));
#endif /* (SILC_I486 || SILC_X86_64) && __GNUC__ */
}

/****d* silcutil/SILCTypes/silc_rol64
 *
 * NAME
 *
 *    static inline SilcUInt64 silc_rol64(SilcUInt64 val, int num);
 *
 * DESCRIPTION
 *
 *    Rotate 64-bit integer's bits to left `num' times.  Bits pushed to the
 *    left will appear from the right side of the integer, thus rotating.
 *    Returns the rotated value.
 *
 ***/
static inline SilcUInt64 silc_rol64(SilcUInt64 val, int num)
{
#if defined(SILC_X86_64) && defined(__GNUC__)
  asm volatile ("rolq %%cl, %0"
		: "=q" (val) : "0" (val), "c" (num));
  return val;
#else
  return ((val << (SilcUInt64)num) | (val >> (64 - (SilcUInt64)num)));
#endif /* SILC_X86_64 && __GNUC__ */
}

/****d* silcutil/SILCTypes/silc_ror64
 *
 * NAME
 *
 *    static inline SilcUInt64 silc_ror64(SilcUInt64 val, int num);
 *
 * DESCRIPTION
 *
 *    Rotate 64-bit integer's bits to right `num' times.  Bits pushed to the
 *    right will appear from the left side of the integer, thus rotating.
 *    Returns the rotated value.
 *
 ***/
static inline SilcUInt64 silc_ror64(SilcUInt64 val, int num)
{
#if defined(SILC_X86_64) && defined(__GNUC__)
  asm volatile ("rorq %%cl, %0"
		: "=q" (val) : "0" (val), "c" (num));
  return val;
#else
  return ((val >> (SilcUInt64)num) | (val << (64 - (SilcUInt64)num)));
#endif /* SILC_X86_64 && __GNUC__ */
}

#endif /* SILCTYPES_H */
