/*

  silctypes.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2008 Pekka Riikonen

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
 * This header file includes basic types and definitions, and various system
 * specific macros and functions used in SILC Toolkits.  Application programmer
 * may use them when needed.
 *
 ***/

#ifndef SILCTYPES_H
#define SILCTYPES_H

/* The bool macro is deprecated.  Use SilcBool instead. */
#ifdef SILC_MACOSX
#define bool _Bool
#endif
#ifndef __cplusplus
#ifndef bool
#define bool unsigned char
#endif
#endif

#if SILC_SIZEOF_SHORT > 2
#error "size of the short must be 2 bytes"
#endif

/******************************* Public API *********************************/

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

/****d* silcutil/SILCTypes/SilcParam
 *
 * NAME
 *
 *    typedef SilcUInt32 SilcParam;
 *
 * DESCRIPTION
 *
 *    A generic parameters that describe the type of an parameter or argument.
 *    They can be used to describe function arguments, buffer encoding format,
 *    etc.
 *
 * SOURCE
 */
typedef SilcUInt32 SilcParam;

#define SILC_PARAM_SINT8         1		/* SilcInt8 */
#define SILC_PARAM_UINT8         2		/* SilcUInt8 */
#define SILC_PARAM_SINT16        3		/* SilcInt16 */
#define SILC_PARAM_UINT16        4		/* SilcUInt16 */
#define SILC_PARAM_SINT32        5		/* SilcInt32 */
#define SILC_PARAM_UINT32        6		/* SilcUInt32 */
#define SILC_PARAM_SINT64        7		/* SilcInt64 */
#define SILC_PARAM_UINT64        8		/* SilcUInt64 */
#define SILC_PARAM_SICHAR        9		/* signed char * */
#define SILC_PARAM_UICHAR        10		/* unsigned char * */
#define SILC_PARAM_BUFFER        11		/* SilcBuffer */
#define SILC_PARAM_PTR           12		/* void * */
#define SILC_PARAM_END           0xfeeefff1     /* End of parameters */
/***/

/* Internal parameter types, not publicly documented, used mainly by the
   SILC Buffer Format API (silcbuffmt.h). */
#define SILC_PARAM_UI8_STRING    100	        /* String (max len 8-bits) */
#define SILC_PARAM_UI16_STRING   101	        /* String (max len 16-bits) */
#define SILC_PARAM_UI32_STRING   102	        /* String (max len 32-bits) */
#define SILC_PARAM_UI8_NSTRING   103	        /* String (max len 8-bits) */
#define SILC_PARAM_UI16_NSTRING  104	        /* String (max len 16-bits) */
#define SILC_PARAM_UI32_NSTRING  105	        /* String (max len 32-bits) */
#define SILC_PARAM_OFFSET        106
#define SILC_PARAM_ADVANCE       107
#define SILC_PARAM_FUNC          108
#define SILC_PARAM_REGEX         109
#define SILC_PARAM_OFFSET_START  110
#define SILC_PARAM_OFFSET_END    111
#define SILC_PARAM_DELETE        112
#define SILC_PARAM_ALLOC         0x00010000     /* Allocate, bitmask */
#define SILC_PARAM_REPLACE       0x00020000	/* Replace, bitmask */

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
		: "=q" (_result_) : "q" (l));	\
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
		: "=q" (_result_) : "q" (l));	\
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

/****d* silcutil/SILCTypes/silc_offsetof
 *
 * NAME
 *
 *    #define silc_offsetof(TYPE, MEMBER)
 *
 * DESCRIPTION
 *
 *    offsetof() macro replacement.  Use this instead of offsetof().
 *
 ***/
#define silc_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/****d* silcutil/SILCTypes/silc_attribute
 *
 * NAME
 *
 *    #define silc_attribute(attrlist)
 *
 * DESCRIPTION
 *
 *    Compiler attributes.  If compiler doesn't support attributes this macro
 *    doesn't do anything.  Currently this works only with GCC compiler.
 *    See GCC documentation for specified attributes.
 *
 * EXAMPLE
 *
 *    int printf(const char *fmt, ...) silc_attribute((format(printf, 1, 2)));
 *
 ***/
#if defined(__GNUC__)
#define silc_attribute(attrlist) __attribute__(attrlist)
#else
#define silc_attribute(attrlist)
#endif /* __GNUC__ */

/****d* silcutil/SILCTypes/silc_likely
 *
 * NAME
 *
 *    #define silc_likely(expression)
 *
 * DESCRIPTION
 *
 *    Branch prediction macro.  It specifies that it is likely that the branch
 *    where silc_likely is applied is taken.  Compiler will optimize the
 *    code based on this prediction.  Never use this before you have profiled
 *    the code first.
 *
 ***/

/****d* silcutil/SILCTypes/silc_unlikely
 *
 * NAME
 *
 *    #define silc_unlikely(expression)
 *
 * DESCRIPTION
 *
 *    Branch prediction macro.  It specifies that it is unlikely that the
 *    branch where silc_unlikely is applied is taken.  Compiler will optimize
 *    the code based on this prediction.  Never use this before you have
 *    profiled the code first.
 *
 ***/
#if __GNUC__ >= 3
#define silc_likely(expr) __builtin_expect(!!(expr), 1)
#define silc_unlikely(expr) __builtin_expect(!!(expr), 0)
#else
#define silc_likely(expr) (expr)
#define silc_unlikely(expr) (expr)
#endif /* __GNUC__ >= 3 */

/* Prefetch operations.  Use these to prefetch data to CPU cache before
   reading or writing if you think that the data will be needed soon after
   prefetching. */

/****d* silcutil/SILCTypes/silc_prefetch
 *
 * NAME
 *
 *    static inline void silc_prefetch(void *addr, int rw, int locality);
 *
 * DESCRIPTION
 *
 *    Simple prefetch.  Loads memory from specified address to CPU cache.
 *    The amount of data loaded is CPU dependant (cache line length).  The
 *    `rw' argument defines the reason for prefetch: 0=read, 1=write.  The
 *    `locality' argument defines the locality of the prefetch, 0=non-temporal
 *    (non-temporal cache, cache closest to CPU, data will not stay long in
 *    the cache), 1=temporal (L2+ cache), 2=temporal (L2, L3+ cache),
 *    3=temporal (fetch to all caches, data stays longer time in cache).
 *
 * NOTES
 *
 *    This produces only a hint for CPU.  CPU doesn't have to actually
 *    prefetch the data.  Use silc_prefetch_block to ensure CPU always
 *    prefetches.
 *
 ***/

static inline silc_attribute((always_inline))
void silc_prefetch(void *addr, int rw, int locality)
{
#if __GNUC__ > 3
  __builtin_prefetch(addr, rw, locality);
#endif /* __GNUC__ */
}

/****d* silcutil/SILCTypes/silc_prefetch_block
 *
 * NAME
 *
 *    static inline void silc_prefetch_block(void *addr,
 *                                           int prefetch_length,
 *                                           const int cache_line_length)
 *
 * DESCRIPTION
 *
 *    Enforced block prefetch.  This function loads the specified amount
 *    `prefetch_length' of memory from the specified address `addr' to CPU
 *    cache with each loaded cache line being the size of `cache_line_length'.
 *    If you don't know the cache line size use 64 bytes.  Note that, the
 *    `cache_line_length' is a const int.  In this context this mean its
 *    value must not come from a variable but must be a constant (the code
 *    won't compile if it comes from a variable).
 *
 *    The `prefetch_length' must be multiple of twice of the
 *    `cache_line_length' or 128 if you don't know the cache line size, hence
 *    the minimum length for `prefetch_length' is 128 bytes when the
 *    `cache_line_length' is 64 bytes.  Shorter cache line length (32 bytes)
 *    can be used too.
 *
 *    You should use the correct `cache_line_length' value for your CPU or
 *    the value of the CPU for which you want to optimize your code.  Intel
 *    CPUs usually have cache size of 32 or 64 bytes.  The most optimal
 *    prefetch is achieved if the `cache_line_length' is the actual CPU cache
 *    line size.  Always do performance testing with and without prefetching
 *    to make sure the prefetch actually helps.  If used improperly, it may
 *    slow down your program.
 *
 *    The difference to silc_prefetch is that this function always performs
 *    the prefetch and has the ability to prefetch more than one cache line
 *    worth of memory, whereas silc_prefetch can prefetch only one cache line
 *    and may not do the prefetch at all.
 *
 ***/

static inline silc_attribute((always_inline))
void silc_prefetch_block(void *addr,
			 int prefetch_length,
			 const int cache_line_length)
{
#if 0
  SILC_ASSERT(cache_line_length >= 32);
  SILC_ASSERT(cache_line_length % 32 == 0);
  SILC_ASSERT(prefetch_length >= cache_line_length);
  SILC_ASSERT(prefetch_length % (cache_line_length * 2) == 0);
#endif

#if SILC_SIZEOF_VOID_P < 8
#define SILC_PREFETCH_UINT SilcUInt32
#else
#define SILC_PREFETCH_UINT SilcUInt64
#endif /* SILC_SIZEOF_VOID_P < 8 */

#if defined(__GNUC__) && (defined(SILC_I386) || defined(SILC_X86_64))

  /* Assembler implementation.

     The idea here is to simply enforce the CPU to load the requested amount
     of bytes to cache.  We simply mov data from the memory to a register.
     Each mov will load a full cache line worth of data from the memory.

     We expect the `cache_line_length' to be the actual cache line size.
     It doesn't matter if it is.  If it is smaller the prefetch is a bit
     slower as there is redundancy.  If it is larger we skip some of the
     data and don't prefetch everything.

     The loop is unrolled to handle two mov's at once, this why we expect
     the `prefetch_length' to be multiple of twice the length of
     `cache_line_length`.  We also mov the data from end to beginning instead
     of from the beginning to assure CPU doesn't prefetch the data before
     we actually want to do it.

     This technique is described by AMD in:
     http://cdrom.amd.com/devconn/events/AMD_block_prefetch_paper.pdf */

  {
    SILC_PREFETCH_UINT temp;

#define SILC_PREFETCH_ASM(ip, rp)					\
    asm volatile ("1:					\n\t"		\
		  "mov" ip " -%c4(%2, %" rp "3), %0	\n\t"		\
		  "mov" ip " -%c5(%2, %" rp "3), %0	\n\t"		\
		  "sub" ip " %5, %" rp "3		\n\t"		\
		  "jnz 1b				"		\
		  : "=&r" (temp), "=r" (prefetch_length)		\
		  : "r" (addr), "1" (prefetch_length),			\
		    "Z" (cache_line_length),				\
		    "Z" (cache_line_length * 2)				\
		  : "memory", "cc");

#if defined(SILC_I386)
    /* 32-bit prefetch */
    SILC_PREFETCH_ASM("l", "");
#else
    /* 64-bit prefetch */
    SILC_PREFETCH_ASM("q", "q");
#endif /* SILC_I386 */
  }

#else
  /* C implementation.	Yes, you can do it in C too.  In fact, we'll try to
     make the compiler generate nearly identical code to the above assembler
     code.  Note that, the memory access must be volatile, otherwise the
     compiler will optimize them away because the temp variable isn't actually
     used for anything.  This should be as fast as the assembler code above,
     unless the compiler decides to start meddling with it (don't use
     -funroll-loops with this code). */

  {
    register unsigned char *a = addr;
    register int len = prefetch_length;
    register SILC_PREFETCH_UINT temp;

    do {
      temp = *(SILC_PREFETCH_UINT volatile *)
	(a + (len - cache_line_length));
      temp = *(SILC_PREFETCH_UINT volatile *)
	(a + (len - (cache_line_length * 2)));
      len -= (cache_line_length * 2);
    } while (len != 0);
  }
#endif /* __GNUC__ */
#undef SILC_PREFETCH_UINT
#undef SILC_PREFETCH_ASM
}

#endif /* SILCTYPES_H */
