/*

  silctypes.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2004 Pekka Riikonen

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
 *    This header includes the most basic types used in the SILC source
 *    tree, such as arithmetic types and their manipulation macros.  This
 *    file is included in the silcincludes.h and is automatically available
 *    for application.
 *
 ***/

#ifndef SILCTYPES_H
#define SILCTYPES_H

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

/****d* silcutil/SILCTypes/bool
 *
 * NAME
 *
 *    #define bool ...
 *
 * DESCRIPTION
 *
 *    Boolean value, and is 8-bits.  Represents value 0 or 1.  In
 *    C++ code this type is defined by the C++, and this definition is
 *    not used.
 *
 * NOTES
 *
 *    This macro is deprecated.  Use SilcBool instead.
 *
 * SOURCE
 */
#ifdef SILC_MACOSX
#define bool _Bool
#endif

#ifndef __cplusplus
#ifndef bool
#define bool unsigned char
#endif
#endif
/***/

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
typedef unigned char SilcBool;

#define silc_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

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

/* Macros */

#define SILC_GET_WORD(cp) ((SilcUInt32)(SilcUInt8)(cp)[0]) << 24	\
		    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 16)		\
		    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 8)		\
		    | ((SilcUInt32)(SilcUInt8)(cp)[3])

/****d* silcutil/SILCTypes/SILC_GET16_MSB
 *
 * NAME
 *
 *    #define SILC_GET16_MSB ...
 *
 * DESCRIPTION
 *
 *    Return two 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#define SILC_GET16_MSB(l, cp)				\
do {							\
	(l) = ((SilcUInt32)(SilcUInt8)(cp)[0] << 8)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[1]);		\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_GET32_MSB
 *
 * NAME
 *
 *    #define SILC_GET32_MSB ...
 *
 * DESCRIPTION
 *
 *    Return four 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#define SILC_GET32_MSB(l, cp)				\
do {							\
	(l) = ((SilcUInt32)(SilcUInt8)(cp)[0]) << 24	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 16)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 8)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[3]);		\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_GET64_MSB
 *
 * NAME
 *
 *    #define SILC_GET64_MSB ...
 *
 * DESCRIPTION
 *
 *    Return eight 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#define SILC_GET64_MSB(l, cp)					\
do {								\
       (l) = ((((SilcUInt64)SILC_GET_WORD((cp))) << 32) |	\
	      ((SilcUInt64)SILC_GET_WORD((cp) + 4)));		\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_GET16_LSB
 *
 * NAME
 *
 *    #define SILC_GET16_MSB ...
 *
 * DESCRIPTION
 *
 *    Return two 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#define SILC_GET16_LSB(l, cp)				\
do {							\
	(l) = ((SilcUInt32)(SilcUInt8)(cp)[0])		\
	    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 8);	\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_GET32_LSB
 *
 * NAME
 *
 *    #define SILC_GET32_LSB ...
 *
 * DESCRIPTION
 *
 *    Return four 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#define SILC_GET32_LSB(l, cp)				\
do {							\
	(l) = ((SilcUInt32)(SilcUInt8)(cp)[0])		\
	    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 8)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 16)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[3] << 24);	\
} while(0)

/* Same as upper but XOR the result always. Special purpose macro. */
#define SILC_GET32_X_LSB(l, cp)				\
	(l) ^= ((SilcUInt32)(SilcUInt8)(cp)[0])		\
	    | ((SilcUInt32)(SilcUInt8)(cp)[1] << 8)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[2] << 16)	\
	    | ((SilcUInt32)(SilcUInt8)(cp)[3] << 24)
/***/

/****d* silcutil/SILCTypes/SILC_PUT16_MSB
 *
 * NAME
 *
 *    #define SILC_PUT16_MSB ...
 *
 * DESCRIPTION
 *
 *    Put two 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#define SILC_PUT16_MSB(l, cp)			\
do {						\
	(cp)[0] = (SilcUInt8)((l) >> 8);	\
	(cp)[1] = (SilcUInt8)(l);		\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_PUT32_MSB
 *
 * NAME
 *
 *    #define SILC_PUT32_MSB ...
 *
 * DESCRIPTION
 *
 *    Put four 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#define SILC_PUT32_MSB(l, cp)			\
do {						\
	(cp)[0] = (SilcUInt8)((l) >> 24);	\
	(cp)[1] = (SilcUInt8)((l) >> 16);	\
	(cp)[2] = (SilcUInt8)((l) >> 8);	\
	(cp)[3] = (SilcUInt8)(l);		\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_PUT64_MSB
 *
 * NAME
 *
 *    #define SILC_PUT64_MSB ...
 *
 * DESCRIPTION
 *
 *    Put eight 8-bit bytes, most significant bytes first.
 *
 * SOURCE
 */
#define SILC_PUT64_MSB(l, cp)					\
do {								\
  SILC_PUT32_MSB((SilcUInt32)((SilcUInt64)(l) >> 32), (cp));	\
  SILC_PUT32_MSB((SilcUInt32)(l), (cp) + 4);			\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_PUT16_LSB
 *
 * NAME
 *
 *    #define SILC_PUT16_LSB ...
 *
 * DESCRIPTION
 *
 *    Put two 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#define SILC_PUT16_LSB(l, cp)			\
do  {						\
	(cp)[0] = (SilcUInt8)(l);		\
	(cp)[1] = (SilcUInt8)((l) >> 8);	\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_PUT32_LSB
 *
 * NAME
 *
 *    #define SILC_PUT32_LSB ...
 *
 * DESCRIPTION
 *
 *    Put four 8-bit bytes, least significant bytes first.
 *
 * SOURCE
 */
#define SILC_PUT32_LSB(l, cp)			\
do {						\
	(cp)[0] = (SilcUInt8)(l);		\
	(cp)[1] = (SilcUInt8)((l) >> 8);	\
	(cp)[2] = (SilcUInt8)((l) >> 16);	\
	(cp)[3] = (SilcUInt8)((l) >> 24);	\
} while(0)
/***/

/****d* silcutil/SILCTypes/SILC_SWAB_16
 *
 * NAME
 *
 *    #define SILC_SWAB_16 ...
 *
 * DESCRIPTION
 *
 *    Swabs 16-bit unsigned integer byte order.
 *
 * SOURCE
 */
#define SILC_SWAB_16(l)						\
  ((SilcUInt16)(((SilcUInt16)(l) & (SilcUInt16)0x00FFU) << 8) |	\
               (((SilcUInt16)(l) & (SilcUInt16)0xFF00U) >> 8))
/***/

/****d* silcutil/SILCTypes/SILC_SWAB_32
 *
 * NAME
 *
 *    #define SILC_SWAB_32 ...
 *
 * DESCRIPTION
 *
 *    Swabs 32-bit unsigned integer byte order.
 *
 * SOURCE
 */
#define SILC_SWAB_32(l)							\
  ((SilcUInt32)(((SilcUInt32)(l) & (SilcUInt32)0x000000FFUL) << 24) |	\
               (((SilcUInt32)(l) & (SilcUInt32)0x0000FF00UL) << 8)  |	\
               (((SilcUInt32)(l) & (SilcUInt32)0x00FF0000UL) >> 8)  |	\
               (((SilcUInt32)(l) & (SilcUInt32)0xFF000000UL) >> 24))
/***/

/****d* silcutil/SILCTypes/SILC_PTR_TO_32
 *
 * NAME
 *
 *    #define SILC_PTR_TO_32 ...
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
 *    #define SILC_PTR_TO_64 ...
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
#define SILC_PTR_TO_64(_ptr__) 						\
  ((SilcUInt64)((SilcUInt64)(_ptr__) & (SilcUInt32)0xFFFFFFFFUL))
#endif
/***/

/****d* silcutil/SILCTypes/SILC_32_TO_PTR
 *
 * NAME
 *
 *    #define SILC_PTR_TO_32 ...
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
 *    #define SILC_PTR_TO_64 ...
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

#endif /* SILCTYPES_H */
