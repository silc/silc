/*

  silcbitops.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Bit Operations Interface
 *
 * DESCRIPTION
 *
 * Bit operations interface.  The interface can be used to set, clear and
 * find bits in an arbitrarily large bitmap.  The interface does not support
 * setting the bits atomically.
 *
 * Example with a pre-allocated bitmap:
 *
 * // Declare bitmap of size of 500 bits
 * SILC_BITMAP_DECLARE(bitmap, 500);
 * int bitmap_size = SILC_BITMAP_SIZE(500);
 *
 * // Set 0 bit
 * silc_bit_set(bitmap, bitmap_size, 0);
 *
 * // Set bit number 100
 * silc_bit_set(bitmap, bitmap_size, 100);
 *
 * // Find first set bit from the bitmap
 * bit = silc_bit_ffs(bitmap, bitmap_size);
 *
 * // Find next set bit from the bitmap
 * bit = silc_bit_fns(bitmap, bitmap_size, bit + 1);
 *
 * // Clear bit number 100
 * silc_bit_set(bitmap, bitmap_size, 100);
 *
 ***/

#ifndef SILCBITOPS_H
#define SILCBITOPS_H

#define SILC_BIT_SIZE (SILC_SIZEOF_LONG * 8)

/****d* silcutil/SilcBitOpAPI/SILC_BITMAP_DECLARE
 *
 * NAME
 *
 *    #define SILC_BITMAP_DECLARE(name, bits)
 *
 * DESCRIPTION
 *
 *    Macro that can be used to declare a pre-allocated bitmap named `name' of
 *    size of `bits' many bits.
 *
 ***/
#define SILC_BITMAP_DECLARE(name, bits)		\
  unsigned long name[SILC_BITMAP_SIZE(bits)]

/****d* silcutil/SilcBitOpAPI/SILC_BITMAP_SIZE
 *
 * NAME
 *
 *    #define SILC_BITMAP_SIZE(bits)
 *
 * DESCRIPTION
 *
 *    Macro that returns the size of a bitmap array of size of `bits' many
 *    bits.  The returned size can be given as argument to the SILC Bit
 *    Operations API functions.
 *
 ***/
#define SILC_BITMAP_SIZE(bits) (((bits) + SILC_BIT_SIZE) / SILC_BIT_SIZE)

/****f* silcutil/SilcBitOpAPI/silc_bit_set
 *
 * SYNOPSIS
 *
 *    SilcBool silc_bit_set(volatile unsigned long *bitmap,
 *                          SilcUInt32 bitmap_size, SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Set bit number `bit' in the `bitmap' of size of `bitmap_size'.  Returns
 *    FALSE on error.
 *
 ***/
SilcBool silc_bit_set(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		      SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_clear
 *
 * SYNOPSIS
 *
 *    SilcBool silc_bit_clear(volatile unsigned long *bitmap,
 *                           SilcUInt32 bitmap_size,  SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Clear bit number `bit' in the `bitmap' of size of `bitmap_size'.
 *    Returns FALSE on error.
 *
 ***/
SilcBool silc_bit_clear(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
			SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_toggle
 *
 * SYNOPSIS
 *
 *    SilcBool silc_bit_toggle(volatile unsigned long *bitmap,
 *                             SilcUInt32 bitmap_size, SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Toggle bit number `bit' in the `bitmap' of size of `bitmap_size'.
 *    Returns FALSE on error.
 *
 ***/
SilcBool silc_bit_toggle(volatile unsigned long *bitmap,
			 SilcUInt32 bitmap_size, SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_test_and_set
 *
 * SYNOPSIS
 *
 *    int silc_bit_test_and_set(volatile unsigned long *bitmap,
 *                              SilcUInt32 bitmap_size, SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Set bit number `bit' in the `bitmap' of size of `bitmap_size' and
 *    return the value before setting.  Returns -1 on error.
 *
 ***/
int silc_bit_test_and_set(volatile unsigned long *bitmap,
			  SilcUInt32 bitmap_size, SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_test_and_clear
 *
 * SYNOPSIS
 *
 *    int silc_bit_test_and_clear(volatile unsigned long *bitmap,
 *                               SilcUInt32 bitmap_size,  SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Clear bit number `bit' in the `bitmap' of size of `bitmap_size' and
 *    return the value before setting.  Returns -1 on error.
 *
 ***/
int silc_bit_test_and_clear(volatile unsigned long *bitmap,
			    SilcUInt32 bitmap_size, SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_test_and_toggle
 *
 * SYNOPSIS
 *
 *    int silc_bit_test_and_toggle(volatile unsigned long *bitmap,
 *                                 SilcUInt32 bitmap_size, SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Toggle bit number `bit' in the `bitmap' of size of `bitmap_size' and
 *    return the value before setting.  Returns -1 on error.
 *
 ***/
int silc_bit_test_and_toggle(volatile unsigned long *bitmap,
			     SilcUInt32 bitmap_size, SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_get
 *
 * SYNOPSIS
 *
 *    int silc_bit_get(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
 *                     SilcUInt32 bit);
 *
 * DESCRIPTION
 *
 *    Returns the value of the bit number `bit' or -1 on error.
 *
 ***/
int silc_bit_get(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		 SilcUInt32 bit);

/****f* silcutil/SilcBitOpAPI/silc_bit_ffs
 *
 * SYNOPSIS
 *
 *    int silc_bit_ffs(volatile unsigned long *bitmap, SilcUInt32 bitmap_size);
 *
 * DESCRIPTION
 *
 *    Returns the bit number of the first set bit in the `bitmap' of size
 *    of `bitmap_size'.  Returns -1 on error or when there were no set bits.
 *
 ***/
int silc_bit_ffs(volatile unsigned long *bitmap, SilcUInt32 bitmap_size);

/****f* silcutil/SilcBitOpAPI/silc_bit_ffz
 *
 * SYNOPSIS
 *
 *    int silc_bit_ffz(volatile unsigned long *bitmap, SilcUInt32 bitmap_size);
 *
 * DESCRIPTION
 *
 *    Returns the bit number of the first zero bit in the `bitmap' of size
 *    of `bitmap_size'.  Returns -1 on error or when there were no zero bits.
 *
 ***/
int silc_bit_ffz(volatile unsigned long *bitmap, SilcUInt32 bitmap_size);

/****f* silcutil/SilcBitOpAPI/silc_bit_fns
 *
 * SYNOPSIS
 *
 *    int silc_bit_fns(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
 *                     SilcUInt32 offset);
 *
 * DESCRIPTION
 *
 *    Returns the bit number of the next set bit in the `bitmap' of size
 *    of `bitmap_size' starting at bit `offset'.  Returns -1 on error or
 *    when there were no more set bits.
 *
 ***/
int silc_bit_fns(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		 SilcUInt32 offset);

/****f* silcutil/SilcBitOpAPI/silc_bit_fnz
 *
 * SYNOPSIS
 *
 *    int silc_bit_fnz(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
 *                     SilcUInt32 offset);
 *
 * DESCRIPTION
 *
 *    Returns the bit number of the next zero bit in the `bitmap' of size
 *    of `bitmap_size' starting at bit `offset'.  Returns -1 on error or
 *    when there were no more zero bits.
 *
 ***/
int silc_bit_fnz(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		 SilcUInt32 offset);

/****f* silcutil/SilcBitOpAPI/silc_bit_clear_bitmap
 *
 * SYNOPSIS
 *
 *    void silc_bit_clear_bitmap(volatile unsigned long *bitmap,
 *                               SilcUInt32 bitmap_size);
 *
 * DESCRIPTION
 *
 *    Clears the whole bitmap.
 *
 ***/
void silc_bit_clear_bitmap(volatile unsigned long *bitmap,
			   SilcUInt32 bitmap_size);

#endif /* SILCBITOPS_H */
