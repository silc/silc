/*

  silcbitops.c

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

#include "silc.h"

#define SILC_BIT_POS(bit) (bit / SILC_BIT_SIZE)
#define SILC_BIT_MASK(bit) (1UL << (bit % SILC_BIT_SIZE))

/* Set bit */

SilcBool silc_bit_set(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		      SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit);

  if (!bitmap || pos >= bitmap_size)
    return FALSE;

  bitmap[pos] |= mask;
  return TRUE;
}

/* Clear bit */

SilcBool silc_bit_clear(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
			SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit);

  if (!bitmap || pos >= bitmap_size)
    return FALSE;

  bitmap[pos] &= ~mask;
  return TRUE;
}

/* Toggle bit */

SilcBool silc_bit_toggle(volatile unsigned long *bitmap,
			 SilcUInt32 bitmap_size, SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit);

  if (!bitmap || pos >= bitmap_size)
    return FALSE;

  bitmap[pos] ^= mask;
  return TRUE;
}

/* Set bit and return old value */

int silc_bit_test_and_set(volatile unsigned long *bitmap,
			  SilcUInt32 bitmap_size, SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit), ret;

  if (!bitmap || pos >= bitmap_size)
    return -1;

  ret = bitmap[pos];
  bitmap[pos] ^= mask;

  return (ret & mask) != 0;
}

/* Clear bit and return old value */

int silc_bit_test_and_clear(volatile unsigned long *bitmap,
			    SilcUInt32 bitmap_size, SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit), ret;

  if (!bitmap || pos >= bitmap_size)
    return -1;

  ret = bitmap[pos];
  bitmap[pos] &= ~mask;

  return (ret & mask) != 0;
}

/* Toggle bit and return old value */

int silc_bit_test_and_toggle(volatile unsigned long *bitmap,
			     SilcUInt32 bitmap_size, SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit), ret;

  if (!bitmap || pos >= bitmap_size)
    return -1;

  ret = bitmap[pos];
  bitmap[pos] ^= mask;

  return (ret & mask) != 0;
}

/* Return bit value */

int silc_bit_get(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		 SilcUInt32 bit)
{
  SilcUInt32 pos = SILC_BIT_POS(bit);
  unsigned long mask = SILC_BIT_MASK(bit);

  if (!bitmap || pos >= bitmap_size)
    return -1;

  return (bitmap[pos] & mask) != 0;
}

/* Return first set bit number */

int silc_bit_ffs(volatile unsigned long *bitmap, SilcUInt32 bitmap_size)
{
  return silc_bit_fns(bitmap, bitmap_size, 0);
}

/* Return first zero bit number */

int silc_bit_ffz(volatile unsigned long *bitmap, SilcUInt32 bitmap_size)
{
  return silc_bit_fnz(bitmap, bitmap_size, 0);
}

/* Return next set bit number */

int silc_bit_fns(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		 SilcUInt32 offset)
{
  register SilcUInt32 i;

  if (!bitmap || offset >= bitmap_size * SILC_BIT_SIZE)
    return -1;

  for (i = offset; i < bitmap_size * SILC_BIT_SIZE; i++)
    if (bitmap[SILC_BIT_POS(i)] & SILC_BIT_MASK(i))
      return i;

  return -1;
}

/* Return next zero bit number */

int silc_bit_fnz(volatile unsigned long *bitmap, SilcUInt32 bitmap_size,
		 SilcUInt32 offset)
{
  register SilcUInt32 i;

  if (!bitmap || offset >= bitmap_size * SILC_BIT_SIZE)
    return -1;

  for (i = offset; i < bitmap_size * SILC_BIT_SIZE; i++)
    if ((bitmap[SILC_BIT_POS(i)] & SILC_BIT_MASK(i)) == 0)
      return i;

  return -1;
}

/* Clear bitmap */

void silc_bit_clear_bitmap(volatile unsigned long *bitmap,
			   SilcUInt32 bitmap_size)
{
  if (!bitmap)
    return;
  memset((void *)bitmap, 0, bitmap_size * 8);
}
