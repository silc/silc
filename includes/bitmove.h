/*

  bitmove.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef BITMOVE_H
#define BITMOVE_H

/* Returns four 8-bit bytes, most significant bytes first. */
#define SILC_GET32_MSB(l, cp) \
	(l) = ((unsigned long)(unsigned char)(cp)[0]) << 24 \
	    | ((unsigned long)(unsigned char)(cp)[1] << 16) \
	    | ((unsigned long)(unsigned char)(cp)[2] << 8) \
	    | ((unsigned long)(unsigned char)(cp)[3])
#define SILC_PUT32_MSB(l, cp) \
	(cp)[0] = l >> 24; \
	(cp)[1] = l >> 16; \
	(cp)[2] = l >> 8; \
	(cp)[3] = l;


/* Returns four 8-bit bytes, less significant bytes first. */
#define SILC_GET32_LSB(l, cp) \
	(l) = ((unsigned long)(unsigned char)(cp)[0]) \
	    | ((unsigned long)(unsigned char)(cp)[1] << 8) \
	    | ((unsigned long)(unsigned char)(cp)[2] << 16) \
	    | ((unsigned long)(unsigned char)(cp)[3] << 24)
/* same as upper but XOR the result always */
#define SILC_GET32_X_LSB(l, cp) \
	(l) ^= ((unsigned long)(unsigned char)(cp)[0]) \
	    | ((unsigned long)(unsigned char)(cp)[1] << 8) \
	    | ((unsigned long)(unsigned char)(cp)[2] << 16) \
	    | ((unsigned long)(unsigned char)(cp)[3] << 24)
#define SILC_PUT32_LSB(l, cp) \
	(cp)[0] = l; \
	(cp)[1] = l >> 8; \
	(cp)[2] = l >> 16; \
	(cp)[3] = l >> 24;


/* Returns two 8-bit bytes, most significant bytes first. */
#define SILC_GET16_MSB(l, cp) \
	(l) = ((unsigned long)(unsigned char)(cp)[0] << 8) \
	    | ((unsigned long)(unsigned char)(cp)[1])
#define SILC_PUT16_MSB(l, cp) \
	(cp)[0] = l >> 8; \
	(cp)[1] = l;

/* Returns two 8-bit bytes, less significant bytes first. */
#define SILC_GET16_LSB(l, cp) \
	(l) = ((unsigned long)(unsigned char)(cp)[0]) \
	    | ((unsigned long)(unsigned char)(cp)[1] << 8)
#define SILC_PUT16_LSB(l, cp) \
	(cp)[0] = l; \
	(cp)[1] = l >> 8;

#endif
