/*

  bitmove.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef BITMOVE_H
#define BITMOVE_H

#define GET_WORD(cp) ((uint32)(uint8)(cp)[0]) << 24	\
		    | ((uint32)(uint8)(cp)[1] << 16)	\
		    | ((uint32)(uint8)(cp)[2] << 8)	\
		    | ((uint32)(uint8)(cp)[3])

/* Returns eight 8-bit bytes, most significant bytes first. */
#define SILC_GET64_MSB(l, cp)			\
       (l) = ((((uint64)GET_WORD((cp))) << 32) |	\
	      ((uint64)GET_WORD((cp) + 4)))
#define SILC_PUT64_MSB(l, cp) 				\
do {							\
  SILC_PUT32_MSB((uint32)((uint64)(l) >> 32), (cp));	\
  SILC_PUT32_MSB((uint32)(l), (cp) + 4); 		\
} while(0)


/* Returns four 8-bit bytes, most significant bytes first. */
#define SILC_GET32_MSB(l, cp)			\
	(l) = ((uint32)(uint8)(cp)[0]) << 24	\
	    | ((uint32)(uint8)(cp)[1] << 16)	\
	    | ((uint32)(uint8)(cp)[2] << 8)	\
	    | ((uint32)(uint8)(cp)[3])
#define SILC_PUT32_MSB(l, cp)			\
	(cp)[0] = l >> 24;			\
	(cp)[1] = l >> 16;			\
	(cp)[2] = l >> 8;			\
	(cp)[3] = l;


/* Returns four 8-bit bytes, less significant bytes first. */
#define SILC_GET32_LSB(l, cp)			\
	(l) = ((uint32)(uint8)(cp)[0])		\
	    | ((uint32)(uint8)(cp)[1] << 8)	\
	    | ((uint32)(uint8)(cp)[2] << 16)	\
	    | ((uint32)(uint8)(cp)[3] << 24)
/* same as upper but XOR the result always */
#define SILC_GET32_X_LSB(l, cp)			\
	(l) ^= ((uint32)(uint8)(cp)[0])		\
	    | ((uint32)(uint8)(cp)[1] << 8)	\
	    | ((uint32)(uint8)(cp)[2] << 16)	\
	    | ((uint32)(uint8)(cp)[3] << 24)
#define SILC_PUT32_LSB(l, cp)			\
	(cp)[0] = l;				\
	(cp)[1] = l >> 8;			\
	(cp)[2] = l >> 16;			\
	(cp)[3] = l >> 24;


/* Returns two 8-bit bytes, most significant bytes first. */
#define SILC_GET16_MSB(l, cp)			\
	(l) = ((uint32)(uint8)(cp)[0] << 8)	\
	    | ((uint32)(uint8)(cp)[1])
#define SILC_PUT16_MSB(l, cp)			\
	(cp)[0] = l >> 8;			\
	(cp)[1] = l;

/* Returns two 8-bit bytes, less significant bytes first. */
#define SILC_GET16_LSB(l, cp)			\
	(l) = ((uint32)(uint8)(cp)[0])		\
	    | ((uint32)(uint8)(cp)[1] << 8)
#define SILC_PUT16_LSB(l, cp)			\
	(cp)[0] = l;				\
	(cp)[1] = l >> 8;

#endif
