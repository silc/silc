/*

  ciphers_def.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CIPHERS_DEF_H
#define CIPHERS_DEF_H

/* General definitions for algorithms */
typedef unsigned char u1byte;
typedef SilcUInt32 u4byte;
typedef SilcUInt32 u32;
typedef SilcUInt32 uint_32t;
typedef SilcUInt8 uint_8t;

#define rotr(x, nr) (((x) >> ((int)(nr))) | ((x) << (32 - (int)(nr))))
#define rotl(x, nr) (((x) << ((int)(nr))) | ((x) >> (32 - (int)(nr))))
#define byte(x, nr) ((x) >> (nr * 8) & 255)

/* Byte key to words */
#define SILC_GET_WORD_KEY(s, d, len)		\
do {						\
  int _i;					\
  for (_i = 0; _i < (len / 8) / 4; _i++)	\
    SILC_GET32_LSB(d[_i], s + (_i * 4));	\
} while(0);

/* CBC mode 128-bit block, LSB, 32-bit block argument must be encrypted */

#define SILC_CBC_ENC_LSB_128_32(len, iv, block, src, dst, i, enc)	\
do {									\
  SILC_ASSERT((len & (16 - 1)) == 0);					\
  if (len & (16 - 1))							\
    return FALSE;							\
  									\
  SILC_GET32_LSB(block[0], &iv[0]);					\
  SILC_GET32_LSB(block[1], &iv[4]);					\
  SILC_GET32_LSB(block[2], &iv[8]);					\
  SILC_GET32_LSB(block[3], &iv[12]);					\
  									\
  for (i = 0; i < len; i += 16) {					\
    SILC_GET32_X_LSB(block[0], &src[0]);				\
    SILC_GET32_X_LSB(block[1], &src[4]);				\
    SILC_GET32_X_LSB(block[2], &src[8]);				\
    SILC_GET32_X_LSB(block[3], &src[12]);				\
									\
    enc;								\
    									\
    SILC_PUT32_LSB(block[0], &dst[0]);					\
    SILC_PUT32_LSB(block[1], &dst[4]);					\
    SILC_PUT32_LSB(block[2], &dst[8]);					\
    SILC_PUT32_LSB(block[3], &dst[12]);					\
    									\
    dst += 16;								\
    src += 16;								\
  }									\
  									\
  SILC_PUT32_LSB(block[0], &iv[0]);					\
  SILC_PUT32_LSB(block[1], &iv[4]);					\
  SILC_PUT32_LSB(block[2], &iv[8]);					\
  SILC_PUT32_LSB(block[3], &iv[12]);					\
} while(0)

/* CBC mode 128-bit block, LSB, decrypt block to block_dec. */

#define SILC_CBC_DEC_LSB_128_32(len, iv, block_prev, block,		\
				block_dec, src, dst, i, dec)		\
do {									\
  if (len & (16 - 1))							\
    return FALSE;							\
  									\
  SILC_GET32_LSB(block_prev[0], &iv[0]);				\
  SILC_GET32_LSB(block_prev[1], &iv[4]);				\
  SILC_GET32_LSB(block_prev[2], &iv[8]);				\
  SILC_GET32_LSB(block_prev[3], &iv[12]);				\
  									\
  for (i = 0; i < len; i += 16) {					\
    SILC_GET32_LSB(block[0], &src[0]);					\
    SILC_GET32_LSB(block[1], &src[4]);					\
    SILC_GET32_LSB(block[2], &src[8]);					\
    SILC_GET32_LSB(block[3], &src[12]);					\
    									\
    dec;								\
    									\
    block_dec[0] ^= block_prev[0];					\
    block_dec[1] ^= block_prev[1];					\
    block_dec[2] ^= block_prev[2];					\
    block_dec[3] ^= block_prev[3];					\
    									\
    SILC_PUT32_LSB(block_dec[0], &dst[0]);				\
    SILC_PUT32_LSB(block_dec[1], &dst[4]);				\
    SILC_PUT32_LSB(block_dec[2], &dst[8]);				\
    SILC_PUT32_LSB(block_dec[3], &dst[12]);				\
    									\
    block_prev[0] = block[0];						\
    block_prev[1] = block[1];						\
    block_prev[2] = block[2];						\
    block_prev[3] = block[3];						\
    									\
    dst += 16;								\
    src += 16;								\
  }									\
  									\
  SILC_PUT32_LSB(block[0], &iv[0]);					\
  SILC_PUT32_LSB(block[1], &iv[4]);					\
  SILC_PUT32_LSB(block[2], &iv[8]);					\
  SILC_PUT32_LSB(block[3], &iv[12]);					\
} while(0)

/* CBC mode 128-bit block, MSB, 32-bit block argument must be encrypted */

#define SILC_CBC_ENC_MSB_128_32(len, iv, block, src, dst, i, enc)	\
do {									\
  SILC_ASSERT((len & (16 - 1)) == 0);					\
  if (len & (16 - 1))							\
    return FALSE;							\
  									\
  SILC_GET32_MSB(block[0], &iv[0]);					\
  SILC_GET32_MSB(block[1], &iv[4]);					\
  SILC_GET32_MSB(block[2], &iv[8]);					\
  SILC_GET32_MSB(block[3], &iv[12]);					\
  									\
  for (i = 0; i < len; i += 16) {					\
    SILC_GET32_X_MSB(block[0], &src[0]);				\
    SILC_GET32_X_MSB(block[1], &src[4]);				\
    SILC_GET32_X_MSB(block[2], &src[8]);				\
    SILC_GET32_X_MSB(block[3], &src[12]);				\
									\
    enc;								\
    									\
    SILC_PUT32_MSB(block[0], &dst[0]);					\
    SILC_PUT32_MSB(block[1], &dst[4]);					\
    SILC_PUT32_MSB(block[2], &dst[8]);					\
    SILC_PUT32_MSB(block[3], &dst[12]);					\
    									\
    dst += 16;								\
    src += 16;								\
  }									\
  									\
  SILC_PUT32_MSB(block[0], &iv[0]);					\
  SILC_PUT32_MSB(block[1], &iv[4]);					\
  SILC_PUT32_MSB(block[2], &iv[8]);					\
  SILC_PUT32_MSB(block[3], &iv[12]);					\
} while(0)

/* CBC mode 128-bit block, MSB, decrypt block to block_dec. */

#define SILC_CBC_DEC_MSB_128_32(len, iv, block_prev, block,		\
				block_dec, src, dst, i, dec)		\
do {									\
  if (len & (16 - 1))							\
    return FALSE;							\
  									\
  SILC_GET32_MSB(block_prev[0], &iv[0]);				\
  SILC_GET32_MSB(block_prev[1], &iv[4]);				\
  SILC_GET32_MSB(block_prev[2], &iv[8]);				\
  SILC_GET32_MSB(block_prev[3], &iv[12]);				\
  									\
  for (i = 0; i < len; i += 16) {					\
    SILC_GET32_MSB(block[0], &src[0]);					\
    SILC_GET32_MSB(block[1], &src[4]);					\
    SILC_GET32_MSB(block[2], &src[8]);					\
    SILC_GET32_MSB(block[3], &src[12]);					\
    									\
    dec;								\
    									\
    block_dec[0] ^= block_prev[0];					\
    block_dec[1] ^= block_prev[1];					\
    block_dec[2] ^= block_prev[2];					\
    block_dec[3] ^= block_prev[3];					\
    									\
    SILC_PUT32_MSB(block_dec[0], &dst[0]);				\
    SILC_PUT32_MSB(block_dec[1], &dst[4]);				\
    SILC_PUT32_MSB(block_dec[2], &dst[8]);				\
    SILC_PUT32_MSB(block_dec[3], &dst[12]);				\
    									\
    block_prev[0] = block[0];						\
    block_prev[1] = block[1];						\
    block_prev[2] = block[2];						\
    block_prev[3] = block[3];						\
    									\
    dst += 16;								\
    src += 16;								\
  }									\
  									\
  SILC_PUT32_MSB(block[0], &iv[0]);					\
  SILC_PUT32_MSB(block[1], &iv[4]);					\
  SILC_PUT32_MSB(block[2], &iv[8]);					\
  SILC_PUT32_MSB(block[3], &iv[12]);					\
} while(0)

/* CBC mode 64-bit block, MSB, 32-bit block argument must be encrypted */

#define SILC_CBC_ENC_MSB_64_32(len, iv, block, src, dst, i, enc)	\
do {									\
  SILC_ASSERT((len & (8 - 1)) == 0);					\
  if (len & (8 - 1))							\
    return FALSE;							\
  									\
  SILC_GET32_MSB(block[0], &iv[0]);					\
  SILC_GET32_MSB(block[1], &iv[4]);					\
  									\
  for (i = 0; i < len; i += 8) {					\
    SILC_GET32_X_MSB(block[0], &src[0]);				\
    SILC_GET32_X_MSB(block[1], &src[4]);				\
									\
    enc;								\
    									\
    SILC_PUT32_MSB(block[0], &dst[0]);					\
    SILC_PUT32_MSB(block[1], &dst[4]);					\
    									\
    dst += 8;								\
    src += 8;								\
  }									\
  									\
  SILC_PUT32_MSB(block[0], &iv[0]);					\
  SILC_PUT32_MSB(block[1], &iv[4]);					\
} while(0)

/* CBC mode 64-bit block, MSB, decrypt block to block_dec. */

#define SILC_CBC_DEC_MSB_64_32(len, iv, block_prev, block,		\
			       block_dec, src, dst, i, dec)		\
do {									\
  if (len & (8 - 1))							\
    return FALSE;							\
  									\
  SILC_GET32_MSB(block_prev[0], &iv[0]);				\
  SILC_GET32_MSB(block_prev[1], &iv[4]);				\
  									\
  for (i = 0; i < len; i += 8) {					\
    SILC_GET32_MSB(block[0], &src[0]);					\
    SILC_GET32_MSB(block[1], &src[4]);					\
    									\
    dec;								\
    									\
    block_dec[0] ^= block_prev[0];					\
    block_dec[1] ^= block_prev[1];					\
    									\
    SILC_PUT32_MSB(block_dec[0], &dst[0]);				\
    SILC_PUT32_MSB(block_dec[1], &dst[4]);				\
    									\
    block_prev[0] = block[0];						\
    block_prev[1] = block[1];						\
    									\
    dst += 8;								\
    src += 8;								\
  }									\
  									\
  SILC_PUT32_MSB(block[0], &iv[0]);					\
  SILC_PUT32_MSB(block[1], &iv[4]);					\
} while(0)


/* CTR mode 128-bit block, MSB, MSB counter, the 8-bit enc_ctr argument must
   be encrypted */

#define SILC_CTR_MSB_128_8(iv, ctr, enc_ctr, pad, src, dst, enc)	\
do {									\
  SILC_GET32_MSB(ctr[0], iv);						\
  SILC_GET32_MSB(ctr[1], iv + 4);					\
  SILC_GET32_MSB(ctr[2], iv + 8);					\
  SILC_GET32_MSB(ctr[3], iv + 12);					\
  									\
  if (pad == 0)								\
    pad = 16;								\
  									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      if (++ctr[3] == 0)						\
	if (++ctr[2] == 0)						\
	  if (++ctr[1] == 0)						\
	    ++ctr[0];							\
      									\
      SILC_PUT32_MSB(ctr[0], enc_ctr);					\
      SILC_PUT32_MSB(ctr[1], enc_ctr + 4);				\
      SILC_PUT32_MSB(ctr[2], enc_ctr + 8);				\
      SILC_PUT32_MSB(ctr[3], enc_ctr + 12);				\
      									\
      enc;								\
      pad = 0;								\
    }									\
    *dst++ = *src++ ^ enc_ctr[pad++];					\
  }									\
  									\
  SILC_PUT32_MSB(ctr[0], iv);						\
  SILC_PUT32_MSB(ctr[1], iv + 4);					\
  SILC_PUT32_MSB(ctr[2], iv + 8);					\
  SILC_PUT32_MSB(ctr[3], iv + 12);					\
} while(0)

/* CTR mode 128-bit block, MSB, MSB counter, the 32-bit ctr argument must
   be encrypted to enc_ctr */

#define SILC_CTR_MSB_128_32(iv, ctr, enc_ctr, pad, src, dst, enc)	\
do {									\
  SILC_GET32_MSB(ctr[0], iv);						\
  SILC_GET32_MSB(ctr[1], iv + 4);					\
  SILC_GET32_MSB(ctr[2], iv + 8);					\
  SILC_GET32_MSB(ctr[3], iv + 12);					\
  									\
  if (pad == 0)								\
    pad = 16;								\
  									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      if (++ctr[3] == 0)						\
	if (++ctr[2] == 0)						\
	  if (++ctr[1] == 0)						\
	    ++ctr[0];							\
      									\
      enc;								\
      SILC_PUT32_MSB(enc_ctr[0], iv);					\
      SILC_PUT32_MSB(enc_ctr[1], iv + 4);				\
      SILC_PUT32_MSB(enc_ctr[2], iv + 8);				\
      SILC_PUT32_MSB(enc_ctr[3], iv + 12);				\
      pad = 0;								\
    }									\
    *dst++ = *src++ ^ enc_ctr[pad++];					\
  }									\
  									\
  SILC_PUT32_MSB(ctr[0], iv);						\
  SILC_PUT32_MSB(ctr[1], iv + 4);					\
  SILC_PUT32_MSB(ctr[2], iv + 8);					\
  SILC_PUT32_MSB(ctr[3], iv + 12);					\
} while(0)

/* CTR mode 128-bit block, LSB, MSB counter, the 32-bit enc_ctr argument
   must be encrypted */

#define SILC_CTR_LSB_128_32(iv, ctr, enc_ctr, pad, src, dst, enc)	\
do {									\
  SILC_GET32_MSB(ctr[0], iv);						\
  SILC_GET32_MSB(ctr[1], iv + 4);					\
  SILC_GET32_MSB(ctr[2], iv + 8);					\
  SILC_GET32_MSB(ctr[3], iv + 12);					\
  									\
  if (pad == 0)								\
    pad = 16;								\
  									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      if (++ctr[3] == 0)						\
	if (++ctr[2] == 0)						\
	  if (++ctr[1] == 0)						\
	    ++ctr[0];							\
      									\
      enc_ctr[0] = SILC_SWAB_32(ctr[0]);				\
      enc_ctr[1] = SILC_SWAB_32(ctr[1]);				\
      enc_ctr[2] = SILC_SWAB_32(ctr[2]);				\
      enc_ctr[3] = SILC_SWAB_32(ctr[3]);				\
      									\
      enc;								\
      SILC_PUT32_LSB(enc_ctr[0], iv);					\
      SILC_PUT32_LSB(enc_ctr[1], iv + 4);				\
      SILC_PUT32_LSB(enc_ctr[2], iv + 8);				\
      SILC_PUT32_LSB(enc_ctr[3], iv + 12);				\
      pad = 0;								\
    }									\
    *dst++ = *src++ ^ iv[pad++];					\
  }									\
  									\
  SILC_PUT32_MSB(ctr[0], iv);						\
  SILC_PUT32_MSB(ctr[1], iv + 4);					\
  SILC_PUT32_MSB(ctr[2], iv + 8);					\
  SILC_PUT32_MSB(ctr[3], iv + 12);					\
} while(0)

/* CTR mode 64-bit block, MSB, MSB counter, the 32-bit ctr argument must
   be encrypted to enc_ctr */

#define SILC_CTR_MSB_64_32(iv, ctr, enc_ctr, pad, src, dst, enc)	\
do {									\
  SILC_GET32_MSB(ctr[0], iv);						\
  SILC_GET32_MSB(ctr[1], iv + 4);					\
  									\
  if (pad == 0)								\
    pad = 8;								\
  									\
  while (len-- > 0) {							\
    if (pad == 8) {							\
      if (++ctr[1] == 0)						\
	++ctr[0];							\
      									\
      enc;								\
      SILC_PUT32_MSB(enc_ctr[0], iv);					\
      SILC_PUT32_MSB(enc_ctr[1], iv + 4);				\
      pad = 0;								\
    }									\
    *dst++ = *src++ ^ iv[pad++];					\
  }									\
  									\
  SILC_PUT32_MSB(ctr[0], iv);						\
  SILC_PUT32_MSB(ctr[1], iv + 4);					\
} while(0)

/* CFB 128-bit block, LSB, the 32-bit cfb argument must be encrypted. */

#define SILC_CFB_ENC_LSB_128_32(iv, cfb, pad, src, dst, enc)		\
do {									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      SILC_GET32_LSB(cfb[0], iv);					\
      SILC_GET32_LSB(cfb[1], iv + 4);					\
      SILC_GET32_LSB(cfb[2], iv + 8);					\
      SILC_GET32_LSB(cfb[3], iv + 12);					\
      									\
      enc;								\
      									\
      SILC_PUT32_LSB(cfb[0], iv);					\
      SILC_PUT32_LSB(cfb[1], iv + 4);					\
      SILC_PUT32_LSB(cfb[2], iv + 8);					\
      SILC_PUT32_LSB(cfb[3], iv + 12);					\
      pad = 0;								\
    }									\
    iv[pad] = (*dst = *src ^ iv[pad]);					\
    dst++;								\
    src++;								\
    pad++;								\
  }									\
} while(0)

/* CFB 128-bit block, LSB, the 32-bit cfb argument must be decrypted. */

#define SILC_CFB_DEC_LSB_128_32(iv, cfb, pad, src, dst, dec)		\
do {									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      SILC_GET32_LSB(cfb[0], iv);					\
      SILC_GET32_LSB(cfb[1], iv + 4);					\
      SILC_GET32_LSB(cfb[2], iv + 8);					\
      SILC_GET32_LSB(cfb[3], iv + 12);					\
      									\
      dec;								\
      									\
      SILC_PUT32_LSB(cfb[0], iv);					\
      SILC_PUT32_LSB(cfb[1], iv + 4);					\
      SILC_PUT32_LSB(cfb[2], iv + 8);					\
      SILC_PUT32_LSB(cfb[3], iv + 12);					\
      pad = 0;								\
    }									\
    iv[pad] = *src ^ iv[pad];						\
    *dst = iv[pad];							\
    iv[pad++] = *src;							\
    dst++;								\
    src++;								\
  }									\
} while(0)

/* CFB 128-bit block, MSB, the 32-bit cfb argument must be encrypted. */

#define SILC_CFB_ENC_MSB_128_32(iv, cfb, pad, src, dst, enc)		\
do {									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      SILC_GET32_MSB(cfb[0], iv);					\
      SILC_GET32_MSB(cfb[1], iv + 4);					\
      SILC_GET32_MSB(cfb[2], iv + 8);					\
      SILC_GET32_MSB(cfb[3], iv + 12);					\
      									\
      enc;								\
      									\
      SILC_PUT32_MSB(cfb[0], iv);					\
      SILC_PUT32_MSB(cfb[1], iv + 4);					\
      SILC_PUT32_MSB(cfb[2], iv + 8);					\
      SILC_PUT32_MSB(cfb[3], iv + 12);					\
      pad = 0;								\
    }									\
    iv[pad] = (*dst = *src ^ iv[pad]);					\
    dst++;								\
    src++;								\
    pad++;								\
  }									\
} while(0)

/* CFB 128-bit block, MSB, the 32-bit cfb argument must be decrypted. */

#define SILC_CFB_DEC_MSB_128_32(iv, cfb, pad, src, dst, dec)		\
do {									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      SILC_GET32_MSB(cfb[0], iv);					\
      SILC_GET32_MSB(cfb[1], iv + 4);					\
      SILC_GET32_MSB(cfb[2], iv + 8);					\
      SILC_GET32_MSB(cfb[3], iv + 12);					\
      									\
      dec;								\
      									\
      SILC_PUT32_MSB(cfb[0], iv);					\
      SILC_PUT32_MSB(cfb[1], iv + 4);					\
      SILC_PUT32_MSB(cfb[2], iv + 8);					\
      SILC_PUT32_MSB(cfb[3], iv + 12);					\
      pad = 0;								\
    }									\
    iv[pad] = *src ^ iv[pad];						\
    *dst = iv[pad];							\
    iv[pad++] = *src;							\
    dst++;								\
    src++;								\
  }									\
} while(0)

/* CFB 64-bit block, MSB, the 32-bit cfb argument must be encrypted. */

#define SILC_CFB_ENC_MSB_64_32(iv, cfb, pad, src, dst, enc)		\
do {									\
  while (len-- > 0) {							\
    if (pad == 8) {							\
      SILC_GET32_MSB(cfb[0], iv);					\
      SILC_GET32_MSB(cfb[1], iv + 4);					\
      									\
      enc;								\
      									\
      SILC_PUT32_MSB(cfb[0], iv);					\
      SILC_PUT32_MSB(cfb[1], iv + 4);					\
      pad = 0;								\
    }									\
    iv[pad] = (*dst = *src ^ iv[pad]);					\
    dst++;								\
    src++;								\
    pad++;								\
  }									\
} while(0)

/* CFB 64-bit block, MSB, the 32-bit cfb argument must be decrypted. */

#define SILC_CFB_DEC_MSB_64_32(iv, cfb, pad, src, dst, dec)		\
do {									\
  while (len-- > 0) {							\
    if (pad == 8) {							\
      SILC_GET32_MSB(cfb[0], iv);					\
      SILC_GET32_MSB(cfb[1], iv + 4);					\
      									\
      dec;								\
      									\
      SILC_PUT32_MSB(cfb[0], iv);					\
      SILC_PUT32_MSB(cfb[1], iv + 4);					\
      pad = 0;								\
    }									\
    iv[pad] = *src ^ iv[pad];						\
    *dst = iv[pad];							\
    iv[pad++] = *src;							\
    dst++;								\
    src++;								\
  }									\
} while(0)

/* CFB 128-bit block, MSB, the 8-bit iv argument must be encrypted. */

#define SILC_CFB_ENC_MSB_128_8(iv, pad, src, dst, enc)			\
do {									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      enc;								\
      pad = 0;								\
    }									\
    iv[pad] = (*dst = *src ^ iv[pad]);					\
    dst++;								\
    src++;								\
    pad++;								\
  }									\
} while(0)

/* CFB 128-bit block, MSB, the 8-bit iv argument must be decrypted. */

#define SILC_CFB_DEC_MSB_128_8(iv, pad, src, dst, dec)			\
 do {									\
  while (len-- > 0) {							\
    if (pad == 16) {							\
      dec;								\
      pad = 0;								\
    }									\
    iv[pad] = *src ^ iv[pad];						\
    *dst = iv[pad];							\
    iv[pad++] = *src;							\
    dst++;								\
    src++;								\
  }									\
} while(0)

#endif
