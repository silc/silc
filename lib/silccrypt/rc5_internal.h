/*

  rc5_internal.h

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

#ifndef RC5_INTERNAL_H
#define RC5_INTERNAL_H

#include "ciphers_def.h"

/* RC5 definitions */
#define w	32	/* word size, in bits */
#define r	16	/* rounds */
#define b	16	/* minimum key size in bytes */
#define c	8	/* same for 128,  192 and 256 bits key */
#define t	34	/* size of table S, t = 2 * (r + 1) */

/* Cipher's context */
typedef struct {
  u32 out_key[t];
} RC5Context;

/* Prototypes */
int rc5_set_key(RC5Context *ctx, const uint32 in_key[], int key_len);
int rc5_encrypt(RC5Context *ctx, u32 *in, u32 *out);
int rc5_decrypt(RC5Context *ctx, u32 *in, u32 *out);

#endif
