/*

  safer_internal.h

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

#ifndef SAFER_INTERNAL_H
#define SAFER_INTERNAL_H

/* Cipher's context */
typedef struct {
  u1byte l_key[33 * 16];
  u4byte k_bytes;
} SaferContext;

/* Prototypes */
u4byte *safer_set_key(SaferContext *ctx,
		      const u4byte in_key[], const u4byte key_len);
void safer_encrypt(SaferContext *ctx,
		   const u4byte in_blk[4], u4byte out_blk[4]);
void safer_decrypt(SaferContext *ctx,
		   const u4byte in_blk[4], u4byte out_blk[4]);

#endif
