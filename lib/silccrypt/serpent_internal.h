/*

  serpent_internal.h

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

#ifndef SERPENT_INTERNAL_H
#define SERPENT_INTERNAL_H

/* Cipher's context */
typedef struct {
  u4byte l_key[140];
} SerpentContext;

/* Prototypes */
u4byte *serpent_set_key(SerpentContext *ctx,
			const u4byte in_key[], const u4byte key_len);
void serpent_encrypt(SerpentContext *ctx,
		     const u4byte in_blk[4], u4byte out_blk[]);
void serpent_decrypt(SerpentContext *ctx,
		     const u4byte in_blk[4], u4byte out_blk[4]);

#endif
