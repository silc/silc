/*

  cast.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1999 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.2  2001/04/03 19:54:10  priikone
 * 	updates. New data types.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:54  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#ifndef CAST_H
#define CAST_H

#include "cast_internal.h"

/* 
 * SILC Crypto API for Cast
 */

/* Sets the key for the cipher. */

inline int silc_cast_init(void *context, 
			  const unsigned char *key, 
			  uint32 keylen)
{
  cast_set_key((CastContext *)context, (uint32 *)key, keylen);
  return 1;
}

/* Sets the string as a new key for the cipher. The string is first
   hashed and then used as a new key. */

inline int silc_cast_set_string_as_key(void *context, 
				       const unsigned char *string,
				       uint32 stringlen)
{
  /*  SilcHash hash;
  unsigned char key[16];

  silc_hash_alloc("md5", &hash);
  hash->make_hash(hash, string, stringlen, key);

  cast_set_key((CastContext *)context, (const u4byte *)key, sizeof(key));

  silc_hash_free(hash);
  memset(&key, 'F', sizeof(key));
  */
  return TRUE;
}

/* Returns the size of the cipher context. */

inline uint32 silc_cast_context_len()
{
  return sizeof(CastContext);
}

/* Encrypts with the cipher in CBC mode. */

inline int silc_cast_encrypt_cbc(void *context,
				 const unsigned char *src,
				 unsigned char *dst,
				 uint32 len,
				 unsigned char *iv)
{
  uint32 *in, *out, *tiv;
  uint32 tmp[4];
  int i;

  in = (uint32 *)src;
  out = (uint32 *)dst;
  tiv = (uint32 *)iv;

  tmp[0] = in[0] ^ tiv[0];
  tmp[1] = in[1] ^ tiv[1];
  tmp[2] = in[2] ^ tiv[2];
  tmp[3] = in[3] ^ tiv[3];
  cast_encrypt((CastContext *)context, tmp, out);
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    tmp[0] = in[0] ^ out[0 - 4];
    tmp[1] = in[1] ^ out[1 - 4];
    tmp[2] = in[2] ^ out[2 - 4];
    tmp[3] = in[3] ^ out[3 - 4];
    cast_encrypt((CastContext *)context, tmp, out);
    in += 4;
    out += 4;
  }

  return 1;
}

/* Decrypts with the cipher in CBC mode. */

inline int silc_cast_decrypt_cbc(void *context,
				 const unsigned char *src,
				 unsigned char *dst,
				 uint32 len,
				 unsigned char *iv)
{
  uint32 *in, *out, *tiv;
  int i;

  in = (uint32 *)src;
  out = (uint32 *)dst;
  tiv = (uint32 *)iv;

  cast_decrypt((CastContext *)context, in, out);
  out[0] ^= tiv[0];
  out[1] ^= tiv[1];
  out[2] ^= tiv[2];
  out[3] ^= tiv[3];
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    cast_decrypt((CastContext *)context, in, out);
    out[0] ^= in[0 - 4];
    out[1] ^= in[1 - 4];
    out[2] ^= in[2 - 4];
    out[3] ^= in[3 - 4];
    in += 4;
    out += 4;
  }

  return 1;
}

#endif
