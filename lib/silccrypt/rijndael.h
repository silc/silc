/*

  rijndael.h

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
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include "rijndael_internal.h"

/* 
 * SILC Crypto API for Rijndael
 */

/* Sets the key for the cipher. */

SILC_CIPHER_API_SET_KEY(rijndael)
{
  rijndael_set_key((RijndaelContext *)context, (unsigned int *)key, keylen);
  return TRUE;
}

/* Sets the string as a new key for the cipher. The string is first
   hashed and then used as a new key. */

SILC_CIPHER_API_SET_KEY_WITH_STRING(rijndael)
{
  /*  unsigned char key[md5_hash_len];
  SilcMarsContext *ctx = (SilcMarsContext *)context;

  make_md5_hash(string, &key);
  memcpy(&ctx->key, mars_set_key(&key, keylen), keylen);
  memset(&key, 'F', sizeoof(key));
  */

  return TRUE;
}

/* Returns the size of the cipher context. */

SILC_CIPHER_API_CONTEXT_LEN(rijnadel)
{
  return sizeof(RijndaelContext);
}

/* Encrypts with the cipher in CBC mode. Source and destination buffers
   maybe one and same. */

SILC_CIPHER_API_ENCRYPT_CBC(rijndael)
{
  unsigned int *in, *out, *tiv;
  unsigned int tmp[4];
  int i;

  in = (unsigned int *)src;
  out = (unsigned int *)dst;
  tiv = (unsigned int *)iv;

  tmp[0] = in[0] ^ tiv[0];
  tmp[1] = in[1] ^ tiv[1];
  tmp[2] = in[2] ^ tiv[2];
  tmp[3] = in[3] ^ tiv[3];
  rijndael_encrypt((RijndaelContext *)context, tmp, out);
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    tmp[0] = in[0] ^ out[0 - 4];
    tmp[1] = in[1] ^ out[1 - 4];
    tmp[2] = in[2] ^ out[2 - 4];
    tmp[3] = in[3] ^ out[3 - 4];
    rijndael_encrypt((RijndaelContext *)context, tmp, out);
    in += 4;
    out += 4;
  }

  return TRUE;
}

/* Decrypts with the cipher in CBC mode. Source and destination buffers
   maybe one and same. */

SILC_CIPHER_API_DECRYPT_CBC(rijndael)
{
  unsigned int *in, *out, *tiv;
  unsigned int tmp[4], tmp2[4];
  int i;

  in = (unsigned int *)src;
  out = (unsigned int *)dst;
  tiv = (unsigned int *)iv;

  tmp[0] = in[0];
  tmp[1] = in[1];
  tmp[2] = in[2];
  tmp[3] = in[3];
  rijndael_decrypt((RijndaelContext *)context, in, out);
  out[0] ^= tiv[0];
  out[1] ^= tiv[1];
  out[2] ^= tiv[2];
  out[3] ^= tiv[3];
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    tmp2[0] = tmp[0];
    tmp2[1] = tmp[1];
    tmp2[2] = tmp[2];
    tmp2[3] = tmp[3];
    tmp[0] = in[0];
    tmp[1] = in[1];
    tmp[2] = in[2];
    tmp[3] = in[3];
    rijndael_decrypt((RijndaelContext *)context, in, out);
    out[0] ^= tmp2[0];
    out[1] ^= tmp2[1];
    out[2] ^= tmp2[2];
    out[3] ^= tmp2[3];
    in += 4;
    out += 4;
  }

  return TRUE;
}

#endif
