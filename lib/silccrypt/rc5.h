/*

  rc5.h

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
 * Revision 1.1.1.1  2000/06/27 11:36:54  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#ifndef RC5_H
#define RC5_H

#include "rc5_internal.h"

/* 
 * SILC Crypto API for RC5
 */

/* Sets the key for the cipher. */

SILC_CIPHER_API_SET_KEY(rc5)
{
  rc5_set_key((RC5Context *)context, (unsigned char *)key, keylen);
  return 1;
}

/* Sets the string as a new key for the cipher. The string is first
   hashed and then used as a new key. */

SILC_CIPHER_API_SET_KEY_WITH_STRING(rc5)
{
  /*  unsigned char key[md5_hash_len];
  SilcMarsContext *ctx = (SilcMarsContext *)context;

  make_md5_hash(string, &key);
  memcpy(&ctx->key, mars_set_key(&key, keylen), keylen);
  memset(&key, 'F', sizeoof(key));
  */

  return 1;
}

/* Returns the size of the cipher context. */

SILC_CIPHER_API_CONTEXT_LEN(rc5)
{
  return sizeof(RC5Context);
}

/* Encrypts with the cipher in CBC mode. */

SILC_CIPHER_API_ENCRYPT_CBC(rc5)
{
  unsigned int *in, *out, *tiv;
  unsigned int tmp[2];
  int i;

  in = (unsigned int *)src;
  out = (unsigned int *)dst;
  tiv = (unsigned int *)iv;

  tmp[0] = in[0] ^ tiv[0];
  tmp[1] = in[1] ^ tiv[1];
  rc5_encrypt((RC5Context *)context, tmp, out);
  in += 2;
  out += 2;

  for (i = 8; i < len; i += 8) {
    tmp[0] = in[0] ^ out[0 - 2];
    tmp[1] = in[1] ^ out[1 - 2];
    rc5_encrypt((RC5Context *)context, tmp, out);
    in += 2;
    out += 2;
  }

  return TRUE;
}

/* Decrypts with the cipher in CBC mode. */

SILC_CIPHER_API_DECRYPT_CBC(rc5)
{
  unsigned int *in, *out, *tiv;
  unsigned int tmp[2], tmp2[2];
  int i;

  in = (unsigned int *)src;
  out = (unsigned int *)dst;
  tiv = (unsigned int *)iv;

  tmp[0] = in[0];
  tmp[1] = in[1];
  tmp[3] = in[3];
  rc5_decrypt((RC5Context *)context, in, out);
  out[0] ^= tiv[0];
  out[1] ^= tiv[1];
  in += 2;
  out += 2;

  for (i = 8; i < len; i += 8) {
    tmp2[0] = tmp[0];
    tmp2[1] = tmp[1];
    tmp[0] = in[0];
    tmp[1] = in[1];
    rc5_decrypt((RC5Context *)context, in, out);
    out[0] ^= tmp2[0];
    out[1] ^= tmp2[1];
    in += 2;
    out += 2;
  }

  return TRUE;
}

#endif
