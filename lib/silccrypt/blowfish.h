/*

  blowfish.h

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

#ifndef BLOWFISH_H
#define BLOWFISH_H

#include "blowfish_internal.h"

/* 
 * SILC Crypto API for Blowfish
 */

/* Sets the key for the cipher. */

SILC_CIPHER_API_SET_KEY(blowfish)
{
  blowfish_set_key((BlowfishContext *)context, 
		   (unsigned char *)key, keylen);
  return TRUE;
}

/* Sets the string as a new key for the cipher. The string is first
   hashed and then used as a new key. */

SILC_CIPHER_API_SET_KEY_WITH_STRING(blowfish)
{
  SilcHash hash;
  unsigned char key[16];

  silc_hash_alloc("md5", &hash);
  hash->make_hash(hash, string, stringlen, key);

  blowfish_set_key((BlowfishContext *)context, key, sizeof(key));

  silc_hash_free(hash);
  memset(&key, 'F', sizeof(key));
  
  return TRUE;
}

/* Returns the size of the cipher context. */

SILC_CIPHER_API_CONTEXT_LEN(blowfish)
{
  return sizeof(BlowfishContext);
}

/* Encrypts with the cipher in CBC mode. */

SILC_CIPHER_API_ENCRYPT_CBC(blowfish)
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
  blowfish_encrypt((BlowfishContext *)context, tmp, out, 16);
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    tmp[0] = in[0] ^ out[0 - 4];
    tmp[1] = in[1] ^ out[1 - 4];
    tmp[2] = in[2] ^ out[2 - 4];
    tmp[3] = in[3] ^ out[3 - 4];
    blowfish_encrypt((BlowfishContext *)context, tmp, out, 16);
    in += 4;
    out += 4;
  }

  return 1;
}

/* Decrypts with the cipher in CBC mode. */

SILC_CIPHER_API_DECRYPT_CBC(blowfish)
{
  unsigned int *in, *out, *tiv;
  int i;

  in = (unsigned int *)src;
  out = (unsigned int *)dst;
  tiv = (unsigned int *)iv;

  blowfish_decrypt((BlowfishContext *)context, in, out, 16);
  out[0] ^= tiv[0];
  out[1] ^= tiv[1];
  out[2] ^= tiv[2];
  out[3] ^= tiv[3];
  in += 4;
  out += 4;

  for (i = 16; i < len; i += 16) {
    blowfish_decrypt((BlowfishContext *)context, in, out, 16);
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
