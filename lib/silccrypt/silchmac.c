/*

  silchmac.c

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
 * Revision 1.1  2000/06/27 11:36:55  priikone
 * Initial revision
 *
 *
 */

#include "silcincludes.h"

/* Allocates a new SilcHmac object. First argument is the hash function
   object to tell the hmac which hash function should be used when creating
   HMAC's. The new SilcHmac object is returned to new_hmac argument. */

int silc_hmac_alloc(SilcHash hash, SilcHmac *new_hmac)
{
  SILC_LOG_DEBUG(("Allocating new hmac object"));

  *new_hmac = silc_calloc(1, sizeof(**new_hmac));
  if (*new_hmac == NULL) {
    SILC_LOG_ERROR(("Could not allocate new hmac object"));
    return 0;
  }

  (*new_hmac)->hash = hash;
  (*new_hmac)->set_key = silc_hmac_set_key;
  (*new_hmac)->make_hmac = silc_hmac_make;
  (*new_hmac)->make_hmac_with_key = silc_hmac_make_with_key;
  (*new_hmac)->make_hmac_truncated = silc_hmac_make_truncated;

  return 1;
}

/* Free's the SilcHmac object. */

void silc_hmac_free(SilcHmac hmac)
{
  if (hmac)
    silc_free(hmac);
}

/* Creates the HMAC. The created keyed hash value is returned to 
   return_hash argument. */

void silc_hmac_make_internal(SilcHmac hmac, unsigned char *data,
			     unsigned int data_len, unsigned char *key,
			     unsigned int key_len, unsigned char *return_hash)
{
  SilcHash hash = hmac->hash;
  unsigned char inner_pad[hash->hash->block_len + 1];
  unsigned char outer_pad[hash->hash->block_len + 1];
  unsigned char hvalue[hash->hash->hash_len];
  void *hash_context;
  int i;

  SILC_LOG_DEBUG(("Making HMAC for message"));

  hash_context = silc_calloc(1, hash->hash->context_len());

  memset(inner_pad, 0, sizeof(inner_pad));
  memset(outer_pad, 0, sizeof(outer_pad));

  /* If the key length is more than block size of the hash function, the
     key is hashed. */
  if (key_len > hash->hash->block_len) {
    hash->make_hash(hash, key, key_len, hvalue);
    key = hvalue;
    key_len = hash->hash->hash_len;
  }

  /* Copy the key into the pads */
  memcpy(inner_pad, key, key_len);
  memcpy(outer_pad, key, key_len);

  /* XOR the key with pads */
  for (i = 0; i < hash->hash->block_len; i++) {
    inner_pad[i] ^= 0x36;
    outer_pad[i] ^= 0x5c;
  }

  /* Do the HMAC transform (too bad I can't do make_hash directly, sigh) */
  hash->hash->init(hash_context);
  hash->hash->update(hash_context, inner_pad, hash->hash->block_len);
  hash->hash->update(hash_context, data, data_len);
  hash->hash->final(hash_context, return_hash);
  hash->hash->init(hash_context);
  hash->hash->update(hash_context, outer_pad, hash->hash->block_len);
  hash->hash->update(hash_context, return_hash, hash->hash->hash_len);
  hash->hash->final(hash_context, return_hash);
}

/* Create the HMAC. This is thee make_hmac function pointer.  This
   uses the internal key set with silc_hmac_set_key. */

void silc_hmac_make(SilcHmac hmac, unsigned char *data,
		    unsigned int data_len, unsigned char *return_hash)
{
  silc_hmac_make_internal(hmac, data, data_len, hmac->key, 
			  hmac->key_len, return_hash);
}

/* Creates the HMAC just as above except that the hash value is truncated
   to the truncated_len sent as argument. NOTE: One should not truncate to
   less than half of the length of original hash value. However, this 
   routine allows these dangerous truncations. */

void silc_hmac_make_truncated(SilcHmac hmac, unsigned char *data,
			      unsigned int data_len,
			      unsigned int truncated_len,
			      unsigned char *return_hash)
{
  unsigned char hvalue[hmac->hash->hash->hash_len];

  silc_hmac_make_internal(hmac, data, data_len, 
			  hmac->key, hmac->key_len, hvalue);
  memcpy(return_hash, hvalue, truncated_len);
  memset(hvalue, 0, sizeof(hvalue));
}

/* Creates HMAC just as above except that this doesn't use the internal
   key. The key is sent as argument to the function. */

void silc_hmac_make_with_key(SilcHmac hmac, unsigned char *data,
			     unsigned int data_len, 
			     unsigned char *key, unsigned int key_len,
			     unsigned char *return_hash)
{
  silc_hmac_make_internal(hmac, data, data_len, key, key_len, return_hash);
}

/* Sets the HMAC key used in the HMAC creation */

void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
		       unsigned int key_len)
{
  hmac->key = silc_calloc(key_len, sizeof(unsigned char));
  memcpy(hmac->key, key, key_len);
}
