/*

  silchmac.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCHMAC_H
#define SILCHMAC_H

/* 
   SILC HMAC object. 
   
   This is the HMAC object to create keyed hash values for message
   authentication. These routines uses already implemented hash functions.
   HMAC's can be created using any hash function implemented in SILC. These
   routines were created according to RFC2104. Following short description 
   of the fields:

   SilcHmacObject:

   char *name

       Name of the HMAC.

   unsigned int len

       Length of the MAC the HMAC is to produce (bytes).


   SilcHmac:

   SilcHash hash

       The hash object to tell what hash function to use with this HMAC.

   char allocated_hash

       TRUE if the `hash' was allocated and FALSE if it is static and
       must not be freed.

   unsigned char *key
   unsigned int len

       The key and its length used to make the HMAC. This is set
       with silc_hmac_set_key function.

*/
typedef struct SilcHmacStruct *SilcHmac;

typedef struct {
  char *name;
  unsigned int len;
} SilcHmacObject;

struct SilcHmacStruct {
  SilcHmacObject *hmac;
  SilcHash hash;
  char allocated_hash;
  unsigned char *key;
  unsigned int key_len;
};

/* Prototypes */
int silc_hmac_register(SilcHmacObject *hmac);
int silc_hmac_unregister(SilcHmacObject *hmac);
int silc_hmac_alloc(char *name, SilcHash hash, SilcHmac *new_hmac);
void silc_hmac_free(SilcHmac hmac);
int silc_hmac_is_supported(const char *name);
char *silc_hmac_get_supported();
unsigned int silc_hmac_len(SilcHmac hmac);
void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
		       unsigned int key_len);
void silc_hmac_make(SilcHmac hmac, unsigned char *data,
		    unsigned int data_len, unsigned char *return_hash,
		    unsigned int *return_len);
void silc_hmac_make_with_key(SilcHmac hmac, unsigned char *data,
			     unsigned int data_len, 
			     unsigned char *key, unsigned int key_len,
			     unsigned char *return_hash,
			     unsigned int *return_len);
void silc_hmac_make_truncated(SilcHmac hmac, 
			      unsigned char *data, 
			      unsigned int data_len,
			      unsigned int truncated_len,
			      unsigned char *return_hash);

#endif
