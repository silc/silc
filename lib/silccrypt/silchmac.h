/*

  silchmac.h

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

#ifndef SILCHMAC_H
#define SILCHMAC_H

/* 
   SILC HMAC object. 
   
   This is the HMAC object to create keyed hash values for message
   authentication. These routines uses already implemented hash functions.
   HMAC's can be created using any hash function implemented in SILC. These
   routines were created according to RFC2104. Following short description 
   of the fields:

   SilcHash hash

       The hash object to tell what hash function to use with this HMAC.

   unsigned char *key
   unsigned int len

       The key and its length used to make the HMAC. This is set
       with silc_hmac_set_key function.

   void (*set_key)(SilcHmac, const unsigned char *, unsigned int)

       Function used to set the key for the HMAC. Second argument is
       the key to be set and last argument is the length of the key.

   void (*make_hmac)(SilcHmac, unsigned char *, unsigned int,
                     unsigned char *)

       Function what is used to create HMAC's. User can also use directly
       silc_hmac_make fuction. Although, one needs to allocate a SilcHmac
       object before doing it, naturally. This uses the key set with
       silc_hmac_set_key function.

   void (*make_hmac_with_key)(SilcHmac, unsigned char *, unsigned int,
                              unsigned char *, unsigned int, unsigned char *)

       Same function as above except that the key used in the HMAC
       creation is sent as argument. The key set with silc_hmac_set_key
       is ignored in this case.

   void (*make_hmac_truncated)(SilcHmac, unsigned char *, unsigned int,
			       unsigned int, unsigned char *)

       Same function as above except that the output hash value is truncated
       to the length sent as argument (second last argument). This makes
       variable truncations possible, however, one should not truncate
       hash values to less than half of the length of the hash value.

*/
typedef struct SilcHmacStruct *SilcHmac;

struct SilcHmacStruct {
  SilcHash hash;
  unsigned char *key;
  unsigned int key_len;
  void (*set_key)(SilcHmac, const unsigned char *, unsigned int);
  void (*make_hmac)(SilcHmac, unsigned char *, unsigned int,
		    unsigned char *);
  void (*make_hmac_with_key)(SilcHmac, unsigned char *, unsigned int,
			     unsigned char *, unsigned int, unsigned char *);
  void (*make_hmac_truncated)(SilcHmac, unsigned char *, 
			      unsigned int, unsigned int, unsigned char *);
};

/* Prototypes */
int silc_hmac_alloc(SilcHash hash, SilcHmac *new_hmac);
void silc_hmac_free(SilcHmac hmac);
void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
		       unsigned int key_len);
void silc_hmac_make(SilcHmac hmac, 
		    unsigned char *data, 
		    unsigned int data_len,
		    unsigned char *return_hash);
void silc_hmac_make_with_key(SilcHmac hmac, 
			     unsigned char *data, 
			     unsigned int data_len,
			     unsigned char *key, 
			     unsigned int key_len, 
			     unsigned char *return_hash);
void silc_hmac_make_truncated(SilcHmac hmac, 
			      unsigned char *data, 
			      unsigned int data_len,
			      unsigned int truncated_len,
			      unsigned char *return_hash);

#endif
