/*

  silchash.h

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

#ifndef SILCHASH_H
#define SILCHASH_H

/* The default Silc hash object to represent any hash function in SILC. */
typedef struct {
  char *name;
  SilcUInt32 hash_len;
  SilcUInt32 block_len;

  void (*init)(void *);
  void (*update)(void *, unsigned char *, SilcUInt32);
  void (*final)(void *, unsigned char *);
  void (*transform)(SilcUInt32 *, unsigned char *);
  SilcUInt32 (*context_len)();
} SilcHashObject;

/* The main SILC hash structure. Use SilcHash instead of SilcHashStruct.
   Also remember that SilcHash is a pointer. */
typedef struct SilcHashStruct {
  SilcHashObject *hash;
  void *context;

  void (*make_hash)(struct SilcHashStruct *, const unsigned char *, 
		    SilcUInt32, unsigned char *);
} *SilcHash;

/* Marks for all hash functions. This can be used in silc_hash_unregister
   to unregister all hash function at once. */
#define SILC_ALL_HASH_FUNCTIONS ((SilcHashObject *)1)

/* Default hash functions for silc_hash_register_default(). */
extern DLLAPI SilcHashObject silc_default_hash[];

/* Default HASH function in the SILC protocol */
#define SILC_DEFAULT_HASH "sha1"

/* Macros */

/* Following macros are used to implement the SILC Hash API. These
   macros should be used instead of declaring functions by hand. */

/* Function names in SILC Hash modules. The name of the hash function
   is appended into these names and used to the get correct symbol out
   of the module. All SILC Hash API compliant modules has to support
   these names as function names (use macros below to assure this). */
#define SILC_HASH_SIM_INIT "init"
#define SILC_HASH_SIM_UPDATE "update"
#define SILC_HASH_SIM_FINAL "final"
#define SILC_HASH_SIM_TRANSFORM "transform"
#define SILC_HASH_SIM_CONTEXT_LEN "context_len"

/* Macros that can be used to declare SILC Hash API functions. */
#define SILC_HASH_API_INIT(hash)		\
void silc_##hash##_init(void *context)
#define SILC_HASH_API_UPDATE(hash)				\
void silc_##hash##_update(void *context, unsigned char *data,	\
			                SilcUInt32 len)
#define SILC_HASH_API_FINAL(hash)				\
void silc_##hash##_final(void *context, unsigned char *digest)
#define SILC_HASH_API_TRANSFORM(hash)					\
void silc_##hash##_transform(SilcUInt32 *state,			\
			                  unsigned char *buffer)
#define SILC_HASH_API_CONTEXT_LEN(hash)		\
SilcUInt32 silc_##hash##_context_len()

/* Prototypes */
bool silc_hash_register(SilcHashObject *hash);
bool silc_hash_unregister(SilcHashObject *hash);
bool silc_hash_register_default(void);
bool silc_hash_alloc(const unsigned char *name, SilcHash *new_hash);
void silc_hash_free(SilcHash hash);
SilcUInt32 silc_hash_len(SilcHash hash);
bool silc_hash_is_supported(const unsigned char *name);
char *silc_hash_get_supported(void);
void silc_hash_make(SilcHash hash, const unsigned char *data,
		    SilcUInt32 len, unsigned char *return_hash);
char *silc_hash_fingerprint(SilcHash hash, const unsigned char *data,
			    SilcUInt32 data_len);
char *silc_hash_babbleprint(SilcHash hash, const unsigned char *data,
			    SilcUInt32 data_len);

#endif
