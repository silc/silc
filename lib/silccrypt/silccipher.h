/*

  silccipher.h

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

#ifndef SILCCIPHER_H
#define SILCCIPHER_H

/* 
   SILC Cipher object.

   Default SILC cipher object to represent any cipher. The function
   pointers are the stub functions for each implemented cipher. Following
   short description of the fields:

   char *name

       Logical name of the cipher.

   uint32 block_len

       Block size of the cipher.

   uint32 key_len

       Length of the key of the cipher (in bits).

*/
typedef struct {
  char *name;
  uint32 block_len;
  uint32 key_len;

  bool (*set_key)(void *, const unsigned char *, uint32);
  bool (*set_key_with_string)(void *, const unsigned char *, uint32);
  bool (*encrypt)(void *, const unsigned char *, unsigned char *,
		  uint32, unsigned char *);
  bool (*decrypt)(void *, const unsigned char *, unsigned char *, 
		  uint32, unsigned char *);
  uint32 (*context_len)();
} SilcCipherObject;

#define SILC_CIPHER_MAX_IV_SIZE 16

/* The main SilcCipher structure. Use SilcCipher instead of SilcCipherStruct.
   Also remember that SilcCipher is a pointer. */
typedef struct SilcCipherStruct {
  SilcCipherObject *cipher;
  void *context;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];

  /* XXX Backwards support for 0.5.x
     XXX Remove in 0.7.x */
  bool back;

  void (*set_iv)(struct SilcCipherStruct *, const unsigned char *);
  void (*get_iv)(struct SilcCipherStruct *, unsigned char *);
  uint32 (*get_key_len)(struct SilcCipherStruct *);
  uint32 (*get_block_len)(struct SilcCipherStruct *);
} *SilcCipher;

/* Marks for all ciphers in silc. This can be used in silc_cipher_unregister
   to unregister all ciphers at once. */
#define SILC_ALL_CIPHERS ((SilcCipherObject *)1)

/* Static list of ciphers for silc_cipher_register_default(). */
extern SilcCipherObject silc_default_ciphers[];

/* Default cipher in the SILC protocol */
#define SILC_DEFAULT_CIPHER "aes-256-cbc"

/* Macros */

/* Function names in SILC Crypto modules. The name of the cipher
   is appended into these names and used to the get correct symbol out
   of the module. All SILC Crypto API compliant modules must support
   these function names (use macros below to assure this). */
#define SILC_CIPHER_SIM_SET_KEY "set_key"
#define SILC_CIPHER_SIM_SET_KEY_WITH_STRING "set_key_with_string"
#define SILC_CIPHER_SIM_ENCRYPT_CBC "encrypt_cbc"
#define SILC_CIPHER_SIM_DECRYPT_CBC "decrypt_cbc"
#define SILC_CIPHER_SIM_CONTEXT_LEN "context_len"

/* These macros can be used to implement the SILC Crypto API and to avoid
   errors in the API these macros should be used always. */
#define SILC_CIPHER_API_SET_KEY(cipher)			\
bool silc_##cipher##_set_key(void *context,		\
			     const unsigned char *key,	\
			     uint32 keylen)
#define SILC_CIPHER_API_SET_KEY_WITH_STRING(cipher)			\
bool silc_##cipher##_set_key_with_string(void *context,			\
	 			 	 const unsigned char *string,	\
			 	         uint32 stringlen)
#define SILC_CIPHER_API_ENCRYPT_CBC(cipher)			\
bool silc_##cipher##_encrypt_cbc(void *context,			\
				 const unsigned char *src,	\
		       	         unsigned char *dst,		\
				 uint32 len,		\
			         unsigned char *iv)
#define SILC_CIPHER_API_DECRYPT_CBC(cipher)			\
bool silc_##cipher##_decrypt_cbc(void *context,			\
			      	 const unsigned char *src,	\
				 unsigned char *dst,		\
				 uint32 len,		\
				 unsigned char *iv)
#define SILC_CIPHER_API_CONTEXT_LEN(cipher)			\
uint32 silc_##cipher##_context_len()

/* Prototypes */
bool silc_cipher_register(SilcCipherObject *cipher);
bool silc_cipher_unregister(SilcCipherObject *cipher);
bool silc_cipher_register_default(void);
bool silc_cipher_alloc(const unsigned char *name, SilcCipher *new_cipher);
void silc_cipher_free(SilcCipher cipher);
bool silc_cipher_is_supported(const unsigned char *name);
char *silc_cipher_get_supported(void);
bool silc_cipher_encrypt(SilcCipher cipher, const unsigned char *src,
			 unsigned char *dst, uint32 len, 
			 unsigned char *iv);
bool silc_cipher_decrypt(SilcCipher cipher, const unsigned char *src,
			 unsigned char *dst, uint32 len, 
			 unsigned char *iv);
bool silc_cipher_set_key(SilcCipher cipher, const unsigned char *key,
			 uint32 keylen);
void silc_cipher_set_iv(SilcCipher cipher, const unsigned char *iv);
void silc_cipher_get_iv(SilcCipher cipher, unsigned char *iv);
uint32 silc_cipher_get_key_len(SilcCipher cipher);
uint32 silc_cipher_get_block_len(SilcCipher cipher);

#endif
