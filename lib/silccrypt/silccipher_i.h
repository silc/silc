/*

  silccipher_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCCIPHER_I_H
#define SILCCIPHER_I_H

#ifndef SILCCIPHER_H
#error "Do not include this header directly"
#endif

/* These macros can be used to implement the SILC Crypto API and to avoid
   errors in the API these macros should be used always. */
#define SILC_CIPHER_API_SET_KEY(name)					\
  SilcBool silc_##name##_set_key(struct SilcCipherObjectStruct *cipher,	\
				 void *context,				\
				 const unsigned char *key,		\
				 SilcUInt32 keylen,			\
				 SilcBool encryption)
#define SILC_CIPHER_API_SET_IV(name)				\
  void silc_##name##_set_iv(struct SilcCipherObjectStruct *cipher,	\
			    void *context,			\
			    const unsigned char *iv)
#define SILC_CIPHER_API_ENCRYPT(name)					\
  SilcBool silc_##name##_encrypt(struct SilcCipherObjectStruct *cipher,	\
				 void *context,				\
				 const unsigned char *src,		\
				 unsigned char *dst,			\
				 SilcUInt32 len,			\
				 unsigned char *iv)
#define SILC_CIPHER_API_DECRYPT(name)					\
  SilcBool silc_##name##_decrypt(struct SilcCipherObjectStruct *cipher,	\
				 void *context,				\
				 const unsigned char *src,		\
				 unsigned char *dst,			\
				 SilcUInt32 len,			\
				 unsigned char *iv)
#define SILC_CIPHER_API_CONTEXT_LEN(name)	\
  SilcUInt32 silc_##name##_context_len()

/* Cipher object to represent a cipher algorithm. */
struct SilcCipherObjectStruct {
  /* Cipher name */
  char *name;

  /* Set new key.  If `encryption' is TRUE the key is for encryption,
     FALSE for decryption.  The `keylen' is in bits. */
  SilcBool (*set_key)(struct SilcCipherObjectStruct *cipher,
		      void *context, const unsigned char *key,
		      SilcUInt32 keylen, SilcBool encryption);

  /* Set IV.  The upper layer (SilcCipher) maintains the IV.  If the algorithm
     needs to set the IV itself, this should be implemented. */
  void (*set_iv)(struct SilcCipherObjectStruct *cipher,
		 void *context, const unsigned char *iv);

  /* Encrypt.  The `src' and `dst' may be same pointer.  The `iv' may be
     edited inside this function. */
  SilcBool (*encrypt)(struct SilcCipherObjectStruct *cipher,
		      void *context, const unsigned char *src,
		      unsigned char *dst, SilcUInt32 len,
		      unsigned char *iv);

  /* Decrypt.  The `src' and `dst' may be same pointer.  The `iv' may be
     edited inside this function. */
  SilcBool (*decrypt)(struct SilcCipherObjectStruct *cipher,
		      void *context, const unsigned char *src,
		      unsigned char *dst, SilcUInt32 len,
		      unsigned char *iv);

  /* Returns the length of the internal cipher context */
  SilcUInt32 (*context_len)(void);

  unsigned int key_len   : 10;		   /* Key length in bits */
  unsigned int block_len : 8;		   /* Block size in bytes */
  unsigned int iv_len    : 8;		   /* IV length in bytes */
  unsigned int mode      : 6;		   /* SilcCipherMode */
};

#endif /* SILCCIPHER_I_H */
