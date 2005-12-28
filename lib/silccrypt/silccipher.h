/*

  silccipher.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCCIPHER_H
#define SILCCIPHER_H

/****h* silccrypt/SILC Cipher Interface
 *
 * DESCRIPTION
 *
 * This is the interface for cipher functions.  It provides cipher
 * registering and unregistering routines, encryption and decryption
 * routines.
 *
 ***/

/****s* silccrypt/SilcCipherAPI/SilcCipher
 *
 * NAME
 *
 *    typedef struct { ... } SilcCipher;
 *
 * DESCRIPTION
 *
 *    This context is the actual cipher context and is allocated
 *    by silc_cipher_alloc and given as argument usually to all
 *    silc_cipher _* functions.  It is freed by the silc_cipher_free
 *    function.
 *
 ***/
typedef struct SilcCipherStruct *SilcCipher;

/* The default SILC Cipher object to represent any cipher in SILC. */
typedef struct {
  char *name;
  SilcUInt32 block_len;
  SilcUInt32 key_len;

  SilcBool (*set_key)(void *, const unsigned char *, SilcUInt32);
  SilcBool (*set_key_with_string)(void *, const unsigned char *, SilcUInt32);
  SilcBool (*encrypt)(void *, const unsigned char *, unsigned char *,
		  SilcUInt32, unsigned char *);
  SilcBool (*decrypt)(void *, const unsigned char *, unsigned char *,
		  SilcUInt32, unsigned char *);
  SilcUInt32 (*context_len)();
} SilcCipherObject;

#define SILC_CIPHER_MAX_IV_SIZE 16

/* Marks for all ciphers in silc. This can be used in silc_cipher_unregister
   to unregister all ciphers at once. */
#define SILC_ALL_CIPHERS ((SilcCipherObject *)1)

/* Static list of ciphers for silc_cipher_register_default(). */
extern DLLAPI const SilcCipherObject silc_default_ciphers[];

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
SilcBool silc_##cipher##_set_key(void *context,		\
			     const unsigned char *key,	\
			     SilcUInt32 keylen)
#define SILC_CIPHER_API_SET_KEY_WITH_STRING(cipher)			\
SilcBool silc_##cipher##_set_key_with_string(void *context,			\
	 			 	 const unsigned char *string,	\
			 	         SilcUInt32 stringlen)
#define SILC_CIPHER_API_ENCRYPT_CBC(cipher)			\
SilcBool silc_##cipher##_encrypt_cbc(void *context,			\
				 const unsigned char *src,	\
		       	         unsigned char *dst,		\
				 SilcUInt32 len,		\
			         unsigned char *iv)
#define SILC_CIPHER_API_DECRYPT_CBC(cipher)			\
SilcBool silc_##cipher##_decrypt_cbc(void *context,			\
			      	 const unsigned char *src,	\
				 unsigned char *dst,		\
				 SilcUInt32 len,		\
				 unsigned char *iv)


#define SILC_CIPHER_API_CONTEXT_LEN(cipher)			\
SilcUInt32 silc_##cipher##_context_len()


/* Prototypes */

/****f* silccrypt/SilcCipherAPI/silc_cipher_register
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_register(const SilcCipherObject *cipher);
 *
 * DESCRIPTION
 *
 *    Register a new cipher into SILC. This is used at the initialization of
 *    the SILC. This function allocates a new object for the cipher to be
 *    registered. Therefore, if memory has been allocated for the object sent
 *    as argument it has to be free'd after this function returns succesfully.
 *
 ***/
SilcBool silc_cipher_register(const SilcCipherObject *cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_unregister
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_unregister(SilcCipherObject *cipher);
 *
 * DESCRIPTION
 *
 *    Unregister a cipher from the SILC.
 *
 ***/
SilcBool silc_cipher_unregister(SilcCipherObject *cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_register_default
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_register_default(void);
 *
 * DESCRIPTION
 *
 *    Function that registers all the default ciphers (all builtin ciphers).
 *    The application may use this to register the default ciphers if specific
 *    ciphers in any specific order is not wanted.
 *
 ***/
SilcBool silc_cipher_register_default(void);

/****f* silccrypt/SilcCipherAPI/silc_cipher_unregister_all
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_unregister_all(void);
 *
 * DESCRIPTION
 *
 *    Unregisters all ciphers.
 *
 ***/
SilcBool silc_cipher_unregister_all(void);

/****f* silccrypt/SilcCipherAPI/silc_cipher_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_alloc(const unsigned char *name,
 *                           SilcCipher *new_cipher);
 *
 * DESCRIPTION
 *
 *    Allocates a new SILC cipher object. Function returns 1 on succes and 0
 *    on error. The allocated cipher is returned in new_cipher argument. The
 *    caller must set the key to the cipher after this function has returned
 *    by calling the ciphers set_key function.
 *
 ***/
SilcBool silc_cipher_alloc(const unsigned char *name, SilcCipher *new_cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_free
 *
 * SYNOPSIS
 *
 *    void silc_cipher_free(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Frees the given cipher.
 *
 ***/
void silc_cipher_free(SilcCipher cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_is_supported
 *
 * SYNOPSIS
 *
 * SilcBool silc_cipher_is_supported(const unsigned char *name);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if cipher `name' is supported.
 *
 ***/
SilcBool silc_cipher_is_supported(const unsigned char *name);

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_supported
 *
 * SYNOPSIS
 *
 *    char *silc_cipher_get_supported(void);
 *
 * DESCRIPTION
 *
 *    Returns comma separated list of supported ciphers.
 *
 ***/
char *silc_cipher_get_supported(void);

/****f* silccrypt/SilcCipherAPI/silc_cipher_encrypt
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_encrypt(SilcCipher cipher,
 *                                 const unsigned char *src,
 *                                 unsigned char *dst, SilcUInt32 len,
 *                                 unsigned char *iv);
 *
 * DESCRIPTION
 *
 *    Encrypts data from `src' into `dst' with the specified cipher and
 *    Initial Vector (IV).  If the `iv' is NULL then the cipher's internal
 *    IV is used.  The `src' and `dst' maybe same buffer.
 *
 ***/
SilcBool silc_cipher_encrypt(SilcCipher cipher, const unsigned char *src,
			     unsigned char *dst, SilcUInt32 len,
			     unsigned char *iv);

/****f* silccrypt/SilcCipherAPI/silc_cipher_decrypt
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_decrypt(SilcCipher cipher,
 *                                 const unsigned char *src,
 *                                 unsigned char *dst, SilcUInt32 len,
 *                                 unsigned char *iv);
 *
 * DESCRIPTION
 *
 *    Decrypts data from `src' into `dst' with the specified cipher and
 *    Initial Vector (IV).  If the `iv' is NULL then the cipher's internal
 *    IV is used.  The `src' and `dst' maybe same buffer.
 *
 ***/
SilcBool silc_cipher_decrypt(SilcCipher cipher, const unsigned char *src,
			     unsigned char *dst, SilcUInt32 len,
			     unsigned char *iv);

/****f* silccrypt/SilcCipherAPI/silc_cipher_set_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_cipher_set_key(SilcCipher cipher, const unsigned char *key,
 *                             SilcUInt32 keylen);
 *
 * DESCRIPTION
 *
 *    Sets the key for the cipher.  The `keylen' is the key length in
 *    bits.
 *
 ***/
SilcBool silc_cipher_set_key(SilcCipher cipher, const unsigned char *key,
			     SilcUInt32 keylen);

/****f* silccrypt/SilcCipherAPI/silc_cipher_set_iv
 *
 * SYNOPSIS
 *
 *    void silc_cipher_set_iv(SilcCipher cipher, const unsigned char *iv);
 *
 * DESCRIPTION
 *
 *    Sets the IV (initial vector) for the cipher.  The `iv' must be
 *    the size of the block size of the cipher.
 *
 ***/
void silc_cipher_set_iv(SilcCipher cipher, const unsigned char *iv);

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_iv
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_cipher_get_iv(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Returns the IV (initial vector) of the cipher.  The returned
 *    pointer must not be freed by the caller.
 *
 ***/
unsigned char *silc_cipher_get_iv(SilcCipher cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_key_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_cipher_get_key_len(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Returns the key length of the cipher in bits.
 *
 ***/
SilcUInt32 silc_cipher_get_key_len(SilcCipher cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_block_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_cipher_get_block_len(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Returns the block size of the cipher in bytes.
 *
 ***/
SilcUInt32 silc_cipher_get_block_len(SilcCipher cipher);

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_cipher_get_name(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Returns the name of the cipher.
 *
 ***/
const char *silc_cipher_get_name(SilcCipher cipher);

#endif
