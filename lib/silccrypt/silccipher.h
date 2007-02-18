/*

  silccipher.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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
  SilcBool (*set_key)(void *, const unsigned char *, SilcUInt32, SilcBool);
  void (*set_iv)(void *, const unsigned char *);
  SilcBool (*encrypt)(void *, const unsigned char *, unsigned char *,
		      SilcUInt32, unsigned char *);
  SilcBool (*decrypt)(void *, const unsigned char *, unsigned char *,
		      SilcUInt32, unsigned char *);
  SilcUInt32 (*context_len)();
  unsigned int key_len   : 10;
  unsigned int block_len : 8;
  unsigned int iv_len    : 8;
  unsigned int mode      : 6;
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
#define SILC_CIPHER_SIM_ENCRYPT "encrypt"
#define SILC_CIPHER_SIM_DECRYPT "decrypt"
#define SILC_CIPHER_SIM_CONTEXT_LEN "context_len"

/* These macros can be used to implement the SILC Crypto API and to avoid
   errors in the API these macros should be used always. */
#define SILC_CIPHER_API_SET_KEY(cipher)				\
SilcBool silc_##cipher##_set_key(void *context,			\
				 const unsigned char *key,	\
				 SilcUInt32 keylen,		\
				 SilcBool encryption)
#define SILC_CIPHER_API_SET_IV(cipher)				\
void silc_##cipher##_set_iv(void *context,			\
			    const unsigned char *iv)
#define SILC_CIPHER_API_ENCRYPT(cipher)				\
SilcBool silc_##cipher##_encrypt(void *context,			\
				 const unsigned char *src,	\
				 unsigned char *dst,		\
				 SilcUInt32 len,		\
				 unsigned char *iv)
#define SILC_CIPHER_API_DECRYPT(cipher)				\
SilcBool silc_##cipher##_decrypt(void *context,			\
				 const unsigned char *src,	\
				 unsigned char *dst,		\
				 SilcUInt32 len,		\
				 unsigned char *iv)
#define SILC_CIPHER_API_CONTEXT_LEN(cipher)	\
SilcUInt32 silc_##cipher##_context_len()

/****d* silccrypt/SilcCipherAPI/SilcCipherMode
 *
 * NAME
 *
 *    typedef enum { ... } SilcCipherMode;
 *
 * DESCRIPTION
 *
 *    Cipher modes.
 *
 * SOURCE
 */
typedef enum {
  SILC_CIPHER_MODE_ECB = 1,	/* ECB mode */
  SILC_CIPHER_MODE_CBC = 2,	/* CBC mode */
  SILC_CIPHER_MODE_CTR = 3,	/* CTR mode */
  SILC_CIPHER_MODE_CFB = 4,	/* CFB mode */
  SILC_CIPHER_MODE_OFB = 5,	/* OFB mode */
} SilcCipherMode;
/***/

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
 *                               SilcCipher *new_cipher);
 *
 * DESCRIPTION
 *
 *    Allocates a new SILC cipher object. Function returns 1 on succes and 0
 *    on error. The allocated cipher is returned in new_cipher argument. The
 *    caller must set the key to the cipher after this function has returned
 *    by calling the ciphers set_key function.
 *
 *    The following ciphers are supported:
 *
 *    aes-256-ctr            AES-256, Counter mode
 *    aes-192-ctr            AES-192, Counter mode
 *    aes-128-ctr            AES,128, Counter mode
 *    aes-256-cbc            AES-256, Cipher block chaining mode
 *    aes-192-cbc            AES-192, Cipher block chaining mode
 *    aes-128-cbc            AES,128, Cipher block chaining mode
 *    twofish-256-cbc        Twofish-256, Cipher block chaining mode
 *    twofish-192-cbc        Twofish-192, Cipher block chaining mode
 *    twofish-128-cbc        Twofish-128, Cipher block chaining mode
 *
 *    Notes about modes:
 *
 *    The CTR is normal counter mode.  The CTR mode does not require the
 *    plaintext length to be multiple by the cipher block size.  If the last
 *    plaintext block is shorter the remaining bits of the key stream are
 *    used next time silc_cipher_encrypt is called.  If silc_cipher_set_iv
 *    is called it will reset the counter for a new block (discarding any
 *    remaining bits from previous key stream).
 *
 *    The CBC is mode is a standard CBC mode.  The plaintext length must be
 *    multiple by the cipher block size.  If it isn't the plaintext must be
 *    padded.
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
 *                                 SilcUInt32 keylen, SilcBool encryption);
 *
 * DESCRIPTION
 *
 *    Sets the key for the cipher.  The `keylen' is the key length in
 *    bits.  If the `encryption' is TRUE the key is for encryption, if FALSE
 *    the key is for decryption.
 *
 ***/
SilcBool silc_cipher_set_key(SilcCipher cipher, const unsigned char *key,
			     SilcUInt32 keylen, SilcBool encryption);

/****f* silccrypt/SilcCipherAPI/silc_cipher_set_iv
 *
 * SYNOPSIS
 *
 *    void silc_cipher_set_iv(SilcCipher cipher, const unsigned char *iv);
 *
 * DESCRIPTION
 *
 *    Sets the IV (initial vector) for the cipher.  The `iv' must be
 *    the size of the block size of the cipher.  If `iv' is NULL this
 *    does not do anything.
 *
 *    If the encryption mode is CTR (Counter mode) this also resets the
 *    the counter for a new block.  This is done also if `iv' is NULL.
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
 *    pointer must not be freed by the caller.  If the caller modifies
 *    the returned pointer the IV inside cipher is also modified.
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

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_iv_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_cipher_get_iv_len(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Returns the IV length of the cipher in bytes.
 *
 ***/
SilcUInt32 silc_cipher_get_iv_len(SilcCipher cipher);

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

/****f* silccrypt/SilcCipherAPI/silc_cipher_get_mode
 *
 * SYNOPSIS
 *
 *    SilcCipherMode silc_cipher_get_mode(SilcCipher cipher);
 *
 * DESCRIPTION
 *
 *    Returns the cipher mode.
 *
 ***/
SilcCipherMode silc_cipher_get_mode(SilcCipher cipher);

#endif /* SILCCIPHER_H */
