/*

  silcpkcs.h

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

/****h* silccrypt/SILC PKCS Interface
 *
 * DESCRIPTION
 *
 * SILC PKCS API provides generic interface for performing various
 * public key cryptography related operations with different types of
 * public and private keys.  Support for loading and saving of different
 * types of public key and private keys are also provided.
 *
 ***/

#ifndef SILCPKCS_H
#define SILCPKCS_H

/* Forward declarations */
typedef struct SilcPKCSAlgorithmStruct SilcPKCSAlgorithm;
typedef struct SilcPKCSObjectStruct SilcPKCSObject;

/****d* silccrypt/SilcPKCSAPI/SilcPKCSType
 *
 * NAME
 *
 *    typedef enum { ... } SilcPKCSType;
 *
 * DESCRIPTION
 *
 *    Supported public key cryptosystem types.
 *
 * SOURCE
 */
typedef enum {
  SILC_PKCS_SILC    = 1,	/* SILC PKCS */
  SILC_PKCS_SSH2    = 2,	/* SSH2 PKCS */
  SILC_PKCS_X509V3  = 3,	/* X.509v3 PKCS */
  SILC_PKCS_OPENPGP = 4,	/* OpenPGP PKCS */
  SILC_PKCS_SPKI    = 5,	/* SPKI PKCS (not supported) */
  SILC_PKCS_ANY     = 0,
} SilcPKCSType;
/***/

/****s* silccrypt/SilcPKCSAPI/SilcPublicKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcPublicKey;
 *
 * DESCRIPTION
 *
 *    This context represents any kind of PKCS public key.  It can be
 *    allocated by silc_pkcs_public_key_alloc and is freed by the
 *    silc_pkcs_public_key_free.  The PKCS specific public key context
 *    can be retrieved by calling silc_pkcs_public_key_get_pkcs.
 *
 * SOURCE
 */
typedef struct SilcPublicKeyStruct {
  SilcPKCSObject *pkcs;		/* PKCS */
  const SilcPKCSAlgorithm *alg;	/* PKCS algorithm */
  void *public_key;		/* PKCS specific public key */
} *SilcPublicKey;
/***/

/****s* silccrypt/SilcPKCSAPI/SilcPrivateKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcPrivateKey;
 *
 * DESCRIPTION
 *
 *    This context represents any kind of PKCS private key.  The PKCS specific
 *    key context can be retrieved by calling silc_pkcs_private_key_get_pkcs.
 *
 * SOURCE
 */
typedef struct SilcPrivateKeyStruct {
  SilcPKCSObject *pkcs;		/* PKCS */
  const SilcPKCSAlgorithm *alg;	/* PKCS algorithm */
  void *private_key;		/* PKCS specific private key */
} *SilcPrivateKey;
/***/

/****d* silccrypt/SilcPKCSAPI/SilcPKCSFileEncoding
 *
 * NAME
 *
 *    typedef enum { ... } SilcPKCSType
 *
 * DESCRIPTION
 *
 *    Public and private key file encoding types.
 *
 * SOURCE
 */
typedef enum {
  SILC_PKCS_FILE_BIN,		/* Binary encoding */
  SILC_PKCS_FILE_BASE64		/* Base64 encoding */
} SilcPKCSFileEncoding;
/***/

/****f* silccrypt/SilcPKCSAPI/SilcPKCSEncryptCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPKCSEncryptCb)(SilcBool success,
 *                                      const unsigned char *encrypted,
 *                                      SilcUInt32 encrypted_len,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Encryption callback.  This callback is given as argument to the
 *    silc_pkcs_encrypt and the encrypted data is delivered to the caller
 *    in this callback.  The `encrypted' is the encrypted data.  If the
 *    `success' is FALSE the encryption operation failed.
 *
 ***/
typedef void (*SilcPKCSEncryptCb)(SilcBool success,
				  const unsigned char *encrypted,
				  SilcUInt32 encrypted_len,
				  void *context);

/****f* silccrypt/SilcPKCSAPI/SilcPKCSDecryptCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPKCSDecryptCb)(SilcBool success,
 *                                      const unsigned char *decrypted,
 *                                      SilcUInt32 decrypted_len,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Decryption callback.  This callback is given as argument to the
 *    silc_pkcs_decrypt and the decrypted data is delivered to the caller
 *    in this callback.  The `decrypted' is the decrypted data.  If the
 *    `success' is FALSE the decryption operation failed.
 *
 ***/
typedef void (*SilcPKCSDecryptCb)(SilcBool success,
				  const unsigned char *decrypted,
				  SilcUInt32 decrypted_len,
				  void *context);

/****f* silccrypt/SilcPKCSAPI/SilcPKCSSignCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPKCSSignCb)(SilcBool success,
 *                                   const unsigned char *signature,
 *                                   SilcUInt32 signature_len,
 *                                   void *context);
 *
 * DESCRIPTION
 *
 *    Signature callback.  This callback is given as argument to the
 *    silc_pkcs_sign and the digitally signed data is delivered to the caller
 *    in this callback.  The `signature' is the signature data.  If the
 *    `success' is FALSE the signature operation failed.
 *
 ***/
typedef void (*SilcPKCSSignCb)(SilcBool success,
			       const unsigned char *signature,
			       SilcUInt32 signature_len,
			       void *context);

/****f* silccrypt/SilcPKCSAPI/SilcPKCSVerifyCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcPKCSVerifyCb)(SilcBool success, void *context);
 *
 * DESCRIPTION
 *
 *    Verification callback.  This callback is given as argument to the
 *    silc_pkcs_verify and the result of the signature verification is
 *    deliver to the caller in this callback.  If the `success' is FALSE
 *    the signature verification failed.
 *
 ***/
typedef void (*SilcPKCSVerifyCb)(SilcBool success, void *context);

#include "silcpkcs_i.h"

/* Marks for all PKCS in. This can be used in silc_pkcs_unregister to
   unregister all PKCS at once. */
#define SILC_ALL_PKCS ((SilcPKCSObject *)1)
#define SILC_ALL_PKCS_ALG ((SilcPKCSAlgorithm *)1)

/* Static lists of PKCS and PKCS algorithms. */
extern DLLAPI const SilcPKCSObject silc_default_pkcs[];
extern DLLAPI const SilcPKCSAlgorithm silc_default_pkcs_alg[];

/* Prototypes */

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_register
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_register(const SilcPKCSObject *pkcs);
 *
 * DESCRIPTION
 *
 *    Registers a new PKCS into the crypto library.  This function is used
 *    at the initialization of an application.  All registered PKCSs
 *    should be unregistered with silc_pkcs_unregister.  The `pkcs' includes
 *    the name of the PKCS and member functions for the algorithm.  Usually
 *    this function is not called directly.  Instead, application can call
 *    the silc_pkcs_register_default to register all PKCSs that are
 *    builtin the sources.  Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_register(const SilcPKCSObject *pkcs);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_unregister
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_unregister(SilcPKCSObject *pkcs);
 *
 * DESCRIPTION
 *
 *    Unregister a PKCS from the crypto library. Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_unregister(SilcPKCSObject *pkcs);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_algorithm_register
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_algorithm_register(const SilcPKCSAlgorithm *pkcs);
 *
 * DESCRIPTION
 *
 *    Registers a new PKCS Algorithm into crypto library.  This function
 *    is used at the initialization of an application.  All registered PKCS
*     algorithms should be unregistered with silc_pkcs_unregister.
 *
 ***/
SilcBool silc_pkcs_algorithm_register(const SilcPKCSAlgorithm *pkcs);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_algorithm_unregister
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_algorithm_unregister(SilcPKCSAlgorithm *pkcs);
 *
 * DESCRIPTION
 *
 *    Unregister a PKCS from the crypto library. Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_algorithm_unregister(SilcPKCSAlgorithm *pkcs);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_register_default
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_register_default(void);
 *
 * DESCRIPTION
 *
 *    Registers all the default PKCS (all builtin PKCS) and PKCS algorithms.
 *    The application may use this to register the default PKCS if specific
 *    PKCS in any specific order is not wanted.  Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_register_default(void);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_unregister_all
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_unregister_all(void);
 *
 * DESCRIPTION
 *
 *    Unregister all PKCS and PKCS algorithms. Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_unregister_all(void);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_get_supported
 *
 * SYNOPSIS
 *
 *    char *silc_pkcs_get_supported(void);
 *
 * DESCRIPTION
 *
 *    Returns comma separated list of supported PKCS algorithms.
 *
 ***/
char *silc_pkcs_get_supported(void);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_find_pkcs
 *
 * SYNOPSIS
 *
 *    const SilcPKCSObject *silc_pkcs_get_pkcs(SilcPKCSType type);
 *
 * DESCRIPTION
 *
 *    Finds PKCS context by the PKCS type.
 *
 ***/
const SilcPKCSObject *silc_pkcs_find_pkcs(SilcPKCSType type);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_find_algorithm
 *
 * SYNOPSIS
 *
 *    const SilcPKCSAlgorithm *silc_pkcs_find_algorithm(const char *algorithm,
 *                                                      const char *scheme);
 *
 * DESCRIPTION
 *
 *    Finds PKCS algorithm context by the algorithm name `algorithm' and
 *    the algorithm scheme `scheme'.  The `scheme' may be NULL.
 *
 ***/
const SilcPKCSAlgorithm *silc_pkcs_find_algorithm(const char *algorithm,
						  const char *scheme);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_get_pkcs
 *
 * SYNOPSIS
 *
 *    const SilcPKCSObject *silc_pkcs_get_pkcs(void *key);
 *
 * DESCRIPTION
 *
 *    Returns the PKCS object from `key', which may be SilcPublicKey or
 *    SilcPrivateKey pointer.
 *
 ***/
const SilcPKCSObject *silc_pkcs_get_pkcs(void *key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_get_algorithm
 *
 * SYNOPSIS
 *
 *    const SilcPKCSAlgorithm *silc_pkcs_get_algorithm(void *key);
 *
 * DESCRIPTION
 *
 *    Returns the PKCS algorithm object from `key', which may be SilcPublicKey
 *    or SilcPrivateKey pointer.
 *
 ***/
const SilcPKCSAlgorithm *silc_pkcs_get_algorithm(void *key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_pkcs_get_name(void *key);
 *
 * DESCRIPTION
 *
 *    Returns PKCS algorithm name from the `key', which may be SilcPublicKey
 *    or SilcPrivateKey pointer.
 *
 ***/
const char *silc_pkcs_get_name(void *key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_get_type
 *
 * SYNOPSIS
 *
 *    SilcPKCSType silc_pkcs_get_type(void *key);
 *
 * DESCRIPTION
 *
 *    Returns PKCS type from the `key', which may be SilcPublicKey or
 *    SilcPrivateKey pointer.
 *
 ***/
SilcPKCSType silc_pkcs_get_type(void *key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_get_pkcs
 *
 * SYNOPSIS
 *
 *    void *silc_pkcs_public_key_get_pkcs(SilcPKCSType type,
 *                                        SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Returns the internal PKCS `type' specific public key context from the
 *    `public_key'.  The caller needs to explicitly type cast it to correct
 *    type.  Returns NULL on error.
 *
 *    For SILC_PKCS_SILC the returned context is SilcSILCPublicKey.
 *    For SILC_PKCS_SSH2 the returned context is SilcSshPublicKey.
 *
 ***/
void *silc_pkcs_public_key_get_pkcs(SilcPKCSType type,
				    SilcPublicKey public_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_private_key_get_pkcs
 *
 * SYNOPSIS
 *
 *    void *silc_pkcs_private_key_get_pkcs(SilcPKCSType type,
 *                                        SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Returns the internal PKCS `type' specific private key context from the
 *    `private_key'.  The caller needs to explicitly type cast it to correct
 *    type.  Returns NULL on error.
 *
 *    For SILC_PKCS_SILC the returned context is SilcSILCPrivateKey.
 *    For SILC_PKCS_SSH2 the returned context is SilcSshPrivateKey.
 *
 ***/
void *silc_pkcs_private_key_get_pkcs(SilcPKCSType type,
				     SilcPrivateKey private_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_public_key_alloc(SilcPKCSType type,
 *                                        unsigned char *key,
 *                                        SilcUInt32 key_len
 *                                        SilcPublicKey *ret_public_key);
 *
 * DESCRIPTION
 *
 *    Allocates SilcPublicKey of the type of `type' from the key data
 *    `key' of length of `key_len' bytes.  Returns FALSE if the `key'
 *    is malformed or unsupported public key type.  This function can be
 *    used to create public key from any kind of PKCS public keys that
 *    the implementation supports.
 *
 ***/
SilcBool silc_pkcs_public_key_alloc(SilcPKCSType type,
				    unsigned char *key,
				    SilcUInt32 key_len,
				    SilcPublicKey *ret_public_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_free
 *
 * SYNOPSIS
 *
 *    void silc_pkcs_public_key_free(SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Frees the public key.
 *
 ***/
void silc_pkcs_public_key_free(SilcPublicKey public_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_export
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_pkcs_public_key_encode(SilcStack stack,
 *                                               SilcPublicKey public_key,
 *                                               SilcUInt32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Encodes the `public_key' into a binary format and returns it.  Returns
 *    NULL on error.  Caller must free the returned buffer.
 *
 *    If the `stack' is non-NULL the returned buffer is allocated from the
 *    `stack'.  This call will consume `stack' so caller should push the stack
 *    before calling and then later pop it.
 *
 ***/
unsigned char *silc_pkcs_public_key_encode(SilcStack stack,
					   SilcPublicKey public_key,
					   SilcUInt32 *ret_len);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_get_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_pkcs_public_key_get_len(SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Returns the key length in bits from the public key.
 *
 ***/
SilcUInt32 silc_pkcs_public_key_get_len(SilcPublicKey public_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_public_key_compare(SilcPublicKey key1,
 *                                          SilcPublicKey key2);
 *
 * DESCRIPTION
 *
 *    Compares two public keys and returns TRUE if they are same key, and
 *    FALSE if they are not same.
 *
 ***/
SilcBool silc_pkcs_public_key_compare(SilcPublicKey key1, SilcPublicKey key2);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_public_key_copy
 *
 * SYNOPSIS
 *
 *    SilcPublicKey silc_pkcs_public_key_copy(SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Copies the public key indicated by `public_key' and returns new
 *    allocated public key which is indentical to the `public_key'.
 *
 ***/
SilcPublicKey silc_pkcs_public_key_copy(SilcPublicKey public_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_private_key_alloc
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_private_key_alloc(SilcPKCSType type,
 *                                         unsigned char *key,
 *                                         SilcUInt32 key_len,
 *                                         SilcPrivateKey *ret_private_key);
 *
 * DESCRIPTION
 *
 *    Allocates SilcPrivateKey of the type of `type' from the key data
 *    `key' of length of `key_len' bytes.  Returns FALSE if the `key'
 *    is malformed or unsupported private key type.
 *
 ***/
SilcBool silc_pkcs_private_key_alloc(SilcPKCSType type,
				     unsigned char *key,
				     SilcUInt32 key_len,
				     SilcPrivateKey *ret_private_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_private_key_get_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_pkcs_private_key_get_len(SilcPrivateKey private_key);
 *
 * DESCRIPTION
 *
 *    Returns the key length in bits from the private key.
 *
 ***/
SilcUInt32 silc_pkcs_private_key_get_len(SilcPrivateKey private_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_private_key_free
 *
 * SYNOPSIS
 *
 *    void silc_pkcs_private_key_free(SilcPrivateKey private_key;
 *
 * DESCRIPTION
 *
 *    Frees the private key.
 *
 ***/
void silc_pkcs_private_key_free(SilcPrivateKey private_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_encrypt
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_pkcs_encrypt(SilcPublicKey public_key,
 *                                         unsigned char *src,
 *                                         SilcUInt32 src_len, SilcRng rng,
 *                                         SilcPKCSEncryptCb encrypt_cb,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Encrypts with the public key.  The `encrypt_cb' will be called to
 *    deliver the encrypted data.  The encryption operation may be asynchronous
 *    if the `public_key' is accelerated public key.  If this returns NULL
 *    the asynchronous operation cannot be controlled.
 *
 ***/
SilcAsyncOperation silc_pkcs_encrypt(SilcPublicKey public_key,
				     unsigned char *src,
				     SilcUInt32 src_len, SilcRng rng,
				     SilcPKCSEncryptCb encrypt_cb,
				     void *context);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_decrypt
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_pkcs_decrypt(SilcPrivateKey private_key,
 *                                         unsigned char *src,
 *                                         SilcUInt32 src_len,
 *                                         SilcPKCSDecryptCb decrypt_cb,
 *                                         void *context);
 *
 * DESCRIPTION
 *
 *    Decrypts with the private key.  The `decrypt_cb' will be called to
 *    deliver the decrypted data.  The decryption operation may be asynchronous
 *    if the `private_key' is accelerated private key.  If this returns NULL
 *    the asynchronous operation cannot be controlled.
 *
 ***/
SilcAsyncOperation silc_pkcs_decrypt(SilcPrivateKey private_key,
				     unsigned char *src, SilcUInt32 src_len,
				     SilcPKCSDecryptCb decrypt_cb,
				     void *context);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_sign
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_pkcs_sign(SilcPrivateKey private_key,
 *                                      unsigned char *src,
 *                                      SilcUInt32 src_len,
 *                                      SilcBool compute_hash,
 *                                      SilcHash hash,
 *                                      SilcRng rng,
 *                                      SilcPKCSSignCb sign_cb,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Computes signature with the private key.  The `sign_cb' will be called
 *    to deliver the signature data.  If `compute_hash' is TRUE the `hash'
 *    will be used to compute a message digest over the `src'.  The `hash'
 *    must always be valid.  The `rng' should always be provided.  The
 *    signature operation may be asynchronous if the `private_key' is
 *    accelerated private key.  If this returns NULL the asynchronous
 *    operation cannot be controlled.
 *
 ***/
SilcAsyncOperation silc_pkcs_sign(SilcPrivateKey private_key,
				  unsigned char *src,
				  SilcUInt32 src_len,
				  SilcBool compute_hash,
				  SilcHash hash,
				  SilcRng rng,
				  SilcPKCSSignCb sign_cb,
				  void *context);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_verify
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_pkcs_verify(SilcPublicKey public_key,
 *                                        unsigned char *signature,
 *                                        SilcUInt32 signature_len,
 *                                        unsigned char *data,
 *                                        SilcUInt32 data_len,
 *                                        SilcHash hash,
 *                                        SilcPKCSVerifyCb verify_cb,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Verifies signature.  The `verify_cb' will be called to deliver the
 *    result of the verification process.  The 'signature' is verified against
 *    the 'data'.  If the `hash' is non-NULL then the `data' will hashed
 *    before verification.  If the `hash' is NULL, then the hash algorithm
 *    to be used is retrieved from the signature.  If it isn't present in the
 *    signature the verification is done as is without hashing.  The `rng'
 *    is usually not needed and may be NULL.  If this returns NULL the
 *    asynchronous operation cannot be controlled.
 *
 ***/
SilcAsyncOperation silc_pkcs_verify(SilcPublicKey public_key,
			            unsigned char *signature,
				    SilcUInt32 signature_len,
				    unsigned char *data,
				    SilcUInt32 data_len,
				    SilcHash hash,
				    SilcPKCSVerifyCb verify_cb,
				    void *context);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_load_public_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_load_public_key(const char *filename,
 *                                       SilcPKCSType type,
 *                                       SilcPublicKey *ret_public_key);
 *
 * DESCRIPTION
 *
 *    Loads public key from file and allocates new public key.  Returns TRUE
 *    if loading was successful.  If `type' is SILC_PKSC_ANY this attempts
 *    to automatically detect the public key type.  If `type' is some other
 *    PKCS type, the key is expected to be of that type.
 *
 ***/
SilcBool silc_pkcs_load_public_key(const char *filename,
				   SilcPKCSType type,
				   SilcPublicKey *ret_public_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_save_public_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_save_public_key(const char *filename,
 *                                       SilcPublicKey public_key,
 *                                       SilcPKCSFileEncoding encoding);
 *
 * DESCRIPTION
 *
 *    Saves public key into file with specified encoding.  Returns FALSE
 *    on error.
 *
 ***/
SilcBool silc_pkcs_save_public_key(const char *filename,
				   SilcPublicKey public_key,
				   SilcPKCSFileEncoding encoding);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_load_private_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_load_private_key(const char *filename,
 *                                        const unsigned char *passphrase,
 *                                        SilcUInt32 passphrase_len,
 *                                        SilcPKCSType type,
 *                                        SilcPrivateKey *ret_private_key);
 *
 * DESCRIPTION
 *
 *    Loads private key from file and allocates new private key.  Returns TRUE
 *    if loading was successful.  The `passphrase' is used as decryption
 *    key of the private key file, in case it is encrypted.  If `type' is
 *    SILC_PKSC_ANY this attempts to automatically detect the private key type.
 *    If `type' is some other PKCS type, the key is expected to be of that
 *    type.
 *
 ***/
SilcBool silc_pkcs_load_private_key(const char *filename,
				    const unsigned char *passphrase,
				    SilcUInt32 passphrase_len,
				    SilcPKCSType type,
				    SilcPrivateKey *ret_private_key);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_save_private_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_save_private_key(const char *filename,
 *                                        SilcPrivateKey private_key,
 *                                        const unsigned char *passphrase,
 *                                        SilcUInt32 passphrase_len,
 *                                        SilcPKCSFileEncoding encoding,
 *                                        SilcRng rng);
 *
 * DESCRIPTION
 *
 *    Saves private key into file.  The private key is encrypted into
 *    the file with the `passphrase' as a key, if PKCS supports encrypted
 *    private keys.  Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_save_private_key(const char *filename,
				    SilcPrivateKey private_key,
				    const unsigned char *passphrase,
				    SilcUInt32 passphrase_len,
				    SilcPKCSFileEncoding encoding,
				    SilcRng rng);

/****f* silccrypt/SilcPKCSAPI/silc_hash_public_key
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_public_key(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    An utility function for hashing public key for SilcHashTable.  Give
 *    this as argument as the hash function for SilcHashTable.
 *
 ***/
SilcUInt32 silc_hash_public_key(void *key, void *user_context);

/****f* silccrypt/SilcPKCSAPI/silc_hash_public_key_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_public_key_compare(void *key1, void *key2,
 *                                          void *user_context);
 *
 * DESCRIPTION
 *
 *    An utility function for comparing public keys for SilcHashTable.  Give
 *    this as argument as the compare function for SilcHashTable.
 *
 ***/
SilcBool silc_hash_public_key_compare(void *key1, void *key2,
				      void *user_context);

#endif	/* !SILCPKCS_H */
