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
typedef struct SilcPKCSObjectStruct SilcPKCSObject;

/****d* silccrypt/SilcPKCSAPI/SilcPKCSType
 *
 * NAME
 *
 *    typedef enum { ... } SilcPKCSType;
 *
 * DESCRIPTION
 *
 *    Public key cryptosystem types.  These are defined by the SILC
 *    Key Exchange protocol.
 *
 * SOURCE
 */
typedef enum {
  SILC_PKCS_SILC    = 1,	/* SILC PKCS */
  SILC_PKCS_SSH2    = 2,	/* SSH2 PKCS (not supported) */
  SILC_PKCS_X509V3  = 3,	/* X.509v3 PKCS (not supported) */
  SILC_PKCS_OPENPGP = 4,	/* OpenPGP PKCS (not supported) */
  SILC_PKCS_SPKI    = 5,	/* SPKI PKCS (not supported) */
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
 *    can be retrieved by calling silc_pkcs_get_context.
 *
 * SOURCE
 */
typedef struct {
  const SilcPKCSObject *pkcs;	/* PKCS */
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
 *    This context represents any kind of PKCS private key.
 *
 * SOURCE
 */
typedef struct {
  const SilcPKCSObject *pkcs;	/* PKCS */
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

/* The PKCS Algorithm object to represent any PKCS algorithm. */
typedef struct {
  /* Algorithm name and scheme */
  char *name;
  char *scheme;

  /* Supported hash functions, comma separated list */
  char *hash;

  /* Generate new key pair. Returns PKCS algorithm specific public key
     and private key contexts. */
  SilcBool (*generate_key)(SilcUInt32 keylen,
			   SilcRng rng,
			   void **ret_public_key,
			   void **ret_private_key);

  /* Public key routines */
  SilcBool (*import_public_key)(unsigned char *key,
				SilcUInt32 key_len,
				void **ret_public_key);
  unsigned char *(*export_public_key)(void *public_key,
				      SilcUInt32 *ret_len);
  SilcUInt32 (*public_key_bitlen)(void *public_key);
  void *(*public_key_copy)(void *public_key);
  SilcBool (*public_key_compare)(void *key1, void *key2);
  void (*public_key_free)(void *public_key);

  /* Private key routines */
  SilcBool (*import_private_key)(unsigned char *key,
				 SilcUInt32 key_len,
				 void **ret_private_key);
  unsigned char *(*export_private_key)(void *private_key,
				       SilcUInt32 *ret_len);
  SilcUInt32 (*private_key_bitlen)(void *public_key);
  void (*private_key_free)(void *private_key);

  /* Encrypt and decrypt operations */
  SilcBool (*encrypt)(void *public_key,
		      unsigned char *src,
		      SilcUInt32 src_len,
		      unsigned char *dst,
		      SilcUInt32 dst_size,
		      SilcUInt32 *ret_dst_len,
		      SilcRng rng);
  SilcBool (*decrypt)(void *private_key,
		      unsigned char *src,
		      SilcUInt32 src_len,
		      unsigned char *dst,
		      SilcUInt32 dst_size,
		      SilcUInt32 *ret_dst_len);

  /* Signature and verification operations */
  SilcBool (*sign)(void *private_key,
		   unsigned char *src,
		   SilcUInt32 src_len,
		   unsigned char *signature,
		   SilcUInt32 signature_size,
		   SilcUInt32 *ret_signature_len,
		   SilcHash hash);
  SilcBool (*verify)(void *public_key,
		     unsigned char *signature,
		     SilcUInt32 signature_len,
		     unsigned char *data,
		     SilcUInt32 data_len,
		     SilcHash hash);
} SilcPKCSAlgorithm;

/* The PKCS (Public Key Cryptosystem) object to represent any PKCS. */
struct SilcPKCSObjectStruct {
  /* PKCS type */
  SilcPKCSType type;

  /* Public key routines */

  /* Returns PKCS algorithm context from public key */
  const SilcPKCSAlgorithm *(*get_algorithm)(void *public_key);

  /* Imports from public key file */
  SilcBool (*import_public_key_file)(unsigned char *filedata,
				     SilcUInt32 filedata_len,
				     SilcPKCSFileEncoding encoding,
				     void **ret_public_key);

  /* Imports from public key binary data */
  SilcBool (*import_public_key)(unsigned char *key,
				SilcUInt32 key_len,
				void **ret_public_key);

  /* Exports public key to file */
  unsigned char *(*export_public_key_file)(void *public_key,
					   SilcPKCSFileEncoding encoding,
					   SilcUInt32 *ret_len);

  /* Export public key as binary data */
  unsigned char *(*export_public_key)(void *public_key,
				      SilcUInt32 *ret_len);

  /* Returns key length in bits */
  SilcUInt32 (*public_key_bitlen)(void *public_key);

  /* Copy public key */
  void *(*public_key_copy)(void *public_key);

  /* Compares public keys */
  SilcBool (*public_key_compare)(void *key1, void *key2);

  /* Free public key */
  void (*public_key_free)(void *public_key);

  /* Private key routines */

  /* Imports from private key file */
  SilcBool (*import_private_key_file)(unsigned char *filedata,
				      SilcUInt32 filedata_len,
				      const char *passphrase,
				      SilcUInt32 passphrase_len,
				      SilcPKCSFileEncoding encoding,
				      void **ret_private_key);

  /* Imports from private key binary data */
  SilcBool (*import_private_key)(unsigned char *key,
				 SilcUInt32 key_len,
				 void **ret_private_key);

  /* Exports private key to file */
  unsigned char *(*export_private_key_file)(void *private_key,
					    const char *passphrase,
					    SilcUInt32 passphrase_len,
					    SilcPKCSFileEncoding encoding,
					    SilcRng rng,
					    SilcUInt32 *ret_len);

  /* Export private key as binary data */
  unsigned char *(*export_private_key)(void *private_key,
				       SilcUInt32 *ret_len);

  /* Returns key length in bits */
  SilcUInt32 (*private_key_bitlen)(void *private_key);

  /* Free private key */
  void (*private_key_free)(void *private_key);

  /* Encrypt and decrypt operations */
  SilcBool (*encrypt)(void *public_key,
		      unsigned char *src,
		      SilcUInt32 src_len,
		      unsigned char *dst,
		      SilcUInt32 dst_size,
		      SilcUInt32 *ret_dst_len,
		      SilcRng rng);
  SilcBool (*decrypt)(void *private_key,
		      unsigned char *src,
		      SilcUInt32 src_len,
		      unsigned char *dst,
		      SilcUInt32 dst_size,
		      SilcUInt32 *ret_dst_len);

  /* Signature and verification operations */
  SilcBool (*sign)(void *private_key,
		   unsigned char *src,
		   SilcUInt32 src_len,
		   unsigned char *signature,
		   SilcUInt32 signature_size,
		   SilcUInt32 *ret_signature_len,
		   SilcHash hash);
  SilcBool (*verify)(void *public_key,
		     unsigned char *signature,
		     SilcUInt32 signature_len,
		     unsigned char *data,
		     SilcUInt32 data_len,
		     SilcHash hash);
};

/* Marks for all PKCS in silc. This can be used in silc_pkcs_unregister
   to unregister all PKCS at once. */
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
 *    Registers a new PKCS into the SILC.  This function is used
 *    at the initialization of the SILC.  All registered PKCSs
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
 *    Unregister a PKCS from the SILC. Returns FALSE on error.
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
 *    Registers a new PKCS Algorithm into the SILC.  This function is used
 *    at the initialization of the SILC.  All registered PKCS algorithms
 *    should be unregistered with silc_pkcs_unregister.
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
 *    Unregister a PKCS from the SILC. Returns FALSE on error.
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

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_get_context
 *
 * SYNOPSIS
 *
 *    void *silc_pkcs_get_context(SilcPKCSType type, SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Returns the internal PKCS `type' specific public key context from the
 *    `public_key'.  The caller needs to explicitly type cast it to correct
 *    type.  Returns NULL on error.
 *
 *    For SILC_PKCS_SILC the returned context is SilcSILCPublicKey.
 *
 ***/
void *silc_pkcs_get_context(SilcPKCSType type, SilcPublicKey public_key);

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
 *    unsigned char *silc_pkcs_public_key_encode(SilcPublicKey public_key,
 *                                               SilcUInt32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Encodes the `public_key' into a binary format and returns it.  Returns
 *    NULL on error.  Caller must free the returned buffer.
 *
 ***/
unsigned char *silc_pkcs_public_key_encode(SilcPublicKey public_key,
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
 *    SilcBool silc_pkcs_encrypt(SilcPublicKey public_key,
 *                               unsigned char *src, SilcUInt32 src_len,
 *                               unsigned char *dst, SilcUInt32 dst_size,
 *                               SilcUInt32 *dst_len);
 *
 * DESCRIPTION
 *
 *    Encrypts with the public key. Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_encrypt(SilcPublicKey public_key,
			   unsigned char *src, SilcUInt32 src_len,
			   unsigned char *dst, SilcUInt32 dst_size,
			   SilcUInt32 *dst_len, SilcRng rng);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_decrypt
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_decrypt(SilcPrivateKey private_key,
 *                               unsigned char *src, SilcUInt32 src_len,
 *                               unsigned char *dst, SilcUInt32 dst_size,
 *                               SilcUInt32 *dst_len);
 *
 * DESCRIPTION
 *
 *    Decrypts with the private key.  Returns FALSE on error.
 *
 ***/
SilcBool silc_pkcs_decrypt(SilcPrivateKey private_key,
			   unsigned char *src, SilcUInt32 src_len,
			   unsigned char *dst, SilcUInt32 dst_size,
			   SilcUInt32 *dst_len);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_sign
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_sign(SilcPrivateKey private_key,
 *                            unsigned char *src, SilcUInt32 src_len,
 *                            unsigned char *dst, SilcUInt32 dst_size,
 *                            SilcUInt32 *dst_len, SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Generates signature with the private key.  Returns FALSE on error.
 *    If `hash' is non-NULL the `src' will be hashed before signing.
 *
 ***/
SilcBool silc_pkcs_sign(SilcPrivateKey private_key,
			unsigned char *src, SilcUInt32 src_len,
			unsigned char *dst, SilcUInt32 dst_size,
			SilcUInt32 *dst_len, SilcHash hash);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_verify
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_verify(SilcPublicKey public_key,
 *                              unsigned char *signature,
 *                              SilcUInt32 signature_len,
 *                              unsigned char *data,
 *                              SilcUInt32 data_len, SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Verifies signature.  Returns FALSE on error.  The 'signature' is
 *    verified against the 'data'.  If the `hash' is non-NULL then the `data'
 *    will hashed before verification.  If the `hash' is NULL, then the
 *    hash algorithm to be used is retrieved from the signature.  If it
 *    isn't present in the signature the verification is done as is without
 *    hashing.
 *
 ***/
SilcBool silc_pkcs_verify(SilcPublicKey public_key,
			  unsigned char *signature,
			  SilcUInt32 signature_len,
			  unsigned char *data,
			  SilcUInt32 data_len, SilcHash hash);

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_load_public_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_load_public_key(const char *filename,
 *                                       SilcPublicKey *ret_public_key);
 *
 * DESCRIPTION
 *
 *    Loads public key from file and allocates new public key.  Returns TRUE
 *    if loading was successful.
 *
 ***/
SilcBool silc_pkcs_load_public_key(const char *filename,
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
 *                                        SilcPrivateKey *ret_private_key);
 *
 * DESCRIPTION
 *
 *    Loads private key from file and allocates new private key.  Returns TRUE
 *    if loading was successful.  The `passphrase' is used as decryption
 *    key of the private key file, in case it is encrypted.
 *
 ***/
SilcBool silc_pkcs_load_private_key(const char *filename,
				    const unsigned char *passphrase,
				    SilcUInt32 passphrase_len,
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

#endif	/* !SILCPKCS_H */
