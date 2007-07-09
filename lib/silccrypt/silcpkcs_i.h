/*

  silcpkcs_i.h

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

#ifndef SILCPKCS_I_H
#define SILCPKCS_I_H

#ifndef SILCPKCS_H
#error "Do not include this header directly"
#endif

/* Macros for defining the PKCS APIs.  Use these when you need to declare
   PKCS API functions. */

#define SILC_PKCS_ALG_GENERATE_KEY(name)			\
  SilcBool name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
		SilcUInt32 keylen, SilcRng rng,			\
		void **ret_public_key, void **ret_private_key)

#define SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(name)				\
  int name(const struct SilcPKCSAlgorithmStruct *pkcs,			\
	   void *key, SilcUInt32 key_len,				\
	   void **ret_public_key)

#define SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(name)				\
  unsigned char *name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
		      SilcStack stack,					\
		      void *public_key,					\
		      SilcUInt32 *ret_len)

#define SILC_PKCS_ALG_PUBLIC_KEY_BITLEN(name)				\
  SilcUInt32 name(const struct SilcPKCSAlgorithmStruct *pkcs,		\
		  void *public_key)

#define SILC_PKCS_ALG_PUBLIC_KEY_COPY(name)			\
  void *name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
	     void *public_key)

#define SILC_PKCS_ALG_PUBLIC_KEY_COMPARE(name)				\
  SilcBool name(const struct SilcPKCSAlgorithmStruct *pkcs,		\
		void *key1, void *key2)

#define SILC_PKCS_ALG_PUBLIC_KEY_FREE(name)				\
  void name(const struct SilcPKCSAlgorithmStruct *pkcs, void *public_key)

#define SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(name)				\
  int name(const struct SilcPKCSAlgorithmStruct *pkcs,			\
	   void *key, SilcUInt32 key_len, void **ret_private_key)

#define SILC_PKCS_ALG_EXPORT_PRIVATE_KEY(name)				\
  unsigned char *name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
		      SilcStack stack, void *private_key,		\
		      SilcUInt32 *ret_len)

#define SILC_PKCS_ALG_PRIVATE_KEY_BITLEN(name)			\
  SilcUInt32 name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
		  void *private_key)

#define SILC_PKCS_ALG_PRIVATE_KEY_FREE(name)		\
  void name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
	    void *private_key)

#define SILC_PKCS_ALG_ENCRYPT(name)					\
  SilcAsyncOperation name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
			  void *public_key,				\
			  unsigned char *src,				\
			  SilcUInt32 src_len,				\
			  SilcRng rng,					\
			  SilcPKCSEncryptCb encrypt_cb,			\
			  void *context)

#define SILC_PKCS_ALG_DECRYPT(name)					\
  SilcAsyncOperation name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
			  void *private_key,				\
			  unsigned char *src,				\
			  SilcUInt32 src_len,				\
			  SilcPKCSDecryptCb decrypt_cb,			\
			  void *context)

#define SILC_PKCS_ALG_SIGN(name)					\
  SilcAsyncOperation name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
			  void *private_key,				\
			  unsigned char *src,				\
			  SilcUInt32 src_len,				\
			  SilcBool compute_hash,			\
			  SilcHash hash,				\
			  SilcPKCSSignCb sign_cb,			\
			  void *context)

#define SILC_PKCS_ALG_VERIFY(name)					\
  SilcAsyncOperation name(const struct SilcPKCSAlgorithmStruct *pkcs,	\
			  void *public_key,				\
			  unsigned char *signature,			\
			  SilcUInt32 signature_len,			\
			  unsigned char *data,				\
			  SilcUInt32 data_len,				\
			  SilcHash hash,				\
			  SilcPKCSVerifyCb verify_cb,			\
			  void *context)

/* The PKCS Algorithm object to represent any PKCS algorithm.  This context
   implements the PKCS algorithm, such as RSA, DSA, etc. */
struct SilcPKCSAlgorithmStruct {
  /* Algorithm name and scheme */
  char *name;			/* Eg. rsa, dsa, etc. */
  char *scheme;			/* Eg. pkcs1, openpgp, etc. */

  /* Supported hash functions, comma separated list */
  char *hash;

  /* Generate new key pair. Returns PKCS algorithm specific public key
     and private key contexts. */
  SILC_PKCS_ALG_GENERATE_KEY((*generate_key));

  /* Public key routines. */

  /* Import/create new public key.  Returns the length of the data that was
     imported from `key' or 0 on error.  Returns the PKCS algorithm specific
     public key to `ret_public_key'. */
  SILC_PKCS_ALG_IMPORT_PUBLIC_KEY((*import_public_key));

  /* Export/encode public key.  Returns the encoded public key buffer that
     the caller must free. */
  SILC_PKCS_ALG_EXPORT_PUBLIC_KEY((*export_public_key));

  /* Returns the bit length of public key */
  SILC_PKCS_ALG_PUBLIC_KEY_BITLEN((*public_key_bitlen));

  /* Duplicated public key */
  SILC_PKCS_ALG_PUBLIC_KEY_COPY((*public_key_copy));

  /* Compares two public keys.  Returns TRUE if they are identical. */
  SILC_PKCS_ALG_PUBLIC_KEY_COMPARE((*public_key_compare));

  /* Free public key */
  SILC_PKCS_ALG_PUBLIC_KEY_FREE((*public_key_free));

  /* Private key routines. */

  /* Import/create new private key.  Returns the length of the data that was
     imported from `key' or 0 on error.  Returns the PKCS algorithm specific
     private key to `ret_private_key'. */
  SILC_PKCS_ALG_IMPORT_PRIVATE_KEY((*import_private_key));

  /* Export/encode private key.  Returns the encoded private key buffer that
     the caller must free. */
  SILC_PKCS_ALG_EXPORT_PRIVATE_KEY((*export_private_key));

  /* Returns the bi length of private key */
  SILC_PKCS_ALG_PRIVATE_KEY_BITLEN((*private_key_bitlen));

  /* Free private key */
  SILC_PKCS_ALG_PRIVATE_KEY_FREE((*private_key_free));

  /* Encrypt and decrypt operations */
  SILC_PKCS_ALG_ENCRYPT((*encrypt));
  SILC_PKCS_ALG_DECRYPT((*decrypt));

  /* Signature and verification operations */
  SILC_PKCS_ALG_SIGN((*sign));
  SILC_PKCS_ALG_VERIFY((*verify));
};

/* Macros for defining the PKCS APIs.  Use these when you need to declare
   PKCS API functions. */

#define SILC_PKCS_GET_ALGORITHM(name)					\
  const SilcPKCSAlgorithm *name(const struct SilcPKCSObjectStruct *pkcs, \
				void *public_key)

#define SILC_PKCS_IMPORT_PUBLIC_KEY_FILE(name)				\
  SilcBool name(const struct SilcPKCSObjectStruct *pkcs,		\
		unsigned char *filedata, SilcUInt32 filedata_len,	\
		SilcPKCSFileEncoding encoding, void **ret_public_key,	\
		const struct SilcPKCSAlgorithmStruct **ret_alg)

#define SILC_PKCS_IMPORT_PUBLIC_KEY(name)			\
  int name(const struct SilcPKCSObjectStruct *pkcs, void *key,	\
	   SilcUInt32 key_len, void **ret_public_key,		\
	   const struct SilcPKCSAlgorithmStruct **ret_alg)

#define SILC_PKCS_EXPORT_PUBLIC_KEY_FILE(name)			\
  unsigned char *name(const struct SilcPKCSObjectStruct *pkcs,	\
		      SilcStack stack, void *public_key,	\
		      SilcPKCSFileEncoding encoding,		\
		      SilcUInt32 *ret_len)

#define SILC_PKCS_EXPORT_PUBLIC_KEY(name)				\
  unsigned char *name(const struct SilcPKCSObjectStruct *pkcs,		\
		      SilcStack stack, void *public_key, SilcUInt32 *ret_len)

#define SILC_PKCS_PUBLIC_KEY_BITLEN(name)			\
  SilcUInt32 name(const struct SilcPKCSObjectStruct *pkcs,	\
		  void *public_key)

#define SILC_PKCS_PUBLIC_KEY_COPY(name)					\
  void *name(const struct SilcPKCSObjectStruct *pkcs, void *public_key)

#define SILC_PKCS_PUBLIC_KEY_COMPARE(name)			\
  SilcBool name(const struct SilcPKCSObjectStruct *pkcs,	\
		void *key1, void *key2)

#define SILC_PKCS_PUBLIC_KEY_FREE(name)					\
  void name(const struct SilcPKCSObjectStruct *pkcs, void *public_key)

#define SILC_PKCS_IMPORT_PRIVATE_KEY_FILE(name)				\
  SilcBool name(const struct SilcPKCSObjectStruct *pkcs,		\
		unsigned char *filedata, SilcUInt32 filedata_len,	\
		const char *passphrase, SilcUInt32 passphrase_len,	\
		SilcPKCSFileEncoding encoding, void **ret_private_key,	\
		const struct SilcPKCSAlgorithmStruct **ret_alg)

#define SILC_PKCS_IMPORT_PRIVATE_KEY(name)			\
  int name(const struct SilcPKCSObjectStruct *pkcs, void *key,	\
	   SilcUInt32 key_len, void **ret_private_key,		\
	   const struct SilcPKCSAlgorithmStruct **ret_alg)

#define SILC_PKCS_EXPORT_PRIVATE_KEY_FILE(name)				\
  unsigned char *name(const struct SilcPKCSObjectStruct *pkcs,		\
		      SilcStack stack, void *private_key,		\
		      const char *passphrase, SilcUInt32 passphrase_len, \
		      SilcPKCSFileEncoding encoding, SilcRng rng,	\
		      SilcUInt32 *ret_len)

#define SILC_PKCS_EXPORT_PRIVATE_KEY(name)				\
  unsigned char *name(const struct SilcPKCSObjectStruct *pkcs,		\
		      SilcStack stack, void *private_key, SilcUInt32 *ret_len)

#define SILC_PKCS_PRIVATE_KEY_BITLEN(name)			\
  SilcUInt32 name(const struct SilcPKCSObjectStruct *pkcs, void *private_key)

#define SILC_PKCS_PRIVATE_KEY_FREE(name)				\
  void name(const struct SilcPKCSObjectStruct *pkcs, void *private_key)

#define SILC_PKCS_ENCRYPT(name)						\
  SilcAsyncOperation name(const struct SilcPKCSObjectStruct *pkcs,	\
			  void *public_key,				\
			  unsigned char *src,				\
			  SilcUInt32 src_len,				\
			  SilcRng rng,					\
			  SilcPKCSEncryptCb encrypt_cb,			\
			  void *context)

#define SILC_PKCS_DECRYPT(name)						\
  SilcAsyncOperation name(const struct SilcPKCSObjectStruct *pkcs,	\
			  void *private_key,				\
			  unsigned char *src,				\
			  SilcUInt32 src_len,				\
			  SilcPKCSDecryptCb decrypt_cb,			\
			  void *context)

#define SILC_PKCS_SIGN(name)						\
  SilcAsyncOperation name(const struct SilcPKCSObjectStruct *pkcs,	\
			  void *private_key,				\
			  unsigned char *src,				\
			  SilcUInt32 src_len,				\
			  SilcBool compute_hash,			\
			  SilcHash hash,				\
			  SilcPKCSSignCb sign_cb,			\
			  void *context)

#define SILC_PKCS_VERIFY(name)						\
  SilcAsyncOperation name(const struct SilcPKCSObjectStruct *pkcs,	\
			  void *public_key,				\
			  unsigned char *signature,			\
			  SilcUInt32 signature_len,			\
			  unsigned char *data,				\
			  SilcUInt32 data_len,				\
			  SilcHash hash,				\
			  SilcPKCSVerifyCb verify_cb,			\
			  void *context)

/* The PKCS (Public Key Cryptosystem) object to represent any PKCS.  This
   context implements the PKCS, such as SILC public keys, X.509 certificates,
   OpenPGP certificates, etc. under a common API. */
struct SilcPKCSObjectStruct {
  /* PKCS type */
  SilcPKCSType type;

  /* Public key routines */

  /* Returns PKCS algorithm context from public key */
  SILC_PKCS_GET_ALGORITHM((*get_algorithm));

  /* Imports from public key file */
  SILC_PKCS_IMPORT_PUBLIC_KEY_FILE((*import_public_key_file));

  /* Imports from public key binary data.  Returns the amount of bytes
     imported from `key' or 0 on error. */
  SILC_PKCS_IMPORT_PUBLIC_KEY((*import_public_key));

  /* Exports public key to file */
  SILC_PKCS_EXPORT_PUBLIC_KEY_FILE((*export_public_key_file));

  /* Export public key as binary data */
  SILC_PKCS_EXPORT_PUBLIC_KEY((*export_public_key));

  /* Returns key length in bits */
  SILC_PKCS_PUBLIC_KEY_BITLEN((*public_key_bitlen));

  /* Copy public key */
  SILC_PKCS_PUBLIC_KEY_COPY((*public_key_copy));

  /* Compares public keys */
  SILC_PKCS_PUBLIC_KEY_COMPARE((*public_key_compare));

  /* Free public key */
  SILC_PKCS_PUBLIC_KEY_FREE((*public_key_free));

  /* Private key routines */

  /* Imports from private key file */
  SILC_PKCS_IMPORT_PRIVATE_KEY_FILE((*import_private_key_file));

  /* Imports from private key binary data.  Returns the amount of bytes
     imported from `key' or 0 on error. */
  SILC_PKCS_IMPORT_PRIVATE_KEY((*import_private_key));

  /* Exports private key to file */
  SILC_PKCS_EXPORT_PRIVATE_KEY_FILE((*export_private_key_file));

  /* Export private key as binary data */
  SILC_PKCS_EXPORT_PRIVATE_KEY((*export_private_key));

  /* Returns key length in bits */
  SILC_PKCS_PRIVATE_KEY_BITLEN((*private_key_bitlen));

  /* Free private key */
  SILC_PKCS_PRIVATE_KEY_FREE((*private_key_free));

  /* Encrypt and decrypt operations */
  SILC_PKCS_ENCRYPT((*encrypt));
  SILC_PKCS_DECRYPT((*decrypt));

  /* Signature and verification operations */
  SILC_PKCS_SIGN((*sign));
  SILC_PKCS_VERIFY((*verify));
};

#endif /* SILCPKCS_I_H */
