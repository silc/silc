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
  SilcBool (*generate_key)(const struct SilcPKCSAlgorithmStruct *pkcs,
			   SilcUInt32 keylen,
			   SilcRng rng,
			   void **ret_public_key,
			   void **ret_private_key);

  /* Public key routines. */

  /* Import/create new public key.  Returns the length of the data that was
     imported from `key' or 0 on error.  Returns the PKCS algorithm specific
     public key to `ret_public_key'. */
  int (*import_public_key)(const struct SilcPKCSAlgorithmStruct *pkcs,
			   void *key, SilcUInt32 key_len,
			   void **ret_public_key);

  /* Export/encode public key.  Returns the encoded public key buffer that
     the caller must free. */
  unsigned char *
  (*export_public_key)(const struct SilcPKCSAlgorithmStruct *pkcs,
		       SilcStack stack,
		       void *public_key,
		       SilcUInt32 *ret_len);

  /* Returns the bit length of public key */
  SilcUInt32 (*public_key_bitlen)(const struct SilcPKCSAlgorithmStruct *pkcs,
				  void *public_key);

  /* Duplicated public key */
  void *(*public_key_copy)(const struct SilcPKCSAlgorithmStruct *pkcs,
			   void *public_key);

  /* Compares two public keys.  Returns TRUE if they are identical. */
  SilcBool (*public_key_compare)(const struct SilcPKCSAlgorithmStruct *pkcs,
				 void *key1, void *key2);

  /* Free public key */
  void (*public_key_free)(const struct SilcPKCSAlgorithmStruct *pkcs,
			  void *public_key);

  /* Private key routines. */

  /* Import/create new private key.  Returns the length of the data that was
     imported from `key' or 0 on error.  Returns the PKCS algorithm specific
     private key to `ret_private_key'. */
  int (*import_private_key)(const struct SilcPKCSAlgorithmStruct *pkcs,
			    void *key,
			    SilcUInt32 key_len,
			    void **ret_private_key);

  /* Export/encode private key.  Returns the encoded private key buffer that
     the caller must free. */
  unsigned char *
  (*export_private_key)(const struct SilcPKCSAlgorithmStruct *pkcs,
			SilcStack stack,
			void *private_key,
			SilcUInt32 *ret_len);

  /* Returns the bi length of private key */
  SilcUInt32 (*private_key_bitlen)(const struct SilcPKCSAlgorithmStruct *pkcs,
				   void *public_key);

  /* Free private key */
  void (*private_key_free)(const struct SilcPKCSAlgorithmStruct *pkcs,
			   void *private_key);

  /* Encrypt and decrypt operations */
  SilcAsyncOperation (*encrypt)(const struct SilcPKCSAlgorithmStruct *pkcs,
				void *public_key,
				unsigned char *src,
				SilcUInt32 src_len,
				SilcRng rng,
				SilcPKCSEncryptCb encrypt_cb,
				void *context);
  SilcAsyncOperation (*decrypt)(const struct SilcPKCSAlgorithmStruct *pkcs,
				void *private_key,
				unsigned char *src,
				SilcUInt32 src_len,
				SilcPKCSDecryptCb decrypt_cb,
				void *context);

  /* Signature and verification operations */
  SilcAsyncOperation (*sign)(const struct SilcPKCSAlgorithmStruct *pkcs,
			     void *private_key,
			     unsigned char *src,
			     SilcUInt32 src_len,
			     SilcBool compute_hash,
			     SilcHash hash,
			     SilcPKCSSignCb sign_cb,
			     void *context);
  SilcAsyncOperation (*verify)(const struct SilcPKCSAlgorithmStruct *pkcs,
			       void *public_key,
			       unsigned char *signature,
			       SilcUInt32 signature_len,
			       unsigned char *data,
			       SilcUInt32 data_len,
			       SilcHash hash,
			       SilcPKCSVerifyCb verify_cb,
			       void *context);
};

/* The PKCS (Public Key Cryptosystem) object to represent any PKCS.  This
   context implements the PKCS, such as SILC public keys, X.509 certificates,
   OpenPGP certificates, etc. under a common API. */
struct SilcPKCSObjectStruct {
  /* PKCS type */
  SilcPKCSType type;

  /* Public key routines */

  /* Returns PKCS algorithm context from public key */
  const SilcPKCSAlgorithm *
  (*get_algorithm)(const struct SilcPKCSObjectStruct *pkcs,
		   void *public_key);

  /* Imports from public key file */
  SilcBool (*import_public_key_file)(const struct SilcPKCSObjectStruct *pkcs,
				     unsigned char *filedata,
				     SilcUInt32 filedata_len,
				     SilcPKCSFileEncoding encoding,
				     void **ret_public_key);

  /* Imports from public key binary data.  Returns the amount of bytes
     imported from `key' or 0 on error. */
  int (*import_public_key)(const struct SilcPKCSObjectStruct *pkcs,
			   void *key,
			   SilcUInt32 key_len,
			   void **ret_public_key);

  /* Exports public key to file */
  unsigned char *
  (*export_public_key_file)(const struct SilcPKCSObjectStruct *pkcs,
			    SilcStack stack,
			    void *public_key,
			    SilcPKCSFileEncoding encoding,
			    SilcUInt32 *ret_len);

  /* Export public key as binary data */
  unsigned char *(*export_public_key)(const struct SilcPKCSObjectStruct *pkcs,
				      SilcStack stack,
				      void *public_key,
				      SilcUInt32 *ret_len);

  /* Returns key length in bits */
  SilcUInt32 (*public_key_bitlen)(const struct SilcPKCSObjectStruct *pkcs,
				  void *public_key);

  /* Copy public key */
  void *(*public_key_copy)(const struct SilcPKCSObjectStruct *pkcs,
			   void *public_key);

  /* Compares public keys */
  SilcBool (*public_key_compare)(const struct SilcPKCSObjectStruct *pkcs,
				 void *key1, void *key2);

  /* Free public key */
  void (*public_key_free)(const struct SilcPKCSObjectStruct *pkcs,
			  void *public_key);

  /* Private key routines */

  /* Imports from private key file */
  SilcBool (*import_private_key_file)(const struct SilcPKCSObjectStruct *pkcs,
				      unsigned char *filedata,
				      SilcUInt32 filedata_len,
				      const char *passphrase,
				      SilcUInt32 passphrase_len,
				      SilcPKCSFileEncoding encoding,
				      void **ret_private_key);

  /* Imports from private key binary data.  Returns the amount of bytes
     imported from `key' or 0 on error. */
  int (*import_private_key)(const struct SilcPKCSObjectStruct *pkcs,
			    void *key,
			    SilcUInt32 key_len,
			    void **ret_private_key);

  /* Exports private key to file */
  unsigned char *
  (*export_private_key_file)(const struct SilcPKCSObjectStruct *pkcs,
			     SilcStack stack,
			     void *private_key,
			     const char *passphrase,
			     SilcUInt32 passphrase_len,
			     SilcPKCSFileEncoding encoding,
			     SilcRng rng,
			     SilcUInt32 *ret_len);

  /* Export private key as binary data */
  unsigned char *(*export_private_key)(const struct SilcPKCSObjectStruct *pkcs,
				       SilcStack stack,
				       void *private_key,
				       SilcUInt32 *ret_len);

  /* Returns key length in bits */
  SilcUInt32 (*private_key_bitlen)(const struct SilcPKCSObjectStruct *pkcs,
				   void *private_key);

  /* Free private key */
  void (*private_key_free)(const struct SilcPKCSObjectStruct *pkcs,
			   void *private_key);

  /* Encrypt and decrypt operations */
  SilcAsyncOperation (*encrypt)(const struct SilcPKCSObjectStruct *pkcs,
				void *public_key,
				unsigned char *src,
				SilcUInt32 src_len,
				SilcRng rng,
				SilcPKCSEncryptCb encrypt_cb,
				void *context);
  SilcAsyncOperation (*decrypt)(const struct SilcPKCSObjectStruct *pkcs,
				void *private_key,
				unsigned char *src,
				SilcUInt32 src_len,
				SilcPKCSDecryptCb decrypt_cb,
				void *context);

  /* Signature and verification operations */
  SilcAsyncOperation (*sign)(const struct SilcPKCSObjectStruct *pkcs,
			     void *private_key,
			     unsigned char *src,
			     SilcUInt32 src_len,
			     SilcBool compute_hash,
			     SilcHash hash,
			     SilcPKCSSignCb sign_cb,
			     void *context);
  SilcAsyncOperation (*verify)(const struct SilcPKCSObjectStruct *pkcs,
			       void *public_key,
			       unsigned char *signature,
			       SilcUInt32 signature_len,
			       unsigned char *data,
			       SilcUInt32 data_len,
			       SilcHash hash,
			       SilcPKCSVerifyCb verify_cb,
			       void *context);
};

#endif /* SILCPKCS_I_H */
