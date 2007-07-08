/*

  silcpkcs1_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C); 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCPKCS1_I_H
#define SILCPKCS1_I_H

SilcBool silc_pkcs1_generate_key(const struct SilcPKCSAlgorithmStruct *pkcs,
				 SilcUInt32 keylen,
				 SilcRng rng,
				 void **ret_public_key,
				 void **ret_private_key);
int silc_pkcs1_import_public_key(const struct SilcPKCSAlgorithmStruct *pkcs,
				 void *key,
				 SilcUInt32 key_len,
				 void **ret_public_key);
unsigned char *
silc_pkcs1_export_public_key(const struct SilcPKCSAlgorithmStruct *pkcs,
			     SilcStack stack,
			     void *public_key,
			     SilcUInt32 *ret_len);
SilcUInt32
silc_pkcs1_public_key_bitlen(const struct SilcPKCSAlgorithmStruct *pkcs,
			     void *public_key);
void *silc_pkcs1_public_key_copy(const struct SilcPKCSAlgorithmStruct *pkcs,
				 void *public_key);
SilcBool
silc_pkcs1_public_key_compare(const struct SilcPKCSAlgorithmStruct *pkcs,
			      void *key1, void *key2);
void silc_pkcs1_public_key_free(const struct SilcPKCSAlgorithmStruct *pkcs,
				void *public_key);
int silc_pkcs1_import_private_key(const struct SilcPKCSAlgorithmStruct *pkcs,
				  void *key,
				  SilcUInt32 key_len,
				  void **ret_private_key);
unsigned char *
silc_pkcs1_export_private_key(const struct SilcPKCSAlgorithmStruct *pkcs,
			      SilcStack stack,
			      void *private_key,
			      SilcUInt32 *ret_len);
SilcUInt32
silc_pkcs1_private_key_bitlen(const struct SilcPKCSAlgorithmStruct *pkcs,
			      void *private_key);
void silc_pkcs1_private_key_free(const struct SilcPKCSAlgorithmStruct *pkcs,
				 void *private_key);
SilcAsyncOperation
silc_pkcs1_encrypt(const struct SilcPKCSAlgorithmStruct *pkcs,
		   void *public_key,
		   unsigned char *src,
		   SilcUInt32 src_len,
		   SilcRng rng,
		   SilcPKCSEncryptCb encrypt_cb,
		   void *context);
SilcAsyncOperation
silc_pkcs1_decrypt(const struct SilcPKCSAlgorithmStruct *pkcs,
		   void *private_key,
		   unsigned char *src,
		   SilcUInt32 src_len,
		   SilcPKCSDecryptCb decrypt_cb,
		   void *context);
SilcAsyncOperation silc_pkcs1_sign(const struct SilcPKCSAlgorithmStruct *pkcs,
				   void *private_key,
				   unsigned char *src,
				   SilcUInt32 src_len,
				   SilcBool compute_hash,
				   SilcHash hash,
				   SilcPKCSSignCb sign_cb,
				   void *context);
SilcAsyncOperation silc_pkcs1_verify(const struct SilcPKCSAlgorithmStruct *pkcs,
				     void *public_key,
				     unsigned char *signature,
				     SilcUInt32 signature_len,
				     unsigned char *data,
				     SilcUInt32 data_len,
				     SilcHash hash,
				     SilcPKCSVerifyCb verify_cb,
				     void *context);
SilcAsyncOperation
silc_pkcs1_sign_no_oid(const struct SilcPKCSAlgorithmStruct *pkcs,
		       void *private_key,
		       unsigned char *src,
		       SilcUInt32 src_len,
		       SilcBool compute_hash,
		       SilcHash hash,
		       SilcPKCSSignCb sign_cb,
		       void *context);
SilcAsyncOperation
silc_pkcs1_verify_no_oid(const struct SilcPKCSAlgorithmStruct *pkcs,
			 void *public_key,
			 unsigned char *signature,
			 SilcUInt32 signature_len,
			 unsigned char *data,
			 SilcUInt32 data_len,
			 SilcHash hash,
			 SilcPKCSVerifyCb verify_cb,
			 void *context);

#endif /* SILCPKCS1_I_H */
