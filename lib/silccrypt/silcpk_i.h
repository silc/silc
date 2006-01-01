/*

  silcpk_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCPK_I_H
#define SILCPK_I_H

/* Public and private key file headers */
#define SILC_PKCS_PUBLIC_KEYFILE_BEGIN "-----BEGIN SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PUBLIC_KEYFILE_END "\n-----END SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_BEGIN "-----BEGIN SILC PRIVATE KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_END "\n-----END SILC PRIVATE KEY-----\n"

const SilcPKCSAlgorithm *silc_pkcs_silc_get_algorithm(void *public_key);
SilcBool silc_pkcs_silc_import_public_key_file(unsigned char *filedata,
					       SilcUInt32 filedata_len,
					       SilcPKCSFileEncoding encoding,
					       void **ret_public_key);
SilcBool silc_pkcs_silc_import_public_key(unsigned char *key,
					  SilcUInt32 key_len,
					  void **ret_public_key);
unsigned char *
silc_pkcs_silc_export_public_key_file(void *public_key,
				      SilcPKCSFileEncoding encoding,
				      SilcUInt32 *ret_len);
unsigned char *silc_pkcs_silc_export_public_key(void *public_key,
						SilcUInt32 *ret_len);
SilcUInt32 silc_pkcs_silc_public_key_bitlen(void *public_key);
void *silc_pkcs_silc_public_key_copy(void *public_key);
SilcBool silc_pkcs_silc_public_key_compare(void *key1, void *key2);
void silc_pkcs_silc_public_key_free(void *public_key);
SilcBool silc_pkcs_silc_import_private_key_file(unsigned char *filedata,
						SilcUInt32 filedata_len,
						const char *passphrase,
						SilcUInt32 passphrase_len,
						SilcPKCSFileEncoding encoding,
						void **ret_private_key);
SilcBool silc_pkcs_silc_import_private_key(unsigned char *key,
					   SilcUInt32 key_len,
					   void **ret_private_key);
unsigned char *
silc_pkcs_silc_export_private_key_file(void *private_key,
				       const char *passphrase,
				       SilcUInt32 passphrase_len,
				       SilcPKCSFileEncoding encoding,
				       SilcRng rng,
				       SilcUInt32 *ret_len);
unsigned char *silc_pkcs_silc_export_private_key(void *private_key,
						 SilcUInt32 *ret_len);
SilcUInt32 silc_pkcs_silc_private_key_bitlen(void *private_key);
void silc_pkcs_silc_private_key_free(void *private_key);
SilcBool silc_pkcs_silc_encrypt(void *public_key,
				unsigned char *src,
				SilcUInt32 src_len,
				unsigned char *dst,
				SilcUInt32 dst_size,
				SilcUInt32 *ret_dst_len);
SilcBool silc_pkcs_silc_decrypt(void *private_key,
				unsigned char *src,
				SilcUInt32 src_len,
				unsigned char *dst,
				SilcUInt32 dst_size,
				SilcUInt32 *ret_dst_len);
SilcBool silc_pkcs_silc_sign(void *private_key,
			     unsigned char *src,
			     SilcUInt32 src_len,
			     unsigned char *signature,
			     SilcUInt32 signature_size,
			     SilcUInt32 *ret_signature_len,
			     SilcHash hash);
SilcBool silc_pkcs_silc_verify(void *public_key,
			       unsigned char *signature,
			       SilcUInt32 signature_len,
			       unsigned char *data,
			       SilcUInt32 data_len,
			       SilcHash hash);

#endif /* SILCPK_I_H */
