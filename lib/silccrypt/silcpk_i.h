/*

  silcpk_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005, 2007 Pekka Riikonen

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

SILC_PKCS_GET_ALGORITHM(silc_pkcs_silc_get_algorithm);
SILC_PKCS_IMPORT_PUBLIC_KEY_FILE(silc_pkcs_silc_import_public_key_file);
SILC_PKCS_IMPORT_PUBLIC_KEY(silc_pkcs_silc_import_public_key);
SILC_PKCS_EXPORT_PUBLIC_KEY_FILE(silc_pkcs_silc_export_public_key_file);
SILC_PKCS_EXPORT_PUBLIC_KEY(silc_pkcs_silc_export_public_key);
SILC_PKCS_PUBLIC_KEY_BITLEN(silc_pkcs_silc_public_key_bitlen);
SILC_PKCS_PUBLIC_KEY_COPY(silc_pkcs_silc_public_key_copy);
SILC_PKCS_PUBLIC_KEY_COMPARE(silc_pkcs_silc_public_key_compare);
SILC_PKCS_PUBLIC_KEY_FREE(silc_pkcs_silc_public_key_free);
SILC_PKCS_IMPORT_PRIVATE_KEY_FILE(silc_pkcs_silc_import_private_key_file);
SILC_PKCS_IMPORT_PRIVATE_KEY(silc_pkcs_silc_import_private_key);
SILC_PKCS_EXPORT_PRIVATE_KEY_FILE(silc_pkcs_silc_export_private_key_file);
SILC_PKCS_EXPORT_PRIVATE_KEY(silc_pkcs_silc_export_private_key);
SILC_PKCS_PRIVATE_KEY_BITLEN(silc_pkcs_silc_private_key_bitlen);
SILC_PKCS_PRIVATE_KEY_FREE(silc_pkcs_silc_private_key_free);
SILC_PKCS_ENCRYPT(silc_pkcs_silc_encrypt);
SILC_PKCS_DECRYPT(silc_pkcs_silc_decrypt);
SILC_PKCS_SIGN(silc_pkcs_silc_sign);
SILC_PKCS_VERIFY(silc_pkcs_silc_verify);

#endif /* SILCPK_I_H */
