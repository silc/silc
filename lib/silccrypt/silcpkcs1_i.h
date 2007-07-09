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

SILC_PKCS_ALG_GENERATE_KEY(silc_pkcs1_generate_key);
SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_pkcs1_import_public_key);
SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_pkcs1_export_public_key);
SILC_PKCS_ALG_PUBLIC_KEY_BITLEN(silc_pkcs1_public_key_bitlen);
SILC_PKCS_ALG_PUBLIC_KEY_COPY(silc_pkcs1_public_key_copy);
SILC_PKCS_ALG_PUBLIC_KEY_COMPARE(silc_pkcs1_public_key_compare);
SILC_PKCS_ALG_PUBLIC_KEY_FREE(silc_pkcs1_public_key_free);
SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_pkcs1_import_private_key);
SILC_PKCS_ALG_EXPORT_PRIVATE_KEY(silc_pkcs1_export_private_key);
SILC_PKCS_ALG_PRIVATE_KEY_BITLEN(silc_pkcs1_private_key_bitlen);
SILC_PKCS_ALG_PRIVATE_KEY_FREE(silc_pkcs1_private_key_free);
SILC_PKCS_ALG_ENCRYPT(silc_pkcs1_encrypt);
SILC_PKCS_ALG_DECRYPT(silc_pkcs1_decrypt);
SILC_PKCS_ALG_SIGN(silc_pkcs1_sign);
SILC_PKCS_ALG_VERIFY(silc_pkcs1_verify);
SILC_PKCS_ALG_SIGN(silc_pkcs1_sign_no_oid);
SILC_PKCS_ALG_VERIFY(silc_pkcs1_verify_no_oid);

#endif /* SILCPKCS1_I_H */
