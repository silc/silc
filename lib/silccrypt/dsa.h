/*

  dsa.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef DSA_H
#define DSA_H

/* DSA Public key */
typedef struct {
  SilcMPInt g;			/* generator */
  SilcMPInt p;			/* prime */
  SilcMPInt q;			/* prime */
  SilcMPInt y;			/* public key */
  SilcUInt16 bits;		/* bits in key */
  SilcUInt16 group_order;	/* group order (size) */
} DsaPublicKey;

/* DSA Private key */
typedef struct {
  SilcMPInt g;			/* generator */
  SilcMPInt p;			/* prime */
  SilcMPInt q;			/* prime */
  SilcMPInt y;			/* public key */
  SilcMPInt x;			/* private key */
  SilcUInt16 bits;		/* bits in key */
  SilcUInt16 group_order;	/* group order (size) */
} DsaPrivateKey;

SILC_PKCS_ALG_GENERATE_KEY(silc_dsa_generate_key);
SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_dsa_import_public_key);
SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_dsa_export_public_key);
SILC_PKCS_ALG_PUBLIC_KEY_BITLEN(silc_dsa_public_key_bitlen);
SILC_PKCS_ALG_PUBLIC_KEY_COPY(silc_dsa_public_key_copy);
SILC_PKCS_ALG_PUBLIC_KEY_COMPARE(silc_dsa_public_key_compare);
SILC_PKCS_ALG_PUBLIC_KEY_FREE(silc_dsa_public_key_free);
SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_dsa_import_private_key);
SILC_PKCS_ALG_EXPORT_PRIVATE_KEY(silc_dsa_export_private_key);
SILC_PKCS_ALG_PRIVATE_KEY_BITLEN(silc_dsa_private_key_bitlen);
SILC_PKCS_ALG_PRIVATE_KEY_FREE(silc_dsa_private_key_free);
SILC_PKCS_ALG_ENCRYPT(silc_dsa_encrypt);
SILC_PKCS_ALG_DECRYPT(silc_dsa_decrypt);
SILC_PKCS_ALG_SIGN(silc_dsa_sign);
SILC_PKCS_ALG_VERIFY(silc_dsa_verify);

#endif /* DSA_H */
