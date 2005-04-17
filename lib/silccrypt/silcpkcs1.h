/*

  silcpkcs1.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccrypt/SILC PKCS1 Interface
 *
 * DESCRIPTION
 *
 * This interface implements the PKCS#1 standard block encoding and decoding
 * routines.  It is used as part of RSA implementation to perform PKCS#1
 * RSA operations.  The routines encode and decode the data for RSA operations
 * such as digital signatures and their verification, and encryption and
 * decryption.
 *
 ***/

#ifndef SILCPKCS1_H
#define SILCPKCS1_H

/****d* silccrypt/SilcPKCS1API/SilcPkcs1BlockType
 *
 * NAME
 *
 *    typedef enum { ... } SilcPkcs1BlockType
 *
 * DESCRIPTION
 *
 *    Defines the PKCS#1 block types that define how the blcok is encoded
 *    for different RSA operations.
 *
 * SOURCE
 */
typedef enum {
  SILC_PKCS1_BT_PRV0 = 0x00,	/* Private key BT 0 */
  SILC_PKCS1_BT_PRV1 = 0x01,	/* Private key BT 1 (use this always) */
  SILC_PKCS1_BT_PUB  = 0x02,	/* Public key BT */
} SilcPkcs1BlockType;
/***/

/****f* silccrypt/SilcPKCS1API/silc_pkcs1_encode
 *
 * SYNOPSIS
 *
 *    bool silc_pkcs1_encode(SilcPkcs1BlockType bt,
 *                           const unsigned char *data,
 *                           SilcUInt32 data_len,
 *                           unsigned char *dest_data,
 *                           SilcUInt32 dest_data_size,
 *                           SilcRng rng);
 *
 * DESCRIPTION
 *
 *    Encodes PKCS#1 data block from the `data' according to the block type
 *    indicated by `bt'.  When encoding signatures the `bt' must be
 *    SILC_PKCS1_BT_PRV1 and when encoding encryption blocks the `bt' must
 *    be SILC_PKCS1_BT_PUB.  The encoded data is copied into the `dest_data'
 *    buffer which is size of `dest_data_size'.  If the `dest_data' is not
 *    able to hold the encoded block this returns FALSE.  Usually the
 *    `dest_data_size' is set to the RSA key length value as it is the
 *    length of one block.  The `rng' should be set when `bt' is set to
 *    SILC_PKCS1_BT_PUB.  If `rng' is NULL global RNG is used.  This
 *    function returns TRUE on success.
 *
 ***/
bool silc_pkcs1_encode(SilcPkcs1BlockType bt,
		       const unsigned char *data,
		       SilcUInt32 data_len,
		       unsigned char *dest_data,
		       SilcUInt32 dest_data_size,
		       SilcRng rng);

/****f* silccrypt/SilcPKCS1API/silc_pkcs1_decode
 *
 * SYNOPSIS
 *
 *    bool silc_pkcs1_decode(SilcPkcs1BlockType bt,
 *                           const unsigned char *data,
 *                           SilcUInt32 data_len,
 *                           unsigned char *dest_data,
 *                           SilcUInt32 dest_data_size,
 *                           SilcUInt32 *dest_len);
 *
 * DESCRIPTION
 *
 *    Decodes the PKCS#1 encoded block according to the block type `bt'.
 *    When verifying signatures the `bt' must be SILC_PKCS1_BT_PRV1 and
 *    when decrypting it must be SILC_PKCS1_BT_PUB.  This copies the
 *    decoded data into `dest_data' which is size of `dest_data_size'.  If
 *    the deocded block does not fit to `dest_data' this returns FALSE.
 *    Returns the decoded length into `dest_len'.
 *
 ***/
bool silc_pkcs1_decode(SilcPkcs1BlockType bt,
		       const unsigned char *data,
		       SilcUInt32 data_len,
		       unsigned char *dest_data,
		       SilcUInt32 dest_data_size,
		       SilcUInt32 *dest_len);

#endif /* SILCPKCS1_H */
