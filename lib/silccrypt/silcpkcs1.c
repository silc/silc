/*

  silcpkcs1.c

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

#include "silcincludes.h"
#include "silcpkcs1.h"

/* Minimum padding in block */
#define SILC_PKCS1_MIN_PADDING 8

/* Encodes PKCS#1 data block from the `data' according to the block type
   indicated by `bt'.  When encoding signatures the `bt' must be
   SILC_PKCS1_BT_PRV1 and when encoding encryption blocks the `bt' must
   be SILC_PKCS1_BT_PUB.  The encoded data is copied into the `dest_data'
   buffer which is size of `dest_data_size'.  If the `dest_data' is not
   able to hold the encoded block this returns FALSE.  The `rng' must be
   set when `bt' is SILC_PKCS1_BT_PUB.  This function returns TRUE on
   success. */

bool silc_pkcs1_encode(SilcPkcs1BlockType bt,
		       const unsigned char *data,
		       SilcUInt32 data_len,
		       unsigned char *dest_data,
		       SilcUInt32 dest_data_size,
		       SilcRng rng)
{
  SilcInt32 padlen;
  int i;

  SILC_LOG_DEBUG(("PKCS#1 encoding, bt %d", bt));

  if (!data || !dest_data ||
      dest_data_size < 3 || dest_data_size < data_len) {
    SILC_LOG_DEBUG(("Data to be encoded is too long"));
    return FALSE;
  }

  /* Start of block */
  dest_data[0] = 0x00;
  dest_data[1] = (unsigned char)bt;

  padlen = (SilcInt32)dest_data_size - (SilcInt32)data_len - 3;
  if (padlen < SILC_PKCS1_MIN_PADDING) {
    SILC_LOG_DEBUG(("Data to be encoded is too long"));
    return FALSE;
  }

  /* Encode according to block type */
  switch (bt) {
  case SILC_PKCS1_BT_PRV0:
  case SILC_PKCS1_BT_PRV1:
    /* Signature */
    memset(dest_data + 2, bt == SILC_PKCS1_BT_PRV1 ? 0xff : 0x00, padlen);
    break;

  case SILC_PKCS1_BT_PUB:
    /* Encryption */

    /* It is guaranteed this routine does not return zero byte. */
    if (rng)
      for (i = 2; i < padlen; i++)
	dest_data[i] = silc_rng_get_byte_fast(rng);
    else
      for (i = 2; i < padlen; i++)
	dest_data[i] = silc_rng_global_get_byte_fast();
    break;
  }

  /* Copy the data */
  dest_data[padlen + 2] = 0x00;
  memcpy(dest_data + padlen + 3, data, data_len);

  return TRUE;
}

/* Decodes the PKCS#1 encoded block according to the block type `bt'.
   When verifying signatures the `bt' must be SILC_PKCS1_BT_PRV1 and
   when decrypting it must be SILC_PKCS1_BT_PUB.  This copies the
   decoded data into `dest_data' which is size of `dest_data_size'.  If
   the deocded block does not fit to `dest_data' this returns FALSE.
   Returns TRUE on success. */

bool silc_pkcs1_decode(SilcPkcs1BlockType bt,
		       const unsigned char *data,
		       SilcUInt32 data_len,
		       unsigned char *dest_data,
		       SilcUInt32 dest_data_size,
		       SilcUInt32 *dest_len)
{
  int i = 0;

  SILC_LOG_DEBUG(("PKCS#1 decoding, bt %d", bt));

  /* Sanity checks */
  if (!data || !dest_data || dest_data_size < 3 ||
      data[0] != 0x00 || data[1] != (unsigned char)bt) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }

  /* Decode according to block type */
  switch (bt) {
  case SILC_PKCS1_BT_PRV0:
    /* Do nothing */
    break;

  case SILC_PKCS1_BT_PRV1:
    /* Verification */
    for (i = 2; i < data_len; i++)
      if (data[i] != 0xff)
	break;
    break;

  case SILC_PKCS1_BT_PUB:
    /* Decryption */
    for (i = 2; i < data_len; i++)
      if (data[i] == 0x00)
	break;
    break;
  }

  /* Sanity checks */
  if (data[i++] != 0x00) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }
  if (i - 1 < SILC_PKCS1_MIN_PADDING) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }
  if (dest_data_size < data_len - i) {
    SILC_LOG_DEBUG(("Destination buffer too small"));
    return FALSE;
  }

  /* Copy the data */
  memcpy(dest_data, data + i, data_len - i);

  /* Return data length */
  if (dest_len)
    *dest_len = data_len - i;

  return TRUE;
}
