/*

  silcpubkey.c

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

#include "silc.h"

/* Encodes Public Key Payload for transmitting public keys and certificates. */

SilcBuffer silc_public_key_payload_encode(SilcPublicKey public_key)
{
  SilcBuffer buffer;
  unsigned char *pk;
  SilcUInt32 pk_len;
  SilcPKCSType type;

  if (!public_key)
    return NULL;

  type = silc_pkcs_get_type(public_key);
  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk)
    return NULL;

  buffer = silc_buffer_alloc_size(4 + pk_len);
  if (!buffer) {
    silc_free(pk);
    return NULL;
  }

  if (silc_buffer_format(buffer,
			 SILC_STR_UI_SHORT(pk_len),
			 SILC_STR_UI_SHORT(type),
			 SILC_STR_UI_XNSTRING(pk, pk_len),
			 SILC_STR_END) < 0) {
    silc_buffer_free(buffer);
    silc_free(pk);
    return NULL;
  }

  silc_free(pk);
  return buffer;
}

/* Decodes public key payload and returns allocated public key */

SilcBool silc_public_key_payload_decode(unsigned char *data,
					SilcUInt32 data_len,
					SilcPublicKey *public_key)
{
  SilcBufferStruct buf;
  SilcUInt16 pk_len, pk_type;
  unsigned char *pk;
  int ret;

  if (!public_key)
    return FALSE;

  silc_buffer_set(&buf, data, data_len);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_SHORT(&pk_len),
			     SILC_STR_UI_SHORT(&pk_type),
			     SILC_STR_END);
  if (ret < 0 || pk_len > data_len - 4)
    return FALSE;

  if (pk_type < SILC_PKCS_SILC || pk_type > SILC_PKCS_SPKI)
    return FALSE;

  silc_buffer_pull(&buf, 4);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_XNSTRING(&pk, pk_len),
			     SILC_STR_END);
  if (ret < 0)
    return FALSE;

  return silc_pkcs_public_key_alloc((SilcPKCSType)pk_type,
				    pk, pk_len, public_key);
}
