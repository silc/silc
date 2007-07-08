/*

  silcpubkey.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC Public Key Payload
 *
 * DESCRIPTION
 *
 * Implementation of the Public Key Payload.  Public Key Payload is used to
 * deliver different types of public keys and certificates in the SILC
 * protocol.
 *
 ***/

#ifndef SILCPUBKEY_H
#define SILCPUBKEY_H

/****f* silccore/SilcPubKeyAPI/silc_public_key_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_public_key_payload_encode(SilcStack stack,
 *                                              SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Encodes the Public Key Payload from the public key indicated by
 *    `public_key'.  Returns the allocated and encoded payload buffer,
 *    or NULL on error.
 *
 *    If `stack' is non-NULL the returned buffer is allocated from `stack'.
 *    This call will consume the `stack' so caller should push the stack
 *    before calling and then later pop it.
 *
 ***/
SilcBuffer silc_public_key_payload_encode(SilcStack stack,
					  SilcPublicKey public_key);

/****f* silccore/SilcPubKeyAPI/silc_public_key_payload_decode
 *
 * SYNOPSIS
 *
 *    SilcBool silc_public_key_payload_decode(unsigned char *data,
 *                                            SilcUInt32 data_len,
 *                                            SilcPublicKey *public_key);
 *
 * DESCRIPTION
 *
 *    Decodes Public Key Payload from `data' of `data_len' bytes in length
 *    data buffer into `public_key' pointer.  Returns FALSE if the payload
 *    cannot be decoded.
 *
 ***/
SilcBool silc_public_key_payload_decode(unsigned char *data,
					SilcUInt32 data_len,
					SilcPublicKey *public_key);

#endif /* SILCPUBKEY_H */
