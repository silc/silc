/*

  silcske_status.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSKE_STATUS_H
#define SILCSKE_STATUS_H

/* Status flags returned by all SKE routines */
typedef enum {
  /* These are defined by the protocol */
  SILC_SKE_STATUS_OK                     = 0,
  SILC_SKE_STATUS_ERROR                  = 1,
  SILC_SKE_STATUS_BAD_PAYLOAD            = 2,
  SILC_SKE_STATUS_UNKNOWN_GROUP          = 3,
  SILC_SKE_STATUS_UNKNOWN_CIPHER         = 4,
  SILC_SKE_STATUS_UNKNOWN_PKCS           = 5,
  SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION  = 6,
  SILC_SKE_STATUS_UNKNOWN_HMAC           = 7,
  SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY = 8,
  SILC_SKE_STATUS_INCORRECT_SIGNATURE    = 9,
  SILC_SKE_STATUS_BAD_VERSION            = 10,

  SILC_SKE_STATUS_PENDING,
  SILC_SKE_STATUS_PUBLIC_KEY_NOT_PROVIDED,
  SILC_SKE_STATUS_KEY_EXCHANGE_NOT_ACTIVE,
  SILC_SKE_STATUS_BAD_RESERVED_FIELD,
  SILC_SKE_STATUS_BAD_PAYLOAD_LENGTH,
  SILC_SKE_STATUS_INCORRECT_HASH,
  SILC_SKE_STATUS_INCORRECT_PUBLIC_KEY,
} SilcSKEStatus;

#endif
