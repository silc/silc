/*

  payload_internal.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef PAYLOAD_INTERNAL_H
#define PAYLOAD_INTERNAL_H

/* SILC Key Exchange Start Payload */
typedef struct {
  unsigned char flags;
  uint16 len;

  unsigned char *cookie;
  uint16 cookie_len;

  unsigned char *version;
  uint16 version_len;

  uint16 ke_grp_len;
  unsigned char *ke_grp_list;

  uint16 pkcs_alg_len;
  unsigned char *pkcs_alg_list;

  uint16 enc_alg_len;
  unsigned char *enc_alg_list;
  
  uint16 hash_alg_len;
  unsigned char *hash_alg_list;

  uint16 hmac_alg_len;
  unsigned char *hmac_alg_list;

  uint16 comp_alg_len;
  unsigned char *comp_alg_list;
} SilcSKEStartPayload;

/* SILC Key Exchange Payload */
typedef struct {
  uint16 pk_len;
  unsigned char *pk_data;
  uint16 pk_type;

  SilcMPInt x;

  uint16 sign_len;
  unsigned char *sign_data;
} SilcSKEKEPayload;

#endif
