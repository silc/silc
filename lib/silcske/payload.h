/*

  payload.h

  Author: Pekka Riikonen <priikone@silcnet.org>

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

#ifndef PAYLOAD_H
#define PAYLOAD_H

#include "silcske_status.h"

/* Forward declarations */
typedef struct SilcSKEStartPayloadStruct SilcSKEStartPayload;
typedef struct SilcSKEKEPayloadStruct SilcSKEKEPayload;

/* SILC Key Exchange Start Payload */
struct SilcSKEStartPayloadStruct {
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
};

/* SILC Key Exchange Payload */
struct SilcSKEKEPayloadStruct {
  uint16 pk_len;
  unsigned char *pk_data;
  uint16 pk_type;

  SilcMPInt x;

  uint16 sign_len;
  unsigned char *sign_data;
};

/* Prototypes */
SilcSKEStatus silc_ske_payload_start_encode(SilcSKE ske,
					    SilcSKEStartPayload *payload,
					    SilcBuffer *return_buffer);
SilcSKEStatus 
silc_ske_payload_start_decode(SilcSKE ske,
			      SilcBuffer buffer,
			      SilcSKEStartPayload **return_payload);
void silc_ske_payload_start_free(SilcSKEStartPayload *payload);
SilcSKEStatus silc_ske_payload_ke_encode(SilcSKE ske,
					 SilcSKEKEPayload *payload,
					 SilcBuffer *return_buffer);
SilcSKEStatus silc_ske_payload_ke_decode(SilcSKE ske,
					 SilcBuffer buffer,
					 SilcSKEKEPayload **return_payload);
void silc_ske_payload_ke_free(SilcSKEKEPayload *payload);

#endif
