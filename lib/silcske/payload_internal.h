/*

  payload_internal.h

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

#ifndef PAYLOAD_INTERNAL_H
#define PAYLOAD_INTERNAL_H

/* SILC Key Exchange Start Payload */
typedef struct {
  unsigned char flags;
  unsigned int len;

  unsigned char *cookie;
  unsigned short cookie_len;

  unsigned char *version;
  unsigned short version_len;

  unsigned short ke_grp_len;
  unsigned char *ke_grp_list;

  unsigned short pkcs_alg_len;
  unsigned char *pkcs_alg_list;

  unsigned short enc_alg_len;
  unsigned char *enc_alg_list;
  
  unsigned short hash_alg_len;
  unsigned char *hash_alg_list;

  unsigned short comp_alg_len;
  unsigned char *comp_alg_list;
} SilcSKEStartPayload;

/* SILC Key Exchange 1 Payload */
typedef struct {
  unsigned short pk_len;
  unsigned char *pk_data;
  unsigned short pk_type;

  SilcInt e;
} SilcSKEOnePayload;

/* SILC Key Exchange 2 Payload */
typedef struct {
  unsigned short pk_len;
  unsigned char *pk_data;
  unsigned short pk_type;

  SilcInt f;

  unsigned short sign_len;
  unsigned char *sign_data;
} SilcSKETwoPayload;

#endif
