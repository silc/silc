/*

  silcske_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSKE_I_H
#define SILCSKE_I_H

/* Length of cookie in Start Payload */
#define SILC_SKE_COOKIE_LEN 16

/* SKE context */
struct SilcSKEStruct {
  SilcPacketStream stream;
  SilcRng rng;
  SilcSKR repository;
  SilcSKECallbacks callbacks;
  void *user_data;
  SilcSKEStatus status;

  /* Negotiated Security properties.  May be NULL in case of error. */
  SilcSKESecurityProperties prop;

  /* Key Exchange payloads filled during key negotiation with
     remote data. Responder may save local data here as well. */
  SilcSKEStartPayload start_payload;
  SilcSKEKEPayload ke1_payload;
  SilcSKEKEPayload ke2_payload;

  /* Temporary copy of the KE Start Payload used in the
     HASH computation. */
  SilcBuffer start_payload_copy;

  /* Random number x, 1 < x < q. This is the secret exponent
     used in Diffie Hellman computations. */
  SilcMPInt *x;

  /* The secret shared key */
  SilcMPInt *KEY;

  /* The hash value HASH of the key exchange */
  unsigned char *hash;
  SilcUInt32 hash_len;

  char *version;		      /* Local version */
  char *remote_version;		      /* Remote version */

  SilcPublicKey public_key;
  SilcPrivateKey private_key;
  SilcSKEPKType pk_type;
  SilcPacket packet;
  SilcSKESecurityPropertyFlag flags;
  SilcSKEKeyMaterial keymat;
  SilcSKERekeyMaterial rekey;
  SilcSchedule schedule;
  SilcFSMStruct fsm;
  SilcAsyncOperationStruct op;
  SilcUInt16 session_port;

  unsigned int aborted    : 1;
  unsigned int responder  : 1;
};

#endif /* SILCSKE_I_H */
