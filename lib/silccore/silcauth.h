/*

  siclauth.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCAUTH_H
#define SILCAUTH_H

/* Forward declaration of the Authentication Payload */
typedef struct SilcAuthPayloadStruct *SilcAuthPayload;

/* Forward declaration of the Key Agreement Payload */
typedef struct SilcKeyAgreementPayloadStruct *SilcKeyAgreementPayload;

/* Authentication method type */
typedef unsigned short SilcAuthMethod;

/* Authentication methods in SILC protocol */
#define SILC_AUTH_NONE        0
#define SILC_AUTH_PASSWORD    1
#define SILC_AUTH_PUBLIC_KEY  2

/* Authentication protocol status message (used by all authentication
   procols in the SILC). */
#define SILC_AUTH_OK          0
#define SILC_AUTH_FAILED      1

/* Prototypes */
SilcAuthPayload silc_auth_payload_parse(SilcBuffer buffer);
SilcBuffer silc_auth_payload_encode(SilcAuthMethod method,
				    unsigned char *random_data,
				    unsigned short random_len,
				    unsigned char *auth_data,
				    unsigned short auth_len);
void silc_auth_payload_free(SilcAuthPayload payload);
SilcBuffer silc_auth_public_key_auth_generate(SilcPKCS pkcs,
					      SilcHash hash,
					      void *id, SilcIdType type);
int silc_auth_public_key_auth_verify(SilcAuthPayload payload,
				     SilcPKCS pkcs, SilcHash hash,
				     void *id, SilcIdType type);
int silc_auth_public_key_auth_verify_data(SilcBuffer payload,
					  SilcPKCS pkcs, SilcHash hash,
					  void *id, SilcIdType type);
SilcKeyAgreementPayload silc_key_agreement_payload_parse(SilcBuffer buffer);
SilcBuffer silc_key_agreement_payload_encode(char *hostname,
					     unsigned int port);
void silc_key_agreement_payload_free(SilcKeyAgreementPayload payload);
char *silc_key_agreement_get_hostname(SilcKeyAgreementPayload payload);
unsigned int silc_key_agreement_get_port(SilcKeyAgreementPayload payload);

#endif
