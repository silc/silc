/*

  silcauth.c

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
/* $Id$ */

#include "silcincludes.h"
#include "silcauth.h"

/******************************************************************************

                           Authentication Payload

******************************************************************************/

/* Authentication Payload structure */
struct SilcAuthPayloadStruct {
  unsigned short len;
  unsigned short auth_method;
  unsigned short random_len;
  unsigned char *random_data;
  unsigned short auth_len;
  unsigned char *auth_data;
};

/* Parses and returns Authentication Payload */

SilcAuthPayload silc_auth_payload_parse(SilcBuffer buffer)
{
  SilcAuthPayload new;
  int ret;

  SILC_LOG_DEBUG(("Parsing Authentication Payload"));

  new = silc_calloc(1, sizeof(*new));

  /* Parse the payload */
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_SHORT(&new->len),
			     SILC_STR_UI_SHORT(&new->auth_method),
			     SILC_STR_UI16_NSTRING_ALLOC(&new->random_data,
							 &new->random_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&new->auth_data,
							 &new->auth_len),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(new);
    return NULL;
  }

  if (new->len != buffer->len) {
    silc_auth_payload_free(new);
    return NULL;
  }

  /* If password authentication, random data must not be set */
  if (new->auth_method == SILC_AUTH_PASSWORD && new->random_len) {
    silc_auth_payload_free(new);
    return NULL;
  }

  return new;
}

/* Encodes authentication payload into buffer and returns it */

SilcBuffer silc_auth_payload_encode(SilcAuthMethod method,
				    unsigned char *random_data,
				    unsigned short random_len,
				    unsigned char *auth_data,
				    unsigned short auth_len)
{
  SilcBuffer buffer;
  unsigned int len;

  SILC_LOG_DEBUG(("Encoding Authentication Payload"));

  len = 4 + 4 + random_len + auth_len;
  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_SHORT(method),
		     SILC_STR_UI_SHORT(random_len),
		     SILC_STR_UI_XNSTRING(random_data, random_len),
		     SILC_STR_UI_SHORT(auth_len),
		     SILC_STR_UI_XNSTRING(auth_data, auth_len),
		     SILC_STR_END);

  return buffer;
}

/* Frees authentication payload. */

void silc_auth_payload_free(SilcAuthPayload payload)
{
  if (payload) {
    if (payload->random_data) {
      memset(payload->random_data, 0, payload->random_len);
      silc_free(payload->random_data);
    }
    if (payload->auth_data) {
      memset(payload->auth_data, 0, payload->auth_len);
      silc_free(payload->auth_data);
    }
    silc_free(payload);
  }
}

/******************************************************************************

                           Authentication Routines

******************************************************************************/

/* Encodes the authentication data for hashing and signing as the protocol
   dictates. */

static unsigned char *
silc_auth_public_key_encode_data(SilcPKCS pkcs, unsigned char *random,
				 unsigned int random_len, void *id,
				 SilcIdType type, unsigned int *ret_len)
{
  SilcBuffer buf;
  unsigned char *pk, *id_data, *ret;
  unsigned int pk_len, id_len;

  pk = silc_pkcs_get_public_key(pkcs, &pk_len);
  if (!pk)
    return NULL;

  id_data = silc_id_id2str(id, type);
  if (!id_data) {
    silc_free(pk);
    return NULL;
  }
  id_len = silc_id_get_len(type);

  buf = silc_buffer_alloc(random_len + pk_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
  silc_buffer_format(buf,
		     SILC_STR_UI_XNSTRING(random, random_len),
		     SILC_STR_UI_XNSTRING(id_data, id_len),
		     SILC_STR_UI_XNSTRING(pk, pk_len),
		     SILC_STR_END);
  
  ret = silc_calloc(buf->len, sizeof(*ret));
  memcpy(ret, buf->data, buf->len);

  if (ret_len)
    *ret_len = buf->len;

  silc_buffer_free(buf);
  silc_free(id_data);
  silc_free(pk);

  return ret;
}

/* Generates Authentication Payload with authentication data. This is used
   to do public key based authentication. This generates the random data
   and the actual authentication data. Returns NULL on error. */

SilcBuffer silc_auth_public_key_auth_generate(SilcPKCS pkcs,
					      SilcHash hash,
					      void *id, SilcIdType type)
{
  unsigned char *random;
  unsigned char auth_data[32];
  unsigned int auth_len;
  unsigned char *tmp;
  unsigned int tmp_len;
  SilcBuffer buf;

  SILC_LOG_DEBUG(("Generating Authentication Payload with data"));

  /* Get 256 bytes of random data */
  random = silc_rng_global_get_rn_data(256);
  if (!random)
    return NULL;
  
  /* Encode the auth data */
  tmp = silc_auth_public_key_encode_data(pkcs, random, 256, id, type, 
					 &tmp_len);
  if (!tmp)
    return NULL;

  /* Compute the hash and the signature. */
  if (!silc_pkcs_sign_with_hash(pkcs, hash, tmp, tmp_len, auth_data,
				&auth_len)) {
    memset(random, 0, 256);
    memset(tmp, 0, tmp_len);
    silc_free(tmp);
    silc_free(random);
    return NULL;
  }

  /* Encode Authentication Payload */
  buf = silc_auth_payload_encode(SILC_AUTH_PUBLIC_KEY, random, 256,
				 auth_data, auth_len);

  memset(tmp, 0, tmp_len);
  memset(auth_data, 0, sizeof(auth_data));
  memset(random, 0, 256);
  silc_free(tmp);
  silc_free(random);

  return buf;
}

/* Verifies the authentication data. Returns TRUE if authentication was
   successfull. */

int silc_auth_public_key_auth_verify(SilcAuthPayload payload,
				     SilcPKCS pkcs, SilcHash hash,
				     void *id, SilcIdType type)
{
  unsigned char *tmp;
  unsigned int tmp_len;

  SILC_LOG_DEBUG(("Verifying authentication data"));

  /* Encode auth data */
  tmp = silc_auth_public_key_encode_data(pkcs, payload->random_data, 
					 payload->random_len, 
					 id, type, &tmp_len);
  if (!tmp) {
    SILC_LOG_DEBUG(("Authentication failed"));
    return FALSE;
  }

  /* Verify the authentication data */
  if (!silc_pkcs_verify_with_hash(pkcs, hash, payload->auth_data,
				  payload->auth_len, tmp, tmp_len)) {

    memset(tmp, 0, tmp_len);
    silc_free(tmp);
    SILC_LOG_DEBUG(("Authentication failed"));
    return FALSE;
  }

  memset(tmp, 0, tmp_len);
  silc_free(tmp);

  SILC_LOG_DEBUG(("Authentication successfull"));

  return TRUE;
}

/* Same as above but the payload is not parsed yet. This will parse it. */

int silc_auth_public_key_auth_verify_data(SilcBuffer payload,
					  SilcPKCS pkcs, SilcHash hash,
					  void *id, SilcIdType type)
{
  SilcAuthPayload auth_payload;
  int ret;

  auth_payload = silc_auth_payload_parse(payload);
  if (!auth_payload) {
    SILC_LOG_DEBUG(("Authentication failed"));
    return FALSE;
  }

  ret = silc_auth_public_key_auth_verify(auth_payload, pkcs, hash, 
					 id, type);

  silc_auth_payload_free(auth_payload);

  return ret;
}
