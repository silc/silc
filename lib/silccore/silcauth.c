/*

  silcauth.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcauth.h"
#include "silcchannel_i.h"
#include "silcprivate_i.h"

/******************************************************************************

                           Authentication Payload

******************************************************************************/

/* Authentication Payload structure */
struct SilcAuthPayloadStruct {
  SilcUInt16 len;
  SilcUInt16 auth_method;
  SilcUInt16 random_len;
  unsigned char *random_data;
  SilcUInt16 auth_len;
  unsigned char *auth_data;
};

/* Parses and returns Authentication Payload */

SilcAuthPayload silc_auth_payload_parse(const unsigned char *data,
					SilcUInt32 data_len)
{
  SilcBufferStruct buffer;
  SilcAuthPayload newp;
  int ret;

  SILC_LOG_DEBUG(("Parsing Authentication Payload"));

  silc_buffer_set(&buffer, (unsigned char *)data, data_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the payload */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&newp->len),
			     SILC_STR_UI_SHORT(&newp->auth_method),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->random_data,
							 &newp->random_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->auth_data,
							 &newp->auth_len),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(newp);
    return NULL;
  }

  if (newp->len != buffer.len || 
      newp->random_len + newp->auth_len > buffer.len - 8) {
    silc_auth_payload_free(newp);
    return NULL;
  }

  /* Authentication data must be provided */
  if (newp->auth_len < 1)  {
    silc_auth_payload_free(newp);
    return NULL;
  }

  /* If password authentication, random data must not be set */
  if (newp->auth_method == SILC_AUTH_PASSWORD && newp->random_len) {
    silc_auth_payload_free(newp);
    return NULL;
  }

  /* If public key authentication, random data must be at least 128 bytes */
  if (newp->auth_method == SILC_AUTH_PUBLIC_KEY && newp->random_len < 128) {
    silc_auth_payload_free(newp);
    return NULL;
  }

  return newp;
}

/* Encodes authentication payload into buffer and returns it */

SilcBuffer silc_auth_payload_encode(SilcAuthMethod method,
				    const unsigned char *random_data,
				    SilcUInt16 random_len,
				    const unsigned char *auth_data,
				    SilcUInt16 auth_len)
{
  SilcBuffer buffer;
  SilcUInt32 len;
  unsigned char *autf8 = NULL;
  SilcUInt32 autf8_len;

  SILC_LOG_DEBUG(("Encoding Authentication Payload"));

  /* Passphrase MUST be UTF-8 encoded, encode if it is not */
  if (method == SILC_AUTH_PASSWORD && !silc_utf8_valid(auth_data, auth_len)) {
    autf8_len = silc_utf8_encoded_len(auth_data, auth_len, 0);
    if (!autf8_len)
      return NULL;
    autf8 = silc_calloc(autf8_len, sizeof(*autf8));
    auth_len = silc_utf8_encode(auth_data, auth_len, 0, autf8, autf8_len);
    auth_data = (const unsigned char *)autf8;
  }

  len = 2 + 2 + 2 + random_len + 2 + auth_len;
  buffer = silc_buffer_alloc_size(len);
  if (!buffer) {
    silc_free(autf8);
    return NULL;
  }

  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_SHORT(method),
		     SILC_STR_UI_SHORT(random_len),
		     SILC_STR_UI_XNSTRING(random_data, random_len),
		     SILC_STR_UI_SHORT(auth_len),
		     SILC_STR_UI_XNSTRING(auth_data, auth_len),
		     SILC_STR_END);

  silc_free(autf8);
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

/* Get authentication method */

SilcAuthMethod silc_auth_get_method(SilcAuthPayload payload)
{
  return payload->auth_method;
}

/* Get the authentication data. If this is passphrase it is UTF-8 encoded. */

unsigned char *silc_auth_get_data(SilcAuthPayload payload,
				  SilcUInt32 *auth_len)
{
  if (auth_len)
    *auth_len = payload->auth_len;

  return payload->auth_data;
}

/******************************************************************************

                           Authentication Routines

******************************************************************************/

/* Encodes the authentication data for hashing and signing as the protocol
   dictates. */

static unsigned char *
silc_auth_public_key_encode_data(SilcPublicKey public_key,
				 const unsigned char *randomdata,
				 SilcUInt32 random_len, const void *id,
				 SilcIdType type, SilcUInt32 *ret_len)
{
  SilcBuffer buf;
  unsigned char *pk, *id_data, *ret;
  SilcUInt32 pk_len, id_len;

  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk)
    return NULL;

  id_data = silc_id_id2str(id, type);
  if (!id_data) {
    silc_free(pk);
    return NULL;
  }
  id_len = silc_id_get_len(id, type);

  buf = silc_buffer_alloc_size(random_len + id_len + pk_len);
  if (!buf) {
    silc_free(pk);
    silc_free(id_data);
    return NULL;
  }
  silc_buffer_format(buf,
		     SILC_STR_UI_XNSTRING(randomdata, random_len),
		     SILC_STR_UI_XNSTRING(id_data, id_len),
		     SILC_STR_UI_XNSTRING(pk, pk_len),
		     SILC_STR_END);

  ret = silc_memdup(buf->data, buf->len);
  if (!ret)
    return NULL;

  if (ret_len)
    *ret_len = buf->len;

  silc_buffer_clear(buf);
  silc_buffer_free(buf);
  silc_free(id_data);
  silc_free(pk);

  return ret;
}

/* Generates Authentication Payload with authentication data. This is used
   to do public key based authentication. This generates the random data
   and the actual authentication data. Returns NULL on error. */

SilcBuffer silc_auth_public_key_auth_generate(SilcPublicKey public_key,
					      SilcPrivateKey private_key,
					      SilcRng rng, SilcHash hash,
					      const void *id, SilcIdType type)
{
  unsigned char *randomdata;
  unsigned char auth_data[2048];
  SilcUInt32 auth_len;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcBuffer buf;
  SilcPKCS pkcs;

  SILC_LOG_DEBUG(("Generating Authentication Payload with data"));

  /* Get 256 bytes of random data */
  if (rng)
    randomdata = silc_rng_get_rn_data(rng, 256);
  else
    randomdata = silc_rng_global_get_rn_data(256);
  if (!randomdata)
    return NULL;

  /* Encode the auth data */
  tmp = silc_auth_public_key_encode_data(public_key, randomdata, 256, id, 
					 type, &tmp_len);
  if (!tmp)
    return NULL;

  /* Allocate PKCS object */
  if (!silc_pkcs_alloc(private_key->name, &pkcs)) {
    memset(tmp, 0, tmp_len);
    silc_free(tmp);
    return NULL;
  }
  silc_pkcs_public_key_set(pkcs, public_key);
  silc_pkcs_private_key_set(pkcs, private_key);

  /* Compute the hash and the signature. */
  if (silc_pkcs_get_key_len(pkcs) / 8 > sizeof(auth_data) - 1 ||
      !silc_pkcs_sign_with_hash(pkcs, hash, tmp, tmp_len, auth_data,
				&auth_len)) {
    memset(randomdata, 0, 256);
    memset(tmp, 0, tmp_len);
    silc_free(tmp);
    silc_free(randomdata);
    silc_pkcs_free(pkcs);
    return NULL;
  }

  /* Encode Authentication Payload */
  buf = silc_auth_payload_encode(SILC_AUTH_PUBLIC_KEY, randomdata, 256,
				 auth_data, auth_len);

  memset(tmp, 0, tmp_len);
  memset(auth_data, 0, sizeof(auth_data));
  memset(randomdata, 0, 256);
  silc_free(tmp);
  silc_free(randomdata);
  silc_pkcs_free(pkcs);

  return buf;
}

/* Verifies the authentication data. Returns TRUE if authentication was
   successful. */

bool silc_auth_public_key_auth_verify(SilcAuthPayload payload,
				      SilcPublicKey public_key, SilcHash hash,
				      const void *id, SilcIdType type)
{
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcPKCS pkcs;

  SILC_LOG_DEBUG(("Verifying authentication data"));

  /* Encode auth data */
  tmp = silc_auth_public_key_encode_data(public_key, payload->random_data,
					 payload->random_len,
					 id, type, &tmp_len);
  if (!tmp) {
    SILC_LOG_DEBUG(("Authentication failed"));
    return FALSE;
  }

  /* Allocate PKCS object */
  if (!silc_pkcs_alloc(public_key->name, &pkcs)) {
    memset(tmp, 0, tmp_len);
    silc_free(tmp);
    return FALSE;
  }
  silc_pkcs_public_key_set(pkcs, public_key);

  /* Verify the authentication data */
  if (!silc_pkcs_verify_with_hash(pkcs, hash, payload->auth_data,
				  payload->auth_len, tmp, tmp_len)) {

    memset(tmp, 0, tmp_len);
    silc_free(tmp);
    silc_pkcs_free(pkcs);
    SILC_LOG_DEBUG(("Authentication failed"));
    return FALSE;
  }

  memset(tmp, 0, tmp_len);
  silc_free(tmp);
  silc_pkcs_free(pkcs);

  SILC_LOG_DEBUG(("Authentication successful"));

  return TRUE;
}

/* Same as above but the payload is not parsed yet. This will parse it. */

bool silc_auth_public_key_auth_verify_data(const unsigned char *payload,
					   SilcUInt32 payload_len,
					   SilcPublicKey public_key,
					   SilcHash hash,
					   const void *id, SilcIdType type)
{
  SilcAuthPayload auth_payload;
  int ret;

  auth_payload = silc_auth_payload_parse(payload, payload_len);
  if (!auth_payload) {
    SILC_LOG_DEBUG(("Authentication failed"));
    return FALSE;
  }

  ret = silc_auth_public_key_auth_verify(auth_payload, public_key, hash,
					 id, type);

  silc_auth_payload_free(auth_payload);

  return ret;
}

/* Verifies the authentication data directly from the Authentication
   Payload. Supports all authentication methods. If the authentication
   method is passphrase based then the `auth_data' and `auth_data_len'
   are the passphrase and its length. If the method is public key
   authentication then the `auth_data' is the SilcPublicKey and the
   `auth_data_len' is ignored. */

bool silc_auth_verify(SilcAuthPayload payload, SilcAuthMethod auth_method,
		      const void *auth_data, SilcUInt32 auth_data_len,
		      SilcHash hash, const void *id, SilcIdType type)
{
  SILC_LOG_DEBUG(("Verifying authentication"));

  if (!payload || auth_method != payload->auth_method)
    return FALSE;

  switch (payload->auth_method) {
  case SILC_AUTH_NONE:
    /* No authentication */
    SILC_LOG_DEBUG(("No authentication required"));
    return TRUE;

  case SILC_AUTH_PASSWORD:
    /* Passphrase based authentication. The `pkcs', `hash', `id' and `type'
       arguments are not needed. */

    /* Sanity checks */
    if ((payload->auth_len == 0) || !auth_data ||
	payload->auth_len != auth_data_len)
      break;

    if (!memcmp(payload->auth_data, auth_data, auth_data_len)) {
      SILC_LOG_DEBUG(("Passphrase Authentication successful"));
      return TRUE;
    }
    break;

  case SILC_AUTH_PUBLIC_KEY:
    /* Public key based authentication */
    return silc_auth_public_key_auth_verify(payload, (SilcPublicKey)auth_data,
					    hash, id, type);
    break;

  default:
    break;
  }

  SILC_LOG_DEBUG(("Authentication failed"));

  return FALSE;
}

/* Same as above but parses the authentication payload before verify. */

bool silc_auth_verify_data(const unsigned char *payload,
			   SilcUInt32 payload_len,
			   SilcAuthMethod auth_method, const void *auth_data,
			   SilcUInt32 auth_data_len, SilcHash hash,
			   const void *id, SilcIdType type)
{
  SilcAuthPayload auth_payload;
  bool ret;

  auth_payload = silc_auth_payload_parse(payload, payload_len);
  if (!auth_payload || (auth_payload->auth_len == 0))
    return FALSE;

  ret = silc_auth_verify(auth_payload, auth_method, auth_data, auth_data_len,
			 hash, id, type);

  silc_auth_payload_free(auth_payload);

  return ret;
}

/******************************************************************************

                            Key Agreement Payload

******************************************************************************/

/* The Key Agreement protocol structure */
struct SilcKeyAgreementPayloadStruct {
  SilcUInt16 hostname_len;
  unsigned char *hostname;
  SilcUInt32 port;
};

/* Parses and returns an allocated Key Agreement payload. */

SilcKeyAgreementPayload
silc_key_agreement_payload_parse(const unsigned char *payload,
				 SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcKeyAgreementPayload newp;
  int ret;

  SILC_LOG_DEBUG(("Parsing Key Agreement Payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the payload */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->hostname,
							 &newp->hostname_len),
			     SILC_STR_UI_INT(&newp->port),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(newp);
    return NULL;
  }

  return newp;
}

/* Encodes the Key Agreement protocol and returns the encoded buffer */

SilcBuffer silc_key_agreement_payload_encode(const char *hostname,
					     SilcUInt32 port)
{
  SilcBuffer buffer;
  SilcUInt32 len = hostname ? strlen(hostname) : 0;

  SILC_LOG_DEBUG(("Encoding Key Agreement Payload"));

  buffer = silc_buffer_alloc_size(2 + len + 4);
  if (!buffer)
    return NULL;
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_XNSTRING(hostname, len),
		     SILC_STR_UI_INT(port),
		     SILC_STR_END);

  return buffer;
}

/* Frees the Key Agreement protocol */

void silc_key_agreement_payload_free(SilcKeyAgreementPayload payload)
{
  if (payload) {
    silc_free(payload->hostname);
    silc_free(payload);
  }
}

/* Returns the hostname in the payload */

char *silc_key_agreement_get_hostname(SilcKeyAgreementPayload payload)
{
  return payload->hostname;
}

/* Returns the port in the payload */

SilcUInt32 silc_key_agreement_get_port(SilcKeyAgreementPayload payload)
{
  return payload->port;
}

/******************************************************************************

                     SILC_MESSAGE_FLAG_SIGNED Payload

******************************************************************************/

/* The SILC_MESSAGE_FLAG_SIGNED Payload */
struct SilcSignedPayloadStruct {
  SilcUInt16 pk_len;
  SilcUInt16 pk_type;
  SilcUInt16 sign_len;
  unsigned char *pk_data;
  unsigned char *sign_data;
};

/* Encodes the data to be signed to SILC_MESSAGE_FLAG_SIGNED Payload */

static SilcBuffer
silc_signed_payload_encode_data(const unsigned char *message_payload,
				SilcUInt32 message_payload_len,
				unsigned char *pk,
				SilcUInt32 pk_len, SilcUInt32 pk_type)
{
  SilcBuffer sign;

  sign = silc_buffer_alloc_size(message_payload_len + 4 + pk_len);
  if (!sign)
    return NULL;

  silc_buffer_format(sign,
		     SILC_STR_UI_XNSTRING(message_payload,
					  message_payload_len),
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_SHORT(pk_type),
		     SILC_STR_END);

  if (pk && pk_len) {
    silc_buffer_pull(sign, message_payload_len + 4);
    silc_buffer_format(sign,
		       SILC_STR_UI_XNSTRING(pk, pk_len),
		       SILC_STR_END);
    silc_buffer_push(sign, message_payload_len + 4);
  }

  return sign;
}

/* Parses the SILC_MESSAGE_FLAG_SIGNED Payload */

SilcSignedPayload silc_signed_payload_parse(const unsigned char *data,
					    SilcUInt32 data_len)
{
  SilcSignedPayload sig;
  SilcBufferStruct buffer;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC_MESSAGE_FLAG_SIGNED Payload"));

  silc_buffer_set(&buffer, (unsigned char *)data, data_len);
  sig = silc_calloc(1, sizeof(*sig));
  if (!sig)
    return NULL;

  /* Parse the payload */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&sig->pk_len),
			     SILC_STR_UI_SHORT(&sig->pk_type),
			     SILC_STR_END);
  if (ret == -1 || sig->pk_len > data_len - 4) {
    silc_signed_payload_free(sig);
    return NULL;
  }

  silc_buffer_pull(&buffer, 4);
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&sig->pk_data,
							sig->pk_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&sig->sign_data,
							 &sig->sign_len),
			     SILC_STR_END);
  if (ret == -1) {
    silc_signed_payload_free(sig);
    return NULL;
  }
  silc_buffer_push(&buffer, 4);

  /* Signature must be provided */
  if (sig->sign_len < 1)  {
    silc_signed_payload_free(sig);
    return NULL;
  }

  return sig;
}

/* Encodes the SILC_MESSAGE_FLAG_SIGNED Payload and computes the digital
   signature. */

SilcBuffer silc_signed_payload_encode(const unsigned char *message_payload,
				      SilcUInt32 message_payload_len,
				      SilcPublicKey public_key,
				      SilcPrivateKey private_key,
				      SilcHash hash,
				      bool include_public_key)
{
  SilcBuffer buffer, sign;
  SilcPKCS pkcs;
  unsigned char auth_data[2048];
  SilcUInt32 auth_len;
  unsigned char *pk = NULL;
  SilcUInt32 pk_len = 0;
  SilcUInt16 pk_type;

  if (!message_payload || !message_payload_len || !private_key || !hash)
    return NULL;
  if (include_public_key && !public_key)
    return NULL;

  if (include_public_key)
    pk = silc_pkcs_public_key_encode(public_key, &pk_len);

  /* Now we support only SILC style public key */
  pk_type = SILC_SKE_PK_TYPE_SILC;

  /* Encode the data to be signed */
  sign = silc_signed_payload_encode_data(message_payload,
					 message_payload_len,
					 pk, pk_len, pk_type);
  if (!sign) {
    silc_free(pk);
    return NULL;
  }

  /* Sign the buffer */

  /* Allocate PKCS object */
  if (!silc_pkcs_alloc(private_key->name, &pkcs)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_free(pk);
    return NULL;
  }
  silc_pkcs_private_key_set(pkcs, private_key);

  /* Compute the hash and the signature. */
  if (silc_pkcs_get_key_len(pkcs) / 8 > sizeof(auth_data) - 1 ||
      !silc_pkcs_sign_with_hash(pkcs, hash, sign->data, sign->len, auth_data,
				&auth_len)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_pkcs_free(pkcs);
    silc_free(pk);
    return NULL;
  }

  /* Encode the SILC_MESSAGE_FLAG_SIGNED Payload */

  buffer = silc_buffer_alloc_size(4 + pk_len + 2 + auth_len);
  if (!buffer) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_pkcs_free(pkcs);
    memset(auth_data, 0, sizeof(auth_data));
    silc_free(pk);
    return NULL;
  }

  silc_buffer_format(sign,
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_SHORT(pk_type),
		     SILC_STR_END);

  if (pk_len && pk) {
    silc_buffer_pull(sign, 4);
    silc_buffer_format(sign,
		       SILC_STR_UI_XNSTRING(pk, pk_len),
		       SILC_STR_END);
    silc_buffer_push(sign, 4);
  }

  silc_buffer_pull(sign, 4 + pk_len);
  silc_buffer_format(sign,
		     SILC_STR_UI_SHORT(auth_len),
		     SILC_STR_UI_XNSTRING(auth_data, auth_len),
		     SILC_STR_END);
  silc_buffer_push(sign, 4 + pk_len);

  memset(auth_data, 0, sizeof(auth_data));
  silc_pkcs_free(pkcs);
  silc_buffer_clear(sign);
  silc_buffer_free(sign);
  silc_free(pk);

  return buffer;
}

/* Free the payload */

void silc_signed_payload_free(SilcSignedPayload sig)
{
  if (sig) {
    memset(sig->sign_data, 0, sig->sign_len);
    silc_free(sig->sign_data);
    silc_free(sig->pk_data);
    silc_free(sig);
  }
}

/* Verify the signature in SILC_MESSAGE_FLAG_SIGNED Payload */

int silc_signed_payload_verify(SilcSignedPayload sig,
			       bool channel_message,
			       void *message_payload,
			       SilcPublicKey remote_public_key,
			       SilcHash hash)
{
  int ret = SILC_AUTH_FAILED;
#if 0
  SilcBuffer sign;
  SilcPKCS pkcs;
  
  if (!sig || !remote_public_key || !hash)
    return ret;

  /* Generate the signature verification data */
  if (channel_message) {
    SilcChannelMessagePayload chm =
      (SilcChannelMessagePayload)message_payload;
    SilcBuffer tmp;

    /* Encode Channel Message Payload */
    tmp = silc_buffer_alloc_size(6 + chm->data_len + chm->pad_len +
				 chm->iv_len);
    silc_buffer_format(tmp,
		       SILC_STR_UI_SHORT(chm->flags),
		       SILC_STR_UI_SHORT(chm->data_len),
		       SILC_STR_UI_XNSTRING(chm->data, chm->data_len),
		       SILC_STR_UI_SHORT(chm->pad_len),
		       SILC_STR_UI_XNSTRING(chm->pad, chm->pad_len),
		       SILC_STR_UI_XNSTRING(chm->iv, chm->iv_len),
		       SILC_STR_END);

    sign = silc_signed_payload_encode_data(tmp->data, tmp->len,
					   sig->pk_data, sig->pk_len,
					   sig->pk_type);
    silc_buffer_clear(tmp);
    silc_buffer_free(tmp);
  } else {
    SilcPrivateMessagePayload prm =
      (SilcPrivateMessagePayload)message_payload;
    SilcBuffer tmp;

    /* Encode Private Message Payload */
    tmp = silc_buffer_alloc_size(4 + prm->data_len +
				 SILC_PRIVATE_MESSAGE_PAD(4 + prm->data_len));
    silc_buffer_format(tmp,
		       SILC_STR_UI_SHORT(prm->flags),
		       SILC_STR_UI_SHORT(prm->message_len),
		       SILC_STR_UI_XNSTRING(prm->message, prm->message_len),
		       SILC_STR_END);

    sign = silc_signed_payload_encode_data(tmp->data, tmp->len,
					   sig->pk_data, sig->pk_len,
					   sig->pk_type);
    silc_buffer_clear(tmp);
    silc_buffer_free(tmp);
  }

  if (!sign)
    return ret;
  
  /* Allocate PKCS object */
  if (!silc_pkcs_alloc(remote_public_key->name, &pkcs)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    return ret;
  }
  silc_pkcs_public_key_set(pkcs, remote_public_key);

  /* Verify the authentication data */
  if (!silc_pkcs_verify_with_hash(pkcs, hash, payload->sign_data
				  payload->sign_len,
				  sign->data, sign->len)) {

    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_pkcs_free(pkcs);
    SILC_LOG_DEBUG(("Signature verification failed"));
    return ret;
  }

  ret = SILC_AUTH_OK;

  silc_buffer_clear(sign);
  silc_buffer_free(sign);
  silc_pkcs_free(pkcs);

  SILC_LOG_DEBUG(("Signature verification successful"));

#endif
  return ret;
}

/* Return the public key from the payload */

SilcPublicKey silc_signed_payload_get_public_key(SilcSignedPayload sig)
{
  SilcPublicKey pk;

  if (!sig->pk_data || !silc_pkcs_public_key_decode(sig->pk_data,
						    sig->pk_len, &pk))
    return NULL;

  return pk;
}
