/*

  silcske.c

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
/* $Id$ */

#include "silcincludes.h"
#include "payload_internal.h"
#include "groups_internal.h"

/* Allocates new SKE object. */

SilcSKE silc_ske_alloc()
{
  SilcSKE ske;

  SILC_LOG_DEBUG(("Allocating new Key Exchange object"));

  ske = silc_calloc(1, sizeof(*ske));
  ske->status = SILC_SKE_STATUS_OK;

  return ske;
}

/* Free's SKE object. */

void silc_ske_free(SilcSKE ske)
{
  SILC_LOG_DEBUG(("Freeing Key Exchange object"));

  if (ske) {
    /* Free start payload */
    if (ske->start_payload)
      silc_ske_payload_start_free(ske->start_payload);

    /* Free KE1 payload */
    if (ske->ke1_payload)
      silc_ske_payload_one_free(ske->ke1_payload);

    /* Free KE2 payload */
    if (ske->ke2_payload)
      silc_ske_payload_two_free(ske->ke2_payload);

    /* Free rest */
    if (ske->prop) {
      if (ske->prop->group)
	silc_free(ske->prop->group);
      if (ske->prop->pkcs)
	silc_pkcs_free(ske->prop->pkcs);
      if (ske->prop->cipher)
	silc_cipher_free(ske->prop->cipher);
      if (ske->prop->hash)
	silc_hash_free(ske->prop->hash);
      silc_free(ske->prop);
    }
    if (ske->start_payload_copy)
      silc_buffer_free(ske->start_payload_copy);
    if (ske->pk)
      silc_free(ske->pk);
    if (ske->x) {
      silc_mp_clear(ske->x);
      silc_free(ske->x);
    }
    if (ske->KEY) {
      silc_mp_clear(ske->KEY);
      silc_free(ske->KEY);
    }
    if (ske->hash)
      silc_free(ske->hash);
    silc_free(ske);
  }
}

/* Starts the SILC Key Exchange protocol for initiator. The connection
   to the remote end must be established before calling this function
   and the connecting socket must be sent as argument. This function
   creates the Key Exchange Start Paload which includes all our
   configured security properties. This payload is then sent to the
   remote end for further processing. This payload must be sent as
   argument to the function, however, it must not be encoded
   already, it is done by this function.

   The packet sending is done by calling a callback function. Caller
   must provide a routine to send the packet. */

SilcSKEStatus silc_ske_initiator_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       SilcSKEStartPayload *start_payload,
				       SilcSKESendPacketCb send_packet,
				       void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer payload_buf;

  SILC_LOG_DEBUG(("Start"));

  ske->sock = sock;
  ske->rng = rng;

  /* Encode the payload */
  status = silc_ske_payload_start_encode(ske, start_payload, &payload_buf);
  if (status != SILC_SKE_STATUS_OK)
    return status;

  /* Take a copy of the payload buffer for future use. It is used to
     compute the HASH value. */
  ske->start_payload_copy = silc_buffer_copy(payload_buf);

  /* Send the packet. */
  if (send_packet)
    (*send_packet)(ske, payload_buf, SILC_PACKET_KEY_EXCHANGE, context);

  silc_buffer_free(payload_buf);

  return status;
}

/* Function called after ske_initiator_start fuction. This receives
   the remote ends Key Exchange Start payload which includes the
   security properties selected by the responder from our payload
   sent in the silc_ske_initiator_start function. */

SilcSKEStatus silc_ske_initiator_phase_1(SilcSKE ske, 
					 SilcBuffer start_payload,
					 SilcSKECb callback,
					 void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcSKEStartPayload *payload;
  SilcSKESecurityProperties prop;
  SilcSKEDiffieHellmanGroup group;

  SILC_LOG_DEBUG(("Start"));

  /* Decode the payload */
  status = silc_ske_payload_start_decode(ske, start_payload, &payload);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }

  /* Take the selected security properties into use while doing
     the key exchange. This is used only while doing the key 
     exchange. The same data is returned to upper levels by calling
     the callback function. */
  ske->prop = prop = silc_calloc(1, sizeof(*prop));
  prop->flags = payload->flags;
  status = silc_ske_get_group_by_name(payload->ke_grp_list, &group);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  prop->group = group;

  if (silc_pkcs_alloc(payload->pkcs_alg_list, &prop->pkcs) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_PKCS;
    goto err;
  }

  if (silc_cipher_alloc(payload->enc_alg_list, &prop->cipher) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_CIPHER;
    goto err;
  }

  if (silc_hash_alloc(payload->hash_alg_list, &prop->hash) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION;
    goto err;
  }

  ske->start_payload = payload;

  /* Return the received payload by calling the callback function. */
  if (callback)
    (*callback)(ske, context);

  return status;

 err:
  if (payload)
    silc_ske_payload_start_free(payload);

  silc_free(group);

  if (prop->pkcs)
    silc_pkcs_free(prop->pkcs);
  if (prop->cipher)
    silc_cipher_free(prop->cipher);
  if (prop->hash)
    silc_hash_free(prop->hash);
  silc_free(prop);
  ske->prop = NULL;

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* This function creates random number x, such that 1 < x < q and 
   computes e = g ^ x mod p and sends the result to the remote end in 
   Key Exchange 1 Payload. */

SilcSKEStatus silc_ske_initiator_phase_2(SilcSKE ske,
					 SilcPublicKey public_key,
					 SilcSKESendPacketCb send_packet,
					 void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer payload_buf;
  SilcInt *x, e;
  SilcSKEOnePayload *payload;
  unsigned int pk_len;

  SILC_LOG_DEBUG(("Start"));

  /* Create the random number x, 1 < x < q. */
  x = silc_calloc(1, sizeof(*x));
  silc_mp_init(x);
  status = 
    silc_ske_create_rnd(ske, ske->prop->group->group_order,
			silc_mp_sizeinbase(&ske->prop->group->group_order, 2),
			x);
  if (status != SILC_SKE_STATUS_OK) {
    silc_mp_clear(x);
    silc_free(x);
    ske->status = status;
    return status;
  }

  SILC_LOG_DEBUG(("Computing e = g ^ x mod p"));

  /* Do the Diffie Hellman computation, e = g ^ x mod p */
  silc_mp_init(&e);
  silc_mp_powm(&e, &ske->prop->group->generator, x, 
	       &ske->prop->group->group);
  
  /* Encode the result to Key Exchange 1 Payload. */
  payload = silc_calloc(1, sizeof(*payload));
  payload->e = e;
  payload->pk_data = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!payload->pk_data) {
    silc_mp_clear(x);
    silc_free(x);
    silc_mp_clear(&e);
    silc_free(payload);
    ske->status = SILC_SKE_STATUS_OK;
    return ske->status;
  }
  payload->pk_len = pk_len;
  payload->pk_type = SILC_SKE_PK_TYPE_SILC;
  status = silc_ske_payload_one_encode(ske, payload, &payload_buf);
  if (status != SILC_SKE_STATUS_OK) {
    silc_mp_clear(x);
    silc_free(x);
    silc_mp_clear(&e);
    silc_free(payload->pk_data);
    silc_free(payload);
    ske->status = status;
    return status;
  }

  ske->ke1_payload = payload;
  ske->x = x;

  /* Send the packet. */
  if (send_packet)
    (*send_packet)(ske, payload_buf, SILC_PACKET_KEY_EXCHANGE_1, context);

  silc_buffer_free(payload_buf);

  return status;
}

/* Receives Key Exchange 2 Payload from responder consisting responders
   public key, f, and signature. This function verifies the public key,
   computes the secret shared key and verifies the signature. */

SilcSKEStatus silc_ske_initiator_finish(SilcSKE ske,
					SilcBuffer ke2_payload,
					SilcSKEVerifyCb verify_key,
					void *verify_context,
					SilcSKECb callback,
					void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcSKETwoPayload *payload;
  SilcPublicKey public_key = NULL;
  SilcInt *KEY;
  unsigned char hash[32];
  unsigned int hash_len;

  SILC_LOG_DEBUG(("Start"));

  /* Decode the payload */
  status = silc_ske_payload_two_decode(ske, ke2_payload, &payload);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }
  ske->ke2_payload = payload;

  SILC_LOG_DEBUG(("Computing KEY = f ^ x mod p"));

  /* Compute the shared secret key */
  KEY = silc_calloc(1, sizeof(*KEY));
  silc_mp_init(KEY);
  silc_mp_powm(KEY, &payload->f, ske->x, &ske->prop->group->group);
  ske->KEY = KEY;

  SILC_LOG_DEBUG(("Verifying public key"));

  if (!silc_pkcs_public_key_decode(payload->pk_data, payload->pk_len, 
				   &public_key)) {
    status = SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;
    goto err;
  }

  if (verify_key) {
    status = (*verify_key)(ske, payload->pk_data, payload->pk_len,
			   payload->pk_type, verify_context);
    if (status != SILC_SKE_STATUS_OK)
      goto err;
  }  

  SILC_LOG_DEBUG(("Public key is authentic"));

  /* Compute the hash value */
  status = silc_ske_make_hash(ske, hash, &hash_len);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  ske->hash = silc_calloc(hash_len, sizeof(unsigned char));
  memcpy(ske->hash, hash, hash_len);
  ske->hash_len = hash_len;

  SILC_LOG_DEBUG(("Verifying signature"));

  /* Verify signature */
  silc_pkcs_public_key_data_set(ske->prop->pkcs, public_key->pk, 
				public_key->pk_len);
  if (ske->prop->pkcs->pkcs->verify(ske->prop->pkcs->context,
				    payload->sign_data, payload->sign_len,
				    hash, hash_len) == FALSE) {

    SILC_LOG_DEBUG(("Signature don't match"));

    status = SILC_SKE_STATUS_INCORRECT_SIGNATURE;
    goto err;
  }

  SILC_LOG_DEBUG(("Signature is Ok"));

  silc_pkcs_public_key_free(public_key);
  memset(hash, 'F', hash_len);

  /* Call the callback. */
  if (callback)
    (*callback)(ske, context);

  return status;

 err:
  memset(hash, 'F', sizeof(hash));
  silc_ske_payload_two_free(payload);
  ske->ke2_payload = NULL;

  silc_mp_clear(ske->KEY);
  silc_free(ske->KEY);
  ske->KEY = NULL;

  if (public_key)
    silc_pkcs_public_key_free(public_key);

  if (ske->hash) {
    memset(ske->hash, 'F', hash_len);
    silc_free(ske->hash);
    ske->hash = NULL;
  }

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* Starts Key Exchange protocol for responder. Responder receives
   Key Exchange Start Payload from initiator consisting of all the
   security properties the initiator supports. This function decodes
   the payload and parses the payload further and selects the right 
   security properties. */

SilcSKEStatus silc_ske_responder_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       char *version,
				       SilcBuffer start_payload,
				       SilcSKECb callback,
				       void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcSKEStartPayload *remote_payload = NULL, *payload = NULL;

  SILC_LOG_DEBUG(("Start"));

  ske->sock = sock;
  ske->rng = rng;

  /* Decode the payload */
  status = silc_ske_payload_start_decode(ske, start_payload, &remote_payload);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }

  /* Take a copy of the payload buffer for future use. It is used to
     compute the HASH value. */
  ske->start_payload_copy = silc_buffer_copy(start_payload);

  /* Parse and select the security properties from the payload */
  payload = silc_calloc(1, sizeof(*payload));
  status = silc_ske_select_security_properties(ske, version,
					       payload, remote_payload);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  ske->start_payload = payload;

  /* Call the callback function. */
  if (callback)
    (*callback)(ske, context);

  return status;

 err:
  if (remote_payload)
    silc_ske_payload_start_free(remote_payload);
  if (payload)
    silc_free(payload);

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* The selected security properties from the initiator payload is now 
   encoded into Key Exchange Start Payload and sent to the initiator. */

SilcSKEStatus silc_ske_responder_phase_1(SilcSKE ske, 
					 SilcSKEStartPayload *start_payload,
					 SilcSKESendPacketCb send_packet,
					 void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer payload_buf;
  SilcSKESecurityProperties prop;
  SilcSKEDiffieHellmanGroup group = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Allocate security properties from the payload. These are allocated
     only for this negotiation and will be free'd after KE is over. */
  ske->prop = prop = silc_calloc(1, sizeof(*prop));
  prop->flags = start_payload->flags;
  status = silc_ske_get_group_by_name(start_payload->ke_grp_list, &group);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  prop->group = group;

  if (silc_pkcs_alloc(start_payload->pkcs_alg_list, 
		      &prop->pkcs) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_PKCS;
    goto err;
  }

  if (silc_cipher_alloc(start_payload->enc_alg_list, 
			&prop->cipher) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_CIPHER;
    goto err;
  }

  if (silc_hash_alloc(start_payload->hash_alg_list,
		      &prop->hash) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION;
    goto err;
  }

  /* Encode the payload */
  status = silc_ske_payload_start_encode(ske, start_payload, &payload_buf);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  /* Send the packet. */
  if (send_packet)
    (*send_packet)(ske, payload_buf, SILC_PACKET_KEY_EXCHANGE, context);

  silc_buffer_free(payload_buf);

  return status;

 err:
  if (group)
    silc_free(group);

  if (prop->pkcs)
    silc_pkcs_free(prop->pkcs);
  if (prop->cipher)
    silc_cipher_free(prop->cipher);
  if (prop->hash)
    silc_hash_free(prop->hash);
  silc_free(prop);
  ske->prop = NULL;

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* This function receives the Key Exchange 1 Payload from the initiator.
   After processing the payload this then selects random number x,
   such that 1 < x < q and computes f = g ^ x mod p. This then puts
   the result f to a Key Exchange 2 Payload which is later processed
   in ske_responder_finish function. The callback function should
   not touch the payload (it should merely call the ske_responder_finish
   function). */

SilcSKEStatus silc_ske_responder_phase_2(SilcSKE ske,
					 SilcBuffer ke1_payload,
					 SilcSKECb callback,
					 void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcSKEOnePayload *one_payload;
  SilcSKETwoPayload *two_payload;
  SilcInt *x, f;

  SILC_LOG_DEBUG(("Start"));

  /* Decode Key Exchange 1 Payload */
  status = silc_ske_payload_one_decode(ske, ke1_payload, &one_payload);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }

  /* Create the random number x, 1 < x < q. */
  x = silc_calloc(1, sizeof(*x));
  silc_mp_init(x);
  status = 
    silc_ske_create_rnd(ske, ske->prop->group->group_order,
			silc_mp_sizeinbase(&ske->prop->group->group_order, 2),
			x);
  if (status != SILC_SKE_STATUS_OK) {
    silc_mp_clear(x);
    silc_free(x);
    return status;
  }

  SILC_LOG_DEBUG(("Computing f = g ^ x mod p"));

  /* Do the Diffie Hellman computation, f = g ^ x mod p */
  silc_mp_init(&f);
  silc_mp_powm(&f, &ske->prop->group->generator, x, 
	       &ske->prop->group->group);
  
  /* Save the results for later processing */
  two_payload = silc_calloc(1, sizeof(*two_payload));
  two_payload->f = f;
  ske->x = x;
  ske->ke1_payload = one_payload;
  ske->ke2_payload = two_payload;

  /* Call the callback. */
  if (callback)
    (*callback)(ske, context);

  return status;
}

/* This function computes the secret shared key KEY = e ^ x mod p, and, 
   a hash value to be signed and sent to the other end. This then
   encodes Key Exchange 2 Payload and sends it to the other end. */

SilcSKEStatus silc_ske_responder_finish(SilcSKE ske,
					SilcPublicKey public_key,
					SilcPrivateKey private_key,
					SilcSKEPKType pk_type,
					SilcSKESendPacketCb send_packet,
					void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer payload_buf;
  SilcInt *KEY;
  unsigned char hash[32], sign[256], *pk;
  unsigned int hash_len, sign_len, pk_len;

  SILC_LOG_DEBUG(("Start"));

  if (!public_key || !private_key) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }

  SILC_LOG_DEBUG(("Computing KEY = e ^ x mod p"));

  /* Compute the shared secret key */
  KEY = silc_calloc(1, sizeof(*KEY));
  silc_mp_init(KEY);
  silc_mp_powm(KEY, &ske->ke1_payload->e, ske->x, 
	       &ske->prop->group->group);
  ske->KEY = KEY;

  SILC_LOG_DEBUG(("Getting public key"));

  /* Get the public key */
  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk) {
    status = SILC_SKE_STATUS_ERROR;
    goto err;
  }
  ske->ke2_payload->pk_data = pk;
  ske->ke2_payload->pk_len = pk_len;
  ske->ke2_payload->pk_type = pk_type;

  SILC_LOG_DEBUG(("Computing HASH value"));

  /* Compute the hash value */
  memset(hash, 0, sizeof(hash));
  status = silc_ske_make_hash(ske, hash, &hash_len);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  ske->hash = silc_calloc(hash_len, sizeof(unsigned char));
  memcpy(ske->hash, hash, hash_len);
  ske->hash_len = hash_len;

  SILC_LOG_DEBUG(("Signing HASH value"));

  /* Sign the hash value */
  silc_pkcs_private_key_data_set(ske->prop->pkcs, private_key->prv, 
				 private_key->prv_len);
  ske->prop->pkcs->pkcs->sign(ske->prop->pkcs->context,
			      hash, hash_len,
			      sign, &sign_len);
  ske->ke2_payload->sign_data = silc_calloc(sign_len, sizeof(unsigned char));
  memcpy(ske->ke2_payload->sign_data, sign, sign_len);
  memset(sign, 0, sizeof(sign));
  ske->ke2_payload->sign_len = sign_len;

  /* Encode the Key Exchange 2 Payload */
  status = silc_ske_payload_two_encode(ske, ske->ke2_payload,
				       &payload_buf);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  /* Send the packet. */
  if (send_packet)
    (*send_packet)(ske, payload_buf, SILC_PACKET_KEY_EXCHANGE_2, context);

  silc_buffer_free(payload_buf);

  return status;

 err:
  silc_mp_clear(ske->KEY);
  silc_free(ske->KEY);
  ske->KEY = NULL;
  silc_ske_payload_two_free(ske->ke2_payload);

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* The Key Exchange protocol is ended by calling this function. This
   must not be called until the keys are processed like the protocol
   defines. This function is for both initiator and responder. */

SilcSKEStatus silc_ske_end(SilcSKE ske,
			   SilcSKESendPacketCb send_packet,
			   void *context)
{
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Start"));

  packet = silc_buffer_alloc(4);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(SILC_SKE_STATUS_OK),
		     SILC_STR_END);

  if (send_packet)
    (*send_packet)(ske, packet, SILC_PACKET_SUCCESS, context);

  silc_buffer_free(packet);

  return SILC_SKE_STATUS_OK;
}

/* Aborts the Key Exchange protocol. This is called if error occurs
   while performing the protocol. The status argument is the error
   status and it is sent to the remote end. */

SilcSKEStatus silc_ske_abort(SilcSKE ske, SilcSKEStatus status,
			     SilcSKESendPacketCb send_packet,
			     void *context)
{
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Start"));

  packet = silc_buffer_alloc(4);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(status),
		     SILC_STR_END);

  if (send_packet)
    (*send_packet)(ske, packet, SILC_PACKET_FAILURE, context);

  silc_buffer_free(packet);

  return SILC_SKE_STATUS_OK;
}

/* Assembles security properties to Key Exchange Start Payload to be
   sent to the remote end. This checks system wide (SILC system, that is)
   settings and chooses from those. However, if other properties
   should be used this function is easy to replace by another function,
   as, this function is called by the caller of the protocol and not
   by the protocol itself. */

SilcSKEStatus 
silc_ske_assemble_security_properties(SilcSKE ske,
				      unsigned char flags,
				      char *version,
				      SilcSKEStartPayload **return_payload)
{
  SilcSKEStartPayload *rp;
  int i;

  SILC_LOG_DEBUG(("Assembling KE Start Payload"));

  rp = silc_calloc(1, sizeof(*rp));

  /* Set flags */
  rp->flags = flags;

  /* Set random cookie */
  rp->cookie = silc_calloc(SILC_SKE_COOKIE_LEN, sizeof(*rp->cookie));
  for (i = 0; i < SILC_SKE_COOKIE_LEN; i++)
    rp->cookie[i] = silc_rng_get_byte(ske->rng);
  rp->cookie_len = SILC_SKE_COOKIE_LEN;

  /* Put version */
  rp->version = strdup(version);
  rp->version_len = strlen(version);

  /* Get supported Key Exhange groups */
  rp->ke_grp_list = silc_ske_get_supported_groups();
  rp->ke_grp_len = strlen(rp->ke_grp_list);

  /* Get supported PKCS algorithms */
  rp->pkcs_alg_list = silc_pkcs_get_supported();
  rp->pkcs_alg_len = strlen(rp->pkcs_alg_list);

  /* Get supported encryption algorithms */
  rp->enc_alg_list = silc_cipher_get_supported();
  rp->enc_alg_len = strlen(rp->enc_alg_list);

  /* Get supported hash algorithms */
  rp->hash_alg_list = silc_hash_get_supported();
  rp->hash_alg_len = strlen(rp->hash_alg_list);

  /* XXX */
  /* Get supported compression algorithms */
  rp->comp_alg_list = "";
  rp->comp_alg_len = 0;

  rp->len = 1 + 1 + 2 + SILC_SKE_COOKIE_LEN + 
    2 + rp->version_len +
    2 + rp->ke_grp_len + 2 + rp->pkcs_alg_len + 
    2 + rp->enc_alg_len + 2 + rp->hash_alg_len + 
    2 + rp->comp_alg_len;

  *return_payload = rp;

  return SILC_SKE_STATUS_OK;
}

/* Selects the supported security properties from the remote end's Key 
   Exchange Start Payload. */

SilcSKEStatus 
silc_ske_select_security_properties(SilcSKE ske,
				    char *version,
				    SilcSKEStartPayload *payload,
				    SilcSKEStartPayload *remote_payload)
{
  SilcSKEStatus status;
  SilcSKEStartPayload *rp;
  char *cp;
  int len;

  SILC_LOG_DEBUG(("Parsing KE Start Payload"));

  rp = remote_payload;

  /* Check version string */
  status = silc_ske_check_version(ske, rp->version, rp->version_len);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }

  /* Flags are returned unchanged. */
  payload->flags = rp->flags;

  /* Take cookie */
  payload->cookie = silc_calloc(SILC_SKE_COOKIE_LEN, sizeof(unsigned char));
  payload->cookie_len = SILC_SKE_COOKIE_LEN;
  memcpy(payload->cookie, rp->cookie, SILC_SKE_COOKIE_LEN);

  /* Put our version to our reply */
  payload->version = strdup(version);
  payload->version_len = strlen(version);

  /* Get supported Key Exchange groups */
  cp = rp->ke_grp_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed KE group `%s'", item));

      if (silc_ske_get_group_by_name(item, NULL) == SILC_SKE_STATUS_OK) {
	SILC_LOG_DEBUG(("Found KE group `%s'", item));

	payload->ke_grp_len = len;
	payload->ke_grp_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->ke_grp_len && !payload->ke_grp_list) {
      SILC_LOG_DEBUG(("Could not find supported KE group"));
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_GROUP;
    }
  } else {

    if (!rp->ke_grp_len) {
      SILC_LOG_DEBUG(("KE group not defined in payload"));
      silc_free(payload);
      return SILC_SKE_STATUS_BAD_PAYLOAD;
    }

    SILC_LOG_DEBUG(("Proposed KE group `%s'", rp->ke_grp_list));
    SILC_LOG_DEBUG(("Found KE group `%s'", rp->ke_grp_list));

    payload->ke_grp_len = rp->ke_grp_len;
    payload->ke_grp_list = strdup(rp->ke_grp_list);
  }

  /* Get supported PKCS algorithms */
  cp = rp->pkcs_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed PKCS alg `%s'", item));

      if (silc_pkcs_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found PKCS alg `%s'", item));

	payload->pkcs_alg_len = len;
	payload->pkcs_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->pkcs_alg_len && !payload->pkcs_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported PKCS alg"));
      silc_free(payload->ke_grp_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_PKCS;
    }
  } else {

    if (!rp->pkcs_alg_len) {
      SILC_LOG_DEBUG(("PKCS alg not defined in payload"));
      silc_free(payload->ke_grp_list);
      silc_free(payload);
      return SILC_SKE_STATUS_BAD_PAYLOAD;
    }

    SILC_LOG_DEBUG(("Proposed PKCS alg `%s'", rp->pkcs_alg_list));
    SILC_LOG_DEBUG(("Found PKCS alg `%s'", rp->pkcs_alg_list));

    payload->pkcs_alg_len = rp->pkcs_alg_len;
    payload->pkcs_alg_list = strdup(rp->pkcs_alg_list);
  }

  /* Get supported encryption algorithms */
  cp = rp->enc_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed encryption alg `%s'", item));

      if (silc_cipher_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found encryption alg `%s'", item));

	payload->enc_alg_len = len;
	payload->enc_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->enc_alg_len && !payload->enc_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported encryption alg"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_CIPHER;
    }
  } else {

    if (!rp->enc_alg_len) {
      SILC_LOG_DEBUG(("Encryption alg not defined in payload"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_BAD_PAYLOAD;
    }

    SILC_LOG_DEBUG(("Proposed encryption alg `%s' and selected it",
		    rp->enc_alg_list));

    payload->enc_alg_len = rp->enc_alg_len;
    payload->enc_alg_list = strdup(rp->enc_alg_list);
  }

  /* Get supported hash algorithms */
  cp = rp->hash_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed hash alg `%s'", item));

      if (silc_hash_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found hash alg `%s'", item));

	payload->hash_alg_len = len;
	payload->hash_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->hash_alg_len && !payload->hash_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported hash alg"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION;
    }
  } else {

    if (!rp->hash_alg_len) {
      SILC_LOG_DEBUG(("Hash alg not defined in payload"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_BAD_PAYLOAD;
    }

    SILC_LOG_DEBUG(("Proposed hash alg `%s' and selected it",
		    rp->hash_alg_list));

    payload->hash_alg_len = rp->hash_alg_len;
    payload->hash_alg_list = strdup(rp->hash_alg_list);
  }

#if 0
  /* Get supported compression algorithms */
  cp = rp->hash_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed hash alg `%s'", item));

      if (silc_hash_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found hash alg `%s'", item));

	payload->hash_alg_len = len;
	payload->hash_alg_list = item;
	break;
      }

      cp += len;
      if (strlen(cp) == 0)
	cp = NULL;
      else
	cp++;

      if (item)
	silc_free(item);
    }

    if (!payload->hash_alg_len && !payload->hash_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported hash alg"));
      silc_ske_abort(ske, SILC_SKE_STATUS_UNKNOWN_HASH_FUNCTION);
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload);
      return;
    }
  } else {

  }
#endif

  payload->len = 1 + 1 + 2 + SILC_SKE_COOKIE_LEN + 
    2 + payload->version_len + 
    2 + payload->ke_grp_len + 2 + payload->pkcs_alg_len + 
    2 + payload->enc_alg_len + 2 + payload->hash_alg_len + 
    2 + payload->comp_alg_len;

  return SILC_SKE_STATUS_OK;
}

/* Creates random number such that 1 < rnd < n and at most length
   of len bits. The rnd sent as argument must be initialized. */

SilcSKEStatus silc_ske_create_rnd(SilcSKE ske, SilcInt n, 
				  unsigned int len, 
				  SilcInt *rnd)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  unsigned char *string;

  SILC_LOG_DEBUG(("Creating random number"));

  /* Get the random number as string */
  string = silc_rng_get_rn_data(ske->rng, (len / 8));
  if (!string)
    return SILC_SKE_STATUS_ERROR;

  /* Decode the string into a MP integer */
  silc_mp_bin2mp(string, (len / 8), rnd);
  silc_mp_mod_2exp(rnd, rnd, len);

  /* Checks */
  if (silc_mp_cmp_ui(rnd, 1) < 0)
    status = SILC_SKE_STATUS_ERROR;

  if (silc_mp_cmp(rnd, &n) >= 0)
    status = SILC_SKE_STATUS_ERROR;

  memset(string, 'F', (len / 8));
  silc_free(string);

  return status;
}

/* Creates a hash value HASH as defined in the SKE protocol. */

SilcSKEStatus silc_ske_make_hash(SilcSKE ske, 
				 unsigned char *return_hash,
				 unsigned int *return_hash_len)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer buf;
  unsigned char *e, *f, *KEY;
  unsigned int e_len, f_len, KEY_len;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  e = silc_mp_mp2bin(&ske->ke1_payload->e, &e_len);
  f = silc_mp_mp2bin(&ske->ke2_payload->f, &f_len);
  KEY = silc_mp_mp2bin(ske->KEY, &KEY_len);

  buf = silc_buffer_alloc(ske->start_payload_copy->len + 
			  ske->pk_len + e_len + f_len + KEY_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  /* Format the buffer used to compute the hash value */
  ret = silc_buffer_format(buf,
			   SILC_STR_UI_XNSTRING(ske->start_payload_copy->data,
						ske->start_payload_copy->len),
			   SILC_STR_UI_XNSTRING(ske->pk, ske->pk_len),
			   SILC_STR_UI_XNSTRING(e, e_len),
			   SILC_STR_UI_XNSTRING(f, f_len),
			   SILC_STR_UI_XNSTRING(KEY, KEY_len),
			   SILC_STR_END);
  if (ret == -1) {
    silc_buffer_free(buf);
    memset(e, 0, e_len);
    memset(f, 0, f_len);
    memset(KEY, 0, KEY_len);
    silc_free(e);
    silc_free(f);
    silc_free(KEY);
    return SILC_SKE_STATUS_ERROR;
  }

  /* Make the hash */
  silc_hash_make(ske->prop->hash, buf->data, buf->len, return_hash);
  *return_hash_len = ske->prop->hash->hash->hash_len;

  SILC_LOG_HEXDUMP(("Hash"), return_hash, *return_hash_len);

  silc_buffer_free(buf);
  memset(e, 0, e_len);
  memset(f, 0, f_len);
  memset(KEY, 0, KEY_len);
  silc_free(e);
  silc_free(f);
  silc_free(KEY);

  return status;
}

/* Processes negotiated key material as protocol specifies. This returns
   the actual keys to be used in the SILC. */

SilcSKEStatus silc_ske_process_key_material(SilcSKE ske, 
					    unsigned int req_iv_len,
					    unsigned int req_enc_key_len,
					    unsigned int req_hmac_key_len,
					    SilcSKEKeyMaterial *key)
{
  int klen;
  SilcBuffer buf;
  unsigned char *tmpbuf;
  unsigned char hash[32];
  unsigned int hash_len = ske->prop->hash->hash->hash_len;
  unsigned int enc_key_len = req_enc_key_len / 8;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  /* Encode KEY to binary data */
  tmpbuf = silc_mp_mp2bin(ske->KEY, &klen);

  buf = silc_buffer_alloc(1 + klen + hash_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
  ret = silc_buffer_format(buf,
			   SILC_STR_UI_CHAR(0),
			   SILC_STR_UI_XNSTRING(tmpbuf, klen),
			   SILC_STR_UI_XNSTRING(ske->hash, ske->hash_len),
			   SILC_STR_END);
  if (ret == -1) {
    memset(tmpbuf, 0, klen);
    silc_free(tmpbuf);
    silc_buffer_free(buf);
    return SILC_SKE_STATUS_ERROR;
  }

  /* Take IVs */
  memset(hash, 0, sizeof(hash));
  buf->data[0] = 0;
  silc_hash_make(ske->prop->hash, buf->data, buf->len, hash);
  key->send_iv = silc_calloc(req_iv_len, sizeof(unsigned char));
  memcpy(key->send_iv, hash, req_iv_len);
  memset(hash, 0, sizeof(hash));
  buf->data[0] = 1;
  silc_hash_make(ske->prop->hash, buf->data, buf->len, hash);
  key->receive_iv = silc_calloc(req_iv_len, sizeof(unsigned char));
  memcpy(key->receive_iv, hash, req_iv_len);
  key->iv_len = req_iv_len;

  /* Take the encryption keys. If requested key size is more than
     the size of hash length we will distribute more key material
     as protocol defines. */
  buf->data[0] = 2;
  if (enc_key_len > hash_len) {
    SilcBuffer dist;
    unsigned char k1[32], k2[32], k3[32];
    unsigned char *dtmp;
    
    /* XXX */
    if (enc_key_len > (3 * hash_len))
      return SILC_SKE_STATUS_ERROR;
    
    memset(k1, 0, sizeof(k1));
    silc_hash_make(ske->prop->hash, buf->data, buf->len, k1);
    
    /* XXX */
    dist = silc_buffer_alloc(hash_len * 3);
    
    silc_buffer_pull_tail(dist, klen + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(tmpbuf, klen),
		       SILC_STR_UI_XNSTRING(k1, hash_len),
		       SILC_STR_END);
    
    memset(k2, 0, sizeof(k2));
    silc_hash_make(ske->prop->hash, dist->data, dist->len, k2);
    
    silc_buffer_pull(dist, klen + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(k2, hash_len),
		       SILC_STR_END);
    silc_buffer_push(dist, klen + hash_len);
    
    memset(k3, 0, sizeof(k3));
    silc_hash_make(ske->prop->hash, dist->data, dist->len, k3);
    
    dtmp = silc_calloc((3 * hash_len), sizeof(unsigned char));
    memcpy(dtmp, k1, hash_len);
    memcpy(dtmp + hash_len, k2, hash_len);
    memcpy(dtmp + hash_len, k3, hash_len);

    key->send_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->send_enc_key, dtmp, enc_key_len);
    key->enc_key_len = req_enc_key_len;

    memset(dtmp, 0, (3 * hash_len));
    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));
    memset(k3, 0, sizeof(k3));
    silc_free(dtmp);
    silc_buffer_free(dist);
  } else {
    /* Take normal hash as key */
    memset(hash, 0, sizeof(hash));
    silc_hash_make(ske->prop->hash, buf->data, buf->len, hash);
    key->send_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->send_enc_key, hash, enc_key_len);
    key->enc_key_len = req_enc_key_len;
  }

  buf->data[0] = 3;
  if (enc_key_len > hash_len) {
    SilcBuffer dist;
    unsigned char k1[32], k2[32], k3[32];
    unsigned char *dtmp;
    
    /* XXX */
    if (enc_key_len > (3 * hash_len))
      return SILC_SKE_STATUS_ERROR;
    
    memset(k1, 0, sizeof(k1));
    silc_hash_make(ske->prop->hash, buf->data, buf->len, k1);
    
    /* XXX */
    dist = silc_buffer_alloc(hash_len * 3);
    
    silc_buffer_pull_tail(dist, klen + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(tmpbuf, klen),
		       SILC_STR_UI_XNSTRING(k1, hash_len),
		       SILC_STR_END);
    
    memset(k2, 0, sizeof(k2));
    silc_hash_make(ske->prop->hash, dist->data, dist->len, k2);
    
    silc_buffer_pull(dist, klen + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(k2, hash_len),
		       SILC_STR_END);
    silc_buffer_push(dist, klen + hash_len);
    
    memset(k3, 0, sizeof(k3));
    silc_hash_make(ske->prop->hash, dist->data, dist->len, k3);
    
    dtmp = silc_calloc((3 * hash_len), sizeof(unsigned char));
    memcpy(dtmp, k1, hash_len);
    memcpy(dtmp + hash_len, k2, hash_len);
    memcpy(dtmp + hash_len, k3, hash_len);

    key->receive_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->receive_enc_key, dtmp, enc_key_len);
    key->enc_key_len = req_enc_key_len;

    memset(dtmp, 0, (3 * hash_len));
    memset(k1, 0, sizeof(k1));
    memset(k2, 0, sizeof(k2));
    memset(k3, 0, sizeof(k3));
    silc_free(dtmp);
    silc_buffer_free(dist);
  } else {
    /* Take normal hash as key */
    memset(hash, 0, sizeof(hash));
    silc_hash_make(ske->prop->hash, buf->data, buf->len, hash);
    key->receive_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->receive_enc_key, hash, enc_key_len);
    key->enc_key_len = req_enc_key_len;
  }

  /* Take HMAC key */
  memset(hash, 0, sizeof(hash));
  buf->data[0] = 4;
  silc_hash_make(ske->prop->hash, buf->data, buf->len, hash);
  key->hmac_key = silc_calloc(req_hmac_key_len, sizeof(unsigned char));
  memcpy(key->hmac_key, hash, req_hmac_key_len);
  key->hmac_key_len = req_hmac_key_len;

  memset(tmpbuf, 0, klen);
  silc_free(tmpbuf);

  return SILC_SKE_STATUS_OK;
}
