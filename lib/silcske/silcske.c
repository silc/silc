/*

  silcske.c

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
/* $Id$ */

#include "silcincludes.h"
#include "silcske.h"
#include "groups_internal.h"

/* Structure to hold all SKE callbacks. */
struct SilcSKECallbacksStruct {
  SilcSKESendPacketCb send_packet;
  SilcSKECb payload_receive;
  SilcSKEVerifyCb verify_key;
  SilcSKECb proto_continue;
  SilcSKECheckVersion check_version;
  void *context;
};

/* Allocates new SKE object. */

SilcSKE silc_ske_alloc()
{
  SilcSKE ske;

  SILC_LOG_DEBUG(("Allocating new Key Exchange object"));

  ske = silc_calloc(1, sizeof(*ske));
  ske->status = SILC_SKE_STATUS_OK;
  ske->users = 1;

  return ske;
}

/* Free's SKE object. */

void silc_ske_free(SilcSKE ske)
{
  ske->users--;
  if (ske->users > 0) {
    SILC_LOG_DEBUG(("Key Exchange set to FREED status"));
    ske->status = SILC_SKE_STATUS_FREED;
    return;
  }

  SILC_LOG_DEBUG(("Freeing Key Exchange object"));

  if (ske) {
    /* Free start payload */
    if (ske->start_payload)
      silc_ske_payload_start_free(ske->start_payload);

    /* Free KE payload */
    if (ske->ke1_payload)
      silc_ske_payload_ke_free(ske->ke1_payload);

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
      if (ske->prop->hmac)
	silc_hmac_free(ske->prop->hmac);
      silc_free(ske->prop);
    }
    if (ske->start_payload_copy)
      silc_buffer_free(ske->start_payload_copy);
    if (ske->x) {
      silc_mp_uninit(ske->x);
      silc_free(ske->x);
    }
    if (ske->KEY) {
      silc_mp_uninit(ske->KEY);
      silc_free(ske->KEY);
    }
    if (ske->hash)
      silc_free(ske->hash);
    silc_free(ske);
  }
}

/* Sets the callback functions for the SKE session. 

   The `send_packet' callback is a function that sends the packet to
   network. The SKE library will call it at any time packet needs to
   be sent to the remote host. 

   The `payload_receive' callback is called when the remote host's Key
   Exchange Start Payload has been processed.  The payload is saved
   to ske->start_payload if the application would need it.  The application
   must also provide the payload to the next state of the SKE.

   The `verify_key' callback is called to verify the received public key
   or certificate.  The verification process is most likely asynchronous.
   That is why the application must call the completion callback when the
   verification process has been completed. The library then calls the user
   callback (`proto_continue'), if it is provided to indicate that the SKE
   protocol may continue. 
   
   The `proto_continue' callback is called to indicate that it is
   safe to continue the execution of the SKE protocol after executing
   an asynchronous operation, such as calling the `verify_key' callback
   function, which is asynchronous. The application should check the
   ske->status in this function to check whether it is Ok to continue
   the execution of the protocol.

   The `check_version' callback is called to verify the remote host's
   version. The application may check its own version against the remote
   host's version and determine whether supporting the remote host
   is possible. 

   The `context' is passed as argument to all of the above callback
   functions. */

void silc_ske_set_callbacks(SilcSKE ske,
			    SilcSKESendPacketCb send_packet,
			    SilcSKECb payload_receive,
			    SilcSKEVerifyCb verify_key,
			    SilcSKECb proto_continue,
			    SilcSKECheckVersion check_version,
			    void *context)
{
  if (ske->callbacks)
    silc_free(ske->callbacks);
  ske->callbacks = silc_calloc(1, sizeof(*ske->callbacks));
  ske->callbacks->send_packet = send_packet;
  ske->callbacks->payload_receive = payload_receive;
  ske->callbacks->verify_key = verify_key;
  ske->callbacks->proto_continue = proto_continue;
  ske->callbacks->check_version = check_version;
  ske->callbacks->context = context;
}

/* Starts the SILC Key Exchange protocol for initiator. The connection
   to the remote end must be established before calling this function
   and the connecting socket must be sent as argument. This function
   creates the Key Exchange Start Payload which includes all our
   configured security properties. This payload is then sent to the
   remote end for further processing. This payload must be sent as
   argument to the function, however, it must not be encoded
   already, it is done by this function. The caller must not free
   the `start_payload' since the SKE library will save it.

   The packet sending is done by calling a callback function. Caller
   must provide a routine to send the packet. */

SilcSKEStatus silc_ske_initiator_start(SilcSKE ske, SilcRng rng,
				       SilcSocketConnection sock,
				       SilcSKEStartPayload *start_payload)
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
  ske->start_payload = start_payload;

  /* Send the packet. */
  if (ske->callbacks->send_packet)
    (*ske->callbacks->send_packet)(ske, payload_buf, SILC_PACKET_KEY_EXCHANGE, 
				   ske->callbacks->context);

  silc_buffer_free(payload_buf);

  return status;
}

/* Function called after ske_initiator_start fuction. This receives
   the remote ends Key Exchange Start payload which includes the
   security properties selected by the responder from our payload
   sent in the silc_ske_initiator_start function. */

SilcSKEStatus silc_ske_initiator_phase_1(SilcSKE ske, 
					 SilcBuffer start_payload)
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
    silc_ske_payload_start_free(ske->start_payload);
    return status;
  }

  /* Check that the cookie is returned unmodified */
  if (memcmp(ske->start_payload->cookie, payload->cookie,
	     ske->start_payload->cookie_len)) {
    SILC_LOG_DEBUG(("Responder modified our cookie and it must not do it"));
    ske->status = SILC_SKE_STATUS_INVALID_COOKIE;
    silc_ske_payload_start_free(ske->start_payload);
    return status;
  }

  /* Free our KE Start Payload context, we don't need it anymore. */
  silc_ske_payload_start_free(ske->start_payload);

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

  if (silc_hmac_alloc(payload->hmac_alg_list, NULL, &prop->hmac) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_HMAC;
    goto err;
  }

  /* Save remote's KE Start Payload */
  ske->start_payload = payload;

  /* Return the received payload by calling the callback function. */
  if (ske->callbacks->payload_receive)
    (*ske->callbacks->payload_receive)(ske, ske->callbacks->context);

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
  if (prop->hmac)
    silc_hmac_free(prop->hmac);
  silc_free(prop);
  ske->prop = NULL;

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* This function creates random number x, such that 1 < x < q and 
   computes e = g ^ x mod p and sends the result to the remote end in 
   Key Exchange Payload. */

SilcSKEStatus silc_ske_initiator_phase_2(SilcSKE ske,
					 SilcPublicKey public_key,
					 SilcPrivateKey private_key)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer payload_buf;
  SilcMPInt *x;
  SilcSKEKEPayload *payload;
  uint32 pk_len;

  SILC_LOG_DEBUG(("Start"));

  /* Create the random number x, 1 < x < q. */
  x = silc_calloc(1, sizeof(*x));
  silc_mp_init(x);
  status = 
    silc_ske_create_rnd(ske, &ske->prop->group->group_order,
			silc_mp_sizeinbase(&ske->prop->group->group_order, 2),
			x);
  if (status != SILC_SKE_STATUS_OK) {
    silc_mp_uninit(x);
    silc_free(x);
    ske->status = status;
    return status;
  }

  /* Encode the result to Key Exchange Payload. */

  payload = silc_calloc(1, sizeof(*payload));
  ske->ke1_payload = payload;

  SILC_LOG_DEBUG(("Computing e = g ^ x mod p"));

  /* Do the Diffie Hellman computation, e = g ^ x mod p */
  silc_mp_init(&payload->x);
  silc_mp_pow_mod(&payload->x, &ske->prop->group->generator, x, 
		  &ske->prop->group->group);

  /* Get public key */
  if (public_key) {
    payload->pk_data = silc_pkcs_public_key_encode(public_key, &pk_len);
    if (!payload->pk_data) {
      silc_mp_uninit(x);
      silc_free(x);
      silc_mp_uninit(&payload->x);
      silc_free(payload);
      ske->status = SILC_SKE_STATUS_OK;
      return ske->status;
    }
    payload->pk_len = pk_len;
  }
  payload->pk_type = SILC_SKE_PK_TYPE_SILC;

  /* Compute signature data if we are doing mutual authentication */
  if (private_key && ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL) {
    unsigned char hash[32], sign[1024];
    uint32 hash_len, sign_len;

    SILC_LOG_DEBUG(("We are doing mutual authentication"));
    SILC_LOG_DEBUG(("Computing HASH_i value"));

    /* Compute the hash value */
    memset(hash, 0, sizeof(hash));
    silc_ske_make_hash(ske, hash, &hash_len, TRUE);

    SILC_LOG_DEBUG(("Signing HASH_i value"));
    
    /* Sign the hash value */
    silc_pkcs_private_key_data_set(ske->prop->pkcs, private_key->prv, 
				   private_key->prv_len);
    silc_pkcs_sign(ske->prop->pkcs, hash, hash_len, sign, &sign_len);
    payload->sign_data = silc_calloc(sign_len, sizeof(unsigned char));
    memcpy(payload->sign_data, sign, sign_len);
    memset(sign, 0, sizeof(sign));
    payload->sign_len = sign_len;
  }

  status = silc_ske_payload_ke_encode(ske, payload, &payload_buf);
  if (status != SILC_SKE_STATUS_OK) {
    silc_mp_uninit(x);
    silc_free(x);
    silc_mp_uninit(&payload->x);
    silc_free(payload->pk_data);
    silc_free(payload);
    ske->status = status;
    return status;
  }

  ske->x = x;

  /* Send the packet. */
  if (ske->callbacks->send_packet)
    (*ske->callbacks->send_packet)(ske, payload_buf, 
				   SILC_PACKET_KEY_EXCHANGE_1, 
				   ske->callbacks->context);

  silc_buffer_free(payload_buf);

  return status;
}

/* An initiator finish final callback that is called to indicate that
   the SKE protocol may continue. */

static void silc_ske_initiator_finish_final(SilcSKE ske,
					    SilcSKEStatus status,
					    void *context)
{
  SilcSKEKEPayload *payload;
  unsigned char hash[32];
  uint32 hash_len;
  SilcPublicKey public_key = NULL;

  /* If the SKE was freed during the async call then free it really now,
     otherwise just decrement the reference counter. */
  if (ske->status == SILC_SKE_STATUS_FREED) {
    silc_ske_free(ske);
    return;
  }

  /* If the caller returns PENDING status SKE library will assume that
     the caller will re-call this callback when it is not anymore in
     PENDING status. */
  if (status == SILC_SKE_STATUS_PENDING)
    return;

  ske->users--;
  payload = ske->ke2_payload;

  /* If the status is an error then the public key that was verified
     by the caller is not authentic. */
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    if (ske->callbacks->proto_continue)
      ske->callbacks->proto_continue(ske, ske->callbacks->context);
    return;
  }

  if (payload->pk_data) {
    /* Decode the public key */
    if (!silc_pkcs_public_key_decode(payload->pk_data, payload->pk_len, 
				     &public_key)) {
      status = SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;
      if (ske->callbacks->proto_continue)
	ske->callbacks->proto_continue(ske, ske->callbacks->context);
      return;
    }

    SILC_LOG_DEBUG(("Public key is authentic"));

    /* Compute the hash value */
    status = silc_ske_make_hash(ske, hash, &hash_len, FALSE);
    if (status != SILC_SKE_STATUS_OK)
      goto err;

    ske->hash = silc_calloc(hash_len, sizeof(unsigned char));
    memcpy(ske->hash, hash, hash_len);
    ske->hash_len = hash_len;

    SILC_LOG_DEBUG(("Verifying signature (HASH)"));

    /* Verify signature */
    silc_pkcs_public_key_set(ske->prop->pkcs, public_key);
    if (silc_pkcs_verify(ske->prop->pkcs, payload->sign_data, 
			 payload->sign_len, hash, hash_len) == FALSE) {
      
      SILC_LOG_DEBUG(("Signature don't match"));
      
      status = SILC_SKE_STATUS_INCORRECT_SIGNATURE;
      goto err;
    }

    SILC_LOG_DEBUG(("Signature is Ok"));
    
    silc_pkcs_public_key_free(public_key);
    memset(hash, 'F', hash_len);
  }

  ske->status = SILC_SKE_STATUS_OK;

  /* Call the callback. The caller may now continue the SKE protocol. */
  if (ske->callbacks->proto_continue)
    ske->callbacks->proto_continue(ske, ske->callbacks->context);

  return;

 err:
  memset(hash, 'F', sizeof(hash));
  silc_ske_payload_ke_free(payload);
  ske->ke2_payload = NULL;

  silc_mp_uninit(ske->KEY);
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
    ske->status = SILC_SKE_STATUS_ERROR;

  ske->status = status;

  /* Call the callback. */
  if (ske->callbacks->proto_continue)
    ske->callbacks->proto_continue(ske, ske->callbacks->context);
}

/* Receives Key Exchange Payload from responder consisting responders
   public key, f, and signature. This function verifies the public key,
   computes the secret shared key and verifies the signature. 

   The `callback' will be called to indicate that the caller may
   continue with the SKE protocol.  The caller must not continue
   before the SKE libary has called that callback.  If this function
   returns an error the callback will not be called.  It is called
   if this function return SILC_SKE_STATUS_OK or SILC_SKE_STATUS_PENDING.
   However, note that when the library calls the callback the ske->status
   may be error.

   This calls the `verify_key' callback to verify the received public
   key or certificate. If the `verify_key' is provided then the remote
   must send public key and it is considered to be an error if remote 
   does not send its public key. If caller is performing a re-key with
   SKE then the `verify_key' is usually not provided when it is not also
   required for the remote to send its public key. */

SilcSKEStatus silc_ske_initiator_finish(SilcSKE ske,
					SilcBuffer ke_payload)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcSKEKEPayload *payload;
  SilcMPInt *KEY;

  SILC_LOG_DEBUG(("Start"));

  /* Decode the payload */
  status = silc_ske_payload_ke_decode(ske, ke_payload, &payload);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }
  ske->ke2_payload = payload;

  if (!payload->pk_data && ske->callbacks->verify_key) {
    SILC_LOG_DEBUG(("Remote end did not send its public key (or certificate), "
		    "even though we require it"));
    ske->status = SILC_SKE_STATUS_PUBLIC_KEY_NOT_PROVIDED;
    goto err;
  }

  SILC_LOG_DEBUG(("Computing KEY = f ^ x mod p"));

  /* Compute the shared secret key */
  KEY = silc_calloc(1, sizeof(*KEY));
  silc_mp_init(KEY);
  silc_mp_pow_mod(KEY, &payload->x, ske->x, &ske->prop->group->group);
  ske->KEY = KEY;

  if (payload->pk_data && ske->callbacks->verify_key) {
    SILC_LOG_DEBUG(("Verifying public key"));
    
    ske->users++;
    (*ske->callbacks->verify_key)(ske, payload->pk_data, payload->pk_len,
				 payload->pk_type, ske->callbacks->context,
				 silc_ske_initiator_finish_final, NULL);
    
    /* We will continue to the final state after the public key has
       been verified by the caller. */
    return SILC_SKE_STATUS_PENDING;
  }

  /* Continue to final state */
  silc_ske_initiator_finish_final(ske, SILC_SKE_STATUS_OK, NULL);

  return SILC_SKE_STATUS_OK;

 err:
  silc_ske_payload_ke_free(payload);
  ske->ke2_payload = NULL;

  silc_mp_uninit(ske->KEY);
  silc_free(ske->KEY);
  ske->KEY = NULL;

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
				       bool mutual_auth)
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

  /* Force the mutual authentication flag if we want to do it. */
  if (mutual_auth) {
    SILC_LOG_DEBUG(("Force mutual authentication"));
    remote_payload->flags |= SILC_SKE_SP_FLAG_MUTUAL;
  }

  /* Parse and select the security properties from the payload */
  payload = silc_calloc(1, sizeof(*payload));
  status = silc_ske_select_security_properties(ske, version,
					       payload, remote_payload);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  ske->start_payload = payload;

  /* Call the callback function. */
  if (ske->callbacks->payload_receive)
    (*ske->callbacks->payload_receive)(ske, ske->callbacks->context);

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
					 SilcSKEStartPayload *start_payload)
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

  if (silc_hmac_alloc(start_payload->hmac_alg_list, NULL,
		      &prop->hmac) == FALSE) {
    status = SILC_SKE_STATUS_UNKNOWN_HMAC;
    goto err;
  }

  /* Encode the payload */
  status = silc_ske_payload_start_encode(ske, start_payload, &payload_buf);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  /* Send the packet. */
  if (ske->callbacks->send_packet)
    (*ske->callbacks->send_packet)(ske, payload_buf, SILC_PACKET_KEY_EXCHANGE, 
				  ske->callbacks->context);

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
  if (prop->hmac)
    silc_hmac_free(prop->hmac);
  silc_free(prop);
  ske->prop = NULL;

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* An responder phase 2 final callback that is called to indicate that
   the SKE protocol may continue. */

static void silc_ske_responder_phase2_final(SilcSKE ske,
					    SilcSKEStatus status,
					    void *context)
{
  SilcSKEKEPayload *recv_payload, *send_payload;
  SilcMPInt *x;

  /* If the SKE was freed during the async call then free it really now,
     otherwise just decrement the reference counter. */
  if (ske->status == SILC_SKE_STATUS_FREED) {
    silc_ske_free(ske);
    return;
  }

  /* If the caller returns PENDING status SKE library will assume that
     the caller will re-call this callback when it is not anymore in
     PENDING status. */
  if (status == SILC_SKE_STATUS_PENDING)
    return;

  ske->users--;
  recv_payload = ske->ke1_payload;

  /* If the status is an error then the public key that was verified
     by the caller is not authentic. */
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    if (ske->callbacks->proto_continue)
      ske->callbacks->proto_continue(ske, ske->callbacks->context);
    return;
  }

  /* The public key verification was performed only if the Mutual
     Authentication flag is set. */
  if (ske->start_payload && 
      ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL) {
    SilcPublicKey public_key = NULL;
    unsigned char hash[32];
    uint32 hash_len;

    /* Decode the public key */
    if (!silc_pkcs_public_key_decode(recv_payload->pk_data, 
				     recv_payload->pk_len, 
				     &public_key)) {
      ske->status = SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;
      if (ske->callbacks->proto_continue)
	ske->callbacks->proto_continue(ske, ske->callbacks->context);
      return;
    }

    SILC_LOG_DEBUG(("Public key is authentic"));

    /* Compute the hash value */
    status = silc_ske_make_hash(ske, hash, &hash_len, TRUE);
    if (status != SILC_SKE_STATUS_OK) {
      ske->status = status;
      if (ske->callbacks->proto_continue)
	ske->callbacks->proto_continue(ske, ske->callbacks->context);
      return;
    }

    SILC_LOG_DEBUG(("Verifying signature (HASH_i)"));
    
    /* Verify signature */
    silc_pkcs_public_key_set(ske->prop->pkcs, public_key);
    if (silc_pkcs_verify(ske->prop->pkcs, recv_payload->sign_data, 
			 recv_payload->sign_len, hash, hash_len) == FALSE) {
      
      SILC_LOG_DEBUG(("Signature don't match"));
      
      ske->status = SILC_SKE_STATUS_INCORRECT_SIGNATURE;
      if (ske->callbacks->proto_continue)
	ske->callbacks->proto_continue(ske, ske->callbacks->context);
      return;
    }
    
    SILC_LOG_DEBUG(("Signature is Ok"));
    
    silc_pkcs_public_key_free(public_key);
    memset(hash, 'F', hash_len);
  }

  /* Create the random number x, 1 < x < q. */
  x = silc_calloc(1, sizeof(*x));
  silc_mp_init(x);
  status = 
    silc_ske_create_rnd(ske, &ske->prop->group->group_order,
			silc_mp_sizeinbase(&ske->prop->group->group_order, 2),
			x);
  if (status != SILC_SKE_STATUS_OK) {
    silc_mp_uninit(x);
    silc_free(x);
    ske->status = status;
    if (ske->callbacks->proto_continue)
      ske->callbacks->proto_continue(ske, ske->callbacks->context);
    return;
  }

  /* Save the results for later processing */
  send_payload = silc_calloc(1, sizeof(*send_payload));
  ske->x = x;
  ske->ke2_payload = send_payload;

  SILC_LOG_DEBUG(("Computing f = g ^ x mod p"));

  /* Do the Diffie Hellman computation, f = g ^ x mod p */
  silc_mp_init(&send_payload->x);
  silc_mp_pow_mod(&send_payload->x, &ske->prop->group->generator, x, 
		  &ske->prop->group->group);
  
  /* Call the callback. The caller may now continue with the SKE protocol. */
  ske->status = SILC_SKE_STATUS_OK;
  if (ske->callbacks->proto_continue)
    ske->callbacks->proto_continue(ske, ske->callbacks->context);
}

/* This function receives the Key Exchange Payload from the initiator.
   This also performs the mutual authentication if required. Then, this 
   function first generated a random number x, such that 1 < x < q
   and computes f = g ^ x mod p. This then puts the result f to a Key
   Exchange Payload. 

   The `callback' will be called to indicate that the caller may
   continue with the SKE protocol.  The caller must not continue
   before the SKE libary has called that callback.  If this function
   returns an error the callback will not be called.  It is called
   if this function return SILC_SKE_STATUS_OK or SILC_SKE_STATUS_PENDING.
   However, note that when the library calls the callback the ske->status
   may be error.

   This calls the `verify_key' callback to verify the received public
   key or certificate if the Mutual Authentication flag is set. If the
   `verify_key' is provided then the remote must send public key and it
   is considered to be an error if remote does not send its public key. */

SilcSKEStatus silc_ske_responder_phase_2(SilcSKE ske,
					 SilcBuffer ke_payload)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcSKEKEPayload *recv_payload;

  SILC_LOG_DEBUG(("Start"));

  /* Decode Key Exchange Payload */
  status = silc_ske_payload_ke_decode(ske, ke_payload, &recv_payload);
  if (status != SILC_SKE_STATUS_OK) {
    ske->status = status;
    return status;
  }

  ske->ke1_payload = recv_payload;

  /* Verify the received public key and verify the signature if we are
     doing mutual authentication. */
  if (ske->start_payload && 
      ske->start_payload->flags & SILC_SKE_SP_FLAG_MUTUAL) {

    SILC_LOG_DEBUG(("We are doing mutual authentication"));
    
    if (!recv_payload->pk_data && ske->callbacks->verify_key) {
      SILC_LOG_DEBUG(("Remote end did not send its public key (or "
		      "certificate), even though we require it"));
      ske->status = SILC_SKE_STATUS_PUBLIC_KEY_NOT_PROVIDED;
      return status;
    }

    if (recv_payload->pk_data && ske->callbacks->verify_key) {
      SILC_LOG_DEBUG(("Verifying public key"));

      ske->users++;
      (*ske->callbacks->verify_key)(ske, recv_payload->pk_data, 
				    recv_payload->pk_len,
				    recv_payload->pk_type, 
				    ske->callbacks->context,
				    silc_ske_responder_phase2_final, NULL);

      /* We will continue to the final state after the public key has
	 been verified by the caller. */
      return SILC_SKE_STATUS_PENDING;
    }
  }

  /* Continue to final state */
  silc_ske_responder_phase2_final(ske, SILC_SKE_STATUS_OK, NULL);

  return SILC_SKE_STATUS_OK;
}

/* This functions generates the secret key KEY = e ^ x mod p, and, a hash
   value to be signed and sent to the other end. This then encodes Key
   Exchange Payload and sends it to the other end. */

SilcSKEStatus silc_ske_responder_finish(SilcSKE ske,
					SilcPublicKey public_key,
					SilcPrivateKey private_key,
					SilcSKEPKType pk_type)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer payload_buf;
  SilcMPInt *KEY;
  unsigned char hash[32], sign[1024], *pk;
  uint32 hash_len, sign_len, pk_len;

  SILC_LOG_DEBUG(("Start"));

  SILC_LOG_DEBUG(("Computing KEY = e ^ x mod p"));

  /* Compute the shared secret key */
  KEY = silc_calloc(1, sizeof(*KEY));
  silc_mp_init(KEY);
  silc_mp_pow_mod(KEY, &ske->ke1_payload->x, ske->x, 
		  &ske->prop->group->group);
  ske->KEY = KEY;

  if (public_key && private_key) {
    SILC_LOG_DEBUG(("Getting public key"));
    
    /* Get the public key */
    pk = silc_pkcs_public_key_encode(public_key, &pk_len);
    if (!pk) {
      status = SILC_SKE_STATUS_ERROR;
      goto err;
    }
    ske->ke2_payload->pk_data = pk;
    ske->ke2_payload->pk_len = pk_len;
    
    SILC_LOG_DEBUG(("Computing HASH value"));
    
    /* Compute the hash value */
    memset(hash, 0, sizeof(hash));
    status = silc_ske_make_hash(ske, hash, &hash_len, FALSE);
    if (status != SILC_SKE_STATUS_OK)
      goto err;

    ske->hash = silc_calloc(hash_len, sizeof(unsigned char));
    memcpy(ske->hash, hash, hash_len);
    ske->hash_len = hash_len;
    
    SILC_LOG_DEBUG(("Signing HASH value"));
    
    /* Sign the hash value */
    silc_pkcs_private_key_data_set(ske->prop->pkcs, private_key->prv, 
				   private_key->prv_len);
    silc_pkcs_sign(ske->prop->pkcs, hash, hash_len, sign, &sign_len);
    ske->ke2_payload->sign_data = silc_calloc(sign_len, sizeof(unsigned char));
    memcpy(ske->ke2_payload->sign_data, sign, sign_len);
    memset(sign, 0, sizeof(sign));
    ske->ke2_payload->sign_len = sign_len;
  }
  ske->ke2_payload->pk_type = pk_type;

  /* Encode the Key Exchange Payload */
  status = silc_ske_payload_ke_encode(ske, ske->ke2_payload,
				      &payload_buf);
  if (status != SILC_SKE_STATUS_OK)
    goto err;

  /* Send the packet. */
  if (ske->callbacks->send_packet)
    (*ske->callbacks->send_packet)(ske, payload_buf, 
				   SILC_PACKET_KEY_EXCHANGE_2,
				   ske->callbacks->context);

  silc_buffer_free(payload_buf);

  return status;

 err:
  silc_mp_uninit(ske->KEY);
  silc_free(ske->KEY);
  ske->KEY = NULL;
  silc_ske_payload_ke_free(ske->ke2_payload);

  if (status == SILC_SKE_STATUS_OK)
    return SILC_SKE_STATUS_ERROR;

  ske->status = status;
  return status;
}

/* The Key Exchange protocol is ended by calling this function. This
   must not be called until the keys are processed like the protocol
   defines. This function is for both initiator and responder. */

SilcSKEStatus silc_ske_end(SilcSKE ske)
{
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Start"));

  packet = silc_buffer_alloc(4);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_INT((uint32)SILC_SKE_STATUS_OK),
		     SILC_STR_END);

  if (ske->callbacks->send_packet)
    (*ske->callbacks->send_packet)(ske, packet, SILC_PACKET_SUCCESS, 
				   ske->callbacks->context);

  silc_buffer_free(packet);

  return SILC_SKE_STATUS_OK;
}

/* Aborts the Key Exchange protocol. This is called if error occurs
   while performing the protocol. The status argument is the error
   status and it is sent to the remote end. */

SilcSKEStatus silc_ske_abort(SilcSKE ske, SilcSKEStatus status)
{
  SilcBuffer packet;

  SILC_LOG_DEBUG(("Start"));

  packet = silc_buffer_alloc(4);
  silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
  silc_buffer_format(packet,
		     SILC_STR_UI_INT((uint32)status),
		     SILC_STR_END);

  if (ske->callbacks->send_packet)
    (*ske->callbacks->send_packet)(ske, packet, SILC_PACKET_FAILURE, 
				   ske->callbacks->context);

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

  /* Get supported HMACs */
  rp->hmac_alg_list = silc_hmac_get_supported();
  rp->hmac_alg_len = strlen(rp->hmac_alg_list);

  /* XXX */
  /* Get supported compression algorithms */
  rp->comp_alg_list = strdup("");
  rp->comp_alg_len = 0;

  rp->len = 1 + 1 + 2 + SILC_SKE_COOKIE_LEN + 
    2 + rp->version_len +
    2 + rp->ke_grp_len + 2 + rp->pkcs_alg_len + 
    2 + rp->enc_alg_len + 2 + rp->hash_alg_len + 
    2 + rp->hmac_alg_len + 2 + rp->comp_alg_len;

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
  if (ske->callbacks->check_version) {
    status = ske->callbacks->check_version(ske, rp->version, 
					   rp->version_len,
					   ske->callbacks->context);
    if (status != SILC_SKE_STATUS_OK) {
      ske->status = status;
      return status;
    }
  }

  /* Flags are returned unchanged. */
  payload->flags = rp->flags;

  /* Take cookie, we must return it to sender unmodified. */
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

  /* Get supported HMACs */
  cp = rp->hmac_alg_list;
  if (cp && strchr(cp, ',')) {
    while(cp) {
      char *item;

      len = strcspn(cp, ",");
      item = silc_calloc(len + 1, sizeof(char));
      memcpy(item, cp, len);

      SILC_LOG_DEBUG(("Proposed HMAC `%s'", item));

      if (silc_hmac_is_supported(item) == TRUE) {
	SILC_LOG_DEBUG(("Found HMAC `%s'", item));

	payload->hmac_alg_len = len;
	payload->hmac_alg_list = item;
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

    if (!payload->hmac_alg_len && !payload->hmac_alg_list) {
      SILC_LOG_DEBUG(("Could not find supported HMAC"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload->hash_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_UNKNOWN_HMAC;
    }
  } else {

    if (!rp->hmac_alg_len) {
      SILC_LOG_DEBUG(("HMAC not defined in payload"));
      silc_free(payload->ke_grp_list);
      silc_free(payload->pkcs_alg_list);
      silc_free(payload->enc_alg_list);
      silc_free(payload->hash_alg_list);
      silc_free(payload);
      return SILC_SKE_STATUS_BAD_PAYLOAD;
    }

    SILC_LOG_DEBUG(("Proposed HMAC `%s' and selected it",
		    rp->hmac_alg_list));

    payload->hmac_alg_len = rp->hmac_alg_len;
    payload->hmac_alg_list = strdup(rp->hmac_alg_list);
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
    2 + payload->hmac_alg_len + 2 + payload->comp_alg_len;

  return SILC_SKE_STATUS_OK;
}

/* Creates random number such that 1 < rnd < n and at most length
   of len bits. The rnd sent as argument must be initialized. */

SilcSKEStatus silc_ske_create_rnd(SilcSKE ske, SilcMPInt *n, 
				  uint32 len, 
				  SilcMPInt *rnd)
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

  if (silc_mp_cmp(rnd, n) >= 0)
    status = SILC_SKE_STATUS_ERROR;

  memset(string, 'F', (len / 8));
  silc_free(string);

  return status;
}

/* Creates a hash value HASH as defined in the SKE protocol. If the
   `initiator' is TRUE then this function is used to create the HASH_i
   hash value defined in the protocol. If it is FALSE then this is used
   to create the HASH value defined by the protocol. */

SilcSKEStatus silc_ske_make_hash(SilcSKE ske, 
				 unsigned char *return_hash,
				 uint32 *return_hash_len,
				 int initiator)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  SilcBuffer buf;
  unsigned char *e, *f, *KEY;
  uint32 e_len, f_len, KEY_len;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  if (initiator == FALSE) {
    e = silc_mp_mp2bin(&ske->ke1_payload->x, 0, &e_len);
    f = silc_mp_mp2bin(&ske->ke2_payload->x, 0, &f_len);
    KEY = silc_mp_mp2bin(ske->KEY, 0, &KEY_len);
    
    buf = silc_buffer_alloc(ske->start_payload_copy->len + 
			    ske->ke2_payload->pk_len + e_len + 
			    f_len + KEY_len);
    silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

    /* Format the buffer used to compute the hash value */
    ret = 
      silc_buffer_format(buf,
			 SILC_STR_UI_XNSTRING(ske->start_payload_copy->data,
					      ske->start_payload_copy->len),
			 SILC_STR_UI_XNSTRING(ske->ke2_payload->pk_data, 
					      ske->ke2_payload->pk_len),
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

    memset(e, 0, e_len);
    memset(f, 0, f_len);
    memset(KEY, 0, KEY_len);
    silc_free(e);
    silc_free(f);
    silc_free(KEY);
  } else {
    e = silc_mp_mp2bin(&ske->ke1_payload->x, 0, &e_len);

    buf = silc_buffer_alloc(ske->start_payload_copy->len + 
			    ske->ke1_payload->pk_len + e_len);
    silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
    
    /* Format the buffer used to compute the hash value */
    ret = 
      silc_buffer_format(buf,
			 SILC_STR_UI_XNSTRING(ske->start_payload_copy->data,
					      ske->start_payload_copy->len),
			 SILC_STR_UI_XNSTRING(ske->ke1_payload->pk_data, 
					      ske->ke1_payload->pk_len),
			 SILC_STR_UI_XNSTRING(e, e_len),
			 SILC_STR_END);
    if (ret == -1) {
      silc_buffer_free(buf);
      memset(e, 0, e_len);
      silc_free(e);
      return SILC_SKE_STATUS_ERROR;
    }

    memset(e, 0, e_len);
    silc_free(e);
  }

  /* Make the hash */
  silc_hash_make(ske->prop->hash, buf->data, buf->len, return_hash);
  *return_hash_len = ske->prop->hash->hash->hash_len;

  if (initiator == FALSE) {
    SILC_LOG_HEXDUMP(("HASH"), return_hash, *return_hash_len);
  } else {
    SILC_LOG_HEXDUMP(("HASH_i"), return_hash, *return_hash_len);
  }

  silc_buffer_free(buf);

  return status;
}

/* Processes the provided key material `data' as the SILC protocol 
   specification defines. */

SilcSKEStatus 
silc_ske_process_key_material_data(unsigned char *data,
				   uint32 data_len,
				   uint32 req_iv_len,
				   uint32 req_enc_key_len,
				   uint32 req_hmac_key_len,
				   SilcHash hash,
				   SilcSKEKeyMaterial *key)
{
  SilcBuffer buf;
  unsigned char hashd[32];
  uint32 hash_len = req_hmac_key_len;
  uint32 enc_key_len = req_enc_key_len / 8;

  SILC_LOG_DEBUG(("Start"));

  if (!req_iv_len || !req_enc_key_len || !req_hmac_key_len)
    return SILC_SKE_STATUS_ERROR;

  buf = silc_buffer_alloc(1 + data_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
  silc_buffer_format(buf,
		     SILC_STR_UI_CHAR(0),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_END);

  /* Take IVs */
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 0;
  silc_hash_make(hash, buf->data, buf->len, hashd);
  key->send_iv = silc_calloc(req_iv_len, sizeof(unsigned char));
  memcpy(key->send_iv, hashd, req_iv_len);
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 1;
  silc_hash_make(hash, buf->data, buf->len, hashd);
  key->receive_iv = silc_calloc(req_iv_len, sizeof(unsigned char));
  memcpy(key->receive_iv, hashd, req_iv_len);
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
    
    /* Take first round */
    memset(k1, 0, sizeof(k1));
    silc_hash_make(hash, buf->data, buf->len, k1);
    
    /* Take second round */
    dist = silc_buffer_alloc(data_len + hash_len);
    silc_buffer_pull_tail(dist, SILC_BUFFER_END(dist));
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(data, data_len),
		       SILC_STR_UI_XNSTRING(k1, hash_len),
		       SILC_STR_END);
    memset(k2, 0, sizeof(k2));
    silc_hash_make(hash, dist->data, dist->len, k2);
    
    /* Take third round */
    dist = silc_buffer_realloc(dist, data_len + hash_len + hash_len);
    silc_buffer_pull_tail(dist, hash_len);
    silc_buffer_pull(dist, data_len + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(k2, hash_len),
		       SILC_STR_END);
    silc_buffer_push(dist, data_len + hash_len);
    memset(k3, 0, sizeof(k3));
    silc_hash_make(hash, dist->data, dist->len, k3);

    /* Then, save the keys */
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
    memset(hashd, 0, sizeof(hashd));
    silc_hash_make(hash, buf->data, buf->len, hashd);
    key->send_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->send_enc_key, hashd, enc_key_len);
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
    
    /* Take first round */
    memset(k1, 0, sizeof(k1));
    silc_hash_make(hash, buf->data, buf->len, k1);
    
    /* Take second round */
    dist = silc_buffer_alloc(data_len + hash_len);
    silc_buffer_pull_tail(dist, SILC_BUFFER_END(dist));
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(data, data_len),
		       SILC_STR_UI_XNSTRING(k1, hash_len),
		       SILC_STR_END);
    memset(k2, 0, sizeof(k2));
    silc_hash_make(hash, dist->data, dist->len, k2);
    
    /* Take third round */
    dist = silc_buffer_realloc(dist, data_len + hash_len + hash_len);
    silc_buffer_pull_tail(dist, hash_len);
    silc_buffer_pull(dist, data_len + hash_len);
    silc_buffer_format(dist,
		       SILC_STR_UI_XNSTRING(k2, hash_len),
		       SILC_STR_END);
    silc_buffer_push(dist, data_len + hash_len);
    memset(k3, 0, sizeof(k3));
    silc_hash_make(hash, dist->data, dist->len, k3);

    /* Then, save the keys */
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
    memset(hashd, 0, sizeof(hashd));
    silc_hash_make(hash, buf->data, buf->len, hashd);
    key->receive_enc_key = silc_calloc(enc_key_len, sizeof(unsigned char));
    memcpy(key->receive_enc_key, hashd, enc_key_len);
    key->enc_key_len = req_enc_key_len;
  }

  /* Take HMAC key */
  memset(hashd, 0, sizeof(hashd));
  buf->data[0] = 4;
  silc_hash_make(hash, buf->data, buf->len, hashd);
  key->hmac_key = silc_calloc(req_hmac_key_len, sizeof(unsigned char));
  memcpy(key->hmac_key, hashd, req_hmac_key_len);
  key->hmac_key_len = req_hmac_key_len;

  silc_buffer_free(buf);

  return SILC_SKE_STATUS_OK;
}

/* Processes negotiated key material as protocol specifies. This returns
   the actual keys to be used in the SILC. */

SilcSKEStatus silc_ske_process_key_material(SilcSKE ske, 
					    uint32 req_iv_len,
					    uint32 req_enc_key_len,
					    uint32 req_hmac_key_len,
					    SilcSKEKeyMaterial *key)
{
  SilcSKEStatus status;
  SilcBuffer buf;
  unsigned char *tmpbuf;
  uint32 klen;

  /* Encode KEY to binary data */
  tmpbuf = silc_mp_mp2bin(ske->KEY, 0, &klen);

  buf = silc_buffer_alloc(klen + ske->hash_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
  silc_buffer_format(buf,
		     SILC_STR_UI_XNSTRING(tmpbuf, klen),
		     SILC_STR_UI_XNSTRING(ske->hash, ske->hash_len),
		     SILC_STR_END);

  /* Process the key material */
  status = silc_ske_process_key_material_data(buf->data, buf->len,
					      req_iv_len, req_enc_key_len,
					      req_hmac_key_len, 
					      ske->prop->hash, key);

  memset(tmpbuf, 0, klen);
  silc_free(tmpbuf);
  silc_buffer_free(buf);

  return status;
}

/* Free key material structure */

void silc_ske_free_key_material(SilcSKEKeyMaterial *key)
{
  if (!key)
    return;

  if (key->send_iv)
    silc_free(key->send_iv);
  if (key->receive_iv)
    silc_free(key->receive_iv);
  if (key->send_enc_key) {
    memset(key->send_enc_key, 0, key->enc_key_len / 8);
    silc_free(key->send_enc_key);
  }
  if (key->receive_enc_key) {
    memset(key->receive_enc_key, 0, key->enc_key_len / 8);
    silc_free(key->receive_enc_key);
  }
  if (key->hmac_key) {
    memset(key->hmac_key, 0, key->hmac_key_len);
    silc_free(key->hmac_key);
  }
  silc_free(key);
}
