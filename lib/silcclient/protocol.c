/*

  protocol.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Client side of the protocols.
 */
/* $Id$ */

#include "clientlibincludes.h"
#include "client_internal.h"

SILC_TASK_CALLBACK(silc_client_protocol_connection_auth);
SILC_TASK_CALLBACK(silc_client_protocol_key_exchange);

extern char *silc_version_string;

/*
 * Key Exhange protocol functions
 */

/* Function that is called when SKE protocol sends packets to network. */

void silc_client_protocol_ke_send_packet(SilcSKE ske,
					 SilcBuffer packet,
					 SilcPacketType type,
					 void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;

  /* Send the packet immediately */
  silc_client_packet_send(client, ske->sock, type, NULL, 0, NULL, NULL,
			  packet->data, packet->len, TRUE);

}

/* Callback that is called when we have received KE2 payload from
   responder. We try to verify the public key now. */

SilcSKEStatus silc_client_protocol_ke_verify_key(SilcSKE ske,
						 unsigned char *pk_data,
						 unsigned int pk_len,
						 SilcSKEPKType pk_type,
						 void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;

  SILC_LOG_DEBUG(("Start"));

  /* Verify public key from user. */
  if (!client->ops->verify_public_key(client, ctx->sock->user_data, 
				      ctx->sock->type,
				      pk_data, pk_len, pk_type))
    return SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;

  return SILC_SKE_STATUS_OK;
}

/* Sets the negotiated key material into use for particular connection. */

void silc_client_protocol_ke_set_keys(SilcSKE ske,
				      SilcSocketConnection sock,
				      SilcSKEKeyMaterial *keymat,
				      SilcCipher cipher,
				      SilcPKCS pkcs,
				      SilcHash hash,
				      SilcHmac hmac)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;

  SILC_LOG_DEBUG(("Setting new keys into use"));

  /* Allocate cipher to be used in the communication */
  silc_cipher_alloc(cipher->cipher->name, &conn->send_key);
  silc_cipher_alloc(cipher->cipher->name, &conn->receive_key);

  conn->send_key->cipher->set_key(conn->send_key->context, 
				 keymat->send_enc_key, 
				 keymat->enc_key_len);
  conn->send_key->set_iv(conn->send_key, keymat->send_iv);
  conn->receive_key->cipher->set_key(conn->receive_key->context, 
				    keymat->receive_enc_key, 
				    keymat->enc_key_len);
  conn->receive_key->set_iv(conn->receive_key, keymat->receive_iv);

  /* Allocate PKCS to be used */
#if 0
  /* XXX Do we ever need to allocate PKCS for the connection??
     If yes, we need to change KE protocol to get the initiators
     public key. */
  silc_pkcs_alloc(pkcs->pkcs->name, &conn->public_Key);
  silc_pkcs_set_public_key(conn->public_key, ske->ke2_payload->pk_data, 
			   ske->ke2_payload->pk_len);
#endif

  /* Save HMAC key to be used in the communication. */
  silc_hmac_alloc(hmac->hmac->name, NULL, &conn->hmac);
  silc_hmac_set_key(conn->hmac, keymat->hmac_key, keymat->hmac_key_len);

  /* Save the HASH function */
  silc_hash_alloc(hash->hash->name, &conn->hash);
}

/* Checks the version string of the server. */

SilcSKEStatus silc_ske_check_version(SilcSKE ske, unsigned char *version,
				     unsigned int len)
{
  SilcClientConnection conn = (SilcClientConnection)ske->sock->user_data;
  SilcClient client = (SilcClient)ske->user_data;
  SilcSKEStatus status = SILC_SKE_STATUS_OK;

  /* Check for initial version string */
  if (!strstr(version, "SILC-1.0-"))
    status = SILC_SKE_STATUS_BAD_VERSION;

  /* Check software version */

  if (len < strlen(silc_version_string))
    status = SILC_SKE_STATUS_BAD_VERSION;

  /* XXX for now there is no other tests due to the abnormal version
     string that is used */

  if (status != SILC_SKE_STATUS_OK)
    client->ops->say(client, conn, 
		     "We don't support server version `%s'", version);

  return status;
}

/* Performs key exchange protocol. This is used for both initiator
   and responder key exchange. This may be called recursively. */

SILC_TASK_CALLBACK(silc_client_protocol_key_exchange)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientConnection conn = ctx->sock->user_data;
  SilcSKEStatus status = 0;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_UNKNOWN)
    protocol->state = SILC_PROTOCOL_STATE_START;

  switch(protocol->state) {
  case SILC_PROTOCOL_STATE_START:
    {
      /*
       * Start Protocol
       */
      SilcSKE ske;

      /* Allocate Key Exchange object */
      ske = silc_ske_alloc();
      ctx->ske = ske;
      ske->rng = client->rng;
      ske->user_data = (void *)client;
      
      if (ctx->responder == TRUE) {
	/* Start the key exchange by processing the received security
	   properties packet from initiator. */
	status = silc_ske_responder_start(ske, ctx->rng, ctx->sock,
					  silc_version_string,
					  ctx->packet->buffer, TRUE,
					  NULL, NULL);
      } else {
	SilcSKEStartPayload *start_payload;

	/* Assemble security properties. */
	silc_ske_assemble_security_properties(ske, SILC_SKE_SP_FLAG_NONE, 
					      silc_version_string,
					      &start_payload);

	/* Start the key exchange by sending our security properties
	   to the remote end. */
	status = silc_ske_initiator_start(ske, ctx->rng, ctx->sock,
					  start_payload,
					  ctx->send_packet,
					  context);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
	return;
      }

      /* Advance protocol state and call the next state if we are responder */
      protocol->state++;
      if (ctx->responder == TRUE)
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 100000);
    }
    break;
  case 2:
    {
      /* 
       * Phase 1 
       */
      if (ctx->responder == TRUE) {
	/* Sends the selected security properties to the initiator. */
	status = 
	  silc_ske_responder_phase_1(ctx->ske, 
				     ctx->ske->start_payload,
				     ctx->send_packet,
				     context);
      } else {
	/* Call Phase-1 function. This processes the Key Exchange Start
	   paylaod reply we just got from the responder. The callback
	   function will receive the processed payload where we will
	   save it. */
	status = silc_ske_initiator_phase_1(ctx->ske, ctx->packet->buffer, 
					    NULL, NULL);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
	return;
      }

      /* Advance protocol state and call next state if we are initiator */
      protocol->state++;
      if (ctx->responder == FALSE)
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 100000);
    }
    break;
  case 3:
    {
      /* 
       * Phase 2 
       */
      if (ctx->responder == TRUE) {
	/* Process the received Key Exchange 1 Payload packet from
	   the initiator. This also creates our parts of the Diffie
	   Hellman algorithm. */
	status = silc_ske_responder_phase_2(ctx->ske, ctx->packet->buffer, 
					    ctx->verify, context, NULL, NULL);
      } else {
	/* Call the Phase-2 function. This creates Diffie Hellman
	   key exchange parameters and sends our public part inside
	   Key Exhange 1 Payload to the responder. */
	status = silc_ske_initiator_phase_2(ctx->ske,
					    client->public_key,
					    client->private_key,
					    ctx->send_packet,
					    context);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
	return;
      }

      /* Advance protocol state and call the next state if we are responder */
      protocol->state++;
      if (ctx->responder == TRUE)
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 100000);
    }
    break;
  case 4:
    {
      /* 
       * Finish protocol
       */
      if (ctx->responder == TRUE) {
	/* This creates the key exchange material and sends our
	   public parts to the initiator inside Key Exchange 2 Payload. */
	status = 
	  silc_ske_responder_finish(ctx->ske, 
				    client->public_key, client->private_key,
				    SILC_SKE_PK_TYPE_SILC,
				    ctx->send_packet,
				    context);
	status = 0;
      } else {
	/* Finish the protocol. This verifies the Key Exchange 2 payload
	   sent by responder. */
	status = silc_ske_initiator_finish(ctx->ske, ctx->packet->buffer,
					   ctx->verify, context, NULL, NULL);
      }

      if (status != SILC_SKE_STATUS_OK) {

        if (status == SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY) {
          client->ops->say(client, conn, 
			   "Received unsupported server %s public key",
			   ctx->sock->hostname);
        } else {
          client->ops->say(client, conn,
			   "Error during key exchange protocol with server %s",
			   ctx->sock->hostname);
        }
	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
	return;
      }
      
      /* Send Ok to the other end. We will end the protocol as server
	 sends Ok to us when we will take the new keys into use. */
      if (ctx->responder == FALSE)
	silc_ske_end(ctx->ske, ctx->send_packet, context);
      
      /* End the protocol on the next round */
      protocol->state = SILC_PROTOCOL_STATE_END;
    }
    break;

  case SILC_PROTOCOL_STATE_END:
    {
      /* 
       * End protocol
       */
      SilcSKEKeyMaterial *keymat;
      int key_len = silc_cipher_get_key_len(ctx->ske->prop->cipher);
      int hash_len = ctx->ske->prop->hash->hash->hash_len;

      /* Process the key material */
      keymat = silc_calloc(1, sizeof(*keymat));
      status = silc_ske_process_key_material(ctx->ske, 16, key_len, hash_len,
					     keymat);
      if (status != SILC_SKE_STATUS_OK) {
	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 300000);
	silc_ske_free_key_material(keymat);
	return;
      }
      ctx->keymat = keymat;

      /* Send Ok to the other end if we are responder. If we are initiator
	 we have sent this already. */
      if (ctx->responder == TRUE)
	silc_ske_end(ctx->ske, ctx->send_packet, context);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_task_unregister(client->timeout_queue, ctx->timeout_task);

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	protocol->execute_final(client->timeout_queue, 0, protocol, fd);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /*
     * Error during protocol
     */
    
    /* Send abort notification */
    silc_ske_abort(ctx->ske, ctx->ske->status, 
		   ctx->send_packet, context);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      protocol->execute_final(client->timeout_queue, 0, protocol, fd);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * Received failure from remote.
     */

    /* Unregister the timeout task since the protocol has ended. 
       This was the timeout task to be executed if the protocol is
       not completed fast enough. */
    if (ctx->timeout_task)
      silc_task_unregister(client->timeout_queue, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      protocol->execute_final(client->timeout_queue, 0, protocol, fd);
    else
      silc_protocol_free(protocol);
    break;
  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }
}

/*
 * Connection Authentication protocol functions
 */

static int
silc_client_get_public_key_auth(SilcClient client,
				char *filepath,
				unsigned char *auth_data,
				unsigned int *auth_data_len,
				SilcSKE ske)
{
  int len;
  SilcPKCS pkcs;
  SilcBuffer auth;
  SilcPublicKey pub_key;

  if (!silc_pkcs_load_public_key(filepath,&pub_key, SILC_PKCS_FILE_PEM))
    if (!silc_pkcs_load_public_key(filepath, &pub_key, SILC_PKCS_FILE_BIN))
      return FALSE;

  silc_pkcs_alloc(pub_key->name, &pkcs);
  if (!silc_pkcs_public_key_set(pkcs, pub_key)) {
    silc_pkcs_free(pkcs);
    silc_pkcs_public_key_free(pub_key);
    return FALSE;
  }

  /* Make the authentication data. Protocol says it is HASH plus
     KE Start Payload. */
  len = ske->hash_len + ske->start_payload_copy->len;
  auth = silc_buffer_alloc(len);
  silc_buffer_pull_tail(auth, len);
  silc_buffer_format(auth,
		     SILC_STR_UI_XNSTRING(ske->hash, ske->hash_len),
		     SILC_STR_UI_XNSTRING(ske->start_payload_copy->data,
					  ske->start_payload_copy->len),
		     SILC_STR_END);

  if (silc_pkcs_sign(pkcs, auth->data, auth->len, auth_data, auth_data_len)) {
    silc_pkcs_free(pkcs);
    silc_buffer_free(auth);
    silc_pkcs_public_key_free(pub_key);
    return TRUE;
  }

  silc_pkcs_free(pkcs);
  silc_buffer_free(auth);
  silc_pkcs_public_key_free(pub_key);
  return FALSE;
}

SILC_TASK_CALLBACK(silc_client_protocol_connection_auth)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientConnAuthInternalContext *ctx = 
    (SilcClientConnAuthInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientConnection conn = ctx->sock->user_data;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_UNKNOWN)
    protocol->state = SILC_PROTOCOL_STATE_START;

  switch(protocol->state) {
  case SILC_PROTOCOL_STATE_START:
    {
      /* 
       * Start protocol. We send authentication data to the server
       * to be authenticated.
       */
      SilcBuffer packet;
      int payload_len = 0;
      unsigned char *auth_data = NULL;
      unsigned int auth_data_len = 0;

      switch(ctx->auth_meth) {
      case SILC_AUTH_NONE:
	/* No authentication required */
	break;

      case SILC_AUTH_PASSWORD:
	/* Password authentication */
	if (ctx->auth_data && ctx->auth_data_len) {
	  auth_data = ctx->auth_data;
	  auth_data_len = ctx->auth_data_len;
	  break;
	}

	client->ops->say(client, conn, 
			 "Password authentication required by server %s",
			 ctx->sock->hostname);
	auth_data = client->ops->ask_passphrase(client, conn);
	auth_data_len = strlen(auth_data);
	break;

      case SILC_AUTH_PUBLIC_KEY:
	{
	  unsigned char sign[1024];

	  /* Public key authentication */
	  silc_client_get_public_key_auth(client, ctx->auth_data,
					  sign, &auth_data_len, 
					  ctx->ske);
	  auth_data = silc_calloc(auth_data_len, sizeof(*auth_data));
	  memcpy(auth_data, sign, auth_data_len);
	  break;
	}
      }

      payload_len = 4 + auth_data_len;
      packet = silc_buffer_alloc(payload_len);
      silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
      silc_buffer_format(packet,
			 SILC_STR_UI_SHORT(payload_len),
			 SILC_STR_UI_SHORT(SILC_SOCKET_TYPE_CLIENT),
			 SILC_STR_UI_XNSTRING(auth_data, auth_data_len),
			 SILC_STR_END);

      /* Send the packet to server */
      silc_client_packet_send(client, ctx->sock,
			      SILC_PACKET_CONNECTION_AUTH,
			      NULL, 0, NULL, NULL,
			      packet->data, packet->len, TRUE);

      if (auth_data) {
	memset(auth_data, 0, auth_data_len);
	silc_free(auth_data);
      }
      silc_buffer_free(packet);
      
      /* Next state is end of protocol */
      protocol->state = SILC_PROTOCOL_STATE_END;
    }
    break;

  case SILC_PROTOCOL_STATE_END:
    {
      /* 
       * End protocol. Nothing special to be done here.
       */

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	protocol->execute_final(client->timeout_queue, 0, protocol, fd);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    {
      /* 
       * Error. Send notify to remote.
       */
      unsigned char error[4];

      SILC_PUT32_MSB(SILC_AUTH_FAILED, error);

      /* Error in protocol. Send FAILURE packet. Although I don't think
	 this could ever happen on client side. */
      silc_client_packet_send(client, ctx->sock, SILC_PACKET_FAILURE,
			      NULL, 0, NULL, NULL, error, 4, TRUE);

      /* On error the final callback is always called. */
      if (protocol->final_callback)
	protocol->execute_final(client->timeout_queue, 0, protocol, fd);
      else
	silc_protocol_free(protocol);
    }

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * Received failure from remote.
     */

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      protocol->execute_final(client->timeout_queue, 0, protocol, fd);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }
}

/* Registers protocols used in client */

void silc_client_protocols_register(void)
{
  silc_protocol_register(SILC_PROTOCOL_CLIENT_CONNECTION_AUTH,
			 silc_client_protocol_connection_auth);
  silc_protocol_register(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE,
			 silc_client_protocol_key_exchange);
}

/* Unregisters protocols */

void silc_client_protocols_unregister(void)
{
  silc_protocol_unregister(SILC_PROTOCOL_CLIENT_CONNECTION_AUTH,
		  	   silc_client_protocol_connection_auth);
  silc_protocol_unregister(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE,
			   silc_client_protocol_key_exchange);
}
