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

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

SILC_TASK_CALLBACK(silc_client_protocol_connection_auth);
SILC_TASK_CALLBACK(silc_client_protocol_key_exchange);
SILC_TASK_CALLBACK(silc_client_protocol_rekey);

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

/* Public key verification callback. Called by the application. */

typedef struct {
  SilcSKE ske;
  SilcSKEVerifyCbCompletion completion;
  void *completion_context;
} *VerifyKeyContext;

static void silc_client_verify_key_cb(bool success, void *context)
{
  VerifyKeyContext verify = (VerifyKeyContext)context;

  SILC_LOG_DEBUG(("Start"));

  /* Call the completion callback back to the SKE */
  verify->completion(verify->ske, success ? SILC_SKE_STATUS_OK : 
		     SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY, 
		     verify->completion_context);

  silc_free(verify);
}

/* Callback that is called when we have received KE payload from
   responder. We try to verify the public key now. */

void silc_client_protocol_ke_verify_key(SilcSKE ske,
					unsigned char *pk_data,
					SilcUInt32 pk_len,
					SilcSKEPKType pk_type,
					void *context,
					SilcSKEVerifyCbCompletion completion,
					void *completion_context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  VerifyKeyContext verify;

  SILC_LOG_DEBUG(("Start"));

  verify = silc_calloc(1, sizeof(*verify));
  verify->ske = ske;
  verify->completion = completion;
  verify->completion_context = completion_context;

  /* Verify public key from user. */
  client->internal->ops->verify_public_key(client, ctx->sock->user_data, 
					   ctx->sock->type,
					   pk_data, pk_len, pk_type,
					   silc_client_verify_key_cb, verify);
}

/* Sets the negotiated key material into use for particular connection. */

void silc_client_protocol_ke_set_keys(SilcSKE ske,
				      SilcSocketConnection sock,
				      SilcSKEKeyMaterial *keymat,
				      SilcCipher cipher,
				      SilcPKCS pkcs,
				      SilcHash hash,
				      SilcHmac hmac,
				      SilcSKEDiffieHellmanGroup group,
				      bool is_responder)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;

  SILC_LOG_DEBUG(("Setting new keys into use"));

  /* Allocate cipher to be used in the communication */
  silc_cipher_alloc(cipher->cipher->name, &conn->send_key);
  silc_cipher_alloc(cipher->cipher->name, &conn->receive_key);
  silc_hmac_alloc((char *)silc_hmac_get_name(hmac), NULL, &conn->hmac_send);
  silc_hmac_alloc((char *)silc_hmac_get_name(hmac), NULL, &conn->hmac_receive);

  if (is_responder == TRUE) {
    silc_cipher_set_key(conn->send_key, keymat->receive_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(conn->send_key, keymat->receive_iv);
    silc_cipher_set_key(conn->receive_key, keymat->send_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(conn->receive_key, keymat->send_iv);
    silc_hmac_set_key(conn->hmac_send, keymat->receive_hmac_key, 
		      keymat->hmac_key_len);
    silc_hmac_set_key(conn->hmac_receive, keymat->send_hmac_key, 
		      keymat->hmac_key_len);
  } else {
    silc_cipher_set_key(conn->send_key, keymat->send_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(conn->send_key, keymat->send_iv);
    silc_cipher_set_key(conn->receive_key, keymat->receive_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(conn->receive_key, keymat->receive_iv);
    silc_hmac_set_key(conn->hmac_send, keymat->send_hmac_key, 
		      keymat->hmac_key_len);
    silc_hmac_set_key(conn->hmac_receive, keymat->receive_hmac_key, 
		      keymat->hmac_key_len);
  }

  /* Rekey stuff */
  conn->rekey = silc_calloc(1, sizeof(*conn->rekey));
  conn->rekey->send_enc_key = silc_memdup(keymat->send_enc_key, 
					  keymat->enc_key_len / 8);
  conn->rekey->enc_key_len = keymat->enc_key_len / 8;

  if (ske->start_payload->flags & SILC_SKE_SP_FLAG_PFS)
    conn->rekey->pfs = TRUE;
  conn->rekey->ske_group = silc_ske_group_get_number(group);

  /* Save the HASH function */
  silc_hash_alloc(hash->hash->name, &conn->hash);
}

/* Checks the version string of the server. */

SilcSKEStatus silc_ske_check_version(SilcSKE ske, unsigned char *version,
				     SilcUInt32 len, void *context)
{
  SilcClientConnection conn = (SilcClientConnection)ske->sock->user_data;
  SilcClient client = (SilcClient)ske->user_data;
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  char *cp;
  int maj = 0, min = 0, build = 0, maj2 = 0, min2 = 0, build2 = 0;

  /* Check for initial version string */
  if (!strstr(version, "SILC-1.0-"))
    status = SILC_SKE_STATUS_BAD_VERSION;

  /* Check software version */

  cp = version + 9;
  if (!cp)
    status = SILC_SKE_STATUS_BAD_VERSION;

  maj = atoi(cp);
  cp = strchr(cp, '.');
  if (cp) {
    min = atoi(cp + 1);
    cp++;
  }
  cp = strchr(cp, '.');
  if (cp)
    build = atoi(cp + 1);

  cp = client->internal->silc_client_version + 9;
  if (!cp)
    status = SILC_SKE_STATUS_BAD_VERSION;

  maj2 = atoi(cp);
  cp = strchr(cp, '.');
  if (cp) {
    min2 = atoi(cp + 1);
    cp++;
  }
  cp = strchr(cp, '.');
  if (cp)
    build2 = atoi(cp + 1);

  if (maj != maj2)
    status = SILC_SKE_STATUS_BAD_VERSION;

  /* XXX backward support for 0.6.1 */
  if (maj == 0 && min == 6 && build < 2)
    ske->backward_version = 1;

  if (status != SILC_SKE_STATUS_OK)
    client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_AUDIT,
			       "We don't support server version `%s'", 
			       version);

  return status;
}

/* Callback that is called by the SKE to indicate that it is safe to
   continue the execution of the protocol. Is given as argument to the 
   silc_ske_initiator_finish or silc_ske_responder_phase_2 functions. 
   This is called due to the fact that the public key verification
   process is asynchronous and we must not continue the protocl until
   the public key has been verified and this callback is called. */

static void silc_client_protocol_ke_continue(SilcSKE ske,
					     void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientConnection conn = ctx->sock->user_data;

  SILC_LOG_DEBUG(("Start"));

  if (ske->status != SILC_SKE_STATUS_OK) {
    /* Call failure client operation */
    client->internal->ops->failure(client, conn, protocol, 
				   (void *)ske->status);
    protocol->state = SILC_PROTOCOL_STATE_ERROR;
    silc_protocol_execute(protocol, client->schedule, 0, 0);
    return;
  }

  /* Send Ok to the other end. We will end the protocol as server
     sends Ok to us when we will take the new keys into use. Do this
     if we are initiator. This is happens when this callback was sent
     to silc_ske_initiator_finish function. */
  if (ctx->responder == FALSE) {
    silc_ske_end(ctx->ske);

    /* End the protocol on the next round */
    protocol->state = SILC_PROTOCOL_STATE_END;
  }

  /* Advance protocol state and call the next state if we are responder. 
     This happens when this callback was sent to silc_ske_responder_phase_2
     function. */
  if (ctx->responder == TRUE) {
    protocol->state++;
    silc_protocol_execute(protocol, client->schedule, 0, 100000);
  }
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
  SilcSKEStatus status = SILC_SKE_STATUS_OK;

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
      ctx->ske = ske = silc_ske_alloc(client->rng, client);

      silc_ske_set_callbacks(ske, ctx->send_packet, NULL,
			     ctx->verify,
			     silc_client_protocol_ke_continue,
			     silc_ske_check_version, 
			     context);
      
      if (ctx->responder == TRUE) {
	/* Start the key exchange by processing the received security
	   properties packet from initiator. */
	status = 
	  silc_ske_responder_start(ske, ctx->rng, ctx->sock,
				   client->internal->silc_client_version,
				   ctx->packet->buffer, TRUE);
      } else {
	SilcSKEStartPayload *start_payload;

	/* Assemble security properties. */
	silc_ske_assemble_security_properties(
				  ske, SILC_SKE_SP_FLAG_MUTUAL, 
				  client->internal->silc_client_version,
				  &start_payload);

	/* Start the key exchange by sending our security properties
	   to the remote end. */
	status = silc_ske_initiator_start(ske, ctx->rng, ctx->sock,
					  start_payload);
      }

      /* Return now if the procedure is pending */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, client->schedule, 0, 0);
	return;
      }

      /* Advance protocol state and call the next state if we are responder */
      protocol->state++;
      if (ctx->responder == TRUE)
	silc_protocol_execute(protocol, client->schedule, 0, 100000);
    }
    break;
  case 2:
    {
      /* 
       * Phase 1 
       */
      if (ctx->responder == TRUE) {
	/* Sends the selected security properties to the initiator. */
	status = silc_ske_responder_phase_1(ctx->ske);
      } else {
	/* Call Phase-1 function. This processes the Key Exchange Start
	   paylaod reply we just got from the responder. The callback
	   function will receive the processed payload where we will
	   save it. */
	status = silc_ske_initiator_phase_1(ctx->ske, ctx->packet->buffer);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, client->schedule, 0, 0);
	return;
      }

      /* Advance protocol state and call next state if we are initiator */
      protocol->state++;
      if (ctx->responder == FALSE)
	silc_protocol_execute(protocol, client->schedule, 0, 100000);
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
	   Hellman algorithm. The silc_client_protocol_ke_continue will
	   be called after the public key has been verified. */
	status = silc_ske_responder_phase_2(ctx->ske, ctx->packet->buffer);
      } else {
	/* Call the Phase-2 function. This creates Diffie Hellman
	   key exchange parameters and sends our public part inside
	   Key Exhange 1 Payload to the responder. */
	status = silc_ske_initiator_phase_2(ctx->ske,
					    client->public_key,
					    client->private_key,
					    SILC_SKE_PK_TYPE_SILC);
	protocol->state++;
      }

      /* Return now if the procedure is pending */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, client->schedule, 0, 0);
	return;
      }
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
				    SILC_SKE_PK_TYPE_SILC);

	/* End the protocol on the next round */
	protocol->state = SILC_PROTOCOL_STATE_END;
      } else {
	/* Finish the protocol. This verifies the Key Exchange 2 payload
	   sent by responder. The silc_client_protocol_ke_continue will
	   be called after the public key has been verified. */
	status = silc_ske_initiator_finish(ctx->ske, ctx->packet->buffer);
      }

      /* Return now if the procedure is pending */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
        if (status == SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY) {
          client->internal->ops->say(
			     client, conn, SILC_CLIENT_MESSAGE_AUDIT, 
			     "Received unsupported server %s public key",
			     ctx->sock->hostname);
        } else {
          client->internal->ops->say(
			   client, conn, SILC_CLIENT_MESSAGE_AUDIT,
			   "Error during key exchange protocol with server %s",
			   ctx->sock->hostname);
        }
	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, client->schedule, 0, 0);
	return;
      }
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
	silc_protocol_execute(protocol, client->schedule, 0, 300000);
	silc_ske_free_key_material(keymat);
	return;
      }
      ctx->keymat = keymat;

      /* Send Ok to the other end if we are responder. If we are initiator
	 we have sent this already. */
      if (ctx->responder == TRUE)
	silc_ske_end(ctx->ske);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_schedule_task_del(client->schedule, ctx->timeout_task);

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, client->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /*
     * Error during protocol
     */
    
    /* Send abort notification */
    silc_ske_abort(ctx->ske, ctx->ske->status);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, client->schedule);
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
      silc_schedule_task_del(client->schedule, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, client->schedule);
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
				SilcClientConnection conn,
				unsigned char *auth_data,
				SilcUInt32 *auth_data_len,
				SilcSKE ske)
{
  int len;
  SilcPKCS pkcs;
  SilcBuffer auth;

  /* Use our default key */
  pkcs = client->pkcs;

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

  if (silc_pkcs_sign_with_hash(pkcs, ske->prop->hash, auth->data, 
			       auth->len, auth_data, auth_data_len)) {
    silc_buffer_free(auth);
    return TRUE;
  }

  silc_buffer_free(auth);
  return FALSE;
}

/* Continues the connection authentication protocol. This funtion may
   be called directly or used as SilcAskPassphrase callback. */

static void 
silc_client_conn_auth_continue(unsigned char *auth_data,
			       SilcUInt32 auth_data_len, void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientConnAuthInternalContext *ctx = 
    (SilcClientConnAuthInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcBuffer packet;
  int payload_len = 0;

  SILC_LOG_DEBUG(("Start"));

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
  silc_buffer_free(packet);
      
  /* Next state is end of protocol */
  protocol->state = SILC_PROTOCOL_STATE_END;
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
      unsigned char *auth_data = NULL;
      SilcUInt32 auth_data_len = 0;
      unsigned char sign[1024];

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

	client->internal->ops->say(
			client, conn, SILC_CLIENT_MESSAGE_INFO,
			"Password authentication required by server %s",
			ctx->sock->hostname);
	client->internal->ops->ask_passphrase(client, conn,
					      silc_client_conn_auth_continue,
					      protocol);
	return;
	break;

      case SILC_AUTH_PUBLIC_KEY:
	if (!ctx->auth_data) {
	  /* Public key authentication */
	  silc_client_get_public_key_auth(client, conn, sign, &auth_data_len, 
					  ctx->ske);
	  auth_data = sign;
	} else {
	  auth_data = ctx->auth_data;
	  auth_data_len = ctx->auth_data_len;
	}
	
	break;
      }

      silc_client_conn_auth_continue(auth_data,
				     auth_data_len, protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_END:
    {
      /* 
       * End protocol. Nothing special to be done here.
       */

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, client->schedule);
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
	silc_protocol_execute_final(protocol, client->schedule);
      else
	silc_protocol_free(protocol);
    }

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * Received failure from remote.
     */

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, client->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }
}

/*
 * Re-key protocol routines
 */

/* Actually takes the new keys into use. */

static void 
silc_client_protocol_rekey_validate(SilcClient client,
				    SilcClientRekeyInternalContext *ctx,
				    SilcSocketConnection sock,
				    SilcSKEKeyMaterial *keymat,
				    bool send)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;

  if (ctx->responder == TRUE) {
    if (send) {
      silc_cipher_set_key(conn->send_key, keymat->receive_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(conn->send_key, keymat->receive_iv);
      silc_hmac_set_key(conn->hmac_send, keymat->receive_hmac_key, 
			keymat->hmac_key_len);
    } else {
      silc_cipher_set_key(conn->receive_key, keymat->send_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(conn->receive_key, keymat->send_iv);
      silc_hmac_set_key(conn->hmac_receive, keymat->send_hmac_key, 
			keymat->hmac_key_len);
    }
  } else {
    if (send) {
      silc_cipher_set_key(conn->send_key, keymat->send_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(conn->send_key, keymat->send_iv);
      silc_hmac_set_key(conn->hmac_send, keymat->send_hmac_key, 
			keymat->hmac_key_len);
    } else {
      silc_cipher_set_key(conn->receive_key, keymat->receive_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(conn->receive_key, keymat->receive_iv);
      silc_hmac_set_key(conn->hmac_receive, keymat->receive_hmac_key, 
			keymat->hmac_key_len);
    }
  }

  /* Save the current sending encryption key */
  if (!send) {
    memset(conn->rekey->send_enc_key, 0, conn->rekey->enc_key_len);
    silc_free(conn->rekey->send_enc_key);
    conn->rekey->send_enc_key = silc_memdup(keymat->send_enc_key,
					    keymat->enc_key_len / 8);
    conn->rekey->enc_key_len = keymat->enc_key_len / 8;
  }
}

/* This function actually re-generates (when not using PFS) the keys and
   takes them into use. */

static void 
silc_client_protocol_rekey_generate(SilcClient client,
				    SilcClientRekeyInternalContext *ctx,
				    bool send)
{
  SilcClientConnection conn = (SilcClientConnection)ctx->sock->user_data;
  SilcSKEKeyMaterial *keymat;
  SilcUInt32 key_len = silc_cipher_get_key_len(conn->send_key);
  SilcUInt32 hash_len = conn->hash->hash->hash_len;

  SILC_LOG_DEBUG(("Generating new %s session keys (no PFS)",
		  send ? "sending" : "receiving"));

  /* Generate the new key */
  keymat = silc_calloc(1, sizeof(*keymat));
  silc_ske_process_key_material_data(conn->rekey->send_enc_key,
				     conn->rekey->enc_key_len,
				     16, key_len, hash_len, 
				     conn->hash, keymat);

  /* Set the keys into use */
  silc_client_protocol_rekey_validate(client, ctx, ctx->sock, keymat, send);

  silc_ske_free_key_material(keymat);
}

/* This function actually re-generates (with PFS) the keys and
   takes them into use. */

static void 
silc_client_protocol_rekey_generate_pfs(SilcClient client,
					SilcClientRekeyInternalContext *ctx,
					bool send)
{
  SilcClientConnection conn = (SilcClientConnection)ctx->sock->user_data;
  SilcSKEKeyMaterial *keymat;
  SilcUInt32 key_len = silc_cipher_get_key_len(conn->send_key);
  SilcUInt32 hash_len = conn->hash->hash->hash_len;
  unsigned char *tmpbuf;
  SilcUInt32 klen;

  SILC_LOG_DEBUG(("Generating new %s session keys (with PFS)",
		  send ? "sending" : "receiving"));

  /* Encode KEY to binary data */
  tmpbuf = silc_mp_mp2bin(ctx->ske->KEY, 0, &klen);

  /* Generate the new key */
  keymat = silc_calloc(1, sizeof(*keymat));
  silc_ske_process_key_material_data(tmpbuf, klen, 16, key_len, hash_len, 
				     conn->hash, keymat);

  /* Set the keys into use */
  silc_client_protocol_rekey_validate(client, ctx, ctx->sock, keymat, send);

  memset(tmpbuf, 0, klen);
  silc_free(tmpbuf);
  silc_ske_free_key_material(keymat);
}

/* Packet sending callback. This function is provided as packet sending
   routine to the Key Exchange functions. */

static void 
silc_client_protocol_rekey_send_packet(SilcSKE ske,
				       SilcBuffer packet,
				       SilcPacketType type,
				       void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientRekeyInternalContext *ctx = 
    (SilcClientRekeyInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;

  /* Send the packet immediately */
  silc_client_packet_send(client, ctx->sock, type, NULL, 0, NULL, NULL,
			  packet->data, packet->len, FALSE);
}

/* Performs re-key as defined in the SILC protocol specification. */

SILC_TASK_CALLBACK(silc_client_protocol_rekey)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientRekeyInternalContext *ctx = 
    (SilcClientRekeyInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcClientConnection conn = (SilcClientConnection)ctx->sock->user_data;
  SilcSKEStatus status;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_UNKNOWN)
    protocol->state = SILC_PROTOCOL_STATE_START;

  SILC_LOG_DEBUG(("State=%d", protocol->state));

  switch(protocol->state) {
  case SILC_PROTOCOL_STATE_START:
    {
      /* 
       * Start protocol.
       */

      if (ctx->responder == TRUE) {
	/*
	 * We are receiving party
	 */

	if (ctx->pfs == TRUE) {
	  /* 
	   * Use Perfect Forward Secrecy, ie. negotiate the key material
	   * using the SKE protocol.
	   */

	  if (ctx->packet->type != SILC_PACKET_KEY_EXCHANGE_1) {
	    /* Error in protocol */
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, client->schedule, 0, 300000);
	  }

	  ctx->ske = silc_ske_alloc(client->rng, client);
	  ctx->ske->prop = silc_calloc(1, sizeof(*ctx->ske->prop));
	  silc_ske_group_get_by_number(conn->rekey->ske_group,
				       &ctx->ske->prop->group);

	  silc_ske_set_callbacks(ctx->ske, 
				 silc_client_protocol_rekey_send_packet,
				 NULL,  NULL, NULL, silc_ske_check_version,
				 context);
      
	  status = silc_ske_responder_phase_2(ctx->ske, ctx->packet->buffer);
	  if (status != SILC_SKE_STATUS_OK) {
	    SILC_LOG_WARNING(("Error (type %d) during Re-key (PFS)",
			      status));
	    
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, client->schedule, 0, 300000);
	    return;
	  }

	  /* Advance the protocol state */
	  protocol->state++;
	  silc_protocol_execute(protocol, client->schedule, 0, 0);
	} else {
	  /*
	   * Do normal and simple re-key.
	   */

	  /* Send the REKEY_DONE to indicate we will take new keys into use */
	  silc_client_packet_send(client, ctx->sock, 
				  SILC_PACKET_REKEY_DONE, 
				  NULL, 0, NULL, NULL, NULL, 0, FALSE);

	  /* After we send REKEY_DONE we must set the sending encryption
	     key to the new key since all packets after this packet must
	     encrypted with the new key. */
	  silc_client_protocol_rekey_generate(client, ctx, TRUE);

	  /* The protocol ends in next stage. */
	  protocol->state = SILC_PROTOCOL_STATE_END;
	}
      
      } else {
	/*
	 * We are the initiator of this protocol
	 */

	/* Start the re-key by sending the REKEY packet */
	silc_client_packet_send(client, ctx->sock, SILC_PACKET_REKEY, 
				NULL, 0, NULL, NULL, NULL, 0, FALSE);

	if (ctx->pfs == TRUE) {
	  /* 
	   * Use Perfect Forward Secrecy, ie. negotiate the key material
	   * using the SKE protocol.
	   */
	  ctx->ske = silc_ske_alloc(client->rng, client);
	  ctx->ske->prop = silc_calloc(1, sizeof(*ctx->ske->prop));
	  silc_ske_group_get_by_number(conn->rekey->ske_group,
				       &ctx->ske->prop->group);

	  silc_ske_set_callbacks(ctx->ske, 
				 silc_client_protocol_rekey_send_packet,
				 NULL,  NULL, NULL, silc_ske_check_version,
				 context);
      
	  status =  silc_ske_initiator_phase_2(ctx->ske, NULL, NULL, 0);
	  if (status != SILC_SKE_STATUS_OK) {
	    SILC_LOG_WARNING(("Error (type %d) during Re-key (PFS)",
			      status));
	    
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, client->schedule, 0, 300000);
	    return;
	  }

	  /* Advance the protocol state */
	  protocol->state++;
	} else {
	  /*
	   * Do normal and simple re-key.
	   */

	  /* Send the REKEY_DONE to indicate we will take new keys into use 
	     now. */ 
	  silc_client_packet_send(client, ctx->sock, 
				  SILC_PACKET_REKEY_DONE, 
				  NULL, 0, NULL, NULL, NULL, 0, FALSE);

	  /* After we send REKEY_DONE we must set the sending encryption
	     key to the new key since all packets after this packet must
	     encrypted with the new key. */
	  silc_client_protocol_rekey_generate(client, ctx, TRUE);

	  /* The protocol ends in next stage. */
	  protocol->state = SILC_PROTOCOL_STATE_END;
	}
      }
    }
    break;

  case 2:
    /*
     * Second state, used only when oding re-key with PFS.
     */
    if (ctx->responder == TRUE) {
      if (ctx->pfs == TRUE) {
	/*
	 * Send our KE packe to the initiator now that we've processed
	 * the initiator's KE packet.
	 */
	status = silc_ske_responder_finish(ctx->ske, NULL, NULL, 
					   SILC_SKE_PK_TYPE_SILC);

	  if (status != SILC_SKE_STATUS_OK) {
	    SILC_LOG_WARNING(("Error (type %d) during Re-key (PFS)",
			      status));
	    
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, client->schedule, 0, 300000);
	    return;
	  }
      }

    } else {
      if (ctx->pfs == TRUE) {
	/*
	 * The packet type must be KE packet
	 */
	if (ctx->packet->type != SILC_PACKET_KEY_EXCHANGE_2) {
	  /* Error in protocol */
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, client->schedule, 0, 300000);
	}
	
	status = silc_ske_initiator_finish(ctx->ske, ctx->packet->buffer);
	if (status != SILC_SKE_STATUS_OK) {
	  SILC_LOG_WARNING(("Error (type %d) during Re-key (PFS)",
			    status));
	  
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, client->schedule, 0, 300000);
	  return;
	}
      }
    }

    /* Send the REKEY_DONE to indicate we will take new keys into use 
       now. */ 
    silc_client_packet_send(client, ctx->sock, SILC_PACKET_REKEY_DONE, 
			    NULL, 0, NULL, NULL, NULL, 0, FALSE);
    
    /* After we send REKEY_DONE we must set the sending encryption
       key to the new key since all packets after this packet must
       encrypted with the new key. */
    silc_client_protocol_rekey_generate_pfs(client, ctx, TRUE);

    /* The protocol ends in next stage. */
    protocol->state = SILC_PROTOCOL_STATE_END;
    break;

  case SILC_PROTOCOL_STATE_END:
    /* 
     * End protocol
     */

    if (ctx->packet->type != SILC_PACKET_REKEY_DONE) {
      /* Error in protocol */
      protocol->state = SILC_PROTOCOL_STATE_ERROR;
      silc_protocol_execute(protocol, client->schedule, 0, 0);
    }

    /* We received the REKEY_DONE packet and all packets after this is
       encrypted with the new key so set the decryption key to the new key */
    silc_client_protocol_rekey_generate(client, ctx, FALSE);

    /* Protocol has ended, call the final callback */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, client->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /*
     * Error occured
     */

    if (ctx->pfs == TRUE) {
      /* Send abort notification */
      silc_ske_abort(ctx->ske, ctx->ske->status);
    }

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, client->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * We have received failure from remote
     */

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, client->schedule);
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
  silc_protocol_register(SILC_PROTOCOL_CLIENT_REKEY,
			 silc_client_protocol_rekey);
}

/* Unregisters protocols */

void silc_client_protocols_unregister(void)
{
  silc_protocol_unregister(SILC_PROTOCOL_CLIENT_CONNECTION_AUTH,
		  	   silc_client_protocol_connection_auth);
  silc_protocol_unregister(SILC_PROTOCOL_CLIENT_KEY_EXCHANGE,
			   silc_client_protocol_key_exchange);
  silc_protocol_unregister(SILC_PROTOCOL_CLIENT_REKEY,
			   silc_client_protocol_rekey);
}
