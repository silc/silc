/*

  protocol.c

  Author: Pekka Riikonen <priikone@silcnet.org>

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
 * Server side of the protocols.
 */
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

SILC_TASK_CALLBACK(silc_server_protocol_connection_auth);
SILC_TASK_CALLBACK(silc_server_protocol_key_exchange);
SILC_TASK_CALLBACK(silc_server_protocol_rekey);

extern char *silc_version_string;

/*
 * Key Exhange protocol functions
 */

static bool 
silc_verify_public_key_internal(SilcServer server, SilcSocketConnection sock,
				SilcSocketType conn_type,
				unsigned char *pk, uint32 pk_len, 
				SilcSKEPKType pk_type)
{
  char file[256], filename[256], *fingerprint;
  struct stat st;

  if (pk_type != SILC_SKE_PK_TYPE_SILC) {
    SILC_LOG_WARNING(("We don't support %s (%s) port %d public key type %d", 
		      sock->hostname, sock->ip, sock->port, pk_type));
    return FALSE;
  }

  /* Accept client keys without verification */
  if (conn_type == SILC_SOCKET_TYPE_CLIENT) {
    SILC_LOG_DEBUG(("Accepting client public key without verification"));
    return TRUE;
  }

  /* XXX For now, accept server keys without verification too. We are
     currently always doing mutual authentication so the proof of posession
     of the private key is verified, and if server is authenticated in
     conn auth protocol with public key we MUST have the key already. */
  return TRUE;
  /* Rest is unreachable code! */
  
  memset(filename, 0, sizeof(filename));
  memset(file, 0, sizeof(file));
  snprintf(file, sizeof(file) - 1, "serverkey_%s_%d.pub", sock->hostname, 
	   sock->port);
  snprintf(filename, sizeof(filename) - 1, SILC_ETCDIR "/serverkeys/%s", 
	   file);

  /* Create serverkeys directory if it doesn't exist. */
  if (stat(SILC_ETCDIR "/serverkeys", &st) < 0) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {  
      if (mkdir(SILC_ETCDIR "/serverkeys", 0755) < 0) {
	SILC_LOG_ERROR(("Couldn't create `%s' directory\n", 
			SILC_ETCDIR "/serverkeys"));
	return TRUE;
      }
    } else {
      SILC_LOG_ERROR(("%s\n", strerror(errno)));
      return TRUE;
    }
  }

  /* Take fingerprint of the public key */
  fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
  SILC_LOG_DEBUG(("Received server %s (%s) port %d public key (%s)", 
		  sock->hostname, sock->ip, sock->port, fingerprint));
  silc_free(fingerprint);

  /* Check whether this key already exists */
  if (stat(filename, &st) < 0) {
    /* We don't have it, then cache it. */
    SILC_LOG_DEBUG(("New public key from server"));

    silc_pkcs_save_public_key_data(filename, pk, pk_len, 
				   SILC_PKCS_FILE_PEM);
    return TRUE;
  } else {
    /* The key already exists, verify it. */
    SilcPublicKey public_key;
    unsigned char *encpk;
    uint32 encpk_len;

    SILC_LOG_DEBUG(("We have the public key saved locally"));

    /* Load the key file */
    if (!silc_pkcs_load_public_key(filename, &public_key, 
				   SILC_PKCS_FILE_PEM))
      if (!silc_pkcs_load_public_key(filename, &public_key, 
				     SILC_PKCS_FILE_BIN)) {
	SILC_LOG_WARNING(("Could not load local copy of the %s (%s) port %d "
			  "server public key", sock->hostname, sock->ip, 
			  sock->port));

	/* Save the key for future checking */
	unlink(filename);
	silc_pkcs_save_public_key_data(filename, pk, pk_len,
				       SILC_PKCS_FILE_PEM);
	return TRUE;
      }
  
    /* Encode the key data */
    encpk = silc_pkcs_public_key_encode(public_key, &encpk_len);
    if (!encpk) {
      SILC_LOG_WARNING(("Local copy of the server %s (%s) port %d public key "
			"is malformed", sock->hostname, sock->ip, sock->port));

      /* Save the key for future checking */
      unlink(filename);
      silc_pkcs_save_public_key_data(filename, pk, pk_len,
				     SILC_PKCS_FILE_PEM);
      return TRUE;
    }

    if (memcmp(encpk, pk, encpk_len)) {
      SILC_LOG_WARNING(("%s (%s) port %d server public key does not match "
			"with local copy", sock->hostname, sock->ip, 
			sock->port));
      SILC_LOG_WARNING(("It is possible that the key has expired or changed"));
      SILC_LOG_WARNING(("It is also possible that some one is performing "
			"man-in-the-middle attack"));
      SILC_LOG_WARNING(("Will not accept the server %s (%s) port %d public "
			"key",
			sock->hostname, sock->ip, sock->port));
      return FALSE;
    }

    /* Local copy matched */
    return TRUE;
  }
}

/* Callback that is called when we have received KE2 payload from
   responder. We try to verify the public key now. */

static void 
silc_server_protocol_ke_verify_key(SilcSKE ske,
				   unsigned char *pk_data,
				   uint32 pk_len,
				   SilcSKEPKType pk_type,
				   void *context,
				   SilcSKEVerifyCbCompletion completion,
				   void *completion_context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx = 
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;

  SILC_LOG_DEBUG(("Start"));

  if (silc_verify_public_key_internal(server, ctx->sock, 
				      (ctx->responder == FALSE ?
				       SILC_SOCKET_TYPE_ROUTER:
				       ctx->sconfig ? SILC_SOCKET_TYPE_SERVER :
				       ctx->rconfig ? SILC_SOCKET_TYPE_ROUTER :
				       SILC_SOCKET_TYPE_CLIENT),
				      pk_data, pk_len, pk_type))
    completion(ske, SILC_SKE_STATUS_OK, completion_context);
  else
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY, 
	       completion_context);
}

/* Packet sending callback. This function is provided as packet sending
   routine to the Key Exchange functions. */

static void silc_server_protocol_ke_send_packet(SilcSKE ske,
						SilcBuffer packet,
						SilcPacketType type,
						void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx = 
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;

  /* Send the packet immediately */
  silc_server_packet_send(server, ske->sock,
			  type, 0, packet->data, packet->len, TRUE);
}

/* Sets the negotiated key material into use for particular connection. */

int silc_server_protocol_ke_set_keys(SilcServer server,
				     SilcSKE ske,
				     SilcSocketConnection sock,
				     SilcSKEKeyMaterial *keymat,
				     SilcCipher cipher,
				     SilcPKCS pkcs,
				     SilcHash hash,
				     SilcHmac hmac,
				     SilcSKEDiffieHellmanGroup group,
				     bool is_responder)
{
  SilcUnknownEntry conn_data;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Setting new key into use"));

  conn_data = silc_calloc(1, sizeof(*conn_data));
  idata = (SilcIDListData)conn_data;

  /* Allocate cipher to be used in the communication */
  if (!silc_cipher_alloc(cipher->cipher->name, &idata->send_key)) {
    silc_free(conn_data);
    return FALSE;
  }
  if (!silc_cipher_alloc(cipher->cipher->name, &idata->receive_key)) {
    silc_free(conn_data);
    return FALSE;
  }
  
  if (!silc_hmac_alloc((char *)silc_hmac_get_name(hmac), NULL, 
		       &idata->hmac_send)) {
    silc_cipher_free(idata->send_key);
    silc_cipher_free(idata->receive_key);
    silc_free(conn_data);
    return FALSE;
  }

  if (!silc_hmac_alloc((char *)silc_hmac_get_name(hmac), NULL, 
		       &idata->hmac_receive)) {
    silc_cipher_free(idata->send_key);
    silc_cipher_free(idata->receive_key);
    silc_hmac_free(idata->hmac_send);
    silc_free(conn_data);
    return FALSE;
  }

  if (is_responder == TRUE) {
    silc_cipher_set_key(idata->send_key, keymat->receive_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(idata->send_key, keymat->receive_iv);
    silc_cipher_set_key(idata->receive_key, keymat->send_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(idata->receive_key, keymat->send_iv);
    silc_hmac_set_key(idata->hmac_send, keymat->receive_hmac_key, 
		      keymat->hmac_key_len);
    silc_hmac_set_key(idata->hmac_receive, keymat->send_hmac_key, 
		      keymat->hmac_key_len);
  } else {
    silc_cipher_set_key(idata->send_key, keymat->send_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(idata->send_key, keymat->send_iv);
    silc_cipher_set_key(idata->receive_key, keymat->receive_enc_key, 
			keymat->enc_key_len);
    silc_cipher_set_iv(idata->receive_key, keymat->receive_iv);
    silc_hmac_set_key(idata->hmac_send, keymat->send_hmac_key, 
		      keymat->hmac_key_len);
    silc_hmac_set_key(idata->hmac_receive, keymat->receive_hmac_key, 
		      keymat->hmac_key_len);
  }

  idata->rekey = silc_calloc(1, sizeof(*idata->rekey));
  idata->rekey->send_enc_key = 
    silc_calloc(keymat->enc_key_len / 8,
		sizeof(*idata->rekey->send_enc_key));
  memcpy(idata->rekey->send_enc_key, 
	 keymat->send_enc_key, keymat->enc_key_len / 8);
  idata->rekey->enc_key_len = keymat->enc_key_len / 8;

  if (ske->start_payload->flags & SILC_SKE_SP_FLAG_PFS)
    idata->rekey->pfs = TRUE;
  idata->rekey->ske_group = silc_ske_group_get_number(group);

  /* Save the hash */
  if (!silc_hash_alloc(hash->hash->name, &idata->hash)) {
    silc_cipher_free(idata->send_key);
    silc_cipher_free(idata->receive_key);
    silc_hmac_free(idata->hmac_send);
    silc_hmac_free(idata->hmac_receive);
    silc_free(conn_data);
    return FALSE;
  }

  /* Save the remote host's public key */
  silc_pkcs_public_key_decode(ske->ke1_payload->pk_data, 
			      ske->ke1_payload->pk_len, &idata->public_key);
  if (ske->prop->flags & SILC_SKE_SP_FLAG_MUTUAL)
    silc_hash_make(server->sha1hash, ske->ke1_payload->pk_data,
		   ske->ke1_payload->pk_len, idata->fingerprint);

  sock->user_data = (void *)conn_data;

  SILC_LOG_INFO(("%s (%s) security properties: %s %s %s", 
		 sock->hostname, sock->ip,
		 idata->send_key->cipher->name,
		 (char *)silc_hmac_get_name(idata->hmac_send),
		 idata->hash->hash->name));

  return TRUE;
}

/* Check remote host version string */

SilcSKEStatus silc_ske_check_version(SilcSKE ske, unsigned char *version,
				     uint32 len, void *context)
{
  SilcSKEStatus status = SILC_SKE_STATUS_OK;
  char *cp;
  int maj = 0, min = 0, build = 0, maj2 = 0, min2 = 0, build2 = 0;

  SILC_LOG_INFO(("%s (%s) is version %s", ske->sock->hostname,
		 ske->sock->ip, version));

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
  if (cp) {
    cp = strchr(cp, '.');
    if (cp)
      build = atoi(cp + 1);
  }

  cp = silc_version_string + 9;
  if (!cp)
    status = SILC_SKE_STATUS_BAD_VERSION;

  maj2 = atoi(cp);
  cp = strchr(cp, '.');
  if (cp) {
    min2 = atoi(cp + 1);
    cp++;
  }
  if (cp) {
    cp = strchr(cp, '.');
    if (cp)
      build2 = atoi(cp + 1);
  }

  if (maj != maj2)
    status = SILC_SKE_STATUS_BAD_VERSION;
#if 0
  if (min > min2)
    status = SILC_SKE_STATUS_BAD_VERSION;
#endif

  /* XXX < 0.6 is not allowed */
  if (maj == 0 && min < 5)
    status = SILC_SKE_STATUS_BAD_VERSION;

  /* XXX backward support for 0.6.1 */
  if (maj == 0 && min == 6 && build < 2)
    ske->backward_version = 1;

  return status;
}

/* Callback that is called by the SKE to indicate that it is safe to
   continue the execution of the protocol. This is used only if we are
   initiator.  Is given as argument to the silc_ske_initiator_finish or
   silc_ske_responder_phase_2 functions. This is called due to the fact
   that the public key verification process is asynchronous and we must
   not continue the protocl until the public key has been verified and
   this callback is called. */

static void silc_server_protocol_ke_continue(SilcSKE ske, void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx = 
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;

  SILC_LOG_DEBUG(("Start"));

  if (ske->status != SILC_SKE_STATUS_OK) {
    SILC_LOG_WARNING(("Error (%s) during Key Exchange protocol",
		      silc_ske_map_status(ske->status)));
    SILC_LOG_DEBUG(("Error (%s) during Key Exchange protocol",
		    silc_ske_map_status(ske->status)));
    
    protocol->state = SILC_PROTOCOL_STATE_ERROR;
    silc_protocol_execute(protocol, server->schedule, 0, 300000);
    return;
  }

  /* Send Ok to the other end. We will end the protocol as responder
     sends Ok to us when we will take the new keys into use. */
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
    silc_protocol_execute(protocol, server->schedule, 0, 100000);
  }
}

/* Performs key exchange protocol. This is used for both initiator
   and responder key exchange. This is performed always when accepting
   new connection to the server. This may be called recursively. */

SILC_TASK_CALLBACK(silc_server_protocol_key_exchange)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerKEInternalContext *ctx = 
    (SilcServerKEInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcSKEStatus status = SILC_SKE_STATUS_OK;

  SILC_LOG_DEBUG(("Start"));

  if (protocol->state == SILC_PROTOCOL_STATE_UNKNOWN)
    protocol->state = SILC_PROTOCOL_STATE_START;

  SILC_LOG_DEBUG(("State=%d", protocol->state));

  switch(protocol->state) {
  case SILC_PROTOCOL_STATE_START:
    {
      /*
       * Start protocol
       */
      SilcSKE ske;

      /* Allocate Key Exchange object */
      ske = silc_ske_alloc();
      ctx->ske = ske;
      ske->rng = server->rng;
      
      silc_ske_set_callbacks(ske, silc_server_protocol_ke_send_packet, NULL,
			     silc_server_protocol_ke_verify_key,
			     silc_server_protocol_ke_continue,
			     silc_ske_check_version, context);
      
      if (ctx->responder == TRUE) {
	/* Start the key exchange by processing the received security
	   properties packet from initiator. */
	status = silc_ske_responder_start(ske, ctx->rng, ctx->sock,
					  silc_version_string,
					  ctx->packet->buffer, TRUE);
      } else {
	SilcSKEStartPayload *start_payload;

	/* Assemble security properties. */
	silc_ske_assemble_security_properties(ske, SILC_SKE_SP_FLAG_MUTUAL, 
					      silc_version_string,
					      &start_payload);

	/* Start the key exchange by sending our security properties
	   to the remote end. */
	status = silc_ske_initiator_start(ske, ctx->rng, ctx->sock,
					  start_payload);
      }

      /* Return now if the procedure is pending. */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (%s) during Key Exchange protocol",
			  silc_ske_map_status(status)));
	SILC_LOG_DEBUG(("Error (%s) during Key Exchange protocol",
			silc_ske_map_status(status)));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, server->schedule, 0, 300000);
	return;
      }

      /* Advance protocol state and call the next state if we are responder */
      protocol->state++;
      if (ctx->responder == TRUE)
	silc_protocol_execute(protocol, server->schedule, 0, 100000);
    }
    break;
  case 2:
    {
      /* 
       * Phase 1 
       */
      if (ctx->responder == TRUE) {
	/* Sends the selected security properties to the initiator. */
	status = silc_ske_responder_phase_1(ctx->ske, 
					    ctx->ske->start_payload);
      } else {
	/* Call Phase-1 function. This processes the Key Exchange Start
	   paylaod reply we just got from the responder. The callback
	   function will receive the processed payload where we will
	   save it. */
	status = silc_ske_initiator_phase_1(ctx->ske, ctx->packet->buffer);
      }

      /* Return now if the procedure is pending. */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (%s) during Key Exchange protocol",
			  silc_ske_map_status(status)));
	SILC_LOG_DEBUG(("Error (%s) during Key Exchange protocol",
			silc_ske_map_status(status)));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, server->schedule, 0, 300000);
	return;
      }

      /* Advance protocol state and call next state if we are initiator */
      protocol->state++;
      if (ctx->responder == FALSE)
	silc_protocol_execute(protocol, server->schedule, 0, 100000);
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
	   Hellman algorithm. The silc_server_protocol_ke_continue
	   will be called after the public key has been verified. */
	status = silc_ske_responder_phase_2(ctx->ske, ctx->packet->buffer);
      } else {
	/* Call the Phase-2 function. This creates Diffie Hellman
	   key exchange parameters and sends our public part inside
	   Key Exhange 1 Payload to the responder. */
	status = silc_ske_initiator_phase_2(ctx->ske,
					    server->public_key,
					    server->private_key);
	protocol->state++;
      }

      /* Return now if the procedure is pending. */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (%s) during Key Exchange protocol",
			  silc_ske_map_status(status)));
	SILC_LOG_DEBUG(("Error (%s) during Key Exchange protocol",
			silc_ske_map_status(status)));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, server->schedule, 0, 300000);
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
	status = silc_ske_responder_finish(ctx->ske, 
					   server->public_key, 
					   server->private_key,
					   SILC_SKE_PK_TYPE_SILC);

	/* End the protocol on the next round */
	protocol->state = SILC_PROTOCOL_STATE_END;
      } else {
	/* Finish the protocol. This verifies the Key Exchange 2 payload
	   sent by responder. The silc_server_protocol_ke_continue will
	   be called after the public key has been verified. */
	status = silc_ske_initiator_finish(ctx->ske, ctx->packet->buffer);
      }

      /* Return now if the procedure is pending. */
      if (status == SILC_SKE_STATUS_PENDING)
	return;

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (%s) during Key Exchange protocol",
			  silc_ske_map_status(status)));
	SILC_LOG_DEBUG(("Error (%s) during Key Exchange protocol",
			silc_ske_map_status(status)));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	silc_protocol_execute(protocol, server->schedule, 0, 300000);
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
	silc_protocol_execute(protocol, server->schedule, 0, 300000);
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
	silc_schedule_task_del(server->schedule, ctx->timeout_task);

      /* Call the final callback */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /*
     * Error occured
     */

    /* Send abort notification */
    silc_ske_abort(ctx->ske, ctx->ske->status);

    /* Unregister the timeout task since the protocol has ended. 
       This was the timeout task to be executed if the protocol is
       not completed fast enough. */
    if (ctx->timeout_task)
      silc_schedule_task_del(server->schedule, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * We have received failure from remote
     */

    /* Unregister the timeout task since the protocol has ended. 
       This was the timeout task to be executed if the protocol is
       not completed fast enough. */
    if (ctx->timeout_task)
      silc_schedule_task_del(server->schedule, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
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
silc_server_password_authentication(SilcServer server, char *auth1, 
				    char *auth2)
{
  if (!auth1 || !auth2)
    return FALSE;

  if (!memcmp(auth1, auth2, strlen(auth1)))
    return TRUE;

  return FALSE;
}

static int
silc_server_public_key_authentication(SilcServer server,
				      SilcPublicKey pub_key,
				      unsigned char *sign,
				      uint32 sign_len,
				      SilcSKE ske)
{
  SilcPKCS pkcs;
  int len;
  SilcBuffer auth;

  if (!pub_key || !sign)
    return FALSE;

  silc_pkcs_alloc(pub_key->name, &pkcs);
  if (!silc_pkcs_public_key_set(pkcs, pub_key)) {
    silc_pkcs_free(pkcs);
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

  /* Verify signature */
  if (silc_pkcs_verify_with_hash(pkcs, ske->prop->hash, sign, sign_len, 
				 auth->data, auth->len)) {
    silc_pkcs_free(pkcs);
    silc_buffer_free(auth);
    return TRUE;
  }

  silc_pkcs_free(pkcs);
  silc_buffer_free(auth);
  return FALSE;
}

static int
silc_server_get_public_key_auth(SilcServer server,
				unsigned char *auth_data,
				uint32 *auth_data_len,
				SilcSKE ske)
{
  int len;
  SilcPKCS pkcs;
  SilcBuffer auth;

  pkcs = server->pkcs;

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

/* Performs connection authentication protocol. If responder, we 
   authenticate the remote data received. If initiator, we will send
   authentication data to the remote end. */

SILC_TASK_CALLBACK(silc_server_protocol_connection_auth)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerConnAuthInternalContext *ctx = 
    (SilcServerConnAuthInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;

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
	int ret;
	uint16 payload_len;
	uint16 conn_type;
	unsigned char *auth_data = NULL;

	SILC_LOG_INFO(("Performing authentication protocol for %s (%s)",
		       ctx->sock->hostname, ctx->sock->ip));

	/* Parse the received authentication data packet. The received
	   payload is Connection Auth Payload. */
	ret = silc_buffer_unformat(ctx->packet->buffer,
				   SILC_STR_UI_SHORT(&payload_len),
				   SILC_STR_UI_SHORT(&conn_type),
				   SILC_STR_END);
	if (ret == -1) {
	  SILC_LOG_DEBUG(("Bad payload in authentication packet"));
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, server->schedule, 0, 300000);
	  return;
	}
	
	if (payload_len != ctx->packet->buffer->len) {
	  SILC_LOG_DEBUG(("Bad payload in authentication packet"));
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, server->schedule, 0, 300000);
	  return;
	}
	
	payload_len -= 4;
	
	if (conn_type < SILC_SOCKET_TYPE_CLIENT || 
	    conn_type > SILC_SOCKET_TYPE_ROUTER) {
	  SILC_LOG_ERROR(("Bad connection type %d", conn_type));
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, server->schedule, 0, 300000);
	  return;
	}
	
	if (payload_len > 0) {
	  /* Get authentication data */
	  silc_buffer_pull(ctx->packet->buffer, 4);
	  ret = silc_buffer_unformat(ctx->packet->buffer,
				     SILC_STR_UI_XNSTRING_ALLOC(&auth_data, 
								payload_len),
				     SILC_STR_END);
	  if (ret == -1) {
	    SILC_LOG_DEBUG(("Bad payload in authentication packet"));
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, server->schedule, 0, 300000);
	    return;
	  }
	}

	/* 
	 * Check the remote connection type and make sure that we have
	 * configured this connection. If we haven't allowed this connection
	 * the authentication must be failed.
	 */

	SILC_LOG_DEBUG(("Remote connection type %d", conn_type));

	/* Remote end is client */
	if (conn_type == SILC_SOCKET_TYPE_CLIENT) {
	  SilcServerConfigSectionClientConnection *client = ctx->cconfig;
	  
	  if (client) {
	    switch(client->auth_meth) {
	    case SILC_AUTH_NONE:
	      /* No authentication required */
	      SILC_LOG_DEBUG(("No authentication required"));
	      break;
	      
	    case SILC_AUTH_PASSWORD:
	      /* Password authentication */
	      SILC_LOG_DEBUG(("Password authentication"));
	      ret = silc_server_password_authentication(server, auth_data,
							client->auth_data);

	      if (ret)
		break;

	      /* Authentication failed */
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      silc_free(auth_data);
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      silc_protocol_execute(protocol, server->schedule, 
				    0, 300000);
	      return;
	      break;
	      
	    case SILC_AUTH_PUBLIC_KEY:
	      /* Public key authentication */
	      SILC_LOG_DEBUG(("Public key authentication"));
	      ret = silc_server_public_key_authentication(server, 
							  client->auth_data,
							  auth_data,
							  payload_len, 
							  ctx->ske);

	      if (ret)
		break;

	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      silc_free(auth_data);
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      silc_protocol_execute(protocol, server->schedule, 
				    0, 300000);
	      return;
	    }
	  } else {
	    SILC_LOG_DEBUG(("No configuration for remote connection"));
	    SILC_LOG_ERROR(("Remote connection not configured"));
	    SILC_LOG_ERROR(("Authentication failed"));
	    silc_free(auth_data);
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, server->schedule, 
				  0, 300000);
	    return;
	  }
	}
	
	/* Remote end is server */
	if (conn_type == SILC_SOCKET_TYPE_SERVER) {
	  SilcServerConfigSectionServerConnection *serv = ctx->sconfig;
	  
	  if (serv) {
	    switch(serv->auth_meth) {
	    case SILC_AUTH_NONE:
	      /* No authentication required */
	      SILC_LOG_DEBUG(("No authentication required"));
	      break;
	      
	    case SILC_AUTH_PASSWORD:
	      /* Password authentication */
	      SILC_LOG_DEBUG(("Password authentication"));
	      ret = silc_server_password_authentication(server, auth_data,
							serv->auth_data);

	      if (ret)
		break;
	      
	      /* Authentication failed */
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      silc_free(auth_data);
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      silc_protocol_execute(protocol, server->schedule, 
				    0, 300000);
	      return;
	      break;

	    case SILC_AUTH_PUBLIC_KEY:
	      /* Public key authentication */
	      SILC_LOG_DEBUG(("Public key authentication"));
	      ret = silc_server_public_key_authentication(server, 
							  serv->auth_data,
							  auth_data,
							  payload_len, 
							  ctx->ske);
							  
	      if (ret)
		break;

	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      silc_free(auth_data);
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      silc_protocol_execute(protocol, server->schedule, 
				    0, 300000);
	      return;
	    }
	  } else {
	    SILC_LOG_DEBUG(("No configuration for remote connection"));
	    SILC_LOG_ERROR(("Remote connection not configured"));
	    SILC_LOG_ERROR(("Authentication failed"));
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, server->schedule, 
				  0, 300000);
	    silc_free(auth_data);
	    return;
	  }
	}
	
	/* Remote end is router */
	if (conn_type == SILC_SOCKET_TYPE_ROUTER) {
	  SilcServerConfigSectionServerConnection *serv = ctx->rconfig;

	  if (serv) {
	    switch(serv->auth_meth) {
	    case SILC_AUTH_NONE:
	      /* No authentication required */
	      SILC_LOG_DEBUG(("No authentication required"));
	      break;
	      
	    case SILC_AUTH_PASSWORD:
	      /* Password authentication */
	      SILC_LOG_DEBUG(("Password authentication"));
	      ret = silc_server_password_authentication(server, auth_data,
							serv->auth_data);

	      if (ret)
		break;
	      
	      /* Authentication failed */
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      silc_free(auth_data);
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      silc_protocol_execute(protocol, server->schedule, 
				    0, 300000);
	      return;
	      break;
	      
	    case SILC_AUTH_PUBLIC_KEY:
	      /* Public key authentication */
	      SILC_LOG_DEBUG(("Public key authentication"));
	      ret = silc_server_public_key_authentication(server, 
							  serv->auth_data,
							  auth_data,
							  payload_len, 
							  ctx->ske);
							  
	      if (ret)
		break;
	      
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      silc_free(auth_data);
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      silc_protocol_execute(protocol, server->schedule, 
				    0, 300000);
	      return;
	    }
	  } else {
	    SILC_LOG_DEBUG(("No configuration for remote connection"));
	    SILC_LOG_ERROR(("Remote connection not configured"));
	    SILC_LOG_ERROR(("Authentication failed"));
	    silc_free(auth_data);
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, server->schedule, 
				  0, 300000);
	    return;
	  }
	}
	
	silc_free(auth_data);

	/* Save connection type. This is later used to create the
	   ID for the connection. */
	ctx->conn_type = conn_type;
	  
	/* Advance protocol state. */
	protocol->state = SILC_PROTOCOL_STATE_END;
	silc_protocol_execute(protocol, server->schedule, 0, 0);

      } else {
	/* 
	 * We are initiator. We are authenticating ourselves to a
	 * remote server. We will send the authentication data to the
	 * other end for verify. 
	 */
	SilcBuffer packet;
	int payload_len = 0;
	unsigned char *auth_data = NULL;
	uint32 auth_data_len = 0;
	
	switch(ctx->auth_meth) {
	case SILC_AUTH_NONE:
	  /* No authentication required */
	  break;
	  
	case SILC_AUTH_PASSWORD:
	  /* Password authentication */
	  if (ctx->auth_data && ctx->auth_data_len) {
	    auth_data = strdup(ctx->auth_data);
	    auth_data_len = ctx->auth_data_len;
	    break;
	  }
	  break;
	  
	case SILC_AUTH_PUBLIC_KEY:
	  {
	    unsigned char sign[1024];

	    /* Public key authentication */
	    silc_server_get_public_key_auth(server, sign, &auth_data_len,
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
			   SILC_STR_UI_SHORT(server->server_type 
					      == SILC_SERVER ?
					      SILC_SOCKET_TYPE_SERVER :
					      SILC_SOCKET_TYPE_ROUTER),
			   SILC_STR_UI_XNSTRING(auth_data, auth_data_len),
			   SILC_STR_END);
	
	/* Send the packet to server */
	silc_server_packet_send(server, ctx->sock,
				SILC_PACKET_CONNECTION_AUTH, 0, 
				packet->data, packet->len, TRUE);
	
	if (auth_data) {
	  memset(auth_data, 0, auth_data_len);
	  silc_free(auth_data);
	}
	silc_buffer_free(packet);
	
	/* Next state is end of protocol */
	protocol->state = SILC_PROTOCOL_STATE_END;
      }
    }
    break;

  case SILC_PROTOCOL_STATE_END:
    {
      /* 
       * End protocol
       */
      unsigned char ok[4];

      SILC_PUT32_MSB(SILC_AUTH_OK, ok);

      /* Authentication successful */
      silc_server_packet_send(server, ctx->sock, SILC_PACKET_SUCCESS,
			      0, ok, 4, TRUE);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_schedule_task_del(server->schedule, ctx->timeout_task);

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
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

      /* Authentication failed */
      silc_server_packet_send(server, ctx->sock, SILC_PACKET_FAILURE,
			      0, error, 4, TRUE);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_schedule_task_del(server->schedule, ctx->timeout_task);

      /* On error the final callback is always called. */
      if (protocol->final_callback)
	silc_protocol_execute_final(protocol, server->schedule);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * We have received failure from remote
     */

    /* Unregister the timeout task since the protocol has ended. 
       This was the timeout task to be executed if the protocol is
       not completed fast enough. */
    if (ctx->timeout_task)
      silc_schedule_task_del(server->schedule, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
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
silc_server_protocol_rekey_validate(SilcServer server,
				    SilcServerRekeyInternalContext *ctx,
				    SilcIDListData idata,
				    SilcSKEKeyMaterial *keymat,
				    bool send)
{
  if (ctx->responder == TRUE) {
    if (send) {
      silc_cipher_set_key(idata->send_key, keymat->receive_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(idata->send_key, keymat->receive_iv);
      silc_hmac_set_key(idata->hmac_send, keymat->receive_hmac_key, 
			keymat->hmac_key_len);
    } else {
      silc_cipher_set_key(idata->receive_key, keymat->send_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(idata->receive_key, keymat->send_iv);
      silc_hmac_set_key(idata->hmac_receive, keymat->send_hmac_key, 
			keymat->hmac_key_len);
    }
  } else {
    if (send) {
      silc_cipher_set_key(idata->send_key, keymat->send_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(idata->send_key, keymat->send_iv);
      silc_hmac_set_key(idata->hmac_send, keymat->send_hmac_key, 
			keymat->hmac_key_len);
    } else {
      silc_cipher_set_key(idata->receive_key, keymat->receive_enc_key, 
			  keymat->enc_key_len);
      silc_cipher_set_iv(idata->receive_key, keymat->receive_iv);
      silc_hmac_set_key(idata->hmac_receive, keymat->receive_hmac_key, 
			keymat->hmac_key_len);
    }
  }

  /* Save the current sending encryption key */
  if (!send) {
    memset(idata->rekey->send_enc_key, 0, idata->rekey->enc_key_len);
    silc_free(idata->rekey->send_enc_key);
    idata->rekey->send_enc_key = 
      silc_calloc(keymat->enc_key_len / 8,
		  sizeof(*idata->rekey->send_enc_key));
    memcpy(idata->rekey->send_enc_key, keymat->send_enc_key, 
	   keymat->enc_key_len / 8);
    idata->rekey->enc_key_len = keymat->enc_key_len / 8;
  }
}

/* This function actually re-generates (when not using PFS) the keys and
   takes them into use. */

void silc_server_protocol_rekey_generate(SilcServer server,
					 SilcServerRekeyInternalContext *ctx,
					 bool send)
{
  SilcIDListData idata = (SilcIDListData)ctx->sock->user_data;
  SilcSKEKeyMaterial *keymat;
  uint32 key_len = silc_cipher_get_key_len(idata->send_key);
  uint32 hash_len = idata->hash->hash->hash_len;

  SILC_LOG_DEBUG(("Generating new %s session keys (no PFS)",
		  send ? "sending" : "receiving"));

  /* Generate the new key */
  keymat = silc_calloc(1, sizeof(*keymat));
  silc_ske_process_key_material_data(idata->rekey->send_enc_key,
				     idata->rekey->enc_key_len,
				     16, key_len, hash_len, 
				     idata->hash, keymat);

  /* Set the keys into use */
  silc_server_protocol_rekey_validate(server, ctx, idata, keymat, send);

  silc_ske_free_key_material(keymat);
}

/* This function actually re-generates (with PFS) the keys and
   takes them into use. */

void 
silc_server_protocol_rekey_generate_pfs(SilcServer server,
					SilcServerRekeyInternalContext *ctx,
					bool send)
{
  SilcIDListData idata = (SilcIDListData)ctx->sock->user_data;
  SilcSKEKeyMaterial *keymat;
  uint32 key_len = silc_cipher_get_key_len(idata->send_key);
  uint32 hash_len = idata->hash->hash->hash_len;
  unsigned char *tmpbuf;
  uint32 klen;

  SILC_LOG_DEBUG(("Generating new %s session keys (with PFS)",
		  send ? "sending" : "receiving"));

  /* Encode KEY to binary data */
  tmpbuf = silc_mp_mp2bin(ctx->ske->KEY, 0, &klen);

  /* Generate the new key */
  keymat = silc_calloc(1, sizeof(*keymat));
  silc_ske_process_key_material_data(tmpbuf, klen, 16, key_len, hash_len, 
				     idata->hash, keymat);

  /* Set the keys into use */
  silc_server_protocol_rekey_validate(server, ctx, idata, keymat, send);

  memset(tmpbuf, 0, klen);
  silc_free(tmpbuf);
  silc_ske_free_key_material(keymat);
}

/* Packet sending callback. This function is provided as packet sending
   routine to the Key Exchange functions. */

static void 
silc_server_protocol_rekey_send_packet(SilcSKE ske,
				       SilcBuffer packet,
				       SilcPacketType type,
				       void *context)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerRekeyInternalContext *ctx = 
    (SilcServerRekeyInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;

  /* Send the packet immediately */
  silc_server_packet_send(server, ctx->sock,
			  type, 0, packet->data, packet->len, FALSE);
}

/* Performs re-key as defined in the SILC protocol specification. */

SILC_TASK_CALLBACK(silc_server_protocol_rekey)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcServerRekeyInternalContext *ctx = 
    (SilcServerRekeyInternalContext *)protocol->context;
  SilcServer server = (SilcServer)ctx->server;
  SilcIDListData idata = (SilcIDListData)ctx->sock->user_data;
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
	    silc_protocol_execute(protocol, server->schedule, 0, 300000);
	    return;
	  }

	  ctx->ske = silc_ske_alloc();
	  ctx->ske->rng = server->rng;
	  ctx->ske->prop = silc_calloc(1, sizeof(*ctx->ske->prop));
	  silc_ske_group_get_by_number(idata->rekey->ske_group,
				       &ctx->ske->prop->group);

	  silc_ske_set_callbacks(ctx->ske, 
				 silc_server_protocol_rekey_send_packet, 
				 NULL, NULL, NULL, silc_ske_check_version,
				 context);
      
	  status = silc_ske_responder_phase_2(ctx->ske, ctx->packet->buffer);
	  if (status != SILC_SKE_STATUS_OK) {
	    SILC_LOG_WARNING(("Error (%s) during Re-key (PFS)",
			      silc_ske_map_status(status)));
	    
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, server->schedule, 0, 300000);
	    return;
	  }

	  /* Advance the protocol state */
	  protocol->state++;
	  silc_protocol_execute(protocol, server->schedule, 0, 0);
	} else {
	  /*
	   * Do normal and simple re-key.
	   */

	  /* Send the REKEY_DONE to indicate we will take new keys into use */
	  silc_server_packet_send(server, ctx->sock, SILC_PACKET_REKEY_DONE,
				  0, NULL, 0, FALSE);

	  /* After we send REKEY_DONE we must set the sending encryption
	     key to the new key since all packets after this packet must
	     encrypted with the new key. */
	  silc_server_protocol_rekey_generate(server, ctx, TRUE);

	  /* The protocol ends in next stage. */
	  protocol->state = SILC_PROTOCOL_STATE_END;
	}
      
      } else {
	/*
	 * We are the initiator of this protocol
	 */

	/* Start the re-key by sending the REKEY packet */
	silc_server_packet_send(server, ctx->sock, SILC_PACKET_REKEY,
				0, NULL, 0, FALSE);

	if (ctx->pfs == TRUE) {
	  /* 
	   * Use Perfect Forward Secrecy, ie. negotiate the key material
	   * using the SKE protocol.
	   */
	  ctx->ske = silc_ske_alloc();
	  ctx->ske->rng = server->rng;
	  ctx->ske->prop = silc_calloc(1, sizeof(*ctx->ske->prop));
	  silc_ske_group_get_by_number(idata->rekey->ske_group,
				       &ctx->ske->prop->group);

	  silc_ske_set_callbacks(ctx->ske, 
				 silc_server_protocol_rekey_send_packet, 
				 NULL, NULL, NULL, silc_ske_check_version,
				 context);
      
	  status = silc_ske_initiator_phase_2(ctx->ske, NULL, NULL);
	  if (status != SILC_SKE_STATUS_OK) {
	    SILC_LOG_WARNING(("Error (%s) during Re-key (PFS)",
			      silc_ske_map_status(status)));
	    
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    silc_protocol_execute(protocol, server->schedule, 0, 300000);
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
	  silc_server_packet_send(server, ctx->sock, SILC_PACKET_REKEY_DONE,
				  0, NULL, 0, FALSE);

	  /* After we send REKEY_DONE we must set the sending encryption
	     key to the new key since all packets after this packet must
	     encrypted with the new key. */
	  silc_server_protocol_rekey_generate(server, ctx, TRUE);

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
	  SILC_LOG_WARNING(("Error (%s) during Re-key (PFS)",
			    silc_ske_map_status(status)));
	  
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, server->schedule, 0, 300000);
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
	  silc_protocol_execute(protocol, server->schedule, 0, 300000);
	  return;
	}
	
	status = silc_ske_initiator_finish(ctx->ske, ctx->packet->buffer);
	if (status != SILC_SKE_STATUS_OK) {
	  SILC_LOG_WARNING(("Error (%s) during Re-key (PFS)",
			    silc_ske_map_status(status)));
	  
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  silc_protocol_execute(protocol, server->schedule, 0, 300000);
	  return;
	}
      }
    }

    /* Send the REKEY_DONE to indicate we will take new keys into use 
       now. */ 
    silc_server_packet_send(server, ctx->sock, SILC_PACKET_REKEY_DONE,
			    0, NULL, 0, FALSE);
    
    /* After we send REKEY_DONE we must set the sending encryption
       key to the new key since all packets after this packet must
       encrypted with the new key. */
    silc_server_protocol_rekey_generate_pfs(server, ctx, TRUE);

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
      silc_protocol_execute(protocol, server->schedule, 0, 300000);
      return;
    }

    /* We received the REKEY_DONE packet and all packets after this is
       encrypted with the new key so set the decryption key to the new key */
    silc_server_protocol_rekey_generate(server, ctx, FALSE);

    /* Protocol has ended, call the final callback */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
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
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_FAILURE:
    /*
     * We have received failure from remote
     */

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      silc_protocol_execute_final(protocol, server->schedule);
    else
      silc_protocol_free(protocol);
    break;

  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }

}

/* Registers protocols used in server. */

void silc_server_protocols_register(void)
{
  silc_protocol_register(SILC_PROTOCOL_SERVER_CONNECTION_AUTH,
			 silc_server_protocol_connection_auth);
  silc_protocol_register(SILC_PROTOCOL_SERVER_KEY_EXCHANGE,
			 silc_server_protocol_key_exchange);
  silc_protocol_register(SILC_PROTOCOL_SERVER_REKEY,
			 silc_server_protocol_rekey);
  silc_protocol_register(SILC_PROTOCOL_SERVER_BACKUP,
			 silc_server_protocol_backup);
}

/* Unregisters protocols */

void silc_server_protocols_unregister(void)
{
  silc_protocol_unregister(SILC_PROTOCOL_SERVER_CONNECTION_AUTH,
			   silc_server_protocol_connection_auth);
  silc_protocol_unregister(SILC_PROTOCOL_SERVER_KEY_EXCHANGE,
			   silc_server_protocol_key_exchange);
  silc_protocol_unregister(SILC_PROTOCOL_SERVER_REKEY,
			   silc_server_protocol_rekey);
  silc_protocol_unregister(SILC_PROTOCOL_SERVER_BACKUP,
			   silc_server_protocol_backup);
}
