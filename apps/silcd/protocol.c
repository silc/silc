/*

  protocol.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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

extern char *silc_version_string;

/*
 * Key Exhange protocol functions
 */

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

static void silc_server_protocol_ke_set_keys(SilcSKE ske,
					     SilcSocketConnection sock,
					     SilcSKEKeyMaterial *keymat,
					     SilcCipher cipher,
					     SilcPKCS pkcs,
					     SilcHash hash,
					     int is_responder)
{
  SilcUnknownEntry conn_data;
  SilcHash nhash;

  SILC_LOG_DEBUG(("Setting new key into use"));

  conn_data = silc_calloc(1, sizeof(*conn_data));

  /* Allocate cipher to be used in the communication */
  silc_cipher_alloc(cipher->cipher->name, &conn_data->send_key);
  silc_cipher_alloc(cipher->cipher->name, &conn_data->receive_key);
  
  if (is_responder == TRUE) {
    conn_data->send_key->cipher->set_key(conn_data->send_key->context, 
					 keymat->receive_enc_key, 
					 keymat->enc_key_len);
    conn_data->send_key->set_iv(conn_data->send_key, keymat->receive_iv);
    conn_data->receive_key->cipher->set_key(conn_data->receive_key->context, 
					    keymat->send_enc_key, 
					    keymat->enc_key_len);
    conn_data->receive_key->set_iv(conn_data->receive_key, keymat->send_iv);
    
  } else {
    conn_data->send_key->cipher->set_key(conn_data->send_key->context, 
					 keymat->send_enc_key, 
					 keymat->enc_key_len);
    conn_data->send_key->set_iv(conn_data->send_key, keymat->send_iv);
    conn_data->receive_key->cipher->set_key(conn_data->receive_key->context, 
					    keymat->receive_enc_key, 
					    keymat->enc_key_len);
    conn_data->receive_key->set_iv(conn_data->receive_key, keymat->receive_iv);
  }

  /* Allocate PKCS to be used */
#if 0
  /* XXX Do we ever need to allocate PKCS for the connection??
     If yes, we need to change KE protocol to get the initiators
     public key. */
  silc_pkcs_alloc(pkcs->pkcs->name, &conn_data->pkcs);
  conn_data->public_key = silc_pkcs_public_key_alloc(XXX);
  silc_pkcs_set_public_key(conn_data->pkcs, ske->ke2_payload->pk_data, 
			   ske->ke2_payload->pk_len);
#endif

  /* Save HMAC key to be used in the communication. */
  silc_hash_alloc(hash->hash->name, &nhash);
  silc_hmac_alloc(nhash, &conn_data->hmac);
  silc_hmac_set_key(conn_data->hmac, keymat->hmac_key, keymat->hmac_key_len);

  sock->user_data = (void *)conn_data;
}

/* XXX TODO */

SilcSKEStatus silc_ske_check_version(SilcSKE ske, unsigned char *version,
				     unsigned int len)
{
  return SILC_SKE_STATUS_OK;
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
  SilcSKEStatus status = 0;

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
      
      if (ctx->responder == TRUE) {
	/* Start the key exchange by processing the received security
	   properties packet from initiator. */
	status = silc_ske_responder_start(ske, ctx->rng, ctx->sock,
					  silc_version_string,
					  ctx->packet, NULL, NULL);
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
					  silc_server_protocol_ke_send_packet,
					  context);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 300000);
	return;
      }

      /* Advance protocol state and call the next state if we are responder */
      protocol->state++;
      if (ctx->responder == TRUE)
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 100000);
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
				     silc_server_protocol_ke_send_packet,
				     context);
      } else {
	/* Call Phase-1 function. This processes the Key Exchange Start
	   paylaod reply we just got from the responder. The callback
	   function will receive the processed payload where we will
	   save it. */
	status = 
	  silc_ske_initiator_phase_1(ctx->ske,
				     ctx->packet,
				     NULL, NULL);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 300000);
	return;
      }

      /* Advance protocol state and call next state if we are initiator */
      protocol->state++;
      if (ctx->responder == FALSE)
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 100000);
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
	status = 
	  silc_ske_responder_phase_2(ctx->ske, ctx->packet, NULL, NULL);
      } else {
	/* Call the Phase-2 function. This creates Diffie Hellman
	   key exchange parameters and sends our public part inside
	   Key Exhange 1 Payload to the responder. */
	status = 
	  silc_ske_initiator_phase_2(ctx->ske,
				     server->public_key,
				     silc_server_protocol_ke_send_packet,
				     context);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 300000);
	return;
      }

      /* Advance protocol state and call the next state if we are responder */
      protocol->state++;
      if (ctx->responder == TRUE)
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 100000);
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
				    server->public_key, server->private_key,
				    SILC_SKE_PK_TYPE_SILC,
				    silc_server_protocol_ke_send_packet,
				    context);
      } else {
	/* Finish the protocol. This verifies the Key Exchange 2 payload
	   sent by responder. */
	status = 
	  silc_ske_initiator_finish(ctx->ske,
				    ctx->packet, NULL, NULL, NULL, NULL);
      }

      if (status != SILC_SKE_STATUS_OK) {
	SILC_LOG_WARNING(("Error (type %d) during Key Exchange protocol",
			  status));
	SILC_LOG_DEBUG(("Error (type %d) during Key Exchange protocol",
			status));

	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 300000);
	return;
      }

      /* Send Ok to the other end. We will end the protocol as responder
	 sends Ok to us when we will take the new keys into use. */
      if (ctx->responder == FALSE)
	silc_ske_end(ctx->ske, silc_server_protocol_ke_send_packet, context);

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

      /* Send Ok to the other end if we are responder. If we are 
	 initiator we have sent this already. */
      if (ctx->responder == TRUE)
	silc_ske_end(ctx->ske, silc_server_protocol_ke_send_packet, context);

      /* Process the key material */
      keymat = silc_calloc(1, sizeof(*keymat));
      silc_ske_process_key_material(ctx->ske, 16, (16 * 8), 16, keymat);

      /* Take the new keys into use. */
      silc_server_protocol_ke_set_keys(ctx->ske, ctx->sock, keymat,
				       ctx->ske->prop->cipher,
				       ctx->ske->prop->pkcs,
				       ctx->ske->prop->hash,
				       ctx->responder);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_task_unregister(server->timeout_queue, ctx->timeout_task);

      /* Call the final callback */
      if (protocol->final_callback)
	protocol->execute_final(server->timeout_queue, 0, protocol, fd);
      else
	silc_protocol_free(protocol);
    }
    break;

  case SILC_PROTOCOL_STATE_ERROR:
    /*
     * Error occured
     */

    /* Send abort notification */
    silc_ske_abort(ctx->ske, ctx->ske->status, 
		   silc_server_protocol_ke_send_packet,
		   context);

    /* Unregister the timeout task since the protocol has ended. 
       This was the timeout task to be executed if the protocol is
       not completed fast enough. */
    if (ctx->timeout_task)
      silc_task_unregister(server->timeout_queue, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      protocol->execute_final(server->timeout_queue, 0, protocol, fd);
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
      silc_task_unregister(server->timeout_queue, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      protocol->execute_final(server->timeout_queue, 0, protocol, fd);
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

/* XXX move these to somehwere else */

int silc_server_password_authentication(SilcServer server, char *auth1, 
					char *auth2)
{
  if (!auth1 || !auth2)
    return FALSE;

  if (!memcmp(auth1, auth2, strlen(auth1)))
    return TRUE;

  return FALSE;
}

int silc_server_public_key_authentication(SilcServer server,
					  char *pkfile,
					  unsigned char *sign,
					  unsigned int sign_len,
					  SilcSKE ske)
{
  SilcPublicKey pub_key;
  SilcPKCS pkcs;
  int len;
  SilcBuffer auth;

  if (!pkfile || !sign)
    return FALSE;

  /* Load public key from file */
  if (!silc_pkcs_load_public_key(pkfile, &pub_key, SILC_PKCS_FILE_PEM))
    if (!silc_pkcs_load_public_key(pkfile, &pub_key, SILC_PKCS_FILE_BIN))
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
  if (pkcs->pkcs->verify(pkcs->context, sign, sign_len,
			 auth->data, auth->len))
    {
      silc_pkcs_free(pkcs);
      silc_pkcs_public_key_free(pub_key);
      silc_buffer_free(auth);
      return TRUE;
    }

  silc_pkcs_free(pkcs);
  silc_pkcs_public_key_free(pub_key);
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
	unsigned short payload_len;
	unsigned short conn_type;
	unsigned char *auth_data;

	SILC_LOG_INFO(("Performing authentication protocol for %s",
		       ctx->sock->hostname ? ctx->sock->hostname :
		       ctx->sock->ip));

	/* Parse the received authentication data packet. The received
	   payload is Connection Auth Payload. */
	silc_buffer_unformat(ctx->packet,
			     SILC_STR_UI_SHORT(&payload_len),
			     SILC_STR_UI_SHORT(&conn_type),
			     SILC_STR_END);
	
	if (payload_len != ctx->packet->len) {
	  SILC_LOG_ERROR(("Bad payload in authentication packet"));
	  SILC_LOG_DEBUG(("Bad payload in authentication packet"));
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 300000);
	  return;
	}
	
	payload_len -= 4;
	
	if (conn_type < SILC_SOCKET_TYPE_CLIENT || 
	    conn_type > SILC_SOCKET_TYPE_ROUTER) {
	  SILC_LOG_ERROR(("Bad connection type %d", conn_type));
	  SILC_LOG_DEBUG(("Bad connection type %d", conn_type));
	  protocol->state = SILC_PROTOCOL_STATE_ERROR;
	  protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 300000);
	  return;
	}
	
	if (payload_len > 0) {
	  /* Get authentication data */
	  silc_buffer_pull(ctx->packet, 4);
	  silc_buffer_unformat(ctx->packet,
			       SILC_STR_UI_XNSTRING_ALLOC(&auth_data, 
							  payload_len),
			       SILC_STR_END);
	} else {
	  auth_data = NULL;
	}

	/* 
	 * Check the remote connection type and make sure that we have
	 * configured this connection. If we haven't allowed this connection
	 * the authentication must be failed.
	 */

	SILC_LOG_DEBUG(("Remote connection type %d", conn_type));

	/* Remote end is client */
	if (conn_type == SILC_SOCKET_TYPE_CLIENT) {
	  SilcConfigServerSectionClientConnection *client = NULL;
	  client = 
	    silc_config_server_find_client_conn(server->config,
						ctx->sock->ip,
						ctx->sock->port);
	  if (!client)
	    client = 
	      silc_config_server_find_client_conn(server->config,
						  ctx->sock->hostname,
						  ctx->sock->port);
	  
	  if (client) {
	    switch(client->auth_meth) {
	    case SILC_PROTOCOL_CONN_AUTH_NONE:
	      /* No authentication required */
	      SILC_LOG_DEBUG(("No authentication required"));
	      break;
	      
	    case SILC_PROTOCOL_CONN_AUTH_PASSWORD:
	      /* Password authentication */
	      SILC_LOG_DEBUG(("Password authentication"));
	      ret = silc_server_password_authentication(server, auth_data,
							client->auth_data);

	      if (ret) {
		memset(auth_data, 0, payload_len);
		silc_free(auth_data);
		auth_data = NULL;
		break;
	      }

	      /* Authentication failed */
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      protocol->execute(server->timeout_queue, 0, 
				protocol, fd, 0, 300000);
	      return;
	      break;
	      
	    case SILC_PROTOCOL_CONN_AUTH_PUBLIC_KEY:
	      /* Public key authentication */
	      SILC_LOG_DEBUG(("Public key authentication"));
	      ret = silc_server_public_key_authentication(server, 
							  client->auth_data,
							  auth_data,
							  payload_len, 
							  ctx->ske);
							  
	      if (ret) {
		memset(auth_data, 0, payload_len);
		silc_free(auth_data);
		auth_data = NULL;
		break;
	      }

	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      protocol->execute(server->timeout_queue, 0, 
				protocol, fd, 0, 300000);
	      return;
	    }
	  } else {
	    SILC_LOG_DEBUG(("No configuration for remote connection"));
	    SILC_LOG_ERROR(("Remote connection not configured"));
	    SILC_LOG_ERROR(("Authentication failed"));
	    memset(auth_data, 0, payload_len);
	    silc_free(auth_data);
	    auth_data = NULL;
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    protocol->execute(server->timeout_queue, 0, 
			      protocol, fd, 0, 300000);
	    return;
	  }
	}
	
	/* Remote end is server */
	if (conn_type == SILC_SOCKET_TYPE_SERVER) {
	  SilcConfigServerSectionServerConnection *serv = NULL;
	  serv = 
	    silc_config_server_find_server_conn(server->config,
						ctx->sock->ip,
						ctx->sock->port);
	  if (!serv)
	    serv = 
	      silc_config_server_find_server_conn(server->config,
						  ctx->sock->hostname,
						  ctx->sock->port);
	  
	  if (serv) {
	    switch(serv->auth_meth) {
	    case SILC_PROTOCOL_CONN_AUTH_NONE:
	      /* No authentication required */
	      SILC_LOG_DEBUG(("No authentication required"));
	      break;
	      
	    case SILC_PROTOCOL_CONN_AUTH_PASSWORD:
	      /* Password authentication */
	      SILC_LOG_DEBUG(("Password authentication"));
	      ret = silc_server_password_authentication(server, auth_data,
							serv->auth_data);

	      if (ret) {
		memset(auth_data, 0, payload_len);
		silc_free(auth_data);
		auth_data = NULL;
		break;
	      }
	      
	      /* Authentication failed */
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      protocol->execute(server->timeout_queue, 0, 
				protocol, fd, 0, 300000);
	      return;
	      break;
	      
	    case SILC_PROTOCOL_CONN_AUTH_PUBLIC_KEY:
	      /* Public key authentication */
	      SILC_LOG_DEBUG(("Public key authentication"));
	      ret = silc_server_public_key_authentication(server, 
							  serv->auth_data,
							  auth_data,
							  payload_len, 
							  ctx->ske);
							  
	      if (ret) {
		memset(auth_data, 0, payload_len);
		silc_free(auth_data);
		auth_data = NULL;
		break;
	      }

	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      protocol->execute(server->timeout_queue, 0, 
				protocol, fd, 0, 300000);
	      return;
	    }
	  } else {
	    SILC_LOG_DEBUG(("No configuration for remote connection"));
	    SILC_LOG_ERROR(("Remote connection not configured"));
	    SILC_LOG_ERROR(("Authentication failed"));
	    memset(auth_data, 0, payload_len);
	    silc_free(auth_data);
	    auth_data = NULL;
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    protocol->execute(server->timeout_queue, 0, 
			      protocol, fd, 0, 300000);
	    return;
	  }
	}
	
	/* Remote end is router */
	if (conn_type == SILC_SOCKET_TYPE_ROUTER) {
	  SilcConfigServerSectionServerConnection *serv = NULL;
	  serv = 
	    silc_config_server_find_router_conn(server->config,
						ctx->sock->ip,
						ctx->sock->port);
	  if (!serv)
	    serv = 
	      silc_config_server_find_router_conn(server->config,
						  ctx->sock->hostname,
						  ctx->sock->port);
	  
	  if (serv) {
	    switch(serv->auth_meth) {
	    case SILC_PROTOCOL_CONN_AUTH_NONE:
	      /* No authentication required */
	      SILC_LOG_DEBUG(("No authentication required"));
	      break;
	      
	    case SILC_PROTOCOL_CONN_AUTH_PASSWORD:
	      /* Password authentication */
	      SILC_LOG_DEBUG(("Password authentication"));
	      ret = silc_server_password_authentication(server, auth_data,
							serv->auth_data);

	      if (ret) {
		memset(auth_data, 0, payload_len);
		silc_free(auth_data);
		auth_data = NULL;
		break;
	      }
	      
	      /* Authentication failed */
	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      protocol->execute(server->timeout_queue, 0, 
				protocol, fd, 0, 300000);
	      return;
	      break;
	      
	    case SILC_PROTOCOL_CONN_AUTH_PUBLIC_KEY:
	      /* Public key authentication */
	      SILC_LOG_DEBUG(("Public key authentication"));
	      ret = silc_server_public_key_authentication(server, 
							  serv->auth_data,
							  auth_data,
							  payload_len, 
							  ctx->ske);
							  
	      if (ret) {
		memset(auth_data, 0, payload_len);
		silc_free(auth_data);
		auth_data = NULL;
		break;
	      }

	      SILC_LOG_ERROR(("Authentication failed"));
	      SILC_LOG_DEBUG(("Authentication failed"));
	      protocol->state = SILC_PROTOCOL_STATE_ERROR;
	      protocol->execute(server->timeout_queue, 0, 
				protocol, fd, 0, 300000);
	      return;
	    }
	  } else {
	    SILC_LOG_DEBUG(("No configuration for remote connection"));
	    SILC_LOG_ERROR(("Remote connection not configured"));
	    SILC_LOG_ERROR(("Authentication failed"));
	    memset(auth_data, 0, payload_len);
	    silc_free(auth_data);
	    auth_data = NULL;
	    protocol->state = SILC_PROTOCOL_STATE_ERROR;
	    protocol->execute(server->timeout_queue, 0, 
			      protocol, fd, 0, 300000);
	    return;
	  }
	}
	
	if (auth_data) {
	  memset(auth_data, 0, payload_len);
	  silc_free(auth_data);
	}
	
	/* Save connection type. This is later used to create the
	   ID for the connection. */
	ctx->conn_type = conn_type;
	  
	/* Advance protocol state. */
	protocol->state = SILC_PROTOCOL_STATE_END;
	protocol->execute(server->timeout_queue, 0, protocol, fd, 0, 0);

      } else {
	/* 
	 * We are initiator. We are authenticating ourselves to a
	 * remote server. We will send the authentication data to the
	 * other end for verify. 
	 */
	SilcBuffer packet;
	int payload_len = 0;
	unsigned char *auth_data = NULL;
	unsigned int auth_data_len = 0;
	
	switch(ctx->auth_meth) {
	case SILC_PROTOCOL_CONN_AUTH_NONE:
	  /* No authentication required */
	  break;
	  
	case SILC_PROTOCOL_CONN_AUTH_PASSWORD:
	  /* Password authentication */
	  if (ctx->auth_data && ctx->auth_data_len) {
	    auth_data = ctx->auth_data;
	    auth_data_len = ctx->auth_data_len;
	    break;
	  }

	  /* No authentication data exits. Ask interactively from user. */
	  /* XXX */

	  break;
	  
	case SILC_PROTOCOL_CONN_AUTH_PUBLIC_KEY:
	  /* Public key authentication */
	  /* XXX TODO */
	  break;
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

      SILC_PUT32_MSB(SILC_CONN_AUTH_OK, ok);

      /* Authentication failed */
      silc_server_packet_send(server, ctx->sock, SILC_PACKET_FAILURE,
			      0, ok, 4, TRUE);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_task_unregister(server->timeout_queue, ctx->timeout_task);

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	protocol->execute_final(server->timeout_queue, 0, protocol, fd);
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

      SILC_PUT32_MSB(SILC_CONN_AUTH_FAILED, error);

      /* Authentication failed */
      silc_server_packet_send(server, ctx->sock, SILC_PACKET_FAILURE,
			      0, error, 4, TRUE);

      /* Unregister the timeout task since the protocol has ended. 
	 This was the timeout task to be executed if the protocol is
	 not completed fast enough. */
      if (ctx->timeout_task)
	silc_task_unregister(server->timeout_queue, ctx->timeout_task);

      /* On error the final callback is always called. */
      if (protocol->final_callback)
	protocol->execute_final(server->timeout_queue, 0, protocol, fd);
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
      silc_task_unregister(server->timeout_queue, ctx->timeout_task);

    /* On error the final callback is always called. */
    if (protocol->final_callback)
      protocol->execute_final(server->timeout_queue, 0, protocol, fd);
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
}

/* Unregisters protocols */

void silc_server_protocols_unregister(void)
{
  silc_protocol_unregister(SILC_PROTOCOL_SERVER_CONNECTION_AUTH,
			   silc_server_protocol_connection_auth);
  silc_protocol_unregister(SILC_PROTOCOL_SERVER_KEY_EXCHANGE,
			   silc_server_protocol_key_exchange);
}
