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
 * Client side of the protocols.
 */
/*
 * $Id$
 * $Log$
 * Revision 1.6  2000/07/14 06:12:29  priikone
 * 	Put the HMAC keys into the HMAC object instead on having them
 * 	saved elsewhere; we can use now silc_hmac_make instead of
 * 	silc_hmac_make_with_key.
 *
 * Revision 1.5  2000/07/07 11:36:09  priikone
 * 	Inform user when received unsupported public key from server.
 *
 * Revision 1.4  2000/07/07 06:53:45  priikone
 * 	Added support for server public key verification.
 *
 * Revision 1.3  2000/07/06 07:14:16  priikone
 * 	Deprecated old `channel_auth' protocol.
 *
 * Revision 1.2  2000/07/05 06:12:05  priikone
 * 	Global cosmetic changes.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:56  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "clientincludes.h"

SILC_TASK_CALLBACK(silc_client_protocol_connection_auth);
SILC_TASK_CALLBACK(silc_client_protocol_key_exchange);

/* SILC client protocol list */
const SilcProtocolObject silc_protocol_list[] =
{
  { SILC_PROTOCOL_CLIENT_CONNECTION_AUTH, 
    silc_client_protocol_connection_auth },
  { SILC_PROTOCOL_CLIENT_KEY_EXCHANGE, 
    silc_client_protocol_key_exchange },

  { SILC_PROTOCOL_CLIENT_NONE, NULL },
};

/*
 * Key Exhange protocol functions
 */

/* Function that is called when SKE protocol sends packets to network. */

static void silc_client_protocol_ke_send_packet(SilcSKE ske,
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

static SilcSKEStatus 
silc_client_protocol_ke_verify_key(SilcSKE ske,
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

  if (!silc_client_verify_server_key(client, ctx->sock, 
				     pk_data, pk_len, pk_type))
    return SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY;

  return SILC_SKE_STATUS_OK;
}

/* Sets the negotiated key material into use for particular connection. */

static void silc_client_protocol_ke_set_keys(SilcSKE ske,
					     SilcSocketConnection sock,
					     SilcSKEKeyMaterial *keymat,
					     SilcCipher cipher,
					     SilcPKCS pkcs,
					     SilcHash hash)
{
  SilcClientWindow win = (SilcClientWindow)sock->user_data;
  SilcHash nhash;

  SILC_LOG_DEBUG(("Setting new keys into use"));

  /* Allocate cipher to be used in the communication */
  silc_cipher_alloc(cipher->cipher->name, &win->send_key);
  silc_cipher_alloc(cipher->cipher->name, &win->receive_key);

  win->send_key->cipher->set_key(win->send_key->context, 
				 keymat->send_enc_key, 
				 keymat->enc_key_len);
  win->send_key->set_iv(win->send_key, keymat->send_iv);
  win->receive_key->cipher->set_key(win->receive_key->context, 
				    keymat->receive_enc_key, 
				    keymat->enc_key_len);
  win->receive_key->set_iv(win->receive_key, keymat->receive_iv);

  /* Allocate PKCS to be used */
#if 0
  /* XXX Do we ever need to allocate PKCS for the connection??
     If yes, we need to change KE protocol to get the initiators
     public key. */
  silc_pkcs_alloc(pkcs->pkcs->name, &win->public_Key);
  silc_pkcs_set_public_key(win->public_key, ske->ke2_payload->pk_data, 
			   ske->ke2_payload->pk_len);
#endif

  /* Save HMAC key to be used in the communication. */
  silc_hash_alloc(hash->hash->name, &nhash);
  silc_hmac_alloc(nhash, &win->hmac);
  silc_hmac_set_key(win->hmac, keymat->hmac_key, keymat->hmac_key_len);
}

/* Performs key exchange protocol. This is used for both initiator
   and responder key exchange. This may be called recursively. */

SILC_TASK_CALLBACK(silc_client_protocol_key_exchange)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientKEInternalContext *ctx = 
    (SilcClientKEInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;
  SilcSKEStatus status;

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
      
      if (ctx->responder == TRUE) {
#if 0
	SilcBuffer start_payload;


	/* Start the key exchange by processing the received security
	   properties packet from initiator. */
	status = silc_ske_responder_start(ske, ctx->rng, ctx->sock,
					  start_payload,
					  silc_client_protocol_ke_send_packet,
					  context);
#endif
      } else {
	SilcSKEStartPayload *start_payload;

	/* Assemble security properties. */
	silc_ske_assemble_security_properties(ske, &start_payload);

	/* Start the key exchange by sending our security properties
	   to the remote end. */
	status = silc_ske_initiator_start(ske, ctx->rng, ctx->sock,
					  start_payload,
					  silc_client_protocol_ke_send_packet,
					  context);
      }

      if (status != SILC_SKE_STATUS_OK) {
	switch(status) {
	  
	default:
	  break;
	}
      }

      /* Advance the state of the protocol. */
      protocol->state++;
    }
    break;
  case 2:
    {
      /* 
       * Phase 1 
       */
      if (ctx->responder == TRUE) {
#if 0
	status = 
	  silc_ske_responder_phase_1(ctx->ske, 
				     ctx->ske->start_payload,
				     silc_server_protocol_ke_send_packet,
				     context);
#endif
      } else {
	/* Call Phase-1 function. This processes the Key Exchange Start
	   paylaod reply we just got from the responder. The callback
	   function will receive the processed payload where we will
	   save it. */
	status = silc_ske_initiator_phase_1(ctx->ske, ctx->packet, NULL, NULL);
      }

      switch(status) {
      default:
	break;
      }

      /* Advance the state of the protocol and call the next state. */
      protocol->state++;
      protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
    }
    break;
  case 3:
    {
      /* 
       * Phase 2 
       */
      if (ctx->responder == TRUE) {
#if 0
	status = 
	  silc_ske_responder_phase_2(ctx->ske, 
				     ctx->ske->start_payload,
				     silc_server_protocol_ke_send_packet,
				     context);
#endif
      } else {
	/* Call the Phase-2 function. This creates Diffie Hellman
	   key exchange parameters and sends our public part inside
	   Key Exhange 1 Payload to the responder. */
	status = 
	  silc_ske_initiator_phase_2(ctx->ske,
				     silc_client_protocol_ke_send_packet,
				     context);
      }

      switch(status) {
      default:
	break;
      }

      /* Advance the state of the protocol. */
      protocol->state++;
    }
    break;
  case 4:
    {
      /* 
       * Finish protocol
       */
      if (ctx->responder == TRUE) {
	status = 0;
#if 0
	status = 
	  silc_ske_responder_phase_2(ctx->ske, 
				     ctx->ske->start_payload,
				     silc_server_protocol_ke_send_packet,
				     context);
#endif
      } else {
	/* Finish the protocol. This verifies the Key Exchange 2 payload
	   sent by responder. */
	status = silc_ske_initiator_finish(ctx->ske, ctx->packet,
					   silc_client_protocol_ke_verify_key,
					   context, NULL, NULL);
      }

      if (status != SILC_SKE_STATUS_OK) {

        if (status == SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY) {
          silc_say(client, "Received unsupported server %s public key",
                   ctx->sock->hostname);
        } else {
          silc_say(client, "Error during key exchange protocol with server %s",
                   ctx->sock->hostname);
        }
	protocol->state = SILC_PROTOCOL_STATE_ERROR;
	protocol->execute(client->timeout_queue, 0, protocol, fd, 0, 0);
	return;
      }
      
      /* Send Ok to the other end. We will end the protocol as server
	 sends Ok to us when we will take the new keys into use. */
      silc_ske_end(ctx->ske, silc_client_protocol_ke_send_packet, context);
      
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

      /* Process the key material */
      keymat = silc_calloc(1, sizeof(*keymat));
      silc_ske_process_key_material(ctx->ske, 16, (16 * 8), 16, keymat);

      /* Take the negotiated keys into use. */
      silc_client_protocol_ke_set_keys(ctx->ske, ctx->sock, keymat,
				       ctx->ske->prop->cipher,
				       ctx->ske->prop->pkcs,
				       ctx->ske->prop->hash);

      /* Protocol has ended, call the final callback */
      if (protocol->final_callback)
	protocol->execute_final(client->timeout_queue, 0, protocol, fd);
      else
	silc_protocol_free(protocol);
    }
    break;
  case SILC_PROTOCOL_STATE_ERROR:
    
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

SILC_TASK_CALLBACK(silc_client_protocol_connection_auth)
{
  SilcProtocol protocol = (SilcProtocol)context;
  SilcClientConnAuthInternalContext *ctx = 
    (SilcClientConnAuthInternalContext *)protocol->context;
  SilcClient client = (SilcClient)ctx->client;

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

	silc_say(client, "Password authentication required by server %s",
		 ctx->sock->hostname);
	auth_data = silc_client_ask_passphrase(client);
	auth_data_len = strlen(auth_data);
	break;

      case SILC_PROTOCOL_CONN_AUTH_PUBLIC_KEY:
	/* XXX */
	break;
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
       * Error
       */

      /* Error in protocol. Send FAILURE packet. Although I don't think
	 this could ever happen on client side. */
      silc_client_packet_send(client, ctx->sock, SILC_PACKET_FAILURE,
			      NULL, 0, NULL, NULL, NULL, 0, TRUE);

      /* On error the final callback is always called. */
      if (protocol->final_callback)
	protocol->execute_final(client->timeout_queue, 0, protocol, fd);
      else
	silc_protocol_free(protocol);
    }
    break;
  case SILC_PROTOCOL_STATE_UNKNOWN:
    break;
  }
}

