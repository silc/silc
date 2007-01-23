/*

  client_keyagr.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************** Types and definitions ***************************/

/* Key agreement context, used by responder */
struct SilcClientKeyAgreementStruct {
  SilcClient client;			  /* Client */
  SilcClientConnection conn;		  /* Server connection */
  SilcKeyAgreementCallback completion;	  /* Key agreement completion */
  void *context;			  /* User context */
  SilcClientConnectionParams params;      /* Connection parameters */
  SilcPublicKey public_key;		  /* Responder public key */
  SilcPrivateKey private_key;		  /* Responder private key */
  SilcNetListener tcp_listener;	          /* TCP listener */
  SilcPacketStream udp_listener;	  /* UDP listener */
  SilcPacketStream stream;  		  /* Remote connection (TCP or UDP) */
  SilcAsyncOperation op;	          /* SKE operation */
  SilcSKE ske;				  /* SKE */
};

/************************ Static utility functions **************************/

/* Destroyes key agreement session */

static void silc_client_keyagr_free(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry)
{
  SilcClientKeyAgreement ke = client_entry->internal.ke;

  silc_schedule_task_del_by_context(conn->internal->schedule, client_entry);

  if (ke->op)
    silc_async_abort(ke->op, NULL, NULL);
  if (ke->ske)
    silc_ske_free(ke->ske);
  if (ke->tcp_listener)
    silc_net_close_listener(ke->tcp_listener);
  silc_packet_stream_destroy(ke->stream);
  silc_packet_stream_destroy(ke->udp_listener);

  client_entry->internal.ke = NULL;
  client_entry->internal.prv_resp = FALSE;
  silc_client_unref_client(client, conn, client_entry);

  silc_free(ke);
}

/* Key agreement timeout callback */

SILC_TASK_CALLBACK(silc_client_keyagr_timeout)
{
  SilcClientEntry client_entry = context;
  SilcClientKeyAgreement ke = client_entry->internal.ke;

  SILC_LOG_DEBUG(("Key agreement %p timeout", ke));

  ke->completion(ke->client, ke->conn, client_entry,
		 SILC_KEY_AGREEMENT_TIMEOUT, NULL, ke->context);

  silc_client_keyagr_free(ke->client, ke->conn, client_entry);
}

/* Client resolving callback.  Continues with the key agreement processing */

static void silc_client_keyagr_resolved(SilcClient client,
					SilcClientConnection conn,
					SilcStatus status,
					SilcDList clients,
					void *context)
{
  /* If no client found, ignore the packet, a silent error */
  if (!clients)
    silc_fsm_next(context, silc_client_key_agreement_error);

  /* Continue processing the packet */
  SILC_FSM_CALL_CONTINUE(context);
}

/* Called after application has verified remote host's public key.  Responder
   function. */

static void silc_client_keyagr_verify_key_cb(SilcBool success, void *context)
{
  VerifyKeyContext verify = context;

  /* Call the completion callback back to the SKE */
  verify->completion(verify->ske, success ? SILC_SKE_STATUS_OK :
		     SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
		     verify->completion_context);

  silc_free(verify);
}

/* Verify remote host's public key.  Responder function. */

static void silc_client_keyagr_verify_key(SilcSKE ske,
					  SilcPublicKey public_key,
					  void *context,
					  SilcSKEVerifyCbCompletion completion,
					  void *completion_context)
{
  SilcClientEntry client_entry = context;
  SilcClientKeyAgreement ke = client_entry->internal.ke;
  SilcClientConnection conn = ke->conn;
  SilcClient client = conn->client;
  VerifyKeyContext verify;

  /* If we provided repository for SKE and we got here the key was not
     found from the repository. */
  if (ke->params.repository && !ke->params.verify_notfound) {
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }

  SILC_LOG_DEBUG(("Verify remote public key"));

  verify = silc_calloc(1, sizeof(*verify));
  if (!verify) {
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }
  verify->ske = ske;
  verify->completion = completion;
  verify->completion_context = completion_context;

  /* Verify public key in application */
  client->internal->ops->verify_public_key(client, conn,
					   SILC_CONN_CLIENT, public_key,
					   silc_client_keyagr_verify_key_cb,
					   verify);
}

/* Key exchange protocol completion callback.  Responder function. */

static void silc_client_keyagr_completion(SilcSKE ske,
					  SilcSKEStatus status,
					  SilcSKESecurityProperties prop,
					  SilcSKEKeyMaterial keymat,
					  SilcSKERekeyMaterial rekey,
					  void *context)
{
  SilcClientEntry client_entry = context;
  SilcClientKeyAgreement ke = client_entry->internal.ke;
  SilcClientConnection conn = ke->conn;
  SilcClient client = conn->client;

  if (status != SILC_SKE_STATUS_OK) {
    /* Key exchange failed */
    ke->completion(client, conn, client_entry,
		   status == SILC_SKE_STATUS_TIMEOUT ?
		   SILC_KEY_AGREEMENT_TIMEOUT :
		   SILC_KEY_AGREEMENT_FAILURE, NULL, ke->context);
    silc_client_keyagr_free(client, conn, client_entry);
    return;
  }

  /* Returns the negotiated key material to application.  Key agreement
     was successful. */
  ke->completion(client, conn, client_entry, SILC_KEY_AGREEMENT_OK,
		 keymat, ke->context);

  silc_client_keyagr_free(client, conn, client_entry);
}

/* Starts key agreement as responder. */

static void silc_client_process_key_agreement(SilcClient client,
					      SilcClientConnection conn,
					      SilcClientEntry client_entry)
{
  SilcClientKeyAgreement ke = client_entry->internal.ke;
  SilcSKEParamsStruct params;

  SILC_LOG_DEBUG(("Processing key agrement %p session", ke));

  /* Allocate SKE */
  ke->ske = silc_ske_alloc(client->rng, conn->internal->schedule,
			   ke->params.repository, ke->public_key,
			   ke->private_key, client_entry);
  if (!ke->ske) {
    ke->completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
		   NULL, ke->context);
    silc_client_keyagr_free(client, conn, client_entry);
    return;
  }

  /* Set SKE parameters */
  params.version = client->internal->silc_client_version;
  params.flags = SILC_SKE_SP_FLAG_MUTUAL;
  if (ke->params.udp) {
    params.flags |= SILC_SKE_SP_FLAG_IV_INCLUDED;
    params.session_port = ke->params.local_port;
  }

  silc_ske_set_callbacks(ke->ske, silc_client_keyagr_verify_key,
			 silc_client_keyagr_completion, client_entry);

  /* Start key exchange as responder */
  ke->op = silc_ske_responder(ke->ske, ke->stream, &params);
  if (!ke->op) {
    ke->completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
		   NULL, ke->context);
    silc_client_keyagr_free(client, conn, client_entry);
  }
}

/* TCP network listener callback.  Accepts new key agreement connection.
   Responder function. */

static void silc_client_tcp_accept(SilcNetStatus status,
				   SilcStream stream,
				   void *context)
{
  SilcClientEntry client_entry = context;
  SilcClientKeyAgreement ke = client_entry->internal.ke;

  /* Create packet stream */
  ke->stream = silc_packet_stream_create(ke->client->internal->packet_engine,
					 ke->conn->internal->schedule, stream);
  if (!ke->stream) {
    silc_stream_destroy(stream);
    return;
  }

  /* Process session */
  silc_client_process_key_agreement(ke->client, ke->conn, client_entry);
}

/* UDP network listener callback.  Accepts new key agreement session.
   Responder function. */

static SilcBool silc_client_udp_accept(SilcPacketEngine engine,
                                       SilcPacketStream stream,
                                       SilcPacket packet,
                                       void *callback_context,
                                       void *stream_context)
{
  SilcClientEntry client_entry = callback_context;
  SilcClientKeyAgreement ke = client_entry->internal.ke;
  SilcUInt16 port;
  const char *ip;

  /* We want only key exchange packet.  Eat other packets so that default
     packet callback doesn't get them. */
  if (packet->type != SILC_PACKET_KEY_EXCHANGE) {
    silc_packet_free(packet);
    return TRUE;
  }

  /* Create packet stream for this remote UDP session */
  if (!silc_packet_get_sender(packet, &ip, &port)) {
    silc_packet_free(packet);
    return TRUE;
  }
  ke->stream = silc_packet_stream_add_remote(stream, ip, port, packet);
  if (!ke->stream) {
    silc_packet_free(packet);
    return TRUE;
  }

  /* Process session */
  silc_client_process_key_agreement(ke->client, ke->conn, client_entry);
  return TRUE;
}

/* Client connect completion callback.  Initiator function. */

static void silc_client_keyagr_perform_cb(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientConnectionStatus status,
					  SilcStatus error,
					  const char *message,
					  void *context)
{
  SilcClientEntry client_entry = context;
  SilcClientKeyAgreement ke = client_entry->internal.ke;
  SilcSKEKeyMaterial keymat;

  ke->op = NULL;

  switch (status) {
  case SILC_CLIENT_CONN_SUCCESS:
    SILC_LOG_DEBUG(("Key agreement %p successful", ke));

    keymat = silc_ske_get_key_material(conn->internal->ske);
    ke->completion(ke->client, ke->conn, client_entry, SILC_KEY_AGREEMENT_OK,
		   keymat, ke->context);
    break;

  case SILC_CLIENT_CONN_ERROR_TIMEOUT:
    SILC_LOG_DEBUG(("Key agreement %p timeout", ke));
    ke->completion(ke->client, ke->conn, client_entry,
		   SILC_KEY_AGREEMENT_TIMEOUT, NULL, ke->context);
    break;

  default:
    SILC_LOG_DEBUG(("Key agreement %p error %d", ke, status));
    ke->completion(ke->client, ke->conn, client_entry,
		   SILC_KEY_AGREEMENT_FAILURE, NULL, ke->context);
    break;
  }

  /* Close the created connection */
  if (conn)
    silc_client_close_connection(ke->client, conn);

  silc_client_keyagr_free(ke->client, ke->conn, client_entry);
}

/* Packet stream callbacks */
static SilcPacketCallbacks silc_client_keyagr_stream_cb =
{
  silc_client_udp_accept, NULL, NULL
};

/*************************** Key Agreement API ******************************/

/* Sends key agreement packet to remote client.  If IP addresses are provided
   creates also listener for íncoming key agreement connection.  Supports
   both TCP and UDP transports. */

void silc_client_send_key_agreement(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry,
				    SilcClientConnectionParams *params,
				    SilcPublicKey public_key,
				    SilcPrivateKey private_key,
				    SilcKeyAgreementCallback completion,
				    void *context)
{
  SilcClientKeyAgreement ke = NULL;
  SilcBuffer buffer;
  SilcUInt16 port = 0, protocol = 0;
  char *local_ip = NULL;
  SilcStream stream;

  SILC_LOG_DEBUG(("Sending key agreement"));

  if (!client_entry)
    return;
  if (conn->internal->disconnected)
    return;

  if (client_entry->internal.ke) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ALREADY_STARTED,
	       NULL, context);
    return;
  }

  if (client_entry == conn->local_entry) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_SELF_DENIED,
	       NULL, context);
    return;
  }

  /* If local IP is provided, create listener */
  if (params && (params->local_ip || params->bind_ip)) {
    ke = silc_calloc(1, sizeof(*ke));
    if (!ke) {
      completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
		 NULL, context);
      return;
    }

    /* Create network listener */
    if (params->udp) {
      /* UDP listener */
      stream = silc_net_udp_connect(params->bind_ip ? params->bind_ip :
				    params->local_ip, params->local_port,
				    NULL, 0, conn->internal->schedule);
      ke->udp_listener =
	silc_packet_stream_create(client->internal->packet_engine,
				  conn->internal->schedule, stream);
      if (!ke->udp_listener) {
	client->internal->ops->say(
		     client, conn, SILC_CLIENT_MESSAGE_ERROR,
		     "Cannot create UDP listener on %s on port %d: %s",
		     params->bind_ip ? params->bind_ip :
		     params->local_ip, params->local_port, strerror(errno));
	completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
		   NULL, context);
	if (stream)
	  silc_stream_destroy(stream);
	silc_free(ke);
	return;
      }
      silc_packet_stream_link(ke->udp_listener,
			      &silc_client_keyagr_stream_cb,
			      client_entry, 1000000,
			      SILC_PACKET_ANY, -1);

      port = params->local_port;
      if (!port) {
	/* Get listener port */
	SilcSocket sock;
	silc_socket_stream_get_info(stream, &sock, NULL, NULL, NULL);
	port = silc_net_get_local_port(sock);
      }
    } else {
      /* TCP listener */
      ke->tcp_listener =
	silc_net_tcp_create_listener(params->bind_ip ?
				     (const char **)&params->bind_ip :
				     (const char **)&params->local_ip,
				     1, params->local_port, FALSE, FALSE,
				     conn->internal->schedule,
				     silc_client_tcp_accept,
				     client_entry);
      if (!ke->tcp_listener) {
	client->internal->ops->say(
		     client, conn, SILC_CLIENT_MESSAGE_ERROR,
		     "Cannot create listener on %s on port %d: %s",
		     params->bind_ip ? params->bind_ip :
		     params->local_ip, params->local_port, strerror(errno));
	completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
		   NULL, context);
	silc_free(ke);
	return;
      }

      port = params->local_port;
      if (!port) {
	/* Get listener port */
	SilcUInt16 *ports;
	ports = silc_net_listener_get_port(ke->tcp_listener, NULL);
	port = ports[0];
	silc_free(ports);
      }
    }

    local_ip = params->local_ip;
    protocol = params->udp;

    ke->client = client;
    ke->conn = conn;
    ke->completion = completion;
    ke->context = context;
    ke->params = *params;
    ke->public_key = public_key;
    ke->private_key = private_key;
    silc_client_ref_client(client, conn, client_entry);
    client_entry->internal.ke = ke;
    client_entry->internal.prv_resp = TRUE;
  }

  /* Encode the key agreement payload */
  buffer = silc_key_agreement_payload_encode(local_ip, protocol, port);
  if (!buffer) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
	       NULL, context);
    silc_client_keyagr_free(client, conn, client_entry);
    return;
  }

  /* Send the key agreement packet to the client */
  if (!silc_packet_send_ext(conn->stream, SILC_PACKET_KEY_AGREEMENT, 0,
			    0, NULL, SILC_ID_CLIENT, &client_entry->id,
			    silc_buffer_datalen(buffer), NULL, NULL)) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
	       NULL, context);
    silc_client_keyagr_free(client, conn, client_entry);
    silc_buffer_free(buffer);
    return;
  }

  /* Add key agreement timeout task */
  if (params && params->timeout_secs)
    silc_schedule_task_add_timeout(conn->internal->schedule,
				   silc_client_keyagr_timeout,
				   client_entry, params->timeout_secs, 0);

  silc_buffer_free(buffer);
}

/* Perform key agreement protocol as initiator.  Conneects to remote host. */

void silc_client_perform_key_agreement(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry,
				       SilcClientConnectionParams *params,
				       SilcPublicKey public_key,
				       SilcPrivateKey private_key,
				       char *hostname, int port,
				       SilcKeyAgreementCallback completion,
				       void *context)
{
  SilcClientKeyAgreement ke;

  SILC_LOG_DEBUG(("Performing key agreement"));

  if (!client_entry || !hostname || !port) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
	       NULL, context);
    return;
  }

  if (client_entry == conn->local_entry) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_SELF_DENIED,
	       NULL, context);
    return;
  }

  ke = silc_calloc(1, sizeof(*ke));
  if (!ke) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
	       NULL, context);
    return;
  }
  ke->client = client;
  ke->conn = conn;
  ke->completion = completion;
  ke->context = context;
  silc_client_ref_client(client, conn, client_entry);
  client_entry->internal.ke = ke;

  if (params)
    params->no_authentication = TRUE;

  /* Connect to the remote client.  Performs key exchange automatically. */
  if (!silc_client_connect_to_client(client, params, public_key,
				     private_key, hostname, port,
				     silc_client_keyagr_perform_cb,
				     client_entry)) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
	       NULL, context);
    silc_client_keyagr_free(client, conn, client_entry);
    return;
  }
}

/* Same as above but caller has created connection. */

void
silc_client_perform_key_agreement_stream(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 SilcClientConnectionParams *params,
					 SilcPublicKey public_key,
					 SilcPrivateKey private_key,
					 SilcStream stream,
					 SilcKeyAgreementCallback completion,
					 void *context)
{
  SilcClientKeyAgreement ke;

  SILC_LOG_DEBUG(("Performing key agreement"));

  if (!client_entry || !stream) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
	       NULL, context);
    return;
  }

  if (client_entry == conn->local_entry) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_SELF_DENIED,
	       NULL, context);
    return;
  }

  ke = silc_calloc(1, sizeof(*ke));
  if (!ke) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
	       NULL, context);
    return;
  }
  ke->client = client;
  ke->conn = conn;
  ke->completion = completion;
  ke->context = context;
  silc_client_ref_client(client, conn, client_entry);
  client_entry->internal.ke = ke;

  if (params)
    params->no_authentication = TRUE;

  /* Perform key exchange protocol */
  if (!silc_client_key_exchange(client, params, public_key,
				private_key, stream, SILC_CONN_CLIENT,
				silc_client_keyagr_perform_cb,
				client_entry)) {
    completion(client, conn, client_entry, SILC_KEY_AGREEMENT_ERROR,
	       NULL, context);
    silc_client_keyagr_free(client, conn, client_entry);
    return;
  }
}

/* This function can be called to unbind the hostname and the port for
   the key agreement protocol. However, this function has effect only
   before the key agreement protocol has been performed. After it has
   been performed the library will automatically unbind the port. The
   `client_entry' is the client to which we sent the key agreement
   request. */

void silc_client_abort_key_agreement(SilcClient client,
				     SilcClientConnection conn,
				     SilcClientEntry client_entry)
{
  SilcClientKeyAgreement ke;

  if (!client_entry || !client_entry->internal.ke)
    return;

  ke = client_entry->internal.ke;

  SILC_LOG_DEBUG(("Abort key agreement %p"));

  ke->completion(client, conn, client_entry,
		 SILC_KEY_AGREEMENT_ABORTED, NULL, ke->context);

  silc_client_keyagr_free(client, conn, client_entry);
}

/* Key agreement packet received */

SILC_FSM_STATE(silc_client_key_agreement)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcClientID remote_id;
  SilcClientEntry remote_client;
  SilcKeyAgreementPayload payload;

  if (packet->src_id_type != SILC_ID_CLIENT) {
    /** Invalid packet */
    silc_fsm_next(fsm, silc_client_key_agreement_error);
    return SILC_FSM_CONTINUE;
  }

  if (!silc_id_str2id(packet->src_id, packet->src_id_len, SILC_ID_CLIENT,
		      &remote_id, sizeof(remote_id))) {
    /** Invalid source ID */
    silc_fsm_next(fsm, silc_client_key_agreement_error);
    return SILC_FSM_CONTINUE;
  }

  /* Check whether we know this client already */
  remote_client = silc_client_get_client_by_id(client, conn, &remote_id);
  if (!remote_client || !remote_client->nickname[0]) {
    /** Resolve client info */
    silc_client_unref_client(client, conn, remote_client);
    SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					 client, conn, &remote_id, NULL,
					 silc_client_keyagr_resolved, fsm));
    /* NOT REACHED */
  }

  /* Parse the key agreement payload */
  payload = silc_key_agreement_payload_parse(silc_buffer_data(&packet->buffer),
					     silc_buffer_len(&packet->buffer));
  if (!payload) {
    /** Malformed Payload */
    SILC_LOG_DEBUG(("Malformed key agreement payload"));
    silc_fsm_next(fsm, silc_client_key_agreement_error);
    return SILC_FSM_CONTINUE;
  }

  /* If remote did not provide connection endpoint, we will assume that we
     will provide it and will be responder. */
  if (!silc_key_agreement_get_hostname(payload))
    remote_client->internal.prv_resp = TRUE;
  else
    remote_client->internal.prv_resp = FALSE;

  /* Notify application for key agreement request */
  client->internal->ops->key_agreement(
				   client, conn, remote_client,
				   silc_key_agreement_get_hostname(payload),
				   silc_key_agreement_get_protocol(payload),
				   silc_key_agreement_get_port(payload));

  silc_key_agreement_payload_free(payload);

  silc_packet_free(packet);
  return SILC_FSM_FINISH;
}

/* Key agreement packet processing error */

SILC_FSM_STATE(silc_client_key_agreement_error)
{
  SilcPacket packet = state_context;
  silc_packet_free(packet);
  return SILC_FSM_FINISH;
}
