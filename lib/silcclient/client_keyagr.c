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
  SilcClientListener listener;	          /* Listener */
  SilcKeyAgreementCallback completion;	  /* Key agreement completion */
  void *context;			  /* User context */
  SilcAsyncOperation op;		  /* Async operation, initiator */
};

/************************ Static utility functions **************************/

/* Destroyes key agreement session */

static void silc_client_keyagr_free(SilcClient client,
				    SilcClientConnection conn,
				    SilcClientEntry client_entry)
{
  SilcClientKeyAgreement ke = client_entry->internal.ke;

  silc_client_listener_free(ke->listener);
  silc_schedule_task_del_by_context(conn->internal->schedule, client_entry);
  if (ke->op)
    silc_async_abort(ke->op, NULL, NULL);
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

/* Key exchange completion callback.  Called after connected to remote host
   and performed key exchange, when we are initiator.  As responder, this is
   called after the remote has connected to us and have performed the key
   exchange. */

static void silc_client_keyagr_completion(SilcClient client,
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

  /* Close the connection */
  if (conn)
    silc_client_close_connection(ke->client, conn);

  silc_client_keyagr_free(ke->client, ke->conn, client_entry);
}

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

  /* If local IP is provided, create listener.  If this is not provided,
     we'll just send empty key agreement payload */
  if (params && (params->local_ip || params->bind_ip)) {
    ke = silc_calloc(1, sizeof(*ke));
    if (!ke) {
      completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
		 NULL, context);
      return;
    }

    /* Create listener */
    ke->listener = silc_client_listener_add(client, conn->internal->schedule,
					    params, public_key, private_key,
					    silc_client_keyagr_completion,
					    client_entry);
    if (!ke->listener) {
      completion(client, conn, client_entry, SILC_KEY_AGREEMENT_NO_MEMORY,
		 NULL, context);
      return;
    }

    local_ip = params->local_ip;
    protocol = params->udp;

    ke->client = client;
    ke->conn = conn;
    ke->completion = completion;
    ke->context = context;
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
  ke->op = silc_client_connect_to_client(client, params, public_key,
					 private_key, hostname, port,
					 silc_client_keyagr_completion,
					 client_entry);
  if (!ke->op) {
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
  ke->op = silc_client_key_exchange(client, params, public_key,
				    private_key, stream, SILC_CONN_CLIENT,
				    silc_client_keyagr_completion,
				    client_entry);
  if (!ke->op) {
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
  if (!remote_client || !remote_client->internal.valid) {
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
