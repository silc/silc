/*

  silcconnauth.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcconnauth.h"

/************************** Types and definitions ***************************/

static SilcBool silc_connauth_packet_receive(SilcPacketEngine engine,
					     SilcPacketStream stream,
					     SilcPacket packet,
					     void *callback_context,
					     void *app_context);

/* Connection authentication context */
struct SilcConnAuthStruct {
  SilcSKE ske;
  SilcFSM fsm;
  SilcAsyncOperationStruct op;
  SilcConnectionType conn_type;
  SilcAuthMethod auth_method;
  void *auth_data;
  SilcUInt32 auth_data_len;
  SilcConnAuthCompletion completion;
  SilcConnAuthGetAuthData get_auth_data;
  void *context;
  SilcDList public_keys;
  SilcSKRStatus skr_status;
  SilcUInt32 timeout_secs;
  SilcPacket packet;
  unsigned int aborted   : 1;
  unsigned int success   : 1;
};

/* Packet stream callbacks */
static SilcPacketCallbacks silc_connauth_stream_cbs =
{
  silc_connauth_packet_receive, NULL, NULL
};


/************************ Static utility functions **************************/

/* Packet callback */

static SilcBool silc_connauth_packet_receive(SilcPacketEngine engine,
					     SilcPacketStream stream,
					     SilcPacket packet,
					     void *callback_context,
					     void *app_context)
{
  SilcConnAuth connauth = callback_context;
  connauth->packet = packet;
  silc_fsm_continue(connauth->fsm);
  return TRUE;
}

/* Async operation abortion callback */

static void silc_connauth_abort(SilcAsyncOperation op, void *context)
{
  SilcConnAuth connauth = context;
  connauth->aborted = TRUE;
}

/* Generates signature for public key based authentication */

static SilcBool silc_connauth_get_signature(SilcConnAuth connauth,
					    unsigned char **auth_data,
					    SilcUInt32 *auth_data_len)
{
  int len;
  SilcSKE ske;
  SilcPrivateKey private_key;
  SilcBuffer auth;

  SILC_LOG_DEBUG(("Compute signature"));

  ske = connauth->ske;
  private_key = connauth->auth_data;

  /* Make the authentication data. Protocol says it is HASH plus
     KE Start Payload. */
  len = ske->hash_len + silc_buffer_len(ske->start_payload_copy);
  auth = silc_buffer_alloc_size(len);
  if (!auth)
    return FALSE;
  silc_buffer_format(auth,
		     SILC_STR_UI_XNSTRING(ske->hash, ske->hash_len),
		     SILC_STR_UI_XNSTRING(
			       ske->start_payload_copy->data,
			       silc_buffer_len(ske->start_payload_copy)),
		     SILC_STR_END);

  len = ((silc_pkcs_private_key_get_len(private_key) + 7) / 8) + 1;
  *auth_data = silc_calloc(len, sizeof(**auth_data));
  if (*auth_data == NULL) {
    silc_buffer_free(auth);
    return FALSE;
  }

  /* Compute signature */
  if (!silc_pkcs_sign(private_key, auth->data, silc_buffer_len(auth),
		      *auth_data, len, auth_data_len, TRUE, ske->prop->hash)) {
    silc_free(*auth_data);
    silc_buffer_free(auth);
    return FALSE;
  }

  silc_buffer_free(auth);
  return TRUE;
}

/* Verifies digital signature */

static SilcBool silc_connauth_verify_signature(SilcConnAuth connauth,
					       SilcPublicKey pub_key,
					       unsigned char *sign,
					       SilcUInt32 sign_len)
{
  int len;
  SilcBuffer auth;
  SilcSKE ske = connauth->ske;

  if (!pub_key || !sign)
    return FALSE;

  /* Make the authentication data. Protocol says it is HASH plus
     KE Start Payload. */
  len = ske->hash_len + silc_buffer_len(ske->start_payload_copy);
  auth = silc_buffer_alloc_size(len);
  if (!auth)
    return FALSE;
  silc_buffer_format(auth,
		     SILC_STR_UI_XNSTRING(ske->hash, ske->hash_len),
		     SILC_STR_UI_XNSTRING(
				  ske->start_payload_copy->data,
				  silc_buffer_len(ske->start_payload_copy)),
		     SILC_STR_END);

  /* Verify signature */
  if (!silc_pkcs_verify(pub_key, sign, sign_len, auth->data,
			silc_buffer_len(auth), ske->prop->hash)) {
    silc_buffer_free(auth);
    return FALSE;
  }

  silc_buffer_free(auth);

  return TRUE;
}

/* Timeout */

SILC_TASK_CALLBACK(silc_connauth_timeout)
{
  SilcConnAuth connauth = context;
  SILC_LOG_DEBUG(("Protocol timeout"));
  connauth->aborted = TRUE;
  silc_fsm_continue_sync(connauth->fsm);
}

/* SKR callback */

static void silc_connauth_skr_callback(SilcSKR skr, SilcSKRFind find,
				       SilcSKRStatus status,
				       SilcDList results, void *context)
{
  SilcConnAuth connauth = context;

  silc_skr_find_free(find);

  connauth->public_keys = results;
  connauth->skr_status = status;

  SILC_FSM_CALL_CONTINUE(connauth->fsm);
}

/* FSM destructor */

static void silc_connauth_fsm_destructor(SilcFSM fsm, void *fsm_context,
					 void *destructor_context)
{
  silc_fsm_free(fsm);
}


/******************************* Protocol API *******************************/

/* Allocate connection authentication context */

SilcConnAuth silc_connauth_alloc(SilcSchedule schedule,
				 SilcSKE ske,
				 SilcUInt32 timeout_secs)
{
  SilcConnAuth connauth;

  if (!schedule || !ske)
    return NULL;

  connauth = silc_calloc(1, sizeof(*connauth));
  if (!connauth)
    return NULL;

  connauth->fsm = silc_fsm_alloc(connauth, silc_connauth_fsm_destructor,
				 NULL, schedule);
  if (!connauth->fsm) {
    silc_connauth_free(connauth);
    return NULL;
  }

  connauth->timeout_secs = timeout_secs;
  connauth->ske = ske;

  return connauth;
}

/* Free connection authentication context */

void silc_connauth_free(SilcConnAuth connauth)
{
  if (connauth->public_keys)
    silc_dlist_uninit(connauth->public_keys);
  silc_free(connauth);
}

/* Return associated SKE context */

SilcSKE silc_connauth_get_ske(SilcConnAuth connauth)
{
  return connauth->ske;
}


/******************************** Initiator *********************************/

SILC_FSM_STATE(silc_connauth_st_initiator_start);
SILC_FSM_STATE(silc_connauth_st_initiator_result);
SILC_FSM_STATE(silc_connauth_st_initiator_failure);

SILC_FSM_STATE(silc_connauth_st_initiator_start)
{
  SilcConnAuth connauth = fsm_context;
  SilcBuffer packet;
  int payload_len = 0;
  unsigned char *auth_data = NULL;
  SilcUInt32 auth_data_len = 0;
  SilcPacketFlags flags = 0;

  SILC_LOG_DEBUG(("Start"));

  if (connauth->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_connauth_st_initiator_failure);
    return SILC_FSM_CONTINUE;
  }

  /* Start timeout */
  if (connauth->timeout_secs)
    silc_schedule_task_add_timeout(silc_fsm_get_schedule(fsm),
				   silc_connauth_timeout, connauth,
				   connauth->timeout_secs, 0);

  switch (connauth->auth_method) {
  case SILC_AUTH_NONE:
    /* No authentication required */
    break;

  case SILC_AUTH_PASSWORD:
    auth_data = silc_memdup(connauth->auth_data, connauth->auth_data_len);
    if (!auth_data) {
      /** Out of memory */
      silc_fsm_next(fsm, silc_connauth_st_initiator_failure);
      return SILC_FSM_CONTINUE;
    }
    auth_data_len = connauth->auth_data_len;
    flags = SILC_PACKET_FLAG_LONG_PAD;
    break;

  case SILC_AUTH_PUBLIC_KEY:
    if (!silc_connauth_get_signature(connauth, &auth_data, &auth_data_len)) {
      /** Error computing signature */
      silc_fsm_next(fsm, silc_connauth_st_initiator_failure);
      return SILC_FSM_CONTINUE;
    }
    break;
  }

  payload_len = 4 + auth_data_len;
  packet = silc_buffer_alloc_size(payload_len);
  if (!packet) {
    /** Out of memory */
    silc_fsm_next(fsm, silc_connauth_st_initiator_failure);
    return SILC_FSM_CONTINUE;
  }

  silc_buffer_format(packet,
		     SILC_STR_UI_SHORT(payload_len),
		     SILC_STR_UI_SHORT(connauth->conn_type),
		     SILC_STR_UI_XNSTRING(auth_data, auth_data_len),
		     SILC_STR_END);

  /* Send the packet */
  if (!silc_packet_send(connauth->ske->stream, SILC_PACKET_CONNECTION_AUTH,
			flags, packet->data, silc_buffer_len(packet))) {
    /** Error sending packet */
    silc_fsm_next(fsm, silc_connauth_st_initiator_failure);
    return SILC_FSM_CONTINUE;
  }

  if (auth_data) {
    memset(auth_data, 0, auth_data_len);
    silc_free(auth_data);
  }
  silc_buffer_free(packet);

  /** Wait for responder */
  silc_fsm_next(fsm, silc_connauth_st_initiator_result);
  return SILC_FSM_WAIT;
}

SILC_FSM_STATE(silc_connauth_st_initiator_result)
{
  SilcConnAuth connauth = fsm_context;

  SILC_LOG_DEBUG(("Start"));

  if (connauth->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_connauth_st_initiator_failure);
    return SILC_FSM_CONTINUE;
  }

  /* Check the status of authentication */
  if (connauth->packet->type == SILC_PACKET_SUCCESS) {
    SILC_LOG_DEBUG(("Authentication successful"));
    connauth->success = TRUE;
  } else {
    SILC_LOG_DEBUG(("Authentication failed"));
    connauth->success = FALSE;
  }
  silc_packet_free(connauth->packet);

  silc_packet_stream_unlink(connauth->ske->stream,
			    &silc_connauth_stream_cbs, connauth);
  silc_schedule_task_del_by_context(silc_fsm_get_schedule(fsm), connauth);

  /* Call completion callback */
  connauth->completion(connauth, connauth->success, connauth->context);

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_connauth_st_initiator_failure)
{
  SilcConnAuth connauth = fsm_context;
  unsigned char error[4];

  SILC_LOG_DEBUG(("Start"));

  /* Send FAILURE packet */
  SILC_PUT32_MSB(SILC_AUTH_FAILED, error);
  silc_packet_send(connauth->ske->stream, SILC_PACKET_FAILURE, 0, error, 4);

  /* Call completion callback */
  connauth->completion(connauth, FALSE, connauth->context);

  silc_packet_stream_unlink(connauth->ske->stream,
			    &silc_connauth_stream_cbs, connauth);
  silc_schedule_task_del_by_context(silc_fsm_get_schedule(fsm), connauth);

  return SILC_FSM_FINISH;
}

SilcAsyncOperation
silc_connauth_initiator(SilcConnAuth connauth,
			SilcConnectionType conn_type,
			SilcAuthMethod auth_method, void *auth_data,
			SilcUInt32 auth_data_len,
			SilcConnAuthCompletion completion,
			void *context)
{
  SILC_LOG_DEBUG(("Connection authentication as initiator"));

  if (auth_method == SILC_AUTH_PASSWORD && !auth_data) {
    completion(connauth, FALSE, context);
    return NULL;
  }

  if (auth_method == SILC_AUTH_PUBLIC_KEY && !auth_data) {
    completion(connauth, FALSE, context);
    return NULL;
  }

  connauth->conn_type = conn_type;
  connauth->auth_method = auth_method;
  connauth->auth_data = auth_data;
  connauth->auth_data_len = auth_data_len;
  connauth->completion = completion;
  connauth->context = context;

  /* Link to packet stream to get packets */
  silc_packet_stream_link(connauth->ske->stream,
			  &silc_connauth_stream_cbs, connauth, 1000000,
			  SILC_PACKET_SUCCESS,
			  SILC_PACKET_FAILURE, -1);

  /* Start the protocol */
  silc_async_init(&connauth->op, silc_connauth_abort, NULL, connauth);
  silc_fsm_start(connauth->fsm, silc_connauth_st_initiator_start);

  return &connauth->op;
}


/******************************** Responder *********************************/

SILC_FSM_STATE(silc_connauth_st_responder_start);
SILC_FSM_STATE(silc_connauth_st_responder_authenticate);
SILC_FSM_STATE(silc_connauth_st_responder_authenticate_pk);
SILC_FSM_STATE(silc_connauth_st_responder_success);
SILC_FSM_STATE(silc_connauth_st_responder_failure);

SILC_FSM_STATE(silc_connauth_st_responder_start)
{
  SilcConnAuth connauth = fsm_context;

  SILC_LOG_DEBUG(("Start"));

  if (connauth->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  /* Start timeout */
  if (connauth->timeout_secs)
    silc_schedule_task_add_timeout(silc_fsm_get_schedule(fsm),
				   silc_connauth_timeout, connauth,
				   connauth->timeout_secs, 0);

  /** Wait for initiator */
  silc_fsm_next(fsm, silc_connauth_st_responder_authenticate);
  return SILC_FSM_WAIT;
}

SILC_FSM_STATE(silc_connauth_st_responder_authenticate)
{
  SilcConnAuth connauth = fsm_context;
  SilcUInt16 payload_len;
  SilcUInt16 conn_type;
  unsigned char *auth_data = NULL, *passphrase = NULL;
  SilcUInt32 passphrase_len;
  SilcSKR repository = NULL;
  int ret;

  SILC_LOG_DEBUG(("Start"));

  if (connauth->aborted) {
    /** Aborted */
    silc_packet_free(connauth->packet);
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  if (connauth->packet->type != SILC_PACKET_CONNECTION_AUTH) {
    /** Protocol failure */
    silc_packet_free(connauth->packet);
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  /* Parse the received authentication data packet. The received
     payload is Connection Auth Payload. */
  ret = silc_buffer_unformat(&connauth->packet->buffer,
			     SILC_STR_UI_SHORT(&payload_len),
			     SILC_STR_UI_SHORT(&conn_type),
			     SILC_STR_END);
  if (ret == -1) {
    /** Bad payload */
    SILC_LOG_ERROR(("Bad payload in authentication packet"));
    silc_packet_free(connauth->packet);
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  if (payload_len != silc_buffer_len(&connauth->packet->buffer)) {
    /** Bad payload length */
    SILC_LOG_ERROR(("Bad payload length in authentication packet"));
    silc_packet_free(connauth->packet);
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  payload_len -= 4;

  if (conn_type < SILC_CONN_CLIENT || conn_type > SILC_CONN_ROUTER) {
    /** Bad connection type */
    SILC_LOG_ERROR(("Bad connection type (%d) in authentication packet",
		    conn_type));
    silc_packet_free(connauth->packet);
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  if (payload_len > 0) {
    /* Get authentication data */
    ret = silc_buffer_unformat(&connauth->packet->buffer,
			       SILC_STR_OFFSET(4),
			       SILC_STR_UI_XNSTRING(&auth_data,
						    payload_len),
			       SILC_STR_END);
    if (ret == -1) {
      /** Bad payload */
      SILC_LOG_DEBUG(("Bad payload in authentication payload"));
      silc_packet_free(connauth->packet);
      silc_fsm_next(fsm, silc_connauth_st_responder_failure);
      return SILC_FSM_CONTINUE;
    }
  }
  silc_packet_free(connauth->packet);

  SILC_LOG_DEBUG(("Remote connection type %d", conn_type));

  /* Get authentication data */
  if (!connauth->get_auth_data(connauth, conn_type, &passphrase,
			       &passphrase_len, &repository,
			       connauth->context)) {
    /** Connection not configured */
    SILC_LOG_ERROR(("Remote connection not configured"));
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  /* Verify */

  /* Passphrase authentication */
  if (passphrase && passphrase_len) {
    SILC_LOG_DEBUG(("Passphrase authentication"));
    if (!memcmp(auth_data, passphrase, passphrase_len)) {
      /** Authentication failed */
      silc_fsm_next(fsm, silc_connauth_st_responder_failure);
      return SILC_FSM_CONTINUE;
    }
  } else if (repository) {
    /* Digital signature */
    SilcSKRFind find;

    SILC_LOG_DEBUG(("Digital signature authentication"));

    connauth->auth_data = silc_memdup(auth_data, payload_len);
    connauth->auth_data_len = payload_len;

    /* Allocate search constraints for finding the key */
    find = silc_skr_find_alloc();

    if (!find || !connauth->auth_data) {
      /** Out of memory */
      silc_fsm_next(fsm, silc_connauth_st_responder_failure);
      return SILC_FSM_CONTINUE;
    }

    silc_skr_find_set_pkcs_type(find, connauth->ske->pk_type);
    silc_skr_find_set_public_key(find, connauth->ske->public_key);
    silc_skr_find_set_usage(find, (SILC_SKR_USAGE_AUTH |
				   SILC_SKR_USAGE_KEY_AGREEMENT));

    /** Find public key */
    silc_fsm_next(fsm, silc_connauth_st_responder_authenticate_pk);
    SILC_FSM_CALL(silc_skr_find(repository, find, silc_connauth_skr_callback,
				connauth));
    /* NOT REACHED */
  }

  /* Passphrase auth Ok, or no authentication required */

  /** Authentication successful */
  silc_fsm_next(fsm, silc_connauth_st_responder_success);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_connauth_st_responder_authenticate_pk)
{
  SilcConnAuth connauth = fsm_context;
  SilcSKRKey key;

  if (connauth->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  if (connauth->skr_status != SILC_SKR_OK) {
    /** Public key not found */
    SILC_LOG_DEBUG(("Public key not found, error %d", connauth->skr_status));
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  SILC_LOG_DEBUG(("Found %d public keys",
		  silc_dlist_count(connauth->public_keys)));

  /* Verify signature */
  key = silc_dlist_get(connauth->public_keys);
  if (!silc_connauth_verify_signature(connauth, key->key,
				      connauth->auth_data,
				      connauth->auth_data_len)) {
    /** Invalid signature */
    SILC_LOG_DEBUG(("Invalid signature"));
    silc_free(connauth->auth_data);
    silc_fsm_next(fsm, silc_connauth_st_responder_failure);
    return SILC_FSM_CONTINUE;
  }

  silc_free(connauth->auth_data);

  /** Authentication successful */
  silc_fsm_next(fsm, silc_connauth_st_responder_success);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_connauth_st_responder_success)
{
  SilcConnAuth connauth = fsm_context;
  unsigned char tmp[4];

  SILC_LOG_DEBUG(("Authentication successful"));

  /* Send FAILURE packet */
  SILC_PUT32_MSB(SILC_AUTH_OK, tmp);
  silc_packet_send(connauth->ske->stream, SILC_PACKET_SUCCESS, 0, tmp, 4);

  /* Call completion callback */
  connauth->completion(connauth, TRUE, connauth->context);

  silc_packet_stream_unlink(connauth->ske->stream,
			    &silc_connauth_stream_cbs, connauth);
  silc_schedule_task_del_by_context(silc_fsm_get_schedule(fsm), connauth);

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_connauth_st_responder_failure)
{
  SilcConnAuth connauth = fsm_context;
  unsigned char error[4];

  SILC_LOG_ERROR(("Authentication failed"));

  /* Send FAILURE packet */
  SILC_PUT32_MSB(SILC_AUTH_FAILED, error);
  silc_packet_send(connauth->ske->stream, SILC_PACKET_FAILURE, 0, error, 4);

  /* Call completion callback */
  connauth->completion(connauth, FALSE, connauth->context);

  silc_packet_stream_unlink(connauth->ske->stream,
			    &silc_connauth_stream_cbs, connauth);
  silc_schedule_task_del_by_context(silc_fsm_get_schedule(fsm), connauth);

  return SILC_FSM_FINISH;
}

SilcAsyncOperation
silc_connauth_responder(SilcConnAuth connauth,
			SilcConnAuthGetAuthData get_auth_data,
			SilcConnAuthCompletion completion,
			void *context)
{
  SILC_LOG_DEBUG(("Connection authentication as responder"));

  connauth->get_auth_data = get_auth_data;
  connauth->completion = completion;
  connauth->context = context;

  /* Link to packet stream to get packets */
  silc_packet_stream_link(connauth->ske->stream,
			  &silc_connauth_stream_cbs, connauth, 1000000,
			  SILC_PACKET_CONNECTION_AUTH,
			  SILC_PACKET_FAILURE, -1);

  /* Start the protocol */
  silc_async_init(&connauth->op, silc_connauth_abort, NULL, connauth);
  silc_fsm_start(connauth->fsm, silc_connauth_st_responder_start);

  return &connauth->op;
}
