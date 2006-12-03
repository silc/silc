/*

  client_st_connect.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

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

/* Public key verification context */
typedef struct {
  SilcSKE ske;
  SilcSKEVerifyCbCompletion completion;
  void *completion_context;
} *VerifyKeyContext;

/************************ Static utility functions **************************/

/* Callback called after connected to remote host */

static void silc_client_connect_callback(SilcNetStatus status,
					 SilcStream stream, void *context)
{
  SilcFSMThread fsm = context;
  SilcClientConnection conn = silc_fsm_get_context(fsm);
  SilcClient client = conn->client;

  if (conn->internal->verbose) {
    switch (status) {
    case SILC_NET_OK:
      break;
    case SILC_NET_UNKNOWN_IP:
      client->internal->ops->say(
		   client, conn, SILC_CLIENT_MESSAGE_ERROR,
		   "Could not connect to host %s: unknown IP address",
		   conn->remote_host);
      break;
    case SILC_NET_UNKNOWN_HOST:
      client->internal->ops->say(
		   client, conn, SILC_CLIENT_MESSAGE_ERROR,
		   "Could not connect to host %s: unknown host name",
		   conn->remote_host);
      break;
    case SILC_NET_HOST_UNREACHABLE:
      client->internal->ops->say(
		   client, conn, SILC_CLIENT_MESSAGE_ERROR,
		   "Could not connect to host %s: network unreachable",
		   conn->remote_host);
      break;
    case SILC_NET_CONNECTION_REFUSED:
      client->internal->ops->say(
		   client, conn, SILC_CLIENT_MESSAGE_ERROR,
		   "Could not connect to host %s: connection refused",
		   conn->remote_host);
      break;
    case SILC_NET_CONNECTION_TIMEOUT:
      client->internal->ops->say(
		   client, conn, SILC_CLIENT_MESSAGE_ERROR,
		   "Could not connect to host %s: connection timeout",
		   conn->remote_host);
      break;
    default:
      client->internal->ops->say(
		   client, conn, SILC_CLIENT_MESSAGE_ERROR,
		   "Could not connect to host %s",
		   conn->remote_host);
      break;
    }
  }

  if (status != SILC_NET_OK) {
    /* Notify application of failure */
    SILC_LOG_DEBUG(("Connecting failed"));
    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0,
		   NULL, conn->callback_context);
    silc_fsm_next(fsm, silc_client_st_connect_error);
    SILC_FSM_CALL_CONTINUE(fsm);
    return;
  }

  /* Connection created successfully */
  SILC_LOG_DEBUG(("Connected"));
  conn->stream = (void *)stream;
  SILC_FSM_CALL_CONTINUE(fsm);
}

/* Called after application has verified remote host's public key */

static void silc_client_ke_verify_key_cb(SilcBool success, void *context)
{
  VerifyKeyContext verify = (VerifyKeyContext)context;

  SILC_LOG_DEBUG(("Start"));

  /* Call the completion callback back to the SKE */
  verify->completion(verify->ske, success ? SILC_SKE_STATUS_OK :
		     SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
		     verify->completion_context);

  silc_free(verify);
}

/* Verify remote host's public key */

static void silc_client_ke_verify_key(SilcSKE ske,
				      SilcPublicKey public_key,
				      void *context,
				      SilcSKEVerifyCbCompletion completion,
				      void *completion_context)
{
  SilcFSMThread fsm = context;
  SilcClientConnection conn = silc_fsm_get_context(fsm);
  SilcClient client = conn->client;
  VerifyKeyContext verify;

  /* If we provided repository for SKE and we got here the key was not
     found from the repository. */
  if (conn->internal->params.repository &&
      !conn->internal->params.verify_notfound) {
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
					   conn->type, public_key,
					   silc_client_ke_verify_key_cb,
					   verify);
}

/* Key exchange protocol completion callback */

static void silc_client_ke_completion(SilcSKE ske,
				      SilcSKEStatus status,
				      SilcSKESecurityProperties prop,
				      SilcSKEKeyMaterial keymat,
				      SilcSKERekeyMaterial rekey,
				      void *context)
{
  SilcFSMThread fsm = context;
  SilcClientConnection conn = silc_fsm_get_context(fsm);
  SilcClient client = conn->client;
  SilcCipher send_key, receive_key;
  SilcHmac hmac_send, hmac_receive;

  if (status != SILC_SKE_STATUS_OK) {
    /* Key exchange failed */
    SILC_LOG_DEBUG(("Error during key exchange with %s: %s (%d)",
		    conn->remote_host, silc_ske_map_status(status), status));

    if (conn->internal->verbose)
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				 "Error during key exchange with %s: %s",
				 conn->remote_host,
				 silc_ske_map_status(status));

    silc_fsm_next(fsm, silc_client_st_connect_error);
    SILC_FSM_CALL_CONTINUE(fsm);
    return;
  }

  SILC_LOG_DEBUG(("Setting keys into use"));

  /* Set the keys into use.  Data will be encrypted after this. */
  if (!silc_ske_set_keys(ske, keymat, prop, &send_key, &receive_key,
			 &hmac_send, &hmac_receive, &conn->internal->hash)) {
    /* Error setting keys */
    SILC_LOG_DEBUG(("Could not set keys into use"));

    if (conn->internal->verbose)
      client->internal->ops->say(
		       client, conn, SILC_CLIENT_MESSAGE_ERROR,
		       "Error during key exchange with %s: cannot use keys",
		       conn->remote_host);

    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR_KE, 0, NULL,
		   conn->callback_context);

    silc_fsm_next(fsm, silc_client_st_connect_error);
    SILC_FSM_CALL_CONTINUE(fsm);
    return;
  }

  silc_packet_set_ciphers(conn->stream, send_key, receive_key);
  silc_packet_set_hmacs(conn->stream, hmac_send, hmac_receive);

  conn->internal->rekey = rekey;

  /* Key exchange done */
  SILC_FSM_CALL_CONTINUE(fsm);
}

/* Callback called by application to return authentication data */

static void silc_client_connect_auth_method(SilcBool success,
					    SilcAuthMethod auth_meth,
					    void *auth, SilcUInt32 auth_len,
					    void *context)
{
  SilcFSMThread fsm = context;
  SilcClientConnection conn = silc_fsm_get_context(fsm);

  conn->internal->params.auth_method = SILC_AUTH_NONE;

  if (success) {
    conn->internal->params.auth_method = auth_meth;
    conn->internal->params.auth = auth;
    conn->internal->params.auth_len = auth_len;
  }

  SILC_FSM_CALL_CONTINUE(fsm);
}

/* Connection authentication completion callback */

static void silc_client_connect_auth_completion(SilcConnAuth connauth,
						SilcBool success,
						void *context)
{
  SilcFSMThread fsm = context;
  SilcClientConnection conn = silc_fsm_get_context(fsm);
  SilcClient client = conn->client;

  silc_connauth_free(connauth);

  if (!success) {
    if (conn->internal->verbose)
	client->internal->ops->say(
			client, conn, SILC_CLIENT_MESSAGE_ERROR,
			"Authentication failed");

    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR_AUTH, 0, NULL,
		   conn->callback_context);
    silc_fsm_next(fsm, silc_client_st_connect_error);
  }

  SILC_FSM_CALL_CONTINUE(fsm);
}

/*************************** Connect remote host ****************************/

/* Creates a connection to remote host */

SILC_FSM_STATE(silc_client_st_connect)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  SILC_LOG_DEBUG(("Connecting to %s:%d", conn->remote_host,
		  conn->remote_port));

  /** Connect */
  silc_fsm_next(fsm, silc_client_st_connect_set_stream);

  if (conn->internal->params.udp) {
    SilcStream stream;

    if (!conn->internal->params.local_ip) {
      /** IP address not given */
      SILC_LOG_ERROR(("Local UDP IP address not specified"));
      conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		     conn->callback_context);
      silc_fsm_next(fsm, silc_client_st_connect_error);
      return SILC_FSM_CONTINUE;
    }

    /* Connect (UDP) */
    stream = silc_net_udp_connect(conn->internal->params.local_ip,
				  conn->internal->params.local_port,
				  conn->remote_host, conn->remote_port,
				  conn->internal->schedule);

    SILC_FSM_CALL(silc_client_connect_callback(stream ? SILC_NET_OK :
					       SILC_NET_HOST_UNREACHABLE,
					       stream, fsm));
  } else {
    /* Connect (TCP) */
    SILC_FSM_CALL(conn->internal->op = silc_net_tcp_connect(
				       NULL, conn->remote_host,
				       conn->remote_port,
				       conn->internal->schedule,
				       silc_client_connect_callback, fsm));
  }
}

/* Sets the new connection stream into use and creates packet stream */

SILC_FSM_STATE(silc_client_st_connect_set_stream)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  /* Create packet stream */
  conn->stream = silc_packet_stream_create(client->internal->packet_engine,
					   conn->internal->schedule,
					   (SilcStream)conn->stream);
  if (!conn->stream) {
    /** Cannot create packet stream */
    SILC_LOG_DEBUG(("Could not create packet stream"));
    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		   conn->callback_context);
    silc_fsm_next(fsm, silc_client_st_connect_error);
    return SILC_FSM_CONTINUE;
  }

  silc_packet_set_context(conn->stream, conn);

  /** Start key exchange */
  silc_fsm_next(fsm, silc_client_st_connect_key_exchange);
  return SILC_FSM_CONTINUE;
}

/* Starts key exchange protocol with remote host */

SILC_FSM_STATE(silc_client_st_connect_key_exchange)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcSKEParamsStruct params;

  SILC_LOG_DEBUG(("Starting key exchange protocol"));

  /* Allocate SKE */
  conn->internal->ske =
    silc_ske_alloc(client->rng, conn->internal->schedule,
		   conn->internal->params.repository,
		   conn->public_key, conn->private_key, fsm);
  if (!conn->internal->ske) {
    /** Out of memory */
    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR_KE, 0, NULL,
		   conn->callback_context);
    silc_fsm_next(fsm, silc_client_st_connect_error);
    return SILC_FSM_CONTINUE;
  }

  /* Set SKE callbacks */
  silc_ske_set_callbacks(conn->internal->ske, silc_client_ke_verify_key,
			 silc_client_ke_completion, fsm);

  /* Set up key exchange parameters */
  params.version = client->internal->silc_client_version;
  params.flags = SILC_SKE_SP_FLAG_MUTUAL;
  if (conn->internal->params.pfs)
    params.flags |= SILC_SKE_SP_FLAG_PFS;
  if (conn->internal->params.udp) {
    params.flags |= SILC_SKE_SP_FLAG_IV_INCLUDED;
    params.session_port = conn->internal->params.local_port;
  }

  if (conn->internal->params.no_authentication)
    /** Run key exchange (no auth) */
    silc_fsm_next(fsm, silc_client_st_connected);
  else if (conn->internal->params.udp)
    /** Run key exchange (UDP)*/
    silc_fsm_next(fsm, silc_client_st_connect_setup_udp);
  else
    /** Run key exchange (TCP) */
    silc_fsm_next(fsm, silc_client_st_connect_auth);

  SILC_FSM_CALL(conn->internal->op = silc_ske_initiator(conn->internal->ske,
							conn->stream,
							&params, NULL));
}

/* For UDP/IP connections, set up the UDP session after successful key
   exchange protocol */

SILC_FSM_STATE(silc_client_st_connect_setup_udp)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcStream stream, old;
  SilcSKESecurityProperties prop;

  SILC_LOG_DEBUG(("Setup UDP SILC session"));

  /* Create new UDP stream */
  prop = silc_ske_get_security_properties(conn->internal->ske);
  stream = silc_net_udp_connect(conn->internal->params.local_ip,
				conn->internal->params.local_port,
				conn->remote_host, prop->remote_port,
				conn->internal->schedule);
  if (!stream) {
    /** Cannot create UDP stream */
    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		   conn->callback_context);
    silc_fsm_next(fsm, silc_client_st_connect_error);
    return SILC_FSM_CONTINUE;
  }

  /* Set the new stream to packet stream */
  old = silc_packet_stream_get_stream(conn->stream);
  silc_packet_stream_set_stream(conn->stream, stream,
				conn->internal->schedule);
  silc_packet_stream_set_iv_included(conn->stream);
  silc_packet_set_sid(conn->stream, 0);

  /* Delete the old stream */
  silc_stream_destroy(old);

  /** Start authentication */
  silc_fsm_next(fsm, silc_client_st_connect_auth);
  return SILC_FSM_CONTINUE;
}

/* Get authentication method to be used in authentication protocol */

SILC_FSM_STATE(silc_client_st_connect_auth)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  SILC_LOG_DEBUG(("Get authentication data"));

  silc_fsm_next(fsm, silc_client_st_connect_auth_start);

  /* If authentication data not provided, ask from application */
  if (!conn->internal->params.auth_set)
    SILC_FSM_CALL(client->internal->ops->get_auth_method(
				    client, conn,
				    conn->remote_host,
				    conn->remote_port,
				    silc_client_connect_auth_method, fsm));

  if (conn->internal->params.auth_method == SILC_AUTH_PUBLIC_KEY)
    conn->internal->params.auth = conn->private_key;

  /* We have authentication data */
  return SILC_FSM_CONTINUE;
}

/* Start connection authentication with remote host */

SILC_FSM_STATE(silc_client_st_connect_auth_start)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcConnAuth connauth;

  SILC_LOG_DEBUG(("Starting connection authentication protocol"));

  /* Allocate connection authentication protocol */
  connauth = silc_connauth_alloc(conn->internal->schedule,
				 conn->internal->ske,
				 client->internal->params->rekey_secs);
  if (!connauth) {
    /** Out of memory */
    conn->callback(client, conn, SILC_CLIENT_CONN_ERROR_AUTH, 0, NULL,
		   conn->callback_context);
    silc_fsm_next(fsm, silc_client_st_connect_error);
    return SILC_FSM_CONTINUE;
  }

  /** Start connection authentication */
  silc_fsm_next(fsm, silc_client_st_connected);
  SILC_FSM_CALL(conn->internal->op = silc_connauth_initiator(
					connauth, SILC_CONN_CLIENT,
					conn->internal->params.auth_method,
					conn->internal->params.auth,
					conn->internal->params.auth_len,
					silc_client_connect_auth_completion,
					fsm));
}

/* Connection fully established */

SILC_FSM_STATE(silc_client_st_connected)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;

  SILC_LOG_DEBUG(("Connection established"));

  /* If we connected to server, now register to network. */
  if (conn->type == SILC_CONN_SERVER &&
      !conn->internal->params.no_authentication) {

    /* If detach data is provided, resume the session. */
    if (conn->internal->params.detach_data &&
	conn->internal->params.detach_data_len) {
      /** Resume detached session */
      silc_fsm_next(fsm, silc_client_st_resume);
    } else {
      /** Register to network */
      silc_fsm_next(fsm, silc_client_st_register);
    }

    return SILC_FSM_CONTINUE;
  }

  /* Call connection callback */
  conn->callback(client, conn, SILC_CLIENT_CONN_SUCCESS, 0, NULL,
		 conn->callback_context);

  return SILC_FSM_FINISH;
}

/* Error during connecting */

SILC_FSM_STATE(silc_client_st_connect_error)
{
  SilcClientConnection conn = fsm_context;

  /* Signal to close connection */
  conn->internal->disconnected = TRUE;
  SILC_FSM_SEMA_POST(&conn->internal->wait_event);

  return SILC_FSM_FINISH;
}
