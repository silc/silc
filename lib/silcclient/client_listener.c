/*

  client_listener.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

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

/* Listener context */
struct SilcClientListenerStruct {
  SilcClient client;			  /* Client */
  SilcSchedule schedule;		  /* Scheduler */
  SilcClientConnectCallback callback;	  /* Connection callback */
  void *context;			  /* User context */
  SilcClientConnectionParams params;      /* Connection parameters */
  SilcPublicKey public_key;		  /* Responder public key */
  SilcPrivateKey private_key;		  /* Responder private key */
  SilcNetListener tcp_listener;	          /* TCP listener */
  SilcPacketStream udp_listener;	  /* UDP listener */
};

/************************ Static utility functions **************************/

/* Called after application has verified remote host's public key. */

static void silc_client_listener_verify_key_cb(SilcBool success, void *context)
{
  SilcVerifyKeyContext verify = context;

  /* Call the completion callback back to the SKE */
  verify->completion(verify->ske, success ? SILC_SKE_STATUS_OK :
		     SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
		     verify->completion_context);

  silc_free(verify);
}

/* Verify remote host's public key. */

static void
silc_client_listener_verify_key(SilcSKE ske,
				SilcPublicKey public_key,
				void *context,
				SilcSKEVerifyCbCompletion completion,
				void *completion_context)
{
  SilcClientConnection conn = context;
  SilcClient client = conn->client;
  SilcVerifyKeyContext verify;

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
					   SILC_CONN_CLIENT, public_key,
					   silc_client_listener_verify_key_cb,
					   verify);
}

/* Key exchange protocol completion callback. */

static void silc_client_listener_completion(SilcSKE ske,
					    SilcSKEStatus status,
					    SilcSKESecurityProperties prop,
					    SilcSKEKeyMaterial keymat,
					    SilcSKERekeyMaterial rekey,
					    void *context)
{
  SilcClientConnection conn = context;
  SilcCipher send_key, receive_key;
  SilcHmac hmac_send, hmac_receive;

  SILC_LOG_DEBUG(("Key exchange completed"));

  if (status != SILC_SKE_STATUS_OK) {
    /* Key exchange failed */
    conn->callback(conn->client, conn,
		   status == SILC_SKE_STATUS_TIMEOUT ?
		   SILC_CLIENT_CONN_ERROR_TIMEOUT :
		   SILC_CLIENT_CONN_ERROR_KE, conn->internal->error,
		   conn->internal->disconnect_message,
		   conn->callback_context);
    return;
  }

  /* Allocate the cipher and HMAC contexts */
  if (!silc_ske_set_keys(ske, keymat, prop, &send_key, &receive_key,
			 &hmac_send, &hmac_receive, &conn->internal->hash)) {
    conn->callback(conn->client, conn,
		   SILC_CLIENT_CONN_ERROR_KE, 0, NULL,
		   conn->callback_context);
    return;
  }

  /* Set the keys into the packet stream.  After this call packets will be
     encrypted with these keys. */
  if (!silc_packet_set_keys(conn->stream, send_key, receive_key, hmac_send,
			    hmac_receive, FALSE)) {
    conn->callback(conn->client, conn,
		   SILC_CLIENT_CONN_ERROR_KE, 0, NULL,
		   conn->callback_context);
    return;
  }

  /* Key exchange successful */
  conn->callback(conn->client, conn, SILC_CLIENT_CONN_SUCCESS, 0, NULL,
		 conn->callback_context);
}

/* Starts key agreement as responder. */

static void
silc_client_listener_new_connection(SilcClientListener listener,
				    SilcPacketStream stream)
{
  SilcClient client = listener->client;
  SilcClientConnection conn;
  SilcSKEParamsStruct params = {};
  const char *hostname = NULL, *ip = NULL;
  SilcUInt16 port;

  /* Get remote information */
  silc_socket_stream_get_info(silc_packet_stream_get_stream(stream),
			      NULL, &hostname, &ip, &port);
  if (!ip || !port) {
    listener->callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL,
		       listener->context);
    silc_packet_stream_destroy(stream);
    return;
  }
  if (!hostname)
    hostname = ip;

  /* Add new connection */
  conn = silc_client_add_connection(client, SILC_CONN_CLIENT, FALSE,
				    &listener->params,
				    listener->public_key,
				    listener->private_key,
				    (char *)hostname, port,
				    listener->callback, listener->context);
  if (!conn) {
    listener->callback(client, NULL, SILC_CLIENT_CONN_ERROR, 0, NULL,
		       listener->context);
    silc_packet_stream_destroy(stream);
    return;
  }
  conn->stream = stream;
  conn->internal->schedule = listener->schedule;
  silc_packet_set_context(conn->stream, conn);

  SILC_LOG_DEBUG(("Processing new incoming connection %p", conn));

  /* Allocate SKE */
  conn->internal->ske =
    silc_ske_alloc(client->rng, conn->internal->schedule,
		   listener->params.repository, listener->public_key,
		   listener->private_key, listener);
  if (!conn->internal->ske) {
    conn->callback(conn->client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		   conn->callback_context);
    return;
  }

  /* Set SKE parameters */
  params.version = client->internal->silc_client_version;
  params.flags = SILC_SKE_SP_FLAG_MUTUAL;
  if (listener->params.udp) {
    params.flags |= SILC_SKE_SP_FLAG_IV_INCLUDED;
    params.session_port = listener->params.local_port;
  }

  silc_ske_set_callbacks(conn->internal->ske, silc_client_listener_verify_key,
			 silc_client_listener_completion, conn);

  /* Start key exchange as responder */
  conn->internal->op = silc_ske_responder(conn->internal->ske,
					  conn->stream, &params);
  if (!conn->internal->op)
    conn->callback(conn->client, conn, SILC_CLIENT_CONN_ERROR, 0, NULL,
		   conn->callback_context);
}

/* TCP network listener callback.  Accepts new key agreement connection.
   Responder function. */

static void silc_client_listener_tcp_accept(SilcNetStatus status,
					    SilcStream stream,
					    void *context)
{
  SilcClientListener listener = context;
  SilcPacketStream packet_stream;

  SILC_LOG_DEBUG(("New incoming TCP connection"));

  /* Create packet stream */
  packet_stream =
    silc_packet_stream_create(listener->client->internal->packet_engine,
			      listener->schedule, stream);
  if (!packet_stream) {
    silc_stream_destroy(stream);
    return;
  }

  /* Process session */
  silc_client_listener_new_connection(listener, packet_stream);
}

/* UDP network listener callback.  Accepts new key agreement session.
   Responder function. */

static SilcBool silc_client_udp_accept(SilcPacketEngine engine,
                                       SilcPacketStream stream,
                                       SilcPacket packet,
                                       void *callback_context,
                                       void *stream_context)
{
  SilcClientListener listener = callback_context;
  SilcPacketStream packet_stream;
  SilcUInt16 port;
  const char *ip;

  SILC_LOG_DEBUG(("New incoming UDP connection"));

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
  packet_stream = silc_packet_stream_add_remote(stream, ip, port, packet);
  if (!packet_stream) {
    silc_packet_free(packet);
    return TRUE;
  }

  /* Process session */
  silc_client_listener_new_connection(listener, packet_stream);
  return TRUE;
}

/* Packet stream callbacks */
static SilcPacketCallbacks silc_client_listener_stream_cb =
{
  silc_client_udp_accept, NULL, NULL
};

/***************************** Listner routines *****************************/

/* Adds network listener.  The `callback' will be called after new conection
   has arrived and key exchange protocol has been completed. */

SilcClientListener
silc_client_listener_add(SilcClient client,
			 SilcSchedule schedule,
			 SilcClientConnectionParams *params,
			 SilcPublicKey public_key,
			 SilcPrivateKey private_key,
			 SilcClientConnectCallback callback,
			 void *context)
{
  SilcClientListener listener;
  SilcStream stream;

  if (!client || !schedule ||
      !params || (!params->local_ip && !params->bind_ip))
    return NULL;

  SILC_LOG_DEBUG(("Adding new listener"));

  listener = silc_calloc(1, sizeof(*listener));
  if (!listener)
    return NULL;
  listener->client = client;
  listener->schedule = schedule;
  listener->callback = callback;
  listener->context = context;
  listener->params = *params;
  listener->public_key = public_key;
  listener->private_key = private_key;

  /* Create network listener */
  if (params->udp) {
    /* UDP listener */
    stream = silc_net_udp_connect(params->bind_ip ? params->bind_ip :
				  params->local_ip, params->local_port,
				  NULL, 0, schedule);
    listener->udp_listener =
      silc_packet_stream_create(client->internal->packet_engine,
				schedule, stream);
    if (!listener->udp_listener) {
      client->internal->ops->say(
		     client, NULL, SILC_CLIENT_MESSAGE_ERROR,
		     "Cannot create UDP listener on %s on port %d: %s",
		     params->bind_ip ? params->bind_ip :
		     params->local_ip, params->local_port, strerror(errno));
      silc_client_listener_free(listener);
      if (stream)
	silc_stream_destroy(stream);
      return NULL;
    }
    silc_packet_stream_link(listener->udp_listener,
			    &silc_client_listener_stream_cb, listener,
			    1000000, SILC_PACKET_ANY, -1);

    if (!params->local_port) {
      /* Get listener port */
      SilcSocket sock;
      silc_socket_stream_get_info(stream, &sock, NULL, NULL, NULL);
      listener->params.local_port = silc_net_get_local_port(sock);
    }
  } else {
    /* TCP listener */
    listener->tcp_listener =
      silc_net_tcp_create_listener(params->bind_ip ?
				   (const char **)&params->bind_ip :
				   (const char **)&params->local_ip,
				   1, params->local_port, TRUE, FALSE,
				   schedule, silc_client_listener_tcp_accept,
				   listener);
    if (!listener->tcp_listener) {
      client->internal->ops->say(
		     client, NULL, SILC_CLIENT_MESSAGE_ERROR,
		     "Cannot create listener on %s on port %d: %s",
		     params->bind_ip ? params->bind_ip :
		     params->local_ip, params->local_port, strerror(errno));

      silc_client_listener_free(listener);
      return NULL;
    }

    if (!params->local_port) {
      /* Get listener port */
      SilcUInt16 *ports;
      ports = silc_net_listener_get_port(listener->tcp_listener, NULL);
      listener->params.local_port = ports[0];
      silc_free(ports);
    }
  }

  SILC_LOG_DEBUG(("Bound listener to %s:%d",
		  params->bind_ip ? params->bind_ip : params->local_ip,
		  listener->params.local_port));

  return listener;
}

/* Close and free listner */

void silc_client_listener_free(SilcClientListener listener)
{
  if (listener->tcp_listener)
    silc_net_close_listener(listener->tcp_listener);
  silc_packet_stream_destroy(listener->udp_listener);
  silc_free(listener);
}

/* Return listner bound port */

SilcUInt16 silc_client_listener_get_local_port(SilcClientListener listener)
{
  return listener->params.local_port;
}
