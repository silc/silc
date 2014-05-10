/*

  client_prvmsg.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2014 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************** Private Message Send ****************************/

/* Sends private message to remote client. */

SilcBool silc_client_send_private_message(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  SilcMessageFlags flags,
					  SilcHash hash,
					  unsigned char *data,
					  SilcUInt32 data_len)
{
  SilcBuffer buffer;
  SilcBool ret;
  SilcID sid, rid;

  if (silc_unlikely(!client || !conn || !client_entry))
    return FALSE;
  if (silc_unlikely(flags & SILC_MESSAGE_FLAG_SIGNED && !hash))
    return FALSE;
  if (silc_unlikely(conn->internal->disconnected))
    return FALSE;

  SILC_LOG_DEBUG(("Sending private message"));

  /* Auto-negotiate private message key (AKE) if there is no key or
     it's time to rekey. */
  if (!client->internal->params->dont_autoneg_prvmsg_keys &&
      !client_entry->internal.no_ake && client_entry != conn->local_entry &&
      (!client_entry->internal.send_key ||
       (client_entry->internal.ake_rekey <= silc_time() ||
	client_entry->internal.ake_generation !=
	conn->internal->ake_generation))) {
    return silc_client_autoneg_private_message_key(
					client, conn, client_entry, NULL,
					flags, hash, data, data_len);
  }

  sid.type = SILC_ID_CLIENT;
  sid.u.client_id = *conn->local_id;
  rid.type = SILC_ID_CLIENT;
  rid.u.client_id = client_entry->id;

  /* Encode private message payload */
  buffer =
    silc_message_payload_encode(flags, data, data_len,
				(!client_entry->internal.send_key ? FALSE :
				 !client_entry->internal.generated),
				TRUE, client_entry->internal.send_key,
				client_entry->internal.hmac_send,
				client->rng, NULL, conn->private_key,
				hash, &sid, &rid, NULL);
  if (silc_unlikely(!buffer)) {
    SILC_LOG_ERROR(("Error encoding private message"));
    return FALSE;
  }

  /* Send the private message packet */
  ret = silc_packet_send_ext(conn->stream, SILC_PACKET_PRIVATE_MESSAGE,
			     client_entry->internal.send_key ?
			     SILC_PACKET_FLAG_PRIVMSG_KEY : 0,
			     0, NULL, SILC_ID_CLIENT, &client_entry->id,
			     silc_buffer_datalen(buffer), NULL, NULL);

  silc_buffer_free(buffer);
  return ret;
}

/************************* Private Message Receive **************************/

/* Client resolving callback.  Continues with the private message processing */

static void silc_client_private_message_resolved(SilcClient client,
						 SilcClientConnection conn,
						 SilcStatus status,
						 SilcDList clients,
						 void *context)
{
  /* If no client found, ignore the private message, a silent error */
  if (!clients)
    silc_fsm_next(context, silc_client_private_message_error);

  /* Continue processing the private message packet */
  SILC_FSM_CALL_CONTINUE(context);
}

/* Private message received. */

SILC_FSM_STATE(silc_client_private_message)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcMessagePayload payload = NULL;
  SilcClientID remote_id;
  SilcClientEntry remote_client = NULL;
  SilcMessageFlags flags;
  unsigned char *message;
  SilcUInt32 message_len;

  SILC_LOG_DEBUG(("Received private message"));

  if (silc_unlikely(packet->src_id_type != SILC_ID_CLIENT)) {
    /** Invalid packet */
    silc_fsm_next(fsm, silc_client_private_message_error);
    return SILC_FSM_CONTINUE;
  }

  if (silc_unlikely(!silc_id_str2id(packet->src_id, packet->src_id_len,
				    SILC_ID_CLIENT, &remote_id,
				    sizeof(remote_id)))) {
    /** Invalid source ID */
    silc_fsm_next(fsm, silc_client_private_message_error);
    return SILC_FSM_CONTINUE;
  }

  /* Check whether we know this client already */
  remote_client = silc_client_get_client_by_id(client, conn, &remote_id);
  if (!remote_client || !remote_client->nickname[0]) {
    /** Resolve client info */
    silc_client_unref_client(client, conn, remote_client);
    SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					 client, conn, &remote_id, NULL,
					 silc_client_private_message_resolved,
					 fsm));
    /* NOT REACHED */
  }

  if (silc_unlikely(packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY &&
		    !remote_client->internal.receive_key &&
		    !remote_client->internal.hmac_receive)) {
#if 1
    /* Kludge to check if the message has SKE packet inside, and then start
       key exchange protocol.  Remove this once AKE support is everywhere. */
    payload = silc_message_payload_parse(silc_buffer_datalen(&packet->buffer),
					 TRUE, FALSE, NULL, NULL,
					 packet->src_id, packet->src_id_len,
					 packet->dst_id, packet->dst_id_len,
					 NULL, FALSE, NULL);
    if (!payload)
      goto out;

    flags = silc_message_get_flags(payload);
    if (flags & SILC_MESSAGE_FLAG_PACKET &&
	silc_client_autoneg_private_message_key(client, conn, remote_client,
						packet, 0, NULL, NULL, 0))
      packet = NULL;
#endif /* 0 */
    goto out;
  }

  /* Parse the payload and decrypt it also if private message key is set */
  payload =
    silc_message_payload_parse(silc_buffer_datalen(&packet->buffer),
			       TRUE, !remote_client->internal.generated,
			       remote_client->internal.receive_key,
			       remote_client->internal.hmac_receive,
			       packet->src_id, packet->src_id_len,
			       packet->dst_id, packet->dst_id_len,
			       NULL, FALSE, NULL);
  if (silc_unlikely(!payload)) {
    /* Private message key is set but the sender may have removed it,
       try to parse without it. */
    if (remote_client->internal.receive_key) {
      SILC_LOG_DEBUG(("Parse payload without using private message key"));
      payload =
	silc_message_payload_parse(silc_buffer_datalen(&packet->buffer),
				   TRUE, FALSE, NULL, NULL,
				   packet->src_id, packet->src_id_len,
				   packet->dst_id, packet->dst_id_len,
				   NULL, FALSE, NULL);
    }
  }
  if (!payload)
    goto out;

  flags = silc_message_get_flags(payload);

  /* If message contains SILC packet, process the packet here */
  if (flags & SILC_MESSAGE_FLAG_PACKET) {
    if (silc_client_autoneg_private_message_key(client, conn, remote_client,
						packet, 0, NULL, NULL, 0))
      packet = NULL;
    goto out;
  }

  message = silc_message_get_data(payload, &message_len);

  /* Pass the private message to application */
  client->internal->ops->private_message(client, conn, remote_client, payload,
					 flags, message, message_len);

  /* See if we are away (gone). If we are away we will reply to the
     sender with the set away message. */
  if (conn->internal->away_message &&
      !(flags & SILC_MESSAGE_FLAG_NOREPLY)) {
    /* If it's me, ignore */
    if (SILC_ID_CLIENT_COMPARE(&remote_id, conn->local_id))
      goto out;

    /* Send the away message */
    silc_client_send_private_message(client, conn, remote_client,
				     SILC_MESSAGE_FLAG_AUTOREPLY |
				     SILC_MESSAGE_FLAG_NOREPLY, NULL,
				     conn->internal->away_message,
				     strlen(conn->internal->away_message));
  }

 out:
  /** Packet processed */
  if (packet)
    silc_packet_free(packet);
  silc_client_unref_client(client, conn, remote_client);
  if (payload)
    silc_message_payload_free(payload);
  return SILC_FSM_FINISH;
}

/* Private message error. */

SILC_FSM_STATE(silc_client_private_message_error)
{
  SilcPacket packet = state_context;
  silc_packet_free(packet);
  return SILC_FSM_FINISH;
}

/* Initialize private message waiter for the `conn' connection. */

SilcBool silc_client_private_message_wait_init(SilcClient client,
					       SilcClientConnection conn,
					       SilcClientEntry client_entry)
{
  SilcID id;

  if (client_entry->internal.prv_waiter)
    return TRUE;

  /* We want SILC_PACKET_PRIVATE_MESSAGE packets from this source ID. */
  id.type = SILC_ID_CLIENT;
  id.u.client_id = client_entry->id;

  client_entry->internal.prv_waiter =
    silc_packet_wait_init(conn->stream, &id, SILC_PACKET_PRIVATE_MESSAGE, -1);
  if (!client_entry->internal.prv_waiter)
    return FALSE;

  return TRUE;
}

/* Uninitializes private message waiter. */

void silc_client_private_message_wait_uninit(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry)
{
  if (!client_entry->internal.prv_waiter)
    return;
  silc_packet_wait_uninit(client_entry->internal.prv_waiter, conn->stream);
  client_entry->internal.prv_waiter = NULL;
}

/* Blocks the calling process or thread until private message has been
   received from the specified client. */

SilcBool silc_client_private_message_wait(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  SilcMessagePayload *payload)
{
  SilcPacket packet;

  if (!client_entry->internal.prv_waiter)
    return FALSE;

  /* Block until private message arrives */
  do {
    if ((silc_packet_wait(client_entry->internal.prv_waiter, 0, &packet)) < 0)
      return FALSE;

    /* Parse the payload and decrypt it also if private message key is set */
    *payload =
      silc_message_payload_parse(silc_buffer_data(&packet->buffer),
				 silc_buffer_len(&packet->buffer),
				 TRUE, !client_entry->internal.generated,
				 client_entry->internal.receive_key,
				 client_entry->internal.hmac_receive,
				 packet->src_id, packet->src_id_len,
				 packet->dst_id, packet->dst_id_len,
				 NULL, FALSE, NULL);
    if (!(*payload)) {
      silc_packet_free(packet);
      continue;
    }

    break;
  } while (1);

  silc_packet_free(packet);
  return TRUE;
}

/*************************** Private Message Key ****************************/

/* Sends private message key request.  Sender of this packet is initiator
   when setting the private message key. */

static SilcBool
silc_client_send_private_message_key_request(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry)
{
  const char *cipher, *hmac;

  SILC_LOG_DEBUG(("Sending private message key request"));

  cipher = silc_cipher_get_name(client_entry->internal.send_key);
  hmac = silc_hmac_get_name(client_entry->internal.hmac_send);

  /* Send the packet */
  return silc_packet_send_va_ext(conn->stream,
				 SILC_PACKET_PRIVATE_MESSAGE_KEY,
				 0, 0, NULL, SILC_ID_CLIENT,
				 &client_entry->id, NULL, NULL,
				 SILC_STR_UI_SHORT(strlen(cipher)),
				 SILC_STR_DATA(cipher, strlen(cipher)),
				 SILC_STR_UI_SHORT(strlen(hmac)),
				 SILC_STR_DATA(hmac, strlen(hmac)),
				 SILC_STR_END);
}

/* Client resolving callback.  Here we simply mark that we are the responder
   side of this private message key request.  */

static void silc_client_private_message_key_cb(SilcClient client,
					       SilcClientConnection conn,
					       SilcStatus status,
					       SilcDList clients,
					       void *context)
{
  SilcFSMThread thread = context;
  SilcPacket packet = silc_fsm_get_state_context(thread);
  unsigned char *cipher = NULL, *hmac = NULL;
  SilcClientEntry client_entry;
  int ret;

  if (!clients) {
    silc_packet_free(packet);
    silc_fsm_finish(thread);
    return;
  }

  /* Parse the private message key payload */
  ret = silc_buffer_unformat(&packet->buffer,
			     SILC_STR_UI16_STRING_ALLOC(&cipher),
			     SILC_STR_UI16_STRING_ALLOC(&hmac),
			     SILC_STR_END);
  if (!ret)
    goto out;

  /* Mark that we are responder */
  client_entry = silc_dlist_get(clients);
  if (client_entry)
    client_entry->internal.prv_resp = TRUE;

  /* XXX we should notify application that remote wants to set up the
     static key.  And we should tell if we already have key with remote.
     Application should return status telling whether to delete the key
     or not. */

 out:
  silc_free(cipher);
  silc_free(hmac);
  silc_packet_free(packet);
  silc_fsm_finish(thread);
}

/* Processes incoming Private Message Key payload to indicate that the
   sender whishes to set up a static private message key. */

SILC_FSM_STATE(silc_client_private_message_key)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcPacket packet = state_context;
  SilcClientID remote_id;

  if (packet->src_id_type != SILC_ID_CLIENT) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  if (!silc_id_str2id(packet->src_id, packet->src_id_len, SILC_ID_CLIENT,
		      &remote_id, sizeof(remote_id))) {
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  /* Always resolve the remote client.  The actual packet is processed
     in the resolving callback. */
  SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
				       client, conn, &remote_id, NULL,
				       silc_client_private_message_key_cb,
				       fsm));
}

/* Adds new private message key to `client_entry'.  If we are setting this
   before receiving request for it from `client_entry' we will send the
   request to the client.  Otherwise, we are responder side. */

SilcBool silc_client_add_private_message_key(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry,
					     const char *cipher,
					     const char *hmac,
					     unsigned char *key,
					     SilcUInt32 key_len)
{
  SilcSKEKeyMaterial keymat;
  SilcBool ret;

  if (!client || !client_entry)
    return FALSE;

  /* Return FALSE if key already set */
  if (client_entry->internal.send_key && client_entry->internal.receive_key)
    return FALSE;

  if (!cipher)
    cipher = SILC_DEFAULT_CIPHER;
  if (!hmac)
    hmac = SILC_DEFAULT_HMAC;

  /* Check the requested cipher and HMAC */
  if (!silc_cipher_is_supported(cipher))
    return FALSE;
  if (!silc_hmac_is_supported(hmac))
    return FALSE;

  /* Save the key */
  client_entry->internal.key = silc_memdup(key, key_len);
  client_entry->internal.key_len = key_len;

  /* Produce the key material as the protocol defines */
  keymat = silc_ske_process_key_material_data(key, key_len, 16, 256, 16,
					      conn->internal->sha1hash);
  if (!keymat)
    return FALSE;

  /* Set the key into use */
  ret = silc_client_add_private_message_key_ske(client, conn, client_entry,
						cipher, hmac, keymat);
  client_entry->internal.generated = FALSE;

  /* Free the key material */
  silc_ske_free_key_material(keymat);

  /* If we are setting the key without a request from the remote client,
     we will send request to remote. */
  if (!client_entry->internal.prv_resp)
    silc_client_send_private_message_key_request(client, conn, client_entry);

  return ret;
}

/* Same as above but takes the key material from the SKE key material
   structure. */

SilcBool silc_client_add_private_message_key_ske(SilcClient client,
						 SilcClientConnection conn,
						 SilcClientEntry client_entry,
						 const char *cipher,
						 const char *hmac,
						 SilcSKEKeyMaterial keymat)
{
  if (!client || !client_entry)
    return FALSE;

  /* Return FALSE if key already set */
  if (client_entry->internal.send_key && client_entry->internal.receive_key)
    return FALSE;

  if (!cipher)
    cipher = SILC_DEFAULT_CIPHER;
  if (!hmac)
    hmac = SILC_DEFAULT_HMAC;

  /* Check the requested cipher and HMAC */
  if (!silc_cipher_is_supported(cipher))
    return FALSE;
  if (!silc_hmac_is_supported(hmac))
    return FALSE;

  client_entry->internal.generated = TRUE;
  client_entry->internal.no_ake = TRUE;

  /* Allocate the cipher and HMAC */
  if (!silc_cipher_alloc(cipher, &client_entry->internal.send_key))
    return FALSE;
  if (!silc_cipher_alloc(cipher, &client_entry->internal.receive_key))
    return FALSE;
  if (!silc_hmac_alloc(hmac, NULL, &client_entry->internal.hmac_send))
    return FALSE;
  if (!silc_hmac_alloc(hmac, NULL, &client_entry->internal.hmac_receive))
    return FALSE;

  /* Set the keys */
  if (client_entry->internal.prv_resp) {
    silc_cipher_set_key(client_entry->internal.send_key,
			keymat->receive_enc_key,
			keymat->enc_key_len, TRUE);
    silc_cipher_set_iv(client_entry->internal.send_key,
		       keymat->receive_iv);
    silc_cipher_set_key(client_entry->internal.receive_key,
			keymat->send_enc_key,
			keymat->enc_key_len, FALSE);
    silc_cipher_set_iv(client_entry->internal.receive_key, keymat->send_iv);
    silc_hmac_set_key(client_entry->internal.hmac_send,
		      keymat->receive_hmac_key,
		      keymat->hmac_key_len);
    silc_hmac_set_key(client_entry->internal.hmac_receive,
		      keymat->send_hmac_key,
		      keymat->hmac_key_len);
  } else {
    silc_cipher_set_key(client_entry->internal.send_key,
			keymat->send_enc_key,
			keymat->enc_key_len, TRUE);
    silc_cipher_set_iv(client_entry->internal.send_key,
		       keymat->send_iv);
    silc_cipher_set_key(client_entry->internal.receive_key,
			keymat->receive_enc_key,
			keymat->enc_key_len, FALSE);
    silc_cipher_set_iv(client_entry->internal.receive_key, keymat->receive_iv);
    silc_hmac_set_key(client_entry->internal.hmac_send,
		      keymat->send_hmac_key,
		      keymat->hmac_key_len);
    silc_hmac_set_key(client_entry->internal.hmac_receive,
		      keymat->receive_hmac_key,
		      keymat->hmac_key_len);
  }

  return TRUE;
}

/* Removes the private message from the library. The key won't be used
   after this to protect the private messages with the remote `client_entry'
   client. Returns FALSE on error, TRUE otherwise. */

SilcBool silc_client_del_private_message_key(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry)
{
  if (!client || !client_entry)
    return FALSE;

  if (!client_entry->internal.send_key && !client_entry->internal.receive_key)
    return FALSE;

  silc_cipher_free(client_entry->internal.send_key);
  silc_cipher_free(client_entry->internal.receive_key);

  if (client_entry->internal.key) {
    memset(client_entry->internal.key, 0, client_entry->internal.key_len);
    silc_free(client_entry->internal.key);
  }

  client_entry->internal.send_key = NULL;
  client_entry->internal.receive_key = NULL;
  client_entry->internal.key = NULL;
  client_entry->internal.prv_resp = FALSE;

  return TRUE;
}

/* Returns array of set private message keys associated to the connection
   `conn'. Returns allocated SilcPrivateMessageKeys array and the array
   count to the `key_count' argument. The array must be freed by the caller
   by calling the silc_client_free_private_message_keys function. Note:
   the keys returned in the array is in raw format. It might not be desired
   to show the keys as is. The application might choose not to show the keys
   at all or to show the fingerprints of the keys. */

SilcPrivateMessageKeys
silc_client_list_private_message_keys(SilcClient client,
				      SilcClientConnection conn,
				      SilcUInt32 *key_count)
{
  SilcPrivateMessageKeys keys;
  SilcUInt32 count = 0;
  SilcList list;
  SilcIDCacheEntry id_cache;
  SilcClientEntry entry;

  if (!client || !conn)
    return NULL;

  silc_mutex_lock(conn->internal->lock);
  if (!silc_idcache_get_all(conn->internal->client_cache, &list)) {
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  keys = silc_calloc(silc_list_count(list), sizeof(*keys));
  if (!keys) {
    silc_mutex_unlock(conn->internal->lock);
    return NULL;
  }

  silc_list_start(list);
  while ((id_cache = silc_list_get(list))) {
    entry = id_cache->context;
    if (entry->internal.send_key) {
      keys[count].client_entry = entry;
      keys[count].cipher = (char *)silc_cipher_get_name(entry->internal.
							send_key);
      keys[count].key = (entry->internal.generated == FALSE ?
			 entry->internal.key : NULL);
      keys[count].key_len = (entry->internal.generated == FALSE ?
			     entry->internal.key_len : 0);
      count++;
    }
  }

  silc_mutex_unlock(conn->internal->lock);

  if (key_count)
    *key_count = count;

  return keys;
}

/* Frees the SilcPrivateMessageKeys array returned by the function
   silc_client_list_private_message_keys. */

void silc_client_free_private_message_keys(SilcPrivateMessageKeys keys,
					   SilcUInt32 key_count)
{
  silc_free(keys);
}

/* Return private message key from the client entry. */

SilcBool
silc_client_private_message_key_is_set(SilcClient client,
				       SilcClientConnection conn,
				       SilcClientEntry client_entry)
{
  return client_entry->internal.send_key != NULL;
}

/********************* Private Message Key Autoneg (AKE) ********************/

/* Private message key auto-negotiation context */
struct SilcClientAutonegMessageKeyStruct {
  SilcClientConnection conn;		 /* Connection to server */
  SilcSKE ske;				 /* SKE with remote client */
  SilcAsyncOperation ske_op;		 /* SKE operation */
  SilcStream stream;			 /* PRIVATE_MESSAGE stream */
  SilcPacketStream ske_stream;	         /* Packet stream for SKE (inside
					    the PRIVATE_MESSAGE stream) */
  SilcDList messages;			 /* Message queue */
  SilcHash hash;			 /* Initial message hash */
  SilcPublicKey public_key;		 /* Remote client public key */
  SilcVerifyKeyContext verify;
  SilcSKEParamsStruct params;
  SilcUInt32 generation;		 /* Starting AKE generation */
};

static SilcBool
silc_client_autoneg_key_recv_ske(SilcPacketEngine engine,
				 SilcPacketStream stream,
				 SilcPacket packet,
				 void *callback_context,
				 void *stream_context);

static const SilcPacketCallbacks autoneg_key_ske_cbs =
{
  silc_client_autoneg_key_recv_ske, NULL, NULL
};

/* Destroy auto-negotiation context */

static void silc_client_autoneg_key_free(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry)
{
  SilcClientAutonegMessageKey ake = client_entry->internal.ake;
  SilcBuffer m;

  if (ake->ske_op)
    silc_async_abort(ake->ske_op, NULL, NULL);

  silc_ske_free(ake->ske);
  silc_packet_stream_unlink(ake->ske_stream, &autoneg_key_ske_cbs, NULL);
  silc_packet_stream_destroy(ake->ske_stream);
  if (ake->hash)
    silc_hash_free(ake->hash);

  silc_dlist_start(ake->messages);
  while ((m = silc_dlist_get(ake->messages)) != SILC_LIST_END) {
    silc_dlist_del(ake->messages, m);
    silc_buffer_free(m);
  }
  silc_dlist_uninit(ake->messages);

  client_entry->internal.op = NULL;
  client_entry->internal.ake = NULL;
  silc_client_unref_client(client, conn, client_entry);

  if (ake->verify)
    ake->verify->aborted = TRUE;
  else if (ake->public_key)
    silc_pkcs_public_key_free(ake->public_key);

  silc_free(ake);
}

/* Destroy auto-negotiation context */

SILC_TASK_CALLBACK(silc_client_autoneg_key_finish)
{
  SilcClientEntry client_entry = context;
  SilcClientAutonegMessageKey ake = client_entry->internal.ake;
  SilcClientConnection conn = ake->conn;
  SilcClient client = conn->client;

  silc_client_autoneg_key_free(client, conn, client_entry);
}

/* Abort callback.  This aborts the auto-negotiation and the SKE */

static void
silc_client_autoneg_key_abort(SilcAsyncOperation op, void *context)
{
  SilcClientEntry client_entry = context;
  SilcClientAutonegMessageKey ake = client_entry->internal.ake;
  SilcClientConnection conn = ake->conn;
  SilcClient client = conn->client;

  if (!ake)
    return;

  silc_client_autoneg_key_free(client, conn, client_entry);
}

/* SKE packet stream callback.  Here we verify that the packets we got
   from the private message are actually SKE packets for us. */

static SilcBool
silc_client_autoneg_key_recv_ske(SilcPacketEngine engine,
				 SilcPacketStream stream,
				 SilcPacket packet,
				 void *callback_context,
				 void *stream_context)
{
  SilcClientEntry client_entry = stream_context;
  SilcClientAutonegMessageKey ake = client_entry->internal.ake;
  SilcClientID remote_id;

  SILC_LOG_DEBUG(("Packet %p type %d inside private message", packet,
		  packet->type));

  /* Take only SKE packets, drop others, no support for anything else */
  if (packet->type != SILC_PACKET_KEY_EXCHANGE &&
      packet->type != SILC_PACKET_KEY_EXCHANGE_1 &&
      packet->type != SILC_PACKET_KEY_EXCHANGE_2 &&
      packet->type != SILC_PACKET_FAILURE)
    goto drop;

  /* Must be from client to client */
  if (packet->dst_id_type != SILC_ID_CLIENT ||
      packet->src_id_type != SILC_ID_CLIENT)
    goto drop;

  if (!silc_id_str2id(packet->src_id, packet->src_id_len, SILC_ID_CLIENT,
		      &remote_id, sizeof(remote_id)))
    goto drop;

  if (!SILC_ID_CLIENT_COMPARE(&client_entry->id, &remote_id)) {
    /* The packet is not for this client, but it must be */
    SILC_LOG_DEBUG(("Client ids do not match"));
    goto drop;
  }

  /* Responder is started here if correct packet comes in */
  if (!ake->ske_op) {
    if (packet->type == SILC_PACKET_KEY_EXCHANGE) {
      /* Ignore pre-set proposal */
      if (ake->params.prop) {
	silc_ske_group_free(ake->params.prop->group);
	silc_cipher_free(ake->params.prop->cipher);
	silc_hash_free(ake->params.prop->hash);
	silc_hmac_free(ake->params.prop->hmac);
	silc_pkcs_public_key_free(ake->params.prop->public_key);
	silc_free(ake->params.prop);
	ake->params.prop = NULL;
      }
    } else if (packet->type != SILC_PACKET_KEY_EXCHANGE_1) {
      SILC_LOG_DEBUG(("Invalid SKE packet for responder"));
      silc_async_abort(client_entry->internal.op, NULL, NULL);
      goto drop;
    }

    ake->ske_op = silc_ske_responder(ake->ske, ake->ske_stream, &ake->params);
    if (!ake->ske_op) {
      silc_async_abort(client_entry->internal.op, NULL, NULL);
      goto drop;
    }

    /* We have to re-inject the packet to SKE stream because SKE wasn't
       listenning to these packets until silc_ske_responder() was called */
    silc_packet_stream_inject(ake->ske_stream, packet);
    return TRUE;
  }

  /* Packet is ok and is for us, let it pass to SKE */
  SILC_LOG_DEBUG(("Pass packet %p type %d", packet, packet->type));
  return FALSE;

 drop:
  silc_packet_free(packet);
  return TRUE;
}

/* Coder callback for actually encoding/decoding the SKE packets inside
   private messages. */

static SilcBool silc_client_autoneg_key_coder(SilcStream stream,
					      SilcStreamStatus status,
					      SilcBuffer buffer,
					      void *context)
{
  SilcBool ret = FALSE;
  SilcBuffer message;
  SilcMessagePayload payload = NULL;
  SilcMessageFlags flags;
  unsigned char *msg;
  SilcUInt32 message_len;

  switch (status) {
  case SILC_STREAM_CAN_READ:
    /* Decode private message.  We get all private messages here from
       the remote client while we're doing SKE, so we must take the
       correct messages. */
    SILC_LOG_DEBUG(("Decode packet inside private message"));

    payload = silc_message_payload_parse(silc_buffer_datalen(buffer),
					 TRUE, FALSE, NULL, NULL, NULL, 0,
					 NULL, 0, NULL, FALSE, NULL);
    if (!payload) {
      SILC_LOG_DEBUG(("Error decoding private message payload"));
      goto out;
    }

    /* Ignore this message if it's not packet */
    flags = silc_message_get_flags(payload);
    if (!(flags & SILC_MESSAGE_FLAG_PACKET)) {
      SILC_LOG_DEBUG(("Private message doesn't contain packet"));
      silc_message_payload_free(payload);
      goto out;
    }

    /* Take the packet */
    ret = TRUE;

    msg = silc_message_get_data(payload, &message_len);
    silc_buffer_reset(buffer);
    if (!silc_buffer_enlarge(buffer, message_len)) {
      silc_message_payload_free(payload);
      goto out;
    }
    silc_buffer_put(buffer, msg, message_len);

    silc_message_payload_free(payload);
    break;

  case SILC_STREAM_CAN_WRITE:
    /* Encode private message */
    SILC_LOG_DEBUG(("Encode packet inside private message"));

    ret = TRUE;

    message =
      silc_message_payload_encode(SILC_MESSAGE_FLAG_PACKET,
				  silc_buffer_datalen(buffer),
				  FALSE, TRUE, NULL, NULL, NULL,
				  NULL, NULL, NULL, NULL, NULL, NULL);
    if (!message) {
      SILC_LOG_DEBUG(("Error encoding private message payload"));
      goto out;
    }

    silc_buffer_reset(buffer);
    if (!silc_buffer_enlarge(buffer, silc_buffer_len(message)))
      goto out;
    silc_buffer_put(buffer, silc_buffer_datalen(message));

    break;

  default:
    break;
  }

 out:
  return ret;
}

/* Called after application has verified remote client's public key */

static void
silc_client_autoneg_key_verify_pubkey_cb(SilcBool success, void *context)
{
  SilcVerifyKeyContext verify = context;
  SilcClientAutonegMessageKey ake = verify->context;

  SILC_LOG_DEBUG(("Start, verify %p, ake %p", context, ake));

  /* Call the completion callback back to the SKE */
  if (!verify->aborted) {
    ake->verify = NULL;
    verify->completion(verify->ske, success ? SILC_SKE_STATUS_OK :
		       SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
		       verify->completion_context);
  } else {
    silc_pkcs_public_key_free(verify->public_key);
  }

  silc_free(verify);
}

/* Remote client's public key verification callback */

static void
silc_client_autoneg_key_verify_pubkey(SilcSKE ske,
				      SilcPublicKey public_key,
				      void *context,
				      SilcSKEVerifyCbCompletion completion,
				      void *completion_context)
{
  SilcClientEntry client_entry = context;
  SilcClientAutonegMessageKey ake = client_entry->internal.ake;
  SilcClientConnection conn = ake->conn;
  SilcClient client = conn->client;
  SilcVerifyKeyContext verify;

  /* Use public key we cached earlier in AKE for direction verification */
  if (client_entry->internal.send_key && client_entry->public_key &&
      silc_pkcs_public_key_compare(public_key, client_entry->public_key)) {
    SILC_LOG_DEBUG(("Client's cached public key matches"));
    completion(ske, SILC_SKE_STATUS_OK, completion_context);
    return;
  }

  /* If we provided repository for SKE and we got here the key was not
     found from the repository. */
  if (conn->internal->params.repository &&
      !conn->internal->params.verify_notfound) {
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }

  SILC_LOG_DEBUG(("Verify remote client public key"));

  ake->public_key = silc_pkcs_public_key_copy(public_key);
  if (!ake->public_key) {
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }

  verify = silc_calloc(1, sizeof(*verify));
  if (!verify) {
    completion(ske, SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY,
	       completion_context);
    return;
  }
  verify->public_key = ake->public_key;
  verify->ske = ske;
  verify->completion = completion;
  verify->completion_context = completion_context;
  verify->context = ake;
  ake->verify = verify;

  conn->context_type = SILC_ID_CLIENT;
  conn->client_entry = client_entry;

  /* Verify public key in application */
  client->internal->ops->verify_public_key(
				client, conn,
				SILC_CONN_CLIENT, ake->public_key,
				silc_client_autoneg_key_verify_pubkey_cb,
				verify);

  conn->context_type = SILC_ID_NONE;
}

/* Key exchange protocol completion callback */

static void silc_client_autoneg_key_done(SilcSKE ske,
					 SilcSKEStatus status,
					 SilcSKESecurityProperties prop,
					 SilcSKEKeyMaterial keymat,
					 SilcSKERekeyMaterial rekey,
					 void *context)
{
  SilcClientEntry client_entry = context;
  SilcClientAutonegMessageKey ake = client_entry->internal.ake;
  SilcClientConnection conn = ake->conn;
  SilcClient client = conn->client;
  SilcBool initiator = !client_entry->internal.prv_resp;
  SilcMessageFlags flags;
  SilcBuffer m;

  ake->ske_op = NULL;

  conn->context_type = SILC_ID_CLIENT;
  conn->client_entry = client_entry;

  if (status != SILC_SKE_STATUS_OK) {
    /* Key exchange failed */
    SILC_LOG_DEBUG(("Error during key exchange: %s (%d)",
                    silc_ske_map_status(status), status));

    if (initiator) {
      if (status != SILC_SKE_STATUS_PROBE_TIMEOUT)
	client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				   "Cannot send private message to %s (%s)",
				   client_entry->nickname,
				   silc_ske_map_status(status));
      else if (client_entry->mode & SILC_UMODE_DETACHED)
	client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				   "Cannot send private message to detached "
				   "client %s", client_entry->nickname);
    } else if (status != SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY) {
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
				 "Private message key exchange failed "
				 "with %s (%s)", client_entry->nickname,
				 silc_ske_map_status(status));
    }

    /* Errors that occur due to user not responding or deciding not to
       trust the public key will not cause us to stop trying AKE next time.
       Other errors disable AKE to allow communication with other means. */
    if (initiator && status != SILC_SKE_STATUS_TIMEOUT &&
	status != SILC_SKE_STATUS_UNSUPPORTED_PUBLIC_KEY &&
	!(client_entry->mode & SILC_UMODE_DETACHED)) {
      client->internal->ops->say(client, conn, SILC_CLIENT_MESSAGE_INFO,
				 "Cannot auto-negotiate key with %s, "
				 "messages will be protected with "
				 "session key", client_entry->nickname);

      /* Don't try this again with this client */
      client_entry->internal.no_ake = TRUE;
    }
    goto out;
  }

  /* Set the new private message key into use */
  silc_client_del_private_message_key(client, conn, client_entry);
  client_entry->internal.prv_resp = !initiator;
  if (!silc_client_add_private_message_key_ske(
					client, conn, client_entry,
					silc_cipher_get_name(prop->cipher),
					silc_hmac_get_name(prop->hmac),
					keymat)) {
    SILC_LOG_DEBUG(("Error adding private message key"));

    client->internal->ops->say(client, conn,
			       SILC_CLIENT_MESSAGE_ERROR,
			       "Private message key exchange error: "
			       "cannot use keys");

    /* Don't try this again with this client */
    client_entry->internal.no_ake = TRUE;
    goto out;
  }

  /* Save the public key to client entry */
  if (!client_entry->public_key) {
    client_entry->public_key = ake->public_key;
    ake->public_key = NULL;
  }

  /* Rekey periodically */
  client_entry->internal.ake_rekey = silc_time() + 300;
  if (initiator)
    client_entry->internal.ake_rekey -= 30;
  client_entry->internal.ake_generation = conn->internal->ake_generation;
  client_entry->internal.no_ake = FALSE;

  SILC_LOG_DEBUG(("AKE completed as %s with %s, rekey in %u secs, "
		  "generation %u", initiator ? "initiator" : "responder",
		  client_entry->nickname, 300,
		  conn->internal->ake_generation));

  /* Send queued messages */
  silc_dlist_start(ake->messages);
  while ((m = silc_dlist_get(ake->messages)) != SILC_LIST_END) {
    SILC_GET16_MSB(flags, m->data - 2);
    silc_client_send_private_message(client, conn, client_entry,
				     flags, ake->hash,
				     silc_buffer_datalen(m));
  }

 out:
  conn->context_type = SILC_ID_NONE;
  conn->client_entry = NULL;
  silc_schedule_task_add_timeout(client->schedule,
				 silc_client_autoneg_key_finish,
				 client_entry, 0, 1);
}

/* Auto-negotiate private message key with the remote client using the
   SKE protocol, which is tunneled through the SILC network inside private
   messages shared between the us and the remote client.

   This operation is naturally asynchronous and will involve exchanging
   multiple messages back and forth.  Despite this, we don't run this
   operation in own FSM thread here, but instead will use the SKE library
   to do the asynchronous operation which we can abort at any time in
   case user disconnects.

   Messages and packets we receive during this operation will be processed
   in the normal connection thread. */

SilcBool
silc_client_autoneg_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry,
					SilcPacket initiator_packet,
					SilcMessageFlags flags,
					SilcHash hash,
					unsigned char *data,
					SilcUInt32 data_len)
{
  SilcClientAutonegMessageKey ake;
  SilcBool initiator = initiator_packet == NULL;
  SilcBuffer m;

  SILC_LOG_DEBUG(("Start private message AKE as %s with %s",
		  initiator ? "initiator" : "responder",
		  client_entry->nickname));

  if (client_entry->internal.op) {
    ake = client_entry->internal.ake;
    if (ake && data) {
      /* If generation has changed, we must abort this exchange and
	 start a new one. */
      if (ake->generation != conn->internal->ake_generation) {
	SILC_LOG_DEBUG(("Abort ongoing AKE and start new one"));
	silc_async_abort(client_entry->internal.op, NULL, NULL);
      } else {
	SILC_LOG_DEBUG(("AKE is ongoing, queue the message"));

	m = silc_buffer_alloc_size(data_len + 2);
	if (!m)
	  return FALSE;
	SILC_PUT16_MSB(flags, m->data);
	silc_buffer_pull(m, 2);
	silc_buffer_put(m, data, data_len);
	silc_dlist_add(ake->messages, m);
	return TRUE;
      }
    } else {
      SILC_LOG_DEBUG(("Cannot start AKE, operation %p is ongoing",
		      client_entry->internal.op));
      return FALSE;
    }
  }

  ake = silc_calloc(1, sizeof(*ake));
  if (!ake)
    return FALSE;
  ake->conn = conn;
  ake->generation = conn->internal->ake_generation;

  ake->messages = silc_dlist_init();
  if (!ake->messages)
    goto err;

  /* Wrap our packet stream to a generic stream for the private messages
     we are going to exchange.  We send the packets with packet flag
     SILC_PACKET_FLAG_PRIVMSG_KEY which is a lie, but is a way to get
     clients which do not support this protocol to ignore these messages.
     This kludge should be removed once support is everywhere and
     responder should look only for the SILC_MESSAGE_FLAG_PACKET. */
  ake->stream = silc_packet_stream_wrap(conn->stream,
					SILC_PACKET_PRIVATE_MESSAGE,
					SILC_PACKET_FLAG_PRIVMSG_KEY, FALSE,
					SILC_ID_NONE, NULL,
					SILC_ID_CLIENT, &client_entry->id,
					silc_client_autoneg_key_coder,
					client_entry);
  if (!ake->stream)
    goto err;

  /* Create a new packet stream for the SKE library using the wrapped
     stream as the underlaying stream, in effect creating a tunnel to
     send SKE packets inside private message packets. */
  ake->ske_stream = silc_packet_stream_create(client->internal->packet_engine,
					      conn->internal->schedule,
					      ake->stream);
  if (!ake->ske_stream)
    goto err;

  silc_packet_set_context(ake->ske_stream, client_entry);
  silc_packet_set_ids(ake->ske_stream, SILC_ID_CLIENT, conn->local_id,
		      SILC_ID_CLIENT, &client_entry->id);

  /* Link to the new packet stream to intercept the packets before they
     go to SKE library so that we can do additional checks and decide if
     we really want to process the packets. */
  if (!silc_packet_stream_link(ake->ske_stream, &autoneg_key_ske_cbs, NULL,
			       1000001, SILC_PACKET_ANY, -1))
    goto err;

  /* Create SKE */
  ake->ske = silc_ske_alloc(client->rng, conn->internal->schedule,
			    conn->internal->params.repository,
			    conn->public_key, conn->private_key,
			    client_entry);
  if (!ake->ske)
    goto err;

  silc_ske_set_callbacks(ake->ske, silc_client_autoneg_key_verify_pubkey,
			 silc_client_autoneg_key_done, client_entry);
  ake->params.version = client->internal->silc_client_version;
  ake->params.probe_timeout_secs = 5;
  ake->params.timeout_secs = 120;
  ake->params.flags = SILC_SKE_SP_FLAG_MUTUAL | SILC_SKE_SP_FLAG_PFS;
  ake->params.small_proposal = TRUE;
  ake->params.no_acks = TRUE;

  if (client_entry->internal.send_key &&
      client_entry->internal.ake_generation == ake->generation) {
    /* Security properties for rekey */
    SilcSKESecurityProperties prop = silc_calloc(1, sizeof(*prop));
    if (!prop)
      goto err;
    silc_cipher_alloc(silc_cipher_get_name(client_entry->internal.send_key),
		      &prop->cipher);
    silc_hmac_alloc(silc_hmac_get_name(client_entry->internal.hmac_send),
		    NULL, &prop->hmac);
    silc_hash_alloc(silc_hash_get_name(silc_hmac_get_hash(
			client_entry->internal.hmac_send)), &prop->hash);
    prop->public_key = silc_pkcs_public_key_copy(client_entry->public_key);
    silc_ske_group_get_by_number(2, &prop->group);
    prop->flags = ake->params.flags;
    ake->params.prop = prop;
  }

  /* Start key exchange, responder is started in the packet callback  */
  if (initiator) {
    ake->ske_op = silc_ske_initiator(ake->ske, ake->ske_stream, &ake->params,
				     NULL);
    if (!ake->ske_op)
      goto err;
  }

  /* Finally, set up the client entry */
  client_entry->internal.op = silc_async_alloc(silc_client_autoneg_key_abort,
					       NULL, client_entry);
  if (!client_entry->internal.op)
    goto err;
  client_entry->internal.ake = ake;
  client_entry->internal.no_ake = FALSE;
  client_entry->internal.prv_resp = !initiator;
  silc_client_ref_client(client, conn, client_entry);

  /* As responder reinject the packet to the new stream so it gets decoded
     from the private message payload. */
  if (initiator_packet)
    silc_packet_stream_inject(conn->stream, initiator_packet);

  /* Save the initial message, it will be sent after the key has been
     negotiated. */
  if (data && data_len) {
    m = silc_buffer_alloc_size(data_len + 2);
    if (m) {
      SILC_PUT16_MSB(flags, m->data);
      silc_buffer_pull(m, 2);
      silc_buffer_put(m, data, data_len);
      silc_dlist_add(ake->messages, m);
    }
    if (hash)
      silc_hash_alloc(silc_hash_get_name(hash), &ake->hash);
  }

  return TRUE;

 err:
  if (ake->ske)
    silc_ske_free(ake->ske);
  if (ake->ske_stream) {
    silc_packet_stream_unlink(ake->ske_stream, &autoneg_key_ske_cbs, NULL);
    silc_packet_stream_destroy(ake->ske_stream);
  } else if (ake->stream)
    silc_stream_destroy(ake->stream);
  silc_dlist_uninit(ake->messages);
  silc_free(ake);
  return FALSE;
}

/* Sets away `message'.  The away message may be set when the client's
   mode is changed to SILC_UMODE_GONE and the client whishes to reply
   to anyone who sends private message.  The `message' will be sent
   automatically back to the the client who send private message.  If
   away message is already set this replaces the old message with the
   new one.  If `message' is NULL the old away message is removed.
   The sender may freely free the memory of the `message'. */

SilcBool silc_client_set_away_message(SilcClient client,
				      SilcClientConnection conn,
				      char *message)
{
  if (!client || !conn)
    return FALSE;

  if (!message) {
    silc_free(conn->internal->away_message);
    conn->internal->away_message = NULL;
    return TRUE;
  }

  if (conn->internal->away_message)
    silc_free(conn->internal->away_message);

  conn->internal->away_message = strdup(message);
  if (!conn->internal->away_message)
    return FALSE;

  return TRUE;
}
