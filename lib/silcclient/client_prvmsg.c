/*

  client_prvmsg.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

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

  if (silc_unlikely(!client || !conn || !client_entry))
    return FALSE;
  if (silc_unlikely(flags & SILC_MESSAGE_FLAG_SIGNED && !hash))
    return FALSE;
  if (silc_unlikely(conn->internal->disconnected))
    return FALSE;

  SILC_LOG_DEBUG(("Sending private message"));

  /* Encode private message payload */
  buffer =
    silc_message_payload_encode(flags, data, data_len,
				(!client_entry->internal.send_key ? FALSE :
				 !client_entry->internal.generated),
				TRUE, client_entry->internal.send_key,
				client_entry->internal.hmac_send,
				client->rng, NULL, conn->private_key,
				hash, NULL);
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

/* Private message waiting context */
typedef struct {
  SilcMutex wait_lock;
  SilcCond wait_cond;
  SilcDList message_queue;
  unsigned int stopped      : 1;
} *SilcClientPrivateMessageWait;

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
  SilcClientPrivateMessageWait pmw;

  SILC_LOG_DEBUG(("Received private message"));

  if (silc_unlikely(packet->src_id_type != SILC_ID_CLIENT)) {
    /** Invalid packet */
    silc_fsm_next(fsm, silc_client_private_message_error);
    SILC_FSM_CONTINUE;
  }

  if (silc_unlikely(!silc_id_str2id(packet->src_id, packet->src_id_len,
				    SILC_ID_CLIENT, &remote_id,
				    sizeof(remote_id)))) {
    /** Invalid source ID */
    silc_fsm_next(fsm, silc_client_private_message_error);
    SILC_FSM_CONTINUE;
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
		    !remote_client->internal.hmac_receive))
    goto out;

  /* Parse the payload and decrypt it also if private message key is set */
  payload =
    silc_message_payload_parse(silc_buffer_datalen(&packet->buffer),
			       TRUE, !remote_client->internal.generated,
			       remote_client->internal.receive_key,
			       remote_client->internal.hmac_receive,
			       NULL, FALSE, NULL);
  if (silc_unlikely(!payload))
    goto out;

#if 0 /* We need to rethink this.  This doesn't work with multiple
	 waiters, and performance is suboptimal. */
  /* Check if some thread is waiting for this private message */
  silc_mutex_lock(conn->internal->lock);
  if (conn->internal->privmsg_wait &&
      silc_hash_table_find_ext(conn->internal->privmsg_wait,
			       &remote_client->id, NULL, (void **)&pmw,
			       NULL, NULL, silc_hash_id_compare_full,
			       SILC_32_TO_PTR(SILC_ID_CLIENT))) {
    /* Signal that message was received */
    silc_mutex_unlock(conn->internal->lock);
    silc_mutex_lock(pmw->wait_lock);
    if (!pmw->stopped) {
      silc_dlist_add(pmw->message_queue, payload);
      silc_cond_broadcast(pmw->wait_cond);
      silc_mutex_unlock(pmw->wait_lock);
      silc_packet_free(packet);
      goto out;
    }
    silc_mutex_unlock(pmw->wait_lock);
  } else
    silc_mutex_unlock(conn->internal->lock);
#endif /* 0 */

  /* Pass the private message to application */
  flags = silc_message_get_flags(payload);
  message = silc_message_get_data(payload, &message_len);
  client->internal->ops->private_message(client, conn, remote_client, payload,
					 flags, message, message_len);

  /* See if we are away (gone). If we are away we will reply to the
     sender with the set away message. */
  if (conn->internal->away && conn->internal->away->away &&
      !(flags & SILC_MESSAGE_FLAG_NOREPLY)) {
    /* If it's me, ignore */
    if (SILC_ID_CLIENT_COMPARE(&remote_id, conn->local_id))
      goto out;

    /* Send the away message */
    silc_client_send_private_message(client, conn, remote_client,
				     SILC_MESSAGE_FLAG_AUTOREPLY |
				     SILC_MESSAGE_FLAG_NOREPLY, NULL,
				     conn->internal->away->away,
				     strlen(conn->internal->away->away));
  }

 out:
  /** Packet processed */
  silc_packet_free(packet);
  silc_client_unref_client(client, conn, remote_client);
  if (payload)
    silc_message_payload_free(payload);
  SILC_FSM_FINISH;
}

/* Private message error. */

SILC_FSM_STATE(silc_client_private_message_error)
{
  SilcPacket packet = state_context;
  silc_packet_free(packet);
  SILC_FSM_FINISH;
}

#if 0 /* XXX we need to rethink this */
/* Initialize private message waiting in a thread. */

void *silc_client_private_message_wait_init(SilcClientConnection conn,
					    SilcClientEntry client_entry)
{
  SilcClientPrivateMessageWait pmw;

  pmw = silc_calloc(1, sizeof(*pmw));
  if (!pmw)
    return NULL;

  pmw->message_queue = silc_dlist_init();
  if (!pmw->message_queue) {
    silc_free(pmw);
    return NULL;
  }

  /* Allocate mutex and conditional variable */
  if (!silc_mutex_alloc(&pmw->wait_lock)) {
    silc_dlist_uninit(pmw->message_queue);
    silc_free(pmw);
    return NULL;
  }
  if (!silc_cond_alloc(&pmw->wait_cond)) {
    silc_dlist_uninit(pmw->message_queue);
    silc_mutex_free(pmw->wait_lock);
    silc_free(pmw);
    return NULL;
  }

  silc_mutex_lock(conn->internal->lock);

  /* Allocate waiting hash table */
  if (!conn->internal->privmsg_wait) {
    conn->internal->privmsg_wait =
      silc_hash_table_alloc(0, silc_hash_id,
			    SILC_32_TO_PTR(SILC_ID_CLIENT),
			    silc_hash_id_compare,
			    SILC_32_TO_PTR(SILC_ID_CLIENT), NULL, NULL, TRUE);
    if (!conn->internal->privmsg_wait) {
      silc_mutex_unlock(conn->internal->lock);
      silc_dlist_uninit(pmw->message_queue);
      silc_mutex_free(pmw->wait_lock);
      silc_cond_free(pmw->wait_cond);
      silc_free(pmw);
      return NULL;
    }
  }

  /* Add to waiting hash table */
  silc_hash_table_add(conn->internal->privmsg_wait, client_entry->id, pmw);

  silc_mutex_unlock(conn->internal->lock);

  return (void *)pmw;
}

/* Uninitialize private message waiting. */

void silc_client_private_message_wait_uninit(SilcClientConnection conn,
					     SilcClientEntry client_entry,
					     void *waiter)
{
  SilcClientPrivateMessageWait pmw = waiter;
  SilcMessagePayload payload;

  /* Signal any threads to stop waiting */
  silc_mutex_lock(pmw->wait_lock);
  pmw->stopped = TRUE;
  silc_cond_broadcast(pmw->wait_cond);
  silc_mutex_unlock(pmw->wait_lock);

  /* Re-acquire lock and free resources */
  silc_mutex_lock(pmw->wait_lock);

  /* Free any remaining message */
  silc_dlist_start(pmw->message_queue);
  while ((payload = silc_dlist_get(pmw->message_queue)))
    silc_message_payload_free(payload);

  silc_dlist_uninit(pmw->message_queue);
  silc_cond_free(pmw->wait_cond);
  silc_mutex_unlock(pmw->wait_lock);
  silc_mutex_free(pmw->wait_lock);

  silc_mutex_lock(conn->internal->lock);
  silc_hash_table_del_by_context(conn->internal->privmsg_wait,
				 client_entry->id, pmw);
  silc_mutex_unlock(conn->internal->lock);

  silc_free(pmw);
}

/* Blocks the calling process or thread until a private message has been
   received from the specified client. */

SilcBool silc_client_private_message_wait(SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  void *waiter,
					  SilcMessagePayload *payload)
{
  SilcClientPrivateMessageWait pmw = waiter;
  SilcPacket packet;

  silc_mutex_lock(pmw->wait_lock);

  /* Wait here until private message has been received */
  while (silc_dlist_count(pmw->message_queue) == 0) {
    if (pmw->stopped) {
      silc_mutex_unlock(pmw->wait_lock);
      return FALSE;
    }
    silc_cond_wait(pmw->wait_cond, pmw->wait_lock);
  }

  /* Return message */
  silc_dlist_start(pmw->message_queue);
  *payload = silc_dlist_get(pmw->message_queue);
  silc_dlist_del(pmw->message_queue, *payload);

  silc_mutex_unlock(pmw->wait_lock);

  return TRUE;
}
#endif /* 0 */

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
  SilcPacket packet = context;
  unsigned char *cipher = NULL, *hmac = NULL;
  SilcClientEntry client_entry;
  int ret;

  if (!clients) {
    silc_packet_free(packet);
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
  client_entry->internal.prv_resp = TRUE;

  /* XXX we should notify application that remote wants to set up the
     static key.  And we should tell if we already have key with remote.
     Application should return status telling whether to delete the key
     or not. */

 out:
  silc_free(cipher);
  silc_free(hmac);
  silc_packet_free(packet);
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
    SILC_FSM_FINISH;
  }

  if (!silc_id_str2id(packet->src_id, packet->src_id_len, SILC_ID_CLIENT,
		      &remote_id, sizeof(remote_id))) {
    silc_packet_free(packet);
    SILC_FSM_FINISH;
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

/* Sets away `message'.  The away message may be set when the client's
   mode is changed to SILC_UMODE_GONE and the client whishes to reply
   to anyone who sends private message.  The `message' will be sent
   automatically back to the the client who send private message.  If
   away message is already set this replaces the old message with the
   new one.  If `message' is NULL the old away message is removed.
   The sender may freely free the memory of the `message'. */

void silc_client_set_away_message(SilcClient client,
				  SilcClientConnection conn,
				  char *message)
{
  assert(client && conn);

  if (!message && conn->internal->away) {
    silc_free(conn->internal->away->away);
    silc_free(conn->internal->away);
    conn->internal->away = NULL;
  }

  if (message) {
    if (!conn->internal->away)
      conn->internal->away = silc_calloc(1, sizeof(*conn->internal->away));
    if (conn->internal->away->away)
      silc_free(conn->internal->away->away);
    conn->internal->away->away = strdup(message);
  }
}
