/*

  client_prvmsg.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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

  sid.type = SILC_ID_CLIENT;
  sid.u.client_id = conn->local_entry->id;
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
		    !remote_client->internal.hmac_receive))
    goto out;

  /* Parse the payload and decrypt it also if private message key is set */
  payload =
    silc_message_payload_parse(silc_buffer_datalen(&packet->buffer),
			       TRUE, !remote_client->internal.generated,
			       remote_client->internal.receive_key,
			       remote_client->internal.hmac_receive,
			       packet->src_id, packet->src_id_len,
			       packet->dst_id, packet->dst_id_len,
			       NULL, FALSE, NULL);
  if (silc_unlikely(!payload))
    goto out;

  /* Pass the private message to application */
  flags = silc_message_get_flags(payload);
  message = silc_message_get_data(payload, &message_len);
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
					       SilcClientConnection conn)
{
  if (conn->internal->prv_waiter)
    return TRUE;

  conn->internal->prv_waiter =
    silc_packet_wait_init(conn->stream, SILC_PACKET_PRIVATE_MESSAGE, -1);
  if (!conn->internal->prv_waiter)
    return FALSE;

  return TRUE;
}

/* Uninitializes private message waiter. */

void silc_client_private_message_wait_uninit(SilcClient client,
					     SilcClientConnection conn)
{
  if (!conn->internal->prv_waiter)
    return;
  silc_packet_wait_uninit(conn->internal->prv_waiter, conn->stream);
  conn->internal->prv_waiter = NULL;
}

/* Blocks the calling process or thread until private message has been
   received from the specified client. */

SilcBool silc_client_private_message_wait(SilcClient client,
					  SilcClientConnection conn,
					  SilcClientEntry client_entry,
					  SilcMessagePayload *payload)
{
  SilcPacket packet;
  SilcClientID remote_id;
  SilcFSMThread thread;

  if (!conn->internal->prv_waiter)
    return FALSE;

  /* Block until private message arrives */
  do {
    if ((silc_packet_wait(conn->internal->prv_waiter, 0, &packet)) < 0)
      return FALSE;

    /* Parse sender ID */
    if (!silc_id_str2id(packet->src_id, packet->src_id_len,
			SILC_ID_CLIENT, &remote_id,
			sizeof(remote_id))) {
      silc_packet_free(packet);
      continue;
    }

    /* If the private message is not for the requested client, pass it to
       normal private message processing. */
    if (!SILC_ID_CLIENT_COMPARE(&remote_id, &client_entry->id)) {
      thread = silc_fsm_thread_alloc(&conn->internal->fsm, conn,
				     silc_client_fsm_destructor, NULL, FALSE);
      if (!thread) {
	silc_packet_free(packet);
	continue;
      }

      /* The packet will be processed in the connection thread, after this
	 FSM thread is started. */
      silc_fsm_set_state_context(thread, packet);
      silc_fsm_start(thread, silc_client_private_message);
      continue;
    }

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
