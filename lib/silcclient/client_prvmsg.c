/*

  client_prvmsg.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2004 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/* This file includes the private message sending and receiving routines
   and private message key handling routines. */

#include "silcincludes.h"
#include "silcclient.h"
#include "client_internal.h"

/* Sends private message to remote client. If private message key has
   not been set with this client then the message will be encrypted using
   normal session keys. Private messages are special packets in SILC
   network hence we need this own function for them. This is similiar
   to silc_client_packet_send_to_channel except that we send private
   message. The `data' is the private message. If the `force_send' is
   TRUE the packet is sent immediately. */

SilcBool silc_client_send_private_message(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry,
				      SilcMessageFlags flags,
				      unsigned char *data,
				      SilcUInt32 data_len,
				      SilcBool force_send)
{
  SilcSocketConnection sock;
  SilcBuffer buffer;
  SilcPacketContext packetdata;
  const SilcBufferStruct packet;
  SilcCipher cipher;
  SilcHmac hmac;
  int block_len;
  SilcBool ret = FALSE;

  assert(client && conn && client_entry);
  sock = conn->sock;
  SILC_LOG_DEBUG(("Sending private message"));

  /* Encode private message payload */
  buffer = silc_message_payload_encode(flags, data, data_len,
				       !client_entry->send_key ? FALSE :
				       !client_entry->generated,
				       TRUE, client_entry->send_key,
				       client_entry->hmac_send,
				       client->rng, NULL, client->private_key,
				       client->sha1hash);
  if (!buffer) {
    SILC_LOG_ERROR(("Error encoding private message"));
    return FALSE;
  }

  /* If we don't have private message specific key then private messages
     are just as any normal packet thus call normal packet sending.  If
     the key exist then the encryption process is a bit different and
     will be done in the rest of this function. */
  if (!client_entry->send_key) {
    silc_client_packet_send(client, sock, SILC_PACKET_PRIVATE_MESSAGE,
			    client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			    buffer->data, buffer->len, force_send);
    ret = TRUE;
    goto out;
  }

  /* We have private message specific key */

  /* Get data used in the encryption */
  cipher = conn->internal->send_key;
  hmac = conn->internal->hmac_send;
  block_len = silc_cipher_get_block_len(cipher);

  /* Set the packet context pointers. */
  data = buffer->data;
  data_len = buffer->len;
  packetdata.flags = SILC_PACKET_FLAG_PRIVMSG_KEY;
  packetdata.type = SILC_PACKET_PRIVATE_MESSAGE;
  packetdata.src_id = conn->local_id_data;
  packetdata.src_id_len = silc_id_get_len(conn->local_id, SILC_ID_CLIENT);
  packetdata.src_id_type = SILC_ID_CLIENT;
  packetdata.dst_id = silc_id_id2str(client_entry->id, SILC_ID_CLIENT);
  packetdata.dst_id_len = silc_id_get_len(client_entry->id, SILC_ID_CLIENT);
  packetdata.dst_id_type = SILC_ID_CLIENT;
  data_len = SILC_PACKET_DATALEN(data_len, SILC_PACKET_HEADER_LEN +
				 packetdata.src_id_len +
				 packetdata.dst_id_len);
  packetdata.truelen = data_len + SILC_PACKET_HEADER_LEN +
    packetdata.src_id_len + packetdata.dst_id_len;
  SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
		      packetdata.src_id_len +
		      packetdata.dst_id_len), block_len, packetdata.padlen);

  /* Create the outgoing packet */
  if (!silc_packet_assemble(&packetdata, client->rng, cipher, hmac, sock,
                            data, data_len, (const SilcBuffer)&packet)) {
    SILC_LOG_ERROR(("Error assembling packet"));
    goto out;
  }

  /* Encrypt the header and padding of the packet. */
  silc_packet_encrypt(cipher, hmac, conn->internal->psn_send++,
		      (SilcBuffer)&packet, SILC_PACKET_HEADER_LEN +
		      packetdata.src_id_len + packetdata.dst_id_len +
		      packetdata.padlen);

  SILC_LOG_HEXDUMP(("Private message packet, len %d", packet.len),
		   packet.data, packet.len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send);

  /* Check for mandatory rekey */
  if (conn->internal->psn_send == SILC_CLIENT_REKEY_THRESHOLD)
    silc_schedule_task_add(client->schedule, sock->sock,
			   silc_client_rekey_callback, sock, 0, 1,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  silc_free(packetdata.dst_id);

  ret = TRUE;

 out:
  silc_buffer_free(buffer);

  return ret;
}

static void silc_client_private_message_cb(SilcClient client,
					   SilcClientConnection conn,
					   SilcClientEntry *clients,
					   SilcUInt32 clients_count,
					   void *context)
{
  SilcPacketContext *packet = (SilcPacketContext *)context;

  if (!clients) {
    silc_packet_context_free(packet);
    return;
  }

  silc_client_private_message(client, conn->sock, packet);
  silc_packet_context_free(packet);
}

/* Private message received. This processes the private message and
   finally displays it on the screen. */

void silc_client_private_message(SilcClient client,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcMessagePayload payload = NULL;
  SilcClientID *remote_id = NULL;
  SilcClientEntry remote_client;
  SilcMessageFlags flags;
  unsigned char *message;
  SilcUInt32 message_len;
  SilcCipher cipher = NULL;
  SilcHmac hmac = NULL;

  if (packet->src_id_type != SILC_ID_CLIENT)
    goto out;

  remote_id = silc_id_str2id(packet->src_id, packet->src_id_len,
			     SILC_ID_CLIENT);
  if (!remote_id)
    goto out;

  /* Check whether we know this client already */
  remote_client = silc_client_get_client_by_id(client, conn, remote_id);
  if (!remote_client || !remote_client->nickname) {
    if (remote_client) {
      if (remote_client->status & SILC_CLIENT_STATUS_RESOLVING) {
	remote_client->status &= ~SILC_CLIENT_STATUS_RESOLVING;
	goto out;
      }
      remote_client->status |= SILC_CLIENT_STATUS_RESOLVING;
      remote_client->resolve_cmd_ident = conn->cmd_ident + 1;
    }

    /* Resolve the client info */
    silc_client_get_client_by_id_resolve(client, conn, remote_id, NULL,
					 silc_client_private_message_cb,
					 silc_packet_context_dup(packet));
    return;
  }

  cipher = remote_client->receive_key;
  hmac = remote_client->hmac_receive;
  if (packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY && !cipher && !hmac) {
    silc_free(remote_id);
    return;
  }

  /* Parse the payload and decrypt it also if private message key is set */
  payload = silc_message_payload_parse(packet->buffer->data,
				       packet->buffer->len, TRUE,
				       !remote_client->generated,
				       cipher, hmac);
  if (!payload) {
    silc_free(remote_id);
    return;
  }

  flags = silc_message_get_flags(payload);

  /* Pass the private message to application */
  message = silc_message_get_data(payload, &message_len);
  client->internal->ops->private_message(client, conn, remote_client, payload,
					 flags, message, message_len);

  /* See if we are away (gone). If we are away we will reply to the
     sender with the set away message. */
  if (conn->internal->away && conn->internal->away->away &&
      !(flags & SILC_MESSAGE_FLAG_NOREPLY)) {
    /* If it's me, ignore */
    if (SILC_ID_CLIENT_COMPARE(remote_id, conn->local_id))
      goto out;

    /* Send the away message */
    silc_client_send_private_message(client, conn, remote_client,
				     SILC_MESSAGE_FLAG_AUTOREPLY |
				     SILC_MESSAGE_FLAG_NOREPLY,
				     conn->internal->away->away,
				     strlen(conn->internal->away->away), TRUE);
  }

 out:
  if (payload)
    silc_message_payload_free(payload);
  silc_free(remote_id);
}

/* Function that actually employes the received private message key */

static void silc_client_private_message_key_cb(SilcClient client,
					       SilcClientConnection conn,
					       SilcClientEntry *clients,
					       SilcUInt32 clients_count,
					       void *context)
{
  SilcPacketContext *packet = (SilcPacketContext *)context;
  unsigned char *key;
  SilcUInt16 key_len;
  unsigned char *cipher = NULL, *hmac = NULL;
  int ret;

  if (!clients)
    goto out;

  /* Parse the private message key payload */
  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI16_NSTRING(&key, &key_len),
			     SILC_STR_UI16_STRING_ALLOC(&cipher),
			     SILC_STR_UI16_STRING_ALLOC(&hmac),
			     SILC_STR_END);
  if (!ret)
    goto out;

  if (key_len > packet->buffer->len)
    goto out;

  /* Mark that we are responder */
  clients[0]->prv_resp = TRUE;

 out:
  silc_free(cipher);
  silc_free(hmac);
  silc_packet_context_free(packet);
}

/* Processes incoming Private Message Key payload to indicate that the
   sender whishes to set up a static private message key. */

void silc_client_private_message_key(SilcClient client,
				     SilcSocketConnection sock,
				     SilcPacketContext *packet)
{
  SilcClientID *remote_id;

  if (packet->src_id_type != SILC_ID_CLIENT)
    return;

  remote_id = silc_id_str2id(packet->src_id, packet->src_id_len,
			     SILC_ID_CLIENT);
  if (!remote_id)
    return;

  silc_client_get_client_by_id_resolve(client, sock->user_data, remote_id,
				       NULL,
				       silc_client_private_message_key_cb,
				       silc_packet_context_dup(packet));
  silc_free(remote_id);
}

/* Adds private message key to the client library. The key will be used to
   encrypt all private message between the client and the remote client
   indicated by the `client_entry'. If the `key' is NULL and the boolean
   value `generate_key' is TRUE the library will generate random key.
   The `key' maybe for example pre-shared-key, passphrase or similar.
   The `cipher' and `hmac' MAY be provided but SHOULD be NULL to assure
   that the requirements of the SILC protocol are met. The API, however,
   allows to allocate any cipher and HMAC.

   If `responder' is TRUE then the sending and receiving keys will be
   set according the client being the receiver of the private key.  If
   FALSE the client is being the sender (or negotiator) of the private
   key.

   It is not necessary to set key for normal private message usage. If the
   key is not set then the private messages are encrypted using normal
   session keys. Setting the private key, however, increases the security.

   Returns FALSE if the key is already set for the `client_entry', TRUE
   otherwise. */

SilcBool silc_client_add_private_message_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 const char *cipher,
					 const char *hmac,
					 unsigned char *key,
					 SilcUInt32 key_len,
					 SilcBool generate_key,
					 SilcBool responder)
{
  unsigned char private_key[32];
  SilcUInt32 len;
  int i;
  SilcSKEKeyMaterial *keymat;

  assert(client && client_entry);

  /* Return FALSE if key already set */
  if (client_entry->send_key && client_entry->receive_key)
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

  /* Generate key if not provided */
  if (generate_key == TRUE) {
    len = 32;
    for (i = 0; i < len; i++)
      private_key[i] = silc_rng_get_byte_fast(client->rng);
    key = private_key;
    key_len = len;
    client_entry->generated = TRUE;
  }

  /* Save the key */
  client_entry->key = silc_memdup(key, key_len);
  client_entry->key_len = key_len;

  /* Produce the key material as the protocol defines */
  keymat = silc_calloc(1, sizeof(*keymat));
  if (silc_ske_process_key_material_data(key, key_len, 16, 256, 16,
					 client->sha1hash, keymat)
      != SILC_SKE_STATUS_OK)
    return FALSE;

  /* Allocate the cipher and HMAC */
  silc_cipher_alloc(cipher, &client_entry->send_key);
  silc_cipher_alloc(cipher, &client_entry->receive_key);
  silc_hmac_alloc(hmac, NULL, &client_entry->hmac_send);
  silc_hmac_alloc(hmac, NULL, &client_entry->hmac_receive);

  /* Set the keys */
  if (responder == TRUE) {
    silc_cipher_set_key(client_entry->send_key, keymat->receive_enc_key,
			keymat->enc_key_len);
    silc_cipher_set_iv(client_entry->send_key, keymat->receive_iv);
    silc_cipher_set_key(client_entry->receive_key, keymat->send_enc_key,
			keymat->enc_key_len);
    silc_cipher_set_iv(client_entry->receive_key, keymat->send_iv);
    silc_hmac_set_key(client_entry->hmac_send, keymat->receive_hmac_key,
		      keymat->hmac_key_len);
    silc_hmac_set_key(client_entry->hmac_receive, keymat->send_hmac_key,
		      keymat->hmac_key_len);
  } else {
    silc_cipher_set_key(client_entry->send_key, keymat->send_enc_key,
			keymat->enc_key_len);
    silc_cipher_set_iv(client_entry->send_key, keymat->send_iv);
    silc_cipher_set_key(client_entry->receive_key, keymat->receive_enc_key,
			keymat->enc_key_len);
    silc_cipher_set_iv(client_entry->receive_key, keymat->receive_iv);
    silc_hmac_set_key(client_entry->hmac_send, keymat->send_hmac_key,
		      keymat->hmac_key_len);
    silc_hmac_set_key(client_entry->hmac_receive, keymat->receive_hmac_key,
		      keymat->hmac_key_len);
  }

  /* Free the key material */
  silc_ske_free_key_material(keymat);

  return TRUE;
}

/* Same as above but takes the key material from the SKE key material
   structure. This structure is received if the application uses the
   silc_client_send_key_agreement to negotiate the key material. The
   `cipher' and `hmac' SHOULD be provided as it is negotiated also in
   the SKE protocol. */

SilcBool silc_client_add_private_message_key_ske(SilcClient client,
					     SilcClientConnection conn,
					     SilcClientEntry client_entry,
					     const char *cipher,
					     const char *hmac,
					     SilcSKEKeyMaterial *key,
					     SilcBool responder)
{
  assert(client && client_entry);

  /* Return FALSE if key already set */
  if (client_entry->send_key && client_entry->receive_key)
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

  client_entry->generated = TRUE;

  /* Allocate the cipher and HMAC */
  silc_cipher_alloc(cipher, &client_entry->send_key);
  silc_cipher_alloc(cipher, &client_entry->receive_key);
  silc_hmac_alloc(hmac, NULL, &client_entry->hmac_send);
  silc_hmac_alloc(hmac, NULL, &client_entry->hmac_receive);

  /* Set the keys */
  if (responder == TRUE) {
    silc_cipher_set_key(client_entry->send_key, key->receive_enc_key,
			key->enc_key_len);
    silc_cipher_set_iv(client_entry->send_key, key->receive_iv);
    silc_cipher_set_key(client_entry->receive_key, key->send_enc_key,
			key->enc_key_len);
    silc_cipher_set_iv(client_entry->receive_key, key->send_iv);
    silc_hmac_set_key(client_entry->hmac_send, key->receive_hmac_key,
		      key->hmac_key_len);
    silc_hmac_set_key(client_entry->hmac_receive, key->send_hmac_key,
		      key->hmac_key_len);
  } else {
    silc_cipher_set_key(client_entry->send_key, key->send_enc_key,
			key->enc_key_len);
    silc_cipher_set_iv(client_entry->send_key, key->send_iv);
    silc_cipher_set_key(client_entry->receive_key, key->receive_enc_key,
			key->enc_key_len);
    silc_cipher_set_iv(client_entry->receive_key, key->receive_iv);
    silc_hmac_set_key(client_entry->hmac_send, key->send_hmac_key,
		      key->hmac_key_len);
    silc_hmac_set_key(client_entry->hmac_receive, key->receive_hmac_key,
		      key->hmac_key_len);
  }

  return TRUE;
}

/* Sends private message key indicator.  The sender of this packet is
   going to be the initiator, if and when, the users set up a static
   private message key (not Key Agreement). */

SilcBool silc_client_send_private_message_key_request(SilcClient client,
						  SilcClientConnection conn,
						  SilcClientEntry client_entry)
{
  SilcSocketConnection sock;
  SilcBuffer buffer;
  int cipher_len, hmac_len;
  const char *cipher, *hmac;

  assert(client && conn && client_entry);

  sock = conn->sock;
  if (!client_entry->send_key || !client_entry->key)
    return FALSE;

  SILC_LOG_DEBUG(("Sending private message key indicator"));

  cipher = silc_cipher_get_name(client_entry->send_key);
  cipher_len = strlen(cipher);
  hmac = silc_hmac_get_name(client_entry->hmac_send);
  hmac_len = strlen(hmac);

  /* Create private message key payload */
  buffer = silc_buffer_alloc_size(4 + cipher_len + hmac_len);
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(cipher_len),
		     SILC_STR_UI_XNSTRING(cipher,
					  cipher_len),
		     SILC_STR_UI_SHORT(hmac_len),
		     SILC_STR_UI_XNSTRING(hmac,
					  hmac_len),
		     SILC_STR_END);

  /* Send the packet */
  silc_client_packet_send(client, sock, SILC_PACKET_PRIVATE_MESSAGE_KEY,
			  client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			  buffer->data, buffer->len, TRUE);
  silc_free(buffer);

  return TRUE;
}

/* Removes the private message from the library. The key won't be used
   after this to protect the private messages with the remote `client_entry'
   client. Returns FALSE on error, TRUE otherwise. */

SilcBool silc_client_del_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry)
{
  assert(client && client_entry);

  if (!client_entry->send_key && !client_entry->receive_key)
    return FALSE;

  silc_cipher_free(client_entry->send_key);
  silc_cipher_free(client_entry->receive_key);

  if (client_entry->key) {
    memset(client_entry->key, 0, client_entry->key_len);
    silc_free(client_entry->key);
  }

  client_entry->send_key = NULL;
  client_entry->receive_key = NULL;
  client_entry->key = NULL;

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
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list;
  SilcClientEntry entry;

  assert(client && conn);

  if (!silc_idcache_get_all(conn->internal->client_cache, &list))
    return NULL;

  if (!silc_idcache_list_count(list)) {
    silc_idcache_list_free(list);
    return NULL;
  }

  keys = silc_calloc(silc_idcache_list_count(list), sizeof(*keys));

  silc_idcache_list_first(list, &id_cache);
  while (id_cache) {
    entry = (SilcClientEntry)id_cache->context;

    if (entry->send_key) {
      keys[count].client_entry = entry;
      keys[count].cipher = (char *)silc_cipher_get_name(entry->send_key);
      keys[count].key = entry->generated == FALSE ? entry->key : NULL;
      keys[count].key_len = entry->generated == FALSE ? entry->key_len : 0;
      count++;
    }

    if (!silc_idcache_list_next(list, &id_cache))
      break;
  }

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
