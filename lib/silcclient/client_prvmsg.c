/*

  client_prvmsg.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/* This file includes the private message sending and receiving routines
   and private message key handling routines. */

#include "clientlibincludes.h"
#include "client_internal.h"

/* Sends private message to remote client. If private message key has
   not been set with this client then the message will be encrypted using
   normal session keys. Private messages are special packets in SILC
   network hence we need this own function for them. This is similiar
   to silc_client_packet_send_to_channel except that we send private
   message. The `data' is the private message. If the `force_send' is
   TRUE the packet is sent immediately. */

void silc_client_send_private_message(SilcClient client,
				      SilcClientConnection conn,
				      SilcClientEntry client_entry,
				      SilcMessageFlags flags,
				      unsigned char *data, 
				      uint32 data_len, 
				      int force_send)
{
  SilcSocketConnection sock = conn->sock;
  SilcBuffer buffer;
  SilcPacketContext packetdata;
  SilcCipher cipher;
  SilcHmac hmac;

  SILC_LOG_DEBUG(("Sending private message"));

  /* Encode private message payload */
  buffer = silc_private_message_payload_encode(flags,
					       data_len, data,
					       client_entry->send_key);

  /* If we don't have private message specific key then private messages
     are just as any normal packet thus call normal packet sending.  If
     the key exist then the encryption process is a bit different and
     will be done in the rest of this function. */
  if (!client_entry->send_key) {
    silc_client_packet_send(client, sock, SILC_PACKET_PRIVATE_MESSAGE,
			    client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			    buffer->data, buffer->len, force_send);
    goto out;
  }

  /* We have private message specific key */

  /* Get data used in the encryption */
  cipher = client_entry->send_key;
  hmac = conn->hmac_send;

  /* Set the packet context pointers. */
  packetdata.flags = SILC_PACKET_FLAG_PRIVMSG_KEY;
  packetdata.type = SILC_PACKET_PRIVATE_MESSAGE;
  packetdata.src_id = conn->local_id_data;
  packetdata.src_id_len = silc_id_get_len(conn->local_id, SILC_ID_CLIENT);
  packetdata.src_id_type = SILC_ID_CLIENT;
  packetdata.dst_id = silc_id_id2str(client_entry->id, SILC_ID_CLIENT);
  packetdata.dst_id_len = silc_id_get_len(client_entry->id, SILC_ID_CLIENT);
  packetdata.dst_id_type = SILC_ID_CLIENT;
  packetdata.truelen = buffer->len + SILC_PACKET_HEADER_LEN + 
    packetdata.src_id_len + packetdata.dst_id_len;
  packetdata.padlen = SILC_PACKET_PADLEN((SILC_PACKET_HEADER_LEN +
					  packetdata.src_id_len +
					  packetdata.dst_id_len));

  /* Prepare outgoing data buffer for packet sending */
  silc_packet_send_prepare(sock, 
			   SILC_PACKET_HEADER_LEN +
			   packetdata.src_id_len + 
			   packetdata.dst_id_len,
			   packetdata.padlen,
			   buffer->len);
  
  packetdata.buffer = sock->outbuf;

  /* Put the actual encrypted message payload data into the buffer. */
  silc_buffer_put(sock->outbuf, buffer->data, buffer->len);

  /* Create the outgoing packet */
  silc_packet_assemble(&packetdata);

  /* Encrypt the header and padding of the packet. */
  cipher = conn->send_key;
  silc_packet_encrypt(cipher, hmac, sock->outbuf, SILC_PACKET_HEADER_LEN + 
		      packetdata.src_id_len + packetdata.dst_id_len +
		      packetdata.padlen);

  SILC_LOG_HEXDUMP(("Private message packet, len %d", sock->outbuf->len),
		   sock->outbuf->data, sock->outbuf->len);

  /* Now actually send the packet */
  silc_client_packet_send_real(client, sock, force_send, FALSE);
  silc_free(packetdata.dst_id);

 out:
  silc_buffer_free(buffer);
}     

static void silc_client_private_message_cb(SilcClient client,
					   SilcClientConnection conn,
					   SilcClientEntry *clients,
					   uint32 clients_count,
					   void *context)
{
  SilcPacketContext *packet = (SilcPacketContext *)context;

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
  SilcPrivateMessagePayload payload = NULL;
  SilcIDCacheEntry id_cache;
  SilcClientID *remote_id = NULL;
  SilcClientEntry remote_client;

  if (packet->src_id_type != SILC_ID_CLIENT)
    goto out;

  remote_id = silc_id_str2id(packet->src_id, packet->src_id_len, 
			     SILC_ID_CLIENT);
  if (!remote_id)
    goto out;

  /* Check whether we know this client already */
  if (!silc_idcache_find_by_id_one_ext(conn->client_cache, (void *)remote_id, 
				       NULL, NULL, 
				       silc_hash_client_id_compare, NULL,
				       &id_cache)) {
    /* Resolve the client info */
    silc_client_get_client_by_id_resolve(client, conn, remote_id,
					 silc_client_private_message_cb,
					 silc_packet_context_dup(packet));
    return;
  }

  remote_client = (SilcClientEntry)id_cache->context;

  /* Parse the payload and decrypt it also if private message key is set */
  payload = silc_private_message_payload_parse(packet->buffer,
					       remote_client->send_key);
  if (!payload) {
    silc_free(remote_id);
    return;
  }

  /* Pass the private message to application */
  client->ops->private_message(client, conn, remote_client,
			       silc_private_message_get_flags(payload),
			       silc_private_message_get_message(payload, 
								NULL));

  /* See if we are away (gone). If we are away we will reply to the
     sender with the set away message. */
  if (conn->away && conn->away->away) {
    /* If it's me, ignore */
    if (SILC_ID_CLIENT_COMPARE(remote_id, conn->local_id))
      goto out;

    /* Send the away message */
    silc_client_send_private_message(client, conn, remote_client,
				     SILC_MESSAGE_FLAG_AUTOREPLY,
				     conn->away->away,
				     strlen(conn->away->away), TRUE);
  }

 out:
  if (payload)
    silc_private_message_payload_free(payload);
  if (remote_id)
    silc_free(remote_id);
}

/* Function that actually employes the received private message key */

static void silc_client_private_message_key_cb(SilcClient client,
					       SilcClientConnection conn,
					       SilcClientEntry *clients,
					       uint32 clients_count,
					       void *context)
{
  SilcPacketContext *packet = (SilcPacketContext *)context;
  unsigned char *key;
  uint16 key_len;
  unsigned char *cipher;
  int ret;

  if (!clients)
    goto out;

  /* Parse the private message key payload */
  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI16_NSTRING(&key, &key_len),
			     SILC_STR_UI16_STRING(&cipher),
			     SILC_STR_END);
  if (!ret)
    goto out;

  if (key_len > packet->buffer->len)
    goto out;

  /* Now take the key in use */
  if (!silc_client_add_private_message_key(client, conn, clients[0],
					   cipher, key, key_len, FALSE))
    goto out;

  /* Print some info for application */
  client->ops->say(client, conn, 
		   "Received private message key from %s%s%s %s%s%s", 
		   clients[0]->nickname,
		   clients[0]->server ? "@" : "",
		   clients[0]->server ? clients[0]->server : "",
		   clients[0]->username ? "(" : "",
		   clients[0]->username ? clients[0]->username : "",
		   clients[0]->username ? ")" : "");

 out:
  silc_packet_context_free(packet);
}

/* Processes incoming Private Message Key payload. The libary always
   accepts the key and takes it into use. */

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
				       silc_client_private_message_key_cb,
				       silc_packet_context_dup(packet));
  silc_free(remote_id);
}

/* Adds private message key to the client library. The key will be used to
   encrypt all private message between the client and the remote client
   indicated by the `client_entry'. If the `key' is NULL and the boolean
   value `generate_key' is TRUE the library will generate random key.
   The `key' maybe for example pre-shared-key, passphrase or similar.
   The `cipher' MAY be provided but SHOULD be NULL to assure that the
   requirements of the SILC protocol are met. The API, however, allows
   to allocate any cipher.

   It is not necessary to set key for normal private message usage. If the
   key is not set then the private messages are encrypted using normal
   session keys. Setting the private key, however, increases the security. 

   Returns FALSE if the key is already set for the `client_entry', TRUE
   otherwise. */

int silc_client_add_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry,
					char *cipher,
					unsigned char *key,
					uint32 key_len,
					int generate_key)
{
  unsigned char private_key[32];
  uint32 len;
  int i;
  SilcSKEKeyMaterial *keymat;

  assert(client_entry);

  /* Return FALSE if key already set */
  if (client_entry->send_key && client_entry->receive_key)
    return FALSE;

  if (!cipher)
    cipher = "aes-256-cbc";

  /* Check the requested cipher */
  if (!silc_cipher_is_supported(cipher))
    return FALSE;

  /* Generate key if not provided */
  if (generate_key == TRUE) {
    len = 32;
    for (i = 0; i < len; i++) private_key[i] = silc_rng_get_byte(client->rng);
    key = private_key;
    key_len = len;
    client_entry->generated = TRUE;
  }

  /* Save the key */
  client_entry->key = silc_calloc(key_len, sizeof(*client_entry->key));
  memcpy(client_entry->key, key, key_len);
  client_entry->key_len = key_len;

  /* Produce the key material as the protocol defines */
  keymat = silc_calloc(1, sizeof(*keymat));
  if (silc_ske_process_key_material_data(key, key_len, 16, 256, 16, 
					 client->md5hash, keymat) 
      != SILC_SKE_STATUS_OK)
    return FALSE;

  /* Allocate the ciphers */
  silc_cipher_alloc(cipher, &client_entry->send_key);
  silc_cipher_alloc(cipher, &client_entry->receive_key);

  /* Set the keys */
  silc_cipher_set_key(client_entry->send_key, keymat->send_enc_key,
		      keymat->enc_key_len);
  silc_cipher_set_iv(client_entry->send_key, keymat->send_iv);
  silc_cipher_set_key(client_entry->receive_key, keymat->receive_enc_key,
		      keymat->enc_key_len);
  silc_cipher_set_iv(client_entry->receive_key, keymat->receive_iv);

  /* Free the key material */
  silc_ske_free_key_material(keymat);

  return TRUE;
}

/* Same as above but takes the key material from the SKE key material
   structure. This structure is received if the application uses the
   silc_client_send_key_agreement to negotiate the key material. The
   `cipher' SHOULD be provided as it is negotiated also in the SKE
   protocol. */

int silc_client_add_private_message_key_ske(SilcClient client,
					    SilcClientConnection conn,
					    SilcClientEntry client_entry,
					    char *cipher,
					    SilcSKEKeyMaterial *key)
{
  assert(client_entry);

  /* Return FALSE if key already set */
  if (client_entry->send_key && client_entry->receive_key)
    return FALSE;

  if (!cipher)
    cipher = "aes-256-cbc";

  /* Check the requested cipher */
  if (!silc_cipher_is_supported(cipher))
    return FALSE;

  /* Allocate the ciphers */
  silc_cipher_alloc(cipher, &client_entry->send_key);
  silc_cipher_alloc(cipher, &client_entry->receive_key);

  /* Set the keys */
  silc_cipher_set_key(client_entry->send_key, key->send_enc_key,
		      key->enc_key_len);
  silc_cipher_set_iv(client_entry->send_key, key->send_iv);
  silc_cipher_set_key(client_entry->receive_key, key->receive_enc_key,
		      key->enc_key_len);
  silc_cipher_set_iv(client_entry->receive_key, key->receive_iv);

  return TRUE;
}

/* Sends private message key payload to the remote client indicated by
   the `client_entry'. If the `force_send' is TRUE the packet is sent
   immediately. Returns FALSE if error occurs, TRUE otherwise. The
   application should call this function after setting the key to the
   client.

   Note that the key sent using this function is sent to the remote client
   through the SILC network. The packet is protected using normal session
   keys. */

int silc_client_send_private_message_key(SilcClient client,
					 SilcClientConnection conn,
					 SilcClientEntry client_entry,
					 int force_send)
{
  SilcSocketConnection sock = conn->sock;
  SilcBuffer buffer;
  int cipher_len;

  if (!client_entry->send_key || !client_entry->key)
    return FALSE;

  SILC_LOG_DEBUG(("Sending private message key"));

  cipher_len = strlen(client_entry->send_key->cipher->name);

  /* Create private message key payload */
  buffer = silc_buffer_alloc(2 + client_entry->key_len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(client_entry->key_len),
		     SILC_STR_UI_XNSTRING(client_entry->key, 
					  client_entry->key_len),
		     SILC_STR_UI_SHORT(cipher_len),
		     SILC_STR_UI_XNSTRING(client_entry->send_key->cipher->name,
					  cipher_len),
		     SILC_STR_END);

  /* Send the packet */
  silc_client_packet_send(client, sock, SILC_PACKET_PRIVATE_MESSAGE_KEY,
			  client_entry->id, SILC_ID_CLIENT, NULL, NULL,
			  buffer->data, buffer->len, force_send);
  silc_free(buffer);

  return TRUE;
}

/* Removes the private message from the library. The key won't be used
   after this to protect the private messages with the remote `client_entry'
   client. Returns FALSE on error, TRUE otherwise. */

int silc_client_del_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry)
{
  assert(client_entry);

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
				      uint32 *key_count)
{
  SilcPrivateMessageKeys keys;
  uint32 count = 0;
  SilcIDCacheEntry id_cache;
  SilcIDCacheList list;
  SilcClientEntry entry;

  if (!silc_idcache_get_all(conn->client_cache, &list))
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
      keys[count].cipher = entry->send_key->cipher->name;
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
					   uint32 key_count)
{
  silc_free(keys);
}
