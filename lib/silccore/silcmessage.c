/*

  silcmessage.c

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
/* Implementation of the Message Payload used as channel messages and
   private messages. */
/* $Id$ */

#include "silc.h"
#include "silcmessage.h"

/*************************** Types and definitions **************************/

/* Calculates padding length for message payload */
#define SILC_MESSAGE_PAD(__payloadlen) (16 - ((__payloadlen) % 16))

/* Header length plus maximum padding length */
#define SILC_MESSAGE_HLEN 6 + 16

/* Maximum message length */
#define SILC_MESSAGE_MAX_LEN SILC_PACKET_MAX_LEN - SILC_MESSAGE_HLEN - 16

/* Payload encoding context */
typedef struct {
  SilcMessageFlags flags;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;
  SilcHash hash;
  SilcCipher cipher;
  SilcHmac hmac;
  unsigned char *iv;
  SilcUInt16 payload_len;
} SilcMessageEncode;


/************************* Static utility functions *************************/

/* Returns the data length that fits to the packet.  If data length is too
   big it will be truncated to fit to the payload. */

static inline
SilcUInt32 silc_message_payload_datalen(SilcUInt32 data_len,
					SilcUInt32 header_len,
					SilcUInt32 flags,
					SilcPublicKey public_key,
					SilcPrivateKey private_key)
{
  SilcUInt32 pklen = (flags & SILC_MESSAGE_FLAG_SIGNED && public_key ?
		      silc_pkcs_public_key_get_len(public_key) : 0);
  SilcUInt32 prlen = (flags & SILC_MESSAGE_FLAG_SIGNED ?
		      silc_pkcs_private_key_get_len(private_key) / 8 : 0);
  SilcUInt32 dlen = data_len + SILC_MESSAGE_HLEN + header_len + pklen + prlen;

  if (dlen > SILC_MESSAGE_MAX_LEN)
    data_len -= (dlen - SILC_MESSAGE_MAX_LEN);

  return data_len;
}

/* Free signed payload */

static void silc_message_signed_payload_free(SilcMessageSignedPayload sig)
{
  if (sig->sign_data) {
    memset(sig->sign_data, 0, sig->sign_len);
    silc_free(sig->sign_data);
  }
  silc_free(sig->pk_data);
}

/* Parses the SILC_MESSAGE_FLAG_SIGNED Payload */

static SilcBool
silc_message_signed_payload_parse(const unsigned char *data,
				  SilcUInt32 data_len,
				  SilcMessageSignedPayload sig)
{
  SilcBufferStruct buffer;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC_MESSAGE_FLAG_SIGNED Payload"));

  SILC_LOG_HEXDUMP(("sig payload"), (unsigned char *)data, data_len);

  silc_buffer_set(&buffer, (unsigned char *)data, data_len);

  /* Parse the payload */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&sig->pk_len),
			     SILC_STR_UI_SHORT(&sig->pk_type),
			     SILC_STR_END);
  if (ret == -1 || sig->pk_len > data_len - 4) {
    SILC_LOG_DEBUG(("Malformed public key in SILC_MESSAGE_FLAG_SIGNED "
		    "Payload"));
    return FALSE;
  }

  silc_buffer_pull(&buffer, 4);
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&sig->pk_data,
							sig->pk_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&sig->sign_data,
							 &sig->sign_len),
			     SILC_STR_END);
  if (ret == -1 || sig->sign_len > silc_buffer_len(&buffer) -
      sig->pk_len - 2) {
    silc_message_signed_payload_free(sig);
    SILC_LOG_DEBUG(("Malformed SILC_MESSAGE_FLAG_SIGNED Payload"));
    return FALSE;
  }
  silc_buffer_push(&buffer, 4);

  /* Signature must be provided */
  if (sig->sign_len < 1)  {
    SILC_LOG_DEBUG(("Malformed signature in SILC_MESSAGE_SIGNED_PAYLOAD "
		    "Payload"));
    silc_message_signed_payload_free(sig);
    return FALSE;
  }

  return TRUE;
}

/* Encodes the data to be signed to SILC_MESSAGE_FLAG_SIGNED Payload */

static SilcBuffer
silc_message_signed_encode_data(const unsigned char *message_payload,
				SilcUInt32 message_payload_len,
				unsigned char *pk,
				SilcUInt32 pk_len, SilcUInt32 pk_type)
{
  SilcBuffer sign;

  sign = silc_buffer_alloc_size(message_payload_len + 4 + pk_len);
  if (!sign)
    return NULL;

  silc_buffer_format(sign,
		     SILC_STR_UI_XNSTRING(message_payload,
					  message_payload_len),
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_SHORT(pk_type),
		     SILC_STR_END);

  if (pk && pk_len) {
    silc_buffer_pull(sign, message_payload_len + 4);
    silc_buffer_format(sign,
		       SILC_STR_UI_XNSTRING(pk, pk_len),
		       SILC_STR_END);
    silc_buffer_push(sign, message_payload_len + 4);
  }

  return sign;
}

/* Encodes the SILC_MESSAGE_FLAG_SIGNED Payload and computes the digital
   signature. */

static SilcBuffer
silc_message_signed_payload_encode(const unsigned char *message_payload,
				   SilcUInt32 message_payload_len,
				   SilcPublicKey public_key,
				   SilcPrivateKey private_key,
				   SilcHash hash)
{
  SilcBuffer buffer, sign;
  unsigned char auth_data[2048 + 1];
  SilcUInt32 auth_len;
  unsigned char *pk = NULL;
  SilcUInt32 pk_len = 0;
  SilcUInt16 pk_type;

  if (!message_payload || !message_payload_len || !private_key || !hash)
    return NULL;

  if (public_key) {
    pk = silc_pkcs_public_key_encode(public_key, &pk_len);
    if (!pk)
      return NULL;
  }
  pk_type = silc_pkcs_get_type(public_key);

  /* Encode the data to be signed */
  sign = silc_message_signed_encode_data(message_payload,
					 message_payload_len,
					 pk, pk_len, pk_type);
  if (!sign) {
    silc_free(pk);
    return NULL;
  }

  /* Sign the buffer */

  /* Compute the hash and the signature. */
  if (!silc_pkcs_sign(private_key, sign->data, silc_buffer_len(sign),
		      auth_data, sizeof(auth_data) - 1, &auth_len, hash)) {
    SILC_LOG_ERROR(("Could not compute signature"));
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_free(pk);
    return NULL;
  }

  /* Encode the SILC_MESSAGE_FLAG_SIGNED Payload */

  buffer = silc_buffer_alloc_size(4 + pk_len + 2 + auth_len);
  if (!buffer) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    memset(auth_data, 0, sizeof(auth_data));
    silc_free(pk);
    return NULL;
  }

  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_SHORT(pk_type),
		     SILC_STR_END);

  if (pk_len && pk) {
    silc_buffer_pull(buffer, 4);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(pk, pk_len),
		       SILC_STR_END);
    silc_buffer_push(buffer, 4);
  }

  silc_buffer_pull(buffer, 4 + pk_len);
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(auth_len),
		     SILC_STR_UI_XNSTRING(auth_data, auth_len),
		     SILC_STR_END);
  silc_buffer_push(buffer, 4 + pk_len);

  SILC_LOG_HEXDUMP(("sig payload"), buffer->data, silc_buffer_len(buffer));

  memset(auth_data, 0, sizeof(auth_data));
  silc_buffer_clear(sign);
  silc_buffer_free(sign);
  silc_free(pk);

  return buffer;
}


/***************************** Payload parsing ******************************/

/* Decrypts the Message Payload. The `data' is the actual Message Payload. */

SilcBool silc_message_payload_decrypt(unsigned char *data,
				      size_t data_len,
				      SilcBool private_message,
				      SilcBool static_key,
				      SilcCipher cipher,
				      SilcHmac hmac,
				      SilcBool check_mac)
{
  SilcUInt32 mac_len, iv_len = 0, block_len;
  SilcUInt16 len, totlen;
  unsigned char mac[32], *ivp;

  mac_len = silc_hmac_len(hmac);
  block_len = silc_cipher_get_block_len(cipher);

  /* IV is present for all channel messages, and private messages when
     static key (pre-shared key) is used. */
  if (!private_message || (private_message && static_key))
    iv_len = block_len;

  if (data_len < (mac_len + iv_len + block_len))
    return FALSE;

  if (check_mac) {
    /* Check the MAC of the message */
    SILC_LOG_DEBUG(("Checking message MAC"));
    silc_hmac_init(hmac);
    silc_hmac_update(hmac, data, data_len - mac_len);
    silc_hmac_final(hmac, mac, &mac_len);
    if (memcmp(data + (data_len - mac_len), mac, mac_len)) {
      SILC_LOG_DEBUG(("Message MAC does not match"));
      return FALSE;
    }
    SILC_LOG_DEBUG(("MAC is Ok"));
  }

  /* Decrypt first only one block to get the header and then rest of
     the data.  This is done because there might be unencrypted data at
     the end and we don't know the encrypted length yet. */

  /* Get pointer to the IV */
  ivp = (iv_len ? data + (data_len - iv_len - mac_len) :
	 silc_cipher_get_iv(cipher));

  /* Decrypt block */
  if (!silc_cipher_decrypt(cipher, data, data, block_len, ivp)) {
    SILC_ASSERT(FALSE);
    return FALSE;
  }

  /* Get the payload length and decrypt rest */
  totlen = 2;
  SILC_GET16_MSB(len, data + totlen);
  totlen += 2 + len;
  if (totlen + iv_len + mac_len + 2 > data_len)
    return FALSE;
  totlen += 2;
  if (totlen >= block_len)
    if (!silc_cipher_decrypt(cipher, data + block_len, data + block_len,
			     (totlen - block_len) + SILC_MESSAGE_PAD(totlen),
			     ivp)) {
      SILC_ASSERT(FALSE);
      return FALSE;
    }

  return TRUE;
}

/* Parses Message Payload returning new payload structure.  This also
   decrypts it and checks the MAC. */

SilcMessagePayload
silc_message_payload_parse(unsigned char *payload,
			   SilcUInt32 payload_len,
			   SilcBool private_message,
			   SilcBool static_key,
			   SilcCipher cipher,
			   SilcHmac hmac,
			   SilcStack stack,
			   SilcBool no_allocation,
			   SilcMessagePayload message)
{
  SilcBufferStruct buffer;
  SilcMessagePayload newp = NULL;
  int ret;
  SilcUInt32 mac_len = 0, iv_len = 0;

  SILC_LOG_DEBUG(("Parsing Message Payload"));

  silc_buffer_set(&buffer, payload, payload_len);

  /* Decrypt the payload */
  if (cipher) {
    ret = silc_message_payload_decrypt(buffer.data, silc_buffer_len(&buffer),
				       private_message, static_key,
				       cipher, hmac, TRUE);
    if (ret == FALSE)
      return NULL;
  }

  if (hmac)
    mac_len = silc_hmac_len(hmac);

  /* IV is present for all channel messages, and private messages when
     static key (pre-shared key) is used. */
  if (cipher && (!private_message || (private_message && static_key)))
    iv_len = silc_cipher_get_block_len(cipher);

  if (!message) {
    newp = message = silc_calloc(1, sizeof(*newp));
    if (!newp)
      return NULL;
  }
  memset(message, 0, sizeof(*message));
  message->allocated = (stack || no_allocation ? FALSE : TRUE);

  /* Parse the Message Payload. */
  if (!no_allocation)
    ret = silc_buffer_sunformat(stack, &buffer,
			  SILC_STR_UI_SHORT(&message->flags),
			  SILC_STR_UI16_NSTRING_ALLOC(&message->data,
						      &message->data_len),
			  SILC_STR_UI16_NSTRING_ALLOC(&message->pad,
						      &message->pad_len),
			  SILC_STR_END);
  else
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_SHORT(&message->flags),
			       SILC_STR_UI16_NSTRING(&message->data,
						     &message->data_len),
			       SILC_STR_UI16_NSTRING(&message->pad,
						     &message->pad_len),
			       SILC_STR_END);
  if (ret == -1)
    goto err;

  if ((message->data_len > silc_buffer_len(&buffer) - 6 - mac_len - iv_len) ||
      (message->pad_len + message->data_len > silc_buffer_len(&buffer) -
       6 - mac_len - iv_len)) {
    SILC_LOG_ERROR(("Incorrect Message Payload in packet"));
    goto err;
  }

  /* Parse Signed Message Payload if provided */
  if (message->flags & SILC_MESSAGE_FLAG_SIGNED &&
      message->data_len + message->pad_len + 6 + mac_len +
      iv_len < silc_buffer_len(&buffer)) {
    if (!silc_message_signed_payload_parse(buffer.data + 6 +
					   message->data_len +
					   message->pad_len,
					   silc_buffer_len(&buffer) -
					   iv_len - mac_len - 6 -
					   message->data_len -
					   message->pad_len,
					   &message->sig))
      goto err;
  }

  /* Parse MAC from the payload */
  if (mac_len)
    message->mac = buffer.data + (silc_buffer_len(&buffer) - mac_len);

  return newp;

 err:
  if (newp)
    silc_message_payload_free(newp);
  return NULL;
}


/***************************** Payload encoding *****************************/

/* This function is used to encrypt the Messsage Payload which is
   the `data' and `data_len'.  This is used internally by the Message
   Payload encoding routines but application may call this too if needed.
   The `true_len' is the data length which is used to create MAC out of. */

SilcBool silc_message_payload_encrypt(unsigned char *data,
				      SilcUInt32 data_len,
				      SilcUInt32 true_len,
				      unsigned char *iv,
				      SilcCipher cipher,
				      SilcHmac hmac)
{
  /* Encrypt payload of the packet */
  if (!silc_cipher_encrypt(cipher, data, data, data_len, iv))
    return FALSE;

  /* Compute the MAC of the encrypted message data */
  silc_hmac_init(hmac);
  silc_hmac_update(hmac, data, true_len);
  silc_hmac_final(hmac, data + true_len, NULL);

  return TRUE;
}

/* Encrypt message payload */

static int silc_message_payload_encode_encrypt(SilcBuffer buffer,
					       void *value, void *context)
{
  SilcMessageEncode *e = context;
  SilcUInt32 mac_len;

  if (!e->cipher || !e->hmac)
    return 0;

  mac_len = silc_hmac_len(e->hmac);
  if (!silc_buffer_enlarge(buffer, mac_len))
    return -1;

  if (!silc_message_payload_encrypt(buffer->head,
				    e->payload_len,
				    silc_buffer_headlen(buffer),
				    e->iv, e->cipher, e->hmac))
    return -1;

  return mac_len;
}

/* Compute message signature */

static int silc_message_payload_encode_sig(SilcBuffer buffer,
					   void *value, void *context)
{
  SilcMessageEncode *e = context;
  SilcBuffer sig;
  int len;

  if (!(e->flags & SILC_MESSAGE_FLAG_SIGNED))
    return 0;

  sig = silc_message_signed_payload_encode(buffer->head,
					   silc_buffer_headlen(buffer),
					   e->public_key, e->private_key,
					   e->hash);
  if (!sig)
    return -1;

  len = silc_buffer_format(buffer,
			   SILC_STR_DATA(silc_buffer_data(sig),
					 silc_buffer_len(sig)),
			   SILC_STR_END);
  if (len < 0) {
    silc_buffer_free(sig);
    return -1;
  }

  silc_buffer_free(sig);
  return len;
}

/* Encodes Message Payload into a buffer and returns it. */

SilcBuffer silc_message_payload_encode(SilcMessageFlags flags,
				       const unsigned char *data,
				       SilcUInt32 data_len,
				       SilcBool generate_iv,
				       SilcBool private_message,
				       SilcCipher cipher,
				       SilcHmac hmac,
				       SilcRng rng,
				       SilcPublicKey public_key,
				       SilcPrivateKey private_key,
				       SilcHash hash,
				       SilcBuffer buffer)
{
  SilcUInt32 pad_len = 0, mac_len = 0, iv_len = 0;
  unsigned char pad[16], iv[SILC_CIPHER_MAX_IV_SIZE];
  SilcBuffer buf = NULL;
  SilcMessageEncode e;
  int i;

  SILC_LOG_DEBUG(("Encoding Message Payload"));

  if (!data_len)
    return NULL;
  if (!private_message && (!cipher || !hmac))
    return NULL;

  if (!buffer) {
    buf = buffer = silc_buffer_alloc(0);
    if (!buf)
      return NULL;
  }
  silc_buffer_reset(buffer);

  /* For channel messages IV is always generated */
  if (!private_message && !generate_iv)
    generate_iv = TRUE;

  /* Generate IV */
  if (cipher && generate_iv) {
    iv_len = silc_cipher_get_block_len(cipher);
    if (rng) {
      for (i = 0; i < iv_len; i++) iv[i] = silc_rng_get_byte_fast(rng);
    } else {
      for (i = 0; i < iv_len; i++) iv[i] = silc_rng_global_get_byte_fast();
    }
  }

  if (hmac)
    mac_len = silc_hmac_len(hmac);
  data_len = silc_message_payload_datalen(data_len, mac_len + iv_len, flags,
					  public_key, private_key);

  /* Calculate length of padding. IV is not included into the calculation
     since it is not encrypted. */
  pad_len = SILC_MESSAGE_PAD(6 + data_len);

  /* Generate padding */
  if (cipher) {
    if (rng) {
      for (i = 0; i < pad_len; i++) pad[i] = silc_rng_get_byte_fast(rng);
    } else {
      for (i = 0; i < pad_len; i++) pad[i] = silc_rng_global_get_byte_fast();
    }
  }

  e.flags = flags;
  e.public_key = public_key;
  e.private_key = private_key;
  e.hash = hash;
  e.cipher = cipher;
  e.hmac = hmac;
  e.iv = iv_len ? iv : NULL;
  e.payload_len = 6 + data_len + pad_len;

  /* Encode the Message Payload */
  if (silc_buffer_format(buffer,
			 SILC_STR_UI_SHORT(flags),
			 SILC_STR_UI_SHORT(data_len),
			 SILC_STR_DATA(data, data_len),
			 SILC_STR_UI_SHORT(pad_len),
			 SILC_STR_DATA(pad, pad_len),
			 SILC_STR_FUNC(silc_message_payload_encode_sig,
				       NULL, &e),
			 SILC_STR_DATA(iv, iv_len),
			 SILC_STR_FUNC(silc_message_payload_encode_encrypt,
				       NULL, &e),
			 SILC_STR_END) < 0) {
    silc_buffer_free(buf);
    return NULL;
  }

  return buffer;
}

/* Free's Message Payload */

void silc_message_payload_free(SilcMessagePayload payload)
{
  if (payload->data) {
    memset(payload->data, 0, payload->data_len);
    if (payload->allocated)
      silc_free(payload->data);
  }
  if (payload->allocated) {
    silc_free(payload->pad);
    silc_free(payload);
  }
  silc_message_signed_payload_free(&payload->sig);
}

/* Return flags */

SilcMessageFlags silc_message_get_flags(SilcMessagePayload payload)
{
  return payload->flags;
}

/* Return data */

unsigned char *silc_message_get_data(SilcMessagePayload payload,
				     SilcUInt32 *data_len)
{
  if (data_len)
    *data_len = payload->data_len;
  return payload->data;
}

/* Return MAC. The caller knows the length of the MAC */

unsigned char *silc_message_get_mac(SilcMessagePayload payload)
{
  return payload->mac;
}

/* Verify the signature in SILC_MESSAGE_FLAG_SIGNED Payload */

SilcAuthResult silc_message_signed_verify(SilcMessagePayload message,
					  SilcPublicKey remote_public_key,
					  SilcHash hash)
{
  int ret = SILC_AUTH_FAILED;
  SilcBuffer sign, tmp;
  SilcMessageSignedPayload sig = &message->sig;

  if (!(message->flags & SILC_MESSAGE_FLAG_SIGNED) ||
      !sig->sign_len || !remote_public_key || !hash)
    return ret;

  /* Generate the signature verification data, the Message Payload */
  tmp = silc_buffer_alloc_size(6 + message->data_len + message->pad_len);
  silc_buffer_format(tmp,
		     SILC_STR_UI_SHORT(message->flags),
		     SILC_STR_UI_SHORT(message->data_len),
		     SILC_STR_UI_XNSTRING(message->data, message->data_len),
		     SILC_STR_UI_SHORT(message->pad_len),
		     SILC_STR_UI_XNSTRING(message->pad, message->pad_len),
		     SILC_STR_END);
  sign = silc_message_signed_encode_data(tmp->data, silc_buffer_len(tmp),
					 sig->pk_data, sig->pk_len,
					 sig->pk_type);
  silc_buffer_clear(tmp);
  silc_buffer_free(tmp);

  if (!sign)
    return ret;

  /* Verify the authentication data */
  if (!silc_pkcs_verify(remote_public_key, sig->sign_data, sig->sign_len,
			silc_buffer_data(sign), silc_buffer_len(sign), hash)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    SILC_LOG_DEBUG(("Signature verification failed"));
    return ret;
  }

  ret = SILC_AUTH_OK;

  silc_buffer_clear(sign);
  silc_buffer_free(sign);

  SILC_LOG_DEBUG(("Signature verification successful"));

  return ret;
}

/* Return the public key from the payload */

SilcPublicKey
silc_message_signed_get_public_key(SilcMessagePayload payload,
				   const unsigned char **pk_data,
				   SilcUInt32 *pk_data_len)
{
  SilcPublicKey pk;
  SilcMessageSignedPayload sig = &payload->sig;

  if (!sig->pk_data)
    return NULL;

  if (!silc_pkcs_public_key_alloc(sig->pk_type, sig->pk_data,
				  sig->pk_len, &pk))
    return NULL;

  if (pk_data)
    *pk_data = sig->pk_data;
  if (pk_data_len)
    *pk_data_len = sig->pk_len;

  return pk;
}
