/*

  silcmessage.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

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

#include "silcincludes.h"
#include "silcmessage.h"

/******************************************************************************

                               Message Payload

******************************************************************************/

/* Calculates padding length for message payload */
#define SILC_MESSAGE_PAD(__payloadlen) (16 - ((__payloadlen) % 16))

/* Header length plus maximum padding length */
#define SILC_MESSAGE_HLEN 6 + 16

/* Returns the data length that fits to the packet.  If data length is too
   big it will be truncated to fit to the payload. */
#define SILC_MESSAGE_DATALEN(data_len, header_len)		\
  ((data_len + SILC_MESSAGE_HLEN + header_len) >		\
   SILC_PACKET_MAX_LEN ?					\
   data_len - ((data_len + SILC_MESSAGE_HLEN + header_len) -	\
	       SILC_PACKET_MAX_LEN) : data_len)

/* Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcMessagePayloadStruct {
  SilcMessageFlags flags;
  SilcUInt16 data_len;
  SilcUInt16 pad_len;
  SilcUInt16 iv_len;
  unsigned char *data;
  unsigned char *pad;
  unsigned char *iv;
  unsigned char *mac;
  /*SilcMessageSignedPayload sig;*/
};

/* Decrypts the Message Payload. The `data' is the actual Message Payload */

bool silc_message_payload_decrypt(unsigned char *data,
				  size_t data_len,
				  bool private_message,
				  bool static_key,
				  SilcCipher cipher,
				  SilcHmac hmac,
				  bool check_mac)
{
  SilcUInt32 mac_len = 0, iv_len = 0;
  unsigned char *mac, mac2[32];

  mac_len = silc_hmac_len(hmac);

  /* IV is present for channel messages and private messages when static
     key (pre-shared key) is used. */
  if (!private_message || (private_message && static_key))
    iv_len = silc_cipher_get_block_len(cipher);

  if (data_len < mac_len)
    return FALSE;

  if (check_mac) {
    /* Take the MAC */
    mac = data + (data_len - mac_len);

    /* Check the MAC of the message */
    SILC_LOG_DEBUG(("Checking message MAC"));
    silc_hmac_init(hmac);
    silc_hmac_update(hmac, data, data_len - mac_len);
    silc_hmac_final(hmac, mac2, &mac_len);
    if (memcmp(mac, mac2, mac_len)) {
      SILC_LOG_DEBUG(("Message MAC does not match"));
      return FALSE;
    }
    SILC_LOG_DEBUG(("MAC is Ok"));
  }

  /* Decrypt the message */
  silc_cipher_decrypt(cipher, data, data, data_len - iv_len - mac_len,
		      (iv_len ? data + (data_len - iv_len - mac_len) : NULL));
  return TRUE;
}

/* Parses Message Payload returning new payload structure.  This also
   decrypts it and checks the MAC. */

SilcMessagePayload 
silc_message_payload_parse(unsigned char *payload,
			   SilcUInt32 payload_len,
			   bool private_message,
			   bool static_key,
			   SilcCipher cipher,
			   SilcHmac hmac)
{
  SilcBufferStruct buffer;
  SilcMessagePayload newp;
  int ret;
  SilcUInt32 mac_len = 0, iv_len = 0;

  SILC_LOG_DEBUG(("Parsing Message Payload"));

  silc_buffer_set(&buffer, payload, payload_len);

  /* Decrypt the payload */
  if (cipher) {
    ret = silc_message_payload_decrypt(buffer.data, buffer.len,
				       private_message, static_key,
				       cipher, hmac, TRUE);
    if (ret == FALSE)
      return NULL;
  }

  if (hmac)
    mac_len = silc_hmac_len(hmac);

  /* IV is present for channel messages and private messages when static
     key (pre-shared key) is used. */
  if (cipher && (!private_message || (private_message && static_key)))
    iv_len = silc_cipher_get_block_len(cipher);

  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the Message Payload. */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&newp->flags),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->data, 
							 &newp->data_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&newp->pad, 
							 &newp->pad_len),
			     SILC_STR_UI_XNSTRING(&newp->iv, iv_len),
			     SILC_STR_UI_XNSTRING(&newp->mac, mac_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if ((newp->data_len > buffer.len - 6 - mac_len - iv_len) ||
      (newp->pad_len + newp->data_len > buffer.len - 6 - mac_len - iv_len)) {
    SILC_LOG_ERROR(("Incorrect Message Payload in packet"));
    goto err;
  }

  newp->iv_len = iv_len;

  return newp;

 err:
  silc_message_payload_free(newp);
  return NULL;
}

/* This function is used to encrypt the Messsage Payload which is
   the `data' and `data_len'.  This is used internally by the Message
   Payload encoding routines but application may call this too if needed. 
   The `data_len' is the data lenght which is used to create MAC out of. */

bool silc_message_payload_encrypt(unsigned char *data,
				  SilcUInt32 data_len,
				  unsigned char *iv,
				  SilcUInt32 iv_len,
				  SilcCipher cipher,
				  SilcHmac hmac)
{
  unsigned char mac[32];
  SilcUInt32 mac_len;
  SilcBufferStruct buf;

  /* Encrypt payload of the packet. If the IV is added to packet do
     not encrypt that. */
  silc_cipher_encrypt(cipher, data, data, data_len - iv_len,
		      iv_len ? iv : NULL);

  /* Compute the MAC of the encrypted message data */
  silc_hmac_init(hmac);
  silc_hmac_update(hmac, data, data_len);
  silc_hmac_final(hmac, mac, &mac_len);

  /* Put rest of the data to the payload */
  silc_buffer_set(&buf, data, data_len + mac_len);
  silc_buffer_pull(&buf, data_len);
  silc_buffer_put(&buf, mac, mac_len);

  return TRUE;
}

/* Encodes Message Payload into a buffer and returns it. */

SilcBuffer silc_message_payload_encode(SilcMessageFlags flags,
				       const unsigned char *data,
				       SilcUInt32 data_len,
				       bool generate_iv,
				       bool private_message,
				       SilcCipher cipher,
				       SilcHmac hmac,
				       SilcRng rng)
{
  int i;
  SilcBuffer buffer;
  SilcUInt32 len, pad_len = 0, mac_len = 0, iv_len = 0;
  unsigned char pad[16], iv[SILC_CIPHER_MAX_IV_SIZE];

  SILC_LOG_DEBUG(("Encoding Message Payload"));

  if (!data_len)
    return NULL;

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
  data_len = SILC_MESSAGE_DATALEN(data_len, mac_len + iv_len);

  /* Calculate length of padding. IV is not included into the calculation
     since it is not encrypted. */
  len = 6 + data_len;
  pad_len = SILC_MESSAGE_PAD(len);

  /* Allocate payload buffer */
  len += pad_len + iv_len + mac_len;
  buffer = silc_buffer_alloc(len);
  if (!buffer)
    return NULL;

  /* Generate padding */
  if (cipher) {
    if (rng) {
      for (i = 0; i < pad_len; i++) pad[i] = silc_rng_get_byte_fast(rng);
    } else {
      for (i = 0; i < pad_len; i++) pad[i] = silc_rng_global_get_byte_fast();
    }
  }

  /* Encode the Message Payload */
  silc_buffer_pull_tail(buffer, 6 + data_len + pad_len + iv_len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(flags),
		     SILC_STR_UI_SHORT(data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI_SHORT(pad_len),
		     SILC_STR_UI_XNSTRING(pad, pad_len),
		     SILC_STR_UI_XNSTRING(iv, iv_len),
		     SILC_STR_END);

  memset(pad, 0, sizeof(pad));

  /* Now encrypt the Message Payload */
  if (cipher) {
    if (!silc_message_payload_encrypt(buffer->data, buffer->len,
				      iv, iv_len, cipher, hmac)) {
      silc_buffer_free(buffer);
      return NULL;
    }
  }
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer) - buffer->len);

  return buffer;
}

/* Free's Message Payload */

void silc_message_payload_free(SilcMessagePayload payload)
{
  if (payload->data) {
    memset(payload->data, 0, payload->data_len);
    silc_free(payload->data);
  }
  silc_free(payload->pad);
  silc_free(payload);
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

/* Return IV. The caller knows the length of the IV */

unsigned char *silc_message_get_iv(SilcMessagePayload payload)
{
  return payload->iv;
}

/******************************************************************************

                     SILC_MESSAGE_FLAG_SIGNED Payload

******************************************************************************/

/* The SILC_MESSAGE_FLAG_SIGNED Payload */
struct SilcMessageSignedPayloadStruct {
  SilcUInt16 pk_len;
  SilcUInt16 pk_type;
  SilcUInt16 sign_len;
  unsigned char *pk_data;
  unsigned char *sign_data;
};

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

/* Parses the SILC_MESSAGE_FLAG_SIGNED Payload */

SilcMessageSignedPayload
silc_message_signed_payload_parse(const unsigned char *data,
				  SilcUInt32 data_len)
{
  SilcMessageSignedPayload sig;
  SilcBufferStruct buffer;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC_MESSAGE_FLAG_SIGNED Payload"));

  silc_buffer_set(&buffer, (unsigned char *)data, data_len);
  sig = silc_calloc(1, sizeof(*sig));
  if (!sig)
    return NULL;

  /* Parse the payload */
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&sig->pk_len),
			     SILC_STR_UI_SHORT(&sig->pk_type),
			     SILC_STR_END);
  if (ret == -1 || sig->pk_len > data_len - 4) {
    silc_message_signed_payload_free(sig);
    return NULL;
  }

  silc_buffer_pull(&buffer, 4);
  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&sig->pk_data,
							sig->pk_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&sig->sign_data,
							 &sig->sign_len),
			     SILC_STR_END);
  if (ret == -1) {
    silc_message_signed_payload_free(sig);
    return NULL;
  }
  silc_buffer_push(&buffer, 4);

  /* Signature must be provided */
  if (sig->sign_len < 1)  {
    silc_message_signed_payload_free(sig);
    return NULL;
  }

  return sig;
}

/* Encodes the SILC_MESSAGE_FLAG_SIGNED Payload and computes the digital
   signature. */

SilcBuffer
silc_message_signed_payload_encode(const unsigned char *message_payload,
				   SilcUInt32 message_payload_len,
				   SilcPublicKey public_key,
				   SilcPrivateKey private_key,
				   SilcHash hash,
				   bool include_public_key)
{
  SilcBuffer buffer, sign;
  SilcPKCS pkcs;
  unsigned char auth_data[2048];
  SilcUInt32 auth_len;
  unsigned char *pk = NULL;
  SilcUInt32 pk_len = 0;
  SilcUInt16 pk_type;

  if (!message_payload || !message_payload_len || !private_key || !hash)
    return NULL;
  if (include_public_key && !public_key)
    return NULL;

  if (include_public_key)
    pk = silc_pkcs_public_key_encode(public_key, &pk_len);

  /* Now we support only SILC style public key */
  pk_type = SILC_SKE_PK_TYPE_SILC;

  /* Encode the data to be signed */
  sign = silc_message_signed_encode_data(message_payload,
					 message_payload_len,
					 pk, pk_len, pk_type);
  if (!sign) {
    silc_free(pk);
    return NULL;
  }

  /* Sign the buffer */

  /* Allocate PKCS object */
  if (!silc_pkcs_alloc(private_key->name, &pkcs)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_free(pk);
    return NULL;
  }
  silc_pkcs_private_key_set(pkcs, private_key);

  /* Compute the hash and the signature. */
  if (silc_pkcs_get_key_len(pkcs) / 8 > sizeof(auth_data) - 1 ||
      !silc_pkcs_sign_with_hash(pkcs, hash, sign->data, sign->len, auth_data,
				&auth_len)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_pkcs_free(pkcs);
    silc_free(pk);
    return NULL;
  }

  /* Encode the SILC_MESSAGE_FLAG_SIGNED Payload */

  buffer = silc_buffer_alloc_size(4 + pk_len + 2 + auth_len);
  if (!buffer) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_pkcs_free(pkcs);
    memset(auth_data, 0, sizeof(auth_data));
    silc_free(pk);
    return NULL;
  }

  silc_buffer_format(sign,
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_SHORT(pk_type),
		     SILC_STR_END);

  if (pk_len && pk) {
    silc_buffer_pull(sign, 4);
    silc_buffer_format(sign,
		       SILC_STR_UI_XNSTRING(pk, pk_len),
		       SILC_STR_END);
    silc_buffer_push(sign, 4);
  }

  silc_buffer_pull(sign, 4 + pk_len);
  silc_buffer_format(sign,
		     SILC_STR_UI_SHORT(auth_len),
		     SILC_STR_UI_XNSTRING(auth_data, auth_len),
		     SILC_STR_END);
  silc_buffer_push(sign, 4 + pk_len);

  memset(auth_data, 0, sizeof(auth_data));
  silc_pkcs_free(pkcs);
  silc_buffer_clear(sign);
  silc_buffer_free(sign);
  silc_free(pk);

  return buffer;
}

/* Free the payload */

void silc_message_signed_payload_free(SilcMessageSignedPayload sig)
{
  if (sig) {
    memset(sig->sign_data, 0, sig->sign_len);
    silc_free(sig->sign_data);
    silc_free(sig->pk_data);
    silc_free(sig);
  }
}

/* Verify the signature in SILC_MESSAGE_FLAG_SIGNED Payload */

int silc_message_signed_verify(SilcMessageSignedPayload sig,
			       SilcMessagePayload message,
			       SilcPublicKey remote_public_key,
			       SilcHash hash)
{
  int ret = SILC_AUTH_FAILED;
  SilcBuffer sign;
  SilcPKCS pkcs;
  SilcBuffer tmp;
  
  if (!sig || !remote_public_key || !hash)
    return ret;

  /* Generate the signature verification data, the Message Payload */
  tmp = silc_buffer_alloc_size(6 + message->data_len + message->pad_len +
			       message->iv_len);
  silc_buffer_format(tmp,
		     SILC_STR_UI_SHORT(message->flags),
		     SILC_STR_UI_SHORT(message->data_len),
		     SILC_STR_UI_XNSTRING(message->data, message->data_len),
		     SILC_STR_UI_SHORT(message->pad_len),
		     SILC_STR_UI_XNSTRING(message->pad, message->pad_len),
		     SILC_STR_UI_XNSTRING(message->iv, message->iv_len),
		     SILC_STR_END);
  sign = silc_message_signed_encode_data(tmp->data, tmp->len,
					 sig->pk_data, sig->pk_len,
					 sig->pk_type);
  silc_buffer_clear(tmp);
  silc_buffer_free(tmp);
  
  if (!sign)
    return ret;
  
  /* Allocate PKCS object */
  if (!silc_pkcs_alloc(remote_public_key->name, &pkcs)) {
    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    return ret;
  }
  silc_pkcs_public_key_set(pkcs, remote_public_key);

  /* Verify the authentication data */
  if (!silc_pkcs_verify_with_hash(pkcs, hash, sig->sign_data,
				  sig->sign_len,
				  sign->data, sign->len)) {

    silc_buffer_clear(sign);
    silc_buffer_free(sign);
    silc_pkcs_free(pkcs);
    SILC_LOG_DEBUG(("Signature verification failed"));
    return ret;
  }

  ret = SILC_AUTH_OK;

  silc_buffer_clear(sign);
  silc_buffer_free(sign);
  silc_pkcs_free(pkcs);

  SILC_LOG_DEBUG(("Signature verification successful"));

  return ret;
}

/* Return the public key from the payload */

SilcPublicKey
silc_message_signed_get_public_key(SilcMessageSignedPayload sig)
{
  SilcPublicKey pk;

  if (!sig->pk_data || !silc_pkcs_public_key_decode(sig->pk_data,
						    sig->pk_len, &pk))
    return NULL;

  return pk;
}
