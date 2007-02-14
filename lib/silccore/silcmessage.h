/*

  silcmessage.h

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

/****h* silccore/SILC Message Interface
 *
 * DESCRIPTION
 *
 * This interface includes the implementation of the Message Payload that
 * is used to send private messages and channel messages.  The interface
 * is also able to automatically provide digital signature in the messages
 * if it is requested.  Message digital signatures may also be verified with
 * this interface.
 *
 ***/

#ifndef SILCMESSAGE_H
#define SILCMESSAGE_H

/****s* silccore/SilcMessageAPI/SilcMessagePayload
 *
 * NAME
 *
 *    typedef struct SilcMessagePayloadObject
 *      *SilcMessagePayload, SilcMessagePayloadStruct;
 *
 *
 * DESCRIPTION
 *
 *    This context is the actual Message Payload and is allocated
 *    by silc_message_payload_parse and given as argument usually
 *    to all silc_message_* functions.  It is freed by the
 *    silc_message_payload_free function.
 *
 ***/
typedef struct SilcMessagePayloadObject
  *SilcMessagePayload, SilcMessagePayloadStruct;

/****d* silccore/SilcMessageAPI/SilcMessageFlags
 *
 * NAME
 *
 *    typedef SilcUInt16 SilcMessageFlags;
 *
 * DESCRIPTION
 *
 *    The message flags type definition and the message flags.  The
 *    message flags are used to indicate some status of the message.
 *
 * SOURCE
 */
typedef SilcUInt16 SilcMessageFlags;

/* The message flags */
#define SILC_MESSAGE_FLAG_NONE        0x0000      /* No flags */
#define SILC_MESSAGE_FLAG_AUTOREPLY   0x0001	  /* Automatically replied */
#define SILC_MESSAGE_FLAG_NOREPLY     0x0002	  /* Send no reply to this */
#define SILC_MESSAGE_FLAG_ACTION      0x0004	  /* Action message */
#define SILC_MESSAGE_FLAG_NOTICE      0x0008	  /* Notice message */
#define SILC_MESSAGE_FLAG_REQUEST     0x0010	  /* A request */
#define SILC_MESSAGE_FLAG_SIGNED      0x0020	  /* Message is signed */
#define SILC_MESSAGE_FLAG_REPLY       0x0040	  /* A reply */
#define SILC_MESSAGE_FLAG_DATA        0x0080	  /* MIME object */
#define SILC_MESSAGE_FLAG_UTF8        0x0100	  /* UTF-8 string */
#define SILC_MESSAGE_FLAG_ACK         0x0200	  /* ACK messages */
#define SILC_MESSAGE_FLAG_STOP        0x0400      /* Stop indication */
#define SILC_MESSAGE_FLAG_RESERVED    0x0800      /* to 0x1000 */
#define SILC_MESSAGE_FLAG_PRIVATE     0x2000	  /* to 0x8000 */
/***/

/****f* silccore/SilcMessageAPI/silc_message_payload_decrypt
 *
 * SYNOPSIS
 *
 *    SilcBool silc_message_payload_decrypt(unsigned char *data,
 *                                          size_t data_len,
 *                                          SilcBool private_message,
 *                                          SilcBool static_key,
 *                                          SilcCipher cipher,
 *                                          SilcHmac hmac,
 *                                          unsigned char *sender_id,
 *                                          SilcUInt32 sender_id_len,
 *                                          unsigned char *receiver_id,
 *                                          SilcUInt32 receiver_id_len,
 *                                          SilcBool check_mac);
 *
 * DESCRIPTION
 *
 *    Decrypt Message Payload indicated by `data'.  If the payload is
 *    channel message then `private_message' is FALSE, and if it is
 *    private message it is TRUE.  If the private message key is static
 *    (pre-shared key) then protocol dictates that the IV is present
 *    and `static_key' must be set to TRUE.  If the key is not static
 *    (Key Agreement was done for the key) then it MUST be FALSE.  For
 *    channel messages the `static_key' is ignored.
 *
 *    The `sender_id' and `receiver_id' are the IDs from the packet header
 *    of the packet where this message payload was received.
 *
 *    This is usually used by the Message Payload interface itself but can
 *    be called by the appliation if separate decryption process is required.
 *    For example server might need to call this directly in some
 *    circumstances. The `cipher' is used to decrypt the payload.  If
 *    `check_mac' is FALSE then MAC is not verified.
 *
 ***/
SilcBool silc_message_payload_decrypt(unsigned char *data,
				      size_t data_len,
				      SilcBool private_message,
				      SilcBool static_key,
				      SilcCipher cipher,
				      SilcHmac hmac,
				      unsigned char *sender_id,
				      SilcUInt32 sender_id_len,
				      unsigned char *receiver_id,
				      SilcUInt32 receiver_id_len,
				      SilcBool check_mac);

/****f* silccore/SilcMessageAPI/silc_message_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcMessagePayload
 *    silc_message_payload_parse(unsigned char *payload,
 *                               SilcUInt32 payload_len,
 *                               SilcBool private_message,
 *                               SilcBool static_key,
 *                               SilcCipher cipher,
 *                               SilcHmac hmac,
 *                               unsigned char *sender_id,
 *                               SilcUInt32 sender_id_len,
 *                               unsigned char *receiver_id,
 *                               SilcUInt32 receiver_id_len,
 *                               SilcStack stack,
 *                               SilcBool no_allocation,
 *                               SilcMessagePayload message);
 *
 * DESCRIPTION
 *
 *    Parses Message Payload returning new payload structure.  This also
 *    decrypts the payload and checks the MAC.  If the payload is
 *    channel message then `private_message' is FALSE, and if it is
 *    private message it is TRUE.  If the private message key is static
 *    (pre-shared key) then protocol dictates that the IV is present
 *    and `static_key' must be set to TRUE.  If the key is not static
 *    (Key Agreement was done for the key) then it MUST be FALSE.  For
 *    channel messages the `static_key' is ignored.
 *
 *    If the `hmac' is no provided then the MAC of the channel message is
 *    not verified.  If the message is private message and `cipher' is NULL
 *    then this assumes that the packet was decrypted with session keys
 *    (no private message key) and this merely decodes the payload.
 *
 *    The `sender_id' and `receiver_id' are the IDs from the packet header
 *    of the packet where this message payload was received.
 *
 *    If the `message' is non-NULL then that pre-allocated context is
 *    used in parsing.  Same context is returned.  Otherwise new context
 *    is allocated and returned.  If the `stack' is non-NULL then memory
 *    is allocated from that stack.  If `no_allocation' is TRUE then the
 *    `message' must be provided and data is merely parsed and referenced
 *    from `payload' and will become invalid when `payload' invalidates.
 *    If `no_allocation' is TRUE the routine does not do any allocations.
 *
 ***/
SilcMessagePayload
silc_message_payload_parse(unsigned char *payload,
			   SilcUInt32 payload_len,
			   SilcBool private_message,
			   SilcBool static_key,
			   SilcCipher cipher,
			   SilcHmac hmac,
			   unsigned char *sender_id,
			   SilcUInt32 sender_id_len,
			   unsigned char *receiver_id,
			   SilcUInt32 receiver_id_len,
			   SilcStack stack,
			   SilcBool no_allocation,
			   SilcMessagePayload message);

/****f* silccore/SilcMessageAPI/silc_message_payload_encrypt
 *
 * SYNOPSIS
 *
 *    SilcBool silc_message_payload_encrypt(unsigned char *data,
 *                                          SilcUInt32 data_len,
 *                                          SilcUInt32 true_len,
 *                                          unsigned char *iv,
 *                                          SilcID *sender_id,
 *                                          SilcID *receiver_id,
 *                                          SilcCipher cipher,
 *                                          SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    This function is used to encrypt the Messsage Payload which is
 *    the `data' and `data_len'.  The `data_len' is the data length which
 *    is used to create MAC out of.  The `data' MUST have additional space
 *    after `true_len' bytes for the MAC which is appended to the data.
 *    The `sender_id' is the ID message sender and `receiver_id' is ID of
 *    message receiver.
 *
 *    This is usually used by the Message Payload interface itself but can
 *    be called by the appliation if separate encryption process is required.
 *    For example server might need to call this directly in some
 *    circumstances. The `cipher' is used to encrypt the payload and `hmac'
 *    to compute the MAC for the payload.
 *
 ***/
SilcBool silc_message_payload_encrypt(unsigned char *data,
				      SilcUInt32 data_len,
				      SilcUInt32 true_len,
				      unsigned char *iv,
				      SilcID *sender_id,
				      SilcID *receiver_id,
				      SilcCipher cipher,
				      SilcHmac hmac);

/****f* silccore/SilcMessageAPI/silc_message_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_message_payload_encode(SilcMessageFlags flags,
 *                                           const unsigned char *data,
 *                                           SilcUInt32 data_len,
 *                                           SilcBool generate_iv,
 *                                           SilcBool private_message,
 *                                           SilcCipher cipher,
 *                                           SilcHmac hmac,
 *                                           SilcRng rng,
 *                                           SilcPublicKey public_key,
 *                                           SilcPrivateKey private_key,
 *                                           SilcHash hash,
 *                                           SilcID *sender_id,
 *                                           SilcID *receiver_id,
 *                                           SilcBuffer buffer);
 *
 * DESCRIPTION
 *
 *    Encodes a Message Payload into a buffer and returns it.  This is
 *    used to encode channel messages and private messages into a packet.
 *    If `private_message' is FALSE then this encodes channel message, if
 *    it is TRUE this encodes private message.  If `private_message' is
 *    TRUE then `generate_iv' MUST be FALSE if the private message key
 *    `cipher' is not static key (pre-shared key).  If it is static key
 *    then protocol dictates that IV must be present in the Message Payload
 *    and `generate_iv' must be TRUE.  The caller must know whether the key
 *    is static or not for private messages.  If the key was generated with
 *    Key Agreement protocol then `generate_iv' is always FALSE.  For
 *    channel messages `generate_iv' is always set to TRUE value.
 *
 *    The `cipher' is the cipher used to encrypt the message and `hmac'
 *    is used to compute the MAC for the payload.  If encoding private
 *    message that will be encrypted with session keys (no private message
 *    key) then `cipher' and `hmac' is NULL and this merely encodes the
 *    payload buffer, and the caller must encrypt the packet later.
 *    If `rng' is NULL then global RNG is used, if non-NULL then the
 *    `rng' is used (for IV and padding generation).
 *
 *    The `public_key', `private_key' and `hash' are provided only if the
 *    flags includes SILC_MESSAGE_FLAG_SIGNED, in which case the message
 *    will be digitally signed.  If `public_key' is non-NULL then it will
 *    be included in the message.  The `private_message' and `hash' MUST
 *    be provided.  The `hash' SHOULD be SHA1.
 *
 *    The `sender_id' is the ID message sender and `receiver_id' is ID of
 *    message receiver.
 *
 *    If the `buffer' is non-NULL then the payload will be encoded into
 *    that buffer.  The same buffer is returned.  Otherwise new buffer is
 *    allocated and returned.  The `buffer' will be automatically enlarged
 *    if the payload does not fit to it.
 *
 ***/
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
				       SilcID *sender_id,
				       SilcID *receiver_id,
				       SilcBuffer buffer);

/****f* silccore/SilcMessageAPI/silc_message_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_message_payload_free(SilcMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Free's Message Payload and all data in it.
 *
 ***/
void silc_message_payload_free(SilcMessagePayload payload);

/****f* silccore/SilcMessageAPI/silc_message_get_flags
 *
 * SYNOPSIS
 *
 *    SilcMessageFlags silc_message_get_flags(SilcMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the message flags from the payload.
 *
 ***/
SilcMessageFlags silc_message_get_flags(SilcMessagePayload payload);

/****f* silccore/SilcMessageAPI/silc_message_get_data
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_message_get_data(SilcMessagePayload payload,
 *                                  SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Return the data in the payload, that is, the actual message data.
 *    The caller must not free it.
 *
 ***/
unsigned char *silc_message_get_data(SilcMessagePayload payload,
				     SilcUInt32 *data_len);

/****f* silccore/SilcMessageAPI/silc_message_get_mac
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_message_get_mac(SilcMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Return the MAC of the payload. The caller must already know the
 *    length of the MAC. The caller must not free the MAC.
 *
 ***/
unsigned char *silc_message_get_mac(SilcMessagePayload payload);

/****f* silccore/SilcMessageAPI/silc_message_signed_verify
 *
 * SYNOPSIS
 *
 *    SilcAuthResult
 *    silc_message_signed_verify(SilcMessagePayload message,
 *                               SilcPublicKey remote_public_key,
 *                               SilcHash hash);
 *
 * DESCRIPTION
 *
 *    This routine can be used to verify the digital signature from the
 *    message indicated by `message'.  The signature is present only if
 *    the SILC_MESSAGE_FLAG_SIGNED is set in the message flags.  This
 *    returns SILC_AUTH_OK if the signature verification was successful.
 *
 ***/
SilcAuthResult silc_message_signed_verify(SilcMessagePayload message,
					  SilcPublicKey remote_public_key,
					  SilcHash hash);

/****f* silccore/SilcMessageAPI/silc_message_signed_get_public_key
 *
 * SYNOPSIS
 *
 *    SilcPublicKey
 *    silc_message_signed_get_public_key(SilcMessagePayload payload,
 *                                       const unsigned char **pk_data,
 *                                       SilcUInt32 *pk_data_len);
 *
 * DESCRIPTION
 *
 *    Returns the decoded SilcPublicKey from the message payload or NULL
 *    if it does not include public key.  The caller must free the returned
 *    public key pointer.  This also returns the raw public key (before
 *    decoding) into `pk_data' and `pk_data_len' if they are provided.  The
 *    caller must not free these pointers.
 *
 ***/
SilcPublicKey
silc_message_signed_get_public_key(SilcMessagePayload payload,
				   const unsigned char **pk_data,
				   SilcUInt32 *pk_data_len);

#include "silcmessage_i.h"

#endif /* SILCMESSAGE_H */
