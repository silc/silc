/*

  silcmessage.h 

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

/****h* silccore/SILC Message Interface
 *
 * DESCRIPTION
 *
 * This interface includes the implementation of the Message Payload that
 * is used to send private messages and channel messages.
 *
 * This interface defines also the SILC_MESSAGE_FLAG_SIGNED Payload,
 * which defines how channel messages and private messages can be digitally
 * signed.  This interface provides the payload parsing, encoding, 
 * signature computing and signature verification routines.
 *
 ***/

#ifndef SILCMESSAGE_H
#define SILCMESSAGE_H

/****s* silccore/SilcMessageAPI/SilcMessagePayload
 *
 * NAME
 * 
 *    typedef struct SilcMessagePayloadStruct *SilcMessagePayload;
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
typedef struct SilcMessagePayloadStruct *SilcMessagePayload;

/****s* silccore/SilcMessageAPI/SilcMessageSignedPayload
 *
 * NAME
 * 
 *    typedef struct SilcMessageSignedPayloadStruct *SilcMessageSignedPayload;
 *
 *
 * DESCRIPTION
 *
 *    This context represents the SILC_MESSAGE_FLAG_SIGNED Payload which
 *    is used with channel messages and private messages to indicate that
 *    the message is digitally signed.  This payload may include the
 *    message sender's public key and it includes the digital signature.
 *    This payload MUST NOT be used in any other context except with
 *    channel and private message sending and reception.
 *
 ***/
typedef struct SilcMessageSignedPayloadStruct *SilcMessageSignedPayload;

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
#define SILC_MESSAGE_FLAG_RESERVED    0x0400	  /* to 0x1000 */
#define SILC_MESSAGE_FLAG_PRIVATE     0x2000	  /* to 0x8000 */
/***/

/****f* silccore/SilcMessageAPI/silc_message_payload_decrypt
 *
 * SYNOPSIS
 *
 *    bool silc_message_payload_decrypt(unsigned char *data,
 *                                      size_t data_len,
 *                                      bool private_message,
 *                                      bool static_key,
 *                                      SilcCipher cipher,
 *                                      SilcHmac hmac,
 *                                      bool check_mac);
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
 *    This is usually used by the Message Payload interface itself but can
 *    be called by the appliation if separate decryption process is required.
 *    For example server might need to call this directly in some 
 *    circumstances. The `cipher' is used to decrypt the payload.  If
 *    `check_mac' is FALSE then MAC is not verified.
 *
 ***/
bool silc_message_payload_decrypt(unsigned char *data,
				  size_t data_len,
				  bool private_message,
				  bool static_key,
				  SilcCipher cipher,
				  SilcHmac hmac,
				  bool check_mac);

/****f* silccore/SilcMessageAPI/silc_message_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcMessagePayload 
 *    silc_message_payload_parse(unsigned char *payload,
 *                               SilcUInt32 payload_len,
 *                               bool private_message,
 *                               bool static_key,
 *                               SilcCipher cipher,
 *                               SilcHmac hmac);
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
 ***/
SilcMessagePayload 
silc_message_payload_parse(unsigned char *payload,
			   SilcUInt32 payload_len,
			   bool private_message,
			   bool static_key,
			   SilcCipher cipher,
			   SilcHmac hmac);

/****f* silccore/SilcMessageAPI/silc_message_payload_encrypt
 *
 * SYNOPSIS
 *
 *    bool silc_message_payload_encrypt(unsigned char *data,
 *                                      SilcUInt32 data_len,
 *                                      SilcUInt32 true_len,
 *                                      unsigned char *iv,
 *                                      SilcUInt32 iv_len,
 *                                      SilcCipher cipher,
 *                                      SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    This function is used to encrypt the Messsage Payload which is
 *    the `data' and `data_len'.  The `data_len' is the data length which
 *    is used to create MAC out of.  The `data' MUST have additional space
 *    after `true_len' bytes for the MAC which is appended to the data.
 *
 *    This is usually used by the Message Payload interface itself but can
 *    be called by the appliation if separate encryption process is required.
 *    For example server might need to call this directly in some 
 *    circumstances. The `cipher' is used to encrypt the payload and `hmac'
 *    to compute the MAC for the payload.
 *
 ***/
bool silc_message_payload_encrypt(unsigned char *data,
				  SilcUInt32 data_len,
				  SilcUInt32 true_len,
				  unsigned char *iv,
				  SilcUInt32 iv_len,
				  SilcCipher cipher,
				  SilcHmac hmac);

/****f* silccore/SilcMessageAPI/silc_message_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_message_payload_encode(SilcMessageFlags flags,
 *                                           const unsigned char *data,
 *                                           SilcUInt32 data_len,
 *                                           bool generate_iv,
 *                                           bool private_message,
 *                                           SilcCipher cipher,
 *                                           SilcHmac hmac,
 *                                           SilcRng rng,
 *                                           SilcPublicKey public_key,
 *                                           SilcPrivateKey private_key,
 *                                           SilcHash hash);
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
 ***/
SilcBuffer silc_message_payload_encode(SilcMessageFlags flags,
				       const unsigned char *data,
				       SilcUInt32 data_len,
				       bool generate_iv,
				       bool private_message,
				       SilcCipher cipher,
				       SilcHmac hmac,
				       SilcRng rng,
				       SilcPublicKey public_key,
				       SilcPrivateKey private_key,
				       SilcHash hash);

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

/****f* silccore/SilcMessageAPI/silc_message_get_iv
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_message_get_iv(SilcMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Return the IV of the payload. The caller must already know the 
 *    length of the IV. The caller must not free the IV.
 *
 ***/
unsigned char *silc_message_get_iv(SilcMessagePayload payload);

/****f* silccore/SilcMessageAPI/silc_message_get_signature
 *
 * SYNOPSIS
 *
 *    SilcMessageSignedPayload
 *    silc_message_get_signature(SilcMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the pointer to the signature of the message if the
 *    SILC_MESSAGE_FLAG_SIGNED was set.  If the flag is set and this
 *    function returns NULL then error had occurred and the signature
 *    could not be retrieved from the message.
 *
 *    The caller SHOULD verify the signature by calling the
 *    silc_message_signed_verify function.
 *
 ***/
SilcMessageSignedPayload
silc_message_get_signature(SilcMessagePayload payload);

/****f* silccore/SilcMessageAPI/silc_message_signed_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcMessageSignedPayload
 *    silc_message_signed_payload_parse(const unsigned char *data,
 *                                      SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Parses the SilcMessageSignedPayload Payload from the `data' of
 *    length of `data_len' bytes.  The `data' must be payload without
 *    the actual message payload.  Returns the parsed payload or NULL
 *    on error.  Caller must free the returned payload.  Application
 *    usually does not need to call this since the function
 *    silc_message_payload_parse calls this automatically for signed
 *    messages.
 *
 ***/
SilcMessageSignedPayload
silc_message_signed_payload_parse(const unsigned char *data,
				  SilcUInt32 data_len);

/****f* silccore/SilcMessageAPI/silc_message_signed_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer
 *    silc_message_signed_payload_encode(const unsigned char *message_payload,
 *                                       SilcUInt32 message_payload_len,
 *                                       SilcPublicKey public_key,
 *                                       SilcPrivateKey private_key,
 *                                       SilcHash hash);
 *
 * DESCRIPTION
 *
 *    Encodes the SilcMessageSignedPayload Payload and computes the
 *    digital signature.  The `message_payload' is the message data that
 *    is used in the signature computation.  The encoding of the buffer
 *    is specified in the SILC protocol.  If `public_key' is provided
 *    then the public key included in the payload.  The `private_key'
 *    is used to produce the signature.  This function returns the encoded
 *    payload with the signature or NULL on error.  Caller must free the
 *    returned buffer.  The `hash' SHOULD be SHA-1 hash function.
 *    
 *    Application usually does not need to call this since the function
 *    silc_message_payload_encode calls this automatically if the caller
 *    wants to sign the message.
 *
 ***/
SilcBuffer
silc_message_signed_payload_encode(const unsigned char *message_payload,
				   SilcUInt32 message_payload_len,
				   SilcPublicKey public_key,
				   SilcPrivateKey private_key,
				   SilcHash hash);

/****f* silccore/SilcMessageAPI/silc_message_signed_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_message_signed_payload_free(SilcMessageSignedPayload sig);
 *
 * DESCRIPTION
 *
 *    Frees the SilcMessageSignedPayload Payload.
 *
 ***/
void silc_message_signed_payload_free(SilcMessageSignedPayload sig);

/****f* silccore/SilcMessageAPI/silc_message_signed_verify
 *
 * SYNOPSIS
 *
 *    int silc_message_signed_verify(SilcMessageSignedPayload sig,
 *                                   SilcMessagePayload message,
 *                                   SilcPublicKey remote_public_key,
 *                                   SilcHash hash);
 *
 * DESCRIPTION
 *
 *    This routine can be used to verify the signature found in
 *    SilcMessageSignedPayload Payload.  This returns SILC_AUTH_OK if the
 *    signature verification was successful.
 *
 ***/
int silc_message_signed_verify(SilcMessageSignedPayload sig,
			       SilcMessagePayload message,
			       SilcPublicKey remote_public_key,
			       SilcHash hash);

/****f* silccore/SilcMessageAPI/silc_message_signed_get_public_key
 *
 * SYNOPSIS
 *
 *    SilcPublicKey
 *    silc_message_signed_get_public_key(SilcMessageSignedPayload sig,
 *                                       unsigned char **pk_data,
 *                                       SilcUInt32 *pk_data_len);
 *
 * DESCRIPTION
 *
 *    Returns the decoded SilcPublicKey from the SilcMessageSignedPayload
 *    Payload or NULL if it does not include public key.  The caller must
 *    free the returned public key pointer.  This also returns the raw
 *    public key (before decoding) into `pk_data' and `pk_data_len' if
 *    they are provided.  The caller must not free these pointers.
 *
 ***/
SilcPublicKey
silc_message_signed_get_public_key(SilcMessageSignedPayload sig,
				   unsigned char **pk_data,
				   SilcUInt32 *pk_data_len);

#endif /* SILCMESSAGE_H */
