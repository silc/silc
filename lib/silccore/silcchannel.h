/*
 
  silcchannel.h
 
  Author: Pekka Riikonen <priikone@silcnet.org>
 
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

/****h* silccore/SILC Channel Interface
 *
 * DESCRIPTION
 *
 * Implementations of the Channel Payload, Channel Message Payload and
 * Channel Key Payload.  The Channel Payload represents new channel and
 * is used to distribute the information of the new channel.  The Channel
 * Message Payload is used to deliver messages to the channel.  The routines
 * for Channel Message Payload also handles the encryption and decryption
 * of the payload.  Last, the Channel Key Payload is used to distribute
 * a new key to the channel.  It is done for example every time someone
 * joins a channel or the old key expires.
 *
 ***/

#ifndef SILCCHANNEL_H
#define SILCCHANNEL_H

#include "silcdlist.h"

/****s* silccore/SilcChannelAPI/SilcChannelPayload
 *
 * NAME
 * 
 *    typedef struct SilcChannelPayloadStruct *SilcChannelPayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Channel Payload and is allocated
 *    by silc_channel_payload_parse and given as argument usually to
 *    all silc_channel_payload_* functions.  It is freed by the
 *    silc_channel_payload_free function.
 *
 ***/
typedef struct SilcChannelPayloadStruct *SilcChannelPayload;

/****s* silccore/SilcChannelAPI/SilcChannelMessagePayload
 *
 * NAME
 * 
 *    typedef struct 
 *    SilcChannelMessagePayloadStruct *SilcChannelMessagePayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Channel Message Payload and is allocated
 *    by silc_channel_message_payload_parse and given as argument usually to
 *    all silc_channel_message_payload_* functions.  It is freed by the
 *    silc_channel_message_payload_free function.
 *
 ***/
typedef struct SilcChannelMessagePayloadStruct *SilcChannelMessagePayload;

/****s* silccore/SilcChannelAPI/SilcChannelKeyPayload
 *
 * NAME
 * 
 *    typedef struct SilcChannelKeyPayloadStruct *SilcChannelKeyPayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Channel Key Payload and is allocated
 *    by silc_channel_key_payload_parse and given as argument usually to
 *    all silc_channel_key_payload_* functions.  It is freed by the
 *    silc_channel_key_payload_free function.
 *
 ***/
typedef struct SilcChannelKeyPayloadStruct *SilcChannelKeyPayload;

/****d* silccore/SilcChannelAPI/SilcMessageFlags
 *
 * NAME
 * 
 *    typedef SilcUInt16 SilcMessageFlags;
 *
 * DESCRIPTION
 *
 *    The message flags type definition and the message flags.  The 
 *    message flags are used to indicate some status of the message.
 *    These flags are also used by the private message interfaces.
 *
 * SOURCE
 */
typedef SilcUInt16 SilcMessageFlags;

/* The message flags (shared by both channel and private messages) */
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
#define SILC_MESSAGE_FLAG_RESERVED    0x0200	  /* to 0x0800 */
#define SILC_MESSAGE_FLAG_PRIVATE     0x1000	  /* to 0x8000 */
/***/

/* Prototypes */

/****f* silccore/SilcChannelAPI/silc_channel_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcChannelPayload 
 *    silc_channel_payload_parse(const unsigned char *payload,
 *                               SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses channel payload returning new channel payload structure. The
 *    `buffer' is the raw payload buffer.
 *
 ***/
SilcChannelPayload silc_channel_payload_parse(const unsigned char *payload,
					      SilcUInt32 payload_len);

/****f* silccore/SilcChannelAPI/silc_channel_payload_parse_list
 *
 * SYNOPSIS
 *
 *    SilcDList
 *    silc_channel_payload_parse_list(const unsigned char *payload,
 *                                    SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses list of channel payloads returning list of payloads. This
 *    is equivalent to the silc_channel_payload_parse except that the `buffer'
 *    now includes multiple Channel Payloads one after the other.
 *
 ***/
SilcDList silc_channel_payload_parse_list(const unsigned char *payload,
					  SilcUInt32 payload_len);

/****f* silccore/SilcChannelAPI/silc_channel_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_channel_payload_encode(const unsigned char *channel_name,
 *                                           SilcUInt16 channel_name_len,
 *                                           const unsigned char *channel_id,
 *                                           SilcUInt32 channel_id_len,
 *                                           SilcUInt32 mode);
 *
 * DESCRIPTION
 *
 *    Encode new channel payload and returns it as buffer.
 *
 ***/
SilcBuffer silc_channel_payload_encode(const unsigned char *channel_name,
				       SilcUInt16 channel_name_len,
				       const unsigned char *channel_id,
				       SilcUInt32 channel_id_len,
				       SilcUInt32 mode);

/****f* silccore/SilcChannelAPI/silc_channel_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_channel_payload_free(SilcChannelPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees Channel Payload and all data in it.
 *
 ***/
void silc_channel_payload_free(SilcChannelPayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_payload_list_free
 *
 * SYNOPSIS
 *
 *    void silc_channel_payload_list_free(SilcDList list);
 *
 * DESCRIPTION
 *
 *    Frees list of Channel Payloads and all data in them.
 *
 ***/
void silc_channel_payload_list_free(SilcDList list);

/****f* silccore/SilcChannelAPI/silc_channel_get_name
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_channel_get_name(SilcChannelPayload payload,
 *                                         SilcUInt32 *channel_name_len);
 *
 * DESCRIPTION
 *
 *    Return the channel name from the payload. The caller must not free it.
 *
 ***/
unsigned char *silc_channel_get_name(SilcChannelPayload payload,
				     SilcUInt32 *channel_name_len);

/****f* silccore/SilcChannelAPI/silc_channel_get_id
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_channel_get_id(SilcChannelPayload payload,
 *                                       SilcUInt32 *channel_id_len);
 *
 * DESCRIPTION
 *
 *    Return the Channel ID data from the payload. The caller must not free it.
 *
 ***/
unsigned char *silc_channel_get_id(SilcChannelPayload payload,
				   SilcUInt32 *channel_id_len);

/****f* silccore/SilcChannelAPI/silc_channel_get_id_parse
 *
 * SYNOPSIS
 *
 *    SilcChannelID *silc_channel_get_id_parse(SilcChannelPayload payload);
 *
 * DESCRIPTION
 *
 *    Return the Channel ID as parsed ID. This is equivalent to the
 *    silc_channel_get_id execpt that the ID is already parsed. The caller
 *    must free the parsed Channel ID.
 *
 ***/
SilcChannelID *silc_channel_get_id_parse(SilcChannelPayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_get_mode
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_channel_get_mode(SilcChannelPayload payload);
 *
 * DESCRIPTION
 *
 *    Return the mode. The mode is arbitrary. It can be the mode of the
 *    channel or perhaps the mode of the client on the channel.  The protocol
 *    dictates what the usage of the mode is in different circumstances.
 *
 ***/
SilcUInt32 silc_channel_get_mode(SilcChannelPayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_message_payload_decrypt
 *
 * SYNOPSIS
 *
 *    bool silc_channel_message_payload_decrypt(unsigned char *data,
 *                                              size_t data_len,
 *                                              SilcCipher cipher,
 *                                              SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Decrypt the channel message. First push the IV out of the packet `data'.
 *    The IV is used in the decryption process. Then decrypt the message.
 *    After decryption, take the MAC from the decrypted packet, compute MAC
 *    and compare the MACs.  If they match, the decryption was successful
 *    and we have the channel message ready to be displayed.
 *
 *    This is usually used by the Channel Message interface itself but can
 *    be called by the appliation if separate decryption process is required.
 *    For example server might need to call this directly in some 
 *    circumstances. The `cipher' is used to decrypt the payload.
 *
 *    If the `hmac' is no provided then the MAC of the channel message is
 *    not verified.
 *
 ***/
bool silc_channel_message_payload_decrypt(unsigned char *data,
					  size_t data_len,
					  SilcCipher cipher,
					  SilcHmac hmac);

/****f* silccore/SilcChannelAPI/silc_channel_message_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcChannelMessagePayload 
 *    silc_channel_message_payload_parse(const unsigned char *payload,
 *                                       SilcUInt32 payload_len,
 *                                       SilcCipher cipher,
 *                                       SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Parses channel message payload returning new channel payload structure.
 *    This also decrypts it and checks the MAC. The `cipher's is used to
 *    decrypt the payload.
 *
 *    If the `hmac' is no provided then the MAC of the channel message is
 *    not verified.
 *
 ***/
SilcChannelMessagePayload 
silc_channel_message_payload_parse(unsigned char *payload,
				   SilcUInt32 payload_len,
				   SilcCipher cipher,
				   SilcHmac hmac);

/****f* silccore/SilcChannelAPI/silc_channel_message_payload_encrypt
 *
 * SYNOPSIS
 *
 *    bool silc_channel_message_payload_encrypt(unsigned char *data,
 *                                              SilcUInt32 data_len,
 *                                              SilcUInt32 true_len,
 *                                              unsigned char *iv,
 *                                              SilcUInt32 iv_len,
 *                                              SilcCipher cipher,
 *                                              SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    This function is used to encrypt the Channel Messsage Payload which is
 *    the `data' and `data_len'.  The `data_len' is the data length which is
 *    used to create MAC out of.  The `true_len' is the true length of `data'
 *    message payload and is used assemble rest of the packet after MAC
 *    creation. The `true_len' length packet will then be encrypted.
 *
 *    This is usually used by the Channel Message interface itself but can
 *    be called by the appliation if separate encryption process is required.
 *    For example server might need to call this directly in some 
 *    circumstances. The `cipher' is used to encrypt the payload.
 *
 ***/
bool silc_channel_message_payload_encrypt(unsigned char *data,
					  SilcUInt32 data_len,
					  SilcUInt32 true_len,
					  unsigned char *iv,
					  SilcUInt32 iv_len,
					  SilcCipher cipher,
					  SilcHmac hmac);

/****f* silccore/SilcChannelAPI/silc_channel_message_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_channel_message_payload_encode(SilcMessageFlags flags,
 *                                                   SilcUInt16 data_len,
 *                                                   const unsigned char *data,
 *                                                   SilcUInt16 iv_len,
 *                                                   unsigned char *iv,
 *                                                   SilcCipher cipher,
 *                                                   SilcHmac hmac.
 *                                                   SilcRng rng);
 *
 * DESCRIPTION
 *
 *    Encodes channel message payload into a buffer and returns it. This
 *    is used to add channel message payload into a packet. As the channel
 *    payload is encrypted separately from other parts of the packet padding
 *    must be applied to the payload. The function generates the padding
 *    automatically from random data.  The `cipher' is the cipher used
 *    encrypt the payload and `hmac' is used to compute the MAC for the
 *    payload.  If `rng' is NULL then global RNG is used, if non-NULL then
 *    the `rng' is used.
 *
 ***/
SilcBuffer silc_channel_message_payload_encode(SilcMessageFlags flags,
					       SilcUInt16 data_len,
					       const unsigned char *data,
					       SilcUInt16 iv_len,
					       unsigned char *iv,
					       SilcCipher cipher,
					       SilcHmac hmac,
					       SilcRng rng);

/****f* silccore/SilcChannelAPI/silc_channel_message_payload_free
 *
 * SYNOPSIS
 *
 *    void 
 *    silc_channel_message_payload_free(SilcChannelMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Free's Channel Message Payload and all data in it.
 *
 ***/
void silc_channel_message_payload_free(SilcChannelMessagePayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_message_get_flags
 *
 * SYNOPSIS
 *
 *    SilcMessageFlags
 *    silc_channel_message_get_flags(SilcChannelMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the message flags from the payload.
 *
 ***/
SilcMessageFlags
silc_channel_message_get_flags(SilcChannelMessagePayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_message_get_data
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_channel_message_get_data(SilcChannelMessagePayload payload,
 *                                  SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Return the data in the payload, that is, the actual channel message.
 *    The caller must not free it.
 *
 ***/
unsigned char *silc_channel_message_get_data(SilcChannelMessagePayload payload,
					     SilcUInt32 *data_len);

/****f* silccore/SilcChannelAPI/silc_channel_message_get_mac
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_channel_message_get_mac(SilcChannelMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Return the MAC of the payload. The caller must already know the 
 *    length of the MAC. The caller must not free the MAC.
 *
 ***/
unsigned char *silc_channel_message_get_mac(SilcChannelMessagePayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_message_get_iv
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_channel_message_get_iv(SilcChannelMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Return the IV of the payload. The caller must already know the 
 *    length of the IV. The caller must not free the IV.
 *
 ***/
unsigned char *silc_channel_message_get_iv(SilcChannelMessagePayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_key_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcChannelKeyPayload 
 *    silc_channel_key_payload_parse(const unsigned char *payload,
 *                                   uin32 payload_len);
 *
 * DESCRIPTION
 *
 *     Parses channel key payload returning new channel key payload 
 *     structure.
 *
 ***/
SilcChannelKeyPayload 
silc_channel_key_payload_parse(const unsigned char *payload,
			       SilcUInt32 payload_len);

/****f* silccore/SilcChannelAPI/silc_channel_key_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_channel_key_payload_encode(SilcUInt16 id_len,
 *                                               const unsigned char *id,
 *                                               SilcUInt16 cipher_len,
 *                                               const unsigned char *cipher,
 *                                               SilcUInt16 key_len,
 *                                               const unsigned char *key);
 *
 * DESCRIPTION
 *
 *    Encodes channel key payload into a buffer and returns it. This is used 
 *    to add channel key payload into a packet.
 *
 ***/
SilcBuffer silc_channel_key_payload_encode(SilcUInt16 id_len,
					   const unsigned char *id,
					   SilcUInt16 cipher_len,
					   const unsigned char *cipher,
					   SilcUInt16 key_len,
					   const unsigned char *key);

/****f* silccore/SilcChannelAPI/silc_channel_key_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_channel_key_payload_free(SilcChannelKeyPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the Channel Key Payload and all data in it.
 *
 ***/
void silc_channel_key_payload_free(SilcChannelKeyPayload payload);

/****f* silccore/SilcChannelAPI/silc_channel_key_get_id
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_channel_key_get_id(SilcChannelKeyPayload payload, 
 *                                           SilcUInt32 *id_len);
 *
 * DESCRIPTION
 *
 *    Return the Channel ID data from the payload. The caller must not
 *    free it.
 *
 ***/
unsigned char *silc_channel_key_get_id(SilcChannelKeyPayload payload, 
				       SilcUInt32 *id_len);

/****f* silccore/SilcChannelAPI/silc_channel_key_get_cipher
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
 *                                               SilcUInt32 *cipher_len);
 *
 * DESCRIPTION
 *
 *    Return the name of the cipher from the payload. The caller must not
 *    free it.
 *
 ***/
unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
					   SilcUInt32 *cipher_len);

/****f* silccore/SilcChannelAPI/silc_channel_key_get_key
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
 *                                            SilcUInt32 *key_len);
 *
 * DESCRIPTION
 *
 *    Return the raw key material from the payload. The caller must not
 *    free it.
 *
 ***/
unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
					SilcUInt32 *key_len);

#endif
