/*

  silcchannel.h

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

#ifndef SILCCHANNEL_H
#define SILCCHANNEL_H

#include "silcdlist.h"

/* Forward declaration for Channel Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelPayloadStruct *SilcChannelPayload;

/* Forward declaration for Channel Message Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelMessagePayloadStruct *SilcChannelMessagePayload;

/* Forward declaration for Channel Key Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelKeyPayloadStruct *SilcChannelKeyPayload;

/* The Message flag type */
typedef uint16 SilcMessageFlags;

/* The message flags (shared by both channel and private messages) */
#define SILC_MESSAGE_FLAG_NONE        0x0000
#define SILC_MESSAGE_FLAG_AUTOREPLY   0x0001
#define SILC_MESSAGE_FLAG_NOREPLY     0x0002
#define SILC_MESSAGE_FLAG_ACTION      0x0004
#define SILC_MESSAGE_FLAG_NOTICE      0x0008
#define SILC_MESSAGE_FLAG_REQUEST     0x0010
#define SILC_MESSAGE_FLAG_RESERVED    0x0020 /* to 0x0200 */
#define SILC_MESSAGE_FLAG_PRIVATE     0x0400 /* to 0x8000 */

/* Prototypes */
SilcChannelPayload silc_channel_payload_parse(SilcBuffer buffer);
SilcDList silc_channel_payload_parse_list(SilcBuffer buffer);
SilcBuffer silc_channel_payload_encode(unsigned char *channel_name,
				       uint16 channel_name_len,
				       unsigned char *channel_id,
				       uint32 channel_id_len,
				       uint32 mode);
void silc_channel_payload_free(SilcChannelPayload payload);
void silc_channel_payload_list_free(SilcDList list);
unsigned char *silc_channel_get_name(SilcChannelPayload payload,
				     uint32 *channel_name_len);
unsigned char *silc_channel_get_id(SilcChannelPayload payload,
				   uint32 *channel_id_len);
SilcChannelID *silc_channel_get_id_parse(SilcChannelPayload payload);
uint32 silc_channel_get_mode(SilcChannelPayload payload);
int silc_channel_message_payload_decrypt(unsigned char *data,
					 size_t data_len,
					 SilcCipher cipher,
					 SilcHmac hmac);
SilcChannelMessagePayload 
silc_channel_message_payload_parse(SilcBuffer buffer,
				   SilcCipher cipher,
				   SilcHmac hmac);
SilcBuffer silc_channel_message_payload_encode(uint16 flags,
					       uint16 data_len,
					       unsigned char *data,
					       uint16 iv_len,
					       unsigned char *iv,
					       SilcCipher cipher,
					       SilcHmac hmac);
void silc_channel_message_payload_free(SilcChannelMessagePayload payload);
uint16 
silc_channel_message_get_flags(SilcChannelMessagePayload payload);
unsigned char *silc_channel_message_get_data(SilcChannelMessagePayload payload,
				     uint32 *data_len);
unsigned char *silc_channel_message_get_mac(SilcChannelMessagePayload payload);
unsigned char *silc_channel_message_get_iv(SilcChannelMessagePayload payload);
SilcChannelKeyPayload silc_channel_key_payload_parse(SilcBuffer buffer);
SilcBuffer silc_channel_key_payload_encode(uint16 id_len,
					   unsigned char *id,
					   uint16 cipher_len,
					   unsigned char *cipher,
					   uint16 key_len,
					   unsigned char *key);
void silc_channel_key_payload_free(SilcChannelKeyPayload payload);
unsigned char *silc_channel_key_get_id(SilcChannelKeyPayload payload, 
				       uint32 *id_len);
unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
					   uint32 *cipher_len);
unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
					uint32 *key_len);

#endif
