/*

  silcchannel.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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

/* Forward declaration for Channel Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelPayloadStruct *SilcChannelPayload;

/* Forward declaration for Channel Key Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelKeyPayloadStruct *SilcChannelKeyPayload;

/* Channel modes */
#define SILC_CHANNEL_MODE_NONE        0x0000
#define SILC_CHANNEL_MODE_PRIVATE     0x0001 /* private channel */
#define SILC_CHANNEL_MODE_SECRET      0x0002 /* secret channel */
#define SILC_CHANNEL_MODE_PRIVKEY     0x0004 /* channel has private key */
#define SILC_CHANNEL_MODE_INVITE      0x0008 /* invite only channel */
#define SILC_CHANNEL_MODE_TOPIC       0x0010 /* topic setting by operator */
#define SILC_CHANNEL_MODE_ULIMIT      0x0020 /* user limit set */
#define SILC_CHANNEL_MODE_PASSPHRASE  0x0040 /* passphrase set */
#define SILC_CHANNEL_MODE_BAN         0x0080 /* ban list set */
#define SILC_CHANNEL_MODE_INVITE_LIST 0x0100 /* invite list set */
#define SILC_CHANNEL_MODE_CIPHER      0x0200 /* sets cipher of channel */

/* User modes on channel */
#define SILC_CHANNEL_UMODE_NONE       0x0000 /* Normal user */
#define SILC_CHANNEL_UMODE_CHANFO     0x0001 /* channel founder */
#define SILC_CHANNEL_UMODE_CHANOP     0x0002 /* channel operator */

/* Prototypes */
SilcChannelPayload silc_channel_payload_parse(SilcBuffer buffer);
SilcBuffer silc_channel_payload_encode(unsigned short data_len,
				       unsigned char *data,
				       unsigned short iv_len,
				       unsigned char *iv,
				       SilcRng rng);
void silc_channel_payload_free(SilcChannelPayload payload);
unsigned char *silc_channel_get_data(SilcChannelPayload payload,
				     unsigned int *data_len);
unsigned char *silc_channel_get_iv(SilcChannelPayload payload,
				   unsigned int *iv_len);
SilcChannelKeyPayload silc_channel_key_payload_parse(SilcBuffer buffer);
SilcBuffer silc_channel_key_payload_encode(unsigned short id_len,
					   unsigned char *id,
					   unsigned short cipher_len,
					   unsigned char *cipher,
					   unsigned short key_len,
					   unsigned char *key);
void silc_channel_key_payload_free(SilcChannelKeyPayload payload);
unsigned char *silc_channel_key_get_id(SilcChannelKeyPayload payload, 
				       unsigned int *id_len);
unsigned char *silc_channel_key_get_cipher(SilcChannelKeyPayload payload,
					   unsigned int *cipher_len);
unsigned char *silc_channel_key_get_key(SilcChannelKeyPayload payload,
					unsigned int *key_len);

#endif
