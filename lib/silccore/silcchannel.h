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

/* Forward declaration for Channel Message Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelPayloadStruct *SilcChannelPayload;

/* Forward declaration for Channel Key Payload parsed from packet. The
   actual structure is defined in source file and is private data. */
typedef struct SilcChannelKeyPayloadStruct *SilcChannelKeyPayload;

/* Prototypes */
SilcChannelPayload silc_channel_payload_parse(SilcBuffer buffer,
					      SilcCipher cipher,
					      SilcHmac hmac);
SilcBuffer silc_channel_payload_encode(unsigned short data_len,
				       unsigned char *data,
				       unsigned short iv_len,
				       unsigned char *iv,
				       SilcCipher cipher,
				       SilcHmac hmac,
				       SilcRng rng);
void silc_channel_payload_free(SilcChannelPayload payload);
unsigned char *silc_channel_get_data(SilcChannelPayload payload,
				     unsigned int *data_len);
unsigned char *silc_channel_get_mac(SilcChannelPayload payload);
unsigned char *silc_channel_get_iv(SilcChannelPayload payload);
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
