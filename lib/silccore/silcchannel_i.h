/*

  silcchannel_i.h 

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

#ifndef SILCCHANNEL_I_H
#define SILCCHANNEL_I_H

#ifndef SILCCHANNEL_H
#error "Do not include internal header file directly"
#endif

/******************************************************************************

                              Channel Payload

******************************************************************************/

/* Channel Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelPayloadStruct {
  unsigned char *channel_name;
  unsigned char *channel_id;
  SilcUInt32 mode;
  SilcUInt16 name_len;
  SilcUInt16 id_len;
};


/******************************************************************************

                          Channel Message Payload

******************************************************************************/

/* Calculates padding length for message payload */
#define SILC_CHANNEL_MESSAGE_PAD(__payloadlen) (16 - ((__payloadlen) % 16))

/* Header length plus maximum padding length */
#define SILC_CHANNEL_MESSAGE_HLEN 6 + 16

/* Returns the data length that fits to the packet.  If data length is too
   big it will be truncated to fit to the payload. */
#define SILC_CHANNEL_MESSAGE_DATALEN(data_len, header_len)		\
  ((data_len + SILC_CHANNEL_MESSAGE_HLEN + header_len) >		\
   SILC_PACKET_MAX_LEN ?						\
   data_len - ((data_len + SILC_CHANNEL_MESSAGE_HLEN + header_len) -	\
	       SILC_PACKET_MAX_LEN) : data_len)

/* Channel Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcChannelMessagePayloadStruct {
  unsigned char *data;
  unsigned char *pad;
  unsigned char *mac;
  unsigned char *iv;
  SilcMessageFlags flags;
  SilcUInt16 data_len;
  SilcUInt16 pad_len;
  SilcUInt16 iv_len;
};


/******************************************************************************

                             Channel Key Payload

******************************************************************************/

/* Channel Key Payload structrue. Channel keys are parsed from SILC
   packets into this structure. */
struct SilcChannelKeyPayloadStruct {
  unsigned char *id;
  unsigned char *cipher;
  unsigned char *key;
  SilcUInt16 id_len;
  SilcUInt16 cipher_len;
  SilcUInt16 key_len;
};

#endif /* SILCCHANNEL_I_H */
