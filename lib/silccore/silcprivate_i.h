/*

  silcprivate_i.h 

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

#ifndef SILCPRIVATE_I_H
#define SILCPRIVATE_I_H

#ifndef SILCPRIVATE_H
#error "Do not include internal header file directly"
#endif

/******************************************************************************

                           Private Message Payload

******************************************************************************/

/* Calculates padding length for message payload */
#define SILC_PRIVATE_MESSAGE_PAD(__payloadlen) (16 - ((__payloadlen) % 16))

/* Header length plus maximum padding length */
#define SILC_PRIVATE_MESSAGE_HLEN 4 + 16

/* Returns the data length that fits to the packet.  If data length is too
   big it will be truncated to fit to the payload. */
#define SILC_PRIVATE_MESSAGE_DATALEN(data_len)				\
  ((data_len + SILC_PRIVATE_MESSAGE_HLEN) > SILC_PACKET_MAX_LEN ?	\
   data_len - ((data_len + SILC_PRIVATE_MESSAGE_HLEN) - 		\
	       SILC_PACKET_MAX_LEN) : data_len)

/* Private Message Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcPrivateMessagePayloadStruct {
  SilcUInt16 flags;
  SilcUInt16 message_len;
  unsigned char *message;
  unsigned char *pad;
  unsigned char *mac;
};

#endif /* SILCPRIVATE_I_H */
