/*

  silcprivate.h

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

#ifndef SILCPRIVATE_H
#define SILCPRIVATE_H

/* Forward declaration of the Private Message Payload. */
typedef struct SilcPrivateMessagePayloadStruct *SilcPrivateMessagePayload;

/* Prototypes */

SilcPrivateMessagePayload 
silc_private_message_payload_parse(SilcBuffer buffer, SilcCipher cipher);
SilcBuffer silc_private_message_payload_encode(uint16 flags,
					       uint16 data_len,
					       unsigned char *data,
					       SilcCipher cipher);
void silc_private_message_payload_free(SilcPrivateMessagePayload payload);
uint16 
silc_private_message_get_flags(SilcPrivateMessagePayload payload);
unsigned char *
silc_private_message_get_nickname(SilcPrivateMessagePayload payload,
				  uint32 *nickname_len);
unsigned char *
silc_private_message_get_message(SilcPrivateMessagePayload payload,
				 uint32 *message_len);

#endif
