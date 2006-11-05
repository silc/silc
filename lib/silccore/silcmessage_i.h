/*

  silcmessage_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCMESSAGE_I_H
#define SILCMESSAGE_I_H

#ifndef SILCMESSAGE_I_H
#error "Do not include this header directly"
#endif

/* The SILC_MESSAGE_FLAG_SIGNED Payload */
typedef struct SilcMessageSignedPayloadStruct {
  unsigned char *pk_data;
  unsigned char *sign_data;
  SilcUInt16 pk_len;
  SilcUInt16 pk_type;
  SilcUInt16 sign_len;
} *SilcMessageSignedPayload;

/* Message Payload structure. */
struct SilcMessagePayloadObject {
  unsigned char *data;
  unsigned char *pad;
  unsigned char *mac;
  struct SilcMessageSignedPayloadStruct sig;
  SilcMessageFlags flags;
  SilcUInt16 data_len;
  SilcUInt16 pad_len;
  SilcUInt16 iv_len;
  unsigned int allocated  : 1;
};

#endif /* SILCMESSAGE_I_H */
