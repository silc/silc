/*
 
  silcprivate.h
 
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

/****h* silccore/SILC Private Message Interface
 *
 * DESCRIPTION
 *
 * Implementation of the SILC Private Message Payload that is used to
 * deliver private messages.
 *
 ***/

#ifndef SILCPRIVATE_H
#define SILCPRIVATE_H

/****s* silccore/SilcPrivateAPI/SilcPrivateMessagePayload
 *
 * NAME
 * 
 *    typedef struct SilcPrivateMessagePayloadStruct 
 *                     *SilcPrivateMessagePayload;
 *
 *
 * DESCRIPTION
 *
 *    This context is the actual Private Message Payload and is allocated
 *    by silc_private_message_payload_parse and given as argument usually
 *    to all silc_private_message_* functions.  It is freed by the
 *    silc_private_message_payload_free function.
 *
 ***/
typedef struct SilcPrivateMessagePayloadStruct *SilcPrivateMessagePayload;

/* Prototypes */

/****f* silccore/SilcPrivateAPI/silc_private_message_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcPrivateMessagePayload 
 *    silc_private_message_payload_parse(unsigned char *payload,
 *                                       SilcUInt32 payload_len,
 *                                       SilcCipher cipher,
 *                                       SilcHmac hmac);
 *
 * DESCRIPTION
 *
 *    Parses private message payload returning new private mesage payload 
 *    structure. This also decrypts the message if the `cipher' is provided.
 *    The data integrity is checked with `hmac'.
 *
 ***/
SilcPrivateMessagePayload 
silc_private_message_payload_parse(unsigned char *payload,
				   SilcUInt32 payload_len,
				   SilcCipher cipher,
				   SilcHmac hmac);

/****f* silccore/SilcPrivateAPI/silc_private_message_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_private_message_payload_encode(SilcUInt16 flags,
 *                                                   SilcUInt16 data_len,
 *                                                   const unsigned char *data,
 *                                                   SilcCipher cipher,
 *                                                   SilcHmac hmac,
 *                                                   SilcRng rng);
 *
 * DESCRIPTION
 *
 *    Encodes private message payload into a buffer and returns it.  If
 *    the `cipher' is provided the packet is also encrypted here.  It is
 *    provided if the private message private keys are used.  If the `rng'
 *    is NULL then global RNG is used, if non-NULL then `rng' is used.
 *    The MAC for the message is computed with `hmac'.
 *
 ***/
SilcBuffer silc_private_message_payload_encode(SilcUInt16 flags,
					       SilcUInt16 data_len,
					       const unsigned char *data,
					       SilcCipher cipher,
					       SilcHmac hmac,
					       SilcRng rng);

/****f* silccore/SilcPrivateAPI/silc_private_message_payload_free
 *
 * SYNOPSIS
 *
 *    void 
 *    silc_private_message_payload_free(SilcPrivateMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Frees Private Message Payload
 *
 ***/
void silc_private_message_payload_free(SilcPrivateMessagePayload payload);

/****f* silccore/SilcPrivateAPI/silc_private_message_get_flags
 *
 * SYNOPSIS
 *
 *    SilcUInt16 
 *    silc_private_message_get_flags(SilcPrivateMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Returns flags from the payload. Message flags may indicate some
 *    status of the message. Private message flags are equivalent to the
 *    channel message flags.
 *
 ***/
SilcUInt16 
silc_private_message_get_flags(SilcPrivateMessagePayload payload);

/****f* silccore/SilcPrivateAPI/silc_private_message_get_message
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_private_message_get_message(SilcPrivateMessagePayload payload,
 *                                     SilcUInt32 *message_len);
 *
 * DESCRIPTION
 *
 *    Returns the actual private message. The caller must not free it.
 *
 ***/
unsigned char *
silc_private_message_get_message(SilcPrivateMessagePayload payload,
				 SilcUInt32 *message_len);

/****f* silccore/SilcPrivateAPI/silc_private_message_get_mac
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_private_message_get_mac(SilcPrivateMessagePayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the MAC from the payload.  The caller knows its length.
 *    The caller must not free it.
 *
 ***/
unsigned char *
silc_private_message_get_mac(SilcPrivateMessagePayload payload);

#endif
