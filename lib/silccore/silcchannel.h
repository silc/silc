/*
 
  silcchannel.h
 
  Author: Pekka Riikonen <priikone@silcnet.org>
 
  Copyright (C) 1997 - 2005 Pekka Riikonen
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC Channel Interface
 *
 * DESCRIPTION
 *
 * Implementations of the Channel Payload and Channel Key Payload.  The
 * Channel Payload represents new channel and is used to distribute the
 * information of the new channel.  The Channel Key Payload is used to
 * distribute a new key to the channel.  It is done for example every
 * time someone joins a channel or the old key expires.
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
