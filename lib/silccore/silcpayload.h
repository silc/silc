/*

  silcpayload.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SilcGenericPayloadAPI
 *
 * DESCRIPTION
 *
 * Implementation of the generic payloads described in the protocol
 * specification; ID Payload and Argument Payload. The ID Payload is
 * used to represent an ID. The Argument Payload is used to include
 * arguments to other payloads that needs arguments.
 *
 ***/

#ifndef SILCPAYLOAD_H
#define SILCPAYLOAD_H

/****s* silccore/SilcGenericPayloadAPI/SilcIDPayload
 *
 * NAME
 * 
 *    typedef struct SilcIDPayloadStruct *SilcIDPayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual ID Payload and is allocated by
 *    silc_id_payload_parse and given as argument usually to all
 *    silc_id_payload_* functions.  It is freed by the function
 *    silc_id_payload_free.
 *
 ***/
typedef struct SilcIDPayloadStruct *SilcIDPayload;

/****s* silccore/SilcGenericPayloadAPI/SilcArgumentPayload
 *
 * NAME
 * 
 *    typedef struct SilcArgumentPayloadStruct *SilcArgumentPayload;
 *
 * DESCRIPTION
 *
 *    This context is the actual Argument Payload and is allocated
 *    by silc_argument_payload_parse and given as argument usually to
 *    all silc_argument_payload_* functions.  It is freed by the
 *    silc_argument_payload_free function.
 *
 ***/
typedef struct SilcArgumentPayloadStruct *SilcArgumentPayload;

/* Prototypes */

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcIDPayload silc_id_payload_parse(SilcBuffer buffer);
 *
 * DESCRIPTION
 *
 *    Parses buffer and return ID payload into payload structure. The
 *    `buffer' is raw payload buffer.
 *
 ***/
SilcIDPayload silc_id_payload_parse(SilcBuffer buffer);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_parse_data
 *
 * SYNOPSIS
 *
 *    SilcIDPayload silc_id_payload_parse_data(unsigned char *data, 
 *                                             uint32 len);
 *
 * DESCRIPTION
 *
 *    Parses buffer and return ID payload into payload structure. The
 *    `data' and `len' are the raw payload buffer. This is equivalent
 *    to the silc_id_payload_parse function.
 *
 ***/
SilcIDPayload silc_id_payload_parse_data(unsigned char *data, 
					 uint32 len);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_parse_id
 *
 * SYNOPSIS
 *
 *    void *silc_id_payload_parse_id(unsigned char *data, uint32 len);
 *
 * DESCRIPTION
 *
 *    Return ID directly from the raw ID Payload data buffer. The
 *    caller must free the returned ID.
 *
 ***/
void *silc_id_payload_parse_id(unsigned char *data, uint32 len);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_id_payload_encode(void *id, SilcIdType type);
 *
 * DESCRIPTION
 *
 *    Encodes ID Payload. The `id' is the ID of the type `type' to put
 *    into the payload. Returns the encoded payload buffer.
 *
 ***/
SilcBuffer silc_id_payload_encode(void *id, SilcIdType type);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_id_payload_free(SilcIDPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the ID Payload and all data in it.
 *
 ***/
void silc_id_payload_free(SilcIDPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_get_type
 *
 * SYNOPSIS
 *
 *    SilcIdType silc_id_payload_get_type(SilcIDPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the ID type from the ID Payload. The type tells the
 *    type of the ID in the payload.
 *
 ***/
SilcIdType silc_id_payload_get_type(SilcIDPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_get_id
 *
 * SYNOPSIS
 *
 *    void *silc_id_payload_get_id(SilcIDPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the ID in the ID Payload. The caller must free the
 *    returned ID.
 *
 ***/
void *silc_id_payload_get_id(SilcIDPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_get_data
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_id_payload_get_data(SilcIDPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the raw ID data from the ID Payload. The data is duplicated
 *    and the caller must free it.
 *
 ***/
unsigned char *silc_id_payload_get_data(SilcIDPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_id_payload_get_len
 *
 * SYNOPSIS
 *
 *    uint32 silc_id_payload_get_len(SilcIDPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the length of the ID in the ID Payload.
 *
 ***/
uint32 silc_id_payload_get_len(SilcIDPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcArgumentPayload silc_argument_payload_parse(SilcBuffer buffer,
 *                                                    uint32 argc);
 *
 * DESCRIPTION
 *
 *    Parses arguments and returns them into Argument Payload structure.
 *    the `buffer' is raw Argument Payload data buffer. The `argc' is
 *    the number of arguments in the Argument Payload. The caller must
 *    know the number of the arguments. This is always known as the
 *    Argument payload is associated with other payloads which defines
 *    the number of the arguments.
 *
 ***/
SilcArgumentPayload silc_argument_payload_parse(SilcBuffer buffer,
						uint32 argc);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_argument_payload_encode(uint32 argc,
 *                                            unsigned char **argv,
 *                                            uint32 *argv_lens,
 *                                            uint32 *argv_types);
 *
 * DESCRIPTION
 *
 *    Encodes arguments in to Argument Paylods returning them to SilcBuffer.
 *    The `argv' is the array of the arguments, the `argv_lens' array of
 *    the length of the `argv' arguments and the `argv_types' array of
 *    the argument types of the `argv' arguments. The `argc' is the 
 *    number of arguments.
 *
 ***/
SilcBuffer silc_argument_payload_encode(uint32 argc,
					unsigned char **argv,
					uint32 *argv_lens,
					uint32 *argv_types);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_payload_encode_payload
 *
 * SYNOPSIS
 *
 *    SilcBuffer 
 *    silc_argument_payload_encode_payload(SilcArgumentPayload payload);
 *
 * DESCRIPTION
 *
 *    Same as silc_argument_payload_encode but encodes the payload from
 *    already allocated SilcArgumentPayload structure instead of raw data.
 *
 ***/
SilcBuffer silc_argument_payload_encode_payload(SilcArgumentPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_payload_free
 *
 * SYNOPSIS
 *
 *    void silc_argument_payload_free(SilcArgumentPayload payload);
 *
 * DESCRIPTION
 *
 *    Frees the Argument Payload and all data in it.
 *
 ***/
void silc_argument_payload_free(SilcArgumentPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_get_arg_num
 *
 * SYNOPSIS
 *
 *    uint32 silc_argument_get_arg_num(SilcArgumentPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the number of argument in the Argument Payload.
 *
 ***/
uint32 silc_argument_get_arg_num(SilcArgumentPayload payload);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_get_first_arg
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
 *                                               uint32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Returns the first argument in the Argument Payload. The lenght
 *    of the argument is returned to `ret_len'. The caller must not
 *    free the returned argument. Returns NULL on error.
 *
 ***/
unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
					   uint32 *ret_len);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_get_next_arg
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
 *                                              uint32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Returns next argument from the Argument Payload. The length of
 *    the argument is returned to `ret_len'. The caller must not free
 *    the returned argument. This returns NULL when there are no more
 *    arguments in the payload.
 *
 ***/
unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
					  uint32 *ret_len);

/****f* silccore/SilcGenericPayloadAPI/silc_argument_get_arg_type
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
 *                                              uint32 type,
 *                                              uint32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Returns argument by type. The returned argument has type `type'
 *    in the Argument Payload. Each argument has their own type (or zero
 *    if no specific type is set). The length of the argument is returned
 *    to the `ret_len'. The caller must not free the returned argument.
 *    Returns NULL on error.
 *
 ***/
unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
					  uint32 type,
					  uint32 *ret_len);

#endif
