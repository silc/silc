/*

  silcargument.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC Argument Interface
 *
 * DESCRIPTION
 *
 * Implementation of the Argument Payload, that is used to include 
 * argument to other payload that needs arguments.
 *
 ***/

#ifndef SILCPAYLOAD_H
#define SILCPAYLOAD_H

/****s* silccore/SilcArgumentAPI/SilcArgumentPayload
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

/****f* silccore/SilcArgumentAPI/silc_argument_payload_parse
 *
 * SYNOPSIS
 *
 *    SilcArgumentPayload 
 *    silc_argument_payload_parse(const unsigned char *payload,
 *                                SilcUInt32 payload_len,
 *                                SilcUInt32 argc);
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
SilcArgumentPayload silc_argument_payload_parse(const unsigned char *payload,
						SilcUInt32 payload_len,
						SilcUInt32 argc);

/****f* silccore/SilcArgumentAPI/silc_argument_payload_encode
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_argument_payload_encode(SilcUInt32 argc,
 *                                            unsigned char **argv,
 *                                            SilcUInt32 *argv_lens,
 *                                            SilcUInt32 *argv_types);
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
SilcBuffer silc_argument_payload_encode(SilcUInt32 argc,
					unsigned char **argv,
					SilcUInt32 *argv_lens,
					SilcUInt32 *argv_types);

/****f* silccore/SilcArgumentAPI/silc_argument_payload_encode_payload
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

/****f* silccore/SilcArgumentAPI/silc_argument_payload_free
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

/****f* silccore/SilcArgumentAPI/silc_argument_get_arg_num
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_argument_get_arg_num(SilcArgumentPayload payload);
 *
 * DESCRIPTION
 *
 *    Returns the number of argument in the Argument Payload.
 *
 ***/
SilcUInt32 silc_argument_get_arg_num(SilcArgumentPayload payload);

/****f* silccore/SilcArgumentAPI/silc_argument_get_first_arg
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
 *                                               SilcUInt32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Returns the first argument in the Argument Payload. The lenght
 *    of the argument is returned to `ret_len'. The caller must not
 *    free the returned argument. Returns NULL on error.
 *
 ***/
unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
					   SilcUInt32 *ret_len);

/****f* silccore/SilcArgumentAPI/silc_argument_get_next_arg
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
 *                                              SilcUInt32 *ret_len);
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
					  SilcUInt32 *ret_len);

/****f* silccore/SilcArgumentAPI/silc_argument_get_arg_type
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
 *                                              SilcUInt32 type,
 *                                              SilcUInt32 *ret_len);
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
					  SilcUInt32 type,
					  SilcUInt32 *ret_len);

#endif
