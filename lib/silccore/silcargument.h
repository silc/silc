/*

  silcargument.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2006 Pekka Riikonen

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
 * Implementations of the Argument Payload and Argument List Payload, that
 * is used to include arguments to other payload that needs arguments.
 *
 ***/

#ifndef SILCARGUMENT_H
#define SILCARGUMENT_H

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

/****f* silccore/SilcArgumentAPI/silc_argument_payload_encode_one
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_argument_payload_encode_one(SilcBuffer args,
 *                                                unsigned char *arg,
 *                                                SilcUInt32 arg_len,
 *                                                SilcUInt32 arg_type);
 *
 * DESCRIPTION
 *
 *    Same as silc_argument_payload_encode but encodes one argument to
 *    the buffer `args' and returns the buffer.  The returned buffer
 *    may be different than the `args'.  If `args' is NULL for the first
 *    argument this allocates the buffer and returns it.
 *
 ***/
SilcBuffer silc_argument_payload_encode_one(SilcBuffer args,
					    unsigned char *arg,
					    SilcUInt32 arg_len,
					    SilcUInt32 arg_type);

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
 *    Returns the number of arguments in the Argument Payload.
 *
 ***/
SilcUInt32 silc_argument_get_arg_num(SilcArgumentPayload payload);

/****f* silccore/SilcArgumentAPI/silc_argument_get_first_arg
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
 *                                               SilcUInt32 *type,
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
					   SilcUInt32 *type,
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
					  SilcUInt32 *type,
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

/****d* silccore/SilcArgumentAPI/SilcArgumentDecodeType
 *
 * NAME
 *
 *    typedef enum { ... } SilcArgumentDecodeType;
 *
 * DESCRIPTION
 *
 *    Argument decode types used with silc_argument_get_decoded.
 *
 * SOURCE
 */
typedef enum {
  SILC_ARGUMENT_ID,		/* SilcID */
  SILC_ARGUMENT_PUBLIC_KEY,	/* SilcPublicKey (always alloc) */
  SILC_ARGUMENT_ATTRIBUTES,	/* SilcDList (always alloc) */
  SILC_ARGUMENT_UINT32,		/* SilcUInt32 */
  SILC_ARGUMENT_BOOL,		/* SilcBool */
} SilcArgumentDecodeType;
/***/

/****f* silccore/SilcArgumentAPI/silc_argument_get_decoded
 *
 * SYNOPSIS
 *
 *    SilcBool silc_argument_get_decoded(SilcArgumentPayload payload,
 *                                       SilcUInt32 type,
 *                                       SilcArgumentDecodeType dec_type,
 *                                       void *ret_arg,
 *                                       void *ret_arg_alloc);
 *
 * DESCRIPTION
 *
 *    Returns decoded argument by type.  This is a helper function to
 *    decode common argument types directly.  The `type' is the argument
 *    type number in the payload, and the `dec_type' is the type the
 *    argument is decoded to.  If the `ret_arg' is non-NULL then the
 *    decodec data is returned into that pointer.  If the `ret_arg_alloc'
 *    is non-NULL then this function will allocate the decoded data and
 *    will return the pointer into `ret_arg_alloc'.  Some types must always
 *    be allocated; see SilcArgumentDecodeType.
 *
 *    Return TRUE if the argument was present and waa successfully decoded.
 *    FALSE if it is not present, or could not be decoded.
 *
 * EXAMPLE
 *
 *    SilcID id;
 *    SilcPublicKey public_key;
 *
 *    if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL))
 *      error;
 *
 *    if (!silc_argument_get_decoded(args, 4, SILC_ARGUMENT_PUBLIC_KEY,
 *                                   NULL, &public_key))
 *      error;
 *
 ***/
SilcBool silc_argument_get_decoded(SilcArgumentPayload payload,
				   SilcUInt32 type,
				   SilcArgumentDecodeType dec_type,
				   void *ret_arg,
				   void **ret_arg_alloc);

/****f* silccore/SilcArgumentAPI/silc_argument_list_parse
 *
 * SYNOPSIS
 *
 *    SilcArgumentPayload
 *    silc_argument_list_parse(const unsigned char *payload,
 *                             SilcUInt32 payload_len);
 *
 * DESCRIPTION
 *
 *    Parses argument list payload.  Returns parsed SilcArgumentPayload which
 *    contains all the arguments from the list.  The caller must free the
 *    returned context with silc_argument_payload_free.
 *
 ***/
SilcArgumentPayload
silc_argument_list_parse(const unsigned char *payload, SilcUInt32 payload_len);

/****s* silccore/SilcArgumentAPI/SilcArgumentDecodedList
 *
 * NAME
 *
 *    typedef struct { ... } *SilcArgumentDecodedList;
 *
 * DESCRIPTION
 *
 *    This structure is in the list returned by the function
 *    silc_argument_list_payload_parse_decoded.  The caller is responsible
 *    of freeing the contents of the structure and the structure itself.
 *
 ***/
typedef struct {
  void *argument;	     /* Decoded argument, caller must know its type */
  SilcUInt32 arg_type;	     /* Argument type number from the payload */
} *SilcArgumentDecodedList;

/****f* silccore/SilcArgumentAPI/silc_argument_list_parse_decoded
 *
 * SYNOPSIS
 *
 *    SilcDList
 *    silc_argument_list_parse_decoded(const unsigned char *payload,
 *                                     SilcUInt32 payload_len,
 *                                     SilcArgumentDecodeType dec_type);
 *
 * DESCRIPTION
 *
 *    Parses argument list payload of arguments of the type `dec_type'.
 *    The returned list includes the already decoded arguments.  The caller
 *    is responsible of freeing the the contents of the list and the list
 *    itself.  Each entry in the list is SilcArgumentDecodedList.  The
 *    caller must free the returned list with silc_argument_list_free.
 *
 ***/
SilcDList
silc_argument_list_parse_decoded(const unsigned char *payload,
				 SilcUInt32 payload_len,
				 SilcArgumentDecodeType dec_type);

/****f* silccore/SilcArgumentAPI/silc_argument_list_free
 *
 * SYNOPSIS
 *
 *    void
 *    silc_argument_list_free(SilcDList list, SilcArgumentDecodeType dec_type);
 *
 * DESCRIPTION
 *
 *    Free's the decoded argument list and its contents.
 *
 ***/
void silc_argument_list_free(SilcDList list, SilcArgumentDecodeType dec_type);

#endif /* SILCARGUMENT_H */
