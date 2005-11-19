/*

  silcmime.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC MIME Interface
 *
 * DESCRIPTION
 *
 * Simple implementation of MIME.  Supports creation and parsing of simple
 * MIME messages, multipart MIME messages, including nested multiparts, and
 * MIME fragmentation and defragmentation.
 *
 ***/

#ifndef SILCMIME_H
#define SILCMIME_H

/****s* silcutil/SILCMIMEAPI/SilcMime
 *
 * NAME
 *
 *    typedef struct SilcMimeStruct *SilcMime;
 *
 * DESCRIPTION
 *
 *    This context is the actual MIME message and is allocated
 *    by silc_mime_alloc and given as argument to all silc_mime_*
 *    functions.  It is freed by the silc_mime_free function.
 *
 ***/
typedef struct SilcMimeStruct *SilcMime;

/****s* silcutil/SILCMIMEAPI/SilcMimeAssembler
 *
 * NAME
 *
 *    typedef struct SilcMimeAssemblerStruct *SilcMimeAssembler;
 *
 * DESCRIPTION
 *
 *    This context is a SILC MIME Assembler that is used to assemble partial
 *    MIME messages (fgraments) into complete MIME messages.  It is allocated
 *    by silc_mime_assembler_alloc and freed by silc_mime_assembler_free.
 *
 ***/
typedef struct SilcMimeAssemblerStruct *SilcMimeAssembler;

/****f* silcutil/SILCMIMEAPI/SilcMimeComplete
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcMimeComplete)(SilcMime mime, void *context);
 *
 * DESCRIPTION
 *
 *    Callback function that is called by silc_mime_assemble function when
 *    all fragments has been received.  The `mime' is the complete MIME
 *    message.  It must be freed with silc_mime_free.
 *
 ***/
typedef void (*SilcMimeComplete)(SilcMime mime, void *context);

/****f* silcutil/SILCMIMEAPI/silc_mime_alloc
 *
 * SYNOPSIS
 *
 *    SilcMime silc_mime_alloc(void)
 *
 * DESCRIPTION
 *
 *    Allocates SILC Mime message context.
 *
 ***/
SilcMime silc_mime_alloc(void);

/****f* silcutil/SILCMIMEAPI/silc_mime_free
 *
 * SYNOPSIS
 *
 *    void silc_mime_alloc(SilcMime mime)
 *
 * DESCRIPTION
 *
 *    Frees `mime' context.
 *
 ***/
void silc_mime_free(SilcMime mime);

/****f* silcutil/SILCMIMEAPI/silc_mime_assembler_alloc
 *
 * SYNOPSIS
 *
 *    SilcMimeAssembler silc_mime_assembler_alloc(SilcMimeComplete complete,
 *                                                void *complete_context);
 *
 * DESCRIPTION
 *
 *    Allocates MIME fragment assembler.  The `complete' callback will be
 *    whenever a MIME message has been assembled completely.  It delivers
 *    the complete MIME message to the caller.
 *
 ***/
SilcMimeAssembler silc_mime_assembler_alloc(SilcMimeComplete complete,
								    void *complete_context);

/****f* silcutil/SILCMIMEAPI/silc_mime_assembler_free
 *
 * SYNOPSIS
 *
 *    void silc_mime_assembler_free(SilcMimeAssembler assembler)
 *
 * DESCRIPTION
 *
 *    Frees `assembler' context.
 *
 ***/
void silc_mime_assembler_free(SilcMimeAssembler assembler);

/****f* silcutil/SILCMIMEAPI/silc_mime_decode
 *
 * SYNOPSIS
 *
 *    SilcMime silc_mime_parse(const unsigned char *data,
 *                             SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Decodes a MIME message and returns the parsed message into newly
 *    allocated SilcMime context.
 *
 * EXAMPLE
 *
 *    // Parse MIME message and get its content type
 *    mime = silc_mime_parse(data, data_len);
 *    type = silc_mime_get_field(mime, "Content-Type");
 *    ...
 *
 *    // Assemble received MIME fragment
 *    mime = silc_mime_parse(data, data_len);
 *    if (silc_mime_is_partial(mime) == TRUE)
 *      silc_mime_assmeble(assembler, mime);
 *
 ***/
SilcMime silc_mime_decode(const unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SILCMIMEAPI/silc_mime_encode
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_mime_encode(SilcMime mime, SilcUInt32 *encoded_len);
 *
 * DESCRIPTION
 *
 *    Encodes the `mime' context into a raw MIME message (may be human
 *    readable).  The caller must free the returned buffer.  If the `mime'
 *    is multipart MIME message all parts will be automatically encoded
 *    as well.
 *
 *    If you want to create fragmented MIME message use the function
 *    silc_mime_encode_partial.
 *
 ***/
unsigned char *silc_mime_encode(SilcMime mime, SilcUInt32 *encoded_len);

/****f* silcutil/SILCMIMEAPI/silc_mime_assemble
 *
 * SYNOPSIS
 *
 *    void silc_mime_assemble(SilcMimeAssembler assembler, SilcMime partial);
 *
 * DESCRIPTION
 *
 *    Processes and attempts to assemble the received MIME fragment `partial'.
 *    To check if a received MIME message is a fragment use the
 *    silc_mime_is_partial function.  The callback that was given as argument
 *    to the function silc_mime_assembler_alloc will be called when all
 *    fragments has been received, to deliver the complete MIME message.
 *    Caller must not free the `partial'.
 *
 * EXAMPLE
 *
 *    // Assemble received MIME fragment
 *    mime = silc_mime_parse(data, data_len);
 *    if (silc_mime_is_partial(mime) == TRUE)
 *      silc_mime_assmeble(assembler, mime);
 *
 ***/
void silc_mime_assemble(SilcMimeAssembler assembler, SilcMime partial);

/****f* silcutil/SILCMIMEAPI/silc_mime_encode_partial
 *
 * SYNOPSIS
 *
 *    SilcDList silc_mime_encode_partial(SilcMime mime, int max_size);
 *
 * DESCRIPTION
 *
 *    Same as silc_mime_encode except fragments the MIME message `mime'
 *    if it is larger than `max_size' in bytes.  Returns the MIME fragments
 *    in SilcDList where each entry is SilcBuffer context.  The caller must
 *    free the returned list and all SilcBuffer entries in it by calling
 *    silc_mime_partial_free function.
 *
 *    To assemble the fragments into a complete MIME message the
 *    silc_mime_assemble can be used.
 *
 ***/
SilcDList silc_mime_encode_partial(SilcMime mime, int max_size);

/****f* silcutil/SILCMIMEAPI/silc_mime_partial_free
 *
 * SYNOPSIS
 *
 *    void silc_mime_partial_free(SilcDList partials);
 *
 * DESCRIPTION
 *
 *    This function must be called to free the list returned by the
 *    silc_mime_encode_partial function.
 *
 ***/
void silc_mime_partial_free(SilcDList partials);

/****f* silcutil/SILCMIMEAPI/silc_mime_add_field
 *
 * SYNOPSIS
 *
 *    void silc_mime_add_field(SilcMime mime,
 *                             const char *field, const char *value);
 *
 * DESCRIPTION
 *
 *    Adds a field indicated by `field' to MIME message `mime'.  The field
 *    value is `value'.
 *
 * EXAMPLE
 *
 *    silc_mime_add_field(mime, "MIME-Version", "1.0");
 *    silc_mime_add_field(mime, "Content-Type", "image/jpeg");
 *    silc_mime_add_field(mime, "Content-Transfer-Encoding", "binary");
 *
 ***/
void silc_mime_add_field(SilcMime mime, const char *field, const char *value);

/****f* silcutil/SILCMIMEAPI/silc_mime_get_field
 *
 * SYNOPSIS
 *
 *    const char *silc_mime_get_field(SilcMime mime, const char *field);
 *
 * DESCRIPTION
 *
 *    Returns the `field' value or NULL if such field does not exist in the
 *    MIME message `mime'.
 *
 ***/
const char *silc_mime_get_field(SilcMime mime, const char *field);

/****f* silcutil/SILCMIMEAPI/silc_mime_add_data
 *
 * SYNOPSIS
 *
 *    void silc_mime_add_data(SilcMime mime, const unsigned char *data,
 *                            SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Adds the actual MIME data to the `mime' message.
 *
 ***/
void silc_mime_add_data(SilcMime mime, const unsigned char *data,
				    SilcUInt32 data_len);

/****f* silcutil/SILCMIMEAPI/silc_mime_get_data
 *
 * SYNOPSIS
 *
 *    const unsigned char *
 *    silc_mime_get_data(SilcMime mime, SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Returns the MIME data from the `mime' message.
 *
 ***/
const unsigned char *silc_mime_get_data(SilcMime mime, SilcUInt32 *data_len);

/****f* silcutil/SILCMIMEAPI/silc_mime_is_partial
 *
 * SYNOPSIS
 *
 *    bool silc_mime_is_partial(SilcMime mime);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the MIME message `mime' is a partial MIME fragment.
 *
 ***/
bool silc_mime_is_partial(SilcMime mime);

/****f* silcutil/SILCMIMEAPI/silc_mime_set_multipart
 *
 * SYNOPSIS
 *
 *    void silc_mime_set_multipart(SilcMime mime, const char *type,
 *                                 const char *boundary);
 *
 * DESCRIPTION
 *
 *    Sets the `mime' to be a multipart MIME message.  The `type' specifies
 *    the multipart type, usually "mixed", but can be something else too.
 *    The `boundary' specifies the multipart boundary.
 *
 ***/
void silc_mime_set_multipart(SilcMime mime, const char *type,
					    const char *boundary);

/****f* silcutil/SILCMIMEAPI/silc_mime_add_multipart
 *
 * SYNOPSIS
 *
 *    bool silc_mime_add_multipart(SilcMime mime, SilcMime part);
 *
 * DESCRIPTION
 *
 *    Adds a multipart `part` to MIME message `mime'.  The `part' will be
 *    freed automatically when silc_mime_free is called for `mime'.  Returns
 *    TRUE if `part' was added to `mime' and FALSE if `mime' is not marked
 *    as multipart MIME message.
 *
 * NOTES
 *
 *    The silc_mime_set_multipart must be called for `mime' before parts
 *    can be added to it.  Otherwise FALSE will be returned.
 *
 * EXAMPLE
 *
 *    part = silc_mime_alloc();
 *    silc_mime_add_field(part, "Content-Type", "image/jpeg");
 *    silc_mime_add_data(part, data, data_len);
 *
 *    silc_mime_set_multipart(mime, "mixed", "boundary1");
 *    silc_mime_add_multipart(mime, part);
 *
 ***/
bool silc_mime_add_multipart(SilcMime mime, SilcMime part);

/****f* silcutil/SILCMIMEAPI/silc_mime_is_multipart
 *
 * SYNOPSIS
 *
 *    bool silc_mime_is_multipart(SilcMime mime);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the MIME message `mime' is a multipart MIME message.
 *    Its parts can be get by calling silc_mime_get_multiparts.
 *
 ***/
bool silc_mime_is_multipart(SilcMime mime);

/****f* silcutil/SILCMIMEAPI/silc_mime_get_multiparts
 *
 * SYNOPSIS
 *
 *    SilcDList silc_mime_get_multiparts(SilcMime mime);
 *
 * DESCRIPTION
 *
 *    Returns list of the parts from the MIME message `mime'.  Each entry
 *    in the list is SilcMime context.  The caller must not free the returned
 *    list or the SilcMime contexts in the list.  Returns NULL if no parts
 *    exists in the MIME message.
 *
 ***/
SilcDList silc_mime_get_multiparts(SilcMime mime);

#endif /* SILCMIME_H */
