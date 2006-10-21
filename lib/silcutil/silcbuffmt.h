/*

  silcbuffmt.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Buffer Format Interface
 *
 * DESCRIPTION
 *
 * SILC Buffer Format API provides functions for formatting different data
 * types into a buffer and retrieving different data types from a buffer
 * into specified data types.  It is especially useful to format packets,
 * protocol payloads and such.
 *
 ***/

#ifndef SILCBUFFMT_H
#define SILCBUFFMT_H

/* Prototypes */

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_format
 *
 * SYNOPSIS
 *
 *    int silc_buffer_format(SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *    Formats a buffer from a variable argument list.  Returns -1 on error
 *    and the length of the formatted buffer otherwise.  The buffer is
 *    enlarged automatically during formatting, if it doesn't already have
 *    enough space.
 *
 * EXAMPLE
 *
 *    SilcBufferStruct buffer;
 *    SilcBuffer buf;
 *
 *    memset(&buffer, 0, sizeof(buffer));
 *    ret = silc_buffer_format(&buffer,
 *                             SILC_STR_INT(intval),
 *                             SILC_STR_CHAR(charval),
 *                             SILC_STR_INT(intval),
 *                             SILC_STR_SHORT(str_len),
 *                             SILC_STR_UI_XNSTRING(str, str_len),
 *                             SILC_STR_END);
 *    if (ret < 0)
 *      error;
 *
 *    // Free the allocated data
 *    silc_buffer_purge(&buffer);
 *
 *    // Allocate zero size buffer
 *    buf = silc_buffer_alloc(0);
 *    ret = silc_buffer_format(buf,
 *                             SILC_STR_INT(intval),
 *                             SILC_STR_CHAR(charval),
 *                             SILC_STR_END);
 *
 *    // Free the allocated buffer
 *    silc_buffer_free(buf);
 *
 ***/
int silc_buffer_format(SilcBuffer dst, ...);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_sformat
 *
 * SYNOPSIS
 *
 *    int silc_buffer_sformat(SilcStack stack, SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_format but uses `stack' to allocate the memory.
 *    if `stack' is NULL reverts back to silc_buffer_format call.
 *
 ***/
int silc_buffer_sformat(SilcStack stack, SilcBuffer dst, ...);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_format_vp
 *
 * SYNOPSIS
 *
 *    int silc_buffer_format_vp(SilcBuffer dst, va_list vp);
 *
 * DESCRIPTION
 *
 *    Formats a buffer from a variable argument list indicated by the `ap'.
 *    Returns -1 on error and the length of the formatted buffer otherwise.
 *
 ***/
int silc_buffer_format_vp(SilcBuffer dst, va_list ap);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_format_vp
 *
 * SYNOPSIS
 *
 *    int silc_buffer_format_vp(SilcBuffer dst, va_list vp);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_format_vp but uses `stack' to allocate the memory.
 *    if `stack' is NULL reverts back to silc_buffer_format_vp call.
 *
 ***/
int silc_buffer_sformat_vp(SilcStack stack, SilcBuffer dst, va_list ap);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_unformat
 *
 * SYNOPSIS
 *
 *    int silc_buffer_unformat(SilcBuffer src, ...);
 *
 * DESCRIPTION
 *
 *    Unformats a buffer from a variable argument list.  Returns -1 on error
 *    and the length of the unformatted buffer otherwise.
 *
 * EXAMPLE
 *
 *    ret = silc_buffer_unformat(buffer,
 *                               SILC_STR_INT(&intval),
 *                               SILC_STR_CHAR(&charval),
 *                               SILC_STR_OFFSET(4),
 *                               SILC_STR_UI16_NSTRING_ALLOC(&str, &str_len),
 *                               SILC_STR_END);
 *    if (ret < 0)
 *      error;
 *
 ***/
int silc_buffer_unformat(SilcBuffer src, ...);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_unformat_vp
 *
 * SYNOPSIS
 *
 *    int silc_buffer_unformat_vp(SilcBuffer src, va_list vp);
 *
 * DESCRIPTION
 *
 *    Unformats a buffer from a variable argument list indicated by the `ap'.
 *    Returns -1 on error and the length of the unformatted buffer otherwise.
 *
 ***/
int silc_buffer_unformat_vp(SilcBuffer src, va_list ap);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_strformat
 *
 * SYNOPSIS
 *
 *   int silc_buffer_strformat(SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *   Formats a buffer from variable argument list of strings.  Each
 *   string must be NULL-terminated and the variable argument list must
 *   be end with SILC_STR_END argument.  This allows that a string in
 *   the list can be NULL, in which case it is skipped.  This automatically
 *   allocates the space for the buffer data but `dst' must be already
 *   allocated by the caller.
 *
 * EXAMPLE
 *
 *    ret = silc_buffer_strformat(buffer, "foo", "bar", SILC_STRFMT_END);
 *    if (ret < 0)
 *      error;
 *
 ***/
int silc_buffer_strformat(SilcBuffer dst, ...);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_sstrformat
 *
 * SYNOPSIS
 *
 *   int silc_buffer_strformat(SilcStack stack, SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *   Formats a buffer from variable argument list of strings.  Each
 *   string must be NULL-terminated and the variable argument list must
 *   be end with SILC_STR_END argument.  This allows that a string in
 *   the list can be NULL, in which case it is skipped.  This automatically
 *   allocates the space for the buffer data but `dst' must be already
 *   allocated by the caller.  This function is equivalent to
 *   silc_buffer_strformat but allocates memory from `stack'.
 *
 ***/
int silc_buffer_sstrformat(SilcStack stack, SilcBuffer dst, ...);

/* Macros for expanding parameters into variable function argument list.
   These are passed to silc_buffer_format and silc_buffer_unformat
   functions. */

/* Buffer parameter types.

   _SI_ = signed
   _UI_ = unsigned

  Any XXX_STRING_ALLOC types will allocate space for the data and
  memcpy the data to the pointer sent as argument (in unformatting).

  Any XXX_STRING will not allocate or copy any data.  Instead it
  will set the pointer to the data.  Note that the data pointer
  returned (in unformatting) must not be freed.

*/
typedef enum {
  SILC_BUFFER_PARAM_SI8_CHAR,
  SILC_BUFFER_PARAM_UI8_CHAR,

  SILC_BUFFER_PARAM_SI16_SHORT,
  SILC_BUFFER_PARAM_UI16_SHORT,

  SILC_BUFFER_PARAM_SI32_INT,
  SILC_BUFFER_PARAM_UI32_INT,

  SILC_BUFFER_PARAM_SI64_INT,
  SILC_BUFFER_PARAM_UI64_INT,

  SILC_BUFFER_PARAM_UI8_STRING,         /* No copy */
  SILC_BUFFER_PARAM_UI8_STRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_UI16_STRING,        /* No copy */
  SILC_BUFFER_PARAM_UI16_STRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_UI32_STRING,	/* No copy */
  SILC_BUFFER_PARAM_UI32_STRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_UI8_NSTRING,	/* No copy */
  SILC_BUFFER_PARAM_UI8_NSTRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_UI16_NSTRING,	/* No copy */
  SILC_BUFFER_PARAM_UI16_NSTRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_UI32_NSTRING,	/* No copy */
  SILC_BUFFER_PARAM_UI32_NSTRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_UI_XNSTRING,	/* No copy */
  SILC_BUFFER_PARAM_UI_XNSTRING_ALLOC,	/* Alloc + memcpy */
  SILC_BUFFER_PARAM_DATA,	        /* No copy */
  SILC_BUFFER_PARAM_DATA_ALLOC,		/* Alloc + memcpy */

  SILC_BUFFER_PARAM_OFFSET,
  SILC_BUFFER_PARAM_ADVANCE,

  SILC_BUFFER_PARAM_END
} SilcBufferParamType;

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_CHAR
 *
 * NAME
 *
 *    #define SILC_STR_UI_CHAR() ...
 *    #define SILC_STR_SI_CHAR() ...
 *
 * DESCRIPTION
 *
 *    One signed/unsigned character.
 *
 *    Formatting:    SILC_STR_SI_CHAR(char)
 *                   SILC_STR_UI_CHAR(unsigned char)
 *    Unformatting:  SILC_STR_SI_CHAR(char *)
 *                   SILC_STR_UI_CHAR(unsigned char *)
 *
 ***/
#define SILC_STR_SI_CHAR(x) SILC_BUFFER_PARAM_SI8_CHAR, (x)
#define SILC_STR_UI_CHAR(x) SILC_BUFFER_PARAM_UI8_CHAR, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_SHORT
 *
 * NAME
 *
 *    #define SILC_STR_UI_SHORT() ...
 *    #define SILC_STR_SI_SHORT() ...
 *
 * DESCRIPTION
 *
 *    Signed/SilcUInt16.
 *
 *    Formatting:    SILC_STR_SI_SHORT(short)
 *                   SILC_STR_UI_SHORT(SilcUInt16)
 *    Unformatting:  SILC_STR_SI_SHORT(short *)
 *                   SILC_STR_UI_SHORT(SilcUInt16 *)
 *
 ***/
#define SILC_STR_SI_SHORT(x) SILC_BUFFER_PARAM_SI16_SHORT, (x)
#define SILC_STR_UI_SHORT(x) SILC_BUFFER_PARAM_UI16_SHORT, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_INT
 *
 * NAME
 *
 *    #define SILC_STR_UI_INT() ...
 *    #define SILC_STR_SI_INT() ...
 *
 * DESCRIPTION
 *
 *    Signed/SilcUInt32.
 *
 *    Formatting:    SILC_STR_SI_INT(int)
 *                   SILC_STR_UI_INT(SilcUInt32)
 *    Unformatting:  SILC_STR_SI_INT(int *)
 *                   SILC_STR_UI_INT(SilcUInt32 *)
 *
 ***/
#define SILC_STR_SI_INT(x) SILC_BUFFER_PARAM_SI32_INT, (x)
#define SILC_STR_UI_INT(x) SILC_BUFFER_PARAM_UI32_INT, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_INT64
 *
 * NAME
 *
 *    #define SILC_STR_UI_INT64() ...
 *    #define SILC_STR_SI_INT64() ...
 *
 * DESCRIPTION
 *
 *    Signed/SilcUInt64.
 *
 *     Formatting:    SILC_STR_SI_INT64(int)
 *                    SILC_STR_UI_INT64(SilcUInt32)
 *     Unformatting:  SILC_STR_SI_INT64(int *)
 *                    SILC_STR_UI_INT64(SilcUInt32 *)
 *
 ***/
#define SILC_STR_SI_INT64(x) SILC_BUFFER_PARAM_SI64_INT, (x)
#define SILC_STR_UI_INT64(x) SILC_BUFFER_PARAM_UI64_INT, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_STRING
 *
 * NAME
 *
 *    #define SILC_STR_UI8_STRING() ...
 *    #define SILC_STR_UI8_STRING_ALLOC() ...
 *    #define SILC_STR_UI16_STRING() ...
 *    #define SILC_STR_UI16_STRING_ALLOC() ...
 *    #define SILC_STR_UI32_STRING() ...
 *    #define SILC_STR_UI32_STRING_ALLOC() ...
 *
 * DESCRIPTION
 *
 *    Unsigned NULL terminated string. Note that the string must be
 *    NULL terminated because strlen() will be used to get the length of
 *    the string.
 *
 *    Formatting:    SILC_STR_UI32_STRING(unsigned char *)
 *    Unformatting:  SILC_STR_UI32_STRING(unsigned char **)
 *
 *    Unformatting procedure will check for length of the string from the
 *    buffer before trying to get the string out. Thus, one *must* format the
 *    length as UI_INT or UI_SHORT into the buffer *before* formatting the
 *    actual string to the buffer, and, in unformatting one must ignore the
 *    length of the string because unformatting procedure will take it
 *    automatically.
 *
 *    Example:
 *
 *    Formatting:    ..., SILC_STR_UI_INT(strlen(string)),
 *                        SILC_STR_UI32_STRING(string), ...
 *    Unformatting:  ..., SILC_STR_UI32_STRING(&string), ...
 *
 *    I.e., you can ignore the formatted length field in unformatting.
 *
 *    UI8, UI16 and UI32 means that the length is considered to be
 *    either char (8 bits), short (16 bits) or int (32 bits) in
 *    unformatting.
 *
 *    _ALLOC routines automatically allocates memory for the variable sent
 *    as argument in unformatting.
 *
 ***/
#define SILC_STR_UI8_STRING(x) SILC_BUFFER_PARAM_UI8_STRING, (x)
#define SILC_STR_UI8_STRING_ALLOC(x) SILC_BUFFER_PARAM_UI8_STRING_ALLOC, (x)
#define SILC_STR_UI16_STRING(x) SILC_BUFFER_PARAM_UI16_STRING, (x)
#define SILC_STR_UI16_STRING_ALLOC(x) SILC_BUFFER_PARAM_UI16_STRING_ALLOC, (x)
#define SILC_STR_UI32_STRING(x) SILC_BUFFER_PARAM_UI32_STRING, (x)
#define SILC_STR_UI32_STRING_ALLOC(x) SILC_BUFFER_PARAM_UI32_STRING_ALLOC, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_NSTRING
 *
 * NAME
 *
 *    #define SILC_STR_UI8_NSTRING() ...
 *    #define SILC_STR_UI8_NSTRING_ALLOC() ...
 *    #define SILC_STR_UI16_NSTRING() ...
 *    #define SILC_STR_UI16_NSTRING_ALLOC() ...
 *    #define SILC_STR_UI32_NSTRING() ...
 *    #define SILC_STR_UI32_NSTRING_ALLOC() ...
 *
 * DESCRIPTION
 *
 *    Unsigned string. Second argument is the length of the string.
 *
 *    Formatting:    SILC_STR_UI32_NSTRING(unsigned char *, SilcUInt32)
 *    Unformatting:  SILC_STR_UI32_NSTRING(unsigned char **, SilcUInt32 *)
 *
 *    Unformatting procedure will check for length of the string from the
 *    buffer before trying to get the string out. Thus, one *must* format the
 *    length as UI_INT or UI_SHORT into the buffer *before* formatting the
 *    actual string to the buffer, and, in unformatting one must ignore the
 *    length of the string because unformatting procedure will take it
 *    automatically.
 *
 *     Example:
 *
 *     Formatting:    ..., SILC_STR_UI_INT(strlen(string)),
 *                         SILC_STR_UI32_NSTRING(string, strlen(string)), ...
 *     Unformatting:  ..., SILC_STR_UI32_NSTRING(&string, &len), ...
 *
 *    I.e., you can ignore the formatted length field in unformatting. The
 *    length taken from the buffer is returned to the pointer sent as
 *    argument (&len in above example).
 *
 *    UI8, UI16 and UI32 means that the length is considered to be
 *    either char (8 bits), short (16 bits) or int (32 bits) in
 *    unformatting.
 *
 *    _ALLOC routines automatically allocates memory for the variable sent
 *    as argument in unformatting.
 *
 ***/
#define SILC_STR_UI8_NSTRING(x, l) SILC_BUFFER_PARAM_UI8_NSTRING, (x), (l)
#define SILC_STR_UI8_NSTRING_ALLOC(x, l) \
  SILC_BUFFER_PARAM_UI8_NSTRING_ALLOC, (x), (l)
#define SILC_STR_UI16_NSTRING(x, l) SILC_BUFFER_PARAM_UI16_NSTRING, (x), (l)
#define SILC_STR_UI16_NSTRING_ALLOC(x, l) \
  SILC_BUFFER_PARAM_UI16_NSTRING_ALLOC, (x), (l)
#define SILC_STR_UI32_NSTRING(x, l) SILC_BUFFER_PARAM_UI32_NSTRING, (x), (l)
#define SILC_STR_UI32_NSTRING_ALLOC(x, l) \
  SILC_BUFFER_PARAM_UI32_NSTRING_ALLOC, (x), (l)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_DATA
 *
 * NAME
 *
 *    #define SILC_STR_DATA() ...
 *    #define SILC_STR_DATA_ALLOC() ...
 *
 * DESCRIPTION
 *
 *    Binary data formatting.  Second argument is the lenght of the data.
 *
 *    Formatting:    SILC_STR_DATA(unsigned char *, SilcUInt32)
 *    Unformatting:  SILC_STR_DATA(unsigned char **, SilcUInt32)
 *
 *    This type can be used to take arbitrary size data block from the buffer
 *    by sending the requested amount of bytes as argument.
 *
 *    _ALLOC routines automatically allocates memory for the variable sent
 *    as argument in unformatting.
 *
 ***/
#define SILC_STR_DATA(x, l) SILC_BUFFER_PARAM_DATA, (x), (l)
#define SILC_STR_DATA_ALLOC(x, l) \
  SILC_BUFFER_PARAM_DATA_ALLOC, (x), (l)

/* Deprecated */
#define SILC_STR_UI_XNSTRING(x, l) SILC_BUFFER_PARAM_UI_XNSTRING, (x), (l)
#define SILC_STR_UI_XNSTRING_ALLOC(x, l) \
  SILC_BUFFER_PARAM_UI_XNSTRING_ALLOC, (x), (l)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_OFFSET
 *
 * NAME
 *
 *    #define SILC_STR_OFFSET() ...
 *
 * DESCRIPTION
 *
 *    Offset in buffer.  This can be used in formatting and unformatting to
 *    move the data pointer of the buffer either forwards (positive offset)
 *    or backwards (negative offset).  It can be used to for example skip
 *    some types during unformatting.
 *
 *    Example:
 *
 *    ..., SILC_STR_OFFSET(5), ...
 *    ..., SILC_STR_OFFSET(-3), ...
 *
 *    Moves the data pointer at the point of the offset either forward
 *    or backward and then moves to the next type.  Multiple SILC_STR_OFFSETs
 *    can be used in formatting and unformatting at the same time.
 *
 ***/
#define SILC_STR_OFFSET(x) SILC_BUFFER_PARAM_OFFSET, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_ADVANCE
 *
 * NAME
 *
 *    #define SILC_STR_ADVANCE ...
 *
 * DESCRIPTION
 *
 *    Advance the buffer to the end of the data after the formatting is
 *    done.  In normal operation when the formatted data is written the
 *    buffer is located at the start of the data.  With SILC_STR_ADVANCE
 *    the buffer will be located at the end of the data.  This makes it
 *    easy to add new data immediately after the previously added data.
 *
 * EXAMPLE
 *
 *    do {
 *      len = read(fd, buf, sizeof(buf));
 *      if (len > 0)
 *        // Add read data to the buffer
 *        silc_buffer_format(buffer,
 *                           SILC_STR_ADVANCE,
 *                           SILC_STR_UI_XNSTRING(buf, len),
 *                           SILC_STR_END);
 *    } while (len > 0);
 *
 *    // Move to beginning of buffer
 *    silc_buffer_push(buffer, silc_buffer_truelen(buffer));
 *
 ***/
#define SILC_STR_ADVANCE SILC_BUFFER_PARAM_ADVANCE

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_END
 *
 * NAME
 *
 *    #define SILC_STR_END ...
 *
 * DESCRIPTION
 *
 *    Marks end of the argument list. This must be at the end of the
 *    argument list or error will occur.
 *
 ***/
#define SILC_STR_END SILC_BUFFER_PARAM_END

/****d* silcutil/SilcBufferFormatAPI/SILC_STRFMT_END
 *
 * NAME
 *
 *    #define SILC_STRFMT_END ...
 *
 * DESCRIPTION
 *
 *    Marks end of the argument list in silc_buffer_strformat function.
 *    This must be at the end of the argument list or error will occur.
 *
 ***/
#define SILC_STRFMT_END (void *)SILC_STR_END

#endif	/* !SILCBUFFMT_H */
