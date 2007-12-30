/*

  silcbuffmt.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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
 * into specified data types.  It is especially useful to encode packets,
 * protocol payloads and such.
 *
 * As the SilcBuffer API is not thread-safe these routines may not be used
 * in multithreaded environment with a same SilcBuffer context without
 * concurrency control.
 *
 * EXAMPLE
 *
 * SilcBufferStruct buffer;
 *
 * memset(&buffer, 0, sizeof(buffer));
 * ret = silc_buffer_format(&buffer,
 *                          SILC_STR_UINT32(intval),
 *                          SILC_STR_UINT8(charval),
 *                          SILC_STR_UINT64(longintval),
 *                          SILC_STR_UINT16(str_len),
 *                          SILC_STR_DATA(str, str_len),
 *                          SILC_STR_END);
 * if (ret < 0)
 *   error;
 *
 ***/

#ifndef SILCBUFFMT_H
#define SILCBUFFMT_H

/****f* silcutil/SilcBufferFormatAPI/SilcBufferFormatFunc
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcBuffeSFormatFunc)(SilcStack stack,
 *                                        SilcBuffer buffer,
 *                                        void *value,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Formatting function callback given with SILC_STR_FUNC type.  The
 *    `buffer' is the buffer being formatted at the location where the
 *    SILC_STR_FUNC was placed in formatting.  The function should call
 *    silc_buffer_senlarge before it adds the data to the buffer to make
 *    sure that it has enough space.  The buffer->head points to the
 *    start of the buffer and silc_buffer_headlen() gives the length
 *    of the currently formatted data area.  It is also possible to use
 *    silc_buffer_sformat with `buffer' which will enlarge the buffer if
 *    needed.
 *
 *    The `value' is the value given to SILC_STR_FUNC that is to be formatted
 *    into the buffer.  It may be NULL if the function is not formatting
 *    new data into the buffer.  The `context' is caller specific context.
 *    Returns -1 on error and length of the formatted value otherwise, and
 *    0 if nothing was formatted.
 *
 ***/
typedef int (*SilcBufferFormatFunc)(SilcStack stack, SilcBuffer buffer,
				    void *value, void *context);

/****f* silcutil/SilcBufferFormatAPI/SilcBufferUnformatFunc
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcBufferUnformatFunc)(SilcBuffer buffer,
 *                                          void **value,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Unformatting function callback given with SILC_STR_FUNC type.  The
 *    `buffer' is the buffer being unformatted and is at the location where
 *    the SILC_STR_FUNC was placed in unformatting.  The function should
 *    check there is enough data in the `buffer' before trying to decode
 *    from it.
 *
 *    If this function unformats anything from the buffer its value is to
 *    be returned to the `value' pointer.  The implementation should itself
 *    decide whether the unformatted value is allocated or not.  If this
 *    function does not unformat anything, nothing is returned to `value'
 *
 *    The `context' is caller specific context.  Returns -1 on error, and
 *    length of the unformatted value otherwise, and 0 if nothing was
 *    unformatted.
 *
 ***/
typedef int (*SilcBufferUnformatFunc)(SilcStack stack, SilcBuffer buffer,
				      void **value, void *context);

/* Prototypes */

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_format
 *
 * SYNOPSIS
 *
 *    int silc_buffer_format(SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *    Formats a buffer from a variable argument list.  Returns -1 if the
 *    system is out of memory and the length of the formatted buffer otherwise.
 *    The buffer is enlarged automatically during formatting, if it doesn't
 *    already have enough space.  Sets silc_errno in case of error.
 *
 * EXAMPLE
 *
 *    Three basic ways of using silc_buffer_format:
 *
 *    // Statically allocated zero size buffer
 *    SilcBufferStruct buffer;
 *
 *    memset(&buffer, 0, sizeof(buffer));
 *    ret = silc_buffer_format(&buffer,
 *                             SILC_STR_UINT32(intval),
 *                             SILC_STR_UINT8(charval),
 *                             SILC_STR_UINT32(intval),
 *                             SILC_STR_UINT16(str_len),
 *                             SILC_STR_DATA(str, str_len),
 *                             SILC_STR_END);
 *    if (ret < 0)
 *      error;
 *
 *    // Free the allocated data
 *    silc_buffer_purge(&buffer);
 *
 *    // Dynamically allocated zero size buffer
 *    SilcBuffer buf;
 *    buf = silc_buffer_alloc(0);
 *    ret = silc_buffer_format(buf,
 *                             SILC_STR_UINT32(intval),
 *                             SILC_STR_UINT8(charval),
 *                             SILC_STR_END);
 *    if (ret < 0)
 *      error;
 *
 *    // Free the allocated buffer
 *    silc_buffer_free(buf);
 *
 *    // Dynamically allocated buffer with enough space
 *    SilcBuffer buf;
 *    buf = silc_buffer_alloc(2 + str_len);
 *    ret = silc_buffer_format(buf,
 *                             SILC_STR_UINT16(str_len),
 *                             SILC_STR_DATA(str, str_len),
 *                             SILC_STR_END);
 *    if (ret < 0)
 *      error;
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
 *    if `stack' is NULL reverts back to silc_buffer_format call.  Returns
 *    -1 if system is out of memory.  Sets silc_errno in case of error.
 *
 *    Note that this call consumes the `stack'.  The caller should push the
 *    stack before calling the function and pop it later.
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
 *    Returns -1 if system is out of memory and the length of the formatted
 *    buffer otherwise.
 *
 ***/
int silc_buffer_format_vp(SilcBuffer dst, va_list ap);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_sformat_vp
 *
 * SYNOPSIS
 *
 *    int silc_buffer_sformat_vp(SilcStack stack, SilcBuffer dst, va_list vp);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_format_vp but uses `stack' to allocate the memory.
 *    if `stack' is NULL reverts back to silc_buffer_format_vp call.  Returns
 *    -1 if system is out of memory.  Sets silc_errno in case of error.
 *
 *    Note that this call consumes the `stack'.  The caller should push the
 *    stack before calling the function and pop it later.
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
 *    and the length of the unformatted buffer otherwise.  Sets silc_errno
 *    in case of error.
 *
 * EXAMPLE
 *
 *    ret = silc_buffer_unformat(buffer,
 *                               SILC_STR_UINT32(&intval),
 *                               SILC_STR_UINT8(&charval),
 *                               SILC_STR_OFFSET(4),
 *                               SILC_STR_UI16_NSTRING_ALLOC(&str, &str_len),
 *                               SILC_STR_END);
 *    if (ret < 0)
 *      error;
 *
 ***/
int silc_buffer_unformat(SilcBuffer src, ...);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_sunformat
 *
 * SYNOPSIS
 *
 *    int silc_buffer_sunformat(SilcStack stack, SilcBuffer src, ...);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_unformat but uses `stack' to allocate the memory.
 *    if `stack' is NULL reverts back to silc_buffer_format call.
 *
 *    Note that this call consumes the `stack'.  The caller should push the
 *    stack before calling the function and pop it later.
 *
 ***/
int silc_buffer_sunformat(SilcStack stack, SilcBuffer src, ...);

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

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_sunformat_vp
 *
 * SYNOPSIS
 *
 *    int silc_buffer_sunformat_vp(SilcBuffer src, va_list vp);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_unformat_vp but uses `stack' to allocate the
 *    memory.  if `stack' is NULL reverts back to silc_buffer_format_vp call.
 *
 *    Note that this call consumes the `stack'.  The caller should push the
 *    stack before calling the function and pop it later.
 *
 ***/
int silc_buffer_sunformat_vp(SilcStack stack, SilcBuffer src, va_list ap);

/****f* silcutil/SilcBufferFormatAPI/silc_buffer_strformat
 *
 * SYNOPSIS
 *
 *    int silc_buffer_strformat(SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *    Formats a buffer from variable argument list of strings.  Each
 *    string must be NULL-terminated and the variable argument list must
 *    be end with SILC_STRFMT_END argument.  This allows that a string in
 *    the list can be NULL, in which case it is skipped.  This automatically
 *    allocates the space for the buffer data but `dst' must be already
 *    allocated by the caller.  Returns -1 if system is out of memory and
 *    sets silc_errno.
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
 *    int silc_buffer_strformat(SilcStack stack, SilcBuffer dst, ...);
 *
 * DESCRIPTION
 *
 *    Formats a buffer from variable argument list of strings.  Each
 *    string must be NULL-terminated and the variable argument list must
 *    be end with SILC_STRFMT_END argument.  This allows that a string in
 *    the list can be NULL, in which case it is skipped.  This automatically
 *    allocates the space for the buffer data but `dst' must be already
 *    allocated by the caller.  This function is equivalent to
 *    silc_buffer_strformat but allocates memory from `stack'.  Returns -1
 *    if system is out of memory and sets silc_errno.
 *
 *    Note that this call consumes the `stack'.  The caller should push the
 *    stack before calling the function and pop it later.
 *
 ***/
int silc_buffer_sstrformat(SilcStack stack, SilcBuffer dst, ...);

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_SINT8
 *
 * NAME
 *
 *    #define SILC_STR_SINT8() ...
 *
 * DESCRIPTION
 *
 *    One 8-bit signed integer.
 *
 *    Formatting:    SILC_STR_SINT8(SilcInt8)
 *    Unformatting:  SILC_STR_SINT8(SilcInt8 *)
 *
 ***/
#define SILC_STR_SINT8(x) SILC_PARAM_SINT8, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_UINT8
 *
 * NAME
 *
 *    #define SILC_STR_UINT8() ...
 *
 * DESCRIPTION
 *
 *    One 8-bit unsigned integer.
 *
 *    Formatting:    SILC_STR_UINT8(SilcUInt8)
 *    Unformatting:  SILC_STR_UINT8(SilcUInt8 *)
 *
 ***/
#define SILC_STR_UINT8(x) SILC_PARAM_UINT8, (x)

/* Deprecated */
#define SILC_STR_SI_CHAR(x) SILC_PARAM_SINT8, (x)
#define SILC_STR_UI_CHAR(x) SILC_PARAM_UINT8, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_SINT16
 *
 * NAME
 *
 *    #define SILC_STR_SINT16() ...
 *
 * DESCRIPTION
 *
 *    SilcInt16.
 *
 *    Formatting:    SILC_STR_SINT16(SilcInt16)
 *    Unformatting:  SILC_STR_SINT16(SilcInt16 *)
 *
 ***/
#define SILC_STR_SINT16(x) SILC_PARAM_SINT16, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_UINT16
 *
 * NAME
 *
 *    #define SILC_STR_UINT16() ...
 *
 * DESCRIPTION
 *
 *    SilcUInt16.
 *
 *    Formatting:    SILC_STR_UINT16(SilcUInt16)
 *    Unformatting:  SILC_STR_UINT16(SilcUInt16 *)
 *
 ***/
#define SILC_STR_UINT16(x) SILC_PARAM_UINT16, (x)

/* Deprecated */
#define SILC_STR_SI_SHORT(x) SILC_PARAM_SINT16, (x)
#define SILC_STR_UI_SHORT(x) SILC_PARAM_UINT16, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_SINT32
 *
 * NAME
 *
 *    #define SILC_STR_SINT32() ...
 *
 * DESCRIPTION
 *
 *    SilcInt32.
 *
 *    Formatting:    SILC_STR_SINT32(SilcInt32)
 *    Unformatting:  SILC_STR_SINT32(SilcInt32 *)
 *
 ***/
#define SILC_STR_SINT32(x) SILC_PARAM_SINT32, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_UINT32
 *
 * NAME
 *
 *    #define SILC_STR_UINT32() ...
 *
 * DESCRIPTION
 *
 *    SilcUInt32.
 *
 *    Formatting:    SILC_STR_UINT32(SilcUInt32)
 *    Unformatting:  SILC_STR_UINT32(SilcUInt32 *)
 *
 ***/
#define SILC_STR_UINT32(x) SILC_PARAM_UINT32, (x)

/* Deprecated */
#define SILC_STR_SI_INT(x) SILC_PARAM_SINT32, (x)
#define SILC_STR_UI_INT(x) SILC_PARAM_UINT32, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_SINT64
 *
 * NAME
 *
 *    #define SILC_STR_SINT64() ...
 *
 * DESCRIPTION
 *
 *    SilcInt64.
 *
 *    Formatting:    SILC_STR_SINT64(SilcInt64)
 *    Unformatting:  SILC_STR_SINT64(SilcInt64 *)
 *
 ***/
#define SILC_STR_SI_INT64(x) SILC_PARAM_SINT64, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_UINT64
 *
 * NAME
 *
 *    #define SILC_STR_UINT64() ...
 *
 * DESCRIPTION
 *
 *    SilcUInt64.
 *
 *    Formatting:    SILC_STR_UINT64(SilcUInt64)
 *    Unformatting:  SILC_STR_UINT64(SilcUInt64 *)
 *
 ***/
#define SILC_STR_UI_INT64(x) SILC_PARAM_UINT64, (x)

/* Deprecated */
#define SILC_STR_SI_INT64(x) SILC_PARAM_SINT64, (x)
#define SILC_STR_UI_INT64(x) SILC_PARAM_UINT64, (x)

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
#define SILC_STR_UI8_STRING(x) SILC_PARAM_UI8_STRING, (x)
#define SILC_STR_UI8_STRING_ALLOC(x) SILC_PARAM_UI8_STRING | SILC_PARAM_ALLOC, (x)
#define SILC_STR_UI16_STRING(x) SILC_PARAM_UI16_STRING, (x)
#define SILC_STR_UI16_STRING_ALLOC(x) SILC_PARAM_UI16_STRING | SILC_PARAM_ALLOC, (x)
#define SILC_STR_UI32_STRING(x) SILC_PARAM_UI32_STRING, (x)
#define SILC_STR_UI32_STRING_ALLOC(x) SILC_PARAM_UI32_STRING | SILC_PARAM_ALLOC, (x)

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
#define SILC_STR_UI8_NSTRING(x, l) SILC_PARAM_UI8_NSTRING, (x), (l)
#define SILC_STR_UI8_NSTRING_ALLOC(x, l) \
  SILC_PARAM_UI8_NSTRING | SILC_PARAM_ALLOC, (x), (l)
#define SILC_STR_UI16_NSTRING(x, l) SILC_PARAM_UI16_NSTRING, (x), (l)
#define SILC_STR_UI16_NSTRING_ALLOC(x, l) \
  SILC_PARAM_UI16_NSTRING | SILC_PARAM_ALLOC, (x), (l)
#define SILC_STR_UI32_NSTRING(x, l) SILC_PARAM_UI32_NSTRING, (x), (l)
#define SILC_STR_UI32_NSTRING_ALLOC(x, l) \
  SILC_PARAM_UI32_NSTRING | SILC_PARAM_ALLOC, (x), (l)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_DATA
 *
 * NAME
 *
 *    #define SILC_STR_DATA() ...
 *    #define SILC_STR_DATA_ALLOC() ...
 *
 * DESCRIPTION
 *
 *    Binary data formatting.  Second argument is the length of the data.
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
#define SILC_STR_DATA(x, l) SILC_PARAM_UICHAR, (x), (l)
#define SILC_STR_DATA_ALLOC(x, l) SILC_PARAM_UICHAR | SILC_PARAM_ALLOC, (x), (l)

/* Deprecated */
#define SILC_STR_UI_XNSTRING(x, l) SILC_PARAM_UICHAR, (x), (l)
#define SILC_STR_UI_XNSTRING_ALLOC(x, l) SILC_PARAM_UICHAR | SILC_PARAM_ALLOC, (x), (l)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_BUFFER
 *
 * NAME
 *
 *    #define SILC_STR_BUFFER() ...
 *    #define SILC_STR_BUFFER_ALLOC() ...
 *
 * DESCRIPTION
 *
 *    SilcBuffer formatting.
 *
 *    Formatting:    SILC_STR_BUFFER(SilcBuffer)
 *    Unformatting:  SILC_STR_BUFFER(SilcBuffer)
 *
 *    This type can be used to format and unformat SilcBuffer.  Note that, the
 *    length of the buffer will be automatically encoded into the buffer as
 *    a 32-bit integer.  In unformatting the SilcBuffer context must be
 *    pre-allocated.
 *
 *    _ALLOC routines automatically allocates memory inside SilcBuffer in
 *    unformatting.
 *
 ***/
#define SILC_STR_BUFFER(x) SILC_PARAM_BUFFER, (x)
#define SILC_STR_BUFFER_ALLOC(x) SILC_PARAM_BUFFER | SILC_PARAM_ALLOC, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_FUNC
 *
 * NAME
 *
 *    #define SILC_STR_FUNC() ...
 *
 * DESCRIPTION
 *
 *    SilcBuffer formatting.
 *
 *    Formatting:    SILC_STR_FUNC(function, void *value, void *context)
 *    Unformatting:  SILC_STR_FUNC(function, void **value, void *context)
 *
 *    This type can be used to call the `function' of the type
 *    SilcBufferFormatFunc or SilcBufferUnformatFunc to encode or decode
 *    the `value'.  In encoding the `value' will be passed to the `function'
 *    and can be encoded into the buffer.  The buffer will be passed as
 *    well to the `function' at the location where SILC_STR_FUNC is placed
 *    in formatting.  The `context' delivers caller specific context to
 *    the `function'
 *
 *    In unformatting the `function' will decode the encoded type and
 *    return it to `value' pointer.  The decoding function should decide
 *    itself whether to allocate or not the decoded value.
 *
 *    The `function' does not have to encode anything and passing `value'
 *    as NULL is allowed.  The `function' could for example modify the
 *    existing buffer.
 *
 * EXAMPLE
 *
 *    // Encode payload, encrypt and compute MAC.
 *    silc_buffer_format(buf,
 *                       SILC_STR_FUNC(foo_encode_id, id, ctx),
 *                       SILC_STR_UINT16(len),
 *                       SILC_STR_DATA(data, len),
 *                       SILC_STR_FUNC(foo_buf_encrypt, NULL, key),
 *                       SILC_STR_FUNC(foo_buf_hmac, NULL, hmac),
 *                       SILC_STR_DATA(iv, iv_len);
 *                       SILC_STR_END);
 *
 *    // Check MAC, decrypt and decode payload
 *    silc_buffer_unformat(buf,
 *                         SILC_STR_FUNC(foo_buf_hmac, NULL, hmac),
 *                         SILC_STR_FUNC(foo_buf_decrypt, NULL, key),
 *                         SILC_STR_FUNC(foo_decode_id, &id, ctx),
 *                         SILC_STR_UINT16(&len),
 *                         SILC_STR_END);
 *
 ***/
#define SILC_STR_FUNC(func, val, context) SILC_PARAM_FUNC, \
    func, (val), (context)

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
#define SILC_STR_OFFSET(x) SILC_PARAM_OFFSET, (x)

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
 *    buffer is positioned at the start of the data.  With SILC_STR_ADVANCE
 *    the buffer will be positioned at the end of the data.  This makes it
 *    easy to add new data immediately after the previously added data.
 *    The SILC_STR_ADVANCE may also be used in unformatting.
 *
 * EXAMPLE
 *
 *    do {
 *      len = read(fd, buf, sizeof(buf));
 *      if (len > 0)
 *        // Add read data to the buffer
 *        silc_buffer_format(buffer,
 *                           SILC_STR_ADVANCE,
 *                           SILC_STR_DATA(buf, len),
 *                           SILC_STR_END);
 *    } while (len > 0);
 *
 *    // Move to beginning of buffer
 *    silc_buffer_start(buffer);
 *
 ***/
#define SILC_STR_ADVANCE SILC_PARAM_ADVANCE

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
#define SILC_STR_END SILC_PARAM_END

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
