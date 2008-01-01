/*

  silcbuffmt.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2008 Pekka Riikonen

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
 * It also provides many advanced features like calling user specified
 * encoder and decoder functions that are free to do anything to the buffer.
 * The API also provides powerful regular expression matching capabilities
 * within the buffer, enabling caller to not only match regular expressions
 * but to make the API behave like Stream Editor (Sed) and Awk.  The buffer
 * can be matched against regular expression and then edited.  Caller can
 * do anything they want to the buffer after a match.  The SILC_STR_REGEX
 * macro provides many different flags that can change the behavior of the
 * matching, with capabilities to also mimic Sed behavior.
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
 * // sed 's/foo/bar/', replace first foo with bar
 * silc_buffer_format(buffer,
 *                    SILC_STR_REGEX("foo", 0),
 *                      SILC_STR_STRING("bar"),
 *                    SILC_STR_END, SILC_STR_END);
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

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_STRING
 *
 * NAME
 *
 *    #define SILC_STR_STRING() ...
 *
 * DESCRIPTION
 *
 *    Encode NULL terminated string.  Use this only for formatting.
 *
 *    Formatting:  SILC_STR_STRING(char *)
 *
 *    For unformatting use one of the SILC_STR_*_STRING macros, which
 *    automatically gets the length of the string from the buffer.  Note
 *    SILC_STR_STRING does not save the length of the string into the buffer.
 *    The caller must do that in order for the unformatting macros to work.
 *
 *    Example:
 *
 *    Formatting:    ..., SILC_STR_UINT32(strlen(string)),
 *                        SILC_STR_STRING(string), ...
 *    Unformatting:  ..., SILC_STR_UI32_STRING(&string), ...
 *
 ***/
#define SILC_STR_STRING(x) SILC_PARAM_UI8_STRING, (x)

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
 *    length as UINT32 or UINT16 or UINT8 into the buffer *before* formatting
 *    the actual string to the buffer, and, in unformatting one ignores the
 *    length of the string because unformatting procedure will take it
 *    automatically.
 *
 *    Example:
 *
 *    Formatting:    ..., SILC_STR_UINT32(strlen(string)),
 *                        SILC_STR_UI32_STRING(string), ...
 *    Unformatting:  ..., SILC_STR_UI32_STRING(&string), ...
 *
 *    I.e., you can ignore the formatted length field in unformatting.
 *
 *    UI8, UI16 and UI32 means that the length is considered to be
 *    either UINT8, UINT16 or UINT32 in unformatting.
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
 *    length as UINT32 or UINT16 or UINT8 into the buffer *before* formatting
 *    the actual string to the buffer, and, in unformatting one ignores the
 *    length of the string because unformatting procedure will take it
 *    automatically.
 *
 *     Example:
 *
 *     Formatting:    ..., SILC_STR_UINT32(strlen(string)),
 *                         SILC_STR_UI32_NSTRING(string, strlen(string)), ...
 *     Unformatting:  ..., SILC_STR_UI32_NSTRING(&string, &len), ...
 *
 *    I.e., you can ignore the formatted length field in unformatting. The
 *    length taken from the buffer is returned to the pointer sent as
 *    argument (&len in above example).
 *
 *    UI8, UI16 and UI32 means that the length is considered to be
 *    either UINT8, UINT16 or UINT32 in unformatting.
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
 *    Formatting and unformatting of arbitrary data.
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

/****d* silcutil/SilcBufferFormatAPI/SilcBufferRegexFlags
 *
 * NAME
 *
 *    typedef enum { ... } SilcBufferRegexFlags;
 *
 * DESCRIPTION
 *
 *    Regular expression flags for SILC_STR_REGEX macro.  The flags can be
 *    used to manipulate the behavior of the SILC_STR_REGEX.  All flags
 *    may be combined unless otherwise stated.
 *
 * SOURCE
 */
typedef enum {
  SILC_STR_REGEX_NONE                 = 0x00000000,

  /* By default mismatch will be skipped.  Set this flag if mismatch should
     cause error and stopping of the formatting/unformatting. */
  SILC_STR_REGEX_MISMATCH             = 0x00000001,

  /* By default only the first match is found.  Set this flag to find
     all matches. */
  SILC_STR_REGEX_ALL                  = 0x00000002,

  /* By default the buffer position is advanced to the position of the
     first match.  Set this flag if the buffer should not be advanced to
     the match. */
  SILC_STR_REGEX_NO_ADVANCE           = 0x00000004,

  /* By default SILC_STR_REGEX performs the match on the whole buffer.  Set
     this flag to make it behave like sed and match line by line.  Each line
     must end with '\n'.  If buffer doesn't have '\n' it is considered to be
     one line.  Note that, any formatting done immediately after SILC_STR_REGEX
     block with this flag will be formatted to the end of the buffer (after
     last line).  Use SILC_STR_OFFSET* macros to change the position if
     needed.  Also note that, any encoding macro inside the SILC_STR_REGEX
     block will see only the matched line (including '\n'), instead of whole
     buffer after the match. */
  SILC_STR_REGEX_NL                   = 0x00000008,

  /* Set this flag to not match the regular expression, but to match everything
     else.  When combined with SILC_STR_REGEX_NL this flag matches all other
     lines except the ones with matching regular expression. */
  SILC_STR_REGEX_NOT                  = 0x00000010,

  /* By default the buffer is advanced to the first match and the rest of the
     buffer remains as is.  Set this flag to pass the exact match to the
     SILC_STR_* macros in the SILC_STR_REGEX block; macros see the start of
     the match and the end of the match, but not rest of the buffer (ie. with
     match 'foo' the size of the buffer is 3 bytes). */
  SILC_STR_REGEX_INCLUSIVE            = 0x00000020,
} SilcBufferRegexFlags;
/***/

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_REGEX
 *
 * NAME
 *
 *    #define SILC_STR_REGEX() ...
 *
 * DESCRIPTION
 *
 *    Regular expression matching within the buffer.
 *
 *    Formatting:    SILC_STR_REGEX(char *regex, SilcBufferRegexFlags flags)
 *    Unformatting:  SILC_STR_REGEX(char *regex, SilcBufferRegexFlags flags)
 *
 *    SILC_STR_REGEX can be used to do regular expression matching within
 *    the SilcBuffer.  When the string in the buffer matches the regular
 *    expression the position of the buffer is advanced to the position of
 *    the first match (rest of the buffer remains intact).  If the regular
 *    expression does not match it is skipped, unless the flags specify
 *    otherwise.  If flags are not needed they can be set to 0.
 *
 *    In addition of matching regular expressions it can be used in a
 *    Stream Editor (sed) and Awk like fashion.  The regular expression can be
 *    matched and then edited by any of the SILC_STR_* macros.  The flags
 *    can be used to perform complex operations on the data.  Some sed
 *    features that cannot be directly done with the flags can be done with
 *    SILC_STR_FUNC and other macros (the SILC_STR_FUNC could do anything
 *    after the match).
 *
 *    The SILC_STR_REGEX itself is used as an opening of a block of encoding
 *    macros and must be closed with SILC_STR_END.  This means that for
 *    each SILC_STR_REGEX there must be one SILC_STR_END.  See examples for
 *    more information.
 *
 *    The SILC_STR_REGEX can be used in buffer unformatting also to do
 *    string matching and parsing, but not editing, except with SILC_STR_FUNC
 *    macro, which can do anything caller wants.
 *
 * EXAMPLE
 *
 *    // sed 's/foo/bar/', replace first foo with bar
 *    silc_buffer_format(buffer,
 *                       SILC_STR_REGEX("foo", 0),
 *                         SILC_STR_STRING("bar"),
 *                       SILC_STR_END, SILC_STR_END);
 *
 *    // sed 's/foo/bar/g', replace all foo's with bar
 *    silc_buffer_format(buffer,
 *                       SILC_STR_REGEX("foo", SILC_STR_REGEX_ALL),
 *                         SILC_STR_STRING("bar"),
 *                       SILC_STR_END, SILC_STR_END);
 *
 *    // sed '/baz/s/foo/bar/g, replace all foo's with bar on lines with baz
 *    silc_buffer_format(buffer,
 *                       SILC_STR_REGEX("baz", SILC_STR_REGEX_NL),
 *                         SILC_STR_REGEX("foo", SILC_STR_REGEX_ALL),
 *                           SILC_STR_STRING("bar"),
 *                         SILC_STR_END,
 *                       SILC_STR_END, SILC_STR_END);
 *
 *    // Print all lines that start with 'R'
 *    int print(SilcStack stack, SilcBuffer buf, void *value, void *context)
 *    {
 *      return fwrite(silc_buffer_data(buf), 1, silc_buffer_len(buf), stdout);
 *    }
 *
 *    silc_buffer_unformat(buffer,
 *                         SILC_STR_REGEX("^R", SILC_STR_REGEX_NL),
 *                           SILC_STR_FUNC(print, NULL, NULL),
 *                         SILC_STR_END, SILC_STR_END);
 *
 ***/
#define SILC_STR_REGEX(regex, flags) SILC_PARAM_REGEX, (regex), (flags)

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

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_OFFSET_START
 *
 * NAME
 *
 *    #define SILC_STR_OFFSET_START ...
 *
 * DESCRIPTION
 *
 *    Moves the buffer position to the start of the data area.
 *
 *    Example:
 *
 *    ..., SILC_STR_OFFSET_START, ...
 *
 ***/
#define SILC_STR_OFFSET_START SILC_PARAM_OFFSET_START

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_OFFSET_END
 *
 * NAME
 *
 *    #define SILC_STR_OFFSET_END ...
 *
 * DESCRIPTION
 *
 *    Moves the buffer position to the end of the data area.
 *
 *    Example:
 *
 *    ..., SILC_STR_OFFSET_END, ...
 *
 ***/
#define SILC_STR_OFFSET_END SILC_PARAM_OFFSET_END

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
