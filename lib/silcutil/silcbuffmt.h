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
 * As the SilcBuffer API is not thread-safe these routines may not be used
 * in multithreaded environment with a same SilcBuffer context without
 * concurrency control.
 *
 ***/

#ifndef SILCBUFFMT_H
#define SILCBUFFMT_H

/****f* silcutil/SilcBufferFormatAPI/SilcBufferFormatFunc
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcBufferFormatFunc)(SilcBuffer buffer,
 *                                        void *value,
 *                                        void *context);
 *
 * DESCRIPTION
 *
 *    Formatting function callback given with SILC_STR_FUNC type.  The
 *    `buffer' is the buffer being formatted at the location where the
 *    SILC_STR_FUNC was placed in formatting.  The function should call
 *    silc_buffer_enlarge before it adds the data to the buffer to make
 *    sure that it has enough space.  The buffer->head points to the
 *    start of the buffer and silc_buffer_headlen() gives the length
 *    of the currently formatted data area.  It is also possible to use
 *    silc_buffer_format with `buffer' which will enlarge the buffer if
 *    needed.
 *
 *    The `value' is the value given to SILC_STR_FUNC that is to be formatted
 *    into the buffer.  It may be NULL if the function is not formatting
 *    new data into the buffer.  The `context' is caller specific context.
 *    Returns -1 on error and length of the formatted value otherwise, and
 *    0 if nothing was formatted.
 *
 ***/
typedef int (*SilcBufferFormatFunc)(SilcBuffer buffer, void *value,
				    void *context);

/****f* silcutil/SilcBufferFormatAPI/SilcBufferSFormatFunc
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcBufferSFormatFunc)(SilcStack stack,
 *                                         SilcBuffer buffer,
 *                                         void *value,
 *                                         void *context);
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
 *    This is same as SilcBufferFormatFunc except the SilcStack will be
 *    delivered.  This callback must be used when SilcStack is used with
 *    formatting.
 *
 ***/
typedef int (*SilcBufferSFormatFunc)(SilcStack stack, SilcBuffer buffer,
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
typedef int (*SilcBufferUnformatFunc)(SilcBuffer buffer, void **value,
				      void *context);

/****f* silcutil/SilcBufferFormatAPI/SilcBufferSUnformatFunc
 *
 * SYNOPSIS
 *
 *    typedef int (*SilcBufferSUnformatFunc)(SilcStack stack,
 *                                           SilcBuffer buffer,
 *                                           void **value,
 *                                           void *context);
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
 *    This is same as SilcBufferUnformatFunc except the SilcStack will be
 *    delivered.  This callback must be used when SilcStack is used with
 *    unformatting.
 *
 ***/
typedef int (*SilcBufferSUnformatFunc)(SilcStack stack, SilcBuffer buffer,
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
 *    Formats a buffer from a variable argument list.  Returns -1 on error
 *    and the length of the formatted buffer otherwise.  The buffer is
 *    enlarged automatically during formatting, if it doesn't already have
 *    enough space.
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
 *                             SILC_STR_UI_INT(intval),
 *                             SILC_STR_CHAR(charval),
 *                             SILC_STR_UI_INT(intval),
 *                             SILC_STR_SHORT(str_len),
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
 *                             SILC_STR_UI_INT(intval),
 *                             SILC_STR_CHAR(charval),
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
 *                             SILC_STR_UI_SHORT(str_len),
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
 *                               SILC_STR_UI_INT(&intval),
 *                               SILC_STR_CHAR(&charval),
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
 ***/
int silc_buffer_sunformat_vp(SilcStack stack, SilcBuffer src, va_list ap);

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

/****d* silcutil/SilcBufferFormatAPI/SilcBufferParamType
 *
 * NAME
 *
 *    typedef enum { ... } SilcBufferParamType;
 *
 * DESCRIPTION
 *
 *    Buffer parameter types.  These are not needed when formatting or
 *    unformatting buffers.  Use the macros such as SILC_STR_UI_CHAR and
 *    others instead.  These types may be used when describing what a
 *    buffer looks like, and how it may be formatted and unformatted.
 *
 * SOURCE
 */
typedef enum {
  SILC_PARAM_SI8_CHAR,		   /* Signed 8-bit char */
  SILC_PARAM_UI8_CHAR,		   /* Unsigned 8-bit char */
  SILC_PARAM_SI16_SHORT,	   /* Signed 16-bit int */
  SILC_PARAM_UI16_SHORT,	   /* Unsigned 16-bit int */
  SILC_PARAM_SI32_INT,		   /* Signed 32-bit int */
  SILC_PARAM_UI32_INT,		   /* Unsigned 32-bit int */
  SILC_PARAM_SI64_INT,		   /* Signed 64-bit int */
  SILC_PARAM_UI64_INT,		   /* Unsigned 64-bit int */
  SILC_PARAM_UI8_STRING,	   /* String (max len 8-bits)*/
  SILC_PARAM_UI16_STRING,	   /* String (max len 16-bits) */
  SILC_PARAM_UI32_STRING,	   /* String (max len 32-bits) */
  SILC_PARAM_BUFFER,		   /* SilcBuffer */

  /* Internal types */
  SILC_PARAM_DATA,		   /* Binary data */
  SILC_PARAM_UI8_NSTRING,	   /* String (max len 8-bits) */
  SILC_PARAM_UI16_NSTRING,	   /* String (max len 16-bits) */
  SILC_PARAM_UI32_NSTRING,	   /* String (max len 32-bits) */
  SILC_PARAM_UI8_STRING_ALLOC,	   /* Alloc + memcpy */
  SILC_PARAM_UI16_STRING_ALLOC,	   /* Alloc + memcpy */
  SILC_PARAM_UI32_STRING_ALLOC,	   /* Alloc + memcpy */
  SILC_PARAM_UI8_NSTRING_ALLOC,	   /* Alloc + memcpy */
  SILC_PARAM_UI16_NSTRING_ALLOC,   /* Alloc + memcpy */
  SILC_PARAM_UI32_NSTRING_ALLOC,   /* Alloc + memcpy */
  SILC_PARAM_DATA_ALLOC,	   /* Alloc + memcpy */
  SILC_PARAM_BUFFER_ALLOC,	   /* Alloc + memcpy */

  SILC_PARAM_OFFSET,
  SILC_PARAM_ADVANCE,
  SILC_PARAM_FUNC,

  SILC_PARAM_UI_XNSTRING,
  SILC_PARAM_UI_XNSTRING_ALLOC,

  SILC_PARAM_END
} SilcBufferParamType;
/***/

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
#define SILC_STR_SI_CHAR(x) SILC_PARAM_SI8_CHAR, (x)
#define SILC_STR_UI_CHAR(x) SILC_PARAM_UI8_CHAR, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_SHORT
 *
 * NAME
 *
 *    #define SILC_STR_UI_SHORT() ...
 *    #define SILC_STR_SI_SHORT() ...
 *
 * DESCRIPTION
 *
 *    SilcInt16/SilcUInt16.
 *
 *    Formatting:    SILC_STR_SI_SHORT(short)
 *                   SILC_STR_UI_SHORT(SilcUInt16)
 *    Unformatting:  SILC_STR_SI_SHORT(short *)
 *                   SILC_STR_UI_SHORT(SilcUInt16 *)
 *
 ***/
#define SILC_STR_SI_SHORT(x) SILC_PARAM_SI16_SHORT, (x)
#define SILC_STR_UI_SHORT(x) SILC_PARAM_UI16_SHORT, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_INT
 *
 * NAME
 *
 *    #define SILC_STR_UI_INT() ...
 *    #define SILC_STR_SI_INT() ...
 *
 * DESCRIPTION
 *
 *    SilcInt32/SilcUInt32.
 *
 *    Formatting:    SILC_STR_SI_INT(int)
 *                   SILC_STR_UI_INT(SilcUInt32)
 *    Unformatting:  SILC_STR_SI_INT(int *)
 *                   SILC_STR_UI_INT(SilcUInt32 *)
 *
 ***/
#define SILC_STR_SI_INT(x) SILC_PARAM_SI32_INT, (x)
#define SILC_STR_UI_INT(x) SILC_PARAM_UI32_INT, (x)

/****d* silcutil/SilcBufferFormatAPI/SILC_STR_*_INT64
 *
 * NAME
 *
 *    #define SILC_STR_UI_INT64() ...
 *    #define SILC_STR_SI_INT64() ...
 *
 * DESCRIPTION
 *
 *    SilcInt64/SilcUInt64.
 *
 *     Formatting:    SILC_STR_SI_INT64(int)
 *                    SILC_STR_UI_INT64(SilcUInt32)
 *     Unformatting:  SILC_STR_SI_INT64(int *)
 *                    SILC_STR_UI_INT64(SilcUInt32 *)
 *
 ***/
#define SILC_STR_SI_INT64(x) SILC_PARAM_SI64_INT, (x)
#define SILC_STR_UI_INT64(x) SILC_PARAM_UI64_INT, (x)

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
#define SILC_STR_UI8_STRING_ALLOC(x) SILC_PARAM_UI8_STRING_ALLOC, (x)
#define SILC_STR_UI16_STRING(x) SILC_PARAM_UI16_STRING, (x)
#define SILC_STR_UI16_STRING_ALLOC(x) SILC_PARAM_UI16_STRING_ALLOC, (x)
#define SILC_STR_UI32_STRING(x) SILC_PARAM_UI32_STRING, (x)
#define SILC_STR_UI32_STRING_ALLOC(x) SILC_PARAM_UI32_STRING_ALLOC, (x)

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
  SILC_PARAM_UI8_NSTRING_ALLOC, (x), (l)
#define SILC_STR_UI16_NSTRING(x, l) SILC_PARAM_UI16_NSTRING, (x), (l)
#define SILC_STR_UI16_NSTRING_ALLOC(x, l) \
  SILC_PARAM_UI16_NSTRING_ALLOC, (x), (l)
#define SILC_STR_UI32_NSTRING(x, l) SILC_PARAM_UI32_NSTRING, (x), (l)
#define SILC_STR_UI32_NSTRING_ALLOC(x, l) \
  SILC_PARAM_UI32_NSTRING_ALLOC, (x), (l)

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
#define SILC_STR_DATA(x, l) SILC_PARAM_DATA, (x), (l)
#define SILC_STR_DATA_ALLOC(x, l) SILC_PARAM_DATA_ALLOC, (x), (l)

/* Deprecated */
#define SILC_STR_UI_XNSTRING(x, l) SILC_PARAM_UI_XNSTRING, (x), (l)
#define SILC_STR_UI_XNSTRING_ALLOC(x, l) SILC_PARAM_UI_XNSTRING_ALLOC, (x), (l)

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
#define SILC_STR_BUFFER_ALLOC(x) SILC_PARAM_BUFFER_ALLOC, (x)

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
 *                       SILC_STR_UI_SHORT(len),
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
 *                         SILC_STR_UI_SHORT(&len),
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
 *                           SILC_STR_DATA(buf, len),
 *                           SILC_STR_END);
 *    } while (len > 0);
 *
 *    // Move to beginning of buffer
 *    silc_buffer_push(buffer, silc_buffer_truelen(buffer));
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
