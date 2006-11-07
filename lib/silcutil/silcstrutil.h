/*

  silcstrutil.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC String Utilities
 *
 * DESCRIPTION
 *
 * String manipulation utility routines.  These routines provides
 * various helper functions for encoding, decoding and otherwise
 * managing strings.
 *
 ***/

#ifndef SILCSTRUTIL_H
#define SILCSTRUTIL_H

/****d* silcutil/SilcStrUtilAPI/SilcStringEncoding
 *
 * NAME
 *
 *    typedef enum { ... } SilcStringEncoding;
 *
 * DESCRIPTION
 *
 *    String encoding definitions used with various string manipulation
 *    routines.  By default, applications are suggested to use
 *    SILC_STRING_LOCALE since it encodes and decodes correctly according
 *    to local system language and character set (locale).
 *
 * SOURCE
 */
typedef enum {
  SILC_STRING_ASCII         = 0,  /* Any 8 bit ASCII encoding (default) */
  SILC_STRING_ASCII_ESC     = 1,  /* 7 bit ASCII (>0x7f escaped) */
  SILC_STRING_BMP           = 2,  /* 16 bit, UCS-2, BMP, ISO/IEC 10646 */
  SILC_STRING_BMP_LSB       = 3,  /* BMP, least significant byte first */
  SILC_STRING_UNIVERSAL     = 4,  /* 32 bit, UCS-4, Universal, ISO/IEC 10646 */
  SILC_STRING_UNIVERSAL_LSB = 5,  /* Universal, least significant byte first */
  SILC_STRING_LOCALE        = 6,  /* A locale specific conversion on
				     those platforms that support iconv().
				     Fallback is SILC_STRING_ASCII. */
  SILC_STRING_UTF8          = 7,  /* UTF-8 encoding */
  SILC_STRING_PRINTABLE     = 8,  /* Printable ASCII (no escaping) */
  SILC_STRING_VISIBLE       = 9,  /* Visible ASCII string */
  SILC_STRING_TELETEX       = 10, /* Teletex ASCII string */
  SILC_STRING_NUMERICAL     = 11, /* Numerical ASCII string (digits) */
  SILC_STRING_LDAP_DN       = 12, /* Strings for LDAP DNs, RFC 2253 */
  SILC_STRING_UTF8_ESCAPE   = 12, /* Escaped UTF-8 as defined in RFC 2253 */

  SILC_STRING_LANGUAGE      = 6,  /* _Deprecated_, use SILC_STRING_LOCALE. */
} SilcStringEncoding;
/***/

/****f* silcutil/SilcStrUtilAPI/silc_pem_encode
 *
 * SYNOPSIS
 *
 *    char *silc_pem_encode(unsigned char *data, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Encodes data into PEM encoding. Returns NULL terminated PEM encoded
 *    data string. Note: This is originally public domain code and is
 *    still PD.
 *
 ***/
char *silc_pem_encode(unsigned char *data, SilcUInt32 len);

/****f* silcutil/SilcStrUtilAPI/silc_pem_encode_file
 *
 * SYNOPSIS
 *
 *    char *silc_pem_encode_file(unsigned char *data, SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_pem_encode() but puts newline ('\n') every 72 characters.
 *
 ***/
char *silc_pem_encode_file(unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcStrUtilAPI/silc_pem_decode
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_pem_decode(unsigned char *pem, SilcUInt32 pem_len,
 *                                   SilcUInt32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Decodes PEM into data. Returns the decoded data. Note: This is
 *    originally public domain code and is still PD.
 *
 ***/
unsigned char *silc_pem_decode(unsigned char *pem, SilcUInt32 pem_len,
			       SilcUInt32 *ret_len);

/****f* silcutil/SilcStrStrUtilAPI/silc_strncat
 *
 * SYNOPSIS
 *
 *    char *silc_strncat(char *dest, SilcUInt32 dest_size,
 *                       const char *src, SilcUInt32 src_len);
 *
 * DESCRIPTION
 *
 *    Concatenates the `src' into `dest'.  If `src_len' is more than the
 *    size of the `dest' (minus NULL at the end) the `src' will be
 *    truncated to fit.
 *
 ***/
char *silc_strncat(char *dest, SilcUInt32 dest_size,
		   const char *src, SilcUInt32 src_len);

/****f* silcutil/SilcStrUtilAPI/silc_string_regexify
 *
 * SYNOPSIS
 *
 *    char *silc_string_regexify(const char *string);
 *
 * DESCRIPTION
 *
 *    Inspects the `string' for wildcards and returns regex string that can
 *    be used by the GNU regex library. A comma (`,') in the `string' means
 *    that the string is list.
 *
 *    This function is system dependant.
 *
 ***/
char *silc_string_regexify(const char *string);

/****f* silcutil/SilcStrUtilAPI/silc_string_regex_match
 *
 * SYNOPSIS
 *
 *    int silc_string_regex_match(const char *regex, const char *string);
 *
 * DESCRIPTION
 *
 *    Matches the two strings and returns TRUE if the strings match.
 *
 *    This function is system dependant.
 *
 ***/
int silc_string_regex_match(const char *regex, const char *string);

/****f* silcutil/SilcStrUtilAPI/silc_string_match
 *
 * SYNOPSIS
 *
 *    int silc_string_match(const char *string1, const char *string2);
 *
 * DESCRIPTION
 *
 *    Do regex match to the two strings `string1' and `string2'. If the
 *    `string2' matches the `string1' this returns TRUE.
 *
 *    This function is system dependant.
 *
 ***/
int silc_string_match(const char *string1, const char *string2);

/****f* silcutil/SilcStrUtilAPI/silc_string_compare
 *
 * SYNOPSIS
 *
 *    int silc_string_compare(char *string1, char *string2);
 *
 * DESCRIPTION
 *
 *    Compares two strings. Strings may include wildcards '*' and '?'.
 *    Returns TRUE if strings match.
 *
 ***/
int silc_string_compare(char *string1, char *string2);

/****f* silcutil/SilcStrUtilAPI/silc_string_split
 *
 * SYNOPSIS
 *
 *    char **silc_string_split(const char *string, char ch, int *ret_count);
 *
 * DESCRIPTION
 *
 *    Splits a `string' that has a separator `ch' into an array of strings
 *    and returns the array.  The `ret_count' will contain the number of
 *    strings in the array.  Caller must free the strings and the array.
 *    Returns NULL on error.  If the string does not have `ch' separator
 *    this returns the `string' in the array.
 *
 ***/
char **silc_string_split(const char *string, char ch, int *ret_count);

#endif /* SILCSTRUTIL_H */
