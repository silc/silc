/*

  silcstrutil.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2005 Pekka Riikonen

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

/****f* silcutil/SilcStrUtilAPI/silc_mime_parse
 *
 * SYNOPSIS
 *
 *    bool
 *    silc_mime_parse(const unsigned char *mime, SilcUInt32 mime_len,
 *                    char *version, SilcUInt32 version_size,
 *                    char *content_type, SilcUInt32 content_type_size,
 *                    char *transfer_encoding,
 *                    SilcUInt32 transfer_encoding_size,
 *                    unsigned char **mime_data_ptr,
 *                    SilcUInt32 *mime_data_len);
 *
 * DESCRIPTION
 *
 *    Parses MIME header indicated by `mime' data block of length of
 *    `mime_len'.  Returns TRUE if the `mime' is valid MIME object.
 *    Parses from the MIME header the MIME Version (if present) and
 *    copies it to the `version' pointer if provided, content type
 *    indicating the data in the MIME object and copies it to the
 *    `content_type' if provided, and the tranfer encoding (if present)
 *    indicating the encoding of the data and copies it to the
 *    `content_transfer_encoding' if provided.
 *
 *    The pointer to the actual data in the MIME object is saved into
 *    `mime_data_ptr'.  The pointer is a location in the `mime' and it
 *    does not allocate or copy anything, ie. the `mime_data_ptr' is a
 *    pointer to the `mime'.  The `mime_data_len' indicates the length of
 *    the data without the MIME header.  The caller is responsible of
 *    NULL terminating the buffers it provides.
 *
 ***/
bool
silc_mime_parse(const unsigned char *mime, SilcUInt32 mime_len,
                char *version, SilcUInt32 version_size,
                char *content_type, SilcUInt32 content_type_size,
                char *transfer_encoding, SilcUInt32 transfer_encoding_size,
                unsigned char **mime_data_ptr, SilcUInt32 *mime_data_len);

/****f* silcutil/SilcStrUtilAPI/silc_strncat
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

/****f* silcutil/SilcStrUtilAPI/silc_identifier_check
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_identifier_check(const unsigned char *identifier,
 *                          SilcUInt32 identifier_len,
 *                          SilcStringEncoding identifier_encoding,
 *                          SilcUInt32 max_allowed_length,
 *                          SilcUInt32 *out_len);
 *
 * DESCRIPTION
 *
 *    Checks that the 'identifier' string is valid identifier string
 *    and does not contain any unassigned or prohibited character.  This
 *    function is used to check for valid nicknames, channel names,
 *    server names, usernames, hostnames, service names, algorithm names,
 *    other security property names, and SILC Public Key name.
 *
 *    If the 'max_allowed_length' is non-zero the identifier cannot be
 *    longer than that, and NULL is returned if it is.  If zero (0), no
 *    length limit exist.  For nicknames the max length must be 128 bytes
 *    and for channel names 256 bytes.  Other identifiers has no default
 *    limit, but application may choose one anyway.
 *
 *    Returns the validated string, that the caller must free.  Returns
 *    NULL if the identifier string is not valid or contain unassigned or
 *    prohibited characters.  Such identifier strings must not be used
 *    SILC protocol.  The returned string is always in UTF-8 encoding.
 *    The length of the returned string is in 'out_len'.
 *
 * NOTES
 *
 *    In addition of validating the identifier string, this function
 *    may map characters to other characters or remove characters from the
 *    original string.  This is done as defined in the SILC protocol.  Error
 *    is returned only if the string contains unassigned or prohibited
 *    characters.  The original 'identifier' is not modified at any point.
 *
 ***/
unsigned char *silc_identifier_check(const unsigned char *identifier,
				     SilcUInt32 identifier_len,
				     SilcStringEncoding identifier_encoding,
				     SilcUInt32 max_allowed_length,
				     SilcUInt32 *out_len);

/****f* silcutil/SilcStrUtilAPI/silc_identifier_verify
 *
 * SYNOPSIS
 *
 *    bool
 *    silc_identifier_check(const unsigned char *identifier,
 *                          SilcUInt32 identifier_len,
 *                          SilcStringEncoding identifier_encoding,
 *                          SilcUInt32 max_allowed_length);
 *
 * DESCRIPTION
 *
 *    Checks that the 'identifier' string is valid identifier string
 *    and does not contain any unassigned or prohibited character.  This
 *    function is used to check for valid nicknames, channel names,
 *    server names, usernames, hostnames, service names, algorithm names,
 *    other security property names, and SILC Public Key name.
 *
 *    If the 'max_allowed_length' is non-zero the identifier cannot be
 *    longer than that, and NULL is returned if it is.  If zero (0), no
 *    length limit exist.  For nicknames the max length must be 128 bytes
 *    and for channel names 256 bytes.  Other identifiers has no default
 *    limit, but application may choose one anyway.
 *
 *    Returns TRUE if the string is valid and FALSE if it is prohibited.
 *
 ***/
bool silc_identifier_verify(const unsigned char *identifier,
			    SilcUInt32 identifier_len,
			    SilcStringEncoding identifier_encoding,
			    SilcUInt32 max_allowed_length);

#endif /* SILCSTRUTIL_H */
