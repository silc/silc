/*

  silcstrutil.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2003 Pekka Riikonen

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

/****d* silcutil/SilcStrUtilAPI/SilcStringEncoding
 *
 * NAME
 * 
 *    typedef enum { ... } SilcStringEncoding;
 *
 * DESCRIPTION
 *
 *    String encoding definitions used with the UTF-8 encoding and
 *    decoding functions.  By default, systems should use SILC_STRING_LANGUAGE
 *    since it encodes and decodes correctly according to local system
 *    language and character set.
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
  SILC_STRING_LANGUAGE      = 6,  /* Language and charset specific conversion
				     on those platforms that support iconv().
				     Fallback is SILC_STRING_ASCII. */
} SilcStringEncoding;
/***/

/****f* silcutil/SilcStrUtilAPI/silc_utf8_encode
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_utf8_encode(const unsigned char *bin, SilcUInt32 bin_len,
 *                                SilcStringEncoding bin_encoding,
 *                                unsigned char *utf8, SilcUInt32 utf8_size);
 *
 * DESCRIPTION
 *
 *    Encodes the string `bin' of which encoding is `bin_encoding' to the
 *    UTF-8 encoding into the buffer `utf8' which is of size of `utf8_size'.
 *    Returns the length of the UTF-8 encoded string, or zero (0) on error.
 *    By default `bin_encoding' is ASCII, and the caller needs to know the
 *    encoding of the input string if it is anything else.
 *
 ***/
SilcUInt32 silc_utf8_encode(const unsigned char *bin, SilcUInt32 bin_len,
			    SilcStringEncoding bin_encoding,
			    unsigned char *utf8, SilcUInt32 utf8_size);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_decode
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_utf8_decode(const unsigned char *utf8, 
 *                                SilcUInt32 utf8_len,
 *                                SilcStringEncoding bin_encoding,
 *                                unsigned char *bin, SilcUInt32 bin_size);
 *
 * DESCRIPTION
 *
 *    Decodes UTF-8 encoded string `utf8' to string of which encoding is
 *    to be `bin_encoding', into the `bin' buffer of size of `bin_size'.
 *    Returns the length of the decoded buffer, or zero (0) on error.
 *    By default `bin_encoding' is ASCII, and the caller needs to know to
 *    which encoding the output string is to be encoded if ASCII is not
 *    desired. 
 *
 ***/
SilcUInt32 silc_utf8_decode(const unsigned char *utf8, SilcUInt32 utf8_len,
			    SilcStringEncoding bin_encoding,
			    unsigned char *bin, SilcUInt32 bin_size);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_encoded_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_utf8_encoded_len(const unsigned char *bin, 
 *                                     SilcUInt32 bin_len,
 *                                     SilcStringEncoding bin_encoding);
 *
 * DESCRIPTION
 *
 *    Returns the length of UTF-8 encoded string if the `bin' of
 *    encoding of `bin_encoding' is encoded with silc_utf8_encode.
 *
 ***/
SilcUInt32 silc_utf8_encoded_len(const unsigned char *bin, SilcUInt32 bin_len,
				 SilcStringEncoding bin_encoding);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_decoded_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_utf8_decoded_len(const unsigned char *bin, 
 *                                     SilcUInt32 bin_len,
 *                                     SilcStringEncoding bin_encoding);
 *
 * DESCRIPTION
 *
 *    Returns the length of decoded string if the `bin' of encoding of
 *    `bin_encoding' is decoded with silc_utf8_decode. 
 *
 ***/
SilcUInt32 silc_utf8_decoded_len(const unsigned char *bin, SilcUInt32 bin_len,
				 SilcStringEncoding bin_encoding);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_valid
 *
 * SYNOPSIS
 *
 *    bool silc_utf8_valid(const unsigned char *utf8, SilcUInt32 utf8_len);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the `utf8' string of length of `utf8_len' is valid
 *    UTF-8 encoded string, FALSE if it is not UTF-8 encoded string.
 *
 ***/
bool silc_utf8_valid(const unsigned char *utf8, SilcUInt32 utf8_len);

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

#endif /* SILCSTRUTIL_H */
