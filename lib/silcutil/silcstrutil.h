/*

  silcstrutil.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

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
 *    String manipulation utility routines.  These routines provides
 *    various helper functions for encoding, decoding and otherwise
 *    managing strings.
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
 *    decoding functions.
 *
 * SOURCE
 */
typedef enum {
  SILC_STRING_ASCII     = 0,	/* Any 8 bit ASCII encoding (default) */

  /* Rest are not implemented yet */
  SILC_STRING_ASCII_ESC = 1,	/* 7 bit ASCII (>0x7f escaped) */
  SILC_STRING_BMP       = 2,	/* 16 bit, UCS-2, BMP, ISO/IEC 10646 */
  SILC_STRING_UNIVERSAL = 3,	/* 32 bit, UCS-4, Universal, ISO/IEC 10646 */
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


#endif /* SILCSTRUTIL_H */
