/*

  silcutf8.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC UTF-8 Interface
 *
 * DESCRIPTION
 *
 * Interface for the UTF-8 Unicode encoding form.  These routines provides
 * applications full UTF-8 and Unicode support.  It supports UTF-8 encoding
 * to and decoding from myriad of other character encodings.
 *
 ***/

#ifndef SILCUTF8_H
#define SILCUTF8_H

/****f* silcutil/SilcUTF8API/silc_utf8_encode
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
 *    Returns zero (0) on error.
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
 *    `bin_encoding' is decoded with silc_utf8_decode.  Returns zero (0)
 *    on error.
 *
 ***/
SilcUInt32 silc_utf8_decoded_len(const unsigned char *bin, SilcUInt32 bin_len,
				 SilcStringEncoding bin_encoding);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_valid
 *
 * SYNOPSIS
 *
 *    SilcBool silc_utf8_valid(const unsigned char *utf8, SilcUInt32 utf8_len);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the `utf8' string of length of `utf8_len' is valid
 *    UTF-8 encoded string, FALSE if it is not UTF-8 encoded string.
 *
 ***/
SilcBool silc_utf8_valid(const unsigned char *utf8, SilcUInt32 utf8_len);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_strcasecmp
 *
 * SYNOPSIS
 *
 *    SilcBool silc_utf8_strcasecmp(const char *s1, const char *s2);
 *
 * DESCRIPTION
 *
 *    The silc_utf8_strcasecmp() function compares the two strings s1 and s2,
 *    ignoring the case of the characters.  It returns TRUE if the strings
 *    match and FALSE if they differ.
 *
 *    This functions expects NULL terminated UTF-8 strings.  The strings
 *    will be casefolded and normalized before comparing.  Certain special
 *    Unicode characters will be ignored when comparing.
 *
 ***/
SilcBool silc_utf8_strcasecmp(const char *s1, const char *s2);

/****f* silcutil/SilcStrUtilAPI/silc_utf8_strncasecmp
 *
 * SYNOPSIS
 *
 *    SilcBool silc_utf8_strcasecmp(const char *s1, const char *s2,
 *                              SilcUInt32 n);
 *
 * DESCRIPTION
 *
 *    The silc_utf8_strcasecmp() function compares the two strings s1 and s2,
 *    ignoring the case of the characters.  It returns TRUE if the strings
 *    match and FALSE if they differ.
 *
 *    This functions expects NULL terminated UTF-8 strings.  The strings
 *    will be casefolded and normalized before comparing.  Certain special
 *    Unicode characters will be ignored when comparing.
 *
 ***/
SilcBool silc_utf8_strncasecmp(const char *s1, const char *s2, SilcUInt32 n);

#endif /* SILCUTF8_H */
