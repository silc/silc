/*

  silcbase64.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Base64 API
 *
 * DESCRIPTION
 *
 * This interface provides Base64 encoding and decoding routines.
 *
 ***/

#ifndef SILCBASE64_H
#define SILCBASE64_H

/****f* silcutil/SilcBase64API/silc_base64_encode
 *
 * SYNOPSIS
 *
 *    char *silc_base64_encode(SilcStack stack,
 *                             unsigned char *data, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Encodes data into Base 64 (PEM) encoding. Returns NULL terminated
 *    Base 64 encoded data string.  Returns NULL if system is out of memory.
 *
 *    If `stack' is non-NULL the returned buffer is allocated from `stack'.
 *
 ***/
char *silc_base64_encode(SilcStack stack, unsigned char *data, SilcUInt32 len);

/****f* silcutil/SilcBase64API/silc_base64_encode_file
 *
 * SYNOPSIS
 *
 *    char *silc_base64_encode_file(SilcStack stack,
 *                                  unsigned char *data, SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_base64_encode() but puts newline ('\n') every 72
 *    characters.  Returns NULL if system is out of memory.
 *
 *    If `stack' is non-NULL the returned buffer is allocated from `stack'.
 *
 ***/
char *silc_base64_encode_file(SilcStack stack,
			      unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcBase64API/silc_base_decode
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_base_decode(SilcStack stack,
 *                                    unsigned char *base64,
 *                                    SilcUInt32 base64_len,
 *                                    SilcUInt32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Decodes Base 64 (PEM) into data. Returns the decoded data.  Returns
 *    NULL if the data is not valid Base 64 encoded data.
 *
 *    If `stack' is non-NULL the returned buffer is allocated from `stack'.
 *
 ***/
unsigned char *silc_base64_decode(SilcStack stack,
				  unsigned char *base64,
				  SilcUInt32 base64_len,
				  SilcUInt32 *ret_len);

#endif /* SILCBASE64_H */
