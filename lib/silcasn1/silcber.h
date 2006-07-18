/*

  silcber.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcasn1/BER Interface
 *
 * DESCRIPTION
 *
 * The Basic Encoding Rules (BER) is the data encoding format for the
 * ASN.1.  This interface provides routines for encoding and decoding
 * arbitraty BER data blocks.  Naturally, this interface can be used
 * to encode and decode DER blocks as well.  These routines does not
 * allocate any memory and have been optimized for general ASN.1 usage.
 *
 * References: ITU-T X.690
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X690_0702.pdf
 *
 ***/

#ifndef SILCBER_H
#define SILCBER_H

/****d* silcasn1/SilcBerAPI/SilcBerClass
 *
 * NAME
 *
 *    typedef enum { ... } SilcBerClass;
 *
 * DESCRIPTION
 *
 *    Defines the BER classes.
 *
 */
typedef enum {
  SILC_BER_CLASS_UNIVERSAL       = 0x00,   /* Universal */
  SILC_BER_CLASS_APPLICATION     = 0x01,   /* Application */
  SILC_BER_CLASS_CONTEXT         = 0x02,   /* Context-specific */
  SILC_BER_CLASS_PRIVATE         = 0x03,   /* Private */
} SilcBerClass;
/***/

/****d* silcasn1/SilcBerAPI/SilcBerEncoding
 *
 * NAME
 *
 *    typedef enum { ... } SilcBerEncoding;
 *
 * DESCRIPTION
 *
 *    Defines the BER encoding type.
 *
 */
typedef enum {
  SILC_BER_ENC_PRIMITIVE         = 0x00,
  SILC_BER_ENC_CONSTRUCTED       = 0x01,
} SilcBerEncoding;
/***/

/****f* silcasn1/SilcBerAPI/silc_ber_encode
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_ber_encode(SilcBuffer ber, SilcBerClass ber_class,
 *                    SilcBerEncoding encoding, SilcUInt32 tag,
 *                    const unsigned char *data, SilcUInt32 data_len,
 *                    SilcBool indefinite);
 *
 * DESCRIPTION
 *
 *    Encodes a BER data block into the `ber', which must already have
 *    sufficient space allocated.  Caller can use silc_ber_encoded_len
 *    function to determine how much to allocate space before calling this
 *    function.  If the `indefinite' is TRUE then the BER block will not
 *    include the length of the data in the BER block.
 *
 ***/
SilcBool silc_ber_encode(SilcBuffer ber, SilcBerClass ber_class,
			 SilcBerEncoding encoding, SilcUInt32 tag,
			 const unsigned char *data, SilcUInt32 data_len,
			 SilcBool indefinite);

/****f* silcasn1/SilcBerAPI/silc_ber_decode
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_ber_decode(SilcBuffer ber, SilcBerClass *ber_class,
 *                    SilcBerEncoding *encoding, SilcUInt32 *tag,
 *                    const unsigned char **data, SilcUInt32 *data_len,
 *                    SilcBool *indefinite, SilcUInt32 *identifier_len);
 *
 * DESCRIPTION
 *
 *    Decodesa a BER data from the buffer `ber'.  Returns the class,
 *    encoding and the tag number for the BER data into `ber_class',
 *    `encoding' and `tag'.  A pointer to the start of the data area is
 *    returned into `data'.  If the length of the data is available from
 *    the BER data the length is returned into `data_len'.  If the
 *    `indefinite' is TRUE then the length found in `data_len' was found
 *    by finding end-of-contents octets from the BER data.  The
 *    `identifier_len' is the length of the BER header, and the length
 *    of the entire BER object is `identifier_len' + `data_len'.
 *
 ***/
SilcBool silc_ber_decode(SilcBuffer ber, SilcBerClass *ber_class,
			 SilcBerEncoding *encoding, SilcUInt32 *tag,
			 const unsigned char **data, SilcUInt32 *data_len,
			 SilcBool *indefinite, SilcUInt32 *identifier_len);

/****f* silcasn1/SilcBerAPI/silc_ber_encoded_len
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_ber_encoded_len(SilcUInt32 tag, SilcUInt32 data_len,
 *                                    SilcBool indefinite);
 *
 * DESCRIPTION
 *
 *    Calculates the length of the encoded BER data object.  This utility
 *    function can be used to calculate how much to allocate space before
 *    encoding with silc_ber_encode.
 *
 ***/
SilcUInt32 silc_ber_encoded_len(SilcUInt32 tag, SilcUInt32 data_len,
				SilcBool indefinite);

#endif /* SILCBER_H */
