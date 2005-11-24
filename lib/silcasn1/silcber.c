/*

  silcber.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* Basic Encoding Rules (BER) encoder and decoder. */

#include "silcincludes.h"
#include "silcber.h"

/* Encodes a BER data block into the `ber', which must already have
   sufficient space allocated.  Caller can use silc_ber_encoded_len
   function to determine how much to allocate space before calling this
   function.  If the `indefinite' is TRUE then the BER block will not
   include the length of the data in the BER block. */

bool silc_ber_encode(SilcBuffer ber, SilcBerClass ber_class,
		     SilcBerEncoding encoding, SilcUInt32 tag,
		     const unsigned char *data, SilcUInt32 data_len,
		     bool indefinite)
{
  int i = 0, c;
  SilcUInt32 tmp;

  if (!ber)
    return FALSE;

  /* Check that buffer is of correct size */
  if (silc_buffer_len(ber) < silc_ber_encoded_len(tag, data_len, indefinite))
    return FALSE;

  /* Put the class and encoding */
  ber->data[i] = (ber_class << 6) | (encoding << 5);

  /* Put the tag */
  if (tag < 0x1f) {
    /* Short tag */
    ber->data[i++] |= tag;
  } else {
    /* Long tag */
    ber->data[i++] |= 0x1f;

    /* Save the tag in multiple octets where 7-bits in the octet is the tag
       value and bit 8 is set, except for the last octet. */
    tmp = tag;
    c = 0;
    while (tmp) {
      c++;
      tmp >>= 7;
    }
    while (c > 1)
      ber->data[i++] = 0x80 | ((tag >> (--c * 7)) & 0x7f);
    ber->data[i++] = tag & 0x7f;
  }

  /* Put the length of data */
  if (!indefinite) {
    if (data_len < 0x80) {
      /* Use short form for less than 128 bytes */
      ber->data[i++] = data_len;
    } else {
      /* Long form */

      /* Calculate the number of octets for the length field */
      tmp = tag;
      c = 0;
      while (tmp) {
	c++;
	tmp >>= 8;
      }
      ber->data[i++] = 0x80 | c;

      /* Put the actual length field octets, 8-bits per octet. */
      while (c > 1)
	ber->data[i++] = (data_len >> (--c * 8)) & 0xff;
      ber->data[i++] = data_len & 0xff;
    }
  } else {
    /* In indefinite form the length of data is not present in the BER */
    ber->data[i++] = 0x80;
  }

  /* Put the data */
  if (data)
    memcpy(&ber->data[i], data, data_len);

  /* Put end-of-content octets if length is indefinite */
  if (indefinite)
    ber->data[i + data_len] = ber->data[i + data_len + 1] = 0x00;

  return TRUE;
}

/* Decodesa a BER data from the buffer `ber'.  Returns the class,
   encoding and the tag number for the BER data into `ber_class',
   `encoding' and `tag'.  A pointer to the start of the data area is
   returned into `data'.  If the length of the data is available from
   the BER data the length is returned into `data_len'.  If the
   `indefinite' is TRUE then the length found in `data_len' was found
   by finding end-of-contents octets from the data.  The
   `identifier_len' is the length of the BER header, and the length
   of the entire BER object is `identifier_len' + `data_len'. */

bool silc_ber_decode(SilcBuffer ber, SilcBerClass *ber_class,
		     SilcBerEncoding *encoding, SilcUInt32 *tag,
		     const unsigned char **data, SilcUInt32 *data_len,
		     bool *indefinite, SilcUInt32 *identifier_len)
{
  int i = 0, c;
  SilcUInt32 t;

  if (!ber || silc_buffer_len(ber) == 0) {
    SILC_LOG_DEBUG(("Invalid data buffer"));
    return FALSE;
  }

  /* Get class */
  if (ber_class)
    *ber_class = (ber->data[0] >> 6) & 0x03;

  /* Get encoding */
  if (encoding)
    *encoding = (ber->data[0] >> 5) & 0x01;

  /* Get the tag.  Assume short tag, the most common case */
  t = ber->data[i++] & 0x1f;

  /* If the tag is over 31 then take it from next octets */
  if (t >= 0x1f) {
    if (i >= silc_buffer_len(ber)) {
      SILC_LOG_DEBUG(("Malformed BER: Not enough bytes"));
      return FALSE;
    }

    /* The tag is in next octets in 7-bits parts, parse them out.  All
       octets except the last one has bit 8 set. */
    t = 0;
    while (ber->data[i] & 0x80) {
      t <<= 7;
      t |= ber->data[i++] & 0x7f;

      if (i >= silc_buffer_len(ber)) {
	SILC_LOG_DEBUG(("Malformed BER: Not enough bytes"));
	return FALSE;
      }
    }

    /* Last 7-bits part */
    t <<= 7;
    t |= ber->data[i++] & 0x7f;
  }
  if (tag)
    *tag = t;

  if (i >= silc_buffer_len(ber)) {
    SILC_LOG_DEBUG(("Malformed BER: Not enough bytes"));
    return FALSE;
  }

  /* Get the data length and the actual data */
  if (data && data_len) {
    /* Assume short format for length */
    *data_len = ber->data[i++];
    if (indefinite)
      *indefinite = FALSE;

    /* The bit 8 is set if the length is in long format */
    if (*data_len & 0x80) {
      /* If the format is definite then this octet includes the number
	 of length octets.  If indefinite it is zero and data is ended
	 with end-of-contents octets (two zero bytes). */
      c = *data_len & 0x7f;
      if (c) {
	if (i >= silc_buffer_len(ber)) {
	  SILC_LOG_DEBUG(("Malformed BER: Not enough bytes"));
	  return FALSE;
	}

	/* Get the length from c many octects (8-bits per octet) */
	*data_len = 0;
	while (c > 0) {
	  *data_len <<= 8;
	  *data_len |= ber->data[i++] & 0xff;

	  if (i >= silc_buffer_len(ber)) {
	    SILC_LOG_DEBUG(("Malformed BER: Length is too long"));
	    return FALSE;
	  }
	  c--;
	}
      } else {
	/* It is indefinite and we attempt to find out the length by
	   finding the end-of-contents octets. */
	if (indefinite)
	  *indefinite = TRUE;
	c = i;
	while (c + 1 < silc_buffer_len(ber)) {
	  if (ber->data[c] == 0x00 && ber->data[c + 1] == 0x00)
	    break;
	  c += 2;
	}
	if (c >= silc_buffer_len(ber)) {
	  SILC_LOG_DEBUG(("Malformed BER: could not find end-of-content"));
	  return FALSE;
	}
	*data_len = c - i;
      }
    }

    if (*data_len > silc_buffer_len(ber) - i) {
      SILC_LOG_DEBUG(("Malformed BER: Length is too long"));
      return FALSE;
    }

    /* Pointer to data area */
    *data = (const unsigned char *)ber->data + i;
  }

  if (identifier_len)
    *identifier_len = i;

  return TRUE;
}

/* Calculates the length of the encoded BER data object.  This utility
   function can be used to calculate how much to allocate space before
   encoding with silc_ber_encode. */

SilcUInt32 silc_ber_encoded_len(SilcUInt32 tag, SilcUInt32 data_len,
				bool indefinite)
{
  SilcUInt32 len, tmp;

  len = 1;
  if (tag >= 0x1f) {
    while (tag) {
      len++;
      tag >>= 7;
    }
  }

  len++;
  if (!indefinite) {
    if (data_len >= 0x80) {
      tmp = data_len;
      while (tmp) {
	len++;
	tmp >>= 8;
      }
    }
  } else {
    len += 2;
  }

  return len + data_len;
}
