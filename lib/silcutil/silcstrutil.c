/*

  silcstrutil.c 

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
/* $Id$ */

#include "silcincludes.h"
#include "silcstrutil.h"

static unsigned char pem_enc[64] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encodes data into PEM encoding. Returns NULL terminated PEM encoded
   data string. Note: This is originally public domain code and is
   still PD. */

char *silc_pem_encode(unsigned char *data, SilcUInt32 len)
{
  int i, j;
  SilcUInt32 bits, c, char_count;
  char *pem;

  char_count = 0;
  bits = 0;
  j = 0;

  pem = silc_calloc(((len * 8 + 5) / 6) + 5, sizeof(*pem));

  for (i = 0; i < len; i++) {
    c = data[i];
    bits += c;
    char_count++;

    if (char_count == 3) {
      pem[j++] = pem_enc[bits  >> 18];
      pem[j++] = pem_enc[(bits >> 12) & 0x3f];
      pem[j++] = pem_enc[(bits >> 6)  & 0x3f];
      pem[j++] = pem_enc[bits & 0x3f];
      bits = 0;
      char_count = 0;
    } else {
      bits <<= 8;
    }
  }

  if (char_count != 0) {
    bits <<= 16 - (8 * char_count);
    pem[j++] = pem_enc[bits >> 18];
    pem[j++] = pem_enc[(bits >> 12) & 0x3f];

    if (char_count == 1) {
      pem[j++] = '=';
      pem[j] = '=';
    } else {
      pem[j++] = pem_enc[(bits >> 6) & 0x3f];
      pem[j] = '=';
    }
  }

  return pem;
}

/* Same as above but puts newline ('\n') every 72 characters. */

char *silc_pem_encode_file(unsigned char *data, SilcUInt32 data_len)
{
  int i, j;
  SilcUInt32 len, cols;
  char *pem, *pem2;

  pem = silc_pem_encode(data, data_len);
  len = strlen(pem);

  pem2 = silc_calloc(len + (len / 72) + 1, sizeof(*pem2));

  for (i = 0, j = 0, cols = 1; i < len; i++, cols++) {
    if (cols == 72) {
      pem2[i] = '\n';
      cols = 0;
      len++;
      continue;
    }

    pem2[i] = pem[j++];
  }

  silc_free(pem);
  return pem2;
}

/* Decodes PEM into data. Returns the decoded data. Note: This is
   originally public domain code and is still PD. */

unsigned char *silc_pem_decode(unsigned char *pem, SilcUInt32 pem_len,
			       SilcUInt32 *ret_len)
{
  int i, j;
  SilcUInt32 len, c, char_count, bits;
  unsigned char *data;
  static char ialpha[256], decoder[256];

  for (i = 64 - 1; i >= 0; i--) {
    ialpha[pem_enc[i]] = 1;
    decoder[pem_enc[i]] = i;
  }

  char_count = 0;
  bits = 0;
  j = 0;

  if (!pem_len)
    len = strlen(pem);
  else
    len = pem_len;

  data = silc_calloc(((len * 6) / 8), sizeof(*data));

  for (i = 0; i < len; i++) {
    c = pem[i];

    if (c == '=')
      break;

    if (c > 127 || !ialpha[c])
      continue;

    bits += decoder[c];
    char_count++;

    if (char_count == 4) {
      data[j++] = bits >> 16;
      data[j++] = (bits >> 8) & 0xff;
      data[j++] = bits & 0xff;
      bits = 0;
      char_count = 0;
    } else {
      bits <<= 6;
    }
  }

  switch(char_count) {
  case 1:
    silc_free(data);
    return NULL;
    break;
  case 2:
    data[j++] = bits >> 10;
    break;
  case 3:
    data[j++] = bits >> 16;
    data[j++] = (bits >> 8) & 0xff;
    break;
  }

  if (ret_len)
    *ret_len = j;

  return data;
}

/* Encodes the string `bin' of which encoding is `bin_encoding' to the
   UTF-8 encoding into the buffer `utf8' which is of size of `utf8_size'.
   Returns the length of the UTF-8 encoded string, or zero (0) on error.
   By default `bin_encoding' is ASCII, and the caller needs to know the
   encoding of the input string if it is anything else. */

SilcUInt32 silc_utf8_encode(const unsigned char *bin, SilcUInt32 bin_len,
			    SilcStringEncoding bin_encoding,
			    unsigned char *utf8, SilcUInt32 utf8_size)
{
  SilcUInt32 enclen = 0, i, charval = 0;

  if (!bin || !bin_len)
    return 0;

  if (silc_utf8_valid(bin, bin_len) && bin_len <= utf8_size) {
    memcpy(utf8, bin, bin_len);
    return bin_len;
  }

  if (bin_encoding == SILC_STRING_LANGUAGE) {
#if defined(HAVE_ICONV) && defined(HAVE_NL_LANGINFO) && defined(CODESET)
    char *fromconv, *icp, *ocp;
    iconv_t icd;
    size_t inlen, outlen;

    setlocale(LC_CTYPE, "");
    fromconv = nl_langinfo(CODESET);
    if (fromconv && strlen(fromconv)) {
      icd = iconv_open("UTF-8", fromconv);
      icp = (char *)bin;
      ocp = (char *)utf8;
      inlen = bin_len;
      outlen = utf8_size;
      if (icp && ocp && icd != (iconv_t)-1) {
	if (iconv(icd, &icp, &inlen, &ocp, &outlen) != -1) {
	  utf8_size -= outlen;
	  iconv_close(icd);
	  return utf8_size;
	}
	iconv_close(icd);
      }
    }
#endif

    /* Fallback to 8-bit ASCII */
    bin_encoding = SILC_STRING_ASCII;
  }

  for (i = 0; i < bin_len; i++) {
    switch (bin_encoding) {
    case SILC_STRING_ASCII:
      charval = bin[i];
      break;
    case SILC_STRING_ASCII_ESC:
      SILC_NOT_IMPLEMENTED("SILC_STRING_ASCII_ESC");
      return 0;
      break;
    case SILC_STRING_BMP:
      SILC_GET16_MSB(charval, bin + i);
      i += 1;
      break;
    case SILC_STRING_BMP_LSB:
      SILC_GET16_LSB(charval, bin + i);
      i += 1;
      break;
    case SILC_STRING_UNIVERSAL:
      SILC_GET32_MSB(charval, bin + i);
      i += 3;
      break;
    case SILC_STRING_UNIVERSAL_LSB:
      SILC_GET32_LSB(charval, bin + i);
      i += 3;
      break;
    case SILC_STRING_LANGUAGE:
      break;
    }

    if (charval < 0x80) {
      if (utf8) {
	if (enclen > utf8_size)
	  return 0;

	utf8[enclen] = (unsigned char)charval;
      }
      enclen++;
    } else if (charval < 0x800) {
      if (utf8) {
	if (enclen + 2 > utf8_size)
	  return 0;

	utf8[enclen    ] = (unsigned char )(((charval >> 6)  & 0x1f) | 0xc0);
	utf8[enclen + 1] = (unsigned char )((charval & 0x3f) | 0x80);
      }
      enclen += 2;
    } else if (charval < 0x10000) {
      if (utf8) {
	if (enclen + 3 > utf8_size)
	  return 0;

	utf8[enclen    ] = (unsigned char )(((charval >> 12) & 0xf)  | 0xe0);
	utf8[enclen + 1] = (unsigned char )(((charval >> 6)  & 0x3f) | 0x80);
	utf8[enclen + 2] = (unsigned char )((charval & 0x3f) | 0x80);
      }
      enclen += 3;
    } else if (charval < 0x200000) {
      if (utf8) {
	if (enclen + 4 > utf8_size)
	  return 0;

	utf8[enclen    ] = (unsigned char )(((charval >> 18) & 0x7)  | 0xf0);
	utf8[enclen + 1] = (unsigned char )(((charval >> 12) & 0x3f) | 0x80);
	utf8[enclen + 2] = (unsigned char )(((charval >> 6)  & 0x3f) | 0x80);
	utf8[enclen + 3] = (unsigned char )((charval & 0x3f) | 0x80);
      }
      enclen += 4;
    } else if (charval < 0x4000000) {
      if (utf8) {
	if (enclen + 5 > utf8_size)
	  return 0;

	utf8[enclen    ] = (unsigned char )(((charval >> 24) & 0x3)  | 0xf8);
	utf8[enclen + 1] = (unsigned char )(((charval >> 18) & 0x3f) | 0x80);
	utf8[enclen + 2] = (unsigned char )(((charval >> 12) & 0x3f) | 0x80);
	utf8[enclen + 3] = (unsigned char )(((charval >> 6)  & 0x3f) | 0x80);
	utf8[enclen + 4] = (unsigned char )((charval & 0x3f) | 0x80);
      }
      enclen += 5;
    } else {
      if (utf8) {
	if (enclen + 6 > utf8_size)
	  return 0;

	utf8[enclen    ] = (unsigned char )(((charval >> 30) & 0x1)  | 0xfc);
	utf8[enclen + 1] = (unsigned char )(((charval >> 24) & 0x3f) | 0x80);
	utf8[enclen + 2] = (unsigned char )(((charval >> 18) & 0x3f) | 0x80);
	utf8[enclen + 3] = (unsigned char )(((charval >> 12) & 0x3f) | 0x80);
	utf8[enclen + 4] = (unsigned char )(((charval >> 6)  & 0x3f) | 0x80);
	utf8[enclen + 5] = (unsigned char )((charval & 0x3f) | 0x80);
      }
      enclen += 6;
    }
  }

  return enclen;
}

/* Decodes UTF-8 encoded string `utf8' to string of which encoding is
   to be `bin_encoding', into the `bin' buffer of size of `bin_size'.
   Returns the length of the decoded buffer, or zero (0) on error.
   By default `bin_encoding' is ASCII, and the caller needs to know to
   which encoding the output string is to be encoded if ASCII is not
   desired. */

SilcUInt32 silc_utf8_decode(const unsigned char *utf8, SilcUInt32 utf8_len,
			    SilcStringEncoding bin_encoding,
			    unsigned char *bin, SilcUInt32 bin_size)
{
  SilcUInt32 enclen = 0, i, charval;

  if (!utf8 || !utf8_len)
    return 0;

  if (bin_encoding == SILC_STRING_LANGUAGE) {
#if defined(HAVE_ICONV) && defined(HAVE_NL_LANGINFO) && defined(CODESET)
    char *toconv, *icp, *ocp;
    iconv_t icd;
    size_t inlen, outlen;

    setlocale(LC_CTYPE, "");
    toconv = nl_langinfo(CODESET);
    if (toconv && strlen(toconv)) {
      icd = iconv_open(toconv, "UTF-8");
      icp = (char *)utf8;
      ocp = (char *)bin;
      inlen = utf8_len;
      outlen = bin_size;
      if (icp && ocp && icd != (iconv_t)-1) {
	if (iconv(icd, &icp, &inlen, &ocp, &outlen) != -1) {
	  bin_size -= outlen;
	  iconv_close(icd);
	  return bin_size;
	}
	iconv_close(icd);
      }
    }
#endif

    /* Fallback to 8-bit ASCII */
    bin_encoding = SILC_STRING_ASCII;
  }

  for (i = 0; i < utf8_len; i++) {
    if ((utf8[i] & 0x80) == 0x00) {
      charval = utf8[i] & 0x7f;
    } else if ((utf8[i] & 0xe0) == 0xc0) {
      if (utf8_len < 2)
        return 0;

      if ((utf8[i + 1] & 0xc0) != 0x80)
        return 0;

      charval = (utf8[i++] & 0x1f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x80)
        return 0;
    } else if ((utf8[i] & 0xf0) == 0xe0) {
      if (utf8_len < 3)
        return 0;

      if (((utf8[i + 1] & 0xc0) != 0x80) || 
	  ((utf8[i + 2] & 0xc0) != 0x80))
        return 0;

      charval = (utf8[i++]  & 0xf)  << 12;
      charval |= (utf8[i++] & 0x3f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x800)
        return 0;
    } else if ((utf8[i] & 0xf8) == 0xf0) {
      if (utf8_len < 4)
        return 0;

      if (((utf8[i + 1] & 0xc0) != 0x80) || 
	  ((utf8[i + 2] & 0xc0) != 0x80) ||
	  ((utf8[i + 3] & 0xc0) != 0x80))
        return 0;

      charval = ((SilcUInt32)(utf8[i++] & 0x7)) << 18;
      charval |= (utf8[i++] & 0x3f) << 12;
      charval |= (utf8[i++] & 0x3f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x10000)
        return 0;
    } else if ((utf8[i] & 0xfc) == 0xf8) {
      if (utf8_len < 5)
        return 0;

      if (((utf8[i + 1] & 0xc0) != 0x80) || 
	  ((utf8[i + 2] & 0xc0) != 0x80) ||
	  ((utf8[i + 3] & 0xc0) != 0x80) ||
	  ((utf8[i + 4] & 0xc0) != 0x80))
        return 0;

      charval = ((SilcUInt32)(utf8[i++]  & 0x3))  << 24;
      charval |= ((SilcUInt32)(utf8[i++] & 0x3f)) << 18;
      charval |= ((SilcUInt32)(utf8[i++] & 0x3f)) << 12;
      charval |= (utf8[i++] & 0x3f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x200000)
        return 0;
    } else if ((utf8[i] & 0xfe) == 0xfc) {
      if (utf8_len < 6)
        return 0;

      if (((utf8[i + 1] & 0xc0) != 0x80) || 
	  ((utf8[i + 2] & 0xc0) != 0x80) ||
	  ((utf8[i + 3] & 0xc0) != 0x80) ||
	  ((utf8[i + 4] & 0xc0) != 0x80) ||
	  ((utf8[i + 5] & 0xc0) != 0x80))
        return 0;

      charval = ((SilcUInt32)(utf8[i++]  & 0x1))  << 30;
      charval |= ((SilcUInt32)(utf8[i++] & 0x3f)) << 24;
      charval |= ((SilcUInt32)(utf8[i++] & 0x3f)) << 18;
      charval |= ((SilcUInt32)(utf8[i++] & 0x3f)) << 12;
      charval |= (utf8[i++] & 0x3f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x4000000)
        return 0;
    } else {
      return 0;
    }

    switch (bin_encoding) {
    case SILC_STRING_ASCII:
      if (bin) {
        if (enclen + 1 > bin_size)
          return 0;

        bin[enclen] = (unsigned char)charval;
      }
      enclen++;
      break;
    case SILC_STRING_ASCII_ESC:
      SILC_NOT_IMPLEMENTED("SILC_STRING_ASCII_ESC");
      return 0;
      break;
    case SILC_STRING_BMP:
      SILC_PUT16_MSB(charval, bin + enclen);
      enclen += 2;
      break;
    case SILC_STRING_BMP_LSB:
      SILC_PUT16_LSB(charval, bin + enclen);
      enclen += 2;
      break;
    case SILC_STRING_UNIVERSAL:
      SILC_PUT32_MSB(charval, bin + enclen);
      enclen += 4;
      break;
    case SILC_STRING_UNIVERSAL_LSB:
      SILC_PUT32_LSB(charval, bin + enclen);
      enclen += 4;
      break;
    case SILC_STRING_LANGUAGE:
      break;
    }
  }

  return enclen;
}

/* Returns the length of UTF-8 encoded string if the `bin' of
   encoding of `bin_encoding' is encoded with silc_utf8_encode. */

SilcUInt32 silc_utf8_encoded_len(const unsigned char *bin, SilcUInt32 bin_len,
				 SilcStringEncoding bin_encoding)
{
  return silc_utf8_encode(bin, bin_len, bin_encoding, NULL, 0);
}

/* Returns TRUE if the `utf8' string of length of `utf8_len' is valid
   UTF-8 encoded string, FALSE if it is not UTF-8 encoded string. */

bool silc_utf8_valid(const unsigned char *utf8, SilcUInt32 utf8_len)
{
  return silc_utf8_decode(utf8, utf8_len, 0, NULL, 0) != 0;
}

/* Mime constants and macros */
#define MIME_VERSION "MIME-Version: "
#define MIME_VERSION_LEN 14
#define MIME_CONTENT_TYPE "Content-Type: "
#define MIME_CONTENT_TYPE_LEN 14
#define MIME_TRANSFER_ENCODING "Content-Transfer-Encoding: "
#define MIME_TRANSFER_ENCODING_LEN 27

#define MIME_GET_FIELD(header, mime, mime_len, field, field_len,	\
		       dest, dest_size)					\
do {									\
  if (dest) {								\
    char *f = strstr(header, field);					\
    if (f) {								\
      f = (char *)mime + (f - header) + field_len;			\
      for (i = 0; i < (mime_len - (f - (char *)mime)); i++) {		\
        if (f[i] == '\r' || f[i] == '\n' || i == dest_size)		\
          break;							\
        dest[i] = f[i];							\
      }									\
    }									\
  }									\
} while(0)

/* Parses MIME object and MIME header in it. */

bool 
silc_mime_parse(const unsigned char *mime, SilcUInt32 mime_len,
                char *version, SilcUInt32 version_size,
                char *content_type, SilcUInt32 content_type_size,
                char *transfer_encoding, SilcUInt32 transfer_encoding_size,
                unsigned char **mime_data_ptr, SilcUInt32 *mime_data_len)
{ 
  int i;
  char header[256];
   
  memcpy(header, mime, 256 > mime_len ? mime_len : 256);
  header[sizeof(header) - 1] = '\0';

  /* Check for mandatory Content-Type field */
  if (!strstr(header, MIME_CONTENT_TYPE))
    return FALSE;
  
  /* Get the pointer to the data area in the object */
  for (i = 0; i < mime_len; i++) {
    if (mime_len >= i + 4 &&
	mime[i    ] == '\r' && mime[i + 1] == '\n' &&
	mime[i + 2] == '\r' && mime[i + 3] == '\n')
      break;
  }
  if (i >= mime_len)
    return FALSE;

  if (mime_data_ptr)
    *mime_data_ptr = (unsigned char *)mime + i + 4;
  if (mime_data_len)
    *mime_data_len = mime_len - ((mime + i + 4) - mime);
  
  /* Get MIME version, Content-Type and Transfer Encoding fields */
  MIME_GET_FIELD(header, mime, mime_len,
		 MIME_VERSION, MIME_VERSION_LEN,
		 version, version_size);
  MIME_GET_FIELD(header, mime, mime_len,
		 MIME_CONTENT_TYPE, MIME_CONTENT_TYPE_LEN,
		 content_type, content_type_size);
  MIME_GET_FIELD(header, mime, mime_len,
		 MIME_TRANSFER_ENCODING, MIME_TRANSFER_ENCODING_LEN,
		 transfer_encoding, transfer_encoding_size);

  return TRUE;
}
