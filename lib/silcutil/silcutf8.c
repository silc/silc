/*

  silcutf8.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2004 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcutf8.h"

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

  if (bin_encoding == SILC_STRING_UTF8) {
    if (!silc_utf8_valid(bin, bin_len))
      return 0;
    if (!utf8)
      return bin_len;
    if (bin_len > utf8_size)
      return 0;
    memcpy(utf8, bin, bin_len);
    return bin_len;
  }

  /* The SILC_STRING_LDAP_DN is alredy UTF-8 but it may be escaped.  We
     remove the escaping and we're done. */
  if (bin_encoding == SILC_STRING_LDAP_DN ||
      bin_encoding == SILC_STRING_UTF8_ESCAPE) {
    unsigned char cv;

    for (i = 0; i < bin_len; i++) {
      if (bin[i] == '\\') {
	if (i + 1 >= bin_len)
	  return 0;

	/* If escaped character is any of the following no processing is
	   needed, otherwise it is a hex value and we need to read it. */
	cv = bin[i + 1];
	if (cv != ',' && cv != '+' && cv != '"' && cv != '\\' && cv != '<' &&
	    cv != '>' && cv != ';' && cv != ' ' && cv != '#') {
	  unsigned int hexval;
	  if (i + 2 >= bin_len)
	    return 0;
	  if (sscanf(&bin[i + 1], "%02X", &hexval) != 1)
	    return 0;
	  if (utf8) {
	    if (enclen + 1 > utf8_size)
	      return 0;
	    utf8[enclen] = (unsigned char)hexval;
	  }

	  i += 2;
	  enclen++;
	  continue;
	}
	i++;
      }

      if (utf8) {
	if (enclen + 1 > utf8_size)
	  return 0;
	utf8[enclen] = bin[i];
      }
      enclen++;
    }

    return enclen;
  }

  if (bin_encoding == SILC_STRING_LOCALE) {
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
      }
      if (icd != (iconv_t)-1)
	iconv_close(icd);
    }
#endif

    /* Fallback to 8-bit ASCII */
    bin_encoding = SILC_STRING_ASCII;
  }

  for (i = 0; i < bin_len; i++) {
    switch (bin_encoding) {
    case SILC_STRING_ASCII:
    case SILC_STRING_TELETEX:
      charval = bin[i];
      break;
    case SILC_STRING_ASCII_ESC:
      SILC_NOT_IMPLEMENTED("SILC_STRING_ASCII_ESC");
      return 0;
      break;
    case SILC_STRING_BMP:
      if (i + 1 >= bin_len)
	return 0;
      SILC_GET16_MSB(charval, bin + i);
      i += 1;
      break;
    case SILC_STRING_BMP_LSB:
      if (i + 1 >= bin_len)
	return 0;
      SILC_GET16_LSB(charval, bin + i);
      i += 1;
      break;
    case SILC_STRING_UNIVERSAL:
      if (i + 3 >= bin_len)
	return 0;
      SILC_GET32_MSB(charval, bin + i);
      i += 3;
      break;
    case SILC_STRING_UNIVERSAL_LSB:
      if (i + 3 >= bin_len)
	return 0;
      SILC_GET32_LSB(charval, bin + i);
      i += 3;
      break;
    case SILC_STRING_PRINTABLE:
    case SILC_STRING_VISIBLE:
      if (!isprint(bin[i]))
	return 0;
      charval = bin[i];
      break;
    case SILC_STRING_NUMERICAL:
      if (bin[i] != 0x20 && !isdigit(bin[i]))
	return 0;
      charval = bin[i];
      break;
    default:
      return 0;
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
  SilcUInt32 enclen = 0, i, charval, bytes;

  if (!utf8 || !utf8_len)
    return 0;

  if (bin_encoding == SILC_STRING_UTF8) {
    if (!silc_utf8_valid(utf8, utf8_len) ||
	utf8_len > bin_size)
      return 0;
    memcpy(bin, utf8, utf8_len);
    return utf8_len;
  }

  if (bin_encoding == SILC_STRING_LOCALE) {
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
      }
      if (icd != (iconv_t)-1)
	iconv_close(icd);
    }
#endif

    /* Fallback to 8-bit ASCII */
    bin_encoding = SILC_STRING_ASCII;
  }

  for (i = 0; i < utf8_len; i++) {
    if ((utf8[i] & 0x80) == 0x00) {
      charval = utf8[i] & 0x7f;
      bytes = 1;
    } else if ((utf8[i] & 0xe0) == 0xc0) {
      if (i + 1 >= utf8_len)
	return 0;

      if ((utf8[i + 1] & 0xc0) != 0x80)
        return 0;

      charval = (utf8[i++] & 0x1f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x80)
        return 0;
      bytes = 2;
    } else if ((utf8[i] & 0xf0) == 0xe0) {
      if (i + 2 >= utf8_len)
	return 0;

      if (((utf8[i + 1] & 0xc0) != 0x80) ||
	  ((utf8[i + 2] & 0xc0) != 0x80))
        return 0;

      /* Surrogates not allowed (D800-DFFF) */
      if (utf8[i] == 0xed &&
	  utf8[i + 1] >= 0xa0 && utf8[i + 1] <= 0xbf &&
	  utf8[i + 2] >= 0x80 && utf8[i + 2] <= 0xbf)
	return 0;

      charval = (utf8[i++]  & 0xf)  << 12;
      charval |= (utf8[i++] & 0x3f) << 6;
      charval |= utf8[i] & 0x3f;
      if (charval < 0x800)
        return 0;
      bytes = 3;
    } else if ((utf8[i] & 0xf8) == 0xf0) {
      if (i + 3 >= utf8_len)
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
      bytes = 4;
    } else if ((utf8[i] & 0xfc) == 0xf8) {
      if (i + 4 >= utf8_len)
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
      bytes = 5;
    } else if ((utf8[i] & 0xfe) == 0xfc) {
      if (i + 5 >= utf8_len)
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
      bytes = 6;
    } else {
      return 0;
    }

    switch (bin_encoding) {
    case SILC_STRING_ASCII:
    case SILC_STRING_PRINTABLE:
    case SILC_STRING_VISIBLE:
    case SILC_STRING_TELETEX:
    case SILC_STRING_NUMERICAL:
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
      if (bin) {
        if (enclen + 2 > bin_size)
          return 0;
	SILC_PUT16_MSB(charval, bin + enclen);
      }
      enclen += 2;
      break;
    case SILC_STRING_BMP_LSB:
      if (bin) {
        if (enclen + 2 > bin_size)
          return 0;
	SILC_PUT16_LSB(charval, bin + enclen);
      }
      enclen += 2;
      break;
    case SILC_STRING_UNIVERSAL:
      if (bin) {
        if (enclen + 4 > bin_size)
          return 0;
	SILC_PUT32_MSB(charval, bin + enclen);
      }
      enclen += 4;
      break;
    case SILC_STRING_UNIVERSAL_LSB:
      if (bin) {
        if (enclen + 4 > bin_size)
          return 0;
	SILC_PUT32_LSB(charval, bin + enclen);
      }
      enclen += 4;
      break;
    case SILC_STRING_LDAP_DN:
      {
        int k;
	unsigned char cv;

	/* Non-printable UTF-8 characters will be escaped, printable will
	   be as is.  We take the bytes directly from the original data. */
	for (k = 0; k < bytes; k++) {
	  cv = utf8[(i - (bytes - 1)) + k];

	  /* If string starts with space or # escape it */
	  if (!enclen && (cv == '#' || cv == ' ')) {
	    if (bin) {
	      if (enclen + 2 > bin_size)
		return 0;
	      bin[enclen] = '\\';
	      bin[enclen + 1] = cv;
	    }
	    enclen += 2;
	    continue;
	  }

	  /* If string ends with space escape it */
	  if (i == utf8_len - 1 && cv == ' ') {
	    if (bin) {
	      if (enclen + 2 > bin_size)
		return 0;
	      bin[enclen] = '\\';
	      bin[enclen + 1] = cv;
	    }
	    enclen += 2;
	    continue;
	  }

	  /* If character is any of following then escape */
	  if (cv == ',' || cv == '+' || cv == '"' || cv == '\\' || cv == '<' ||
	      cv == '>' || cv == ';') {
	    if (bin) {
	      if (enclen + 2 > bin_size)
		return 0;
	      bin[enclen] = '\\';
	      bin[enclen + 1] = cv;
	    }
	    enclen += 2;
	    continue;
	  }

	  /* If character is not printable escape it with hex character */
	  if (!isprint((int)cv)) {
	    if (bin) {
	      if (enclen + 3 > bin_size)
		return 0;
	      bin[enclen] = '\\';
	      silc_snprintf(bin + enclen + 1, 3, "%02X", cv);
	    }
	    enclen += 3;
	    continue;
	  }

	  if (bin) {
	    if (enclen + 1 > bin_size)
	      return 0;
	    bin[enclen] = cv;
	  }
	  enclen++;
	}
      }
      break;
    default:
      return 0;
      break;
    }
  }

  return enclen;
}

/* UTF-8 to wide characters */

SilcUInt32 silc_utf8_c2w(const unsigned char *utf8, SilcUInt32 utf8_len,
			 SilcUInt16 *utf8_wide, SilcUInt32 utf8_wide_size)
{
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  int i, k;

  tmp_len = silc_utf8_decoded_len(utf8, utf8_len, SILC_STRING_BMP);
  if (!tmp_len)
    return 0;

  if (utf8_wide_size < tmp_len / 2)
    return 0;

  memset(utf8_wide, 0, utf8_wide_size * 2);

  tmp = silc_malloc(tmp_len);
  if (!tmp)
    return 0;

  silc_utf8_decode(utf8, utf8_len, SILC_STRING_BMP, tmp, tmp_len);

  for (i = 0, k = 0; i < tmp_len; i += 2, k++)
    SILC_GET16_MSB(utf8_wide[k], tmp + i);

  silc_free(tmp);
  return k + 1;
}

/* Wide characters to UTF-8 */

SilcUInt32 silc_utf8_w2c(const SilcUInt16 *wide_str,
			 SilcUInt32 wide_str_len,
			 unsigned char *utf8, SilcUInt32 utf8_size)

{
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  int i, k;

  if (utf8_size < wide_str_len * 2)
    return 0;

  memset(utf8, 0, utf8_size);

  tmp = silc_malloc(wide_str_len * 2);
  if (!tmp)
    return 0;

  for (i = 0, k = 0; i < wide_str_len; i += 2, k++)
    SILC_PUT16_MSB(wide_str[k], tmp + i);

  tmp_len = silc_utf8_encode(tmp, wide_str_len * 2, SILC_STRING_BMP,
			     utf8, utf8_size);

  silc_free(tmp);
  return tmp_len;
}

/* Returns the length of UTF-8 encoded string if the `bin' of
   encoding of `bin_encoding' is encoded with silc_utf8_encode. */

SilcUInt32 silc_utf8_encoded_len(const unsigned char *bin, SilcUInt32 bin_len,
				 SilcStringEncoding bin_encoding)
{
  return silc_utf8_encode(bin, bin_len, bin_encoding, NULL, 0);
}

/* Returns the length of decoded string if the `bin' of encoding of
   `bin_encoding' is decoded with silc_utf8_decode. */

SilcUInt32 silc_utf8_decoded_len(const unsigned char *bin, SilcUInt32 bin_len,
				 SilcStringEncoding bin_encoding)
{
  return silc_utf8_decode(bin, bin_len, bin_encoding, NULL, 0);
}

/* Returns TRUE if the `utf8' string of length of `utf8_len' is valid
   UTF-8 encoded string, FALSE if it is not UTF-8 encoded string. */

SilcBool silc_utf8_valid(const unsigned char *utf8, SilcUInt32 utf8_len)
{
  return silc_utf8_decode(utf8, utf8_len, 0, NULL, 0) != 0;
}

/* Pretty close strcasecmp */

SilcBool silc_utf8_strcasecmp(const char *s1, const char *s2)
{
  if (s1 == s2)
    return TRUE;
  if (strlen(s1) != strlen(s2))
    return FALSE;

  return silc_utf8_strncasecmp(s1, s2, strlen(s1));
}

/* Pretty close strcasecmp */

SilcBool silc_utf8_strncasecmp(const char *s1, const char *s2, SilcUInt32 n)
{
  unsigned char *s1u, *s2u;
  SilcUInt32 s1u_len, s2u_len;
  SilcStringprepStatus status;
  SilcBool ret;

  if (s1 == s2)
    return TRUE;

  /* Casefold and normalize */
  status = silc_stringprep(s1, n, SILC_STRING_UTF8,
			   SILC_IDENTIFIERC_PREP, 0, &s1u,
			   &s1u_len, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK)
    return FALSE;

  /* Casefold and normalize */
  status = silc_stringprep(s2, n, SILC_STRING_UTF8,
			   SILC_IDENTIFIERC_PREP, 0, &s2u,
			   &s2u_len, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK)
    return FALSE;

  ret = !memcmp(s1u, s2u, n);

  silc_free(s1u);
  silc_free(s2u);

  return ret;
}
