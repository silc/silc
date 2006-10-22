/*

  silcstrutil.c

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
/* $Id$ */

#include "silc.h"
#include "silcstrutil.h"

static unsigned char pem_enc[64] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encodes data into PEM encoding. Returns NULL terminated PEM encoded
   data string. */

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

/* Decodes PEM into data. Returns the decoded data. */

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

/* Concatenates the `src' into `dest'.  If `src_len' is more than the
   size of the `dest' (minus NULL at the end) the `src' will be
   truncated to fit. */

char *silc_strncat(char *dest, SilcUInt32 dest_size,
		   const char *src, SilcUInt32 src_len)
{
  int len;

  dest[dest_size - 1] = '\0';

  len = dest_size - 1 - strlen(dest);
  if (len < src_len) {
    if (len > 0)
      strncat(dest, src, len);
  } else {
    strncat(dest, src, src_len);
  }

  return dest;
}

/* Compares two strings. Strings may include wildcards '*' and '?'.
   Returns TRUE if strings match. */

int silc_string_compare(char *string1, char *string2)
{
  int i;
  int slen1;
  int slen2;
  char *tmpstr1, *tmpstr2;

  if (!string1 || !string2)
    return FALSE;

  slen1 = strlen(string1);
  slen2 = strlen(string2);

  /* See if they are same already */
  if (!strncmp(string1, string2, slen2) && slen2 == slen1)
    return TRUE;

  if (slen2 < slen1)
    if (!strchr(string1, '*'))
      return FALSE;

  /* Take copies of the original strings as we will change them */
  tmpstr1 = silc_calloc(slen1 + 1, sizeof(char));
  memcpy(tmpstr1, string1, slen1);
  tmpstr2 = silc_calloc(slen2 + 1, sizeof(char));
  memcpy(tmpstr2, string2, slen2);

  for (i = 0; i < slen1; i++) {

    /* * wildcard. Only one * wildcard is possible. */
    if (tmpstr1[i] == '*')
      if (!strncmp(tmpstr1, tmpstr2, i)) {
	memset(tmpstr2, 0, slen2);
	strncpy(tmpstr2, tmpstr1, i);
	break;
      }

    /* ? wildcard */
    if (tmpstr1[i] == '?') {
      if (!strncmp(tmpstr1, tmpstr2, i)) {
	if (!(slen1 < i + 1))
	  if (tmpstr1[i + 1] != '?' &&
	      tmpstr1[i + 1] != tmpstr2[i + 1])
	    continue;

	if (!(slen1 < slen2))
	  tmpstr2[i] = '?';
      }
    }
  }

  /* if using *, remove it */
  if (strchr(tmpstr1, '*'))
    *strchr(tmpstr1, '*') = 0;

  if (!strcmp(tmpstr1, tmpstr2)) {
    memset(tmpstr1, 0, slen1);
    memset(tmpstr2, 0, slen2);
    silc_free(tmpstr1);
    silc_free(tmpstr2);
    return TRUE;
  }

  memset(tmpstr1, 0, slen1);
  memset(tmpstr2, 0, slen2);
  silc_free(tmpstr1);
  silc_free(tmpstr2);
  return FALSE;
}
