/*

  silcstrutil.c

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
/* $Id$ */

#include "silcincludes.h"
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

/* Mime constants and macros */
#define MIME_VERSION "MIME-Version: "
#define MIME_VERSION_LEN 14
#define MIME_CONTENT_TYPE "Content-Type: "
#define MIME_CONTENT_TYPE_LEN 14
#define MIME_TRANSFER_ENCODING "Content-Transfer-Encoding: "
#define MIME_TRANSFER_ENCODING_LEN 27

#define MIME_GET_FIELD(mime, mime_len, field, field_len,		\
		       dest, dest_size)					\
do {									\
  if (dest) {								\
    char *f = strstr(mime, field);					\
    if (f) {								\
      int parse_len;							\
      f += field_len;							\
      parse_len = (mime_len - (f - (char *)mime));			\
      for (i = 0; i < parse_len; i++) {					\
        if ((i == dest_size) ||						\
	    ((f[i] == '\n') && 						\
	       ((i == parse_len - 1) ||					\
		  ((f[i+1] != ' ') && (f[i+1] != '\t')))) ||		\
	    ((f[i] == '\r') &&						\
	       ((i == parse_len - 1) || (f[i+1] == '\n')) &&		\
	       ((i >= parse_len - 2) || 				\
		  ((f[i+2] != ' ') && (f[i+2] != '\t')))))		\
          break;							\
        dest[i] = f[i];							\
      }									\
    }									\
  }									\
} while(0)

/* Parses MIME object and MIME header in it. */

SilcBool
silc_mime_parse(const unsigned char *mime, SilcUInt32 mime_len,
                char *version, SilcUInt32 version_size,
                char *content_type, SilcUInt32 content_type_size,
                char *transfer_encoding, SilcUInt32 transfer_encoding_size,
                unsigned char **mime_data_ptr, SilcUInt32 *mime_data_len)
{
  int i;
  unsigned char *tmp;

  /* Get the pointer to the data area in the object */
  for (i = 0; i < mime_len; i++) {
    if ((mime_len >= i + 4 &&
	 mime[i    ] == '\r' && mime[i + 1] == '\n' &&
	 mime[i + 2] == '\r' && mime[i + 3] == '\n') ||
	(mime_len >= i + 2 &&
	 mime[i    ] == '\n' && mime[i + 1] == '\n'))
      break;
  }
  if (i >= mime_len)
    return FALSE;

  if (mime_data_ptr)
    *mime_data_ptr = (unsigned char *)mime + i +
	    (mime[i] == '\n' ? 2 : 4);
  if (mime_data_len)
    *mime_data_len = mime_len - (i + (mime[i] == '\n' ? 2 : 4));

  /* Check for mandatory Content-Type field */
  tmp = strstr(mime, MIME_CONTENT_TYPE);
  if (!tmp || (tmp - mime) >= i)
    return FALSE;

  /* Get MIME version, Content-Type and Transfer Encoding fields */
  MIME_GET_FIELD(mime, mime_len,
		 MIME_VERSION, MIME_VERSION_LEN,
		 version, version_size);
  MIME_GET_FIELD(mime, mime_len,
		 MIME_CONTENT_TYPE, MIME_CONTENT_TYPE_LEN,
		 content_type, content_type_size);
  MIME_GET_FIELD(mime, mime_len,
		 MIME_TRANSFER_ENCODING, MIME_TRANSFER_ENCODING_LEN,
		 transfer_encoding, transfer_encoding_size);

  return TRUE;
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

/* Checks that the 'identifier' string is valid identifier string
   and does not contain any unassigned or prohibited character.  This
   function is used to check for valid nicknames, channel names,
   server names, usernames, hostnames, service names, algorithm names,
   other security property names, and SILC Public Key name. */

unsigned char *silc_identifier_check(const unsigned char *identifier,
				     SilcUInt32 identifier_len,
				     SilcStringEncoding identifier_encoding,
				     SilcUInt32 max_allowed_length,
				     SilcUInt32 *out_len)
{
  unsigned char *utf8s;
  SilcUInt32 utf8s_len;
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return NULL;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return NULL;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_PREP, 0,
			   &utf8s, &utf8s_len, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return NULL;
  }

  if (out_len)
    *out_len = utf8s_len;

  return utf8s;
}

/* Same as above but does not allocate memory, just checks the
   validity of the string. */

SilcBool silc_identifier_verify(const unsigned char *identifier,
			    SilcUInt32 identifier_len,
			    SilcStringEncoding identifier_encoding,
			    SilcUInt32 max_allowed_length)
{
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return FALSE;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return FALSE;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_PREP, 0,
			   NULL, NULL, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return FALSE;
  }

  return TRUE;
}

unsigned char *silc_channel_name_check(const unsigned char *identifier,
				       SilcUInt32 identifier_len,
				       SilcStringEncoding identifier_encoding,
				       SilcUInt32 max_allowed_length,
				       SilcUInt32 *out_len)
{
  unsigned char *utf8s;
  SilcUInt32 utf8s_len;
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return NULL;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return NULL;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_CH_PREP, 0,
			   &utf8s, &utf8s_len, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return NULL;
  }

  if (out_len)
    *out_len = utf8s_len;

  return utf8s;
}

/* Same as above but does not allocate memory, just checks the
   validity of the string. */

SilcBool silc_channel_name_verify(const unsigned char *identifier,
			      SilcUInt32 identifier_len,
			      SilcStringEncoding identifier_encoding,
			      SilcUInt32 max_allowed_length)
{
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return FALSE;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return FALSE;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_CH_PREP, 0,
			   NULL, NULL, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return FALSE;
  }

  return TRUE;
}
