/*

  silcbuffmt.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

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

/* Macros to check whether there is enough free space to add the
   required amount of data. For unformatting this means that there must
   be the data that is to be extracted. */
#define FORMAT_HAS_SPACE(__x__, __req__)	\
  do {						\
    if (__req__ > silc_buffer_len((__x__)))	\
      goto fail;				\
  } while(0)
#define UNFORMAT_HAS_SPACE(__x__, __req__)	\
  do {						\
    if (__req__ > silc_buffer_len((__x__)))	\
      goto fail;				\
    if ((__req__ + 1) <= 0)			\
      goto fail;				\
  } while(0)

/* Formats the arguments sent and puts them into the buffer sent as
   argument. The buffer must be initialized beforehand and it must have
   enough free space to include the formatted data. If this function
   fails caller should not trust the buffer anymore and should free it.
   This function is used, for example, to create packets to send over
   network. */

int silc_buffer_format(SilcBuffer dst, ...)
{
  va_list ap;
  int ret;

  va_start(ap, dst);
  ret = silc_buffer_format_vp(dst, ap);
  va_end(ap);

  return ret;
}

int silc_buffer_format_vp(SilcBuffer dst, va_list ap)
{
  SilcBufferParamType fmt;
  unsigned char *start_ptr = dst->data;
  int len;

  /* Parse the arguments by formatting type. */
  while (1) {
    fmt = va_arg(ap, SilcBufferParamType);

    switch(fmt) {
    case SILC_BUFFER_PARAM_OFFSET:
      {
	int offst = va_arg(ap, int);
	if (!offst)
	  break;
	if (offst > 1) {
	  FORMAT_HAS_SPACE(dst, offst);
	  silc_buffer_pull(dst, offst);
	} else {
	  silc_buffer_push(dst, -(offst));
	}
	break;
      }
    case SILC_BUFFER_PARAM_SI8_CHAR:
      {
	char x = (char)va_arg(ap, int);
	FORMAT_HAS_SPACE(dst, 1);
	silc_buffer_put(dst, &x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_CHAR:
      {
	unsigned char x = (unsigned char)va_arg(ap, int);
	FORMAT_HAS_SPACE(dst, 1);
	silc_buffer_put(dst, &x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }
    case SILC_BUFFER_PARAM_SI16_SHORT:
      {
	unsigned char xf[2];
	SilcInt16 x = (SilcInt16)va_arg(ap, int);
	FORMAT_HAS_SPACE(dst, 2);
	SILC_PUT16_MSB(x, xf);
	silc_buffer_put(dst, xf, 2);
	silc_buffer_pull(dst, 2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_SHORT:
      {
	unsigned char xf[2];
	SilcUInt16 x = (SilcUInt16)va_arg(ap, int);
	FORMAT_HAS_SPACE(dst, 2);
	SILC_PUT16_MSB(x, xf);
	silc_buffer_put(dst, xf, 2);
	silc_buffer_pull(dst, 2);
	break;
      }
    case SILC_BUFFER_PARAM_SI32_INT:
      {
	unsigned char xf[4];
	SilcInt32 x = va_arg(ap, SilcInt32);
	FORMAT_HAS_SPACE(dst, 4);
	SILC_PUT32_MSB(x, xf);
	silc_buffer_put(dst, xf, 4);
	silc_buffer_pull(dst, 4);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_INT:
      {
	unsigned char xf[4];
	SilcUInt32 x = va_arg(ap, SilcUInt32);
	FORMAT_HAS_SPACE(dst, 4);
	SILC_PUT32_MSB(x, xf);
	silc_buffer_put(dst, xf, 4);
	silc_buffer_pull(dst, 4);
	break;
      }
    case SILC_BUFFER_PARAM_SI64_INT:
      {
	unsigned char xf[8];
	SilcInt64 x = va_arg(ap, SilcInt64);
	FORMAT_HAS_SPACE(dst, sizeof(SilcInt64));
	SILC_PUT64_MSB(x, xf);
	silc_buffer_put(dst, xf, sizeof(SilcInt64));
	silc_buffer_pull(dst, sizeof(SilcInt64));
	break;
      }
    case SILC_BUFFER_PARAM_UI64_INT:
      {
	unsigned char xf[8];
	SilcUInt64 x = va_arg(ap, SilcUInt64);
	FORMAT_HAS_SPACE(dst, sizeof(SilcUInt64));
	SILC_PUT64_MSB(x, xf);
	silc_buffer_put(dst, xf, sizeof(SilcUInt64));
	silc_buffer_pull(dst, sizeof(SilcUInt64));
	break;
      }
    case SILC_BUFFER_PARAM_UI8_STRING:
    case SILC_BUFFER_PARAM_UI16_STRING:
    case SILC_BUFFER_PARAM_UI32_STRING:
    case SILC_BUFFER_PARAM_UI8_STRING_ALLOC:
    case SILC_BUFFER_PARAM_UI16_STRING_ALLOC:
    case SILC_BUFFER_PARAM_UI32_STRING_ALLOC:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	SilcUInt32 tmp_len = strlen(x);
	FORMAT_HAS_SPACE(dst, tmp_len);
	silc_buffer_put(dst, x, tmp_len);
	silc_buffer_pull(dst, tmp_len);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_NSTRING:
    case SILC_BUFFER_PARAM_UI16_NSTRING:
    case SILC_BUFFER_PARAM_UI32_NSTRING:
    case SILC_BUFFER_PARAM_UI_XNSTRING:
    case SILC_BUFFER_PARAM_UI8_NSTRING_ALLOC:
    case SILC_BUFFER_PARAM_UI16_NSTRING_ALLOC:
    case SILC_BUFFER_PARAM_UI32_NSTRING_ALLOC:
    case SILC_BUFFER_PARAM_UI_XNSTRING_ALLOC:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	SilcUInt32 len = va_arg(ap, SilcUInt32);
	if (x && len) {
	  FORMAT_HAS_SPACE(dst, len);
	  silc_buffer_put(dst, x, len);
	  silc_buffer_pull(dst, len);
	}
	break;
      }
    case SILC_BUFFER_PARAM_END:
      goto ok;
      break;
    default:
      SILC_LOG_DEBUG(("Bad buffer formatting type `%d'. Could not "
		      "format the data.", fmt));
      goto fail;
      break;
    }
  }

 fail:
  SILC_LOG_DEBUG(("Error occured while formatting data"));
  len = dst->data - start_ptr;
  silc_buffer_push(dst, len);
  return -1;

 ok:
  /* Push the buffer back to where it belongs. */
  len = dst->data - start_ptr;
  silc_buffer_push(dst, len);
  return len;
}

/* Unformats the buffer sent as argument. The unformatted data is returned
   to the variable argument list of pointers. The buffer must point to the
   start of the data area to be unformatted. Buffer maybe be safely free'd
   after this returns succesfully. */

int silc_buffer_unformat(SilcBuffer src, ...)
{
  va_list ap;
  int ret;

  va_start(ap, src);
  ret = silc_buffer_unformat_vp(src, ap);
  va_end(ap);

  return ret;
}

int silc_buffer_unformat_vp(SilcBuffer src, va_list ap)
{
  SilcBufferParamType fmt;
  unsigned char *start_ptr = src->data;
  int len = 0;

  /* Parse the arguments by formatting type. */
  while(1) {
    fmt = va_arg(ap, SilcBufferParamType);

    switch(fmt) {
    case SILC_BUFFER_PARAM_OFFSET:
      {
	int offst = va_arg(ap, int);
	if (!offst)
	  break;
	if (offst > 1) {
	  UNFORMAT_HAS_SPACE(src, offst);
	  silc_buffer_pull(src, offst);
	} else {
	  silc_buffer_push(src, -(offst));
	}
	break;
      }
    case SILC_BUFFER_PARAM_SI8_CHAR:
      {
	char *x = va_arg(ap, char *);
	UNFORMAT_HAS_SPACE(src, 1);
	if (x)
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_CHAR:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	UNFORMAT_HAS_SPACE(src, 1);
	if (x)
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }
    case SILC_BUFFER_PARAM_SI16_SHORT:
      {
	SilcInt16 *x = va_arg(ap, SilcInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	if (x)
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_SHORT:
      {
	SilcUInt16 *x = va_arg(ap, SilcUInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	if (x)
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }
    case SILC_BUFFER_PARAM_SI32_INT:
      {
	SilcInt32 *x = va_arg(ap, SilcInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	if (x)
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_INT:
      {
	SilcUInt32 *x = va_arg(ap, SilcUInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	if (x)
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }
    case SILC_BUFFER_PARAM_SI64_INT:
      {
	SilcInt64 *x = va_arg(ap, SilcInt64 *);
	UNFORMAT_HAS_SPACE(src, sizeof(SilcInt64));
	if (x)
	  SILC_GET64_MSB(*x, src->data);
	silc_buffer_pull(src, sizeof(SilcInt64));
	break;
      }
    case SILC_BUFFER_PARAM_UI64_INT:
      {
	SilcUInt64 *x = va_arg(ap, SilcUInt64 *);
	UNFORMAT_HAS_SPACE(src, sizeof(SilcUInt64));
	if (x)
	  SILC_GET64_MSB(*x, src->data);
	silc_buffer_pull(src, sizeof(SilcUInt64));
	break;
      }
    case SILC_BUFFER_PARAM_UI8_STRING:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_STRING:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_STRING_ALLOC:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (x && len2) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_STRING_ALLOC:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (x && len2) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_STRING:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_STRING_ALLOC:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (x && len2) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_NSTRING:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt8 *len = va_arg(ap, SilcUInt8 *);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len)
	  *len = len2;
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_NSTRING:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt16 *len = va_arg(ap, SilcUInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len)
	  *len = len2;
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_NSTRING_ALLOC:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt8 *len = va_arg(ap, SilcUInt8 *);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len)
	  *len = len2;
	if (x && len2) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_NSTRING_ALLOC:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt16 *len = va_arg(ap, SilcUInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len)
	  *len = len2;
	if (x && len2) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_NSTRING:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 *len = va_arg(ap, SilcUInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len)
	  *len = len2;
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI_XNSTRING:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 len = va_arg(ap, SilcUInt32);
	UNFORMAT_HAS_SPACE(src, len);
	if (len && x)
	  *x = src->data;
	silc_buffer_pull(src, len);
	break;
      }
    case SILC_BUFFER_PARAM_UI_XNSTRING_ALLOC:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 len = va_arg(ap, SilcUInt32);
	UNFORMAT_HAS_SPACE(src, len);
	if (len && x) {
	  *x = silc_calloc(len + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len);
	}
	silc_buffer_pull(src, len);
	break;
      }
    case SILC_BUFFER_PARAM_END:
      goto ok;
      break;
    default:
      SILC_LOG_DEBUG(("Bad buffer formatting type `%d'. Could not "
		      "format the data.", fmt));
      goto fail;
      break;
    }
  }

 fail:
  SILC_LOG_DEBUG(("Error occured while unformatting buffer"));
  len = src->data - start_ptr;
  silc_buffer_push(src, len);
  return -1;

 ok:
  /* Push the buffer back to the start. */
  len = src->data - start_ptr;
  silc_buffer_push(src, len);
  return len;
}

/* Formats strings into a buffer */

int silc_buffer_strformat(SilcBuffer dst, ...)
{
  int len = silc_buffer_truelen(dst);
  va_list va;

  va_start(va, dst);

  /* Parse the arguments by formatting type. */
  while(1) {
    char *string = va_arg(va, char *);
    unsigned char *d;
    SilcInt32 slen;

    if (!string)
      continue;
    if (string == (char *)SILC_BUFFER_PARAM_END)
      goto ok;

    slen = strlen(string);
    d = silc_realloc(dst->head, sizeof(*dst->head) * (slen + len + 1));
    if (!d)
      return -1;
    dst->head = d;
    memcpy(dst->head + len, string, slen);
    len += slen;
    dst->head[len] = '\0';
  }

  SILC_LOG_DEBUG(("Error occured while formatting buffer"));
  va_end(va);
  return -1;

 ok:
  dst->end = dst->head + len;
  dst->data = dst->head;
  dst->tail = dst->end;

  va_end(va);
  return len;
}

/* Formats strings into a buffer.  Allocates memory from SilcStack. */

int silc_buffer_sstrformat(SilcStack stack, SilcBuffer dst, ...)
{
  int len = silc_buffer_truelen(dst);
  va_list va;

  va_start(va, dst);

  /* Parse the arguments by formatting type. */
  while(1) {
    char *string = va_arg(va, char *);
    unsigned char *d;
    SilcInt32 slen;

    if (!string)
      continue;
    if (string == (char *)SILC_BUFFER_PARAM_END)
      goto ok;

    slen = strlen(string);
    d = silc_srealloc_ua(stack, len, dst->head,
			 sizeof(*dst->head) * (slen + len + 1));
    if (!d)
      return -1;
    dst->head = d;
    memcpy(dst->head + len, string, slen);
    len += slen;
    dst->head[len] = '\0';
  }

  SILC_LOG_DEBUG(("Error occured while formatting buffer"));
  va_end(va);
  return -1;

 ok:
  dst->end = dst->head + len;
  dst->data = dst->head;
  dst->tail = dst->end;

  va_end(va);
  return len;
}
