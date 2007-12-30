/*

  silcbuffmt.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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

/************************** Types and definitions ***************************/

/* Check that buffer has enough room to format data in it, if not
   allocate more. */
#define FORMAT_HAS_SPACE(s, b, req)			\
do {							\
  if (silc_unlikely(!silc_buffer_senlarge(s, b, req)))	\
    goto fail;						\
  flen += req;						\
} while(0)

/* Check that there is data to be unformatted */
#define UNFORMAT_HAS_SPACE(b, req)		        \
do {							\
  if (silc_unlikely(req > silc_buffer_len(b))) {	\
    silc_set_errno(SILC_ERR_OVERFLOW);			\
    goto fail;						\
  }							\
  if (silc_unlikely((req + 1) <= 0)) {			\
    silc_set_errno(SILC_ERR_UNDERFLOW);			\
    goto fail;						\
  }							\
} while(0)


/******************************* Formatting *********************************/

int silc_buffer_format(SilcBuffer dst, ...)
{
  va_list ap;
  int ret;

  va_start(ap, dst);
  ret = silc_buffer_sformat_vp(NULL, dst, ap);
  va_end(ap);

  return ret;
}

int silc_buffer_format_vp(SilcBuffer dst, va_list ap)
{
  return silc_buffer_sformat_vp(NULL, dst, ap);
}

int silc_buffer_sformat(SilcStack stack, SilcBuffer dst, ...)
{
  va_list ap;
  int ret;

  va_start(ap, dst);
  ret = silc_buffer_sformat_vp(stack, dst, ap);
  va_end(ap);

  return ret;
}

int silc_buffer_sformat_vp(SilcStack stack, SilcBuffer dst, va_list ap)
{
  SilcParam fmt;
  int flen = 0;
  SilcBool advance = FALSE;

  /* Parse the arguments by formatting type. */
  while (1) {
    fmt = va_arg(ap, SilcParam);

    SILC_LOG_DEBUG(("Buffer format type %x", fmt));

    switch (fmt) {
    case SILC_PARAM_FUNC:
      {
	SilcBufferFormatFunc func;
	void *val;
	void *context;
	int tmp_len;
	func = va_arg(ap, SilcBufferFormatFunc);
	val = va_arg(ap, void *);
	context = va_arg(ap, void *);
	tmp_len = func(stack, dst, val, context);
	if (tmp_len < 0)
	  goto fail;
	if (tmp_len) {
	  silc_buffer_pull(dst, tmp_len);
	  flen += tmp_len;
	}
      }
      break;
    case SILC_PARAM_UI8_STRING:
    case SILC_PARAM_UI16_STRING:
    case SILC_PARAM_UI32_STRING:
    case SILC_PARAM_UI8_STRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UI16_STRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UI32_STRING | SILC_PARAM_ALLOC:
      {
	char *x = va_arg(ap, char *);
	SilcUInt32 tmp_len = x ? strlen(x) : 0;
	if (x && tmp_len) {
	  FORMAT_HAS_SPACE(stack, dst, tmp_len);
	  silc_buffer_put(dst, (unsigned char *)x, tmp_len);
	  silc_buffer_pull(dst, tmp_len);
	}
	break;
      }
    case SILC_PARAM_UI8_NSTRING:
    case SILC_PARAM_UI16_NSTRING:
    case SILC_PARAM_UI32_NSTRING:
    case SILC_PARAM_UICHAR:
    case SILC_PARAM_UI8_NSTRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UI16_NSTRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UI32_NSTRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UICHAR | SILC_PARAM_ALLOC:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	SilcUInt32 tmp_len = va_arg(ap, SilcUInt32);
	if (x && tmp_len) {
	  FORMAT_HAS_SPACE(stack, dst, tmp_len);
	  silc_buffer_put(dst, x, tmp_len);
	  silc_buffer_pull(dst, tmp_len);
	}
	break;
      }
    case SILC_PARAM_UINT8:
      {
	unsigned char x = (unsigned char)va_arg(ap, int);
	FORMAT_HAS_SPACE(stack, dst, 1);
	silc_buffer_put(dst, &x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }
    case SILC_PARAM_UINT16:
      {
	unsigned char xf[2];
	SilcUInt16 x = (SilcUInt16)va_arg(ap, int);
	FORMAT_HAS_SPACE(stack, dst, 2);
	SILC_PUT16_MSB(x, xf);
	silc_buffer_put(dst, xf, 2);
	silc_buffer_pull(dst, 2);
	break;
      }
    case SILC_PARAM_UINT32:
      {
	unsigned char xf[4];
	SilcUInt32 x = va_arg(ap, SilcUInt32);
	FORMAT_HAS_SPACE(stack, dst, 4);
	SILC_PUT32_MSB(x, xf);
	silc_buffer_put(dst, xf, 4);
	silc_buffer_pull(dst, 4);
	break;
      }
    case SILC_PARAM_UINT64:
      {
	unsigned char xf[8];
	SilcUInt64 x = va_arg(ap, SilcUInt64);
	FORMAT_HAS_SPACE(stack, dst, sizeof(SilcUInt64));
	SILC_PUT64_MSB(x, xf);
	silc_buffer_put(dst, xf, sizeof(SilcUInt64));
	silc_buffer_pull(dst, sizeof(SilcUInt64));
	break;
      }
    case SILC_PARAM_SINT8:
      {
	char x = (char)va_arg(ap, int);
	FORMAT_HAS_SPACE(stack, dst, 1);
	silc_buffer_put(dst, (unsigned char *)&x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }
    case SILC_PARAM_SINT16:
      {
	unsigned char xf[2];
	SilcInt16 x = (SilcInt16)va_arg(ap, int);
	FORMAT_HAS_SPACE(stack, dst, 2);
	SILC_PUT16_MSB(x, xf);
	silc_buffer_put(dst, xf, 2);
	silc_buffer_pull(dst, 2);
	break;
      }
    case SILC_PARAM_SINT32:
      {
	unsigned char xf[4];
	SilcInt32 x = va_arg(ap, SilcInt32);
	FORMAT_HAS_SPACE(stack, dst, 4);
	SILC_PUT32_MSB(x, xf);
	silc_buffer_put(dst, xf, 4);
	silc_buffer_pull(dst, 4);
	break;
      }
    case SILC_PARAM_SINT64:
      {
	unsigned char xf[8];
	SilcInt64 x = va_arg(ap, SilcInt64);
	FORMAT_HAS_SPACE(stack, dst, sizeof(SilcInt64));
	SILC_PUT64_MSB(x, xf);
	silc_buffer_put(dst, xf, sizeof(SilcInt64));
	silc_buffer_pull(dst, sizeof(SilcInt64));
	break;
      }
    case SILC_PARAM_BUFFER:
    case SILC_PARAM_BUFFER | SILC_PARAM_ALLOC:
      {
	SilcBuffer x = va_arg(ap, SilcBuffer);
	unsigned char xf[4];
	if (x && silc_buffer_len(x)) {
	  FORMAT_HAS_SPACE(stack, dst, silc_buffer_len(x) + 4);
	  SILC_PUT32_MSB(silc_buffer_len(x), xf);
	  silc_buffer_put(dst, xf, 4);
	  silc_buffer_pull(dst, 4);
	  silc_buffer_put(dst, silc_buffer_data(x), silc_buffer_len(x));
	  silc_buffer_pull(dst, silc_buffer_len(x));
	}
      }
      break;
    case SILC_PARAM_OFFSET:
      {
	int offst = va_arg(ap, int);
	if (!offst)
	  break;
	if (offst > 1) {
	  if (offst > silc_buffer_len(dst)) {
	    silc_set_errno(SILC_ERR_OVERFLOW);
	    goto fail;
	  }
	  silc_buffer_pull(dst, offst);
	  flen += offst;
	} else {
	  silc_buffer_push(dst, -(offst));
	  flen += -(offst);
	}
	break;
      }
    case SILC_PARAM_ADVANCE:
      advance = TRUE;
      break;
    case SILC_PARAM_END:
      goto ok;
      break;
    default:
      SILC_LOG_DEBUG(("Bad buffer formatting type `%d'. Could not "
		      "format the data.", fmt));
      silc_set_errno_reason(SILC_ERR_INVALID_ARGUMENT,
			    "Bad buffer formatting type %d", fmt);
      goto fail;
      break;
    }
  }

 fail:
  SILC_LOG_DEBUG(("Error occured while formatting data"));
  if (!advance)
    silc_buffer_push(dst, flen);
  return -1;

 ok:
  /* Push the buffer back to where it belongs. */
  if (!advance)
    silc_buffer_push(dst, flen);
  return flen;
}


/****************************** Unformatting ********************************/

int silc_buffer_unformat(SilcBuffer src, ...)
{
  va_list ap;
  int ret;

  va_start(ap, src);
  ret = silc_buffer_sunformat_vp(NULL, src, ap);
  va_end(ap);

  return ret;
}

int silc_buffer_unformat_vp(SilcBuffer src, va_list ap)
{
  return silc_buffer_sunformat_vp(NULL, src, ap);
}

int silc_buffer_sunformat(SilcStack stack, SilcBuffer src, ...)
{
  va_list ap;
  int ret;

  va_start(ap, src);
  ret = silc_buffer_sunformat_vp(stack, src, ap);
  va_end(ap);

  return ret;
}

int silc_buffer_sunformat_vp(SilcStack stack, SilcBuffer src, va_list ap)
{
  SilcParam fmt;
  unsigned char *start_ptr = src->data;
  int len = 0;
  SilcBool advance = FALSE;

  /* Parse the arguments by formatting type. */
  while (1) {
    fmt = va_arg(ap, SilcParam);

    SILC_LOG_DEBUG(("Buffer unformat type %x", fmt));

    switch (fmt) {
    case SILC_PARAM_FUNC:
      {
	SilcBufferUnformatFunc func;
	void **val;
	void *context;
	int tmp_len;
	func = va_arg(ap, SilcBufferUnformatFunc);
	val = va_arg(ap, void **);
	context = va_arg(ap, void *);
	tmp_len = func(stack, src, val, context);
	if (tmp_len < 0)
	  goto fail;
	if (tmp_len) {
	  UNFORMAT_HAS_SPACE(src, tmp_len);
	  silc_buffer_pull(src, tmp_len);
	}
      }
    case SILC_PARAM_UICHAR:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 len2 = va_arg(ap, SilcUInt32);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(len2 && x))
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UICHAR | SILC_PARAM_ALLOC:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 len2 = va_arg(ap, SilcUInt32);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(len2 && x)) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UINT8:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	UNFORMAT_HAS_SPACE(src, 1);
	if (silc_likely(x))
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }
    case SILC_PARAM_UINT16:
      {
	SilcUInt16 *x = va_arg(ap, SilcUInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	if (silc_likely(x))
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }
    case SILC_PARAM_UINT32:
      {
	SilcUInt32 *x = va_arg(ap, SilcUInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	if (silc_likely(x))
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }
    case SILC_PARAM_UINT64:
      {
	SilcUInt64 *x = va_arg(ap, SilcUInt64 *);
	UNFORMAT_HAS_SPACE(src, sizeof(SilcUInt64));
	if (silc_likely(x))
	  SILC_GET64_MSB(*x, src->data);
	silc_buffer_pull(src, sizeof(SilcUInt64));
	break;
      }
    case SILC_PARAM_SINT8:
      {
	char *x = va_arg(ap, char *);
	UNFORMAT_HAS_SPACE(src, 1);
	if (silc_likely(x))
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }
    case SILC_PARAM_SINT16:
      {
	SilcInt16 *x = va_arg(ap, SilcInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	if (silc_likely(x))
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }
    case SILC_PARAM_SINT32:
      {
	SilcInt32 *x = va_arg(ap, SilcInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	if (silc_likely(x))
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }
    case SILC_PARAM_SINT64:
      {
	SilcInt64 *x = va_arg(ap, SilcInt64 *);
	UNFORMAT_HAS_SPACE(src, sizeof(SilcInt64));
	if (silc_likely(x))
	  SILC_GET64_MSB(*x, src->data);
	silc_buffer_pull(src, sizeof(SilcInt64));
	break;
      }
    case SILC_PARAM_UI8_STRING:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(x))
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI8_STRING | SILC_PARAM_ALLOC:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(x && len2)) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI16_STRING:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(x))
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI16_STRING | SILC_PARAM_ALLOC:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(x && len2)) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI32_STRING:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(x))
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI32_STRING | SILC_PARAM_ALLOC:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (silc_likely(x && len2)) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI8_NSTRING:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt8 *len3 = va_arg(ap, SilcUInt8 *);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len3)
	  *len3 = len2;
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI8_NSTRING | SILC_PARAM_ALLOC:
      {
	SilcUInt8 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt8 *len3 = va_arg(ap, SilcUInt8 *);
	UNFORMAT_HAS_SPACE(src, 1);
	len2 = (SilcUInt8)src->data[0];
	silc_buffer_pull(src, 1);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len3)
	  *len3 = len2;
	if (x && len2) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI16_NSTRING:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt16 *len3 = va_arg(ap, SilcUInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len3)
	  *len3 = len2;
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI16_NSTRING | SILC_PARAM_ALLOC:
      {
	SilcUInt16 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt16 *len3 = va_arg(ap, SilcUInt16 *);
	UNFORMAT_HAS_SPACE(src, 2);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len3)
	  *len3 = len2;
	if (x && len2) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI32_NSTRING:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 *len3 = va_arg(ap, SilcUInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len3)
	  *len3 = len2;
	if (x)
	  *x = src->data;
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_UI32_NSTRING | SILC_PARAM_ALLOC:
      {
	SilcUInt32 len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 *len3 = va_arg(ap, SilcUInt32 *);
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	if (len3)
	  *len3 = len2;
	if (silc_likely(x && len2)) {
	  *x = silc_scalloc(stack, len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_PARAM_BUFFER:
      {
	SilcBuffer x = va_arg(ap, SilcBuffer);
	SilcUInt32 len2;
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	silc_buffer_set(x, src->data, len2);
	silc_buffer_pull(src, len2);
      }
      break;
    case SILC_PARAM_BUFFER | SILC_PARAM_ALLOC:
      {
	SilcBuffer x = va_arg(ap, SilcBuffer);
	SilcUInt32 len2;
	UNFORMAT_HAS_SPACE(src, 4);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	UNFORMAT_HAS_SPACE(src, len2);
	silc_buffer_sformat(stack, x,
			    SILC_STR_DATA(src->data, len2),
			    SILC_STR_END);
	silc_buffer_pull(src, len2);
      }
      break;
    case SILC_PARAM_OFFSET:
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
    case SILC_PARAM_ADVANCE:
      advance = TRUE;
      break;
    case SILC_PARAM_END:
      goto ok;
      break;
    default:
      SILC_LOG_DEBUG(("Bad buffer formatting type `%d'. Could not "
		      "format the data.", fmt));
      silc_set_errno_reason(SILC_ERR_INVALID_ARGUMENT,
			    "Bad buffer formatting type %d", fmt);
      goto fail;
      break;
    }
  }

 fail:
  SILC_LOG_DEBUG(("Error occured while unformatting buffer, type %d", fmt));
  len = src->data - start_ptr;
  silc_buffer_push(src, len);
  return -1;

 ok:
  /* Push the buffer back to the start. */
  if (!advance) {
    len = src->data - start_ptr;
    silc_buffer_push(src, len);
  }
  return len;
}


/**************************** Utility functions *****************************/

/* Formats strings into a buffer */

int silc_buffer_strformat(SilcBuffer dst, ...)
{
  int len = silc_buffer_truelen(dst);
  int hlen = silc_buffer_headlen(dst);
  va_list va;

  va_start(va, dst);

  /* Parse the arguments by formatting type. */
  while(1) {
    char *string = va_arg(va, char *);
    unsigned char *d;
    SilcInt32 slen;

    if (!string)
      continue;
    if (string == (char *)SILC_PARAM_END)
      goto ok;

    slen = strlen(string);
    d = silc_realloc(dst->head, sizeof(*dst->head) * (slen + len + 1));
    if (silc_unlikely(!d))
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
  dst->data = dst->head + hlen;
  dst->tail = dst->end;

  va_end(va);
  return len;
}

/* Formats strings into a buffer.  Allocates memory from SilcStack. */

int silc_buffer_sstrformat(SilcStack stack, SilcBuffer dst, ...)
{
  int len = silc_buffer_truelen(dst);
  int hlen = silc_buffer_headlen(dst);
  va_list va;

  va_start(va, dst);

  /* Parse the arguments by formatting type. */
  while(1) {
    char *string = va_arg(va, char *);
    unsigned char *d;
    SilcInt32 slen;

    if (!string)
      continue;
    if (string == (char *)SILC_PARAM_END)
      goto ok;

    slen = strlen(string);
    d = silc_srealloc(stack, len + 1, dst->head,
		      sizeof(*dst->head) * (slen + len + 1));
    if (silc_unlikely(!d))
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
  dst->data = dst->head + hlen;
  dst->tail = dst->end;

  va_end(va);
  return len;
}
