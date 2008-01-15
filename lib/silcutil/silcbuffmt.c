/*

  silcbuffmt.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2008 Pekka Riikonen

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

/* Check that buffer has enough room to format data in it, if not
   allocate more.  This will append, thus not replacing any existing data. */
#define FORMAT_HAS_SPACE_APPEND(s, b, req)				\
do {									\
  if (silc_buffer_len(b) < req)						\
    if (silc_unlikely(!silc_buffer_sappend(s, b, req - silc_buffer_len(b)))) \
      goto fail;							\
  flen += req;								\
} while(0)

/* Check that there is data to be unformatted */
#define UNFORMAT_HAS_SPACE(b, req)		        \
do {							\
  if (silc_unlikely(req > silc_buffer_len(b))) {	\
    silc_set_errno(SILC_ERR_OVERFLOW);			\
    goto fail;						\
  }							\
  if (silc_unlikely((req + 1) <= 0)) {			\
    silc_set_errno(SILC_ERR_OVERFLOW);			\
    goto fail;						\
  }							\
} while(0)

#if defined(SILC_DEBUG)
static const char *silc_param_string(SilcParam fmt)
{
  if (fmt == SILC_PARAM_SINT8)
    return "SINT8";
  if (fmt == SILC_PARAM_UINT8)
    return "UINT8";
  if (fmt == SILC_PARAM_SINT16)
    return "SINT16";
  if (fmt == SILC_PARAM_UINT16)
    return "UINT16";
  if (fmt == SILC_PARAM_SINT32)
    return "SINT32";
  if (fmt == SILC_PARAM_UINT32)
    return "UINT32";
  if (fmt == SILC_PARAM_SINT64)
    return "SINT64";
  if (fmt == SILC_PARAM_UINT64)
    return "UINT64";
  if (fmt == SILC_PARAM_SICHAR)
    return "SICHAR";
  if (fmt == (SILC_PARAM_SICHAR | SILC_PARAM_ALLOC))
    return "SICHAR ALLOC";
  if (fmt == SILC_PARAM_UICHAR)
    return "UICHAR";
  if (fmt == (SILC_PARAM_UICHAR | SILC_PARAM_ALLOC))
    return "UICHAR ALLOC";
  if (fmt == (SILC_PARAM_UICHAR | SILC_PARAM_REPLACE))
    return "UICHAR REPLACE";
  if (fmt == SILC_PARAM_BUFFER)
    return "BUFFER";
  if (fmt == (SILC_PARAM_BUFFER | SILC_PARAM_ALLOC))
    return "BUFFER ALLOC";
  if (fmt == SILC_PARAM_PTR)
    return "PTR";
  if (fmt == SILC_PARAM_END)
    return "END";
  if (fmt == SILC_PARAM_UI8_STRING)
    return "UI8_STRING";
  if (fmt == SILC_PARAM_UI16_STRING)
    return "UI16_STRING";
  if (fmt == SILC_PARAM_UI32_STRING)
    return "UI32_STRING";
  if (fmt == SILC_PARAM_UI8_NSTRING)
    return "UI8_STRING";
  if (fmt == SILC_PARAM_UI16_NSTRING)
    return "UI16_STRING";
  if (fmt == SILC_PARAM_UI32_NSTRING)
    return "UI32_STRING";
  if (fmt == (SILC_PARAM_UI8_STRING | SILC_PARAM_ALLOC))
    return "UI8_STRING ALLOC";
  if (fmt == (SILC_PARAM_UI16_STRING | SILC_PARAM_ALLOC))
    return "UI16_STRING ALLOC";
  if (fmt == (SILC_PARAM_UI32_STRING | SILC_PARAM_ALLOC))
    return "UI32_STRING ALLOC";
  if (fmt == (SILC_PARAM_UI8_NSTRING | SILC_PARAM_ALLOC))
    return "UI8_STRING ALLOC";
  if (fmt == (SILC_PARAM_UI16_NSTRING | SILC_PARAM_ALLOC))
    return "UI16_STRING ALLOC";
  if (fmt == (SILC_PARAM_UI32_NSTRING | SILC_PARAM_ALLOC))
    return "UI32_STRING";
  if (fmt == SILC_PARAM_OFFSET)
    return "OFFSET";
  if (fmt == SILC_PARAM_ADVANCE)
    return "ADDVANCE";
  if (fmt == SILC_PARAM_FUNC)
    return "FUNC";
  if (fmt == SILC_PARAM_REGEX)
    return "REGEX";
  if (fmt == SILC_PARAM_OFFSET_START)
    return "OFFSET_START";
  if (fmt == SILC_PARAM_OFFSET_END)
    return "OFFSET_END";
  if (fmt == SILC_PARAM_DELETE)
    return "DELETE";
  return "";
}
#endif /* SILC_DEBUG */

/******************************* Formatting *********************************/

int silc_buffer_sformat_vp_i(SilcStack stack, SilcBuffer dst, va_list ap,
			     SilcBool process)
{
  SilcParam fmt;
  int flen = 0;
  SilcBool advance = FALSE;

  /* Parse the arguments by formatting type. */
  while (1) {
    fmt = va_arg(ap, SilcParam);

#if defined(SILC_DEBUG)
    if (process)
      SILC_LOG_DEBUG(("Buffer format type %s (%d)",
		      silc_param_string(fmt), fmt));
#endif /* SILC_DEBUG */

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

	if (!process)
	  break;

	tmp_len = func(stack, dst, val, context);
	if (tmp_len < 0)
	  goto fail;
	if (tmp_len) {
	  silc_buffer_pull(dst, tmp_len);
	  flen += tmp_len;
	}
	break;
      }

    case SILC_PARAM_REGEX:
      {
	const char *regex = va_arg(ap, char *);
	SilcBufferRegexFlags rflags = va_arg(ap, SilcUInt32);
	SilcBufferStruct match;
	SilcBool match_all = (rflags & SILC_STR_REGEX_ALL) != 0;
	SilcBool match_nl = (rflags & SILC_STR_REGEX_NL) != 0;
	SilcBool ret;
	SilcUInt32 inclusive_pos = 0;
	int matched = 0, ret_len;
	va_list cp;

	if (!process)
	  break;

	if (!regex)
	  break;

	if (match_nl) {
	start_nl_match:
	  /* Match for '\n' in the buffer.  If not found, treat as line
	     without '\n' (buffer has only one line, or this is last line). */
	  if (silc_regex_buffer(dst, "\n", &match, NULL))
	    dst->tail = match.tail;
	}

      start_match:
	/* Match */
	ret = silc_regex_buffer(dst, regex, &match, NULL);
	ret ^= (rflags & SILC_STR_REGEX_NOT) != 0;
	if (!ret) {
	  if (!matched && rflags & SILC_STR_REGEX_MISMATCH) {
	    silc_set_errno(SILC_ERR_NOT_FOUND);
	    goto fail;
	  }
	  goto end_match;
	}
	matched++;

	if (rflags & SILC_STR_REGEX_NOT)
	  match = *dst;

	if (!(rflags & SILC_STR_REGEX_NO_ADVANCE)) {
	  /* Advance buffer after match */
	  flen += (match.data - dst->data);
	  if (!silc_buffer_pull(dst, (match.data - dst->data)))
	    goto fail;
	}

	if (rflags & SILC_STR_REGEX_INCLUSIVE) {
	  inclusive_pos = dst->tail - match.tail;
	  dst->tail = match.tail;
	}

	/* Recursively format */
	silc_va_copy(cp, ap);
	ret_len = silc_buffer_sformat_vp_i(stack, dst, cp, TRUE);
	va_end(cp);
	if (ret_len < 0)
	  goto fail;

	if (rflags & SILC_STR_REGEX_INCLUSIVE)
	  if (!silc_buffer_pull_tail(dst, inclusive_pos))
	    goto fail;

	/* Advance buffer after formatting */
	flen += ret_len;
	if (!silc_buffer_pull(dst, ret_len))
	  goto fail;

	if (match_all && (!match_nl || silc_buffer_len(dst) > 1))
	  goto start_match;

      end_match:
	if (match_nl) {
	  /* Go to next line, it is at the end of the data area.  Adjust
	     the tail area of the target buffer to show rest of the buffer. */
	  flen += (dst->tail - dst->data);
	  if (!silc_buffer_pull(dst, (dst->tail - dst->data)))
	    goto fail;
	  if (!silc_buffer_pull_tail(dst, silc_buffer_taillen(dst)))
	    goto fail;

	  if (silc_buffer_len(dst) > 0)
	    goto start_nl_match;
	}

	/* Skip to the next SILC_PARAM_END */
	silc_buffer_sformat_vp_i(NULL, NULL, ap, FALSE);
	break;
      }

    case SILC_PARAM_UI8_STRING:
    case SILC_PARAM_UI16_STRING:
    case SILC_PARAM_UI32_STRING:
    case SILC_PARAM_UI8_STRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UI16_STRING | SILC_PARAM_ALLOC:
    case SILC_PARAM_UI32_STRING | SILC_PARAM_ALLOC:
      {
	char *x = va_arg(ap, char *);
	SilcUInt32 tmp_len = x ? strlen(x) : 0;

	if (!process)
	  break;

	if (x && tmp_len) {
	  FORMAT_HAS_SPACE(stack, dst, tmp_len);
	  silc_buffer_put(dst, x, tmp_len);
	  silc_buffer_pull(dst, tmp_len);
	}
	break;
      }

    case SILC_PARAM_UICHAR | SILC_PARAM_REPLACE:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	SilcUInt32 x_len = va_arg(ap, SilcUInt32);

	if (!process)
	  break;

	if (!x)
	  break;

	if (silc_buffer_len(dst) == x_len) {
	  /* Replace */
	  if (x_len) {
	    silc_buffer_put(dst, x, x_len);
	    silc_buffer_pull(dst, x_len);
	    flen += x_len;
	  }
	} else if (silc_buffer_len(dst) < x_len) {
	  /* Append */
	  if (x_len) {
	    FORMAT_HAS_SPACE_APPEND(stack, dst, x_len);
	    silc_buffer_put(dst, x, x_len);
	    silc_buffer_pull(dst, x_len);
	  }
	} else {
	  /* Delete */
	  if (x_len) {
	    silc_buffer_put(dst, x, x_len);
	    silc_buffer_pull(dst, x_len);
	    flen += x_len;
	  }
	  goto delete_rest;
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

	if (!process)
	  break;

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

	if (!process)
	  break;

	FORMAT_HAS_SPACE(stack, dst, 1);
	silc_buffer_put(dst, &x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }

    case SILC_PARAM_UINT16:
      {
	unsigned char xf[2];
	SilcUInt16 x = (SilcUInt16)va_arg(ap, int);

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

	FORMAT_HAS_SPACE(stack, dst, sizeof(SilcUInt64));
	SILC_PUT64_MSB(x, xf);
	silc_buffer_put(dst, xf, sizeof(SilcUInt64));
	silc_buffer_pull(dst, sizeof(SilcUInt64));
	break;
      }

    case SILC_PARAM_SINT8:
      {
	char x = (char)va_arg(ap, int);

	if (!process)
	  break;

	FORMAT_HAS_SPACE(stack, dst, 1);
	silc_buffer_put(dst, (unsigned char *)&x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }

    case SILC_PARAM_SINT16:
      {
	unsigned char xf[2];
	SilcInt16 x = (SilcInt16)va_arg(ap, int);

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

    case SILC_PARAM_DELETE:
      {
	int n = va_arg(ap, int);

	if (!process)
	  break;

	if (n == -1) {
	  /* Move all data from tail to data area */
	  if (dst->data != dst->tail) {
	  delete_rest:
	    n = silc_buffer_len(dst);
	    memmove(dst->data, dst->tail, silc_buffer_taillen(dst));
	    silc_buffer_push_tail(dst, n);
	    if (!silc_buffer_srealloc(stack, dst,
				      silc_buffer_truelen(dst) - n))
	      goto fail;
	  }
	  break;
	}

	if (n > silc_buffer_len(dst))
	  goto fail;

	memmove(dst->data, dst->data + n, (silc_buffer_len(dst) - n) +
		silc_buffer_taillen(dst));
	silc_buffer_push_tail(dst, silc_buffer_len(dst) - n);
	if (!silc_buffer_srealloc(stack, dst, silc_buffer_truelen(dst) - n))
	  goto fail;

	break;
      }

    case SILC_PARAM_OFFSET:
      {
	int offst = va_arg(ap, int);

	if (!process)
	  break;

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

    case SILC_PARAM_OFFSET_START:
      if (!process)
	break;
      if (!silc_buffer_push(dst, flen))
	goto fail;
      flen = 0;
      break;

    case SILC_PARAM_OFFSET_END:
      if (!process)
	break;
      flen += silc_buffer_len(dst);
      silc_buffer_pull(dst, silc_buffer_len(dst));
      break;

    case SILC_PARAM_ADVANCE:
      if (!process)
	break;
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
  if (process && !advance)
    silc_buffer_push(dst, flen);
  return -1;

 ok:
  /* Push the buffer back to where it belongs. */
  if (process && !advance)
    silc_buffer_push(dst, flen);
  return flen;
}

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
  return silc_buffer_sformat_vp_i(stack, dst, ap, TRUE);
}

/****************************** Unformatting ********************************/

int silc_buffer_sunformat_vp_i(SilcStack stack, SilcBuffer src, va_list ap,
			       SilcBool process)
{
  SilcParam fmt;
  unsigned char *start_ptr = src->data;
  int len = 0;
  SilcBool advance = FALSE;

  /* Parse the arguments by formatting type. */
  while (1) {
    fmt = va_arg(ap, SilcParam);

    SILC_LOG_DEBUG(("Buffer unformat type %s (%d)",
		    silc_param_string(fmt), fmt));

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

	if (!process)
	  break;

	tmp_len = func(stack, src, val, context);
	if (tmp_len < 0)
	  goto fail;
	if (tmp_len) {
	  UNFORMAT_HAS_SPACE(src, tmp_len);
	  silc_buffer_pull(src, tmp_len);
	}
      }
      break;

    case SILC_PARAM_REGEX:
      {
	const char *regex = va_arg(ap, char *);
	SilcBufferRegexFlags rflags = va_arg(ap, SilcUInt32);
	SilcBufferStruct match;
	SilcBool match_all = (rflags & SILC_STR_REGEX_ALL) != 0;
	SilcBool match_nl = (rflags & SILC_STR_REGEX_NL) != 0;
	SilcBool ret;
	SilcUInt32 inclusive_pos = 0;
	int matched = 0, ret_len;
	va_list cp;

	if (!process)
	  break;

	if (!regex)
	  break;

	if (match_nl) {
	start_nl_match:
	  /* Match for '\n' in the buffer.  If not found, treat as line
	     without '\n' (buffer has only one line, or this is last line). */
	  if (silc_regex_buffer(src, "\n", &match, NULL))
	    src->tail = match.tail;
	}

      start_match:
	/* Match */
	ret = silc_regex_buffer(src, regex, &match, NULL);
	ret ^= (rflags & SILC_STR_REGEX_NOT) != 0;
	if (!ret) {
	  if (!matched && rflags & SILC_STR_REGEX_MISMATCH) {
	    silc_set_errno(SILC_ERR_NOT_FOUND);
	    goto fail;
	  }
	  goto end_match;
	}
	matched++;

	if (rflags & SILC_STR_REGEX_NOT)
	  match = *src;

	if (!(rflags & SILC_STR_REGEX_NO_ADVANCE)) {
	  /* Advance buffer after match */
	  if (!silc_buffer_pull(src, (match.data - src->data)))
	    goto fail;
	}

	if (rflags & SILC_STR_REGEX_INCLUSIVE) {
	  inclusive_pos = src->tail - match.tail;
	  src->tail = match.tail;
	}

	/* Recursively format */
	silc_va_copy(cp, ap);
	ret_len = silc_buffer_sunformat_vp_i(stack, src, cp, TRUE);
	va_end(cp);
	if (ret_len < 0)
	  goto fail;

	if (rflags & SILC_STR_REGEX_INCLUSIVE)
	  if (!silc_buffer_pull_tail(src, inclusive_pos))
	    goto fail;

	/* Advance buffer after formatting */
	if (!silc_buffer_pull(src, ret_len))
	  goto fail;

	if (match_all && (!match_nl || silc_buffer_len(src) > 1))
	  goto start_match;

      end_match:
	if (match_nl) {
	  /* Go to next line, it is at the end of the data area.  Adjust
	     the tail area of the target buffer to show rest of the buffer. */
	  if (!silc_buffer_pull(src, (src->tail - src->data)))
	    goto fail;
	  if (!silc_buffer_pull_tail(src, silc_buffer_taillen(src)))
	    goto fail;

	  if (silc_buffer_len(src) > 0)
	    goto start_nl_match;
	}

	/* Skip to the next SILC_PARAM_END */
	silc_buffer_sunformat_vp_i(NULL, src, ap, FALSE);
	break;
      }
      break;

    case SILC_PARAM_UICHAR:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	SilcUInt32 len2 = va_arg(ap, SilcUInt32);

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, 1);
	if (silc_likely(x))
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }

    case SILC_PARAM_UINT16:
      {
	SilcUInt16 *x = va_arg(ap, SilcUInt16 *);

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, 2);
	if (silc_likely(x))
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }

    case SILC_PARAM_UINT32:
      {
	SilcUInt32 *x = va_arg(ap, SilcUInt32 *);

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, 4);
	if (silc_likely(x))
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }

    case SILC_PARAM_UINT64:
      {
	SilcUInt64 *x = va_arg(ap, SilcUInt64 *);

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, sizeof(SilcUInt64));
	if (silc_likely(x))
	  SILC_GET64_MSB(*x, src->data);
	silc_buffer_pull(src, sizeof(SilcUInt64));
	break;
      }

    case SILC_PARAM_SINT8:
      {
	char *x = va_arg(ap, char *);

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, 1);
	if (silc_likely(x))
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }

    case SILC_PARAM_SINT16:
      {
	SilcInt16 *x = va_arg(ap, SilcInt16 *);

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, 2);
	if (silc_likely(x))
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }

    case SILC_PARAM_SINT32:
      {
	SilcInt32 *x = va_arg(ap, SilcInt32 *);

	if (!process)
	  break;

	UNFORMAT_HAS_SPACE(src, 4);
	if (silc_likely(x))
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }

    case SILC_PARAM_SINT64:
      {
	SilcInt64 *x = va_arg(ap, SilcInt64 *);

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

	if (!process)
	  break;

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

    case SILC_PARAM_OFFSET_START:
      if (!process)
	break;
      silc_buffer_push(src, (src->data - start_ptr));
      break;

    case SILC_PARAM_OFFSET_END:
      if (!process)
	break;
      silc_buffer_pull(src, silc_buffer_len(src));
      break;

    case SILC_PARAM_ADVANCE:
      if (!process)
	break;
      advance = TRUE;
      break;

    case SILC_PARAM_END:
      goto ok;
      break;

    case SILC_PARAM_DELETE:
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
  if (process && !advance) {
    len = src->data - start_ptr;
    silc_buffer_push(src, len);
  }
  return -1;

 ok:
  /* Push the buffer back to the start. */
  if (process && !advance) {
    len = src->data - start_ptr;
    silc_buffer_push(src, len);
  }
  return len;
}

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
  return silc_buffer_sunformat_vp_i(stack, src, ap, TRUE);
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
