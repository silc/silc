/*

  silcbuffmt.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* XXX: These routines needs to be made more stable as these can crash
   if the data (for unformatting for example) is malformed or the buffer
   is too short. Must be fixed. There are some other obvious bugs as
   well. */
/*
 * $Id$
 * $Log$
 * Revision 1.1  2000/09/13 17:45:16  priikone
 * 	Splitted SILC core library. Core library includes now only
 * 	SILC protocol specific stuff. New utility library includes the
 * 	old stuff from core library that is more generic purpose stuff.
 *
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

/* Formats the arguments sent and puts them into the buffer sent as
   argument. The buffer must be initialized beforehand and it must have
   enough free space to include the formatted data. If this function
   fails caller should not trust the buffer anymore and should free it. 
   This function is used, for example, to create packets to send over
   network. */

int silc_buffer_format(SilcBuffer dst, ...)
{
  va_list ap;
  SilcBufferParamType fmt;
  unsigned char *start_ptr = dst->data;

  va_start(ap, dst);

  /* Parse the arguments by formatting type. */
  while(1) {
    fmt = va_arg(ap, SilcBufferParamType);

    switch(fmt) {
    case SILC_BUFFER_PARAM_SI8_CHAR:
      {
	char x = va_arg(ap, char);
	silc_buffer_put(dst, &x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_CHAR:
      {
	unsigned char x = va_arg(ap, unsigned char);
	silc_buffer_put(dst, &x, 1);
	silc_buffer_pull(dst, 1);
	break;
      }
    case SILC_BUFFER_PARAM_SI16_SHORT:
      {
	unsigned char xf[2];
	short x = va_arg(ap, short);
	SILC_PUT16_MSB(x, xf);
	silc_buffer_put(dst, xf, 2);
	silc_buffer_pull(dst, 2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_SHORT:
      {
	unsigned char xf[2];
	unsigned short x = va_arg(ap, unsigned short);
	SILC_PUT16_MSB(x, xf);
	silc_buffer_put(dst, xf, 2);
	silc_buffer_pull(dst, 2);
	break;
      }
    case SILC_BUFFER_PARAM_SI32_INT:
      {
	unsigned char xf[4];
	int x = va_arg(ap, int);
	SILC_PUT32_MSB(x, xf);
	silc_buffer_put(dst, xf, 4);
	silc_buffer_pull(dst, 4);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_INT:
      {
	unsigned char xf[4];
	unsigned int x = va_arg(ap, unsigned int);
	SILC_PUT32_MSB(x, xf);
	silc_buffer_put(dst, xf, 4);
	silc_buffer_pull(dst, 4);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_STRING:
    case SILC_BUFFER_PARAM_UI32_STRING:
    case SILC_BUFFER_PARAM_UI16_STRING_ALLOC:
    case SILC_BUFFER_PARAM_UI32_STRING_ALLOC:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	silc_buffer_put(dst, x, strlen(x));
	silc_buffer_pull(dst, strlen(x));
	break;
      }
    case SILC_BUFFER_PARAM_UI16_NSTRING:
    case SILC_BUFFER_PARAM_UI32_NSTRING:
    case SILC_BUFFER_PARAM_UI_XNSTRING:
    case SILC_BUFFER_PARAM_UI16_NSTRING_ALLOC:
    case SILC_BUFFER_PARAM_UI32_NSTRING_ALLOC:
    case SILC_BUFFER_PARAM_UI_XNSTRING_ALLOC:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	unsigned int len = va_arg(ap, unsigned int);
	silc_buffer_put(dst, x, len);
	silc_buffer_pull(dst, len);
	break;
      }
    case SILC_BUFFER_PARAM_END:
      goto ok;
      break;
    default:
      SILC_LOG_ERROR(("Bad buffer formatting type `%d'. Could not "
		      "format the data.", fmt));
      goto fail;
      break;
    }
  }

 fail:
  SILC_LOG_ERROR(("Error occured while formatting data"));
  return FALSE;

 ok:
  /* Push the buffer back to where it belongs. */
  silc_buffer_push(dst, dst->data - start_ptr);
  return dst->len;
}

/* Unformats the buffer sent as argument. The unformatted data is returned
   to the variable argument list of pointers. The buffer must point to the
   start of the data area to be unformatted. Buffer maybe be safely free'd
   after this returns succesfully. */

int silc_buffer_unformat(SilcBuffer src, ...)
{
  va_list ap;
  SilcBufferParamType fmt;
  unsigned char *start_ptr = src->data;
  int len = 0;

  va_start(ap, src);

  /* Parse the arguments by formatting type. */
  while(1) {
    fmt = va_arg(ap, SilcBufferParamType);

    switch(fmt) {
    case SILC_BUFFER_PARAM_SI8_CHAR:
      {
	char *x = va_arg(ap, char *);
	if (x)
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }
    case SILC_BUFFER_PARAM_UI8_CHAR:
      {
	unsigned char *x = va_arg(ap, unsigned char *);
	if (x)
	  *x = src->data[0];
	silc_buffer_pull(src, 1);
	break;
      }
    case SILC_BUFFER_PARAM_SI16_SHORT:
      {
	short *x = va_arg(ap, short *);
	if (x)
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_SHORT:
      {
	unsigned short *x = va_arg(ap, unsigned short *);
	if (x)
	  SILC_GET16_MSB(*x, src->data);
	silc_buffer_pull(src, 2);
	break;
      }
    case SILC_BUFFER_PARAM_SI32_INT:
      {
	int *x = va_arg(ap, int *);
	if (x)
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_INT:
      {
	unsigned int *x = va_arg(ap, unsigned int *);
	if (x)
	  SILC_GET32_MSB(*x, src->data);
	silc_buffer_pull(src, 4);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_STRING:
      {
	unsigned short len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	if ((len2 > src->len))
	  goto fail;
	if (len2 < 1)
	  break;
	if (x)
	  memcpy(x, src->data, len2);
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_STRING_ALLOC:
      {
	unsigned short len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	if ((len2 > src->len))
	  goto fail;
	if (len2 < 1)
	  break;
	if (x) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_STRING:
      {
	unsigned int len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	if ((len2 > src->len))
	  goto fail;
	if (len2 < 1)
	  break;
	if (x)
	  memcpy(x, src->data, len2);
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_STRING_ALLOC:
      {
	unsigned int len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	if ((len2 > src->len))
	  goto fail;
	if (len2 < 1)
	  break;
	if (x) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_NSTRING:
      {
	unsigned short len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	unsigned short *len = va_arg(ap, unsigned short *);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	if ((len2 > src->len))
	  break;
	if (len2 < 1)
	  break;
	if (len)
	  *len = len2;
	if (x)
	  memcpy(x, src->data, len2);
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI16_NSTRING_ALLOC:
      {
	unsigned short len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	unsigned short *len = va_arg(ap, unsigned short *);
	SILC_GET16_MSB(len2, src->data);
	silc_buffer_pull(src, 2);
	if ((len2 > src->len))
	  break;
	if (len2 < 1)
	  break;
	if (len)
	  *len = len2;
	if (x) {
	  *x = silc_calloc(len2 + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len2);
	}
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI32_NSTRING:
      {
	unsigned int len2;
	unsigned char **x = va_arg(ap, unsigned char **);
	unsigned int *len = va_arg(ap, unsigned int *);
	SILC_GET32_MSB(len2, src->data);
	silc_buffer_pull(src, 4);
	if ((len2 > src->len))
	  goto fail;
	if (len2 < 1)
	  break;
	if (len)
	  *len = len2;
	if (x)
	  memcpy(x, src->data, len2);
	silc_buffer_pull(src, len2);
	break;
      }
    case SILC_BUFFER_PARAM_UI_XNSTRING_ALLOC:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	unsigned int len = va_arg(ap, unsigned int);
	if (len && x) {
	  *x = silc_calloc(len + 1, sizeof(unsigned char));
	  memcpy(*x, src->data, len);
	}
	silc_buffer_pull(src, len);
	break;
      }
    case SILC_BUFFER_PARAM_UI_XNSTRING:
      {
	unsigned char **x = va_arg(ap, unsigned char **);
	unsigned int len = va_arg(ap, unsigned int);
	if (len && x)
	  memcpy(x, src->data, len);
	silc_buffer_pull(src, len);
	break;
      }
    case SILC_BUFFER_PARAM_END:
      goto ok;
      break;
    default:
      SILC_LOG_ERROR(("Bad buffer formatting type `%d'. Could not "
		      "format the data.", fmt));
      goto fail;
      break;
    }
  }

 fail:
  SILC_LOG_ERROR(("Error occured while unformatting buffer"));
  return FALSE;

 ok:
  /* Push the buffer back to the start. */
  len = src->data - start_ptr;
  silc_buffer_push(src, len);
  return len;
}
