/*

  silcmode.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcmode.h"

/******************************************************************************

                               Set Mode Payload

******************************************************************************/

struct SilcSetModePayloadStruct {
  unsigned short mode_type;
  unsigned int mode_mask;
  unsigned char argc;
  SilcArgumentPayload args;
};

/* Parse Set Mode payload buffer and return data into payload structure */

SilcSetModePayload silc_set_mode_payload_parse(SilcBuffer buffer)
{
  SilcSetModePayload new;
  unsigned short len;

  SILC_LOG_DEBUG(("Parsing Set Mode payload"));

  new = silc_calloc(1, sizeof(*new));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&new->mode_type),
		       SILC_STR_UI_SHORT(&len),
		       SILC_STR_UI_INT(&new->mode_mask),
		       SILC_STR_UI_CHAR(&new->argc),
		       SILC_STR_END);

  if (len > buffer->len)
    goto err;

  if (new->argc) {
    silc_buffer_pull(buffer, 5);
    new->args = silc_argument_payload_parse(buffer, new->argc);
    silc_buffer_push(buffer, 5);
  }

  return new;

 err:
  silc_free(new);
  return NULL;
}

/* Encode Set Mode payload with variable argument list. If `argc' is > 0
   argument payloads will be associated to the Set Mode payload. Variable
   arguments must be {usigned char *, unsigned int (len)}. */

SilcBuffer silc_set_mode_payload_encode(unsigned short mode_type, 
					unsigned int mode_mask,
					unsigned int argc, 
					va_list ap)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  unsigned char **argv;
  unsigned int *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  unsigned int x_len;
  int i, len = 0;

  if (argc) {
    argv = silc_calloc(argc, sizeof(unsigned char *));
    argv_lens = silc_calloc(argc, sizeof(unsigned int));
    argv_types = silc_calloc(argc, sizeof(unsigned int));
    
    for (i = 0; i < argc; i++) {
      x = va_arg(ap, unsigned char *);
      x_len = va_arg(ap, unsigned int);
      
      argv[i] = silc_calloc(x_len + 1, sizeof(unsigned char));
      memcpy(argv[i], x, x_len);
      argv_lens[i] = x_len;
      argv_types[i] = i + 1;
    }

    args = silc_argument_payload_encode(argc, argv, argv_lens, argv_types);
    len = args->len;

    for (i = 0; i < argc; i++)
      silc_free(argv[i]);
    silc_free(argv);
    silc_free(argv_lens);
    silc_free(argv_types);
  }

  len += 5;
  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(mode_type),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_INT(mode_mask),
		     SILC_STR_UI_CHAR(argc),
		     SILC_STR_END);

  if (argc) {
    silc_buffer_pull(buffer, 5);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, args->len),
		       SILC_STR_END);
    silc_buffer_push(buffer, 5);
    silc_buffer_free(args);
  }

  return buffer;
}

/* Free's Set Mode payload */

void silc_set_mode_payload_free(SilcSetModePayload payload)
{
  if (payload) {
    silc_argument_payload_free(payload->args);
    silc_free(payload);
  }
}

/* Return mode type */

unsigned short silc_set_mode_get_type(SilcSetModePayload payload)
{
  return payload->mode_type;
}

/* Return mode mask */

unsigned int silc_set_mode_get_mode(SilcSetModePayload payload)
{
  return payload->mode_mask;
}

/* Return argument nums */

unsigned int silc_set_mode_get_arg_num(SilcSetModePayload payload)
{
  return payload->argc;
}

/* Return argument payload */

SilcArgumentPayload silc_set_mode_get_args(SilcSetModePayload payload)
{
  return payload->args;
}
