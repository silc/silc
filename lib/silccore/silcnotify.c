/*

  silcnotify.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

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
#include "silcnotify.h"

/******************************************************************************

                               Notify Payload

******************************************************************************/

struct SilcNotifyPayloadStruct {
  SilcNotifyType type;
  unsigned char argc;
  SilcArgumentPayload args;
};

/* Parse notify payload buffer and return data into payload structure */

SilcNotifyPayload silc_notify_payload_parse(SilcBuffer buffer)
{
  SilcNotifyPayload new;
  uint16 len;
  int ret;

  SILC_LOG_DEBUG(("Parsing Notify payload"));

  new = silc_calloc(1, sizeof(*new));

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&new->type),
			     SILC_STR_UI_SHORT(&len),
			     SILC_STR_UI_CHAR(&new->argc),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

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

/* Encode notify payload with variable argument list. If `argc' is > 0
   argument payloads will be associated to the notify payload. Variable
   arguments must be {usigned char *, uint32 (len)}. */

SilcBuffer silc_notify_payload_encode(SilcNotifyType type, uint32 argc, 
				      va_list ap)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  unsigned char **argv;
  uint32 *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  uint32 x_len;
  int i, k = 0, len = 0;

  if (argc) {
    argv = silc_calloc(argc, sizeof(unsigned char *));
    argv_lens = silc_calloc(argc, sizeof(uint32));
    argv_types = silc_calloc(argc, sizeof(uint32));
    
    for (i = 0, k = 0; i < argc; i++) {
      x = va_arg(ap, unsigned char *);
      x_len = va_arg(ap, uint32);

      if (!x || !x_len)
	continue;
      
      argv[k] = silc_calloc(x_len + 1, sizeof(unsigned char));
      memcpy(argv[k], x, x_len);
      argv_lens[k] = x_len;
      argv_types[k] = i + 1;
      k++;
    }

    args = silc_argument_payload_encode(k, argv, argv_lens, argv_types);
    len = args->len;

    for (i = 0; i < k; i++)
      silc_free(argv[i]);
    silc_free(argv);
    silc_free(argv_lens);
    silc_free(argv_types);
  }

  len += 5;
  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(type),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_CHAR(k),
		     SILC_STR_END);

  if (k) {
    silc_buffer_pull(buffer, 5);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, args->len),
		       SILC_STR_END);
    silc_buffer_push(buffer, 5);
    silc_buffer_free(args);
  }

  return buffer;
}

/* Same as above but takes argument from the `args' Argument Payload. */

SilcBuffer silc_notify_payload_encode_args(SilcNotifyType type, 
					   uint32 argc,
					   SilcBuffer args)
{
  SilcBuffer buffer;
  int len;

  len = 5 + (args ? args->len : 0);
  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(type),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_CHAR(argc),
		     SILC_STR_END);

  if (args) {
    silc_buffer_pull(buffer, 5);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, args->len),
		       SILC_STR_END);
    silc_buffer_push(buffer, 5);
  }

  return buffer;
}

/* Free's notify payload */

void silc_notify_payload_free(SilcNotifyPayload payload)
{
  if (payload) {
    silc_argument_payload_free(payload->args);
    silc_free(payload);
  }
}

/* Return notify type */

SilcNotifyType silc_notify_get_type(SilcNotifyPayload payload)
{
  return payload->type;
}

/* Return argument nums */

uint32 silc_notify_get_arg_num(SilcNotifyPayload payload)
{
  return payload->argc;
}

/* Return argument payload */

SilcArgumentPayload silc_notify_get_args(SilcNotifyPayload payload)
{
  return payload->args;
}
