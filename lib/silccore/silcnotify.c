/*

  silcnotify.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2005 Pekka Riikonen

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

SilcNotifyPayload silc_notify_payload_parse(const unsigned char *payload,
					    SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcNotifyPayload newp;
  SilcUInt16 len;
  int ret;

  SILC_LOG_DEBUG(("Parsing Notify payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  ret = silc_buffer_unformat(&buffer,
			     SILC_STR_UI_SHORT(&newp->type),
			     SILC_STR_UI_SHORT(&len),
			     SILC_STR_UI_CHAR(&newp->argc),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  if (len > silc_buffer_len(&buffer))
    goto err;

  if (newp->argc) {
    silc_buffer_pull(&buffer, 5);
    newp->args = silc_argument_payload_parse(buffer.data, silc_buffer_len(&buffer),
					     newp->argc);
    silc_buffer_push(&buffer, 5);
  }

  return newp;

 err:
  silc_free(newp);
  return NULL;
}

/* Encode notify payload with variable argument list. If `argc' is > 0
   argument payloads will be associated to the notify payload. Variable
   arguments must be {usigned char *, SilcUInt32 (len)}. */

SilcBuffer silc_notify_payload_encode(SilcNotifyType type, SilcUInt32 argc,
				      va_list ap)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  unsigned char **argv;
  SilcUInt32 *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  SilcUInt32 x_len, len = 0;
  int i, k = 0;

  if (argc) {
    argv = silc_calloc(argc, sizeof(unsigned char *));
    if (!argv)
      return NULL;
    argv_lens = silc_calloc(argc, sizeof(SilcUInt32));
    if (!argv_lens) {
      silc_free(argv);
      return NULL;
    }
    argv_types = silc_calloc(argc, sizeof(SilcUInt32));
    if (!argv_types) {
      silc_free(argv_lens);
      silc_free(argv);
      return NULL;
    }

    for (i = 0, k = 0; i < argc; i++) {
      x = va_arg(ap, unsigned char *);
      x_len = va_arg(ap, SilcUInt32);

      if (!x || !x_len)
	continue;

      argv[k] = silc_memdup(x, x_len);
      if (!argv[k])
	return NULL;
      argv_lens[k] = x_len;
      argv_types[k] = i + 1;
      k++;
    }

    args = silc_argument_payload_encode(k, argv, argv_lens, argv_types);
    len = silc_buffer_len(args);

    for (i = 0; i < k; i++)
      silc_free(argv[i]);
    silc_free(argv);
    silc_free(argv_lens);
    silc_free(argv_types);
  }

  len += 5;
  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(type),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_CHAR(k),
		     SILC_STR_END);

  if (k) {
    silc_buffer_pull(buffer, 5);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, silc_buffer_len(args)),
		       SILC_STR_END);
    silc_buffer_push(buffer, 5);
    silc_buffer_free(args);
  }

  return buffer;
}

/* Same as above but takes argument from the `args' Argument Payload. */

SilcBuffer silc_notify_payload_encode_args(SilcNotifyType type,
					   SilcUInt32 argc,
					   SilcBuffer args)
{
  SilcBuffer buffer;
  SilcUInt32 len;

  len = 5 + (args ? silc_buffer_len(args) : 0);
  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(type),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_CHAR(argc),
		     SILC_STR_END);

  if (args) {
    silc_buffer_pull(buffer, 5);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, silc_buffer_len(args)),
		       SILC_STR_END);
    silc_buffer_push(buffer, 5);
  }

  return buffer;
}

/* Frees notify payload */

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

SilcUInt32 silc_notify_get_arg_num(SilcNotifyPayload payload)
{
  return payload->argc;
}

/* Return argument payload */

SilcArgumentPayload silc_notify_get_args(SilcNotifyPayload payload)
{
  return payload->args;
}
