/*

  silcargument.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* Implementation of Argument Payload routines */ 
/* $Id$ */

#include "silcincludes.h"
#include "silcargument.h"

/******************************************************************************

                             Argument Payload

******************************************************************************/

struct SilcArgumentPayloadStruct {
  SilcUInt32 argc;
  unsigned char **argv;
  SilcUInt32 *argv_lens;
  SilcUInt32 *argv_types;
  SilcUInt32 pos;
};

/* Parses arguments and returns them into Argument Payload structure. */

SilcArgumentPayload silc_argument_payload_parse(const unsigned char *payload,
						SilcUInt32 payload_len,
						SilcUInt32 argc)
{
  SilcBufferStruct buffer;
  SilcArgumentPayload newp;
  SilcUInt16 p_len = 0;
  unsigned char arg_num = 0;
  unsigned char arg_type = 0;
  SilcUInt32 pull_len = 0;
  int i = 0, ret;

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;
  newp->argv = silc_calloc(argc, sizeof(unsigned char *));
  if (!newp->argv)
    goto err;
  newp->argv_lens = silc_calloc(argc, sizeof(SilcUInt32));
  if (!newp->argv_lens)
    goto err;
  newp->argv_types = silc_calloc(argc, sizeof(SilcUInt32));
  if (!newp->argv_types)
    goto err;
    
  /* Get arguments */
  arg_num = 1;
  for (i = 0; i < argc; i++) {
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_SHORT(&p_len),
			       SILC_STR_UI_CHAR(&arg_type),
			       SILC_STR_END);
    if (ret == -1 || p_len > buffer.len - 3)
      goto err;

    newp->argv_lens[i] = p_len;
    newp->argv_types[i] = arg_type;

    /* Get argument data */
    silc_buffer_pull(&buffer, 3);
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_XNSTRING_ALLOC(&newp->argv[i], 
							  p_len),
			       SILC_STR_END);
    if (ret == -1)
      goto err;

    silc_buffer_pull(&buffer, p_len);
    pull_len += 3 + p_len;
  }

  if (buffer.len != 0) {
    SILC_LOG_DEBUG(("Malformed argument payload"));
    goto err;
  }

  newp->argc = argc;
  newp->pos = 0;

  silc_buffer_push(&buffer, pull_len);

  return newp;

 err:
  SILC_LOG_DEBUG(("Error parsing argument payload"));
  if (i)
    for (ret = 0; ret < i; ret++)
      silc_free(newp->argv[ret]);

  silc_free(newp->argv);
  silc_free(newp->argv_lens);
  silc_free(newp->argv_types);
  silc_free(newp);

  return NULL;
}

/* Encodes arguments in to Argument Paylods returning them to SilcBuffer. */

SilcBuffer silc_argument_payload_encode(SilcUInt32 argc,
					unsigned char **argv,
					SilcUInt32 *argv_lens,
					SilcUInt32 *argv_types)
{
  SilcBuffer buffer;
  SilcUInt32 len;
  int i;

  len = 0;
  for (i = 0; i < argc; i++)
    len += 3 + (SilcUInt16)argv_lens[i];

  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;

  /* Put arguments */
  for (i = 0; i < argc; i++) {
    silc_buffer_format(buffer,
		       SILC_STR_UI_SHORT(argv_lens[i]),
		       SILC_STR_UI_CHAR(argv_types[i]),
		       SILC_STR_UI_XNSTRING(argv[i], (SilcUInt16)argv_lens[i]),
		       SILC_STR_END);
    silc_buffer_pull(buffer, 3 + (SilcUInt16)argv_lens[i]);
  }

  silc_buffer_push(buffer, len);

  return buffer;
}

/* Encode one argument to buffer */

SilcBuffer silc_argument_payload_encode_one(SilcBuffer args,
					    unsigned char *arg,
					    SilcUInt32 arg_len,
					    SilcUInt32 arg_type)
{
  SilcBuffer buffer = args;
  SilcUInt32 len;

  len = 3 + (SilcUInt16)arg_len;
  buffer = silc_buffer_realloc(buffer,
			       (buffer ? buffer->truelen + len : len));
  if (!buffer)
    return NULL;
  silc_buffer_pull(buffer, buffer->len);
  silc_buffer_pull_tail(buffer, len);
  silc_buffer_format(buffer, 
		     SILC_STR_UI_SHORT(arg_len),
		     SILC_STR_UI_CHAR(arg_type),
		     SILC_STR_UI_XNSTRING(arg, (SilcUInt16)arg_len),
		     SILC_STR_END);
  silc_buffer_push(buffer, buffer->data - buffer->head);

  return buffer;
}

/* Same as above but encode the buffer from SilcArgumentPayload structure
   instead of raw data. */

SilcBuffer silc_argument_payload_encode_payload(SilcArgumentPayload payload)
{
  SilcBuffer buffer;
  SilcUInt32 len;
  int i;

  len = 0;
  for (i = 0; i < payload->argc; i++)
    len += 3 + payload->argv_lens[i];

  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;

  /* Put arguments */
  for (i = 0; i < payload->argc; i++) {
    silc_buffer_format(buffer,
		       SILC_STR_UI_SHORT(payload->argv_lens[i]),
		       SILC_STR_UI_CHAR(payload->argv_types[i]),
		       SILC_STR_UI_XNSTRING(payload->argv[i], 
					    payload->argv_lens[i]),
		       SILC_STR_END);
    silc_buffer_pull(buffer, 3 + payload->argv_lens[i]);
  }

  silc_buffer_push(buffer, len);

  return buffer;
}

/* Frees Argument Payload */

void silc_argument_payload_free(SilcArgumentPayload payload)
{
  int i;

  if (payload) {
    for (i = 0; i < payload->argc; i++)
      silc_free(payload->argv[i]);

    silc_free(payload->argv);
    silc_free(payload->argv_lens);
    silc_free(payload->argv_types);
    silc_free(payload);
  }
}

/* Returns number of arguments in payload */

SilcUInt32 silc_argument_get_arg_num(SilcArgumentPayload payload)
{
  return payload ? payload->argc : 0;
}

/* Returns first argument from payload. */

unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
					   SilcUInt32 *type,
					   SilcUInt32 *ret_len)
{
  if (!payload)
    return NULL;

  payload->pos = 0;

  if (type)
    *type = payload->argv_types[payload->pos];
  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns next argument from payload or NULL if no more arguments. */

unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
					  SilcUInt32 *type,
					  SilcUInt32 *ret_len)
{
  if (!payload)
    return NULL;

  if (payload->pos >= payload->argc)
    return NULL;

  if (type)
    *type = payload->argv_types[payload->pos];
  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns argument which type is `type'. */

unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
					  SilcUInt32 type,
					  SilcUInt32 *ret_len)
{
  int i;

  if (!payload)
    return NULL;

  for (i = 0; i < payload->argc; i++)
    if (payload->argv_types[i] == type)
      break;

  if (i >= payload->argc)
    return NULL;

  if (ret_len)
    *ret_len = payload->argv_lens[i];

  return payload->argv[i];
}
