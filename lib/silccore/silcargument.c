/*

  silcargument.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

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
  uint32 argc;
  unsigned char **argv;
  uint32 *argv_lens;
  uint32 *argv_types;
  uint32 pos;
};

/* Parses arguments and returns them into Argument Payload structure. */

SilcArgumentPayload silc_argument_payload_parse(const unsigned char *payload,
						uint32 payload_len,
						uint32 argc)
{
  SilcBufferStruct buffer;
  SilcArgumentPayload new;
  uint16 p_len = 0;
  unsigned char arg_num = 0;
  unsigned char arg_type = 0;
  uint32 pull_len = 0;
  int i = 0, ret;

  SILC_LOG_DEBUG(("Parsing argument payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  new = silc_calloc(1, sizeof(*new));
  new->argv = silc_calloc(argc, sizeof(unsigned char *));
  new->argv_lens = silc_calloc(argc, sizeof(uint32));
  new->argv_types = silc_calloc(argc, sizeof(uint32));
    
  /* Get arguments */
  arg_num = 1;
  for (i = 0; i < argc; i++) {
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_SHORT(&p_len),
			       SILC_STR_UI_CHAR(&arg_type),
			       SILC_STR_END);
    if (ret == -1)
      goto err;
    
    new->argv_lens[i] = p_len;
    new->argv_types[i] = arg_type;

    if (p_len > buffer.len - 3)
      break;
    
    /* Get argument data */
    silc_buffer_pull(&buffer, 3);
    ret = silc_buffer_unformat(&buffer,
			       SILC_STR_UI_XNSTRING_ALLOC(&new->argv[i], 
							  p_len),
			       SILC_STR_END);
    if (ret == -1)
      goto err;

    silc_buffer_pull(&buffer, p_len);
    pull_len += 3 + p_len;
  }

  if (buffer.len != 0)
    goto err;

  new->argc = argc;
  new->pos = 0;

  silc_buffer_push(&buffer, pull_len);

  return new;

 err:
  if (i) {
    int k;

    for (k = 0; k < i; k++)
      silc_free(new->argv[k]);
  }

  silc_free(new->argv);
  silc_free(new->argv_lens);
  silc_free(new->argv_types);

  if (new)
    silc_free(new);

  return NULL;
}

/* Encodes arguments in to Argument Paylods returning them to SilcBuffer. */

SilcBuffer silc_argument_payload_encode(uint32 argc,
					unsigned char **argv,
					uint32 *argv_lens,
					uint32 *argv_types)
{
  SilcBuffer buffer;
  uint32 len;
  int i;

  SILC_LOG_DEBUG(("Encoding Argument payload"));

  len = 0;
  for (i = 0; i < argc; i++)
    len += 3 + argv_lens[i];

  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Put arguments */
  for (i = 0; i < argc; i++) {
    silc_buffer_format(buffer,
		       SILC_STR_UI_SHORT(argv_lens[i]),
		       SILC_STR_UI_CHAR(argv_types[i]),
		       SILC_STR_UI_XNSTRING(argv[i], argv_lens[i]),
		       SILC_STR_END);
    silc_buffer_pull(buffer, 3 + argv_lens[i]);
  }

  silc_buffer_push(buffer, len);

  return buffer;
}

/* Same as above but encode the buffer from SilcArgumentPayload structure
   instead of raw data. */

SilcBuffer silc_argument_payload_encode_payload(SilcArgumentPayload payload)
{
  SilcBuffer buffer;
  uint32 len;
  int i;

  SILC_LOG_DEBUG(("Encoding Argument payload"));

  len = 0;
  for (i = 0; i < payload->argc; i++)
    len += 3 + payload->argv_lens[i];

  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

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

uint32 silc_argument_get_arg_num(SilcArgumentPayload payload)
{
  return payload ? payload->argc : 0;
}

/* Returns first argument from payload. */

unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
					   uint32 *ret_len)
{
  if (!payload)
    return NULL;

  payload->pos = 0;

  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns next argument from payload or NULL if no more arguments. */

unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
					  uint32 *ret_len)
{
  if (!payload)
    return NULL;

  if (payload->pos >= payload->argc)
    return NULL;

  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns argument which type is `type'. */

unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
					  uint32 type,
					  uint32 *ret_len)
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
