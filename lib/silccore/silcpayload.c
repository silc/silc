/*

  silcpayload.c

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
/* Implementation of generic payloads described in the protocol 
   specification drafts. */
/* $Id$ */

#include "silcincludes.h"
#include "silcpayload.h"

/******************************************************************************

                                ID Payload

******************************************************************************/

struct SilcIDPayloadStruct {
  SilcIdType type;
  unsigned short len;
  unsigned char *id;
};

/* Parses data and return ID payload into payload structure */

SilcIDPayload silc_id_payload_parse(SilcBuffer buffer)
{
  SilcIDPayload new;

  SILC_LOG_DEBUG(("Parsing ID payload"));

  new = silc_calloc(1, sizeof(*new));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&new->type),
		       SILC_STR_UI_SHORT(&new->len),
		       SILC_STR_END);

  if (new->len > buffer->len)
    goto err;

  silc_buffer_pull(buffer, 4);
  silc_buffer_unformat(buffer,
		       SILC_STR_UI_XNSTRING_ALLOC(&new->id, new->len),
		       SILC_STR_END);
  silc_buffer_push(buffer, 4);

  return new;

 err:
  silc_free(new);
  return NULL;
}

/* Encodes ID Payload */

SilcBuffer silc_id_payload_encode(void *id, unsigned short len,
				  SilcIdType type)
{
  SilcBuffer buffer;
  unsigned char *id_data;

  SILC_LOG_DEBUG(("Parsing ID payload"));

  id_data = silc_id_id2str(id, type);

  buffer = silc_buffer_alloc(4 + len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(type),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_XNSTRING(id_data, len),
		     SILC_STR_END);
  silc_free(id_data);

  return buffer;
}

/* Free ID Payload */

void silc_id_payload_free(SilcIDPayload payload)
{
  if (payload) {
    silc_free(payload->id);
  }
}

/* Get ID type */

SilcIdType silc_id_payload_get_type(SilcIDPayload payload)
{
  return payload->type;
}

/* Get ID */

void *silc_id_payload_get_id(SilcIDPayload payload)
{
  return silc_id_str2id(payload->id, payload->type);
}

/******************************************************************************

                             Argument Payload

******************************************************************************/

struct SilcArgumentPayloadStruct {
  unsigned int argc;
  unsigned char **argv;
  unsigned int *argv_lens;
  unsigned int *argv_types;
  unsigned int pos;
};

/* Parses arguments and returns them into Argument Payload structure. */

SilcArgumentPayload silc_argument_payload_parse(SilcBuffer buffer,
						unsigned int argc)
{
  SilcArgumentPayload new;
  unsigned short payload_len = 0;
  unsigned char arg_num = 0;
  unsigned int arg_type = 0;
  unsigned int pull_len = 0;
  int i = 0;

  SILC_LOG_DEBUG(("Parsing argument payload"));

  new = silc_calloc(1, sizeof(*new));
  new->argv = silc_calloc(argc, sizeof(unsigned char *));
  new->argv_lens = silc_calloc(argc, sizeof(unsigned int));
  new->argv_types = silc_calloc(argc, sizeof(unsigned int));
    
  /* Get arguments */
  arg_num = 1;
  for (i = 0; i < argc; i++) {
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_SHORT(&payload_len),
			 SILC_STR_UI_CHAR(&arg_type),
			 SILC_STR_END);
    
    new->argv_lens[i] = payload_len;
    new->argv_types[i] = arg_type;

    if (payload_len > buffer->len)
      break;
    
    /* Get argument data */
    silc_buffer_pull(buffer, 3);
    silc_buffer_unformat(buffer,
			 SILC_STR_UI_XNSTRING_ALLOC(&new->argv[i], 
						    payload_len),
			 SILC_STR_END);

    silc_buffer_pull(buffer, payload_len);
    pull_len += 3 + payload_len;
  }

  if (buffer->len != 0)
    goto err;

  new->argc = argc;
  new->pos = 0;

  silc_buffer_push(buffer, pull_len);

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

SilcBuffer silc_argument_payload_encode(unsigned int argc,
					unsigned char **argv,
					unsigned int *argv_lens,
					unsigned int *argv_types)
{
  SilcBuffer buffer;
  unsigned int len;
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

#if 0
/* Encodes Argument payload with variable argument list. The arguments
   must be: unsigned int, unsigned char *, unsigned int, ... One 
   {unsigned int, unsigned char * and unsigned int} forms one argument, 
   thus `argc' in case when sending one {unsigned int, unsigned char * 
   and unsigned int} equals one (1) and when sending two of those it
   equals two (2), and so on. This has to be preserved or bad things
   will happen. The variable arguments is: {type, data, data_len}. */

SilcBuffer silc_command_encode_payload_va(unsigned int argc, ...)
{
  va_list ap;
  unsigned char **argv;
  unsigned int *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  unsigned int x_len;
  unsigned int x_type;
  SilcBuffer buffer;
  int i;

  va_start(ap, argc);

  argv = silc_calloc(argc, sizeof(unsigned char *));
  argv_lens = silc_calloc(argc, sizeof(unsigned int));
  argv_types = silc_calloc(argc, sizeof(unsigned int));

  for (i = 0; i < argc; i++) {
    x_type = va_arg(ap, unsigned int);
    x = va_arg(ap, unsigned char *);
    x_len = va_arg(ap, unsigned int);

    argv[i] = silc_calloc(x_len + 1, sizeof(unsigned char));
    memcpy(argv[i], x, x_len);
    argv_lens[i] = x_len;
    argv_types[i] = x_type;
  }

  buffer = silc_argument_payload_encode(argc, argv, 
					argv_lens, argv_types);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv);
  silc_free(argv_lens);
  silc_free(argv_types);

  return buffer;
}
#endif

/* Free's Command Payload */

void silc_argument_payload_free(SilcArgumentPayload payload)
{
  int i;

  if (payload) {
    for (i = 0; i < payload->argc; i++)
      silc_free(payload->argv[i]);

    silc_free(payload->argv);
    silc_free(payload);
  }
}

/* Returns number of arguments in payload */

unsigned int silc_argument_get_arg_num(SilcArgumentPayload payload)
{
  return payload->argc;
}

/* Returns first argument from payload. */

unsigned char *silc_argument_get_first_arg(SilcArgumentPayload payload,
					   unsigned int *ret_len)
{
  payload->pos = 0;

  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns next argument from payload or NULL if no more arguments. */

unsigned char *silc_argument_get_next_arg(SilcArgumentPayload payload,
					  unsigned int *ret_len)
{
  if (payload->pos >= payload->argc)
    return NULL;

  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns argument which type is `type'. */

unsigned char *silc_argument_get_arg_type(SilcArgumentPayload payload,
					  unsigned int type,
					  unsigned int *ret_len)
{
  int i;

  for (i = 0; i < payload->argc; i++)
    if (payload->argv_types[i] == type)
      break;

  if (i >= payload->argc)
    return NULL;

  if (ret_len)
    *ret_len = payload->argv_lens[i];

  return payload->argv[i];
}
