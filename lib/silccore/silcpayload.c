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

/* Parses buffer and return ID payload into payload structure */

SilcIDPayload silc_id_payload_parse(SilcBuffer buffer)
{
  SilcIDPayload new;
  int ret;

  SILC_LOG_DEBUG(("Parsing ID payload"));

  new = silc_calloc(1, sizeof(*new));

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&new->type),
			     SILC_STR_UI_SHORT(&new->len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  silc_buffer_pull(buffer, 4);

  if (new->len > buffer->len)
    goto err;

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&new->id, new->len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  silc_buffer_push(buffer, 4);

  return new;

 err:
  silc_free(new);
  return NULL;
}

/* Parses data and return ID payload into payload structure. */

SilcIDPayload silc_id_payload_parse_data(unsigned char *data, 
					 unsigned int len)
{
  SilcIDPayload new;
  SilcBuffer buffer;
  int ret;

  SILC_LOG_DEBUG(("Parsing ID payload"));

  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_put(buffer, data, len);

  new = silc_calloc(1, sizeof(*new));

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&new->type),
			     SILC_STR_UI_SHORT(&new->len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  silc_buffer_pull(buffer, 4);

  if (new->len > buffer->len)
    goto err;

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&new->id, new->len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  silc_buffer_free(buffer);
  return new;

 err:
  silc_buffer_free(buffer);
  silc_free(new);
  return NULL;
}

/* Return the ID directly from the raw payload data. */

void *silc_id_payload_parse_id(unsigned char *data, unsigned int len)
{
  SilcBuffer buffer;
  SilcIdType type;
  unsigned short idlen;
  unsigned char *id;
  int ret;

  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));
  silc_buffer_put(buffer, data, len);

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_SHORT(&type),
			     SILC_STR_UI_SHORT(&idlen),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  silc_buffer_pull(buffer, 4);

  if (idlen > buffer->len)
    goto err;

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI_XNSTRING_ALLOC(&id, idlen),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  silc_buffer_free(buffer);

  return silc_id_str2id(id, idlen, type);

 err:
  silc_buffer_free(buffer);
  return NULL;
}

/* Encodes ID Payload */

SilcBuffer silc_id_payload_encode(void *id, SilcIdType type)
{
  SilcBuffer buffer;
  unsigned char *id_data;
  unsigned int len;

  SILC_LOG_DEBUG(("Encoding %s ID payload",
		  type == SILC_ID_CLIENT ? "Client" :
		  type == SILC_ID_SERVER ? "Server" : "Channel"));

  id_data = silc_id_id2str(id, type);
  len = silc_id_get_len(type);

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
  return silc_id_str2id(payload->id, payload->len, payload->type);
}

/* Get raw ID data. Data is duplicated. */

unsigned char *silc_id_payload_get_data(SilcIDPayload payload)
{
  unsigned char *ret = silc_calloc(payload->len, sizeof(*ret));
  memcpy(ret, payload->id, payload->len);
  return ret;
}

/* Get length of ID */

unsigned int silc_id_payload_get_len(SilcIDPayload payload)
{
  return payload->len;
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
  unsigned char arg_type = 0;
  unsigned int pull_len = 0;
  int i = 0, ret;

  SILC_LOG_DEBUG(("Parsing argument payload"));

  new = silc_calloc(1, sizeof(*new));
  new->argv = silc_calloc(argc, sizeof(unsigned char *));
  new->argv_lens = silc_calloc(argc, sizeof(unsigned int));
  new->argv_types = silc_calloc(argc, sizeof(unsigned int));
    
  /* Get arguments */
  arg_num = 1;
  for (i = 0; i < argc; i++) {
    ret = silc_buffer_unformat(buffer,
			       SILC_STR_UI_SHORT(&payload_len),
			       SILC_STR_UI_CHAR(&arg_type),
			       SILC_STR_END);
    if (ret == -1)
      goto err;
    
    new->argv_lens[i] = payload_len;
    new->argv_types[i] = arg_type;

    if (payload_len > buffer->len)
      break;
    
    /* Get argument data */
    silc_buffer_pull(buffer, 3);
    ret = silc_buffer_unformat(buffer,
			       SILC_STR_UI_XNSTRING_ALLOC(&new->argv[i], 
							  payload_len),
			       SILC_STR_END);
    if (ret == -1)
      goto err;

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

/* Same as above but encode the buffer from SilcArgumentPayload structure
   instead of raw data. */

SilcBuffer silc_argument_payload_encode_payload(SilcArgumentPayload payload)
{
  SilcBuffer buffer;
  unsigned int len;
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
  return payload ? payload->argc : 0;
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
