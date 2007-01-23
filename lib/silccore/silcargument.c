/*

  silcargument.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2006 Pekka Riikonen

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

#include "silc.h"
#include "silcargument.h"

/*************************** Argument Payload *******************************/

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
    if (ret == -1 || p_len > silc_buffer_len(&buffer) - 3)
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

  if (silc_buffer_len(&buffer) != 0) {
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
			       (buffer ? silc_buffer_truelen(buffer) +
				len : len));
  if (!buffer)
    return NULL;
  silc_buffer_pull(buffer, silc_buffer_len(buffer));
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

/* Return argument already decoded */

static SilcBool silc_argument_decode(unsigned char *data,
				     SilcUInt32 data_len,
				     SilcArgumentDecodeType dec_type,
				     void *ret_arg,
				     void **ret_arg_alloc)
{
  switch (dec_type) {

  case SILC_ARGUMENT_ID:
    if (ret_arg)
      if (!silc_id_payload_parse_id(data, data_len, (SilcID *)ret_arg))
	return FALSE;

    if (ret_arg_alloc) {
      SilcID id;
      if (!silc_id_payload_parse_id(data, data_len, &id))
	return FALSE;
      *ret_arg_alloc = silc_memdup(&id, sizeof(id));
    }
    break;

  case SILC_ARGUMENT_PUBLIC_KEY:
    {
      SilcPublicKey public_key;

      if (!ret_arg_alloc)
	return FALSE;

      if (!silc_public_key_payload_decode(data, data_len, &public_key))
	return FALSE;

      *ret_arg_alloc = public_key;
    }
    break;

  case SILC_ARGUMENT_ATTRIBUTES:
    if (!ret_arg_alloc)
      return FALSE;

    *ret_arg_alloc = silc_attribute_payload_parse(data, data_len);
    break;

  case SILC_ARGUMENT_UINT32:
    if (data_len != 4)
      return FALSE;

    if (ret_arg) {
      SilcUInt32 *i = ret_arg;
      SILC_GET32_MSB(*i, data);
    }

    if (ret_arg_alloc) {
      SilcUInt32 i;
      SILC_GET32_MSB(i, data);
      *ret_arg_alloc = silc_memdup(&i, sizeof(i));
    }
    break;

  case SILC_ARGUMENT_BOOL:
    if (data_len != sizeof(SilcBool))
      return FALSE;

    if (ret_arg) {
      SilcBool *b = ret_arg;
      *b = (data[0] == 0x01 ? TRUE : FALSE);
    }

    if (ret_arg_alloc) {
      SilcBool b;
      b = (data[0] == 0x01 ? TRUE : FALSE);
      *ret_arg_alloc = silc_memdup(&b, sizeof(b));
    }
    break;

  default:
    return FALSE;
  }

  return TRUE;
}

/* Return argument already decoded */

SilcBool silc_argument_get_decoded(SilcArgumentPayload payload,
				   SilcUInt32 type,
				   SilcArgumentDecodeType dec_type,
				   void *ret_arg,
				   void **ret_arg_alloc)
{
  unsigned char *tmp;
  SilcUInt32 tmp_len;

  tmp = silc_argument_get_arg_type(payload, type, &tmp_len);
  if (!tmp)
    return FALSE;

  return silc_argument_decode(tmp, tmp_len, dec_type, ret_arg, ret_arg_alloc);
}

/************************* Argument List Payload ****************************/

/* Parses argument payload list */

SilcArgumentPayload
silc_argument_list_parse(const unsigned char *payload,
			 SilcUInt32 payload_len)
{
  SilcArgumentPayload arg;
  SilcUInt16 argc;

  if (payload_len < 5)
    return NULL;

  SILC_GET16_MSB(argc, payload);

  arg = silc_argument_payload_parse(payload + 2, payload_len - 2, argc);

  return arg;
}

/* Parses argument payload list of specific argument types */

SilcDList
silc_argument_list_parse_decoded(const unsigned char *payload,
				 SilcUInt32 payload_len,
				 SilcArgumentDecodeType dec_type)
{
  SilcArgumentPayload arg;
  SilcArgumentDecodedList dec;
  unsigned char *data;
  SilcUInt32 data_len, type;
  SilcDList list;

  arg = silc_argument_list_parse(payload, payload_len);
  if (!arg)
    return NULL;

  list = silc_dlist_init();
  if (!list) {
    silc_argument_payload_free(arg);
    return NULL;
  }

  data = silc_argument_get_first_arg(arg, &type, &data_len);
  while (data) {
    dec = silc_calloc(1, sizeof(*dec));
    if (!dec)
      continue;
    dec->arg_type = type;
    if (silc_argument_decode(data, data_len, dec_type, NULL, &dec->argument))
      silc_dlist_add(list, dec);
    else
      silc_free(dec);
    data = silc_argument_get_next_arg(arg, &type, &data_len);
  }

  silc_argument_payload_free(arg);

  silc_dlist_start(list);

  return list;
}

/* Free decoded argument payload list */

void silc_argument_list_free(SilcDList list, SilcArgumentDecodeType dec_type)
{
  SilcArgumentDecodedList dec;

  if (!list)
    return;

  silc_dlist_start(list);
  while ((dec = silc_dlist_get(list))) {
    switch (dec_type) {

    case SILC_ARGUMENT_ID:
    case SILC_ARGUMENT_UINT32:
    case SILC_ARGUMENT_BOOL:
      silc_free(dec->argument);
      break;

    case SILC_ARGUMENT_PUBLIC_KEY:
      silc_pkcs_public_key_free(dec->argument);
      break;

    case SILC_ARGUMENT_ATTRIBUTES:
      silc_attribute_payload_free(dec->argument);
      break;

    default:
      break;
    }

    silc_free(dec);
  }

  silc_dlist_uninit(list);
}
