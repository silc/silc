/*

  silccommand.c

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
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"
#include "silccommand.h"

/* Command Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcCommandPayloadStruct {
  SilcCommand cmd;
  unsigned int argc;
  unsigned char **argv;
  unsigned int *argv_lens;
  unsigned int *argv_types;
  unsigned int pos;
};

/* Length of the command payload */
#define SILC_COMMAND_PAYLOAD_LEN 4

/* Parses command payload returning new command payload structure */

SilcCommandPayload silc_command_parse_payload(SilcBuffer buffer)
{
  SilcCommandPayload new;
  unsigned short payload_len = 0;
  unsigned char args_num = 0;
  unsigned char arg_num = 0;
  unsigned int arg_type = 0;
  unsigned int pull_len = 0;
  int i = 0;

  SILC_LOG_DEBUG(("Parsing command payload"));

  new = silc_calloc(1, sizeof(*new));
  if (!new) {
    SILC_LOG_ERROR(("Could not allocate new command payload"));
    return NULL;
  }

  /* Parse the Command Payload */
  silc_buffer_unformat(buffer, 
		       SILC_STR_UI_CHAR(&new->cmd),
		       SILC_STR_UI_CHAR(&args_num),
		       SILC_STR_UI_SHORT(&payload_len),
		       SILC_STR_END);

  if (payload_len != buffer->len) {
    SILC_LOG_ERROR(("Incorrect command payload in packet, packet dropped"));
    return NULL;
  }

  if (new->cmd == 0)
    return NULL;

  if (args_num && payload_len) {

    new->argv = silc_calloc(args_num, sizeof(unsigned char *));
    new->argv_lens = silc_calloc(args_num, sizeof(unsigned int));
    new->argv_types = silc_calloc(args_num, sizeof(unsigned int));

    silc_buffer_pull(buffer, SILC_COMMAND_PAYLOAD_LEN);
    pull_len += SILC_COMMAND_PAYLOAD_LEN;

    /* Parse Command Argument Payloads */
    arg_num = 1;
    while(arg_num) {
      silc_buffer_unformat(buffer,
			   SILC_STR_UI_CHAR(&arg_num),
			   SILC_STR_UI_CHAR(&arg_type),
			   SILC_STR_UI_SHORT(&payload_len),
			   SILC_STR_END);

      /* Check that argument number is correct */
      if (arg_num != i + 1)
	goto err;

      new->argv_lens[i] = payload_len;
      new->argv_types[i] = arg_type;

      /* Get argument data */
      silc_buffer_pull(buffer, 4);
      silc_buffer_unformat(buffer,
			   SILC_STR_UI_XNSTRING_ALLOC(&new->argv[i], 
						      payload_len),
			   SILC_STR_END);
      silc_buffer_pull(buffer, payload_len);
      pull_len += 4 + payload_len;

      i++;

      if (i == args_num)
	break;
    }

    /* Check the number of arguments */
    if (arg_num != args_num)
      goto err;
  }

  new->argc = i;
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

/* Encodes Command Payload returning it to SilcBuffer. */

SilcBuffer silc_command_encode_payload(SilcCommand cmd,
				       unsigned int argc,
				       unsigned char **argv,
				       unsigned int *argv_lens,
				       unsigned int *argv_types)
{
  SilcBuffer buffer;
  unsigned int len;
  int i;

  SILC_LOG_DEBUG(("Encoding command payload"));

  len = 1 + 1 + 2;
  for (i = 0; i < argc; i++)
    len += 1 + 1 + 2 + argv_lens[i];

  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Create Command payload */
  silc_buffer_format(buffer,
		     SILC_STR_UI_CHAR(cmd),
		     SILC_STR_UI_CHAR(argc),
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_END);

  /* Put arguments */
  if (argc) {
    silc_buffer_pull(buffer, 4);
   
    for (i = 0; i < argc; i++) {
      silc_buffer_format(buffer,
			 SILC_STR_UI_CHAR(i + 1),
			 SILC_STR_UI_CHAR(argv_types[i]),
			 SILC_STR_UI_SHORT(argv_lens[i]),
			 SILC_STR_UI_XNSTRING(argv[i], argv_lens[i]),
			 SILC_STR_END);
      silc_buffer_pull(buffer, 4 + argv_lens[i]);
    }

    silc_buffer_push(buffer, len);
  }

  return buffer;
}

/* Encodes Command payload with variable argument list. The arguments
   must be: unsigned char *, unsigned int, ... One unsigned char *
   and unsigned int forms one argument, hence `argc' in case when
   sending one unsigned char * and unsigned int equals one (1) and
   when sending two of those it equals two (2), and so on. This has
   to be preserved or bad things will happen. */

SilcBuffer silc_command_encode_payload_va(SilcCommand cmd, 
					  unsigned int argc, ...)
{
  va_list ap;
  unsigned char **argv;
  unsigned int *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  unsigned int x_len;
  SilcBuffer buffer;
  int i;

  va_start(ap, argc);

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

  buffer = silc_command_encode_payload(cmd, argc, argv, 
				       argv_lens, argv_types);

  for (i = 0; i < argc; i++)
    silc_free(argv[i]);
  silc_free(argv);
  silc_free(argv_lens);
  silc_free(argv_types);

  return buffer;
}

/* Free's Command Payload */

void silc_command_free_payload(SilcCommandPayload payload)
{
  int i;

  if (payload) {
    for (i = 0; i < payload->argc; i++)
      silc_free(payload->argv[i]);

    silc_free(payload->argv);
    silc_free(payload);
  }
}

/* Returns the command type in payload */

SilcCommand silc_command_get(SilcCommandPayload payload)
{
  return payload->cmd;
}

/* Returns number of arguments in payload */

unsigned int silc_command_get_arg_num(SilcCommandPayload payload)
{
  return payload->argc;
}

/* Returns first argument from payload. */

unsigned char *silc_command_get_first_arg(SilcCommandPayload payload,
					  unsigned int *ret_len)
{
  payload->pos = 0;

  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns next argument from payload or NULL if no more arguments. */

unsigned char *silc_command_get_next_arg(SilcCommandPayload payload,
					 unsigned int *ret_len)
{
  if (payload->pos >= payload->argc)
    return NULL;

  if (ret_len)
    *ret_len = payload->argv_lens[payload->pos];

  return payload->argv[payload->pos++];
}

/* Returns argument which type is `type'. */

unsigned char *silc_command_get_arg_type(SilcCommandPayload payload,
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

/* Encodes command status payload. Status payload is sent as one reply
   argument. The returned payload still has to be saved into the 
   Command Argument payload. */

SilcBuffer silc_command_encode_status_payload(SilcCommandStatus status,
					      unsigned char *data,
					      unsigned int len)
{
  SilcBuffer sp;

  sp = silc_buffer_alloc(len + 2);
  silc_buffer_pull_tail(sp, SILC_BUFFER_END(sp));
  silc_buffer_format(sp,
		     SILC_STR_UI_SHORT(status),
		     SILC_STR_UI_XNSTRING(data, len),
		     SILC_STR_END);

  return sp;
}
