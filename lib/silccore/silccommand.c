/*

  silccommand.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
#include "silccommand.h"

/******************************************************************************

                              Command Payload

******************************************************************************/

/* Command Payload structure. Contents of this structure is parsed
   from SILC packets. */
struct SilcCommandPayloadStruct {
  SilcCommand cmd;
  uint16 ident;
  SilcArgumentPayload args;
};

/* Length of the command payload */
#define SILC_COMMAND_PAYLOAD_LEN 6

/* Parses command payload returning new command payload structure */

SilcCommandPayload silc_command_payload_parse(SilcBuffer buffer)
{
  SilcCommandPayload new;
  unsigned char args_num;
  uint16 payload_len;
  int ret;

  SILC_LOG_DEBUG(("Parsing command payload"));

  new = silc_calloc(1, sizeof(*new));

  /* Parse the Command Payload */
  ret = silc_buffer_unformat(buffer, 
			     SILC_STR_UI_SHORT(&payload_len),
			     SILC_STR_UI_CHAR(&new->cmd),
			     SILC_STR_UI_CHAR(&args_num),
			     SILC_STR_UI_SHORT(&new->ident),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(new);
    return NULL;
  }

  if (payload_len != buffer->len) {
    SILC_LOG_ERROR(("Incorrect command payload in packet, packet dropped"));
    silc_free(new);
    return NULL;
  }

  if (new->cmd == 0) {
    silc_free(new);
    return NULL;
  }

  silc_buffer_pull(buffer, SILC_COMMAND_PAYLOAD_LEN);
  if (args_num) {
    new->args = silc_argument_payload_parse(buffer, args_num);
    if (!new->args) {
      silc_free(new);
      return NULL;
    }
  }
  silc_buffer_push(buffer, SILC_COMMAND_PAYLOAD_LEN);

  return new;
}

/* Encodes Command Payload returning it to SilcBuffer. */

SilcBuffer silc_command_payload_encode(SilcCommand cmd,
				       uint32 argc,
				       unsigned char **argv,
				       uint32 *argv_lens,
				       uint32 *argv_types,
				       uint16 ident)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  uint32 len = 0;

  SILC_LOG_DEBUG(("Encoding command payload"));

  if (argc) {
    args = silc_argument_payload_encode(argc, argv, argv_lens, argv_types);
    len = args->len;
  }

  len += SILC_COMMAND_PAYLOAD_LEN;
  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Create Command payload */
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_CHAR(cmd),
		     SILC_STR_UI_CHAR(argc),
		     SILC_STR_UI_SHORT(ident),
		     SILC_STR_END);

  /* Add arguments */
  if (argc) {
    silc_buffer_pull(buffer, SILC_COMMAND_PAYLOAD_LEN);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, args->len),
		       SILC_STR_END);
    silc_buffer_push(buffer, SILC_COMMAND_PAYLOAD_LEN);
    silc_free(args);
  }

  return buffer;
}

/* Same as above but encode the buffer from SilcCommandPayload structure
   instead of raw data. */

SilcBuffer silc_command_payload_encode_payload(SilcCommandPayload payload)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  uint32 len = 0;
  uint32 argc = 0;

  SILC_LOG_DEBUG(("Encoding command payload"));

  if (payload->args) {
    args = silc_argument_payload_encode_payload(payload->args);
    len = args->len;
    argc = silc_argument_get_arg_num(payload->args);
  }

  len += SILC_COMMAND_PAYLOAD_LEN;
  buffer = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buffer, SILC_BUFFER_END(buffer));

  /* Create Command payload */
  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(len),
		     SILC_STR_UI_CHAR(payload->cmd),
		     SILC_STR_UI_CHAR(argc),
		     SILC_STR_UI_SHORT(payload->ident),
		     SILC_STR_END);

  /* Add arguments */
  if (args) {
    silc_buffer_pull(buffer, SILC_COMMAND_PAYLOAD_LEN);
    silc_buffer_format(buffer,
		       SILC_STR_UI_XNSTRING(args->data, args->len),
		       SILC_STR_END);
    silc_buffer_push(buffer, SILC_COMMAND_PAYLOAD_LEN);
    silc_free(args);
  }

  return buffer;
}

/* Encodes Command payload with variable argument list. The arguments
   must be: uint32, unsigned char *, unsigned int, ... One 
   {uint32, unsigned char * and unsigned int} forms one argument, 
   thus `argc' in case when sending one {uint32, unsigned char * 
   and uint32} equals one (1) and when sending two of those it
   equals two (2), and so on. This has to be preserved or bad things
   will happen. The variable arguments is: {type, data, data_len}. */

SilcBuffer silc_command_payload_encode_va(SilcCommand cmd, 
					  uint16 ident, 
					  uint32 argc, ...)
{
  va_list ap;
  SilcBuffer buffer;

  va_start(ap, argc);
  buffer = silc_command_payload_encode_vap(cmd, ident, argc, ap);
  va_end(ap);

  return buffer;
}

/* Same as above but with va_list. */

SilcBuffer silc_command_payload_encode_vap(SilcCommand cmd, 
					   uint16 ident, 
					   uint32 argc, va_list ap)
{
  unsigned char **argv;
  uint32 *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  uint32 x_len;
  uint32 x_type;
  SilcBuffer buffer;
  int i, k;

  argv = silc_calloc(argc, sizeof(unsigned char *));
  argv_lens = silc_calloc(argc, sizeof(uint32));
  argv_types = silc_calloc(argc, sizeof(uint32));

  for (i = 0, k = 0; i < argc; i++) {
    x_type = va_arg(ap, uint32);
    x = va_arg(ap, unsigned char *);
    x_len = va_arg(ap, uint32);

    if (!x_type || !x || !x_len)
      continue;

    argv[k] = silc_calloc(x_len + 1, sizeof(unsigned char));
    memcpy(argv[k], x, x_len);
    argv_lens[k] = x_len;
    argv_types[k] = x_type;
    k++;
  }

  buffer = silc_command_payload_encode(cmd, k, argv, argv_lens, 
				       argv_types, ident);

  for (i = 0; i < k; i++)
    silc_free(argv[i]);
  silc_free(argv);
  silc_free(argv_lens);
  silc_free(argv_types);

  return buffer;
}

/* Same as above except that this is used to encode strictly command
   reply packets. The command status message to be returned is sent as
   extra argument to this function. The `argc' must not count `status'
   as on argument. */

SilcBuffer 
silc_command_reply_payload_encode_va(SilcCommand cmd, 
				     SilcCommandStatus status,
				     uint16 ident,
				     uint32 argc, ...)
{
  va_list ap;
  unsigned char **argv;
  uint32 *argv_lens = NULL, *argv_types = NULL;
  unsigned char status_data[2];
  unsigned char *x;
  uint32 x_len;
  uint32 x_type;
  SilcBuffer buffer;
  int i, k;

  va_start(ap, argc);

  argc++;
  argv = silc_calloc(argc, sizeof(unsigned char *));
  argv_lens = silc_calloc(argc, sizeof(uint32));
  argv_types = silc_calloc(argc, sizeof(uint32));

  SILC_PUT16_MSB(status, status_data);
  argv[0] = silc_calloc(sizeof(status_data) + 1, sizeof(unsigned char));
  memcpy(argv[0], status_data, sizeof(status_data));
  argv_lens[0] = sizeof(status_data);
  argv_types[0] = 1;

  for (i = 1, k = 1; i < argc; i++) {
    x_type = va_arg(ap, uint32);
    x = va_arg(ap, unsigned char *);
    x_len = va_arg(ap, uint32);

    if (!x_type || !x || !x_len)
      continue;

    argv[k] = silc_calloc(x_len + 1, sizeof(unsigned char));
    memcpy(argv[k], x, x_len);
    argv_lens[k] = x_len;
    argv_types[k] = x_type;
    k++;
  }

  buffer = silc_command_payload_encode(cmd, k, argv, argv_lens, 
				       argv_types, ident);

  for (i = 0; i < k; i++)
    silc_free(argv[i]);
  silc_free(argv);
  silc_free(argv_lens);
  silc_free(argv_types);

  va_end(ap);

  return buffer;
}

/* Frees Command Payload */

void silc_command_payload_free(SilcCommandPayload payload)
{
  if (payload) {
    silc_argument_payload_free(payload->args);
    silc_free(payload);
  }
}

/* Returns command */

SilcCommand silc_command_get(SilcCommandPayload payload)
{
  return payload->cmd;
}

/* Retuns arguments payload */

SilcArgumentPayload silc_command_get_args(SilcCommandPayload payload)
{
  return payload->args;
}

/* Returns identifier */

uint16 silc_command_get_ident(SilcCommandPayload payload)
{
  return payload->ident;
}

/* Function to set identifier to already allocated Command Payload. Command
   payloads are frequentlly resent in SILC and thusly this makes it easy
   to set the identifier. */

void silc_command_set_ident(SilcCommandPayload payload, uint16 ident)
{
  payload->ident = ident;
}

/* Function to set the command to already allocated Command Payload. */

void silc_command_set_command(SilcCommandPayload payload, SilcCommand command)
{
  payload->cmd = command;
}
