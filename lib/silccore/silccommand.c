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
  SilcUInt16 ident;
  SilcArgumentPayload args;
};

/* Length of the command payload */
#define SILC_COMMAND_PAYLOAD_LEN 6

/* Parses command payload returning new command payload structure */

SilcCommandPayload silc_command_payload_parse(const unsigned char *payload,
					      SilcUInt32 payload_len)
{
  SilcBufferStruct buffer;
  SilcCommandPayload newp;
  unsigned char args_num;
  SilcUInt16 p_len;
  int ret;

  SILC_LOG_DEBUG(("Parsing command payload"));

  silc_buffer_set(&buffer, (unsigned char *)payload, payload_len);
  newp = silc_calloc(1, sizeof(*newp));
  if (!newp)
    return NULL;

  /* Parse the Command Payload */
  ret = silc_buffer_unformat(&buffer, 
			     SILC_STR_UI_SHORT(&p_len),
			     SILC_STR_UI_CHAR(&newp->cmd),
			     SILC_STR_UI_CHAR(&args_num),
			     SILC_STR_UI_SHORT(&newp->ident),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(newp);
    return NULL;
  }

  if (p_len != buffer.len) {
    SILC_LOG_ERROR(("Incorrect command payload in packet, packet dropped"));
    silc_free(newp);
    return NULL;
  }

  if (newp->cmd == 0) {
    silc_free(newp);
    return NULL;
  }

  silc_buffer_pull(&buffer, SILC_COMMAND_PAYLOAD_LEN);
  if (args_num) {
    newp->args = silc_argument_payload_parse(buffer.data, buffer.len, args_num);
    if (!newp->args) {
      silc_free(newp);
      return NULL;
    }
  }
  silc_buffer_push(&buffer, SILC_COMMAND_PAYLOAD_LEN);

  return newp;
}

/* Encodes Command Payload returning it to SilcBuffer. */

SilcBuffer silc_command_payload_encode(SilcCommand cmd,
				       SilcUInt32 argc,
				       unsigned char **argv,
				       SilcUInt32 *argv_lens,
				       SilcUInt32 *argv_types,
				       SilcUInt16 ident)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  SilcUInt32 len = 0;

  SILC_LOG_DEBUG(("Encoding command payload"));

  if (argc) {
    args = silc_argument_payload_encode(argc, argv, argv_lens, argv_types);
    len = args->len;
  }

  len += SILC_COMMAND_PAYLOAD_LEN;
  buffer = silc_buffer_alloc_size(len);
  if (!buffer)
    return NULL;

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
    silc_buffer_free(args);
  }

  return buffer;
}

/* Same as above but encode the buffer from SilcCommandPayload structure
   instead of raw data. */

SilcBuffer silc_command_payload_encode_payload(SilcCommandPayload payload)
{
  SilcBuffer buffer;
  SilcBuffer args = NULL;
  SilcUInt32 len = 0;
  SilcUInt32 argc = 0;

  SILC_LOG_DEBUG(("Encoding command payload"));

  if (payload->args) {
    args = silc_argument_payload_encode_payload(payload->args);
    len = args->len;
    argc = silc_argument_get_arg_num(payload->args);
  }

  len += SILC_COMMAND_PAYLOAD_LEN;
  buffer = silc_buffer_alloc_size(len);
  if (!buffer) {
    if (args)
      silc_buffer_free(args);
    return NULL;
  }

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
    silc_buffer_free(args);
  }

  return buffer;
}

/* Encodes Command payload with variable argument list. The arguments
   must be: SilcUInt32, unsigned char *, unsigned int, ... One 
   {SilcUInt32, unsigned char * and unsigned int} forms one argument, 
   thus `argc' in case when sending one {SilcUInt32, unsigned char * 
   and SilcUInt32} equals one (1) and when sending two of those it
   equals two (2), and so on. This has to be preserved or bad things
   will happen. The variable arguments is: {type, data, data_len}. */

SilcBuffer silc_command_payload_encode_va(SilcCommand cmd, 
					  SilcUInt16 ident, 
					  SilcUInt32 argc, ...)
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
					   SilcUInt16 ident, 
					   SilcUInt32 argc, va_list ap)
{
  unsigned char **argv = NULL;
  SilcUInt32 *argv_lens = NULL, *argv_types = NULL;
  unsigned char *x;
  SilcUInt32 x_len;
  SilcUInt32 x_type;
  SilcBuffer buffer = NULL;
  int i, k = 0;

  if (argc) {
    argv = silc_calloc(argc, sizeof(unsigned char *));
    if (!argv)
      return NULL;
    argv_lens = silc_calloc(argc, sizeof(SilcUInt32));
    if (!argv_lens)
      return NULL;
    argv_types = silc_calloc(argc, sizeof(SilcUInt32));
    if (!argv_types)
      return NULL;

    for (i = 0, k = 0; i < argc; i++) {
      x_type = va_arg(ap, SilcUInt32);
      x = va_arg(ap, unsigned char *);
      x_len = va_arg(ap, SilcUInt32);
      
      if (!x_type || !x || !x_len)
	continue;
      
      argv[k] = silc_memdup(x, x_len);
      if (!argv[k])
	goto out;
      argv_lens[k] = x_len;
      argv_types[k] = x_type;
      k++;
    }
  }

  buffer = silc_command_payload_encode(cmd, k, argv, argv_lens, 
				       argv_types, ident);

 out:
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
				     SilcUInt16 ident,
				     SilcUInt32 argc, ...)
{
  va_list ap;
  SilcBuffer buffer;

  va_start(ap, argc);
  buffer = silc_command_reply_payload_encode_vap(cmd, status, ident, argc, ap);
  va_end(ap);

  return buffer;
}

SilcBuffer 
silc_command_reply_payload_encode_vap(SilcCommand cmd, 
				      SilcCommandStatus status,
				      SilcUInt16 ident, SilcUInt32 argc, 
				      va_list ap)
{
  unsigned char **argv;
  SilcUInt32 *argv_lens = NULL, *argv_types = NULL;
  unsigned char status_data[2];
  unsigned char *x;
  SilcUInt32 x_len;
  SilcUInt32 x_type;
  SilcBuffer buffer = NULL;
  int i, k;

  argc++;
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

  SILC_PUT16_MSB(status, status_data);
  argv[0] = silc_memdup(status_data, sizeof(status_data));
  if (!argv[0]) {
    silc_free(argv_types);
    silc_free(argv_lens);
    silc_free(argv);
    return NULL;
  }
  argv_lens[0] = sizeof(status_data);
  argv_types[0] = 1;

  for (i = 1, k = 1; i < argc; i++) {
    x_type = va_arg(ap, SilcUInt32);
    x = va_arg(ap, unsigned char *);
    x_len = va_arg(ap, SilcUInt32);

    if (!x_type || !x || !x_len)
      continue;

    argv[k] = silc_memdup(x, x_len);
    if (!argv[k])
      goto out;
    argv_lens[k] = x_len;
    argv_types[k] = x_type;
    k++;
  }

  buffer = silc_command_payload_encode(cmd, k, argv, argv_lens, 
				       argv_types, ident);

 out:
  for (i = 0; i < k; i++)
    silc_free(argv[i]);
  silc_free(argv);
  silc_free(argv_lens);
  silc_free(argv_types);

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

SilcUInt16 silc_command_get_ident(SilcCommandPayload payload)
{
  return payload->ident;
}

/* Return command status */

SilcCommandStatus silc_command_get_status(SilcCommandPayload payload)
{
  unsigned char *tmp;
  SilcCommandStatus status;

  if (!payload->args)
    return 0;
  tmp = silc_argument_get_arg_type(payload->args, 1, NULL);
  if (!tmp)
    return 0;

  SILC_GET16_MSB(status, tmp);
  return status;
}

/* Function to set identifier to already allocated Command Payload. Command
   payloads are frequentlly resent in SILC and thusly this makes it easy
   to set the identifier. */

void silc_command_set_ident(SilcCommandPayload payload, SilcUInt16 ident)
{
  payload->ident = ident;
}

/* Function to set the command to already allocated Command Payload. */

void silc_command_set_command(SilcCommandPayload payload, SilcCommand command)
{
  payload->cmd = command;
}
