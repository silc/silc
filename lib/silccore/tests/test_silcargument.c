/*

  test_silcargument.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* Tests:
   silc_argument_payload_parse
   silc_argument_payload_encode
   silc_argument_payload_encode_one
   silc_argument_payload_encode_payload
   silc_argument_payload_free
   silc_argument_get_arg_num
   silc_argument_get_arg_first_arg
   silc_argument_get_arg_next_arg
   silc_argument_get_arg_type
*/

#include "silc.h"
#include "silcargument.h"

#define ARG_NUM 250

int main(int argc, char **argv)
{
  SilcArgumentPayload payload;
  SilcBuffer args, args2;
  char arg[ARG_NUM + 2];
  int i;
  unsigned char **argvv, *a;
  SilcUInt32 *argvv_lens, l;
  SilcUInt32 *argvv_types, t;
  SilcBool success = FALSE;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_debug = 1;
    silc_debug_hexdump = 1;
    silc_log_set_debug_string("*argument*");
  }

  SILC_LOG_DEBUG(("Encoding %d arguments", ARG_NUM));
  argvv = silc_calloc(ARG_NUM, sizeof(unsigned char *));
  argvv_lens = silc_calloc(ARG_NUM, sizeof(SilcUInt32));
  argvv_types = silc_calloc(ARG_NUM, sizeof(SilcUInt32));
  for (i = 0; i < ARG_NUM; i++) {
    memset(arg, 0, sizeof(arg));
    memset(arg, 'a', i + 1);

    SILC_LOG_DEBUG(("Argument %d, len %d, type %d", i + 1,
		   strlen(arg), i + 1));
    SILC_LOG_HEXDUMP(("Argument data"), arg, strlen(arg));

    argvv[i] = silc_memdup(arg, strlen(arg));
    argvv_lens[i] = strlen(arg);
    argvv_types[i] = i + 1;
  }
  args = silc_argument_payload_encode(ARG_NUM, argvv, argvv_lens, argvv_types);
  if (!args)
    goto out;
  SILC_LOG_DEBUG(("Encoding was successful"));


  SILC_LOG_DEBUG(("Adding one extra argument"));
  memset(arg, 0, sizeof(arg));
  memset(arg, 'a', ARG_NUM + 1);
  SILC_LOG_DEBUG(("Argument %d, len %d, type %d", ARG_NUM + 1,
		 strlen(arg), ARG_NUM + 1));
  SILC_LOG_HEXDUMP(("Argument data"), arg, strlen(arg));
  args = silc_argument_payload_encode_one(args, arg, strlen(arg), 
					  ARG_NUM + 1);
  if (!args)
    goto out;
  SILC_LOG_DEBUG(("Adding one argument was successful"));

  SILC_LOG_HEXDUMP(("Encoded payload"), args->data, args->len);


  SILC_LOG_DEBUG(("Parsing the encoded payload"));
  payload = silc_argument_payload_parse(args->data, args->len, ARG_NUM + 1);
  if (!payload)
    goto out;
  SILC_LOG_DEBUG(("Parsing was successful"));


  SILC_LOG_DEBUG(("Re-encoding the parsed payload"));
  args2 = silc_argument_payload_encode_payload(payload);
  if (!args2)
    goto out;
  if (args2->len != args->len ||
      memcmp(args2->data, args->data, args->len)) {
    SILC_LOG_DEBUG(("Re-encoding failed"));
    goto out;
  }
  silc_buffer_free(args2);
  SILC_LOG_DEBUG(("Re-encoding was successful"));


  SILC_LOG_DEBUG(("Checking number of arguments"));
  SILC_LOG_DEBUG(("Number of arguments: %d (expecting %d)",
		 silc_argument_get_arg_num(payload), ARG_NUM + 1));
  if (silc_argument_get_arg_num(payload) != ARG_NUM + 1)
    goto out;


  SILC_LOG_DEBUG(("Traversing the parsed arguments"));
  i = 0;
  a = silc_argument_get_first_arg(payload, &t, &l);
  if (!a || t != argvv_types[0] || l != argvv_lens[0] ||
      memcmp(a, argvv[0], l)) {
    SILC_LOG_DEBUG(("First argument failed"));
    goto out;
  }
  while (a) {
    if (i + 1 == ARG_NUM + 1) {
      SILC_LOG_DEBUG(("Argument %d, len %d (expected %d), "
		      "type %d (expected %d)", i + 1, l, strlen(arg),
		      t, ARG_NUM + 1));
      if (!a || t != ARG_NUM + 1 || l != strlen(arg) ||
	  memcmp(a, arg, l)) {
	SILC_LOG_DEBUG(("Argument %d failed", ARG_NUM + 1));
	goto out;
      }
    } else {
      SILC_LOG_DEBUG(("Argument %d, len %d (expected %d), "
		      "type %d (expected %d)", i + 1, l, argvv_lens[i],
		      t, argvv_types[i]));
      if (!a || t != argvv_types[i] || l != argvv_lens[i] ||
	  memcmp(a, argvv[i], l)) {
	SILC_LOG_DEBUG(("Argument %d failed", i + 1));
	goto out;
      }
    }
    a = silc_argument_get_next_arg(payload, &t, &l);
    i++;
  }
  if (i != ARG_NUM + 1) {
    SILC_LOG_DEBUG(("All arguments was not parsed, missing %d args",
		    ARG_NUM + 1 - i));
    goto out;
  }
  SILC_LOG_DEBUG(("Traversing successful"));


  SILC_LOG_DEBUG(("Traversing arguments by type"));
  for (i = 0; i < ARG_NUM + 1; i++) {
    a = silc_argument_get_arg_type(payload, i + 1, &l);
    if (i + 1 == ARG_NUM + 1) {
      if (!a || t != ARG_NUM + 1 || l != strlen(arg) ||
	  memcmp(a, arg, l)) {
	SILC_LOG_DEBUG(("Argument %d failed", ARG_NUM + 1));
	goto out;
      }
    } else {
      if (!a || l != argvv_lens[i] || memcmp(a, argvv[i], l)) {
	SILC_LOG_DEBUG(("Argument %d failed", i + 1));
	goto out;
      }
    }
  }
  SILC_LOG_DEBUG(("Traversing successful"));

  success = TRUE;

 out:
  silc_argument_payload_free(payload);
  for (i = 0; i < ARG_NUM; i++)
    silc_free(argvv[i]);
  silc_free(argvv);
  silc_free(argvv_lens);
  silc_free(argvv_types);
  silc_buffer_free(args);

  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  exit(success);
}
