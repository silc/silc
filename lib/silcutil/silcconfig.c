/*

  silcconfig.c

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
 * Revision 1.1  2000/09/13 17:45:16  priikone
 * 	Splitted SILC core library. Core library includes now only
 * 	SILC protocol specific stuff. New utility library includes the
 * 	old stuff from core library that is more generic purpose stuff.
 *
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

/* Opens and reads a configuration file to a buffer. The read data is 
   returned to the ret_buffer argument. */

void silc_config_open(char *filename, SilcBuffer *ret_buffer)
{
  char *buffer;
  int filelen;

  buffer = silc_file_read(filename, &filelen);
  if (buffer == NULL)
    return;

  /* Buffer don't have EOF, but we'll need it. */
  buffer[filelen] = EOF;

  *ret_buffer = silc_buffer_alloc(filelen + 1);
  silc_buffer_pull_tail(*ret_buffer, filelen + 1);
  silc_buffer_put(*ret_buffer, buffer, filelen + 1);

  SILC_LOG_DEBUG(("Config file `%s' opened", filename));
}

/* Returns next token from a buffer to the dest argument. Returns the
   length of the token. This is used to take tokens from a configuration
   line. */

int silc_config_get_token(SilcBuffer buffer, char **dest)
{
  int len;

  if (strchr(buffer->data, ':')) {
    len = strcspn(buffer->data, ":");
    if (len) {
      *dest = silc_calloc(len + 1, sizeof(char));
      memset(*dest, 0, len + 1);
      memcpy(*dest, buffer->data, len);
    }
    silc_buffer_pull(buffer, len + 1);
    return len;
  }

  return -1;
}

/* Returns number of tokens in a buffer. */

int silc_config_check_num_token(SilcBuffer buffer)
{
  int len, len2, num;

  if (strchr(buffer->data, ':')) {
    len = 0;
    num = 0;
    while (strchr(buffer->data + len, ':')) {
      num++;
      len2 = strcspn(buffer->data + len, ":") + 1;
      len += len2;
    }

    return num;
  }

  return 0;
}
