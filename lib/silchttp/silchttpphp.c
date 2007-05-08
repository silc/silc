/*

  silchttpphp.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silchttpphp.h"

/* Executes PHP code and returns result */

SilcBuffer silc_http_php(char *php_data)
{
  SilcBuffer ret;
  char *name, tmp[32];

  /* Write the PHP data to temporary file */
#ifdef SILC_WIN32
  name = _mktemp("silchttpphpXXXXXX");
  if (!name)
    return NULL;
#else
  memset(tmp, 0, sizeof(tmp));
  silc_snprintf(tmp, sizeof(tmp) - 1, "/tmp/silchttpphpXXXXXX");
  if (mkstemp(tmp) == -1)
    return NULL;
  name = tmp;
#endif /* SILC_WIN32 */

  silc_file_writefile_mode(name, php_data, strlen(php_data), 0600);

  /* Execute PHP */
  ret = silc_http_php_file(name);

#ifdef SILC_WIN32
  _unlink(name);
#else
  unlink(name);
#endif /* SILC_WIN32 */

  return ret;
}

/* Loads PHP file and executes the PHP code and returns the result */

SilcBuffer silc_http_php_file(const char *filename)
{
  SilcBuffer ret = NULL;
  unsigned char tmp[8192];
  FILE *fd;
  int len;

  SILC_LOG_DEBUG(("Executing PHP"));

  memset(tmp, 0, sizeof(tmp));
  silc_snprintf(tmp, sizeof(tmp) - 1, "php -f %s", filename);

#ifdef SILC_WIN32
  fd = _popen(tmp, "r");
#else
  fd = popen(tmp, "r");
#endif /* SILC_WIN32 */
  if (!fd)
    return NULL;

  /* Read the result */
  do {
    len = fread(tmp, 1, sizeof(tmp), fd);
    if (len < 0) {
      silc_buffer_free(ret);
#ifdef SILC_WIN32
      _pclose(fd);
#else
      pclose(fd);
#endif /* SILC_WIN32 */
      return NULL;
    }

    if (len) {
      if (!ret) {
	ret = silc_buffer_alloc(0);
	if (!ret) {
#ifdef SILC_WIN32
      _pclose(fd);
#else
      pclose(fd);
#endif /* SILC_WIN32 */
	  return NULL;
	}
      }

      silc_buffer_format(ret,
			 SILC_STR_ADVANCE,
			 SILC_STR_DATA(tmp, len),
			 SILC_STR_END);
    }
  } while (len);

  if (ret) {
    silc_buffer_format(ret,
		       SILC_STR_ADVANCE,
		       SILC_STR_DATA('\0', 1),
		       SILC_STR_END);
    silc_buffer_push(ret, silc_buffer_truelen(ret));
  }

  return ret;
}
