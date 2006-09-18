/*

  silchttpphp.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silchttp/SILC HTTP PHP Translator
 *
 * DESCRIPTION
 *
 * PHP translator for SILC HTTP Server, enabling PHP support for the pages
 * served through the SILC HTTP Server interface (silchttpserver.h).
 * The PHP must be installed in the system and must be in the execution
 * path for the interface to work.
 *
 ***/

#ifndef SILCHTTPPHP_H
#define SILCHTTPPHP_H

/****f* silchttp/SilcHTTPServer/silc_http_php
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_http_php(char *php_data);
 *
 * DESCRIPTION
 *
 *    Executes the PHP code contained in the buffer `php_data' and returns
 *    the result in the allocated SilcBuffer or NULL on error.  The caller
 *    must free the returned buffer.
 *
 ***/
SilcBuffer silc_http_php(char *php_data);

/****f* silchttp/SilcHTTPServer/silc_http_php
 *
 * SYNOPSIS
 *
 *    SilcBuffer silc_http_php_file(const char *filepath);
 *
 * DESCRIPTION
 *
 *    Reads the PHP contents from the file indicated by the `filepath' and
 *    executes the PHP code and returns the result in the allocated
 *    SilcBuffer or NULL on error.  The caller must free the returned buffer.
 *
 ***/
SilcBuffer silc_http_php_file(const char *filename);

#endif /* SILCHTTPPHP_H */
