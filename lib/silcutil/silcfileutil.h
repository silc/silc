/*

  silcfileutil.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SilcFileUtilAPI
 *
 * DESCRIPTION
 *
 *
 ***/

#ifndef SILCFILEUTIL_H
#define SILCFILEUTIL_H

/* Prototypes */

int silc_file_open(const char *filename, int flags);
int silc_file_open_mode(const char *filename, int flags, int mode);
int silc_file_read(int fd, unsigned char *buf, uint32 buf_len);
int silc_file_write(int fd, const char *buffer, uint32 len);
int silc_file_close(int fd);
char *silc_file_readfile(const char *filename, uint32 *return_len);
int silc_file_writefile(const char *filename, const char *buffer, uint32 len);
int silc_file_writefile_mode(const char *filename, const char *buffer, 
			     uint32 len, int mode);
uint64 silc_file_size(const char *filename);

#endif /* SILCFILEUTIL_H */
