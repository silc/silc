/*

  silcfileutil.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC File Util Interface
 *
 * DESCRIPTION
 *
 *    The SILC File Util Interface is a small set of functions that provides a
 *    portable access method to the filesystem.
 *
 ***/

#ifndef SILCFILEUTIL_H
#define SILCFILEUTIL_H

/* Prototypes */

/****f* silcutil/SilcFileUtilAPI/silc_file_open
 *
 * SYNOPSIS
 *
 *    int silc_file_open(const char *filename, int flags);
 *
 * DESCRIPTION
 *
 *    Opens a file indicated by the filename `filename' with flags indicated
 *    by `flags'.  The opening permission defaults to 0600.  The `flags'
 *    are defined in open(2).  Returns the opened file descriptor or -1 on
 *    error.
 *
 ***/
int silc_file_open(const char *filename, int flags);

/****f* silcutil/SilcFileUtilAPI/silc_file_open_mode
 *
 * SYNOPSIS
 *
 *    int silc_file_open_mode(const char *filename, int flags, int mode);
 *
 * DESCRIPTION
 *
 *    Opens a file indicated by the filename `filename' with flags indicated
 *    by `flags'.  The argument `mode' specifies the permissions to use in
 *    case a new file is created.  The `flags' are defined in open(2).
 *    Returns the opened file descriptor or -1 on error.
 *
 ***/
int silc_file_open_mode(const char *filename, int flags, int mode);

/****f* silcutil/SilcFileUtilAPI/silc_file_read
 *
 * SYNOPSIS
 *
 *    int silc_file_read(int fd, unsigned char *buf, SilcUInt32 buf_len);
 *
 * DESCRIPTION
 *
 *    Reads data from file descriptor `fd' to `buf'.  Returns the amount of
 *    bytes read, 0 on EOF or -1 on error.
 *
 ***/
int silc_file_read(int fd, unsigned char *buf, SilcUInt32 buf_len);

/****f* silcutil/SilcFileUtilAPI/silc_file_write
 *
 * SYNOPSIS
 *
 *    int silc_file_write(int fd, const char *buffer, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Writes `buffer' of length of `len' to file descriptor `fd'.  Returns
 *    the amount of bytes written, 0 on EOF or -1 on error.
 *
 ***/
int silc_file_write(int fd, const char *buffer, SilcUInt32 len);

/****f* silcutil/SilcFileUtilAPI/silc_file_close
 *
 * SYNOPSIS
 *
 *    int silc_file_close(int fd);
 *
 * DESCRIPTION
 *
 *    Closes file descriptor previously opened with silc_file_open().
 *    Returns 0 on success or -1 on error.
 *
 ***/
int silc_file_close(int fd);

/****f* silcutil/SilcFileUtilAPI/silc_file_set_nonblock
 *
 * SYNOPSIS
 *
 *    int silc_file_set_nonblock(int fd);
 *
 * DESCRIPTION
 *
 *    Sets the file descriptor to non-blocking mode.
 *
 ***/
int silc_file_set_nonblock(int fd);

/****f* silcutil/SilcFileUtilAPI/silc_file_readfile
 *
 * SYNOPSIS
 *
 *    char *silc_file_readfile(const char *filename, SilcUInt32 *return_len,
 *                             SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Reads the content of `filename' to a buffer.  The allocated buffer is
 *    returned.  This does not NULL terminate the buffer but EOF terminate
 *    it.  The caller must replace the EOF with NULL if the buffer must be
 *    NULL terminated.
 *
 *    If the `return_len' pointer is not NULL, it's filled with the length of
 *    the file.
 *
 *    If `stack' is non-NULL the returned buffer is allocated from `stack'.
 *    The allocation consumes `stack' so caller should push the stack before
 *    calling this function and pop it later.
 *
 ***/
char *silc_file_readfile(const char *filename, SilcUInt32 *return_len,
			 SilcStack stack);

/****f* silcutil/SilcFileUtilAPI/silc_file_writefile
 *
 * SYNOPSIS
 *
 *    int silc_file_writefile(const char *filename, const char *buffer,
 *                            SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Writes a buffer to the file.  If the file is created specific mode is
 *    set to the file.
 *
 ***/
int silc_file_writefile(const char *filename, const char *buffer,
			SilcUInt32 len);

/****f* silcutil/SilcFileUtilAPI/silc_file_writefile_mode
 *
 * SYNOPSIS
 *
 *    int silc_file_writefile_mode(const char *filename, const char *buffer,
 *                                 SilcUInt32 len, int mode);
 *
 * DESCRIPTION
 *
 *    Writes a buffer to the file.  If the file is created the specified `mode'
 *    is set to the file.
 *
 ***/
int silc_file_writefile_mode(const char *filename, const char *buffer,
			     SilcUInt32 len, int mode);

/****f* silcutil/SilcFileUtilAPI/silc_file_size
 *
 * SYNOPSIS
 *
 *    SilcUInt64 silc_file_size(const char *filename);
 *
 * DESCRIPTION
 *
 *    Returns the size of `filename'. Returns 0 on error.
 *
 ***/
SilcUInt64 silc_file_size(const char *filename);

#endif	/* !SILCFILEUTIL_H */
