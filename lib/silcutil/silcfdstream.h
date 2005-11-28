/*

  silcfdstream.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC File Descriptor Stream Interface
 *
 * DESCRIPTION
 *
 * Implementation of SILC File Descriptor Stream.  The file descriptor
 * stream can be used read from and write to a file descriptor.  This
 * interface should be used only with real file descriptors, not with
 * sockets.  Use the SILC Socket Stream for sockets.
 *
 * SILC File Descriptor Stream is not thread-safe.  If same stream must be
 * used in multithreaded environment concurrency control must be employed.
 *
 ***/

#ifndef SILCFDSTREAM_H
#define SILCFDSTREAM_H

/****f* silcutil/SilcFDStreamAPI/silc_fd_stream_create
 *
 * SYNOPSIS
 *
 *    SilcStream silc_fd_stream_create(int fd, SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Creates file descriptor stream for the open file descriptor indicated
 *    by `fd'.  The stream is closed with the silc_stream_close and destroyed
 *    with the silc_stream_destroy.
 *
 ***/
SilcStream silc_fd_stream_create(int fd, SilcSchedule schedule);

/****f* silcutil/SilcFDStreamAPI/silc_fd_stream_create2
 *
 * SYNOPSIS
 *
 *    SilcStream silc_fd_stream_create2(int read_fd, int write_fd,
 *                                      SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Creates file descriptor stream for the open file descriptors indicated
 *    by `read_fd' and `write_fd'.  The `read_fd' must be opened for reading
 *    and `write_fd' opened for writing.  The stream is closed with the
 *    silc_stream_close and destroyed with the silc_stream_destroy.
 *
 ***/
SilcStream silc_fd_stream_create2(int read_fd, int write_fd,
				  SilcSchedule schedule);

/****f* silcutil/SilcFDStreamAPI/silc_fd_stream_get_info
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_fd_stream_get_info(SilcStream stream, int *read_fd, int *write_fd);
 *
 * DESCRIPTION
 *
 *    Returns the file descriptors associated with the stream.  The 'write_fd'
 *    is available only if the stream was created with silc_fd_stream_create2
 *    function.
 *
 ***/
SilcBool silc_fd_stream_get_info(SilcStream stream, int *read_fd, int *write_fd);

/****f* silcutil/SilcFDStreamAPI/silc_fd_stream_get_error
 *
 * SYNOPSIS
 *
 *    int silc_fd_stream_get_error(SilcStream stream);
 *
 * DESCRIPTION
 *
 *    If error occurred during file descriptor stream operations, this
 *    function can be used to retrieve the error number that occurred.
 *
 ***/
int silc_fd_stream_get_error(SilcStream stream);

#endif /* SILCFDSTREAM_H */
