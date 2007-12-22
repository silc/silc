/*

  silcstream.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Stream Interface
 *
 * DESCRIPTION
 *
 * SILC Stream API is a generic representation of a stream.  A common API
 * is defined that can be used to read from and write to the stream.  Any
 * other stream API derived from this API can use this same interface for
 * reading and writing.
 *
 * Note that stream implementations usually are not thread-safe.  Always
 * verify whether a stream implementation is thread-safe by checking their
 * corresponding documentation.
 *
 ***/

#ifndef SILCSTREAM_H
#define SILCSTREAM_H

/****s* silcutil/SilcStreamAPI/SilcStream
 *
 * NAME
 *
 *    typedef void *SilcStream;
 *
 * DESCRIPTION
 *
 *    Abstact stream context representing any stream.  All streams are using
 *    this abstraction so that the stream can be accessed using the standard
 *    silc_stream_* functions.  All streams are destroyed by calling the
 *    silc_stream_destroy function.
 *
 ***/
typedef void *SilcStream;

/****d* silcutil/SilcStreamAPI/SilcStreamStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcStreamStatus;
 *
 * DESCRIPTION
 *
 *    Stream status.  This status is returned into the SilcStreamNotifier
 *    callback function to indicate the status of the stream at a given
 *    moment.
 *
 * SOURCE
 */
typedef enum {
  SILC_STREAM_CAN_READ,		/* Data available for reading */
  SILC_STREAM_CAN_WRITE,	/* Stream ready for writing */
} SilcStreamStatus;
/***/

/****f* silcutil/SilcStreamAPI/SilcStreamNotifier
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcStreamNotifier)(SilcStream stream,
 *                                       SilcStreamStatus status,
 *                                       void *context);
 *
 * DESCRIPTION
 *
 *    A callback of this type is called as stream notifier to notify of a
 *    certain action taken over the stream.  This is called to notify for
 *    example that data is ready for reading, or writing or that end of
 *    stream occurred.
 *
 ***/
typedef void (*SilcStreamNotifier)(SilcStream stream,
				   SilcStreamStatus status,
				   void *context);

/****s* silcutil/SilcStreamAPI/SilcStreamOps
 *
 * NAME
 *
 *    typedef struct { ... } SilcStreamOps;
 *
 * DESCRIPTION
 *
 *    SILC Stream operations structure.  This structure includes callback
 *    functions to the actual stream implementation.  Any stream that
 *    use SILC Stream abstraction must fill this structure with the actual
 *    stream implementation.
 *
 *    Each stream implementation MUST set this structure as the first field
 *    in their stream structure.  As it is that structure that is passed
 *    to the silc_stream_* routines, the SILC Stream API expects that the
 *    SilcStream context starts with this structure.
 *
 * EXAMPLE
 *
 *    typedef struct {
 *      const SilcStreamOps *ops;
 *      ... other stuff ...
 *    } *SilcFooStream;
 *
 *    SilcFooStream foo;
 *    silc_stream_write(foo, data, data_len);
 *
 * SOURCE
 */
typedef struct {
  /* This is called to read data from the stream.  This is called when
     silc_stream_read function was called. */
  int (*read)(SilcStream stream, unsigned char *buf, SilcUInt32 buf_len);

  /* This is called when writing data to the stream.  This is called when
     silc_stream_write function was called. */
  int (*write)(SilcStream stream, const unsigned char *data,
	       SilcUInt32 data_len);

  /* This is called to close the stream.  This is called when the
     silc_stream_close function was called. */
  SilcBool (*close)(SilcStream stream);

  /* This is called to destroy the stream.  This is called when the
     silc_stream_destroy function was called. */
  void (*destroy)(SilcStream stream);

  /* This is called to set a notifier callback to the stream and schedule
     the stream.  Stream should not be scheduled before calling this
     function.  If stream does not need scheduler then the scheduler can
     be ignored.  This is called when silc_stream_set_notifier was called.
     Returns FALSE if the stream could not be scheduled. */
  SilcBool (*notifier)(SilcStream stream, SilcSchedule schedule,
		       SilcStreamNotifier callback, void *context);

  /* This is called to return the associated scheduler, if set.  This is
     called when silc_stream_get_schedule was called. */
  SilcSchedule (*get_schedule)(SilcStream stream);
} SilcStreamOps;
/***/

/****f* silcutil/SilcStreamAPI/silc_stream_read
 *
 * SYNOPSIS
 *
 *    int silc_stream_read(SilcStream stream, unsigned char *buf,
 *                         SilcUInt32 buf_len);
 *
 * DESCRIPTION
 *
 *    Reads data from the stream indicated by `stream' into the data buffer
 *    indicated by `buf' which is size of `buf_len'.  This returns the amount
 *    of data read, zero (0) if end of stream occurred, -1 if data could
 *    not be read at this moment, or -2 if error occurred.  If -1 is returned
 *    the notifier callback will later be called with SILC_STREAM_CAN_READ
 *    status when stream is again ready for reading.
 *
 *    If error occurred the error code can be retrieved with silc_errno.
 *
 ***/
int silc_stream_read(SilcStream stream, unsigned char *buf,
		     SilcUInt32 buf_len);

/****f* silcutil/SilcStreamAPI/silc_stream_write
 *
 * SYNOPSIS
 *
 *    int silc_stream_write(SilcStream stream, const unsigned char *data,
 *                          SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Writes `data_len' bytes of data to the stream indicated by `stream' from
 *    data buffer indicated by `data'.  Returns the amount of data written,
 *    zero (0) if end of stream occurred, -1 if data could not be written
 *    at this moment, or -2 if error occurred.  If -1 is returned the
 *    notifier callback will later be called with SILC_STREAM_CAN_WRITE
 *    status when stream is again ready for writing.
 *
 *    If error occurred the error code can be retrieved with silc_errno.
 *
 ***/
int silc_stream_write(SilcStream stream, const unsigned char *data,
		      SilcUInt32 data_len);

/****f* silcutil/SilcStreamAPI/silc_stream_close
 *
 * SYNOPSIS
 *
 *    SilcBool silc_stream_close(SilcStream stream);
 *
 * DESCRIPTION
 *
 *    Closes the stream indicated by `stream'.  No data can be read or written
 *    to the stream after calling this function.  Return TRUE if the stream
 *    could be closed.  If action is taken on closed stream the notifier
 *    callback may be called with an error status.
 *
 ***/
SilcBool silc_stream_close(SilcStream stream);

/****f* silcutil/SilcStreamAPI/silc_stream_destroy
 *
 * SYNOPSIS
 *
 *    void silc_stream_destroy(SilcStream stream);
 *
 * DESCRIPTION
 *
 *    Destroy the stream indicated by `stream'.  The `stream' will become
 *    invalid after this function returns.  All streams are destroyed by
 *    calling this function.  The silc_stream_close should be called
 *    before calling this function.  However, if it is not called this
 *    function will call it.
 *
 ***/
void silc_stream_destroy(SilcStream stream);

/****f* silcutil/SilcStreamAPI/silc_stream_set_notifier
 *
 * SYNOPSIS
 *
 *    SilcBool silc_stream_set_notifier(SilcStream stream,
 *                                      SilcSchedule schedule,
 *                                      SilcStreamNotifier notifier,
 *                                      void *context);
 *
 * DESCRIPTION
 *
 *    Schedule `stream' for stream events.  Set the `notifier' callback to
 *    be called when some event takes place on the stream.  The event will
 *    be delievered to the `notifier' callback with the `context'.  It is
 *    called for example when data is available for reading or writing, or
 *    if an error occurs.  This can be called at any time for valid stream.
 *    This call will also set the `stream' into non-blocking mode.
 *
 *    If `notifier' is set to NULL no callback will be called for the stream,
 *    and the stream is not scheduled anymore.
 *
 *    This function returns FALSE if the `schedule' was provided and the
 *    stream could not be scheduled.  The actual API for `stream' may provide
 *    access to the actual error information.  Returns TRUE on success.
 *
 ***/
SilcBool silc_stream_set_notifier(SilcStream stream, SilcSchedule schedule,
				  SilcStreamNotifier notifier, void *context);

/****f* silcutil/SilcStreamAPI/silc_stream_get_schedule
 *
 * SYNOPSIS
 *
 *    SilcSchedule silc_stream_get_schedule(SilcStream stream);
 *
 * DESCRIPTION
 *
 *    Returns the scheduler that has been associated with the `stream', or
 *    NULL if one has not been set for the `stream'.
 *
 ***/
SilcSchedule silc_stream_get_schedule(SilcStream stream);

#endif /* SILCSTREAM_H */
