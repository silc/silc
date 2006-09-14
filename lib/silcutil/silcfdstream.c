/*

  silcfdstream.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/************************** Types and definitions ***************************/

#define SILC_IS_FD_STREAM(s) (s->ops == &silc_fd_stream_ops)

const SilcStreamOps silc_fd_stream_ops;

/* FD stream context */
typedef struct {
  const SilcStreamOps *ops;
  SilcSchedule schedule;
  SilcStreamNotifier notifier;
  void *notifier_context;
  int fd1;
  int fd2;
  int error;
} *SilcFDStream;


/************************ Static utility functions **************************/

/* The IO process callback that calls the notifier callback to upper layer. */

SILC_TASK_CALLBACK(silc_fd_stream_io)
{
  SilcFDStream stream = context;

  if (!stream->notifier)
    return;

  switch (type) {
  case SILC_TASK_WRITE:
    stream->notifier(stream, SILC_STREAM_CAN_WRITE, stream->notifier_context);
    break;

  case SILC_TASK_READ:
    stream->notifier(stream, SILC_STREAM_CAN_READ, stream->notifier_context);
    break;

  default:
    break;
  }
}


/****************************** Public API **********************************/

/* Create file descriptor stream */

SilcStream silc_fd_stream_create(int fd)
{
  if (fd < 1)
    return NULL;
  return silc_fd_stream_create2(fd, 0);
}

/* Create stream with two file descriptors */

SilcStream silc_fd_stream_create2(int read_fd, int write_fd)
{
  SilcFDStream stream;

  if (read_fd < 1)
    return NULL;

  stream = silc_calloc(1, sizeof(*stream));
  if (!stream)
    return NULL;

  SILC_LOG_DEBUG(("Creating new fd stream %p", stream));

  stream->ops = &silc_fd_stream_ops;
  stream->fd1 = read_fd;
  stream->fd2 = write_fd;

  return stream;
}

/* Create by opening file */

SilcStream silc_fd_stream_file(const char *filename,
			       SilcBool reading, SilcBool writing)
{
  int fd, flags = 0;

  if (!filename)
    return NULL;

  if (reading)
    flags |= O_RDONLY;
  if (writing)
    flags |= O_CREAT | O_WRONLY;
  if (reading && writing)
    flags |= O_CREAT | O_RDWR;

  fd = silc_file_open(filename, flags);
  if (fd < 0)
    return NULL;

  return silc_fd_stream_create(fd);
}

/* Return fds */

SilcBool silc_fd_stream_get_info(SilcStream stream, int *read_fd,
				 int *write_fd)
{
  SilcFDStream fd_stream = stream;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return FALSE;

  if (read_fd)
    *read_fd = fd_stream->fd1;
  if (write_fd)
    *write_fd = fd_stream->fd2;

  return TRUE;
}

/* Return errno */

int silc_fd_stream_get_error(SilcStream stream)
{
  SilcFDStream fd_stream = stream;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return 0;

  return fd_stream->error;
}

/* Read */

int silc_fd_stream_read(SilcStream stream, unsigned char *buf,
			SilcUInt32 buf_len)
{
  SilcFDStream fd_stream = stream;
  int len = 0;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return -2;
  if (!fd_stream->notifier)
    return -2;

  SILC_LOG_DEBUG(("Reading data from fd %d", fd_stream->fd1));

  len = silc_file_read(fd_stream->fd1, buf, buf_len);
  if (len < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      silc_schedule_set_listen_fd(fd_stream->schedule, fd_stream->fd1,
				  SILC_TASK_READ, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot read from fd: %d:%s",
		    fd_stream->fd1, strerror(errno)));
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd1);
    fd_stream->error = errno;
    return -2;
  }

  SILC_LOG_DEBUG(("Read %d bytes", len));

  if (!len)
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd1);

  return len;
}

/* Write */

int silc_fd_stream_write(SilcStream stream, const unsigned char *data,
			 SilcUInt32 data_len)
{
  SilcFDStream fd_stream = stream;
  int ret;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return -2;
  if (!fd_stream->notifier)
    return -2;

  SILC_LOG_DEBUG(("Writing data to fd %d", fd_stream->fd2));

  ret = silc_file_write(fd_stream->fd2, data, data_len);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
      silc_schedule_set_listen_fd(fd_stream->schedule, fd_stream->fd2,
				  SILC_TASK_READ | SILC_TASK_WRITE, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot write to fd: %s", strerror(errno)));
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd2);
    fd_stream->error = errno;
    return -2;
  }

  SILC_LOG_DEBUG(("Wrote data %d bytes", ret));

  if (fd_stream->fd1 == fd_stream->fd2)
    silc_schedule_set_listen_fd(fd_stream->schedule, fd_stream->fd2,
				SILC_TASK_READ, FALSE);
  else
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd2);

  return ret;
}

/* Close stream */

SilcBool silc_fd_stream_close(SilcStream stream)
{
  SilcFDStream fd_stream = stream;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return FALSE;

  if (fd_stream->fd1 > 0) {
    silc_file_close(fd_stream->fd1);
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd1);
  }
  if (fd_stream->fd2 > 0 && fd_stream->fd2 != fd_stream->fd1) {
    silc_file_close(fd_stream->fd2);
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd2);
  }

  return TRUE;
}

/* Destroy stream */

void silc_fd_stream_destroy(SilcStream stream)
{
  SilcFDStream fd_stream = stream;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return;

  silc_fd_stream_close(stream);
  silc_schedule_task_del_by_fd(fd_stream->schedule, fd_stream->fd1);
  silc_schedule_task_del_by_fd(fd_stream->schedule, fd_stream->fd2);
  silc_free(stream);
}

/* Sets stream notification callback for the stream */

void silc_fd_stream_notifier(SilcStream stream,
			     SilcSchedule schedule,
			     SilcStreamNotifier callback,
			     void *context)
{
  SilcFDStream fd_stream = stream;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return;

  SILC_LOG_DEBUG(("Setting stream notifier callback"));

  fd_stream->notifier = callback;
  fd_stream->notifier_context = context;
  fd_stream->schedule = schedule;

  /* Schedule the file descriptors */
  if (schedule) {
    if (fd_stream->fd2 > 0) {
      silc_schedule_task_add_fd(schedule, fd_stream->fd2,
				silc_fd_stream_io, stream);
      silc_file_set_nonblock(fd_stream->fd2);
    }
    if (fd_stream->fd1 > 0) {
      silc_schedule_task_add_fd(schedule, fd_stream->fd1,
				silc_fd_stream_io, stream);
      silc_schedule_set_listen_fd(schedule, fd_stream->fd1,
				  SILC_TASK_READ, FALSE);
      silc_file_set_nonblock(fd_stream->fd1);;
      if (fd_stream->fd2 < 1)
	fd_stream->fd2 = fd_stream->fd1;
    }
  } else {
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd1);
    silc_schedule_unset_listen_fd(fd_stream->schedule, fd_stream->fd2);
  }
}

/* Return schedule */

SilcSchedule silc_fd_stream_get_schedule(SilcStream stream)
{
  SilcFDStream fd_stream = stream;

  if (!SILC_IS_FD_STREAM(fd_stream))
    return NULL;

  return fd_stream->schedule;
}

/* File descriptor stream operations */
const SilcStreamOps silc_fd_stream_ops =
{
  silc_fd_stream_read,
  silc_fd_stream_write,
  silc_fd_stream_close,
  silc_fd_stream_destroy,
  silc_fd_stream_notifier,
  silc_fd_stream_get_schedule
};
