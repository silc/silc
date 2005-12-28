/*

  silcstream.c

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

#include "silc.h"

typedef struct {
  SilcStreamOps *ops;
} *SilcStreamHeader;

int silc_stream_read(SilcStream stream, unsigned char *buf,
		     SilcUInt32 buf_len)
{
  SilcStreamHeader h = stream;
  return h->ops->read(stream, buf, buf_len);
}

int silc_stream_write(SilcStream stream, const unsigned char *data,
		      SilcUInt32 data_len)
{
  SilcStreamHeader h = stream;
  return h->ops->write(stream, data, data_len);
}

SilcBool silc_stream_close(SilcStream stream)
{
  SilcStreamHeader h = stream;
  return h->ops->close(stream);
}

void silc_stream_destroy(SilcStream stream)
{
  SilcStreamHeader h = stream;
  return h->ops->destroy(stream);
}

void silc_stream_set_notifier(SilcStream stream, SilcSchedule schedule,
			      SilcStreamNotifier notifier, void *context)
{
  SilcStreamHeader h = stream;
  return h->ops->notifier(stream, schedule, notifier, context);
}

SilcSchedule silc_stream_get_schedule(SilcStream stream)
{
  SilcStreamHeader h = stream;
  return h->ops->get_schedule(stream);
}
