/*

  silcasync.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005, 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/* Halts async operation */

SilcBool silc_async_halt(SilcAsyncOperation op)
{
  SILC_LOG_DEBUG(("Halting async operation"));

  if (op->pause_cb)
    return op->pause_cb(op, TRUE, op->context);

  return FALSE;
}

/* Resumes async operation */

SilcBool silc_async_resume(SilcAsyncOperation op)
{
  SILC_LOG_DEBUG(("Resuming async operation"));

  if (op->pause_cb)
    return op->pause_cb(op, FALSE, op->context);

  return FALSE;
}

/* Aborts async operation */

void silc_async_abort(SilcAsyncOperation op,
                      SilcAsyncOperationAbort abort_cb, void *context)
{
  SILC_LOG_DEBUG(("Aborting async operation"));

  if (op->abort_cb)
    op->abort_cb(op, op->context);

  if (abort_cb)
    abort_cb(op, context);

  silc_async_free(op);
}

/* Creates new async operation */

SilcAsyncOperation silc_async_alloc(SilcAsyncOperationAbort abort_cb,
				    SilcAsyncOperationPause pause_cb,
				    void *context)
{
  SilcAsyncOperation op;

  SILC_LOG_DEBUG(("Creating new async operation"));

  op = silc_calloc(1, sizeof(*op));
  if (!op)
    return NULL;

  silc_async_init(op, abort_cb, pause_cb, context);

  op->allocated = TRUE;

  return op;
}

/* Creates new async operation */

SilcBool silc_async_init(SilcAsyncOperation op,
			 SilcAsyncOperationAbort abort_cb,
			 SilcAsyncOperationPause pause_cb,
			 void *context)
{
  SILC_ASSERT(abort_cb);
  op->abort_cb = abort_cb;
  op->pause_cb = pause_cb;
  op->context = context;
  op->allocated = FALSE;
  return TRUE;
}

/* Stops async operation */

void silc_async_free(SilcAsyncOperation op)
{
  if (op->allocated) {
    SILC_LOG_DEBUG(("Stopping async operation"));
    silc_free(op);
  }
}

/* Return context */

void *silc_async_get_context(SilcAsyncOperation op)
{
  return op->context;
}
