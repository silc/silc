/*

  silcsymbianschduler.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* On symbian the SILC Scheduler doesn't do anything.  All timeout tasks
   are dispatched by the generic scheduler implementation.  Sockets and
   file descriptors are dispatched automatically in their class
   implementation, so adding FD Tasks on Symbian doesn't do anything.

   This also means that on Symbian the SILC Scheduler always returns
   immediately.  Because FD tasks use the Symbian scheduler the performance
   is as good as it can be.  For timeout tasks the performance is not an
   issue. */

#include "silc.h"

int silc_poll(SilcSchedule schedule, void *context)
{
  /* Return immediately, timeout. */
  return 0;
}

SilcBool silc_schedule_internal_schedule_fd(SilcSchedule schedule,
					    void *context,
					    SilcTaskFd task,
					    SilcTaskEvent event_mask)
{
  /* Nothing to do */
  return TRUE;
}

void *silc_schedule_internal_init(SilcSchedule schedule,
				  void *app_context)
{
  /* Nothing to do */
  return NULL;
}


void silc_schedule_internal_uninit(SilcSchedule schedule, void *context)
{
  /* Nothing to do */
}

void silc_schedule_internal_wakeup(SilcSchedule schedule, void *context)
{
  /* Nothing to do */
}

void silc_schedule_internal_signal_register(SilcSchedule schedule,
					    void *context,
					    SilcUInt32 sig,
                                            SilcTaskCallback callback,
                                            void *callback_context)
{
  /* Nothing to do */
}

void silc_schedule_internal_signal_unregister(SilcSchedule schedule,
					      void *context,
					      SilcUInt32 sig)
{
  /* Nothing to do */
}

void silc_schedule_internal_signals_call(SilcSchedule schedule, void *context)
{
  /* Nothing to do */
}

void silc_schedule_internal_signals_block(SilcSchedule schedule, void *context)
{
  /* Nothing to do */
}

void silc_schedule_internal_signals_unblock(SilcSchedule schedule,
					    void *context)
{
  /* Nothing to do */
}

const SilcScheduleOps schedule_ops =
{
  silc_schedule_internal_init,
  silc_schedule_internal_uninit,
  silc_poll,
  silc_schedule_internal_schedule_fd,
  silc_schedule_internal_wakeup,
  silc_schedule_internal_signal_register,
  silc_schedule_internal_signal_unregister,
  silc_schedule_internal_signals_call,
  silc_schedule_internal_signals_block,
  silc_schedule_internal_signals_unblock,
};
