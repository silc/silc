/*

  silcsymbianscheduler.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include <e32base.h>

/* The SILC Scheduler for Symbian handles only timeout tasks.  Fd tasks are
   not handled by the SILC Scheduler at all but are handled by the Symbian's
   Active Scheduler.  Fd and socket stream callbacks are delivered back
   to caller in their respective class implementatios.

   The SILC Scheduler in Symbian works by creating CActiveSchedulerWait
   when silc_schedule() is called.  This will block the calling thread just
   like silc_schedule is supposed to do.  Under that Active Scheduler we
   run our SilcSymbianScheduler timer which will handle the actual SILC
   Scheduler by calling silc_schedule_one at correct times.  The timeout
   values are selected by the SILC Scheduler itself when silc_schedule_one
   is called.  After that call returns we go back to the Active Scheduler
   to dispatch other active objects and to wait for next timeout.

   Wakeup of the scheduler works by simply cancelling the outstanding timeout
   and issuing a zero timeout to call the silc_schedule_one again.

   If user directly calls silc_schedule_one it behaves same as on other
   platforms. */

class SilcSymbianScheduler;
class SilcSymbianSchedulerWakeup;

typedef struct {
  SilcSymbianScheduler *timer;
  SilcSymbianSchedulerWakeup *wakeup;
} *SilcSymbianInternal;

/* SILC scheduler timer class.  This handles the actual SILC Scheduler
   by calling silc_schedule_one and scheduling the scheduler timeouts. */
class SilcSymbianScheduler : public CTimer {
public:
  /* Constructor */
  SilcSymbianScheduler() : CTimer(CActive::EPriorityStandard)
  {
    CTimer::ConstructL();
    CActiveScheduler::Add(this);
    After(0);
  }

  /* Destructor */
  ~SilcSymbianScheduler()
  {
    Cancel();
  }

  /* Timeout callback */
  virtual void RunL()
  {
    if (!silc_schedule_one(schedule, -1))
      s->AsyncStop();
  }

  CActiveSchedulerWait *s;
  SilcSchedule schedule;
};

/* Scheduler wakeup class */
class SilcSymbianSchedulerWakeup : public CActive {
public:
  /* Constructor */
  SilcSymbianSchedulerWakeup() : CActive(CActive::EPriorityStandard)
  {
    CActiveScheduler::Add(this);
    iStatus = KRequestPending;
    SetActive();
  }

  /* Destructor */
  ~SilcSymbianSchedulerWakeup()
  {
    Cancel();
  }

  /* Wakeup */
  void Wakeup(TThreadId thread_id)
  {
    if (wake_signal)
      return;
    wake_signal = TRUE;

    TRequestStatus *status = &iStatus;
    if (id != thread_id)
      thread.RequestComplete(status, KErrNone);
    else
      User::RequestComplete(status, KErrNone);
  }

  /* Timeout callback */
  virtual void RunL()
  {
    SILC_LOG_DEBUG(("Wakeup scheduler"));

    /* Wakeup scheduler */
    timer->Cancel();
    timer->After(0);
    wake_signal = FALSE;

    iStatus = KRequestPending;
    SetActive();
  }

  virtual void DoCancel()
  {

  }

  RThread thread;
  TThreadId id;
  SilcSymbianScheduler *timer;
  unsigned int wake_signal  : 1;
};

extern "C" {

/* Symbian's silc_schedule call.  We start Active Scheduler here and start
   our SILC Scheduler.  The calling thread will block here. */

void silc_schedule(SilcSchedule schedule)
{
  SilcSymbianInternal internal = (SilcSymbianInternal)schedule->internal;
  CActiveSchedulerWait *s;

  SILC_LOG_DEBUG(("Running scheduler"));

  /* Create Active Scheduler */
  s = new CActiveSchedulerWait;
  SILC_ASSERT(s);

  /* Start SILC Scheduler */
  internal->timer = new SilcSymbianScheduler;
  SILC_ASSERT(internal->timer);
  internal->timer->schedule = schedule;
  internal->timer->s = s;
  internal->wakeup = new SilcSymbianSchedulerWakeup;
  SILC_ASSERT(internal->wakeup);
  internal->wakeup->id = RThread().Id();
  internal->wakeup->thread.Open(internal->wakeup->id);
  internal->wakeup->timer = internal->timer;

  /* Start Active Scheduler */
  s->Start();

  delete internal->wakeup;
  delete internal->timer;
  delete s;
}

int silc_poll(SilcSchedule schedule, void *context)
{
  SilcSymbianInternal internal = (SilcSymbianInternal)context;
  int timeout = -1;
  TTime at_timeout;

  /* When user is using silc_schedule_one we don't have our timer set,
     so just return immediately. */
  if (!internal->timer)
    return 0;

  /* Schedule next timeout */
  if (schedule->has_timeout)
    timeout = ((schedule->timeout.tv_sec * 1000) +
		(schedule->timeout.tv_usec / 1000));

  if (!timeout)
    return 0;

  if (timeout == -1)
    timeout = 0;

  /* Set the timeout value */
  at_timeout.HomeTime();
  while (timeout > 2100 * 1000) {
    at_timeout += (TTimeIntervalMicroSeconds32)(2100 * 1000 * 1000);
    timeout -= (2100 * 1000);
  }
  at_timeout += (TTimeIntervalMicroSeconds32)timeout;

  /* Schedule the timeout */
  internal->timer->At(at_timeout);

  /* Return special "ignore" value.  Causes the scheduler to just break
     the scheduler iteration and return back to its caller. */
  return -2;
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
  SilcSymbianInternal internal;

  internal = (SilcSymbianInternal)silc_calloc(1, sizeof(*internal));
  if (!internal)
    return NULL;

  return internal;
}

void silc_schedule_internal_uninit(SilcSchedule schedule, void *context)
{
  SilcSymbianInternal internal = (SilcSymbianInternal)context;
  silc_free(internal);
}

void silc_schedule_internal_wakeup(SilcSchedule schedule, void *context)
{
#ifdef SILC_THREADS
  SilcSymbianInternal internal = (SilcSymbianInternal)context;
  TThreadId id;

  if (!internal->timer)
    return;

  id = RThread().Id();
  internal->wakeup->Wakeup(id);
#endif /* SILC_THREADS */
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

EXPORT_C const SilcScheduleOps schedule_ops =
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

} /* extern "C" */
