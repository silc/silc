/*

  silcfsm.c

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

#include "silc.h"

SILC_TASK_CALLBACK(silc_fsm_run);
SILC_TASK_CALLBACK(silc_fsm_finish_fsm);
SILC_TASK_CALLBACK(silc_fsm_event_timedout);
SILC_TASK_CALLBACK(silc_fsm_start_real_thread);
static void silc_fsm_thread_termination_signal(SilcFSMEvent event);
static void silc_fsm_event_ref(SilcFSMEvent event);
static void silc_fsm_event_unref(SilcFSMEvent event);
void *silc_fsm_thread(void *context);

/* Allocate FSM */

SilcFSM silc_fsm_alloc(void *fsm_context,
                       SilcFSMDestructor destructor,
                       void *destructor_context,
                       SilcSchedule schedule)
{
  SilcFSM fsm;

  fsm = silc_calloc(1, sizeof(*fsm));
  if (silc_unlikely(!fsm))
    return NULL;

  if (silc_unlikely(!silc_fsm_init(fsm, fsm_context, destructor,
				   destructor_context, schedule))) {
    silc_free(fsm);
    return NULL;
  }

  return fsm;
}

/* Initialize FSM */

SilcBool silc_fsm_init(SilcFSM fsm,
		       void *fsm_context,
		       SilcFSMDestructor destructor,
		       void *destructor_context,
		       SilcSchedule schedule)
{
  if (!schedule)
    return FALSE;

  fsm->fsm_context = fsm_context;
  fsm->state_context = NULL;
  fsm->destructor = destructor;
  fsm->destructor_context = destructor_context;
  fsm->schedule = schedule;
  fsm->thread = FALSE;
  fsm->async_call = FALSE;
  fsm->started = FALSE;
  fsm->u.m.lock = NULL;
  silc_atomic_init32(&fsm->u.m.threads, 0);

  return TRUE;
}

/* Allocate FSM thread.  Internally machine and thread use same context. */

SilcFSMThread silc_fsm_thread_alloc(SilcFSM fsm,
				    void *thread_context,
				    SilcFSMThreadDestructor destructor,
				    void *destructor_context,
				    SilcBool real_thread)
{
  SilcFSMThread thread;

  thread = silc_calloc(1, sizeof(*thread));
  if (silc_unlikely(!thread))
    return NULL;

  silc_fsm_thread_init(thread, fsm, thread_context, destructor,
		       destructor_context, real_thread);
  return thread;
}

/* Initialize FSM thread.  Internally machine and thread use same context. */

void silc_fsm_thread_init(SilcFSMThread thread,
			  SilcFSM fsm,
			  void *thread_context,
			  SilcFSMThreadDestructor destructor,
			  void *destructor_context,
			  SilcBool real_thread)
{
  SILC_LOG_DEBUG(("Initializing new thread %p (%s)",
		  thread, real_thread ? "real" : "FSM"));

  SILC_ASSERT(!fsm->thread);

  thread->fsm_context = thread_context;
  thread->state_context = NULL;
  thread->destructor = (SilcFSMDestructor)destructor;
  thread->destructor_context = destructor_context;
  thread->schedule = fsm->schedule;
  thread->thread = TRUE;
  thread->async_call = FALSE;
  thread->started = FALSE;
  thread->real_thread = real_thread;
  thread->u.t.fsm = fsm;

  /* Add to machine */
  silc_atomic_add_int32(&fsm->u.m.threads, 1);

  /* Allocate lock for the machine if using real threads. */
  if (real_thread && !fsm->u.m.lock)
    if (!silc_mutex_alloc(&fsm->u.m.lock))
      thread->real_thread = FALSE;
}

/* FSM is destroyed through scheduler to make sure that all dying
   real system threads will have their finish callbacks scheduled before
   this one (when SILC_FSM_THREAD_WAIT was used). */

SILC_TASK_CALLBACK(silc_fsm_free_final)
{
  SilcFSM f = context;

#if defined(SILC_DEBUG)
  /* We must be finished */
  SILC_ASSERT(f->finished);

  /* Machine must not have active threads */
  if (!f->thread && silc_atomic_get_int32(&f->u.m.threads))
    SILC_ASSERT(silc_atomic_get_int32(&f->u.m.threads) == 0);
#endif /* SILC_DEBUG */

  if (!f->thread && f->u.m.lock)
    silc_mutex_free(f->u.m.lock);

  if (f->thread && f->u.t.event)
    silc_fsm_event_free(f->u.t.event);

  if (!f->thread)
    silc_atomic_uninit32(&f->u.m.threads);

  silc_free(f);
}

/* Free FSM */

void silc_fsm_free(void *fsm)
{
  SilcFSM f = fsm;
  if (!f->thread)
    if (silc_schedule_task_add_timeout(f->schedule, silc_fsm_free_final,
				       f, 0, 0))
      return;
  silc_fsm_free_final(f->schedule, silc_schedule_get_context(f->schedule),
		      0, 0, f);
}

/* Task to start real thread. We start threads through scheduler, not
   directly in silc_fsm_start. */

SILC_TASK_CALLBACK(silc_fsm_start_real_thread)
{
  SilcFSM f = context;

#ifdef SILC_THREADS
  if (silc_thread_create(silc_fsm_thread, f, FALSE))
    return;
#endif /* SILC_THREADS */

  SILC_LOG_DEBUG(("Could not create real thread, using normal FSM thread"));

  /* Normal FSM operation */
  f->real_thread = FALSE;
  silc_fsm_continue_sync(f);
}

/* Start FSM in the specified state */

void silc_fsm_start(void *fsm, SilcFSMStateCallback start_state)
{
  SilcFSM f = fsm;

  SILC_LOG_DEBUG(("Starting %s %p", f->thread ? "thread" : "FSM", fsm));

  f->finished = FALSE;
  f->next_state = start_state;
  f->synchronous = FALSE;
  f->started = TRUE;

  /* Start real thread through scheduler */
  if (f->thread && f->real_thread) {
    if (!silc_schedule_task_add_timeout(f->schedule,
					silc_fsm_start_real_thread,
					f, 0, 0))
      silc_fsm_start_real_thread(f->schedule,
				 silc_schedule_get_context(f->schedule),
				 0, 0, f);
    silc_schedule_wakeup(f->schedule);
    return;
  }

  /* Normal FSM operation */
  if (!silc_schedule_task_add_timeout(f->schedule, silc_fsm_run, f, 0, 0))
    silc_fsm_run(f->schedule, silc_schedule_get_context(f->schedule), 0, 0, f);

  /* Wakeup scheduler in case we are starting this thread from another
     real thread. */
  if (f->thread)
    silc_schedule_wakeup(f->schedule);
}

/* Start FSM in the specified state synchronously */

void silc_fsm_start_sync(void *fsm, SilcFSMStateCallback start_state)
{
  SilcFSM f = fsm;

  SILC_LOG_DEBUG(("Starting %s %p", f->thread ? "thread" : "FSM", fsm));

  f->finished = FALSE;
  f->next_state = start_state;
  f->synchronous = TRUE;
  f->started = TRUE;

  /* Start real thread directly */
  if (f->thread && f->real_thread) {
    silc_fsm_start_real_thread(f->schedule,
			       silc_schedule_get_context(f->schedule),
			       0, 0, f);
    return;
  }

  /* Normal FSM operation */
  silc_fsm_run(f->schedule, silc_schedule_get_context(f->schedule), 0, 0, f);
}

/* Set next FSM state */

void silc_fsm_next(void *fsm, SilcFSMStateCallback next_state)
{
  SilcFSM f = fsm;
  f->next_state = next_state;
}

/* Continue after timeout */

void silc_fsm_next_later(void *fsm, SilcFSMStateCallback next_state,
			 SilcUInt32 seconds, SilcUInt32 useconds)
{
  SilcFSM f = fsm;

  f->next_state = next_state;
  if (!seconds && !useconds)
    return;

  silc_schedule_task_add_timeout(f->schedule, silc_fsm_run, f,
				 seconds, useconds);
  f->next_later = TRUE;

  /* Wakeup up the scheduler just in case this was called from another
     thread. */
  silc_schedule_wakeup(f->schedule);
}

/* Continue after callback or async operation */

void silc_fsm_continue(void *fsm)
{
  SilcFSM f = fsm;

  if (f->next_later) {
    /* Cancel next_later timeout */
    silc_schedule_task_del_by_all(f->schedule, 0, silc_fsm_run, f);
    f->next_later = FALSE;
  }

  if (!silc_schedule_task_add_timeout(f->schedule, silc_fsm_run, f, 0, 0))
    silc_fsm_run(f->schedule, silc_schedule_get_context(f->schedule), 0, 0, f);

  /* Wakeup up the scheduler just in case this was called from another
     thread. */
  silc_schedule_wakeup(f->schedule);
}

/* Continue after callback or async operation immediately */

void silc_fsm_continue_sync(void *fsm)
{
  SilcFSM f = fsm;
  if (f->next_later) {
    silc_schedule_task_del_by_all(f->schedule, 0, silc_fsm_run, f);
    f->next_later = FALSE;
  }
  silc_fsm_run(f->schedule, silc_schedule_get_context(f->schedule), 0, 0, f);
}

/* Finish FSM */

void silc_fsm_finish(void *fsm)
{
  SilcFSM f = fsm;

  SILC_ASSERT(!f->finished);

  f->started = FALSE;
  f->finished = TRUE;

  silc_schedule_task_del_by_all(f->schedule, 0, silc_fsm_run, f);
  f->next_later = FALSE;

  /* If we are thread and using real threads, the FSM thread will finish
     after the real thread has finished, in the main thread. */
  if (f->thread && f->real_thread) {
    /* Stop the real thread's scheduler to finish the thread */
    silc_schedule_stop(f->schedule);
    silc_schedule_wakeup(f->schedule);
    return;
  }

  /* Normal FSM operation */
  if (!f->synchronous)
    if (silc_schedule_task_add_timeout(f->schedule, silc_fsm_finish_fsm,
				       f, 0, 0))
      return;

  silc_fsm_finish_fsm(f->schedule, silc_schedule_get_context(f->schedule),
		      0, 0, fsm);
}

/* Return associated scheduler */

SilcSchedule silc_fsm_get_schedule(void *fsm)
{
  SilcFSM f = fsm;
  return f->schedule;
}

/* Return thread's machine */

SilcFSM silc_fsm_get_machine(SilcFSMThread thread)
{
  SILC_ASSERT(thread->thread);
  return (SilcFSM)thread->u.t.fsm;
}

/* Returns TRUE if FSM is started */

SilcBool silc_fsm_is_started(void *fsm)
{
  SilcFSM f = fsm;
  return f->started;
}

/* Set context */

void silc_fsm_set_context(void *fsm, void *fsm_context)
{
  SilcFSM f = fsm;
  f->fsm_context = fsm_context;
}

/* Get context */

void *silc_fsm_get_context(void *fsm)
{
  SilcFSM f = fsm;
  return f->fsm_context;
}

/* Set state context */

void silc_fsm_set_state_context(void *fsm, void *state_context)
{
  SilcFSM f = fsm;
  f->state_context = state_context;
}

/* Get state context */

void *silc_fsm_get_state_context(void *fsm)
{
  SilcFSM f = fsm;
  return f->state_context;
}

/* Wait for thread to terminate */

SilcBool silc_fsm_thread_wait(void *fsm, void *thread)
{
  SilcFSM t = thread;

  SILC_ASSERT(t->thread);

  t->u.t.event = silc_fsm_event_alloc(t->u.t.fsm);
  if (!t->u.t.event)
    return FALSE;

  SILC_LOG_DEBUG(("Waiting for thread %p to terminate", thread));
  silc_fsm_event_wait(t->u.t.event, fsm);
  return TRUE;
}

/* The machine */

SILC_TASK_CALLBACK(silc_fsm_run)
{
  SilcFSM fsm = context;
  SilcFSMStatus status;

  SILC_LOG_DEBUG(("Running %s %p", fsm->thread ? "thread" : "FSM", fsm));

  /* Run the states */
  do
    status = fsm->next_state(fsm, fsm->fsm_context, fsm->state_context);
  while (status == SILC_FSM_ST_CONTINUE);

  switch (status) {
  case SILC_FSM_ST_YIELD:
    /* Continue through scheduler */
    silc_fsm_continue(fsm);
    break;

  case SILC_FSM_ST_WAIT:
    /* The machine is in hold */
    SILC_LOG_DEBUG(("State wait %p", fsm));
    fsm->synchronous = FALSE;
    break;

  case SILC_FSM_ST_FINISH:
    /* Finish the state machine */
    SILC_LOG_DEBUG(("State finish %p", fsm));
    silc_fsm_finish(fsm);
    break;

  default:
    break;
  }
}

/* Finishes the FSM.  This is always executed in the main thread, even
   for FSM threads that were run in real threads. */

SILC_TASK_CALLBACK(silc_fsm_finish_fsm)
{
  SilcFSM fsm = context;

  SILC_LOG_DEBUG(("%s %p, is finished", fsm->thread ? "Thread" : "FSM", fsm));

  fsm->next_state = NULL;

  if (fsm->thread) {
    /* This is thread, send signal */
    if (fsm->u.t.event) {
      silc_fsm_thread_termination_signal(fsm->u.t.event);
      silc_fsm_event_free(fsm->u.t.event);
      fsm->u.t.event = NULL;
    }

    /* Remove the thread from machine */
    silc_atomic_sub_int32(&fsm->u.t.fsm->u.m.threads, 1);

    /* Call the destructor callback only if the underlaying machine is
       still valid. */
    if (fsm->destructor && fsm->u.t.fsm->finished == FALSE)
      fsm->destructor(fsm, fsm->fsm_context, fsm->destructor_context);

  } else {
    /* Machine must not have active threads */
    assert(silc_atomic_get_int32(&fsm->u.m.threads) == 0);

    if (fsm->u.m.lock) {
      silc_mutex_free(fsm->u.m.lock);
      fsm->u.m.lock = NULL;
    }

    /* Call the destructor callback. */
    if (fsm->destructor)
      fsm->destructor(fsm, fsm->fsm_context, fsm->destructor_context);
  }
}

/* Allocate FSM event */

SilcFSMEvent silc_fsm_event_alloc(SilcFSM fsm)
{
  SilcFSMEvent event;

  event = silc_calloc(1, sizeof(*event));
  if (silc_unlikely(!event))
    return NULL;

  silc_fsm_event_init(event, fsm);
  event->allocated = TRUE;

  return event;
}

/* Initializes FSM event */

void silc_fsm_event_init(SilcFSMEvent event, SilcFSM fsm)
{
  SILC_LOG_DEBUG(("Initializing event %p", event));
  SILC_ASSERT(!fsm->thread);
  memset(event, 0, sizeof(*event));
  event->fsm = fsm;
  event->refcnt = 0;
  silc_list_init(event->waiters, struct SilcFSMObject, next);
}

/* Free event */

void silc_fsm_event_free(SilcFSMEvent event)
{
  if (event->refcnt > 0)
    return;
  if (silc_list_count(event->waiters) > 0)
    return;
  silc_free(event);
}

/* Reference event */

static void silc_fsm_event_ref(SilcFSMEvent event)
{
  event->refcnt++;
}

/* Unreference event */

static void silc_fsm_event_unref(SilcFSMEvent event)
{
  event->refcnt--;
  if (event->refcnt == 0 && event->allocated)
    silc_fsm_event_free(event);
}

/* Wait until event is non-zero. */

SilcUInt32 silc_fsm_event_wait(SilcFSMEvent event, void *fsm)
{
  SilcMutex lock = event->fsm->u.m.lock;

  silc_mutex_lock(lock);

  if (!event->value) {
#if defined(SILC_DEBUG)
    SilcFSM entry;
    silc_list_start(event->waiters);
    while ((entry = silc_list_get(event->waiters)))
      SILC_ASSERT(entry != fsm);
#endif /* SILC_DEBUG */

    SILC_LOG_DEBUG(("Waiting for event %p", event));

    /* Add the FSM to waiter list */
    silc_list_add(event->waiters, fsm);
    silc_mutex_unlock(lock);
    return 0;
  }

  SILC_LOG_DEBUG(("Received event %p", event));

  /* Remove from waiting */
  silc_list_del(event->waiters, fsm);

  /* Decrease the counter only after all waiters have acquired the signal. */
  if (!silc_list_count(event->waiters))
    event->value--;

  silc_mutex_unlock(lock);
  return 1;
}

/* Wait util event is non-zero, or timeout occurs. */

SilcUInt32 silc_fsm_event_timedwait(SilcFSMEvent event, void *fsm,
				    SilcUInt32 seconds, SilcUInt32 useconds,
				    SilcBool *ret_to)
{
  SilcMutex lock = event->fsm->u.m.lock;
  SilcFSM f = fsm;
  SilcUInt32 value;

  silc_mutex_lock(lock);

  if (f->event_timedout) {
    SILC_LOG_DEBUG(("Event waiting timedout"));
    f->event_timedout = FALSE;
    if (ret_to)
      *ret_to = TRUE;
    silc_mutex_unlock(lock);
    return 1;
  }

  silc_mutex_unlock(lock);

  value = silc_fsm_event_wait(event, fsm);
  if (!value) {
    silc_schedule_task_add_timeout(f->schedule, silc_fsm_event_timedout,
				   f, seconds, useconds);
    f->event = event;
  }

  if (ret_to)
    *ret_to = FALSE;

  return value;
}

/* Event timedout */

SILC_TASK_CALLBACK(silc_fsm_event_timedout)
{
  SilcFSM fsm = context;
  SilcMutex lock = fsm->event->fsm->u.m.lock;

  SILC_LOG_DEBUG(("Event %p timedout", fsm->event));

  /* Remove the waiter from the event waiters list */
  silc_mutex_lock(lock);
  silc_list_del(fsm->event->waiters, fsm);

  /* Continue */
  if (fsm->event) {
    silc_fsm_continue(fsm);
    fsm->event_timedout = TRUE;
    fsm->event = NULL;
  }

  silc_mutex_unlock(lock);
}

/* Signalled, event */

SILC_TASK_CALLBACK(silc_fsm_signal)
{
  SilcFSMEventSignal p = context;
  SilcMutex lock = p->event->fsm->u.m.lock;
  SilcFSM fsm;

  /* We have to check for couple of things before delivering the signal. */

  /* If the event value has went to zero while we've been waiting this
     callback, the event has been been signalled already.  It can happen
     when using real threads because the FSM may not be in waiting state
     when the event is signalled. */
  silc_mutex_lock(lock);
  if (!p->event->value) {
    silc_mutex_unlock(lock);
    silc_fsm_event_unref(p->event);
    silc_free(p);
    return;
  }

  /* If the waiter is not waiting anymore, don't deliver the signal.  It
     can happen if there were multiple signallers and the waiter went away
     after the first signal. */
  silc_list_start(p->event->waiters);
  while ((fsm = silc_list_get(p->event->waiters)))
    if (fsm == p->fsm)
      break;
  if (!fsm) {
    silc_mutex_unlock(lock);
    silc_fsm_event_unref(p->event);
    silc_free(p);
    return;
  }
  silc_mutex_unlock(lock);

  SILC_LOG_DEBUG(("Signalled %s %p", p->fsm->thread ? "thread" : "FSM",
		  p->fsm));

  /* Signal */
  silc_fsm_continue_sync(p->fsm);

  silc_fsm_event_unref(p->event);
  silc_free(p);
}

/* Signal event */

void silc_fsm_event_signal(SilcFSMEvent event)
{
  SilcFSM fsm;
  SilcFSMEventSignal p;
  SilcMutex lock = event->fsm->u.m.lock;

  SILC_LOG_DEBUG(("Signal event %p", event));

  silc_mutex_lock(lock);

  event->value++;
  silc_list_start(event->waiters);
  while ((fsm = silc_list_get(event->waiters))) {
    if (fsm->event) {
      silc_schedule_task_del_by_all(fsm->schedule, 0, silc_fsm_event_timedout,
				    fsm);
      fsm->event = NULL;
    }

    p = silc_calloc(1, sizeof(*p));
    if (silc_unlikely(!p))
      continue;
    p->event = event;
    p->fsm = fsm;
    silc_fsm_event_ref(event);

    /* Signal through scheduler.  Wake up destination scheduler in case
       caller is a real thread. */
    silc_schedule_task_add_timeout(fsm->schedule, silc_fsm_signal, p, 0, 0);
    silc_schedule_wakeup(fsm->schedule);
  }

  silc_mutex_unlock(lock);
}

/* Post thread termination event.  Special function used only to
   signal thread termination when SILC_FSM_THREAD_WAIT was used. */

static void silc_fsm_thread_termination_signal(SilcFSMEvent event)
{
  SilcFSM fsm;
  SilcMutex lock = event->fsm->u.m.lock;

  SILC_LOG_DEBUG(("Post thread terminate event %p", event));

  silc_mutex_lock(lock);

  silc_list_start(event->waiters);
  while ((fsm = silc_list_get(event->waiters))) {
    /* Signal on thread termination.  Wake up destination scheduler in case
       caller is a real thread. */
    silc_list_del(event->waiters, fsm);
    silc_fsm_continue(fsm);
    silc_schedule_wakeup(fsm->schedule);
  }

  silc_mutex_unlock(lock);
}

/* Real thread */

void *silc_fsm_thread(void *context)
{
  SilcFSM fsm = context;
  SilcSchedule old = fsm->schedule;

  SILC_LOG_DEBUG(("Starting FSM thread in real thread"));

  /* We allocate new SilcSchedule for the FSM, as the old SilcSchedule
     cannot be used in this thread.  Application may still use it if it
     wants but we use our own. */
  fsm->schedule = silc_schedule_init(0, old, silc_schedule_get_stack(old));
  if (silc_unlikely(!fsm->schedule)) {
    fsm->schedule = old;
    return NULL;
  }

  /* Start the FSM thread */
  if (silc_unlikely(!silc_schedule_task_add_timeout(fsm->schedule,
						    silc_fsm_run, fsm, 0, 0))) {
    silc_schedule_uninit(fsm->schedule);
    fsm->schedule = old;
    return NULL;
  }

  /* Run the scheduler */
  silc_schedule(fsm->schedule);

  /* Free resources */
  silc_schedule_uninit(fsm->schedule);

  fsm->schedule = old;

  /* Finish the FSM thread in the main thread */
  SILC_ASSERT(fsm->finished);
  silc_schedule_task_add_timeout(fsm->schedule, silc_fsm_finish_fsm,
				 fsm, 0, 0);
  silc_schedule_wakeup(fsm->schedule);

  return NULL;
}
