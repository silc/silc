/*

  silcfsm.c

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

#include "silcincludes.h"

SILC_TASK_CALLBACK(silc_fsm_run);
SILC_TASK_CALLBACK(silc_fsm_finish);
SILC_TASK_CALLBACK(silc_fsm_sema_timedout);
SILC_TASK_CALLBACK(silc_fsm_start_real_thread);
static void *silc_fsm_thread(void *context);

/* Allocate FSM */

SilcFSM silc_fsm_alloc(void *fsm_context,
                       SilcFSMDestructor destructor,
                       void *destructor_context,
                       SilcSchedule schedule)
{
  SilcFSM fsm;

  fsm = silc_calloc(1, sizeof(*fsm));
  if (!fsm)
    return NULL;

  if (!silc_fsm_init(fsm, fsm_context, destructor,
		     destructor_context, schedule)) {
    silc_free(fsm);
    return NULL;
  }

  return fsm;
}

/* Initialize FSM */

bool silc_fsm_init(SilcFSM fsm,
		   void *fsm_context,
                   SilcFSMDestructor destructor,
                   void *destructor_context,
                   SilcSchedule schedule)
{
  if (!schedule)
    return FALSE;

  fsm->fsm_context = fsm_context;
  fsm->destructor = destructor;
  fsm->destructor_context = destructor_context;
  fsm->schedule = schedule;
  fsm->thread = FALSE;
  fsm->async_call = FALSE;
  fsm->u.m.threads = 0;
  fsm->u.m.lock = NULL;

  return TRUE;
}

/* Allocate FSM thread.  Internally machine and thread use same context. */

SilcFSMThread silc_fsm_thread_alloc(SilcFSM fsm,
				    void *thread_context,
				    SilcFSMThreadDestructor destructor,
				    void *destructor_context,
				    bool real_thread)
{
  SilcFSMThread thread;

  thread = silc_calloc(1, sizeof(*thread));
  if (!thread)
    return NULL;

  if (!silc_fsm_thread_init(thread, fsm, thread_context, destructor,
			    destructor_context, real_thread)) {
    silc_free(thread);
    return NULL;
  }

  return thread;
}

/* Initialize FSM thread.  Internally machine and thread use same context. */

bool silc_fsm_thread_init(SilcFSMThread thread,
			  SilcFSM fsm,
			  void *thread_context,
			  SilcFSMThreadDestructor destructor,
			  void *destructor_context,
			  bool real_thread)
{
  SILC_LOG_DEBUG(("Initializing new thread %p (%s)",
		  thread, real_thread ? "real" : "FSM"));

#if defined(SILC_DEBUG)
  assert(!fsm->thread);
#endif /* SILC_DEBUG */

  thread->fsm_context = thread_context;
  thread->destructor = (SilcFSMDestructor)destructor;
  thread->destructor_context = destructor_context;
  thread->schedule = fsm->schedule;
  thread->thread = TRUE;
  thread->async_call = FALSE;
  thread->real_thread = real_thread;
  thread->u.t.fsm = fsm;

  /* Add to machine */
  fsm->u.m.threads++;

  /* Allocate lock for the machine if using real threads. */
  if (real_thread && !fsm->u.m.lock)
    if (!silc_mutex_alloc(&fsm->u.m.lock))
      thread->real_thread = FALSE;

  return TRUE;
}

/* FSM is destroyed through scheduler to make sure that all dying
   real system threads will have their finish callbacks scheduled before
   this one (when SILC_FSM_THREAD_WAIT was used). */

SILC_TASK_CALLBACK(silc_fsm_free_final)
{
  SilcFSM f = context;

#if defined(SILC_DEBUG)
  /* Machine must not have active threads */
  if (!f->thread && f->u.m.threads)
    assert(f->u.m.threads == 0);
#endif /* SILC_DEBUG */

  if (!f->thread && f->u.m.lock)
    silc_mutex_free(f->u.m.lock);

  if (f->thread && f->u.t.sema)
    silc_fsm_sema_free(f->u.t.sema);

  silc_free(f);
}

/* Free FSM */

void silc_fsm_free(void *fsm)
{
  SilcFSM f = fsm;
  silc_schedule_task_add_timeout(f->schedule, silc_fsm_free_final, f, 0, 1);
}

/* FSM is uninitialized through scheduler to make sure that all dying
   real system threads will have their finish callbacks scheduled before
   this one (when SILC_FSM_THREAD_WAIT was used). */

SILC_TASK_CALLBACK(silc_fsm_uninit_final)
{
  SilcFSM f = context;

#if defined(SILC_DEBUG)
  /* Machine must not have active threads */
  if (!f->thread && f->u.m.threads)
    assert(f->u.m.threads == 0);
#endif /* SILC_DEBUG */

  if (!f->thread && f->u.m.lock)
    silc_mutex_free(f->u.m.lock);

  if (f->thread && f->u.t.sema)
    silc_fsm_sema_free(f->u.t.sema);
}

/* Uninitializes FSM */

void silc_fsm_uninit(void *fsm)
{
  SilcFSM f = fsm;
  silc_schedule_task_add_timeout(f->schedule, silc_fsm_uninit_final, f, 0, 1);
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

  f->real_thread = FALSE;
  if (f->u.m.lock) {
    silc_mutex_free(f->u.m.lock);
    f->u.m.lock = NULL;
  }

  /* Normal FSM operation */
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

  /* Start real threads through scheduler */
  if (f->thread && f->real_thread) {
    silc_schedule_task_add_timeout(f->schedule, silc_fsm_start_real_thread,
				   f, 0, 1);
    return;
  }

  /* Normal FSM operation */
  silc_schedule_task_add_timeout(f->schedule, silc_fsm_run, f, 0, 1);
}

/* Start FSM in the specified state synchronously */

void silc_fsm_start_sync(void *fsm, SilcFSMStateCallback start_state)
{
  SilcFSM f = fsm;

  SILC_LOG_DEBUG(("Starting %s %p", f->thread ? "thread" : "FSM", fsm));

  f->finished = FALSE;
  f->next_state = start_state;
  f->synchronous = TRUE;

  /* Start real threads through scheduler */
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
  silc_schedule_task_add_timeout(f->schedule, silc_fsm_run, f,
				 seconds, useconds);
}

/* Continue after callback or async operation */

void silc_fsm_continue(void *fsm)
{
  SilcFSM f = fsm;
  silc_schedule_task_add_timeout(f->schedule, silc_fsm_run, f, 0, 1);
}

/* Continue after callback or async operation immediately */

void silc_fsm_continue_sync(void *fsm)
{
  SilcFSM f = fsm;
  silc_fsm_run(f->schedule, silc_schedule_get_context(f->schedule), 0, 0, f);
}

/* Return associated scheduler */

SilcSchedule silc_fsm_get_schedule(void *fsm)
{
  SilcFSM f = fsm;
  return f->schedule;
}

/* Get context */

void *silc_fsm_get_context(void *fsm)
{
  SilcFSM f = fsm;
  return f->fsm_context;
}

/* Set context */

void silc_fsm_set_context(void *fsm, void *fsm_context)
{
  SilcFSM f = fsm;
  f->fsm_context = fsm_context;
}

/* Wait for thread to terminate */

bool silc_fsm_thread_wait(void *fsm, void *thread)
{
  SilcFSM t = thread;
#if defined(SILC_DEBUG)
  assert(t->thread);
#endif /* SILC_DEBUG */
  t->u.t.sema = silc_fsm_sema_alloc(t->u.t.fsm, 0);
  if (!t->u.t.sema)
    return FALSE;
  silc_fsm_sema_wait(t->u.t.sema, fsm);
  return TRUE;
}

/* The machine */

SILC_TASK_CALLBACK(silc_fsm_run)
{
  SilcFSM fsm = context;
  SilcFSMStatus status;

  SILC_LOG_DEBUG(("Running %s %p", fsm->thread ? "thread" : "FSM", fsm));

  /* Run the state */
  status = fsm->next_state(fsm, fsm->fsm_context);

  switch (status) {
  case SILC_FSM_CONTINUE:
    /* Synchronously move to next state */
    SILC_LOG_DEBUG(("State continue %p", fsm));
    silc_fsm_run(schedule, app_context, type, fd, context);
    break;

  case SILC_FSM_WAIT:
    /* The machine is in hold */
    SILC_LOG_DEBUG(("State wait %p", fsm));
    fsm->synchronous = FALSE;
    break;

  case SILC_FSM_FINISH:
    /* Finish the state machine */
    SILC_LOG_DEBUG(("State finish %p", fsm));
#if defined(SILC_DEBUG)
    assert(!fsm->finished);
#endif /* SILC_DEBUG */
    fsm->finished = TRUE;

    /* If we are thread and using real threads, the FSM thread will finish
       in the main thread, not in the created thread. */
    if (fsm->thread && fsm->real_thread) {
      silc_schedule_task_add_timeout(app_context, silc_fsm_finish, fsm, 0, 1);
      silc_schedule_wakeup(app_context);
      silc_schedule_stop(fsm->schedule);
      break;
    }

    /* Normal FSM operation */
    if (fsm->synchronous)
      silc_fsm_finish(fsm->schedule, app_context, 0, 0, fsm);
    else
      silc_schedule_task_add_timeout(fsm->schedule, silc_fsm_finish,
				     fsm, 0, 1);
    break;
  }
}

/* Finishes the FSM.  This is always executed in the main thread, even
   for FSM threads that were run in real threads. */

SILC_TASK_CALLBACK(silc_fsm_finish)
{
  SilcFSM fsm = context;

  SILC_LOG_DEBUG(("%s %p, is finished", fsm->thread ? "Thread" : "FSM", fsm));

  fsm->next_state = NULL;

  if (fsm->thread) {
    /* This is thread, send signal */
    if (fsm->u.t.sema) {
      silc_fsm_sema_post(fsm->u.t.sema);
      silc_fsm_sema_wait(fsm->u.t.sema, fsm->u.t.sema->fsm);
      silc_fsm_sema_free(fsm->u.t.sema);
      fsm->u.t.sema = NULL;
    }

    /* Remove the thread from machine */
    fsm->u.t.fsm->u.m.threads--;

    /* Call the destructor callback only if the underlaying machine is
       still valid. */
    if (fsm->destructor && fsm->u.t.fsm->finished == FALSE)
      fsm->destructor(fsm, fsm->fsm_context, fsm->destructor_context);

  } else {
    /* Call the destructor callback. */
    if (fsm->destructor)
      fsm->destructor(fsm, fsm->fsm_context, fsm->destructor_context);
  }
}

/* Signalled, semaphore */

static void silc_fsm_signal(SilcFSM fsm)
{
  SILC_LOG_DEBUG(("Signalled %s %p", fsm->thread ? "thread" : "FSM", fsm));

  /* Continue */
  silc_fsm_continue(fsm);

  /* Wakeup the destination's scheduler in case the signaller is a
     real thread. */
  silc_schedule_wakeup(fsm->schedule);
}

/* Allocate FSM semaphore */

SilcFSMSema silc_fsm_sema_alloc(SilcFSM fsm, SilcUInt32 value)
{
  SilcFSMSema sema;

  sema = silc_calloc(1, sizeof(*sema));
  if (!sema)
    return NULL;

  silc_fsm_sema_init(sema, fsm, value);

  return sema;
}

/* Initializes FSM semaphore */

void silc_fsm_sema_init(SilcFSMSema sema, SilcFSM fsm, SilcUInt32 value)
{
  SILC_LOG_DEBUG(("Initializing semaphore %p", sema));
#if defined(SILC_DEBUG)
  assert(!fsm->thread);
#endif /* SILC_DEBUG */
  sema->fsm = fsm;
  silc_list_init(sema->waiters, struct SilcFSMObject, next);
  sema->value = value;
}

/* Free semaphore */

void silc_fsm_sema_free(SilcFSMSema sema)
{
#if defined(SILC_DEBUG)
  assert(silc_list_count(sema->waiters) == 0);
#endif /* SILC_DEBUG */
  silc_free(sema);
}

/* Wait until semaphore is non-zero. */

SilcUInt32 silc_fsm_sema_wait(SilcFSMSema sema, void *fsm)
{
  SilcMutex lock = sema->fsm->u.m.lock;

  silc_mutex_lock(lock);

  if (!sema->value) {
#if defined(SILC_DEBUG)
    SilcFSM entry;
    silc_list_start(sema->waiters);
    while ((entry = silc_list_get(sema->waiters)) != SILC_LIST_END)
      assert(entry != fsm);
#endif /* SILC_DEBUG */

    SILC_LOG_DEBUG(("Waiting for semaphore %p", sema));

    /* Add the FSM to waiter list */
    silc_list_add(sema->waiters, fsm);
    silc_mutex_unlock(lock);
    return 0;
  }

  SILC_LOG_DEBUG(("Acquired semaphore %p", sema));

  /* It is possible that this FSM is in the list so remove it */
  silc_list_del(sema->waiters, fsm);
  sema->value--;
  silc_mutex_unlock(lock);
  return 1;
}

/* Wait util semaphore is non-zero, or timeout occurs. */

SilcUInt32 silc_fsm_sema_timedwait(SilcFSMSema sema, void *fsm,
				   SilcUInt32 seconds, SilcUInt32 useconds)
{
  SilcFSM f = fsm;
  SilcUInt32 value;

  if (f->sema_timedout) {
    SILC_LOG_DEBUG(("Semaphore was timedout"));
    f->sema_timedout = FALSE;
    return 1;
  }

  value = silc_fsm_sema_wait(sema, fsm);
  if (!value) {
    silc_schedule_task_add_timeout(f->schedule, silc_fsm_sema_timedout,
				   f, seconds, useconds);
    f->sema = sema;
  }

  return value;
}

/* Semaphore timedout */

SILC_TASK_CALLBACK(silc_fsm_sema_timedout)
{
  SilcFSM fsm = context;
  SilcMutex lock = fsm->sema->fsm->u.m.lock;

  SILC_LOG_DEBUG(("Semaphore %p timedout", fsm->sema));

  /* Remove the waiter from the semaphore */
  silc_mutex_lock(lock);
  silc_list_del(fsm->sema->waiters, fsm);
  silc_mutex_unlock(lock);

  fsm->sema = NULL;
  fsm->sema_timedout = TRUE;

  /* Continue */
  silc_fsm_continue(fsm);
}

/* Increase semaphore */

void silc_fsm_sema_post(SilcFSMSema sema)
{
  SilcFSM fsm;
  SilcMutex lock = sema->fsm->u.m.lock;

  SILC_LOG_DEBUG(("Posting semaphore %p", sema));

  silc_mutex_lock(lock);

  sema->value++;
  silc_list_start(sema->waiters);
  while ((fsm = silc_list_get(sema->waiters)) != SILC_LIST_END) {
    if (fsm->sema) {
      silc_schedule_task_del_by_all(fsm->schedule, 0, silc_fsm_sema_timedout,
				    fsm);
      fsm->sema = NULL;
    }
    silc_fsm_signal(fsm);
  }

  silc_mutex_unlock(lock);
}

/* Real thread */

static void *silc_fsm_thread(void *context)
{
  SilcFSM fsm = context;
  SilcSchedule old = fsm->schedule;

  SILC_LOG_DEBUG(("Starting FSM thread in real thread"));

  /* We allocate new SilcSchedule for the FSM, as the old SilcSchedule
     cannot be used in this thread.  Application may still use it if it
     wants but we use our own. */
  fsm->schedule = silc_schedule_init(0, old);
  if (!fsm->schedule)
    return NULL;

  /* Start the FSM thread */
  if (!silc_schedule_task_add_timeout(fsm->schedule, silc_fsm_run, fsm, 0, 1))
    return NULL;

  /* Run the scheduler */
  silc_schedule(fsm->schedule);

  /* Free resources */
  silc_schedule_uninit(fsm->schedule);

  fsm->schedule = old;

  return NULL;
}
