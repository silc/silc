/*

  silcfsm_i.h

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

#ifndef SILCFSM_I_H
#define SILCFSM_I_H

#ifndef SILCFSM_H
#error "Do not include this header directly"
#endif

/* Semaphore structure, holds list of FSM machines that are waiting
   for this semaphore.  The SilcFSM has *next; pointer that is used
   with SilcList. */
struct SilcFSMSemaObject {
  SilcFSM fsm;			        /* Machine */
  SilcList waiters;			/* List of SilcFSM pointers */
  SilcUInt32 value;			/* Current semaphore value */
};

/* FSM and FSM thread context */
struct SilcFSMObject {
  struct SilcFSMObject *next;
  void *fsm_context;		        /* Caller's context */
  SilcSchedule schedule;		/* Scheduler */
  SilcFSMSema sema;			/* Valid if waiting sema timeout */
  SilcFSMStateCallback next_state;	/* Next state in machine */
  SilcFSMDestructor destructor;		/* Destructor */
  void *destructor_context;
  union {
    /* Machine */
    struct {
      SilcUInt32 threads;		/* Number of threads */
      SilcMutex lock;		        /* Lock, valid if using real threads */
    } m;

    /* Thread */
    struct {
      struct SilcFSMObject *fsm;	/* Machine */
      SilcFSMSema sema;	                /* Semaphore for waiting termination */
    } t;
  } u;
  unsigned int thread           : 1;	/* Set if this is thread */
  unsigned int real_thread      : 1;    /* Set if to use real threads */
  unsigned int async_call       : 1;    /* Set if called real async call */
  unsigned int finished         : 1;    /* Set if SILC_FSM_FINISH returned */
  unsigned int sema_timedout    : 1;    /* Set if waiting sema timedout */
  unsigned int synchronous      : 1;    /* Set if silc_fsm_start_sync called */
};

/* Used internally by the SILC_FSM_CALL macros to detect whether async
   call is really async or not. */
static inline
bool silc_fsm_set_call(struct SilcFSMObject *fsm, bool async_call)
{
  bool old = fsm->async_call;
  fsm->async_call = async_call;
  return old;
}

/* Continues after callback */
void silc_fsm_continue(void *fsm);
void silc_fsm_continue_sync(void *fsm);

/* Wait for thread to terminate */
bool silc_fsm_thread_wait(void *fsm, void *thread);

/* Semaphores */
SilcUInt32 silc_fsm_sema_wait(SilcFSMSema sema, void *fsm);
SilcUInt32 silc_fsm_sema_timedwait(SilcFSMSema sema, void *fsm,
				   SilcUInt32 seconds, SilcUInt32 useconds);
void silc_fsm_sema_post(SilcFSMSema sema);

#endif /* SILCFSM_I_H */
