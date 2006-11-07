/*

  silcfsm_i.h

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
  unsigned int value     : 21;		/* Current semaphore value */
  unsigned int refcnt    : 10;		/* Reference counter */
  unsigned int allocated : 1;		/* Set if allocated */
};

/* FSM and FSM thread context */
struct SilcFSMObject {
  struct SilcFSMObject *next;
  void *fsm_context;		        /* Caller's context */
  SilcSchedule schedule;		/* Scheduler */
  SilcFSMSema sema;			/* Valid if waiting sema timeout */
  SilcFSMStateCallback next_state;	/* Next state in machine */
  void *state_context;		        /* Extra state specific context */
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
  unsigned int next_later       : 1;    /* Set if silc_fsm_next_later called */
};

/* Semaphore post context */
typedef struct {
  SilcFSMSema sema;		        /* Semaphore */
  SilcFSM fsm;				/* Signalled FSM */
} *SilcFSMSemaPost;

/* Used internally by the SILC_FSM_CALL macros to detect whether async
   call is really async or not. */
static inline
SilcBool silc_fsm_set_call(struct SilcFSMObject *fsm, SilcBool async_call)
{
  SilcBool old = fsm->async_call;
  fsm->async_call = async_call;
  return old;
}

/* Wait for thread to terminate */
SilcBool silc_fsm_thread_wait(void *fsm, void *thread);

/* Semaphores */
SilcUInt32 silc_fsm_sema_wait(SilcFSMSema sema, void *fsm);
SilcUInt32 silc_fsm_sema_timedwait(SilcFSMSema sema, void *fsm,
				   SilcUInt32 seconds, SilcUInt32 useconds,
				   SilcBool *ret_to);
void silc_fsm_sema_post(SilcFSMSema sema);

#endif /* SILCFSM_I_H */
