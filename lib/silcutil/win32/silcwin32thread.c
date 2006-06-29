/*

  silcwin32thread.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"

/**************************** SILC Thread API *******************************/

#ifdef SILC_THREADS

/* Thread structure for WIN32 */
typedef struct {
  HANDLE thread;
  SilcThreadStart start_func;
  void *context;
  SilcBool waitable;
} *SilcWin32Thread;

static DWORD silc_thread_tls;

/* Actual routine that is called by WIN32 when the thread is created.
   We will call the start_func from here. When this returns the thread
   is destroyed. */

unsigned __stdcall silc_thread_win32_start(void *context)
{
  SilcWin32Thread thread = (SilcWin32Thread)context;

  TlsSetValue(silc_thread_tls, context);
  silc_thread_exit(thread->start_func(thread->context));

  return 0;
}
#endif

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable)
{
#ifdef SILC_THREADS
  SilcWin32Thread thread;
  unsigned id;

  SILC_LOG_DEBUG(("Creating new thread"));

  thread = silc_calloc(1, sizeof(*thread));
  thread->start_func = start_func;
  thread->context = context;
  thread->waitable = waitable;
  thread->thread =
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)silc_thread_win32_start,
		 (void *)thread, 0, &id);

  if (!thread->thread) {
    SILC_LOG_ERROR(("Could not create new thread"));
    silc_free(thread);
    return NULL;
  }

  return (SilcThread)thread;
#else
  /* Call thread callback immediately */
  (*start_func)(context);
  return NULL;
#endif
}

void silc_thread_exit(void *exit_value)
{
#ifdef SILC_THREADS
  SilcWin32Thread thread = TlsGetValue(silc_thread_tls);

  if (thread) {
    /* If the thread is waitable the memory is freed only in silc_thread_wait
       by another thread. If not waitable, free it now. */
    if (!thread->waitable) {
      TerminateThread(thread->thread, 0);
      silc_free(thread);
    }

    TlsSetValue(silc_thread_tls, NULL);
  }
  ExitThread(0);
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  SilcWin32Thread self = TlsGetValue(silc_thread_tls);

  if (!self) {
    /* This should only happen for the main thread! */
    HANDLE handle = GetCurrentThread ();
    HANDLE process = GetCurrentProcess ();
    self = silc_calloc(1, sizeof(*self));
    DuplicateHandle(process, handle, process,
		    &self->thread, 0, FALSE,
		    DUPLICATE_SAME_ACCESS);
    TlsSetValue(silc_thread_tls, self);
  }

  return (SilcThread)self;
	#else
  return NULL;
#endif
}

SilcBool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  SilcWin32Thread self = (SilcWin32Thread)thread;

  SILC_LOG_DEBUG(("Waiting for thread %p", self));

  if (!self->waitable)
    return FALSE;

  /* The thread is waitable thus we will free all memory after the
     WaitForSingleObject returns, the thread is destroyed after that. */
  if (WaitForSingleObject(self->thread, 2500) == WAIT_TIMEOUT)
    TerminateThread(self->thread, 0);

  silc_free(self);
  if (exit_value)
    *exit_value = NULL;

  return TRUE;
#else
  return FALSE;
#endif
}


/***************************** SILC Mutex API *******************************/

/* SILC Mutex structure */
struct SilcMutexStruct {
#ifdef SILC_THREADS
  CRITICAL_SECTION mutex;
  BOOL locked;
#else
  void *tmp;
#endif /* SILC_THREADS */
};

SilcBool silc_mutex_alloc(SilcMutex *mutex)
{
#ifdef SILC_THREADS
  *mutex = silc_calloc(1, sizeof(**mutex));
  if (!(*mutex))
    return FALSE;
  InitializeCriticalSection(&((*mutex)->mutex));
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS */
}

void silc_mutex_free(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    DeleteCriticalSection(&mutex->mutex);
    silc_free(mutex);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_lock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    EnterCriticalSection(&mutex->mutex);
    assert(mutex->locked == FALSE);
    mutex->locked = TRUE;
  }
#endif /* SILC_THREADS */
}

void silc_mutex_unlock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    assert(mutex->locked == TRUE);
    mutex->locked = FALSE;
    LeaveCriticalSection(&mutex->mutex);
  }
#endif /* SILC_THREADS */
}


/**************************** SILC Cond API ******************************/

/* SILC Conditional Variable context */
struct SilcCondStruct {
#ifdef SILC_THREADS
  HANDLE event;
#endif /* SILC_THREADS*/
  unsigned int waiters : 23;
  unsigned int signal  : 1;
};

SilcBool silc_cond_alloc(SilcCond *cond)
{
#ifdef SILC_THREADS
  *cond = silc_calloc(1, sizeof(**cond));
  if (*cond == NULL)
    return FALSE;
  (*cond)->event = CreateEvent(NULL, TRUE, FALSE, NULL);
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS*/
}

void silc_cond_free(SilcCond cond)
{
#ifdef SILC_THREADS
  CloseHandle(cond->event);
  silc_free(cond);
#endif /* SILC_THREADS*/
}

void silc_cond_signal(SilcCond cond)
{
#ifdef SILC_THREADS
  cond->signal = TRUE;
  SetEvent(cond->event);
#endif /* SILC_THREADS*/
}

void silc_cond_broadcast(SilcCond cond)
{
#ifdef SILC_THREADS
  cond->signal = TRUE;
  SetEvent(cond->event);
#endif /* SILC_THREADS*/
}

void silc_cond_wait(SilcCond cond, SilcMutex mutex)
{
#ifdef SILC_THREADS
  silc_cond_timedwait(cond, mutex, NULL);
#endif /* SILC_THREADS*/
}

SilcBool silc_cond_timedwait(SilcCond cond, SilcMutex mutex,
			     int timeout)
{
#ifdef SILC_THREADS
  DWORD ret, t = INFINITE;

  if (timeout)
    t = timeout;

  while (TRUE) {
    cond->waiters++;
    silc_mutex_unlock(mutex);

    ret = WaitForSingleObject(cond->event, t);

    silc_mutex_lock(mutex);
    cond->waiters--;

    if (ret != WAIT_OBJECT_0)
      return FALSE;

    if (cond->signal) {
      cond->signal = FALSE;
      ResetEvent(cond->event);
      break;
    }
  }
#endif /* SILC_THREADS*/
}
