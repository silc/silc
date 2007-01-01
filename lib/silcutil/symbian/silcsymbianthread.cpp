/*

  silcsymbianthread.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include <e32std.h>

/**************************** SILC Thread API *******************************/

/* Thread structure for Symbian */
typedef struct {
#ifdef SILC_THREADS
  RThread *thread;
  SilcThreadStart start_func;
  void *context;
  bool waitable;
#else
  void *tmp;
#endif
} *SilcSymbianThread;

/* The actual thread function */

TInt silc_thread_epoc_start(TAny *context)
{
#ifdef SILC_THREADS
  SilcSymbianThread thread = (SilcSymbianThread)context;
  void *ret;

  ret = thread->start_func(thread->context);
  silc_thread_exit(ret);

#endif
  return 0;
}

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      bool waitable)
{
#ifdef SILC_THREADS
  SilcSymbianThread thread;
  TInt ret;
  TBuf<32> name;

  SILC_LOG_DEBUG(("Creating new thread"));

  thread = (SilcSymbianThread)silc_calloc(1, sizeof(*thread));
  if (!thread)
    return NULL;
  thread->start_func = start_func;
  thread->context = context;
  thread->waitable = waitable;

  /* Create the thread */
  /* XXX Unique name should be given for the thread */
  thread->thread = new RThread();
  if (!thread->thread) {
    silc_free(thread);
    return NULL;
  }

  name = (TText *)"silc" + time(NULL);
  ret = thread->thread->Create(name, silc_thread_epoc_start,
			       8192, 4096, 1024 * 1024, (TAny *)thread);
  if (ret != KErrNone) {
    SILC_LOG_ERROR(("Could not create new thread"));
    delete thread->thread;
    silc_free(thread);
    return NULL;
  }
  thread->thread->Resume();

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
  /* XXX */
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  /* XXX */
  return NULL;
#else
  return NULL;
#endif
}

SilcBool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  /* XXX */
  return TRUE;
#else
  return FALSE;
#endif
}

/***************************** SILC Mutex API *******************************/

/* SILC Mutex structure */
struct SilcMutexStruct {
#ifdef SILC_THREADS
  RMutex *mutex;
#endif /* SILC_THREADS */
  unsigned int locked : 1;
};

SilcBool silc_mutex_alloc(SilcMutex *mutex)
{
#ifdef SILC_THREADS
  *mutex = (SilcMutex)silc_calloc(1, sizeof(**mutex));
  if (*mutex == NULL)
    return FALSE;
  (*mutex)->mutex = new RMutex();
  if (!(*mutex)->mutex) {
    silc_free(*mutex);
    return FALSE;
  }
  if ((*mutex)->mutex->CreateLocal() != KErrNone) {
    delete (*mutex)->mutex;
    silc_free(*mutex);
    return FALSE;
  }
  (*mutex)->locked = FALSE;
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS */
}

void silc_mutex_free(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    mutex->mutex->Close();
    delete mutex->mutex;
    silc_free(mutex);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_lock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    mutex->mutex->Wait();
    mutex->locked = TRUE;
  }
#endif /* SILC_THREADS */
}

void silc_mutex_unlock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    mutex->mutex->Signal();
    mutex->locked = FALSE;
  }
#endif /* SILC_THREADS */
}

void silc_mutex_assert_locked(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex)
    SILC_ASSERT(mutex->locked);
#endif /* SILC_THREADS */
}


/****************************** SILC Cond API *******************************/

/* SILC Conditional Variable context */
struct SilcCondStruct {
#ifdef SILC_THREADS
  RCondVar *cond;
#else
  void *tmp;
#endif /* SILC_THREADS*/
};

SilcBool silc_cond_alloc(SilcCond *cond)
{
#ifdef SILC_THREADS
  *cond = (SilcCond)silc_calloc(1, sizeof(**cond));
  if (*cond == NULL)
    return FALSE;
  (*cond)->cond = new RCondVar();
  if (!(*cond)->cond) {
    silc_free(*cond);
    return FALSE;
  }
  if ((*cond)->cond->CreateLocal() != KErrNone) {
    delete (*cond)->cond;
    silc_free(*cond);
    return FALSE;
  }
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS*/
}

void silc_cond_free(SilcCond cond)
{
#ifdef SILC_THREADS
  cond->cond->Close();
  delete cond->cond;
  silc_free(cond);
#endif /* SILC_THREADS*/
}

void silc_cond_signal(SilcCond cond)
{
#ifdef SILC_THREADS
  cond->cond->Signal();
#endif /* SILC_THREADS*/
}

void silc_cond_broadcast(SilcCond cond)
{
#ifdef SILC_THREADS
  cond->cond->Broadcast();
#endif /* SILC_THREADS*/
}

void silc_cond_wait(SilcCond cond, SilcMutex mutex)
{
#ifdef SILC_THREADS
  cond->cond->Wait(*mutex->mutex);
#endif /* SILC_THREADS*/
}

SilcBool silc_cond_timedwait(SilcCond cond, SilcMutex mutex,
			     int timeout)
{
#ifdef SILC_THREADS
  if (timeout)
    return (cond->cond->TimedWait(*mutex->mutex, (TInt)timeout * 1000) ==
	    KErrNone);
  return (cond->cond->Wait(*mutex->mutex) == KErrNone);
#else
  return FALSE;
#endif /* SILC_THREADS*/
}
