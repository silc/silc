/*

  silcsymbianthread.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2007 Pekka Riikonen

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

extern "C" {

/* Thread structure for Symbian */
typedef struct {
#ifdef SILC_THREADS
  SilcThreadStart start_func;
  void *context;
  SilcBool waitable;
#else
  void *tmp;
#endif
} *SilcSymbianThread;

/* The actual thread function */

static TInt silc_thread_start(TAny *context)
{
#ifdef SILC_THREADS
  SilcSymbianThread tc = (SilcSymbianThread)context;
  SilcThreadStart start_func = tc->start_func;
  void *user_context = tc->context;
  SilcBool waitable = tc->waitable;

  silc_free(tc);

  /* Call the thread function */
  if (waitable)
    silc_thread_exit(start_func(user_context));
  else
    start_func(user_context);

#endif
  return KErrNone;
}

/* Executed new thread */

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable)
{
#ifdef SILC_THREADS
  SilcSymbianThread tc;
  RThread *thread;
  TInt ret;
  TBuf<32> name;

  SILC_LOG_DEBUG(("Creating new thread"));

  tc = (SilcSymbianThread)silc_calloc(1, sizeof(*thread));
  if (!tc)
    return NULL;
  tc->start_func = start_func;
  tc->context = context;
  tc->waitable = waitable;

  /* Allocate thread */
  thread = new RThread();
  if (!thread) {
    silc_free(tc);
    return NULL;
  }

  /* Create the thread */
  name = (TText *)silc_time_string(0);
  ret = thread->Create(name, silc_thread_start, 8192, 4096, 1024 * 1024,
		       (TAny *)tc);
  if (ret != KErrNone) {
    SILC_LOG_ERROR(("Could not create new thread"));
    delete thread;
    silc_free(tc);
    return NULL;
  }

  /* Start the thread */
  thread->Resume();

  /* Close our instance to the thread */
  thread->Close();

  return (SilcThread)thread;
#else
  /* Call thread callback immediately */
  (*start_func)(context);
  return NULL;
#endif
}

/* Exits current thread */

void silc_thread_exit(void *exit_value)
{
#ifdef SILC_THREADS
  RThread().Kill((TInt)exit_value);
#endif
}

/* Returns current thread context */

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  RThread thread = RThread();
  return (SilcThread)&thread;
#else
  return NULL;
#endif
}

/* Blocks calling thread to wait for `thread' to finish. */

SilcBool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  TRequestStatus req;
  RThread *t = (RThread *)thread;
  t->Logon(req);
  User::WaitForAnyRequest();
  return TRUE;
#else
  return FALSE;
#endif
}

/* Yield processor */

void silc_thread_yield(void)
{
#ifdef SILC_THREADS
  User::After(1);
#endif /* SILC_THREADS */
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

/***************************** SILC Rwlock API *****************************/

/* SILC read/write lock structure */
struct SilcRwLockStruct {
#ifdef SILC_THREADS
  SilcMutex mutex;
  SilcCond cond;
#endif /* SILC_THREADS */
  unsigned int readers : 31;
  unsigned int locked  : 1;
};

SilcBool silc_rwlock_alloc(SilcRwLock *rwlock)
{
#ifdef SILC_THREADS
  *rwlock = (SilcRwLock)silc_calloc(1, sizeof(**rwlock));
  if (!(*rwlock))
    return FALSE;
  if (!silc_mutex_alloc(&(*rwlock)->mutex)) {
    silc_free(*rwlock);
    return FALSE;
  }
  if (!silc_cond_alloc(&(*rwlock)->cond)) {
    silc_mutex_free((*rwlock)->mutex);
    silc_free(*rwlock);
    return FALSE;
  }
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS */
}

void silc_rwlock_free(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock) {
    silc_mutex_free(rwlock->mutex);
    silc_cond_free(rwlock->cond);
    silc_free(rwlock);
  }
#endif /* SILC_THREADS */
}

void silc_rwlock_rdlock(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock) {
    silc_mutex_lock(rwlock->mutex);
    rwlock->readers++;
    silc_mutex_unlock(rwlock->mutex);
  }
#endif /* SILC_THREADS */
}

void silc_rwlock_wrlock(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock) {
    silc_mutex_lock(rwlock->mutex);
    while (rwlock->readers > 0)
      silc_cond_wait(rwlock->cond, rwlock->mutex);
    rwlock->locked = TRUE;
  }
#endif /* SILC_THREADS */
}

void silc_rwlock_unlock(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock) {
    if (rwlock->locked) {
      /* Unlock writer */
      rwlock->locked = FALSE;
      silc_mutex_unlock(rwlock->mutex);
      return;
    }

    /* Unlock reader */
    silc_mutex_lock(rwlock->mutex);
    rwlock->readers--;
    silc_cond_broadcast(rwlock->cond);
    silc_mutex_unlock(rwlock->mutex);
  }
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

} /* extern "C" */