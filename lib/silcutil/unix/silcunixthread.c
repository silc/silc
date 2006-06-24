/*

  silcunixthread.c

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

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable)
{
#ifdef SILC_THREADS
  pthread_attr_t attr;
  pthread_t thread;
  int ret;

  SILC_LOG_DEBUG(("Creating new thread"));

  if (!start_func)
    return NULL;

  if (pthread_attr_init(&attr)) {
    SILC_LOG_ERROR(("Thread error: %s", strerror(errno)));
    return NULL;
  }

  if (pthread_attr_setdetachstate(&attr,
				  waitable ? PTHREAD_CREATE_JOINABLE :
				  PTHREAD_CREATE_DETACHED)) {
    SILC_LOG_ERROR(("Thread error: %s", strerror(errno)));
    pthread_attr_destroy(&attr);
    return NULL;
  }

  ret = pthread_create(&thread, &attr, (void * (*)(void *))start_func,
		       context);
  if (ret) {
    SILC_LOG_ERROR(("Thread error: %s", strerror(errno)));
    pthread_attr_destroy(&attr);
    return NULL;
  }

  pthread_attr_destroy(&attr);

  SILC_LOG_DEBUG(("Created thread %p", (SilcThread)thread));

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
  pthread_exit(exit_value);
#endif
}

SilcThread silc_thread_self(void)
{
#ifdef SILC_THREADS
  pthread_t self = pthread_self();
  return (SilcThread)self;
#else
  return NULL;
#endif
}

SilcBool silc_thread_wait(SilcThread thread, void **exit_value)
{
#ifdef SILC_THREADS
  SILC_LOG_DEBUG(("Waiting for thread %p", thread));
  if (!pthread_join(*(pthread_t *)thread, exit_value))
    return TRUE;
  return FALSE;
#else
  return FALSE;
#endif
}


/***************************** SILC Mutex API *******************************/

/* SILC Mutex structure */
struct SilcMutexStruct {
#ifdef SILC_THREADS
  pthread_mutex_t mutex;
#else
  void *tmp;
#endif /* SILC_THREADS */
};

SilcBool silc_mutex_alloc(SilcMutex *mutex)
{
#ifdef SILC_THREADS
  *mutex = silc_calloc(1, sizeof(**mutex));
  if (*mutex == NULL)
    return FALSE;
  pthread_mutex_init(&(*mutex)->mutex, NULL);
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS */
}

void silc_mutex_free(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    pthread_mutex_destroy(&mutex->mutex);
    silc_free(mutex);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_lock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    if (pthread_mutex_lock(&mutex->mutex))
      assert(FALSE);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_unlock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    if (pthread_mutex_unlock(&mutex->mutex))
      assert(FALSE);
  }
#endif /* SILC_THREADS */
}


/**************************** SILC CondVar API ******************************/

/* SILC Conditional Variable context */
struct SilcCondVarStruct {
#ifdef SILC_THREADS
  pthread_cond_t cond;
#else
  void *tmp;
#endif /* SILC_THREADS*/
};

SilcBool silc_condvar_alloc(SilcCondVar *cond)
{
#ifdef SILC_THREADS
  *cond = silc_calloc(1, sizeof(**cond));
  if (*cond == NULL)
    return FALSE;
  pthread_cond_init(&(*cond)->cond, NULL);
  return TRUE;
#else
  return FALSE;
#endif /* SILC_THREADS*/
}

void silc_condvar_free(SilcCondVar cond)
{
#ifdef SILC_THREADS
  pthread_cond_destroy(&cond->cond);
  silc_free(cond);
#endif /* SILC_THREADS*/
}

void silc_condvar_signal(SilcCondVar cond)
{
#ifdef SILC_THREADS
  pthread_cond_signal(&cond->cond);
#endif /* SILC_THREADS*/
}

void silc_condvar_broadcast(SilcCondVar cond)
{
#ifdef SILC_THREADS
  pthread_cond_broadcast(&cond->cond);
#endif /* SILC_THREADS*/
}

void silc_condvar_wait(SilcCondVar cond, SilcMutex mutex)
{
#ifdef SILC_THREADS
  pthread_cond_wait(&cond->cond, &mutex->mutex);
#endif /* SILC_THREADS*/
}

SilcBool silc_condvar_timedwait(SilcCondVar cond, SilcMutex mutex,
				int timeout)
{
#ifdef SILC_THREADS
  struct timespec t;
  if (timeout) {
    t.tv_sec = timeout / 1000;
    t.tv_nsec = (timeout % 1000) * 1000;
    return pthread_cond_timedwait(&cond->cond, &mutex->mutex, &t) == 0;
  }

  return pthread_cond_wait(&cond->cond, &mutex->mutex) == 0;
#endif /* SILC_THREADS*/
}
