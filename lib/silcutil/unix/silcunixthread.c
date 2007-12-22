/*

  silcunixthread.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

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

typedef struct {
  SilcThreadStart start_func;
  void *context;
} *SilcThreadStartContext;

static void *silc_thread_start(void *context)
{
  SilcThreadStartContext c = context;
  SilcThreadStart start_func = c->start_func;
  void *start_context = c->context;

  silc_free(c);

  silc_thread_tls_init();

  return start_func(start_context);
}

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      SilcBool waitable)
{
#ifdef SILC_THREADS
  SilcThreadStartContext c;
  pthread_attr_t attr;
  pthread_t thread;
  int ret;

  SILC_LOG_DEBUG(("Creating new thread"));

  if (!start_func)
    return NULL;

  c = silc_calloc(1, sizeof(*c));
  if (!c)
    return NULL;
  c->start_func = start_func;
  c->context = context;

  if (pthread_attr_init(&attr)) {
    silc_set_errno_posix(errno);
    SILC_LOG_ERROR(("Thread error: %s", silc_errno_string(silc_errno)));
    silc_free(c);
    return NULL;
  }

  if (pthread_attr_setdetachstate(&attr,
				  waitable ? PTHREAD_CREATE_JOINABLE :
				  PTHREAD_CREATE_DETACHED)) {
    silc_set_errno_posix(errno);
    SILC_LOG_ERROR(("Thread error: %s", silc_errno_string(silc_errno)));
    pthread_attr_destroy(&attr);
    silc_free(c);
    return NULL;
  }

  ret = pthread_create(&thread, &attr, silc_thread_start, c);
  if (ret) {
    silc_set_errno_posix(errno);
    SILC_LOG_ERROR(("Thread error: %s", silc_errno_string(silc_errno)));
    pthread_attr_destroy(&attr);
    silc_free(c);
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

void silc_thread_yield(void)
{
#ifdef SILC_THREADS
#ifdef HAVE_SCHED_YIELD
  sched_yield();
#endif /* HAVE_SCHED_YIELD */
#endif /* SILC_THREADS */
}

/***************************** SILC Mutex API *******************************/

/* SILC Mutex structure */
struct SilcMutexStruct {
#ifdef SILC_THREADS
  pthread_mutex_t mutex;
#endif /* SILC_THREADS */
  unsigned int locked : 1;
};

SilcBool silc_mutex_alloc(SilcMutex *mutex)
{
#ifdef SILC_THREADS
  *mutex = silc_calloc(1, sizeof(**mutex));
  if (*mutex == NULL)
    return FALSE;
  if (pthread_mutex_init(&(*mutex)->mutex, NULL)) {
    silc_set_errno_posix(errno);
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
    pthread_mutex_destroy(&mutex->mutex);
    silc_free(mutex);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_lock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    SILC_VERIFY(pthread_mutex_lock(&mutex->mutex) == 0);
    mutex->locked = TRUE;
  }
#endif /* SILC_THREADS */
}

void silc_mutex_unlock(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex) {
    mutex->locked = FALSE;
    SILC_VERIFY(pthread_mutex_unlock(&mutex->mutex) == 0);
  }
#endif /* SILC_THREADS */
}

void silc_mutex_assert_locked(SilcMutex mutex)
{
#ifdef SILC_THREADS
  if (mutex)
    SILC_VERIFY(mutex->locked);
#endif /* SILC_THREADS */
}

/***************************** SILC Rwlock API ******************************/

/* SILC read/write lock structure */
struct SilcRwLockStruct {
#ifdef SILC_THREADS
  pthread_rwlock_t rwlock;
#else
  void *tmp;
#endif /* SILC_THREADS */
};

SilcBool silc_rwlock_alloc(SilcRwLock *rwlock)
{
#ifdef SILC_THREADS
  *rwlock = silc_calloc(1, sizeof(**rwlock));
  if (*rwlock == NULL)
    return FALSE;
  if (pthread_rwlock_init(&(*rwlock)->rwlock, NULL)) {
    silc_set_errno_posix(errno);
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
    pthread_rwlock_destroy(&rwlock->rwlock);
    silc_free(rwlock);
  }
#endif /* SILC_THREADS */
}

void silc_rwlock_rdlock(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock)
    pthread_rwlock_rdlock(&rwlock->rwlock);
#endif /* SILC_THREADS */
}

void silc_rwlock_wrlock(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock)
    SILC_VERIFY(pthread_rwlock_wrlock(&rwlock->rwlock) == 0);
#endif /* SILC_THREADS */
}

void silc_rwlock_unlock(SilcRwLock rwlock)
{
#ifdef SILC_THREADS
  if (rwlock)
    SILC_VERIFY(pthread_rwlock_unlock(&rwlock->rwlock) == 0);
#endif /* SILC_THREADS */
}

/****************************** SILC Cond API *******************************/

/* SILC Conditional Variable context */
struct SilcCondStruct {
#ifdef SILC_THREADS
  pthread_cond_t cond;
#else
  void *tmp;
#endif /* SILC_THREADS*/
};

SilcBool silc_cond_alloc(SilcCond *cond)
{
#ifdef SILC_THREADS
  *cond = silc_calloc(1, sizeof(**cond));
  if (*cond == NULL)
    return FALSE;
  if (pthread_cond_init(&(*cond)->cond, NULL)) {
    silc_set_errno_posix(errno);
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
  pthread_cond_destroy(&cond->cond);
  silc_free(cond);
#endif /* SILC_THREADS*/
}

void silc_cond_signal(SilcCond cond)
{
#ifdef SILC_THREADS
  pthread_cond_signal(&cond->cond);
#endif /* SILC_THREADS*/
}

void silc_cond_broadcast(SilcCond cond)
{
#ifdef SILC_THREADS
  pthread_cond_broadcast(&cond->cond);
#endif /* SILC_THREADS*/
}

void silc_cond_wait(SilcCond cond, SilcMutex mutex)
{
#ifdef SILC_THREADS
  pthread_cond_wait(&cond->cond, &mutex->mutex);
#endif /* SILC_THREADS*/
}

SilcBool silc_cond_timedwait(SilcCond cond, SilcMutex mutex,
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
#else
  return FALSE;
#endif /* SILC_THREADS*/
}

/************************** Thread-local Storage ****************************/

#if (defined(SILC_THREADS) && defined(HAVE_PTHREAD_KEY_CREATE) && \
     defined(HAVE_PTHREAD_ONCE))

static pthread_key_t key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

static void silc_thread_tls_destructor(void *context)
{
  silc_free(context);
}

static void silc_thread_tls_alloc(void)
{
  if (pthread_key_create(&key, silc_thread_tls_destructor))
    SILC_LOG_ERROR(("Error creating Thread-local storage"));
}

SilcTls silc_thread_tls_init(void)
{
  SilcTls tls;

  pthread_once(&key_once, silc_thread_tls_alloc);

  if (silc_thread_get_tls())
    return silc_thread_get_tls();

  /* Allocate Tls for the thread */
  tls = silc_calloc(1, sizeof(*tls));
  if (!tls) {
    SILC_LOG_ERROR(("Error allocating Thread-local storage"));
    return NULL;
  }

  pthread_setspecific(key, tls);
  return tls;
}

SilcTls silc_thread_get_tls(void)
{
  return pthread_getspecific(key);
}

#else

SilcTlsStruct tls;
SilcTls tls_ptr = NULL;

SilcTls silc_thread_tls_init(void)
{
  if (silc_thread_get_tls())
    return silc_thread_get_tls();

  tls_ptr = &tls;
  memset(tls_ptr, 0, sizeof(*tls_ptr));
  return tls_ptr;
}

SilcTls silc_thread_get_tls(void)
{
  return tls_ptr;
}

#endif
