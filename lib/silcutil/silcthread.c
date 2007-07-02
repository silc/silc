/*

  silcthread.c

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

/************************** Types and definitions ***************************/

/* Thread pool thread context */
typedef struct SilcThreadPoolThreadStruct {
  struct SilcThreadPoolThreadStruct *next;
  struct SilcThreadPoolThreadStruct *next2;
  SilcThreadPool tp;		    /* The thread pool */
  SilcSchedule schedule;	    /* Scheduler, may be NULL */
  SilcThreadPoolFunc run;	    /* The function to run in a thread */
  SilcThreadPoolFunc completion;    /* Completion function */
  void *run_context;
  void *completion_context;
  unsigned int stop        : 1;	    /* Set to stop the thread */
} *SilcThreadPoolThread;

/* Completion context */
typedef struct SilcThreadPoolCompletionStruct {
  SilcSchedule schedule;	    /* Scheduler, may be NULL */
  SilcThreadPoolFunc completion;    /* Completion function */
  void *completion_context;
} *SilcThreadPoolCompletion;

/* Thread pool context */
struct SilcThreadPoolStruct {
  SilcStack stack;		    /* Stack for memory allocation */
  SilcMutex lock;		    /* Pool lock */
  SilcCond pool_signal;	            /* Condition variable for signalling */
  SilcList threads;		    /* Threads in the pool */
  SilcList free_threads;	    /* Threads freelist */
  SilcList queue;		    /* Queue for waiting calls */
  SilcUInt16 min_threads;	    /* Minimum threads in the pool */
  SilcUInt16 max_threads;	    /* Maximum threads in the pool */
  SilcUInt16 refcnt;		    /* Reference counter */
  unsigned int destroy       : 1;   /* Set when pool is to be destroyed */
};

/************************ Static utility functions **************************/

/* Reference thread pool.  Must be called locked. */

static void silc_thread_pool_ref(SilcThreadPool tp)
{
  tp->refcnt++;
  SILC_LOG_DEBUG(("Thread pool %p, refcnt %d -> %d", tp, tp->refcnt - 1,
		  tp->refcnt));
}

/* Unreference thread pool.  Must be called locked.  Releases the lock. */

static void silc_thread_pool_unref(SilcThreadPool tp)
{
  tp->refcnt--;
  SILC_LOG_DEBUG(("Thread pool %p refcnt %d -> %d", tp, tp->refcnt + 1,
		  tp->refcnt));
  if (!tp->refcnt) {
    silc_mutex_unlock(tp->lock);
    silc_mutex_free(tp->lock);
    silc_cond_free(tp->pool_signal);
    silc_sfree(tp->stack, tp);
    return;
  }
  silc_mutex_unlock(tp->lock);
}

/* Thread completion callback */

SILC_TASK_CALLBACK(silc_thread_pool_run_completion)
{
  SilcThreadPoolCompletion c = context;
  c->completion(c->schedule, c->completion_context);
  silc_free(c);
}

/* The thread executor.  Each thread in the pool is run here.  They wait
   here for something to do which is given to them by silc_thread_pool_run. */

static void *silc_thread_pool_run_thread(void *context)
{
  SilcThreadPoolThread t = context, q;
  SilcThreadPool tp = t->tp;
  SilcMutex lock = tp->lock;
  SilcCond pool_signal = tp->pool_signal;

  silc_mutex_lock(lock);

  while (1) {
    /* Wait here for code to execute */
    while (!t->run && !t->stop)
      silc_cond_wait(pool_signal, lock);

    if (t->stop) {
      /* Stop the thread.  Remove from threads list and free memory. */
      SILC_LOG_DEBUG(("Stop thread %p", t));
      silc_list_del(tp->threads, t);
      silc_sfree(tp->stack, t);

      /* If we are last thread, signal the waiting destructor. */
      if (silc_list_count(tp->threads) == 0)
	silc_cond_broadcast(pool_signal);

      /* Release pool reference.  Releases lock also. */
      silc_thread_pool_unref(tp);
      break;
    }
    silc_mutex_unlock(lock);

    /* Execute code */
    SILC_LOG_DEBUG(("Execute call %p, context %p, thread %p", t->run,
		    t->run_context, t));
    t->run(t->schedule, t->run_context);

    /* If scheduler is NULL, call completion directly from here.  Otherwise
       it is called through the scheduler in the thread where the scheduler
       is running. */
    if (t->completion) {
      if (t->schedule) {
	SilcThreadPoolCompletion c = silc_calloc(1, sizeof(*c));
	if (c) {
	  SILC_LOG_DEBUG(("Run completion through scheduler %p", t->schedule));
	  c->schedule = t->schedule;
	  c->completion = t->completion;
	  c->completion_context = t->completion_context;
	  silc_schedule_task_add_timeout(c->schedule,
					 silc_thread_pool_run_completion, c,
					 0, 0);
	  silc_schedule_wakeup(c->schedule);
	} else {
	  t->completion(NULL, t->completion_context);
	}
      } else {
	SILC_LOG_DEBUG(("Run completion directly"));
	t->completion(NULL, t->completion_context);
      }
    }

    silc_mutex_lock(lock);

    /* Check if there are calls in queue */
    if (silc_list_count(tp->queue) > 0) {
      silc_list_start(tp->queue);
      q = silc_list_get(tp->queue);

      SILC_LOG_DEBUG(("Execute call from queue"));

      /* Execute this call now */
      t->run = q->run;
      t->run_context = q->run_context;
      t->completion = q->completion;
      t->completion_context = q->completion_context;
      t->schedule = q->schedule;

      silc_list_del(tp->queue, q);
      silc_sfree(tp->stack, q);
      continue;
    }

    /* The thread is now free for use again. */
    t->run = NULL;
    t->completion = NULL;
    t->schedule = NULL;
    silc_list_add(tp->free_threads, t);
  }

  return NULL;
}

/* Creates new thread to thread pool */

static SilcThreadPoolThread silc_thread_pool_new_thread(SilcThreadPool tp)
{
  SilcThreadPoolThread t;

  t = silc_scalloc(tp->stack, 1, sizeof(*t));
  if (!t)
    return NULL;
  t->tp = tp;
  silc_list_add(tp->threads, t);
  silc_list_add(tp->free_threads, t);
  silc_thread_pool_ref(tp);

  SILC_LOG_DEBUG(("Start thread %p", t));

  /* Start the thread */
  silc_thread_create(silc_thread_pool_run_thread, t, FALSE);

  return t;
}

/**************************** Thread Pool API *******************************/

/* Allocate thread pool */

SilcThreadPool silc_thread_pool_alloc(SilcStack stack,
				      SilcUInt32 min_threads,
				      SilcUInt32 max_threads,
				      SilcBool start_min_threads)
{
  SilcThreadPool tp;
  int i;

  if (max_threads < min_threads)
    return NULL;

  tp = silc_scalloc(stack, 1, sizeof(*tp));
  if (!tp)
    return NULL;

  SILC_LOG_DEBUG(("Starting thread pool %p, min threads %d, max threads %d",
		  tp, min_threads, max_threads));

  tp->stack = stack;
  tp->min_threads = min_threads;
  tp->max_threads = max_threads;
  tp->refcnt++;

  if (!silc_mutex_alloc(&tp->lock)) {
    silc_sfree(stack, tp);
    return NULL;
  }

  if (!silc_cond_alloc(&tp->pool_signal)) {
    silc_mutex_free(tp->lock);
    silc_sfree(stack, tp);
    return NULL;
  }

  silc_list_init(tp->threads, struct SilcThreadPoolThreadStruct, next);
  silc_list_init(tp->free_threads, struct SilcThreadPoolThreadStruct, next2);
  silc_list_init(tp->queue, struct SilcThreadPoolThreadStruct, next);

  for (i = 0; i < tp->min_threads && start_min_threads; i++)
    silc_thread_pool_new_thread(tp);

  return tp;
}

/* Free thread pool */

void silc_thread_pool_free(SilcThreadPool tp, SilcBool wait_unfinished)
{
  SilcThreadPoolThread t;

  SILC_LOG_DEBUG(("Free thread pool %p", tp));

  silc_mutex_lock(tp->lock);
  tp->destroy = TRUE;

  /* Stop threads */
  silc_list_start(tp->threads);
  while ((t = silc_list_get(tp->threads)))
    t->stop = TRUE;
  silc_cond_broadcast(tp->pool_signal);

  if (wait_unfinished) {
    SILC_LOG_DEBUG(("Wait threads to finish"));
    while (silc_list_count(tp->threads))
      silc_cond_wait(tp->pool_signal, tp->lock);
  }

  /* Free calls from queue */
  silc_list_start(tp->queue);
  while ((t = silc_list_get(tp->queue)))
    silc_sfree(tp->stack, t);
  silc_list_init(tp->queue, struct SilcThreadPoolThreadStruct, next);

  /* Release reference.  Releases lock also. */
  silc_thread_pool_unref(tp);
}

/* Execute code in a thread in the pool */

SilcBool silc_thread_pool_run(SilcThreadPool tp,
			      SilcBool queuable,
			      SilcSchedule schedule,
			      SilcThreadPoolFunc run,
			      void *run_context,
			      SilcThreadPoolFunc completion,
			      void *completion_context)
{
  SilcThreadPoolThread t;

  silc_mutex_lock(tp->lock);

  if (tp->destroy) {
    silc_mutex_unlock(tp->lock);
    return FALSE;
  }

  /* Get free thread */
  silc_list_start(tp->free_threads);
  t = silc_list_get(tp->free_threads);
  if (!t) {
    if (silc_list_count(tp->threads) + 1 > tp->max_threads) {
      /* Maximum threads reached */
      if (!queuable) {
	silc_mutex_unlock(tp->lock);
	return FALSE;
      }

      SILC_LOG_DEBUG(("Queue call %p, context %p", run, run_context));

      /* User wants to queue this call until thread becomes free */
      t = silc_scalloc(tp->stack, 1, sizeof(*t));
      if (!t) {
	silc_mutex_unlock(tp->lock);
	return FALSE;
      }

      t->run = run;
      t->run_context = run_context;
      t->completion = completion;
      t->completion_context = completion_context;
      t->schedule = schedule;

      silc_list_add(tp->queue, t);
      silc_mutex_unlock(tp->lock);
      return TRUE;
    } else {
      /* Create new thread */
      t = silc_thread_pool_new_thread(tp);
      if (!t) {
	silc_mutex_unlock(tp->lock);
	return FALSE;
      }
    }
  }

  SILC_LOG_DEBUG(("Run call %p, context %p, thread %p", run, run_context, t));

  /* Mark this call to be executed in this thread */
  t->run = run;
  t->run_context = run_context;
  t->completion = completion;
  t->completion_context = completion_context;
  t->schedule = schedule;
  silc_list_del(tp->free_threads, t);

  /* Signal threads */
  silc_cond_broadcast(tp->pool_signal);

  silc_mutex_unlock(tp->lock);
  return TRUE;
}

/* Set maximum threads in the pool */

void silc_thread_pool_set_max_threads(SilcThreadPool tp,
				      SilcUInt32 max_threads)
{
  SILC_LOG_DEBUG(("Set thread pool %p max threads to %d", tp, max_threads));

  silc_mutex_lock(tp->lock);
  tp->max_threads = max_threads;
  silc_mutex_unlock(tp->lock);
}

/* Get maximum threads in the pool */

SilcUInt32 silc_thread_pool_num_max_threads(SilcThreadPool tp)
{
  SilcUInt32 max_threads;

  silc_mutex_lock(tp->lock);
  max_threads = tp->max_threads;
  silc_mutex_unlock(tp->lock);

  return max_threads;
}

/* Get numnber of free threads in the pool */

SilcUInt32 silc_thread_pool_num_free_threads(SilcThreadPool tp)
{
  SilcUInt32 free_threads;

  silc_mutex_lock(tp->lock);
  free_threads = silc_list_count(tp->free_threads);
  silc_mutex_unlock(tp->lock);

  return free_threads;
}

/* Purge pool */

void silc_thread_pool_purge(SilcThreadPool tp)
{
  SilcThreadPoolThread t;
  int i;

  silc_mutex_lock(tp->lock);

  if (silc_list_count(tp->free_threads) <= tp->min_threads) {
    SILC_LOG_DEBUG(("No threads to purge"));
    silc_mutex_unlock(tp->lock);
    return;
  }

  i = silc_list_count(tp->free_threads) - tp->min_threads;

  SILC_LOG_DEBUG(("Purge %d threads", i));

  silc_list_start(tp->threads);
  while ((t = silc_list_get(tp->threads))) {
    if (t->run)
      continue;

    t->stop = TRUE;
    silc_list_del(tp->free_threads, t);

    i--;
    if (!i)
      break;
  }

  /* Signal threads to stop */
  silc_cond_broadcast(tp->pool_signal);

  silc_mutex_unlock(tp->lock);
}
