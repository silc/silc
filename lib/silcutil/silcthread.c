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

/* Explanation of the thread pool execution.

   When new call is added to thread pool by calling silc_thread_pool_run
   it is assigned to a first free thread from the free list.  If no threads
   are available we take one from the threads list and assign the call to
   its queue.  The threads list always takes different thread finally wrapping
   from the beginning.  This way each thread will get a chance to execute
   queued calls.

   The thread function silc_thread_pool_run_thread executes each call.  After
   executing the current call that has been assigned to it, it will check
   if there are any queued calls in its queue, and it will execute all calls
   from the queue.  If there aren't any calls in the queue, it will attempt
   to steal a call from some other thread and execute it.

   The queue list is always consumed in last-in-first-out order.  The most
   recently added call gets priority.  With full utilization this helps to
   avoid CPU cache misses.  Since the queues are thread specific with full
   utilization each thread should always be doing work for the most recent
   (and thus most important) calls. */

/************************** Types and definitions ***************************/

/* Thread pool thread context.  Each thread contains the most current call
   to be executed, and a list of queued calls. */
typedef struct SilcThreadPoolThreadStruct {
  struct SilcThreadPoolThreadStruct *next;
  struct SilcThreadPoolThreadStruct *next2;
  SilcThreadPool tp;		    /* The thread pool */
  SilcCond thread_signal;           /* Condition variable for signalling */
  SilcMutex lock;		    /* Thread lock */
  SilcList queue;		    /* Queue for waiting calls */
  SilcList free_queue;		    /* Queue freelist */
  SilcSchedule schedule;	    /* The current Scheduler, may be NULL */
  SilcThreadPoolFunc run;	    /* The current call to run in a thread */
  SilcTaskCallback completion;	    /* The current Completion function */
  void *run_context;
  void *completion_context;
  unsigned int stop        : 1;	    /* Set to stop the thread */
} *SilcThreadPoolThread;

/* Thread pool context */
struct SilcThreadPoolStruct {
  SilcStack stack;		    /* Stack for memory allocation */
  SilcCond pool_signal;	            /* Condition variable for signalling */
  SilcMutex lock;		    /* Pool lock */
  SilcList threads;		    /* Threads in the pool */
  SilcList free_threads;	    /* Threads freelist */
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
    SilcStack stack = tp->stack;
    silc_mutex_unlock(tp->lock);
    silc_mutex_free(tp->lock);
    silc_cond_free(tp->pool_signal);
    silc_sfree(stack, tp);
    silc_stack_free(stack);
    return;
  }
  silc_mutex_unlock(tp->lock);
}

/* The thread executor.  Each thread in the pool is run here.  They wait
   here for something to do which is given to them by silc_thread_pool_run. */

static void *silc_thread_pool_run_thread(void *context)
{
  SilcThreadPoolThread t = context, o, q;
  SilcThreadPool tp = t->tp;
  SilcMutex lock = t->lock;
  SilcCond thread_signal = t->thread_signal;

  silc_mutex_lock(lock);

  while (1) {
    /* Wait here for code to execute */
    while (!t->run && !t->stop)
      silc_cond_wait(thread_signal, lock);

    if (t->stop)
      goto stop;

    /* Execute code */
    silc_mutex_unlock(lock);
  execute:
    SILC_LOG_DEBUG(("Execute call %p, context %p, thread %p", t->run,
		    t->run_context, t));
    t->run(t->schedule, t->run_context);

    /* If scheduler is NULL, call completion directly from here.  Otherwise
       it is called through the scheduler in the thread where the scheduler
       is running. */
    if (t->completion) {
      if (t->schedule) {
	SILC_LOG_DEBUG(("Run completion through scheduler %p", t->schedule));
	if (!silc_schedule_task_add_timeout(t->schedule, t->completion,
					    t->completion_context, 0, 0)) {
	  SILC_LOG_DEBUG(("Run completion directly"));
	  t->completion(NULL, NULL, 0, 0, t->completion_context);
	}
	silc_schedule_wakeup(t->schedule);
      } else {
	SILC_LOG_DEBUG(("Run completion directly"));
	t->completion(NULL, NULL, 0, 0, t->completion_context);
      }
    }

    silc_mutex_lock(lock);
    if (t->stop)
      goto stop;

    /* Check if there are calls in queue.  Takes the most recently added
       call since new ones are added at the start of the list. */
    if (silc_list_count(t->queue) > 0) {
    execute_queue:
      silc_list_start(t->queue);
      q = silc_list_get(t->queue);

      SILC_LOG_DEBUG(("Execute call from queue"));

      /* Execute this call now */
      t->run = q->run;
      t->run_context = q->run_context;
      t->completion = q->completion;
      t->completion_context = q->completion_context;
      t->schedule = q->schedule;

      silc_list_del(t->queue, q);
      silc_list_add(t->free_queue, q);
      silc_mutex_unlock(lock);
      goto execute;
    }

    silc_mutex_unlock(lock);
    silc_mutex_lock(tp->lock);

    /* Nothing to do.  Attempt to steal call from some other thread. */
    o = silc_list_get(tp->threads);
    if (!o) {
      /* List wraps around */
      silc_list_start(tp->threads);
      o = silc_list_get(tp->threads);
    }

    /* Check that the other thread is valid and has something to execute. */
    silc_mutex_lock(o->lock);
    if (o == t || o->stop || silc_list_count(o->queue) == 0) {
      silc_mutex_unlock(o->lock);
      o = NULL;
    }

    if (o) {
      silc_mutex_unlock(tp->lock);
      silc_list_start(o->queue);
      q = silc_list_get(o->queue);

      SILC_LOG_DEBUG(("Execute call from queue from thread %p", o));

      /* Execute this call now */
      t->run = q->run;
      t->run_context = q->run_context;
      t->completion = q->completion;
      t->completion_context = q->completion_context;
      t->schedule = q->schedule;

      silc_list_del(o->queue, q);
      silc_list_add(o->free_queue, q);
      silc_mutex_unlock(o->lock);
      goto execute;
    }

    silc_mutex_lock(lock);
    if (t->stop) {
      silc_mutex_unlock(tp->lock);
      goto stop;
    }

    /* Now that we have the lock back, check the queue again. */
    if (silc_list_count(t->queue) > 0) {
      silc_mutex_unlock(tp->lock);
      goto execute_queue;
    }

    /* The thread is now free for use again. */
    t->run = NULL;
    t->completion = NULL;
    t->schedule = NULL;
    silc_list_add(tp->free_threads, t);
    silc_mutex_unlock(tp->lock);
  }

 stop:
  /* Stop the thread.  Remove from threads list. */
  SILC_LOG_DEBUG(("Stop thread %p", t));

  /* We can unlock the thread now.  After we get the thread pool lock
     no one can retrieve the thread anymore. */
  silc_mutex_unlock(lock);
  silc_mutex_lock(tp->lock);

  silc_list_del(tp->threads, t);
  silc_list_start(tp->threads);

  /* Clear thread's call queue. */
  silc_list_start(t->queue);
  silc_list_start(t->free_queue);
  while ((q = silc_list_get(t->queue)))
    silc_sfree(tp->stack, q);
  while ((q = silc_list_get(t->free_queue)))
    silc_sfree(tp->stack, q);

  /* Destroy the thread */
  silc_mutex_free(lock);
  silc_cond_free(thread_signal);
  silc_sfree(tp->stack, t);

  /* If we are last thread, signal the waiting destructor. */
  if (silc_list_count(tp->threads) == 0)
    silc_cond_signal(tp->pool_signal);

  /* Release pool reference.  Releases lock also. */
  silc_thread_pool_unref(tp);

  return NULL;
}

/* Creates new thread to thread pool */

static SilcThreadPoolThread silc_thread_pool_new_thread(SilcThreadPool tp)
{
  SilcThreadPoolThread t;

  t = silc_scalloc(tp->stack, 1, sizeof(*t));
  if (!t)
    return NULL;

  if (!silc_mutex_alloc(&t->lock)) {
    silc_sfree(tp->stack, t);
    return NULL;
  }

  if (!silc_cond_alloc(&t->thread_signal)) {
    silc_mutex_free(t->lock);
    silc_sfree(tp->stack, t);
    return NULL;
  }

  t->tp = tp;
  silc_list_init(t->queue, struct SilcThreadPoolThreadStruct, next);
  silc_list_init(t->free_queue, struct SilcThreadPoolThreadStruct, next);

  /* Add to thread pool */
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
  if (!max_threads)
    return NULL;

  if (stack)
    stack = silc_stack_alloc(0, stack);

  tp = silc_scalloc(stack, 1, sizeof(*tp));
  if (!tp) {
    silc_stack_free(stack);
    return NULL;
  }

  SILC_LOG_DEBUG(("Starting thread pool %p, min threads %d, max threads %d",
		  tp, min_threads, max_threads));

  tp->stack = stack;
  tp->min_threads = min_threads;
  tp->max_threads = max_threads;
  tp->refcnt++;

  if (!silc_mutex_alloc(&tp->lock)) {
    silc_sfree(stack, tp);
    silc_stack_free(stack);
    return NULL;
  }

  if (!silc_cond_alloc(&tp->pool_signal)) {
    silc_mutex_free(tp->lock);
    silc_sfree(stack, tp);
    silc_stack_free(stack);
    return NULL;
  }

  silc_list_init(tp->threads, struct SilcThreadPoolThreadStruct, next);
  silc_list_init(tp->free_threads, struct SilcThreadPoolThreadStruct, next2);

  for (i = 0; i < tp->min_threads && start_min_threads; i++)
    silc_thread_pool_new_thread(tp);

  silc_list_start(tp->threads);

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
  while ((t = silc_list_get(tp->threads))) {
    silc_mutex_lock(t->lock);
    t->stop = TRUE;
    silc_cond_signal(t->thread_signal);
    silc_mutex_unlock(t->lock);
  }

  if (wait_unfinished) {
    SILC_LOG_DEBUG(("Wait threads to finish"));
    while (silc_list_count(tp->threads))
      silc_cond_wait(tp->pool_signal, tp->lock);
  }

  /* Release reference.  Releases lock also. */
  silc_thread_pool_unref(tp);
}

/* Execute code in a thread in the pool */

SilcBool silc_thread_pool_run(SilcThreadPool tp,
			      SilcBool queuable,
			      SilcSchedule schedule,
			      SilcThreadPoolFunc run,
			      void *run_context,
			      SilcTaskCallback completion,
			      void *completion_context)
{
  SilcThreadPoolThread t, q;

  silc_mutex_lock(tp->lock);

  if (tp->destroy) {
    silc_mutex_unlock(tp->lock);
    return FALSE;
  }

  /* Get free thread */
  silc_list_start(tp->free_threads);
  t = silc_list_get(tp->free_threads);
  if (!t || t->stop) {
    if (silc_list_count(tp->threads) + 1 > tp->max_threads) {
      /* Maximum threads reached */
      if (!queuable) {
	silc_mutex_unlock(tp->lock);
	return FALSE;
      }

      /* User wants to queue this call until thread becomes free.  Get
	 a thread to assign this call. */
      t = silc_list_get(tp->threads);
      if (!t) {
	/* List wraps around */
	silc_list_start(tp->threads);
	t = silc_list_get(tp->threads);
      }
      silc_mutex_unlock(tp->lock);

      SILC_LOG_DEBUG(("Queue call %p, context %p in thread %p",
		      run, run_context, t));

      silc_mutex_lock(t->lock);

      /* Get free call context from the list */
      silc_list_start(t->free_queue);
      q = silc_list_get(t->free_queue);
      if (!q) {
	q = silc_scalloc(tp->stack, 1, sizeof(*q));
	if (!q) {
	  silc_mutex_unlock(t->lock);
	  return FALSE;
	}
      } else {
	silc_list_del(t->free_queue, q);
      }

      q->run = run;
      q->run_context = run_context;
      q->completion = completion;
      q->completion_context = completion_context;
      q->schedule = schedule;

      /* Add at the start of the list.  It gets executed first. */
      silc_list_insert(t->queue, NULL, q);
      silc_mutex_unlock(t->lock);
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

  silc_list_del(tp->free_threads, t);
  silc_mutex_unlock(tp->lock);

  SILC_LOG_DEBUG(("Run call %p, context %p, thread %p", run, run_context, t));

  silc_mutex_lock(t->lock);

  /* Mark this call to be executed in this thread */
  t->run = run;
  t->run_context = run_context;
  t->completion = completion;
  t->completion_context = completion_context;
  t->schedule = schedule;

  /* Signal the thread */
  silc_cond_signal(t->thread_signal);
  silc_mutex_unlock(t->lock);

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

SilcUInt32 silc_thread_pool_get_max_threads(SilcThreadPool tp)
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
    silc_mutex_lock(t->lock);
    if (t->run) {
      silc_mutex_unlock(t->lock);
      continue;
    }

    /* Signal the thread to stop */
    t->stop = TRUE;
    silc_cond_signal(t->thread_signal);
    silc_mutex_unlock(t->lock);

    silc_list_del(tp->free_threads, t);

    i--;
    if (!i)
      break;
  }

  silc_list_start(tp->threads);
  silc_mutex_unlock(tp->lock);
}
