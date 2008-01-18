/*

  silcthreadqueue.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcruntime.h"

/************************** Types and definitions ***************************/

/* Thread queue context */
struct SilcThreadQueueStruct {
  SilcDList queue;		/* The queue */
  SilcMutex lock;		/* Queue lock */
  SilcCond cond;		/* Condition for waiting */
  SilcAtomic32 connected;	/* Number of connected threads */
};

/************************** SILC Thread Queue API ***************************/

/* Allocate thread queue */

SilcThreadQueue silc_thread_queue_alloc(void)
{
  SilcThreadQueue queue;

  queue = silc_calloc(1, sizeof(*queue));
  if (!queue)
    return NULL;

  SILC_LOG_DEBUG(("Allocated thread queue %p", queue));

  if (!silc_mutex_alloc(&queue->lock)) {
    silc_free(queue);
    return NULL;
  }

  if (!silc_cond_alloc(&queue->cond)) {
    silc_mutex_free(queue->lock);
    silc_free(queue);
    return NULL;
  }

  queue->queue = silc_dlist_init();
  if (!queue->queue) {
    silc_cond_free(queue->cond);
    silc_mutex_free(queue->lock);
    silc_free(queue);
    return NULL;
  }

  silc_atomic_init32(&queue->connected, 1);

  return queue;
}

/* Connect current thread to queue */

void silc_thread_queue_connect(SilcThreadQueue queue)
{
  silc_atomic_add_int32(&queue->connected, 1);
}

/* Disconnect current thread from queue */

void silc_thread_queue_disconnect(SilcThreadQueue queue)
{
  if (silc_atomic_sub_int32(&queue->connected, 1) > 0)
    return;

  /* Free queue */
  SILC_LOG_DEBUG(("Free thread queue %p", queue));
  silc_cond_free(queue->cond);
  silc_mutex_free(queue->lock);
  silc_dlist_uninit(queue->queue);
  silc_atomic_uninit32(&queue->connected);
  silc_free(queue);
}

/* Push data to queue */

void silc_thread_queue_push(SilcThreadQueue queue, void *data)
{
  if (silc_unlikely(!data))
    return;

  SILC_LOG_DEBUG(("Push data %p to thread queue %p", data, queue));

  silc_mutex_lock(queue->lock);
  silc_dlist_start(queue->queue);
  silc_dlist_insert(queue->queue, data);
  silc_cond_broadcast(queue->cond);
  silc_mutex_unlock(queue->lock);
}

/* Get data or wait if wanted or return NULL. */

void *silc_thread_queue_pop(SilcThreadQueue queue, SilcBool block)
{
  void *data;

  if (block)
    return silc_thread_queue_timed_pop(queue, 0);

  silc_mutex_lock(queue->lock);

  silc_dlist_start(queue->queue);
  data = silc_dlist_get(queue->queue);
  if (data)
    silc_dlist_del(queue->queue, data);

  SILC_LOG_DEBUG(("Pop data %p from thread queue %p", data, queue));

  silc_mutex_unlock(queue->lock);

  return data;
}

/* Get data or wait for a while */

void *silc_thread_queue_timed_pop(SilcThreadQueue queue,
				  int timeout_msec)
{
  void *data;

  silc_mutex_lock(queue->lock);

  silc_dlist_start(queue->queue);
  while ((data = silc_dlist_get(queue->queue)) == SILC_LIST_END) {
    if (!silc_cond_timedwait(queue->cond, queue->lock, timeout_msec))
      break;
    silc_dlist_start(queue->queue);
  }

  if (data)
    silc_dlist_del(queue->queue, data);

  SILC_LOG_DEBUG(("Pop data %p from thread queue %p", data, queue));

  silc_mutex_unlock(queue->lock);

  return data;
}

/* Pop entire queue */

SilcDList silc_thread_queue_pop_list(SilcThreadQueue queue, SilcBool block)
{
  SilcDList list;

  silc_mutex_lock(queue->lock);

  if (block)
    while (silc_dlist_count(queue->queue) == 0)
      silc_cond_wait(queue->cond, queue->lock);

  list = queue->queue;
  queue->queue = silc_dlist_init();

  silc_mutex_unlock(queue->lock);

  silc_dlist_start(list);

  return list;
}
