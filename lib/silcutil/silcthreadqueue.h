/*

  silcthreadqueue.h

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

/****h* silcutil/SILC Thread Queue Interface
 *
 * DESCRIPTION
 *
 * This interface provides asynchronous thread queues that can be used to
 * pass messages and data between two or more threads.  Typically a thread
 * would create the queue, push data into the queue and some other thread
 * takes the data from the queue or blocks until more data is available
 * in the queue.
 *
 * EXAMPLE
 *
 * Thread 1:
 *
 * // Create queue and push data into it
 * SilcThreadQueue queue = silc_thread_queue_alloc();
 * silc_thread_queue_push(queue, data);
 *
 * Thread 2:
 *
 * // Connect to the queue
 * silc_thread_queue_connect(queue);
 *
 * // Block here until data is available from the queue
 * data = silc_thread_queue_pop(queue, TRUE);
 *
 ***/

#ifndef SILCTHREADQUEUE_H
#define SILCTHREADQUEUE_H

/****s* silcutil/SilcThreadQueueAPI/SilcThreadQueue
 *
 * NAME
 *
 *    typedef struct SilcThreadQueueStruct *SilcThreadQueue;
 *
 * DESCRIPTION
 *
 *    The thread queue context allocated by silc_thread_queue_alloc and
 *    given as argument to all silc_thread_queue_* functions.
 *
 ***/
typedef struct SilcThreadQueueStruct *SilcThreadQueue;

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_alloc
 *
 * SYNOPSIS
 *
 *    SilcThreadQueue silc_thread_queue_alloc(void);
 *
 * DESCRIPTION
 *
 *    Allocates new thread queue context and returns it.  Returns NULL in
 *    case of error and sets the silc_errno.  The returned context is
 *    immediately ready to be used.  For a thread to be able to use the
 *    queue it must first connect to it by calling silc_thread_queue_connect.
 *    The thread that creates the queue automatically connects to the queue.
 *
 ***/
SilcThreadQueue silc_thread_queue_alloc(void);

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_connect
 *
 * SYNOPSIS
 *
 *    SilcBool silc_thread_queue_connect(SilcThreadQueue queue);
 *
 * DESCRIPTION
 *
 *    Connects current thread to the thread queue.  This function must
 *    be called by each thread wanting to use the thread queue.  After the
 *    thread is finished using the queue it must disconnect from the queue
 *    by calling silc_thread_queue_disconnect.
 *
 ***/
void silc_thread_queue_connect(SilcThreadQueue queue);

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_disconnect
 *
 * SYNOPSIS
 *
 *    void silc_thread_queue_disconnect(SilcThreadQueue queue);
 *
 * DESCRIPTION
 *
 *    Disconnects the current thread from the thread queue.  This must be
 *    called after the thread has finished using the thread queue.
 *
 *    When the last thread has disconnected from the queue the queue is
 *    destroyed.
 *
 ***/
void silc_thread_queue_disconnect(SilcThreadQueue queue);

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_push
 *
 * SYNOPSIS
 *
 *    void silc_thread_queue_push(SilcThreadQueue queue, void *data);
 *
 * DESCRIPTION
 *
 *    Pushes the `data' into the thread queue.  The data will become
 *    immediately available in the queue for other threads.
 *
 ***/
void silc_thread_queue_push(SilcThreadQueue queue, void *data);

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_pop
 *
 * SYNOPSIS
 *
 *    void *silc_thread_queue_pop(SilcThreadQueue queue, SilcBool block);
 *
 * DESCRIPTION
 *
 *    Takes data from the queue and returns it.  If `block' is TRUE and
 *    data is not available this will block until data becomes available.
 *    If `block' is FALSE and data is not available this will return NULL.
 *    If `block' is TRUE this will never return NULL.
 *
 ***/
void *silc_thread_queue_pop(SilcThreadQueue queue, SilcBool block);

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_timed_pop
 *
 * SYNOPSIS
 *
 *    void *silc_thread_queue_timed_pop(SilcThreadQueue queue,
 *                                      int timeout_msec);
 *
 * DESCRIPTION
 *
 *    Takes data from the thread queue or waits at most `timeout_msec'
 *    milliseconds for the data to arrive.  If data is not available when
 *    the timeout occurrs this returns NULL.
 *
 ***/
void *silc_thread_queue_timed_pop(SilcThreadQueue queue,
				  int timeout_msec);

/****f* silcutil/SilcThreadQueueAPI/silc_thread_queue_pop_list
 *
 * SYNOPSIS
 *
 *    SilcDList silc_thread_queue_pop_list(SilcThreadQueue queue,
 *                                         SilcBool block);
 *
 * DESCRIPTION
 *
 *    Takes everything from the queue and returns the data in a list.  The
 *    caller must free the returned list with silc_dlist_uninit.  If the
 *    `block' is FALSE this will never block but will return the queue
 *    immediately.  If `block' is TRUE this will block if the queue is
 *    empty.
 *
 ***/
SilcDList silc_thread_queue_pop_list(SilcThreadQueue queue, SilcBool block);

#endif /* SILCTHREADQUEUE_H */
