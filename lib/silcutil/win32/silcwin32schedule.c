/*

  silcwin32schedule.c

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

const SilcScheduleOps schedule_ops;

/* Our "select()" for WIN32. This mimics the behaviour of select() system
   call. It does not call the Winsock's select() though. Its functions
   are derived from GLib's g_poll() and from some old Xemacs's sys_select().

   This makes following assumptions, which I don't know whether they
   are correct or not:

   o SILC_TASK_WRITE is ignored, if set this will return immediately.
   o If all arguments except timeout are NULL then this will register
     a timeout with SetTimer and will wait just for Windows messages
     with WaitMessage.
   o MsgWaitForMultipleObjects is used to wait all kind of events, this
     includes SOCKETs and Windows messages.
   o All Windows messages are dispatched from this function.
   o The Operating System has Winsock 2.

   References:

   o http://msdn.microsoft.com/library/default.asp?
     url=/library/en-us/winui/hh/winui/messques_77zk.asp
   o http://msdn.microsoft.com/library/default.asp?
     url=/library/en-us/winsock/hh/winsock/apistart_9g1e.asp
   o http://msdn.microsoft.com/library/default.asp?
     url=/library/en-us/dnmgmt/html/msdn_getpeek.asp
   o http://developer.novell.com/support/winsock/doc/toc.htm

*/

int silc_select(SilcSchedule schedule, void *context)
{
  SilcHashTableList htl;
  SilcTaskFd task;
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  DWORD ready, curtime;
  LONG timeo;
  UINT timer;
  MSG msg;
  int nhandles = 0, fd;

  silc_hash_table_list(schedule->fd_queue, &htl);
  while (silc_hash_table_get(&htl, (void **)&fd, (void **)&task)) {
    if (!task->events)
      continue;
    if (nhandles >= MAXIMUM_WAIT_OBJECTS)
      break;

    if (task->events & SILC_TASK_READ)
      handles[nhandles++] = (HANDLE)fd;

    /* If writing then just set the bit and return */
    if (task->events & SILC_TASK_WRITE) {
      task->revents = SILC_TASK_WRITE;
      return 1;
    }

    task->revents = 0;
  }
  silc_hash_table_list_reset(&htl);
  silc_list_init(schedule->fd_dispatch, struct SilcTaskStruct, next);

  timeo = (schedule->has_timeout ? ((schedule->timeout.tv_sec * 1000) +
				    (schedule->timeout.tv_usec / 1000))
	   : INFINITE);

  /* If we have nothing to wait and timeout is set then register a timeout
     and wait just for windows messages. */
  if (nhandles == 0 && schedule->has_timeout) {
    SILC_SCHEDULE_UNLOCK(schedule);
    timer = SetTimer(NULL, 0, timeo, NULL);
    curtime = GetTickCount();
    while (timer) {
      WaitMessage();

      while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
	if (msg.message == WM_TIMER) {
	  KillTimer(NULL, timer);
	  SILC_SCHEDULE_LOCK(schedule);
	  return 0;
	}
	TranslateMessage(&msg);
	DispatchMessage(&msg);
      }

      KillTimer(NULL, timer);
      if (timeo != INFINITE) {
	timeo -= GetTickCount() - curtime;
	curtime = GetTickCount();
	if (timeo < 0)
	  timeo = 0;
      }
      timer = SetTimer(NULL, 0, timeo, NULL);
    }
    SILC_SCHEDULE_LOCK(schedule);
  }

  SILC_SCHEDULE_UNLOCK(schedule);
 retry:
  curtime = GetTickCount();
  ready = MsgWaitForMultipleObjects(nhandles, handles, FALSE, timeo,
				    QS_ALLINPUT);
  SILC_SCHEDULE_LOCK(schedule);

  if (ready == WAIT_FAILED) {
    /* Wait failed with error */
    SILC_LOG_WARNING(("WaitForMultipleObjects() failed"));
    return -1;
  } else if (ready >= WAIT_ABANDONED_0 &&
	     ready < WAIT_ABANDONED_0 + nhandles) {
    /* Signal abandoned */
    SILC_LOG_WARNING(("WaitForMultipleObjects() failed (ABANDONED)"));
    return -1;
  } else if (ready == WAIT_TIMEOUT) {
    /* Timeout */
    return 0;
  } else if (ready == WAIT_OBJECT_0 + nhandles) {
    /* Windows messages. The MSDN online says that if the application
       creates a window then its main loop (and we're assuming that
       it is our SILC Scheduler) must handle the Windows messages, so do
       it here as the MSDN suggests. */
    SILC_SCHEDULE_UNLOCK(schedule);
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }

    /* If timeout is set then we must update the timeout since we won't
       return and we will give the wait another try. */
    if (timeo != INFINITE) {
      timeo -= GetTickCount() - curtime;
      curtime = GetTickCount();
      if (timeo < 0)
	timeo = 0;
    }

    /* Give the wait another try */
    goto retry;
  } else if (ready >= WAIT_OBJECT_0 && ready < WAIT_OBJECT_0 + nhandles) {
    /* Some other event, like SOCKET or something. */

    /* Go through all fds even though only one was set. This is to avoid
       starvation of high numbered fds. */
    nhandles = silc_hash_table_count(schedule->fd_queue);
    ready -= WAIT_OBJECT_0;
    do {
      if (!silc_hash_table_find(schedule->fd_queue,
				SILC_32_TO_PTR((SilcUInt32)handles[ready]),
				NULL, (void *)&task))
	break;

      if (task->header.valid && task->events) {
	task->revents |= SILC_TASK_READ;
	silc_list_add(schedule->fd_dispatch, task);
      }

      /* Check the status of the next handle and set its fd to the fd
	 set if data is available. */
      SILC_SCHEDULE_UNLOCK(schedule);
      while (++ready < nhandles)
	if (WaitForSingleObject(handles[ready], 0) == WAIT_OBJECT_0)
	  break;
      SILC_SCHEDULE_LOCK(schedule);
    } while (ready < nhandles);

    return silc_list_count(schedule->fd_dispatch);
  }

  return -1;
}

#ifdef SILC_THREADS

/* Internal wakeup context. */
typedef struct {
  HANDLE wakeup_sema;
  SilcTask wakeup_task;
} *SilcWin32Wakeup;

SILC_TASK_CALLBACK(silc_schedule_wakeup_cb)
{
  /* Nothing */
}

#endif /* SILC_THREADS */

/* Initializes the platform specific scheduler.  This for example initializes
   the wakeup mechanism of the scheduler.  In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues.  Returns context to the platform specific scheduler. */

void *silc_schedule_internal_init(SilcSchedule schedule, void *app_context)
{
#ifdef SILC_THREADS
  SilcWin32Wakeup wakeup;
#endif

  schedule->max_tasks = MAXIMUM_WAIT_OBJECTS;

#ifdef SILC_THREADS
  wakeup = silc_calloc(1, sizeof(*wakeup));
  if (!wakeup)
    return NULL;

  wakeup->wakeup_sema = CreateSemaphore(NULL, 0, 100, NULL);
  if (!wakeup->wakeup_sema) {
    silc_free(wakeup);
    return NULL;
  }

  wakeup->wakeup_task =
    silc_schedule_task_add(schedule, (int)wakeup->wakeup_sema,
			   silc_schedule_wakeup_cb, wakeup,
			   0, 0, SILC_TASK_FD);
  if (!wakeup->wakeup_task) {
    CloseHandle(wakeup->wakeup_sema);
    silc_free(wakeup);
    return NULL;
  }

  return (void *)wakeup;
#else
  return (void *)1;
#endif
}

/* Uninitializes the platform specific scheduler context. */

void silc_schedule_internal_uninit(SilcSchedule schedule, void *context)
{
#ifdef SILC_THREADS
  SilcWin32Wakeup wakeup = (SilcWin32Wakeup)context;

  if (!wakeup)
    return;

  CloseHandle(wakeup->wakeup_sema);
  silc_free(wakeup);
#endif
}

/* Schedule `task' with events `event_mask'. Zero `event_mask' unschedules. */

SilcBool silc_schedule_internal_schedule_fd(SilcSchedule schedule,
					    void *context,
					    SilcTaskFd task,
					    SilcTaskEvent event_mask)
{
  return TRUE;
}

/* Wakes up the scheduler */

void silc_schedule_internal_wakeup(SilcSchedule schedule, void *context)
{
#ifdef SILC_THREADS
  SilcWin32Wakeup wakeup = (SilcWin32Wakeup)context;

  if (!wakeup)
    return;

  ReleaseSemaphore(wakeup->wakeup_sema, 1, NULL);
#endif
}

/* Register signal */

void silc_schedule_internal_signal_register(SilcSchedule schedule,
					    void *context,
                                            SilcUInt32 signal,
                                            SilcTaskCallback callback,
                                            void *callback_context)
{

}

/* Unregister signal */

void silc_schedule_internal_signal_unregister(SilcSchedule schedule,
					      void *context,
                                              SilcUInt32 signal)
{

}

/* Call all signals */

void silc_schedule_internal_signals_call(SilcSchedule schedule,
					 void *context)
{

}

/* Block registered signals in scheduler. */

void silc_schedule_internal_signals_block(SilcSchedule schedule,
					  void *context)
{

}

/* Unblock registered signals in schedule. */

void silc_schedule_internal_signals_unblock(SilcSchedule schedule,
					    void *context)
{

}

const SilcScheduleOps schedule_ops =
{
  silc_schedule_internal_init,
  silc_schedule_internal_uninit,
  silc_select,
  silc_schedule_internal_schedule_fd,
  silc_schedule_internal_wakeup,
  silc_schedule_internal_signal_register,
  silc_schedule_internal_signal_unregister,
  silc_schedule_internal_signals_call,
  silc_schedule_internal_signals_block,
  silc_schedule_internal_signals_unblock,
};
