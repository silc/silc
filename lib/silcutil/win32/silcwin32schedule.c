/*

  silcwin32schedule.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "silcschedule_i.h"

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

int silc_select(SilcScheduleFd fds, SilcUInt32 fds_count, struct timeval *timeout)
{
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  DWORD ready, curtime, timeo;
  int nhandles = 0, i;
  MSG msg;

  if (fds_count > MAXIMUM_WAIT_OBJECTS)
    fds_count = MAXIMUM_WAIT_OBJECTS;

  for (i = 0; i < fds_count; i++) {
    if (!fds[i].events)
      continue;

    if (fds[i].events & SILC_TASK_READ)
      handles[nhandles++] = (HANDLE)fds[i].fd;

    /* If writing then just set the bit and return */
    if (fds[i].events & SILC_TASK_WRITE) {
      fds[i].revents = SILC_TASK_WRITE;
      return 1;
    }

    fds[i].revents = 0;
  }

  timeo = (timeout ? (timeout->tv_sec * 1000) + (timeout->tv_usec / 1000) :
	   INFINITE);

  /* If we have nothing to wait and timeout is set then register a timeout
     and wait just for windows messages. */
  if (nhandles == 0 && timeout) {
    UINT timer = SetTimer(NULL, 0, timeo, NULL);
    curtime = GetTickCount();
    while (timer) {
      WaitMessage();

      while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
	if (msg.message == WM_TIMER) {
	  KillTimer(NULL, timer);
	  return 0;
	}
	TranslateMessage(&msg); 
	DispatchMessage(&msg); 
      }

      KillTimer(NULL, timer);
      if (timeo != INFINITE) {
	timeo -= GetTickCount() - curtime;
	if (timeo < 0)
	  timeo = 0;
      }
      timer = SetTimer(NULL, 0, timeo, NULL);
    }
  }

 retry:
  curtime = GetTickCount();
  ready = MsgWaitForMultipleObjects(nhandles, handles, FALSE, timeo, 
				    QS_ALLINPUT);

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
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg); 
      DispatchMessage(&msg); 
    }

    /* If timeout is set then we must update the timeout since we won't
       return and we will give the wait another try. */
    if (timeo != INFINITE) {
      timeo -= GetTickCount() - curtime;
      if (timeo < 0)
	timeo = 0;
    }

    /* Give the wait another try */
   goto retry;
  } else if (ready >= WAIT_OBJECT_0 && ready < WAIT_OBJECT_0 + nhandles) {
    /* Some other event, like SOCKET or something. */

    /* Go through all fds even though only one was set. This is to avoid
       starvation of high numbered fds. */
    ready -= WAIT_OBJECT_0;
    do {
      for (i = 0; i < fds_count; i++) {
	if (!fds[i].events)
	  continue;
	
	if (fds[i].fd == (int)handles[ready]) {
	  fds[i].revents |= SILC_TASK_READ;
	  break;
	}
      }

      /* Check the status of the next handle and set its fd to the fd
	 set if data is available. */
      while (++ready < fds_count)
	if (WaitForSingleObject(handles[ready], 0) == WAIT_OBJECT_0)
	  break;
    } while (ready < fds_count);

    return i + 1;
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

void *silc_schedule_internal_init(SilcSchedule schedule)
{
#ifdef SILC_THREADS
  SilcWin32Wakeup wakeup;

  wakeup = silc_calloc(1, sizeof(*wakeup));

  wakeup->wakeup_sema = CreateSemaphore(NULL, 0, 100, NULL);
  if (!wakeup->wakeup_sema) {
    silc_free(wakeup);
    return NULL;
  }

  wakeup->wakeup_task = 
    silc_schedule_task_add(schedule, (int)wakeup->wakeup_sema,
			   silc_schedule_wakeup_cb, wakeup,
			   0, 0, SILC_TASK_FD, 
			   SILC_TASK_PRI_NORMAL);
  if (!wakeup->wakeup_task) {
    CloseHandle(wakeup->wakeup_sema);
    silc_free(wakeup);
    return NULL;
  }

  return (void *)wakeup;
#else
  return NULL;
#endif
}

/* Uninitializes the platform specific scheduler context. */

void silc_schedule_internal_uninit(void *context)
{
#ifdef SILC_THREADS
  SilcWin32Wakeup wakeup = (SilcWin32Wakeup)context;

  if (!wakeup)
    return;

  CloseHandle(wakeup->wakeup_sema);
  silc_free(wakeup);
#endif
}

/* Wakes up the scheduler */

void silc_schedule_internal_wakeup(void *context)
{
#ifdef SILC_THREADS
  SilcWin32Wakeup wakeup = (SilcWin32Wakeup)context;

  if (!wakeup)
    return;

  ReleaseSemaphore(wakeup->wakeup_sema, 1, NULL);
#endif
}

/* Register signal */

void silc_schedule_internal_signal_register(void *context,
					    SilcUInt32 signal)
{

}

/* Unregister signal */

void silc_schedule_internal_signal_unregister(void *context,
					      SilcUInt32 signal)
{

}

/* Block registered signals in scheduler. */

void silc_schedule_internal_signals_block(void *context)
{

}

/* Unblock registered signals in schedule. */

void silc_schedule_internal_signals_unblock(void *context)
{

}
