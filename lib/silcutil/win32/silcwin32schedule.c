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

#define SILC_WM_EVENT WM_USER + 1

typedef struct {
  HWND window;			/* Hidden window for receiving socket events */
  WNDCLASS wclass;		/* Window class */
  HANDLE wakeup_sema;		/* Scheduler wakeup semaphore */
  unsigned int in_schedule   : 1;
} *SilcWin32Scheduler;

/* Our select() call.  This simply waits for some events to happen.  It also
   dispatches window messages so it can be used as the main loop of Windows
   application.  This doesn't wait for fds or sockets but does receive
   notifications via wakeup semaphore when event occurs on some fd or socket.
   The fds and sockets are scheduled via WSAAsyncSelect. */

int silc_select(SilcSchedule schedule, void *context)
{
  SilcWin32Scheduler internal = (SilcWin32Scheduler)context;
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  DWORD ready, curtime;
  LONG timeo = INFINITE;
  UINT timer;
  MSG msg;
  int nhandles = 0;

  if (!internal->in_schedule) {
    internal->in_schedule = TRUE;
    silc_list_init(schedule->fd_dispatch, struct SilcTaskStruct, next);
  }

  /* Add wakeup semaphore to events */
  handles[nhandles++] = internal->wakeup_sema;

  /* Get timeout */
  if (schedule->has_timeout)
    timeo = ((schedule->timeout.tv_sec * 1000) +
	     (schedule->timeout.tv_usec / 1000));

  SILC_SCHEDULE_UNLOCK(schedule);
 retry:
  curtime = GetTickCount();
  ready = MsgWaitForMultipleObjects(nhandles, handles, FALSE, timeo,
				    QS_ALLINPUT);

  if (ready == WAIT_FAILED) {
    /* Wait failed with error */
    SILC_LOG_WARNING(("WaitForMultipleObjects() failed"));
    SILC_SCHEDULE_LOCK(schedule);
    internal->in_schedule = FALSE;
    return -1;

  } else if (ready >= WAIT_ABANDONED_0 &&
	     ready < WAIT_ABANDONED_0 + nhandles) {
    /* Signal abandoned */
    SILC_LOG_WARNING(("WaitForMultipleObjects() failed (ABANDONED)"));
    SILC_SCHEDULE_LOCK(schedule);
    internal->in_schedule = FALSE;
    return -1;

  } else if (ready == WAIT_TIMEOUT) {
    /* Timeout */
    SILC_LOG_DEBUG(("Timeout"));
    SILC_SCHEDULE_LOCK(schedule);
    internal->in_schedule = FALSE;
    return 0;

  } else if (ready == WAIT_OBJECT_0 + nhandles) {
    /* Windows messages. The MSDN online says that if the application
       creates a window then its main loop (and we're assuming that
       it is our SILC Scheduler) must handle the Windows messages, so do
       it here as the MSDN suggests. */
    SILC_LOG_DEBUG(("Dispatch window messages"));
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
    /* Some event occurred. */
    SILC_LOG_DEBUG(("Dispatch events"));
    SILC_SCHEDULE_LOCK(schedule);
    internal->in_schedule = FALSE;
    return silc_list_count(schedule->fd_dispatch) + 1;
  }

  internal->in_schedule = FALSE;
  return -1;
}

/* Window callback.  We get here when some event occurs on file descriptor
   or socket that has been scheduled.  We add them to dispatch queue and
   notify the scheduler to handle them. */

static LRESULT CALLBACK
silc_schedule_wnd_proc(HWND hwnd, UINT wMsg, WPARAM wParam, LPARAM lParam)
{
  SilcSchedule schedule = (SilcSchedule)GetWindowLong(hwnd, GWL_USERDATA);
  SilcWin32Scheduler internal;
  SilcUInt32 fd;
  SilcTaskFd task;

  switch (wMsg) {
  case SILC_WM_EVENT:
    internal = (SilcWin32Scheduler)schedule->internal;
    fd = (SilcUInt32)wParam;

    SILC_LOG_DEBUG(("SILC_WM_EVENT fd %d", fd));
    SILC_SCHEDULE_LOCK(schedule);

    if (!internal->in_schedule) {
      /* We are not in scheduler so set up the dispatch queue now */
      internal->in_schedule = TRUE;
      silc_list_init(schedule->fd_dispatch, struct SilcTaskStruct, next);
    }

    /* Find task by fd */
    if (!silc_hash_table_find(schedule->fd_queue, SILC_32_TO_PTR(fd),
			      NULL, (void *)&task)) {
      SILC_SCHEDULE_UNLOCK(schedule);
      break;
    }

    /* Ignore the event if the task is not valid anymore */
    if (!task->header.valid || !task->events) {
      SILC_SCHEDULE_UNLOCK(schedule);
      break;
    }
    task->revents = 0;

    /* Handle event */
    switch (WSAGETSELECTEVENT(lParam)) {
    case FD_READ:
    case FD_OOB:
      SILC_LOG_DEBUG(("FD_READ"));
      task->revents |= SILC_TASK_READ;
      silc_list_add(schedule->fd_dispatch, task);
      break;

    case FD_WRITE:
      SILC_LOG_DEBUG(("FD_WRITE"));
      task->revents |= SILC_TASK_WRITE;
      silc_list_add(schedule->fd_dispatch, task);
      break;

    case FD_ACCEPT:
      SILC_LOG_DEBUG(("FD_ACCEPT"));
      task->revents |= SILC_TASK_READ;
      silc_list_add(schedule->fd_dispatch, task);
      break;

    default:
      break;
    }

    /* Wakeup scheduler */
    ReleaseSemaphore(internal->wakeup_sema, 1, NULL);

    SILC_SCHEDULE_UNLOCK(schedule);
    return TRUE;
    break;

  default:
    break;
  }

  return DefWindowProc(hwnd, wMsg, wParam, lParam);
}

/* Init Winsock2. */

static SilcBool silc_net_win32_init(void)
{
  int ret, sopt = SO_SYNCHRONOUS_NONALERT;
  WSADATA wdata;
  WORD ver = MAKEWORD(2, 2);

  ret = WSAStartup(ver, &wdata);
  if (ret)
    return FALSE;

  /* Allow using the SOCKET's as file descriptors so that we can poll
     them with SILC Scheduler. */
  ret = setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&sopt,
		   sizeof(sopt));
  if (ret)
    return FALSE;

  return TRUE;
}

/* Uninit Winsock2 */

static void silc_net_win32_uninit(void)
{
  WSACleanup();
}

/* Initializes the platform specific scheduler.  This for example initializes
   the wakeup mechanism of the scheduler.  In multi-threaded environment
   the scheduler needs to be wakenup when tasks are added or removed from
   the task queues.  Returns context to the platform specific scheduler. */

void *silc_schedule_internal_init(SilcSchedule schedule, void *app_context)
{
  SilcWin32Scheduler internal;
  char n[32];

  /* Initialize Winsock */
  silc_net_win32_init();

  internal = silc_calloc(1, sizeof(*internal));
  if (!internal)
    return NULL;

  schedule->max_tasks = MAXIMUM_WAIT_OBJECTS;

  /* Create hidden window.  We need window so that we can use WSAAsyncSelect
     to set socket events.  */
  silc_snprintf(n, sizeof(n), "SilcSchedule-%p", schedule);
  internal->wclass.lpfnWndProc = silc_schedule_wnd_proc;
  internal->wclass.cbWndExtra = sizeof(schedule);
  internal->wclass.lpszClassName = (CHAR *)strdup(n);
  RegisterClass(&internal->wclass);
  internal->window = CreateWindow((CHAR *)internal->wclass.lpszClassName, "",
				  0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);
  if (!internal->window) {
    SILC_LOG_ERROR(("Could not create hidden window for scheduler"));
    DestroyWindow(internal->window);
    UnregisterClass((CHAR *)n, NULL);
    silc_free(internal);
    return NULL;
  }

  /* Set the scheduler as the window's context */
  SetWindowLong(internal->window, GWL_USERDATA, (void *)schedule);
  SetWindowPos(internal->window, HWND_BOTTOM, 0, 0, 0, 0, SWP_FRAMECHANGED);

  internal->wakeup_sema = CreateSemaphore(NULL, 0, 100, NULL);
  if (!internal->wakeup_sema) {
    SILC_LOG_ERROR(("Could not create wakeup semaphore for scheduler"));
    silc_free(internal);
    return NULL;
  }

  return (void *)internal;
}

/* Uninitializes the platform specific scheduler context. */

void silc_schedule_internal_uninit(SilcSchedule schedule, void *context)
{
  SilcWin32Scheduler internal = (SilcWin32Scheduler)context;
  char n[32];

  if (!internal)
    return;

  silc_snprintf(n, sizeof(n), "SilcSchedule-%p", schedule);
  DestroyWindow(internal->window);
  UnregisterClass((CHAR *)n, NULL);

  CloseHandle(internal->wakeup_sema);
  silc_net_win32_uninit();

  silc_free(internal);
}

/* Schedule `task' with events `event_mask'. Zero `event_mask' unschedules. */

SilcBool silc_schedule_internal_schedule_fd(SilcSchedule schedule,
					    void *context,
					    SilcTaskFd task,
					    SilcTaskEvent event_mask)
{
  SilcWin32Scheduler internal = (SilcWin32Scheduler)context;
  int events = 0;

  if (!internal)
    return TRUE;

  SILC_LOG_DEBUG(("Scheduling fd %d for events %d", task->fd, event_mask));

  if (event_mask & SILC_TASK_READ)
    events |= FD_READ | FD_ACCEPT | FD_OOB;
  if (event_mask & SILC_TASK_WRITE)
    events |= FD_WRITE;

  /* Schedule for events.  The silc_schedule_wnd_proc will be called to
     deliver the events for this fd. */
  WSAAsyncSelect(task->fd, internal->window, SILC_WM_EVENT, events);
  task->revents = 0;

  return TRUE;
}

/* Wakes up the scheduler */

void silc_schedule_internal_wakeup(SilcSchedule schedule, void *context)
{
#ifdef SILC_THREADS
  SilcWin32Scheduler internal = (SilcWin32Scheduler)context;
  ReleaseSemaphore(internal->wakeup_sema, 1, NULL);
#endif /* SILC_THREADS */
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
