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

/* Our "select()" for WIN32. This mimics the behaviour of select() system
   call. It does not call the Winsock's select() though. Its functions
   are derived from GLib's g_poll() and from some old Xemacs's sys_select().

   This makes following assumptions, which I don't know whether they
   are correct or not:

   o writefds are ignored, if set this will return immediately.
   o exceptfds are ignored totally
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
   o http://developer.novell.com/support/winsock/doc/toc.htm

*/

int silc_select(int n, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  DWORD ready, curtime, timeo;
  int nhandles = 0, i;
  MSG msg;

  /* Check fd sets (ignoring the exceptfds) */
  if (readfds) {
    for (i = 0; i < n - 1; i++)
      if (FD_ISSET(i, readfds))
	handles[nhandles++] = (HANDLE)i;

    FD_ZERO(readfds);
  }

  /* If writefds is set then return immediately */
  if (writefds) {
    for (i = 0; i < n - 1; i++)
      if (FD_ISSET(i, writefds))
	return 1;
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
      KillTimer(NULL, timer);

      while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
	if (msg.message == WM_TIMER)
	  return 0;
	TranslateMessage(&msg); 
	DispatchMessage(&msg); 
      }

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
  } else if (ready >= WAIT_OBJECT_0 && ready < WAIT_OBJECT_0 + nhandles &&
	     readfds) {
    /* Some other event, like SOCKET or something. */

    /* Go through all fds even though only one was set. This is to avoid
       starvation of high numbered fds. */
    ready -= WAIT_OBJECT_0;
    i = 0;
    do {
      /* Set the handle to fd set */
      FD_SET((int)handles[ready], readfds);
      i++;

      /* Check the status of the next handle and set it's fd to the fd
	 set if data is available. */
      while (++ready < n)
	if (WaitForSingleObject(handles[ready], 0) == WAIT_OBJECT_0)
	  break;
    } while (ready < n);

    return i;
  }

  return -1;
}
