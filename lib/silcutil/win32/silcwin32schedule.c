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

/* Our "select()" for WIN32. This actually is not the select() and does
   not call Winsock's select() (since it cannot be used for our purposes)
   but mimics the functions of select(). 

   This is taken from the GLib and is the g_poll function in the Glib.
   It has been *heavily* modified to be select() like and fit for SILC. */

int silc_select(int n, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout)
{
  HANDLE handles[MAXIMUM_WAIT_OBJECTS];
  DWORD ready;
  int nhandles = 0;
  int timeo, i;

  /* Check fd sets (ignoring the exceptfds for now) */

  if (readfds) {
    for (i = 0; i < n - 1; i++)
      if (FD_ISSET(i, readfds))
	handles[nhandles++] = (HANDLE)i;
  }

  if (writefds) {
    /* If write fd is set then we just return */
    for (i = 0; i < n - 1; i++)
      if (FD_ISSET(i, writefds))
	return 1;
  }

  if (!timeout)
    timeo = INFINITE;
  else
    timeo = (timeout.tv_sec * 1000) + (timeout.tv_usec / 1000);

 retry:
  if (nhandles == 0)
    return -1;
  else
    ready = WaitForMultipleObjects(nhandles, handles, FALSE, timeo,
				   QS_ALLINPUT);

  if (ready == WAIT_FAILED) {
    SILC_LOG_WARNING(("WaitForMultipleObjects() failed"));
    return -1;
  } else if (ready == WAIT_TIMEOUT) {
    return 0;
  } else if (ready == WAIT_OBJECT_0 + nhandles) {
    /* For Windows messages. The MSDN online says that if the application
       creates a window then its main loop (and we're assuming that
       it is our SILC Scheduler) must handle the Windows messages, so do
       it here as the MSDN suggests. -Pekka */
    /* For reference: http://msdn.microsoft.com/library/default.asp?
       url=/library/en-us/winui/hh/winui/messques_77zk.asp */
    MSG msg;

    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
      TranslateMessage(&msg); 
      DispatchMessage(&msg); 
    }

    /* Bad thing is that I don't know what to return, since actually
       nothing for us happened. So, make another try with the waiting
       and do not return. This of course may fuck up the timeouts! */
    goto retry;
  } else if (ready >= WAIT_OBJECT_0 && ready < WAIT_OBJECT_0 + nhandles &&
	     readfds) {
    for (i = 0; i < n - 1; i++) {
      if (ready - WAIT_OBJECT_0 != i)
	FD_CLR(i, readfds);
    }

    /* Always one entry in the fd set. */
    return 1;
  }

  return -1;
}
