/*

  silcwin32thread.c

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
/* These routines are based on GLib's WIN32 gthread implementation and
   thus credits should go there. */
/* $Id$ */

#include "silcincludes.h"

#ifdef SILC_THREADS

/* Thread structure for WIN32 */
typedef struct {
  HANDLE thread;
  SilcThreadStart start_func;
  void *context;
  bool waitable;
} *SilcWin32Thread;

static DWORD silc_thread_tls;

/* Actual routine that is called by WIN32 when the thread is created.
   We will call the start_func from here. When this returns the thread
   is destroyed. */

unsigned __stdcall silc_thread_win32_start(void *context)
{
  SilcWin32Thread thread = (SilcWin32Thread)context;

  TlsSetValue(silc_thread_tls, context);
  thread->start_func(thread->context);
  silc_thread_exit(NULL);

  return 0;
}

SilcThread silc_thread_create(SilcThreadStart start_func, void *context,
			      bool waitable)
{
  SilcWin32Thread thread;
  unsigned id;

  SILC_LOG_DEBUG(("Creating new thread"));

  thread = silc_calloc(1, sizeof(*thread));
  thread->start_func = start_func;
  thread->context = context;
  thread->waitable = waitable;
  thread->thread = (HANDLE)_beginthreadex(NULL, 0, silc_thread_win32_start,
					  (void *)thread, 0, &id);
  if (!thread->thread) {
    SILC_LOG_ERROR(("Could not create new thread"));
    silc_free(thread);
    return NULL;
  }

  return (SilcThread)thread;
}

void silc_thread_exit(void *exit_value)
{
  SilcWin32Thread thread = TlsGetValue(silc_thread_tls);
  
  if (thread) {
    /* If the thread is waitable the memory is freed only in silc_thread_wait
       by another thread. If not waitable, free it now. */
    if (!thread->waitable) {
      CloseHandle(thread->thread);
      silc_free(thread);
    }

    TlsSetValue(silc_thread_tls, NULL);
  }

  _endthreadex(0);
}

SilcThread silc_thread_self(void)
{
  SilcWin32Thread self = TlsGetValue(silc_thread_tls);

  if (!self) {
    /* This should only happen for the main thread! */
    HANDLE handle = GetCurrentThread ();
    HANDLE process = GetCurrentProcess ();
    self = silc_calloc(1, sizeof(*self));
    DuplicateHandle(process, handle, process, 
		    &self->thread, 0, FALSE, 
		    DUPLICATE_SAME_ACCESS);
    TlsSetValue(silc_thread_tls, self);
  }

  return (SilcThread)self;
}

bool silc_thread_wait(SilcThread thread, void **exit_value)
{
  SilcWin32Thread self = (SilcWin32Thread)thread;

  SILC_LOG_DEBUG(("Waiting for thread %p", self));

  if (!self->waitable)
    return FALSE;

  /* The thread is waitable thus we will free all memory after the
     WaitForSingleObject returns, the thread is destroyed after that. */
  WaitForSingleObject(self->thread, INFINITE);
  CloseHandle(self->thread);
  silc_free(self);
  if (exit_value)
    *exit_value = NULL;

  return TRUE;
}

#endif /* SILC_THREADS */
