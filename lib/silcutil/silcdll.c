/*

  silcdll.c

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

/* Load shared object */

SilcDll silc_dll_load(const char *object_path)
{
#ifdef SILC_UNIX
#if defined(HAVE_DLOPEN)
#if defined(RTLD_NOW)
  return dlopen(object_path, RTLD_NOW);
#elif defined(RTLD_LAZY)
  return dlopen(object_path, RTLD_LAZY);
#else
  return dlopen(object_path, 0);
#endif /* RTLD_NOW */
#endif /* HAVE_DLOPEN */
#elif SILC_WIN32
  return LoadLibrary(object_path);
#else
  /* XXX Symbian */
#endif /* SILC_UNIX */
  SILC_LOG_ERROR(("Shared objects are not supported on this platform"));
  return NULL;
}

/* Close shared object */

void silc_dll_close(SilcDll dll)
{
#ifdef SILC_UNIX
  dlclose(dll);
#elif SILC_WIN32
  FreeLibrary(dll);
#else
  /* XXX Symbian */
#endif /* SILC_UNIX */
}

/* Get symbol address from shared object */

void *silc_dll_getsym(SilcDll dll, const char *symbol)
{
#ifdef SILC_UNIX
  return (void *)dlsym(dll, symbol);
#elif SILC_WIN32
  return (void *)GetProcAddress(dll, symbol);
#else
  /* XXX Symbian */
#endif /* SILC_UNIX */
  SILC_LOG_ERROR(("Shared objects are not supported on this platform"));
  return NULL;
}

/* Get error string */

const char *silc_dll_error(SilcDll dll)
{
#ifdef SILC_UNIX
  return dlerror();
#elif SILC_WIN32
  return NULL;
#else
  /* XXX Symbian */
#endif /* SILC_UNIX */
  return NULL;
}
