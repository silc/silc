/*

  silcdll.h

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

/****h* silcutil/Shared Object Interface
 *
 * DESCRIPTION
 *
 * Platform independent iterface for loading and using shared objects and
 * dynamically linked libraries (DLLs).
 *
 ***/

#ifndef SILCDLL_H
#define SILCDLL_H

/****s* silcutil/SilcDLLAPI/SilcDll
 *
 * NAME
 *
 *    typedef void *SilcDll;
 *
 * DESCRIPTION
 *
 *    This context represents the shared object and it is allocated by
 *    silc_dll_load and is destroyed with silc_dll_close functions.
 *    The context is given as argument to all funtions in this interface.
 *
 ***/
#ifdef SILC_UNIX
typedef void *SilcDll;
#elif SILC_WIN32
typedef HMODULE SilcDll;
#else
typedef void *SilcDll;
#endif /* SILC_UNIX */

/****f* silcutil/SilcDLLAPI/silc_dll_load
 *
 * SYNOPSIS
 *
 *    SilcDll silc_dll_load(const char *object_path);
 *
 * DESCRIPTION
 *
 *    Load shared object or DLL indicated by the `object_path'.  The path
 *    must include the absolute path to the object and the object name.
 *    Returns the SilcDll context or NULL on error.  The actual error
 *    message may be available by calling silc_dll_error function.  Symbols
 *    may be retrieved from the returned context by calling silc_dll_getsym.
 *
 ***/
SilcDll silc_dll_load(const char *object_path);

/****f* silcutil/SilcDLLAPI/silc_dll_close
 *
 * SYNOPSIS
 *
 *    void silc_dll_close(SilcDll dll);
 *
 * DESCRIPTION
 *
 *    Closes the shared object indicated by `dll'.  Any symbol retrieved
 *    from the `dll' with silc_dll_getsym will become invalid and cannot
 *    be used anymore.
 *
 ***/
void silc_dll_close(SilcDll dll);

/****f* silcutil/SilcDLLAPI/silc_dll_getsym
 *
 * SYNOPSIS
 *
 *    void *silc_dll_getsym(SilcDll dll, const char *symbol);
 *
 * DESCRIPTION
 *
 *    Returns the memory address of the symbol indicated by `symbol' from
 *    the shared object indicated by `dll'.  If such symbol does not exist
 *    this returns NULL.
 *
 ***/
void *silc_dll_getsym(SilcDll dll, const char *symbol);

/****f* silcutil/SilcDLLAPI/silc_dll_error
 *
 * SYNOPSIS
 *
 *    const char *silc_dll_error(SilcDll dll);
 *
 * DESCRIPTION
 *
 *    This routine may return error string after an error has occured with
 *    the shared object indicated by `dll'.  If error string is not available
 *    this will return NULL.
 *
 ***/
const char *silc_dll_error(SilcDll dll);

#endif /* SILCDLL_H */
