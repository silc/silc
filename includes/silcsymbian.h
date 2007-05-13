/*

  silcsymbian.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2006 Pekka Riikonen

  The contents of this file are subject to one of the Licenses specified 
  in the COPYING file;  You may not use this file except in compliance 
  with the License.

  The software distributed under the License is distributed on an "AS IS"
  basis, in the hope that it will be useful, but WITHOUT WARRANTY OF ANY
  KIND, either expressed or implied.  See the COPYING file for more
  information.

*/
/* Native Symbian specific includes and definitions. */

#ifndef SILCSYMBIAN_H
#define SILCSYMBIAN_H

/* Various hacks follow */

/* Do not treat conversions from 'unsigned char *' to 'char *' as errors
   with WINSCW */
#ifdef __WINSCW__
#pragma mpwc_relax on
#endif /* __WINSCW__ */

/* Define the need for wchar_t, otherwise the stddef.h may not define it,
   as it is not guaranteed that the stddef.h used is from Symbian headers
   (due to some include path ordering problem in some cases). */
#ifndef __need_wchar_t
#define __need_wchar_t
#endif /* __need_wchar_t */

/* And just in case, include stddef.h here to get the Symbian one as
   early as possible. */
#include <stddef.h>
#include <sys/times.h>
#include <sys/stat.h>

/* Some internal routines */
void silc_symbian_usleep(long microseconds);
void silc_symbian_debug(const char *function, int line, char *string);

#endif /* SILCSYMBIAN_H */
