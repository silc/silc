/*

  silcsymbian.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

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

#endif /* SILCSYMBIAN_H */
