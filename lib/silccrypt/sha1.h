/*

  sha1.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#ifndef SHA1_H
#define SHA1_H

#include "sha1_internal.h"

/* 
 * SILC Hash API for SHA1
 */

SILC_HASH_API_INIT(sha1);
SILC_HASH_API_UPDATE(sha1);
SILC_HASH_API_FINAL(sha1);
SILC_HASH_API_TRANSFORM(sha1);
SILC_HASH_API_CONTEXT_LEN(sha1);

#endif
