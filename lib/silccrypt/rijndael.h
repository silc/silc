/*

  rijndael.h

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
 * Revision 1.2  2000/10/02 18:31:46  priikone
 * 	Added rijndael (AES) to cipher list.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include "rijndael_internal.h"

/* 
 * SILC Crypto API for Rijndael
 */

SILC_CIPHER_API_SET_KEY(rijndael);
SILC_CIPHER_API_SET_KEY_WITH_STRING(rijndael);
SILC_CIPHER_API_CONTEXT_LEN(rijndael);
SILC_CIPHER_API_ENCRYPT_CBC(rijndael);
SILC_CIPHER_API_DECRYPT_CBC(rijndael);


#endif
