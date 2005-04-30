/*

  none.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.1.1.1.4.1  2005/04/30 15:31:26  priikone
 * 	Header changes.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:54  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#ifndef NONE_H
#define NONE_H

/* 
 * SILC Crypto API for None cipher (ie. no cipher) :)
 */

SILC_CIPHER_API_SET_KEY(none);
SILC_CIPHER_API_SET_KEY_WITH_STRING(none);
SILC_CIPHER_API_CONTEXT_LEN(none);
SILC_CIPHER_API_ENCRYPT_CBC(none);
SILC_CIPHER_API_DECRYPT_CBC(none);

#endif
