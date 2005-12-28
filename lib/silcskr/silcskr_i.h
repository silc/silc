/*

  silcskr_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSKR_I_H
#define SILCSKR_I_H

#ifndef SILCSKR_H
#error "Do not include this header directly"
#endif

/* Internal representation of SilcSKRKey context. */
typedef struct {
  struct SilcSKRKeyStruct key;	           /* Key data */
  SilcInt32 refcnt;			   /* Reference counter */
} *SilcSKRKeyInternal;

/* Key Repository context */
struct SilcSKRObject {
  SilcSchedule scheduler;
  SilcMutex lock;		          /* Repository lock */
  SilcHashTable keys;			  /* All keys in repository */
};

/* Find context */
struct SilcSKRFindStruct {
  SilcHashTable constr;			   /* Search constraints */
};

#endif /* SILCSKR_I_H */
