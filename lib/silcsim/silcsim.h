/*

  silcsim.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSIM_H
#define SILCSIM_H

/* All SIM types. New types maybe freely added. */
typedef enum {
  SILC_SIM_NONE = 0,
  SILC_SIM_CIPHER,
  SILC_SIM_HASH,
} SilcSimType;

/* 
   SILC Module (SIM) Context.

   This context holds relevant information about the SIM loaded into
   the system. Following short description of the fields.

   void *handle

       Pointer to the SIM. This is used to get the symbols out of
       the SIM. This is initalized by system specific routine.

   SilcSimType type

       Type of the SIM.

   char *libname;

       Filename and path to the SIM library file.

   int flags

       Flags used with the SIM. These are system specific flags.
       See below for more information.

*/
typedef struct {
  void *handle;
  SilcSimType type;
  char *libname;
  int flags;
} SilcSimContext;

/* Flags used to retrieve the symbols from the library file. Default
   is that the symbols are resolved as they are loaded. However, if
   system doesn't support this we have no other choice but to do it lazy
   thus experience some overhead when using the symbol first time. */
#define SILC_SIM_FLAGS RTLD_NOW
/*#define SILC_SIM_FLAGS RTLD_LAZY */

/* Prototypes */
SilcSimContext *silc_sim_alloc();
void silc_sim_free(SilcSimContext *sim);
int silc_sim_load(SilcSimContext *sim);
int silc_sim_close(SilcSimContext *sim);
char *silc_sim_error();
void *silc_sim_getsym(SilcSimContext *sim, const char *symbol);

#endif
