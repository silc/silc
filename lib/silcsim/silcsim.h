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

typedef struct SilcSimStruct *SilcSim;

/* All SIM types. New types maybe freely added. */
typedef enum {
  SILC_SIM_NONE = 0,
  SILC_SIM_CIPHER,
  SILC_SIM_HASH,
} SilcSimType;

/* Flags used to retrieve the symbols from the library file. Default
   is that the symbols are resolved as they are loaded. However, if
   system doesn't support this we have no other choice but to do it lazy
   thus experience some overhead when using the symbol first time. */
#if defined(RTLD_NOW)
#define SILC_SIM_FLAGS RTLD_NOW
#elif defined(RTLD_LAZY)
#define SILC_SIM_FLAGS RTLD_LAZY
#else
#define SILC_SIM_FLAGS 0
#endif

/* Prototypes */
SilcSim silc_sim_alloc(SilcSimType type, const char *libname, 
		       SilcUInt32 flags);
void silc_sim_free(SilcSim sim);
int silc_sim_load(SilcSim sim);
int silc_sim_close(SilcSim sim);
const char *silc_sim_error(SilcSim sim);
void *silc_sim_getsym(SilcSim sim, const char *symbol);

#endif
