/*

  silcsim.c

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
/*
  These routines implement the SILC Module (SIM) support. SIM's are
  dynamically run-time loaded shared objects that can implement some
  routines SILC can use to extend its features. Currently all
  SILC Crypto modules are implemented as SIM's. They all implement
  the SILC Crypto API and can be loaded run-time into the SILC and
  used when needed. 

  Basically any SILC API can be implemented as SIM, however, currently
  only SILC Crypto modules (ciphers and hash functions (PKCS are not
  supported)) are supported.

  This implementation expects that no SILC specific symbols needs to
  be exported into the SIM's. This means that SIM's cannot directly
  use SILC specific symbols or definitions. This feature can be
  supported with SIM's but currently (with Crypto modules) this is
  not needed. 

  NOTE: These routines maybe highly system dependant thus I can expect 
  some heavy #ifdef's here. However, I'm more happy to see some macro 
  SIM API and restrict the #ifdef's to silcsim.h file.

*/

#include "silcincludes.h"

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
struct SilcSimStruct {
  void *handle;
  SilcSimType type;
  char *libname;
  int flags;
};

#ifdef SILC_SIM			/* SIM upport enabled */

/* Allocates new SIM context. This is later send to all SIM 
   routines. */

SilcSim silc_sim_alloc(SilcSimType type, const char *libname, 
		       SilcUInt32 flags)
{
  SilcSim sim;

  SILC_LOG_DEBUG(("Initializing new SIM context"));

  sim = silc_calloc(1, sizeof(*sim));
  if (!sim) {
    SILC_LOG_ERROR(("Could not allocate new SIM context"));
    return NULL;
  }

  sim->handle = NULL;
  sim->type = type;
  sim->libname = strdup(libname);
  sim->flags = !flags ? SILC_SIM_FLAGS : flags;

  return sim;
}

/* Free's SIM context. SIM must be closed with silc_sim_close before
   calling this. */

void silc_sim_free(SilcSim sim)
{
  assert(sim->handle == NULL);
  silc_free(sim->libname);
  silc_free(sim);
}

/* Loads SIM into the SILC system. */

int silc_sim_load(SilcSim sim)
{
  assert(sim != NULL);

  SILC_LOG_DEBUG(("Loading SIM '%s'", sim->libname));

  /* Load the library */
  sim->handle = dlopen(sim->libname, sim->flags);
  if (!sim->handle) {
    SILC_LOG_ERROR(("Error loading SIM: %s", silc_sim_error(sim)));
    return FALSE;
  }

  return TRUE;
}

/* Closes SIM. This is called when execution of program is ending or
   one explicitly wants to remove this SIM from SILC. */

int silc_sim_close(SilcSim sim)
{
  assert(sim != NULL);

  SILC_LOG_DEBUG(("Closing SIM '%s'", sim->libname));

  /* Close the library */
  dlclose(sim->handle);
  sim->handle = NULL;

  return TRUE;
}

/* Returns error string if error has occured while processing SIM's. */

const char *silc_sim_error(SilcSim sim)
{
  return dlerror();
}

/* Returns opaque pointer for a symbol in SIM. Caller must know the
   symbols they want to get from SIM and use the returned pointer to
   what ever it is intended. */

void *silc_sim_getsym(SilcSim sim, const char *symbol)
{
  assert(sim != NULL);

  SILC_LOG_DEBUG(("Getting symbol '%s' from SIM", symbol));

  return dlsym(sim->handle, symbol);
}

#endif /* SILC_SIM */
