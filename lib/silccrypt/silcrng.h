/*

  silcSilcRng.h

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

#ifndef SILCRNG_H
#define SILCRNG_H

/* Forward declaration. Actual object is in source file. */
typedef struct SilcRngObjectStruct *SilcRng;

/* Number of states to fetch data from pool. */
#define SILC_RNG_STATE_NUM 4

/* Byte size of the random data pool. */
#define SILC_RNG_POOLSIZE 1024

/* Prototypes */
SilcRng silc_rng_alloc();
void silc_rng_free(SilcRng rng);
void silc_rng_init(SilcRng rng);
unsigned char silc_rng_get_byte(SilcRng rng);
uint16 silc_rng_get_rn16(SilcRng rng);
uint32 silc_rng_get_rn32(SilcRng rng);
unsigned char *silc_rng_get_rn_string(SilcRng rng, uint32 len);
unsigned char *silc_rng_get_rn_data(SilcRng rng, uint32 len);
void silc_rng_add_noise(SilcRng rng, unsigned char *buffer, uint32 len);

int silc_rng_global_init(SilcRng rng);
int silc_rng_global_uninit();
unsigned char silc_rng_global_get_byte();
uint16 silc_rng_global_get_rn16();
uint32 silc_rng_global_get_rn32();
unsigned char *silc_rng_global_get_rn_string(uint32 len);
unsigned char *silc_rng_global_get_rn_data(uint32 len);
void silc_rng_global_add_noise(unsigned char *buffer, uint32 len);

#endif
