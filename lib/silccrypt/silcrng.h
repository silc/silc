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
void silc_rng_get_soft_noise(SilcRng rng);
void silc_rng_get_medium_noise(SilcRng rng);
void silc_rng_get_hard_noise(SilcRng rng);
void silc_rng_exec_command(SilcRng rng, char *command);
void silc_rng_add_noise(SilcRng rng, unsigned char *buffer, 
			unsigned int len);
void silc_rng_xor(SilcRng rng, unsigned int val, unsigned int pos);
void silc_rng_stir_pool(SilcRng rng);
unsigned int silc_rng_get_position(SilcRng rng);
unsigned char silc_rng_get_byte(SilcRng rng);
unsigned short silc_rng_get_rn16(SilcRng rng);
unsigned int silc_rng_get_rn32(SilcRng rng);
unsigned char *silc_rng_get_rn_string(SilcRng rng, unsigned int len);
unsigned char *silc_rng_get_rn_data(SilcRng rng, unsigned int len);

#endif
