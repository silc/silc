/*

  silcprimegen.h
  
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

#ifndef SILCPRIMEGEN_H
#define SILCPRIMEGEN_H

int silc_math_gen_prime(SilcInt *prime, uint32 bits, int verbose);
int silc_math_prime_test(SilcInt *p);
void silc_math_primegen_init();
void silc_math_primegen_uninit();

#endif
