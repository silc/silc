/****h* silcmath/silcmath.h
 *
 * NAME
 *
 * silcmath.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Copyright (C) 1997 - 2000 Pekka Riikonen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * DESCRIPTION
 *
 * SILC Math interface includes various utility functions such as
 * prime generation, and conversion routines. See the silcmp.h for the
 * SILC MP interface.
 *
 */

#ifndef SILCMATH_H
#define SILCMATH_H

/****f* silcmath/SilcMathAPI/silc_math_gen_prime
 *
 * SYNOPSIS
 *
 *    int silc_math_gen_prime(SilcMPInt *prime, uint32 bits, int verbose);
 *
 * DESCRIPTION
 *
 *    Find appropriate prime. It generates a number by taking random bytes. 
 *    It then tests the number that it's not divisible by any of the small 
 *    primes and then it performs Fermat's prime test. I thank Rieks Joosten 
 *    (r.joosten@pijnenburg.nl) for such a good help with prime tests. 
 *
 *    If argument verbose is TRUE this will display some status information
 *    about the progress of generation.
 *
 ***/
int silc_math_gen_prime(SilcMPInt *prime, uint32 bits, int verbose);

/****f* silcmath/SilcMathAPI/silc_math_prime_test
 *
 * SYNOPSIS
 *
 *    int silc_math_prime_test(SilcMPInt *p);
 *
 * DESCRIPTION
 *
 *    Performs primality testings for given number. Returns TRUE if the 
 *    number is probably a prime.
 *
 ***/
int silc_math_prime_test(SilcMPInt *p);

#endif
