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

/****f* silcmath/SilcMathAPI/silc_mp_modinv
 *
 * SYNOPSIS
 *
 *    void silc_mp_modinv(SilcInt *inv, SilcInt *a, SilcInt *n);
 *
 * DESCRIPTION
 *
 *    Find multiplicative inverse using Euclid's extended algorithm. 
 *    Computes inverse such that a * inv mod n = 1, where 0 < a < n. 
 *    Algorithm goes like this:
 *  
 *    g(0) = n    v(0) = 0
 *    g(1) = a    v(1) = 1
 * 
 *    y = g(i-1) / g(i)
 *    g(i+1) = g(i-1) - y * g(i) = g(i)-1 mod g(i)
 *    v(i+1) = v(i-1) - y * v(i)
 * 
 *    do until g(i) = 0, then inverse = v(i-1). If inverse is negative then n, 
 *    is added to inverse making it positive again. (Sometimes the algorithm 
 *    has a variable u defined too and it behaves just like v, except that 
 *    initalize values are swapped (i.e. u(0) = 1, u(1) = 0). However, u is 
 *    not needed by the algorithm so it does not have to be included.)
 *
 ***/
void silc_mp_modinv(SilcInt *inv, SilcInt *a, SilcInt *n);

/****f* silcmath/SilcMathAPI/silc_mp_mp2bin
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_mp_mp2bin(SilcInt *val, uint32 len,
 *                                  uint32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Encodes MP integer into binary data. Returns allocated data that
 *    must be free'd by the caller. If `len' is provided the destination
 *    buffer is allocated that large. If zero then the size is approximated.
 *
 ***/
unsigned char *silc_mp_mp2bin(SilcInt *val, uint32 len,
			      uint32 *ret_len);

/****f* silcmath/SilcMathAPI/silc_mp_mp2bin_noalloc
 *
 * SYNOPSIS
 *
 *    void silc_mp_mp2bin_noalloc(SilcInt *val, unsigned char *dst,
 *                                uint32 dst_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_mp_mp2bin but does not allocate any memory.  The
 *    encoded data is returned into `dst' and it's length to the `ret_len'.
 *
 ***/
void silc_mp_mp2bin_noalloc(SilcInt *val, unsigned char *dst,
			    uint32 dst_len);

/****f* silcmath/SilcMathAPI/silc_mp_bin2mp
 *
 * SYNOPSIS
 *
 *    void silc_mp_bin2mp(unsigned char *data, uint32 len, SilcInt *ret);
 *
 * DESCRIPTION
 *
 *    Decodes binary data into MP integer. The integer sent as argument
 *    must be initialized.
 *
 ***/
void silc_mp_bin2mp(unsigned char *data, uint32 len, SilcInt *ret);

/****f* silcmath/SilcMathAPI/silc_math_gen_prime
 *
 * SYNOPSIS
 *
 *    int silc_math_gen_prime(SilcInt *prime, uint32 bits, int verbose);
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
int silc_math_gen_prime(SilcInt *prime, uint32 bits, int verbose);

/****f* silcmath/SilcMathAPI/silc_math_prime_test
 *
 * SYNOPSIS
 *
 *    int silc_math_prime_test(SilcInt *p);
 *
 * DESCRIPTION
 *
 *    Performs primality testings for given number. Returns TRUE if the 
 *    number is probably a prime.
 *
 ***/
int silc_math_prime_test(SilcInt *p);

#endif
