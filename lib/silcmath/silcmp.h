/****h* silcmath/silcmp.h
 *
 * NAME
 *
 * silcmp.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@silcnet.org>
 *
 * Copyright (C) 1997 - 2001 Pekka Riikonen
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
 * SILC MP Library Interface. This interface defines the arbitrary
 * precision arithmetic routines for SILC. Currently the actual routines
 * are implemented separately, usually by some other MP library. The
 * interface is generic but is mainly intended for crypto usage. This
 * interface is used by SILC routines that needs big numbers, such as
 * RSA implementation, Diffie-Hellman implementation etc.
 *
 ***/

#ifndef SILCMP_H
#define SILCMP_H

#ifdef SILC_MP_GMP
#include "mp_gmp.h"		/* SILC_MP_GMP */
#else
#include "mp_mpi.h"		/* SILC_MP_NSS_MPI */
#endif

/****d* silcmath/SilcMPAPI/SilcMPInt
 *
 * NAME
 *
 *    typedef SILC_MP_INT SilcMPInt;
 *
 * DESCRIPTION
 *
 *    The SILC MP Integer definition. This is the actual MP integer.
 *    The type is defined as SILC_MP_INT as it is implementation specific
 *    and is unknown to the application.
 *
 * SOURCE
 */
typedef SILC_MP_INT SilcMPInt;
/***/

/****f* silcmath/SilcMPAPI/silc_mp_alloc
 *
 * SYNOPSIS
 *
 *    void silc_mp_init(SilcMPInt mp);
 *
 * DESCRIPTION
 *
 *    Initializes the SilcMPInt *that is the actual MP Integer.
 *    This must be called before any of the silc_mp_ routines can be
 *    used. The integer is uninitialized with the silc_mp_uninit function.
 *
 ***/
void silc_mp_init(SilcMPInt *mp);

/****f* silcmath/SilcMPAPI/silc_mp_free
 *
 * SYNOPSIS
 *
 *    void silc_mp_uninit(SilcMPInt *mp);
 *
 * DESCRIPTION
 *
 *    Uninitializes the MP Integer.
 *
 ***/
void silc_mp_uninit(SilcMPInt *mp);

/****f* silcmath/SilcMPAPI/silc_mp_size
 *
 * SYNOPSIS
 *
 *    size_t silc_mp_size(SilcMPInt *mp);
 *
 * DESCRIPTION
 *
 *    Return the precision size of the integer `mp'.
 *
 ***/
size_t silc_mp_size(SilcMPInt *mp);

/****f* silcmath/SilcMPAPI/silc_mp_sizeinbase
 *
 * SYNOPSIS
 *
 *    size_t silc_mp_sizeinbase(SilcMPInt *mp, int base);
 *
 * DESCRIPTION
 *
 *    Return the size of the integer in base `base'. Note that this size
 *    is probably only an approximation.  However, it is guaranteed that
 *    the returned size is always at least the size of the integer, however,
 *    it may be larger.
 *
 ***/
size_t silc_mp_sizeinbase(SilcMPInt *mp, int base);

/****f* silcmath/SilcMPAPI/silc_mp_set
 *
 * SYNOPSIS
 *
 *    void silc_mp_set(SilcMPInt *dst, SilcMPInt *src);
 *
 * DESCRIPTION
 *
 *    Set `dst' integer from `src' integer. The `dst' must already be
 *    initialized.
 *
 ***/
void silc_mp_set(SilcMPInt *dst, SilcMPInt *src);

/****f* silcmath/SilcMPAPI/silc_mp_set_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_set_ui(SilcMPInt *dst, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Set `dst' integer from unsigned word `ui'. The `dst' must already be
 *    initialized.
 *
 ***/
void silc_mp_set_ui(SilcMPInt *dst, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_set_si
 *
 * SYNOPSIS
 *
 *    void silc_mp_set_si(SilcMPInt *dst, int32 si);
 *
 * DESCRIPTION
 *
 *    Set `dst' integer from single word `si'. The `dst' must
 *    already be initialized.
 *
 ***/
void silc_mp_set_si(SilcMPInt *dst, int32 si);

/****f* silcmath/SilcMPAPI/silc_mp_set_str
 *
 * SYNOPSIS
 *
 *    void silc_mp_set_str(SilcMPInt *dst, const char *str, int base);
 *
 * DESCRIPTION
 *
 *    Set `dst' integer from string `str' of base `base'. The `dst' must
 *    already be initialized.
 *
 ***/
void silc_mp_set_str(SilcMPInt *dst, const char *str, int base);

/****f* silcmath/SilcMPAPI/silc_mp_get_ui
 *
 * SYNOPSIS
 *
 *    uint32 silc_mp_get_ui(SilcMPInt *mp);
 *
 * DESCRIPTION
 *
 *    Returns the least significant unsigned word from `mp'.
 *
 ***/
uint32 silc_mp_get_ui(SilcMPInt *mp);

/****f* silcmath/SilcMPAPI/silc_mp_get_str
 *
 * SYNOPSIS
 *
 *    void silc_mp_get_str(char *str, SilcMPInt *mp, int base);
 *
 * DESCRIPTION
 *
 *    Converts integer `mp' into a string of base `base'. The `str'
 *    must already have space allocated. The function returns the same
 *    as `str' or NULL on error.
 *
 ***/
char *silc_mp_get_str(char *str, SilcMPInt *mp, int base);

/****f* silcmath/SilcMPAPI/silc_mp_add
 *
 * SYNOPSIS
 *
 *    void silc_mp_add(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Add two integers `mp1' and `mp2' and save the result to `dst'.
 *
 ***/
void silc_mp_add(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_add_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Add two integers `mp1' and unsigned word `ui' and save the result
 *    to `dst'.
 *
 ***/
void silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_sub
 *
 * SYNOPSIS
 *
 *    void silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Subtract two integers `mp1' and `mp2' and save the result to `dst'.
 *
 ***/
void silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_sub_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Subtract integers `mp1' and unsigned word `ui' and save the result
 *    to `dst'.
 *
 ***/
void silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mul
 *
 * SYNOPSIS
 *
 *    void silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Multiply two integers `mp1' and `mp2' and save the result to `dst'.
 *
 ***/
void silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_mul_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Multiply integer `mp1' and unsigned word `ui' and save the result
 *    to `dst'.
 *
 ***/
void silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mul_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp);
 *
 * DESCRIPTION
 *
 *    Multiply integers `mp1' with 2 ** `exp' and save the result to 
 *    `dst'. This is equivalent to dst = mp1 * (2 ^ exp).
 *
 ***/
void silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_sqrt
 *
 * SYNOPSIS
 *
 *    void silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src);
 *
 * DESCRIPTION
 *
 *    Compute square root of floor(sqrt(src)) and save the result to `dst'.
 *
 ***/
void silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src);

/****f* silcmath/SilcMPAPI/silc_mp_div
 *
 * SYNOPSIS
 *
 *    void silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' and `mp2' and save the result to the `dst'. This
 *    is equivalent to dst = mp1 / mp2;
 *
 ***/
void silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_div_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' and unsigned word `ui' and save the result to the
 *    `dst'. This is equivalent to dst = mp1 / ui;
 *
 ***/
void silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_div_qr
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1, 
 *                        SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' and `mp2' and save the quotient to the `q' and
 *    the remainder to the `r'.  This is equivalent to the q = mp1 / mp2, 
 *    r = mp1 mod mp2 (or mp1 = mp2 * q + r). If the `q' or `r' is NULL
 *    then the operation is omitted.
 *
 ***/
void silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1, 
		    SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_div_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' with 2 ** `exp' and save the result to `dst'.
 *    This is equivalent to dst = mp1 / (2 ^ exp).
 *
 ***/
void silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_div_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1, 
 *                             uint32 exp);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' with 2 ** `exp' and save the quotient to `q' and
 *    the remainder to `r'. This is equivalent to q = mp1 / (2 ^ exp),
 *    r = mp1 mod (2 ^ exp). If the `q' or `r' is NULL then the operation
 *    is omitted.
 *
 ***/
void silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1, 
			 uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_mod
 *
 * SYNOPSIS
 *
 *    void silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Mathematical MOD function. Produces the remainder of `mp1' and `mp2'
 *    and saves the result to `dst'. This is equivalent to dst = mp1 mod mp2.
 *    The same result can also be get with silc_mp_div_qr as that function
 *    returns the remainder as well.
 *
 ***/
void silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_mod_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Mathematical MOD function. Produces the remainder of `mp1' and 
 *    unsigned word `ui' and saves the result to `dst'. This is equivalent
 *    to dst = mp1 mod ui.
 *
 ***/
void silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mod_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Computes the remainder of `mp1' with 2 ** `exp' and saves the
 *    result to `dst'. This is equivalent to dst = mp1 mod (2 ^ exp).
 *    The same result can also be get with silc_mp_div_2exp_qr as that
 *    function returns the remainder as well.
 *
 ***/
void silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_pow
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp);
 *
 * DESCRIPTION
 *
 *    Compute `mp1' ** `exp' and save the result to `dst'. This is
 *    equivalent to dst = mp1 ^ exp.
 *
 ***/
void silc_mp_pow(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp);

/****f* silcmath/SilcMPAPI/silc_mp_pow_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp);
 *
 * DESCRIPTION
 *
 *    Compute `mp1' ** `exp' and save the result to `dst'. This is
 *    equivalent to dst = mp1 ^ exp.
 *
 ***/
void silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_pow_mod
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp, 
 *                         SilcMPInt *mod);
 *
 * DESCRIPTION
 *
 *    Compute (`mp1' ** `exp') mod `mod' and save the result to `dst'.
 *    This is equivalent to dst = (mp1 ^ exp) mod mod.
 *
 ***/
void silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp, 
		     SilcMPInt *mod);

/****f* silcmath/SilcMPAPI/silc_mp_pow_mod_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp, 
 *                            SilcMPInt *mod);
 *
 * DESCRIPTION
 *
 *    Compute (`mp1' ** `exp') mod `mod' and save the result to `dst'.
 *    This is equivalent to dst = (mp1 ^ exp) mod mod.
 *
 ***/
void silc_mp_pow_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp, 
			SilcMPInt *mod);

/****f* silcmath/SilcMPAPI/silc_mp_modinv
 *
 * SYNOPSIS
 *
 *    void silc_mp_modinv(SilcMPInt *inv, SilcMPInt *a, SilcMPInt *n);
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
void silc_mp_modinv(SilcMPInt *inv, SilcMPInt *a, SilcMPInt *n);

/****f* silcmath/SilcMPAPI/silc_mp_gcd
 *
 * SYNOPSIS
 *
 *    void silc_mp_gcd(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Calculate the greatest common divisor of the integers `mp1' and `mp2'
 *    and save the result to `dst'.
 *
 ***/
void silc_mp_gcd(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_gcdext
 *
 * SYNOPSIS
 *
 *    void silc_mp_gcdext(SilcMPInt *g, SilcMPInt *s, SilcMPInt *t, 
 *                        SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Calculate the extended greatest common divisor `g', `s' and `t' such
 *    that g = mp1 * s + mp2 * + t.
 *
 ***/
void silc_mp_gcdext(SilcMPInt *g, SilcMPInt *s, SilcMPInt *t, SilcMPInt *mp1,
		    SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_cmp
 *
 * SYNOPSIS
 *
 *    int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Compare `mp1' and `mp2'. Returns posivite, zero, or negative
 *    if `mp1' > `mp2', `mp1' == `mp2', or `mp1' < `mp2', respectively.
 *
 ***/
int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_cmp_si
 *
 * SYNOPSIS
 *
 *    int silc_mp_cmp_si(SilcMPInt *mp1, int32 si);
 *
 * DESCRIPTION
 *
 *    Compare `mp1' and single word `si'. Returns posivite, zero, or negative
 *    if `mp1' > `si', `mp1' == `si', or `mp1' < `si', respectively.
 *
 ***/
int silc_mp_cmp_si(SilcMPInt *mp1, int32 si);

/****f* silcmath/SilcMPAPI/silc_mp_cmp_ui
 *
 * SYNOPSIS
 *
 *    int silc_mp_cmp_ui(SilcMPInt *mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Compare `mp1' and unsigned word `ui'. Returns posivite, zero, or 
 *    negative if `mp1' > `ui', `mp1' == `ui', or `mp1' < `ui', 
 *    respectively.
 *
 ***/
int silc_mp_cmp_ui(SilcMPInt *mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mp2bin
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_mp_mp2bin(SilcMPInt *val, uint32 len, 
 *                                  uint32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Encodes MP integer into binary data. Returns allocated data that
 *    must be free'd by the caller. If `len' is provided the destination
 *    buffer is allocated that large. If zero then the size is approximated.
 *
 ***/
unsigned char *silc_mp_mp2bin(SilcMPInt *val, uint32 len, 
			      uint32 *ret_len);

/****f* silcmath/SilcMPAPI/silc_mp_mp2bin_noalloc
 *
 * SYNOPSIS
 *
 *    void silc_mp_mp2bin_noalloc(SilcMPInt *val, unsigned char *dst,
 *                                uint32 dst_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_mp_mp2bin but does not allocate any memory.  The
 *    encoded data is returned into `dst' and it's length to the `ret_len'.
 *
 ***/
void silc_mp_mp2bin_noalloc(SilcMPInt *val, unsigned char *dst,
			    uint32 dst_len);

/****f* silcmath/SilcMPAPI/silc_mp_bin2mp
 *
 * SYNOPSIS
 *
 *    void silc_mp_bin2mp(unsigned char *data, uint32 len, 
 *                        SilcMPInt *ret);
 *
 * DESCRIPTION
 *
 *    Decodes binary data into MP integer. The integer sent as argument
 *    must be initialized.
 *
 ***/
void silc_mp_bin2mp(unsigned char *data, uint32 len, SilcMPInt *ret);

/****f* silcmath/SilcMPAPI/silc_mp_abs
 *
 * SYNOPSIS
 *
 *    void silc_mp_abs(SilcMPInt *src, SilcMPInt *dst);
 *
 * DESCRIPTION
 *
 *    Assign the absolute value of `src' to `dst'.
 *
 ***/
void silc_mp_abs(SilcMPInt *dst, SilcMPInt *src);

/****f* silcmath/SilcMPAPI/silc_mp_neg
 *
 * SYNOPSIS
 *
 *    void silc_mp_neg(SilcMPInt *dst, SilcMPInt *src);
 *
 * DESCRIPTION
 *
 *    Negate `src' and save the result to `dst'.
 *
 ***/
void silc_mp_neg(SilcMPInt *dst, SilcMPInt *src);

/****f* silcmath/SilcMPAPI/silc_mp_and
 *
 * SYNOPSIS
 *
 *    void silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Logical and operator. The result is saved to `dst'.
 *
 ***/
void silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_or
 *
 * SYNOPSIS
 *
 *    void silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Logical inclusive OR operator. The result is saved to `dst'.
 *
 ***/
void silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

/****f* silcmath/SilcMPAPI/silc_mp_or
 *
 * SYNOPSIS
 *
 *    void silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);
 *
 * DESCRIPTION
 *
 *    Logical exclusive OR operator. The result is saved to `dst'.
 *
 ***/
void silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2);

#endif
