/****h* silcmath/silcmp.h
 *
 * NAME
 *
 * silcmp.h
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
 ***/

#ifndef SILCMP_H
#define SILCMP_H

#include "gmp.h"

#if 1

/* SILC MP library definitions. We use GNU MP library as default
   MP library. However, to make possible future changes easier (SILC 
   might have its own MP library in the future) we implement our own 
   MP API with simple macros. */ 

typedef MP_INT SilcInt;
#define silc_mp_abs(a, b) mpz_abs((a), (b))
#define silc_mp_add(a, b, c) mpz_add((a), (b), (c))
#define silc_mp_add_ui(a, b, c) mpz_add_ui((a), (b), (c))
#define silc_mp_and(a, b, c) mpz_and((a), (b), (c))
#define silc_mp_cdiv_q(a, b, c) mpz_cdiv_q((a), (b), (c))
#define silc_mp_cdiv_q_ui(a, b, c) mpz_cdiv_q_ui((a), (b), (c))
#define silc_mp_cdiv_r(a, b, c) mpz_cdiv_r((a), (b), (c))
#define silc_mp_cdiv_r_ui(a, b, c) mpz_cdiv_r_ui((a), (b), (c))
#define silc_mp_cdiv_ui(a, b) mpz_cdiv_ui((a), (b))
#define silc_mp_clear(a) mpz_clear((a))
#define silc_mp_clrbit(a, b) mpz_clrbit((a), (b))
#define silc_mp_cmp(a, b) mpz_cmp((a), (b))
#define silc_mp_cmp_si(a, b) mpz_cmp_si((a), (b))
#define silc_mp_cmp_ui(a, b) mpz_cmp_ui((a), (b))
#define silc_mp_com(a, b) mpz_com((a), (b))
#define silc_mp_divexact(a, b, c) mpz_divexact((a), (b), (c))
#define silc_mp_div(a, b, c) mpz_div((a), (b), (c))
#define silc_mp_div_ui(a, b, c) mpz_div_ui((a), (b), (c))
#define silc_mp_fdiv_ui(a, b) mpz_fdiv_ui((a), (b))
#define silc_mp_fdiv_q(a, b, c) mpz_fdiv_q((a), (b), (c))
#define silc_mp_fdiv_q_2exp(a, b, c) mpz_fdiv_q_2exp((a), (b), (c))
#define silc_mp_fdiv_q_ui(a, b, c) mpz_fdiv_q_ui((a), (b), (c))
#define silc_mp_fdiv_qr(a, b, c, d) mpz_fdiv_qr((a), (b), (c), (d))
#define silc_mp_fdiv_qr_ui(a, b, c, d) mpz_fdiv_qr_ui((a), (b), (c), (d))
#define silc_mp_fdiv_r(a, b, c) mpz_fdiv_r((a), (b), (c))
#define silc_mp_fdiv_r_2exp(a, b, c) mpz_fdiv_r_2exp((a), (b), (c))
#define silc_mp_fdiv_r_ui(a, b, c) mpz_fdiv_r_ui((a), (b), (c))
#define silc_mp_fdiv_ui(a, b) mpz_fdiv_ui((a), (b))
#define silc_mp_gcd(a, b, c) mpz_gcd((a), (b), (c))
#define silc_mp_gcd_ui(a, b, c) mpz_gcd_ui((a), (b), (c))
#define silc_mp_gcdext(a, b, c, d, e) mpz_gcdext((a), (b), (c), (d), (e))
#define silc_mp_get_ui(a) mpz_get_ui((a))
#define silc_mp_init(a) mpz_init((a))
#define silc_mp_init_set(a, b) mpz_init_set((a), (b))
#define silc_mp_init_set_d(a, b) mpz_init_set_d((a), (b))
#define silc_mp_init_set_si(a, b) mpz_init_set_si((a), (b))
#define silc_mp_init_set_str(a, b, c) mpz_init_set_str((a), (b), (c))
#define silc_mp_init_set_ui(a, b) mpz_init_set_ui((a), (b))
#define silc_mp_invert(a, b, c) mpz_invert((a), (b), (c))
#define silc_mp_ior(a, b, c) mpz_ior((a), (b), (c))
#define silc_mp_mod(a, b, c) mpz_mod((a), (b), (c))
#define silc_mp_mod_2exp(a, b, c) mpz_mod_2exp((a), (b), (c))
#define silc_mp_mod_ui(a, b, c) mpz_mod_ui((a), (b), (c))
#define silc_mp_mul(a, b, c) mpz_mul((a), (b), (c))
#define silc_mp_mul_2exp(a, b, c) mpz_mul_2exp((a), (b), (c))
#define silc_mp_mul_ui(a, b, c) mpz_mul_ui((a), (b), (c))
#define silc_mp_neg(a, b) mpz_neg((a), (b))
#define silc_mp_pow_ui(a, b, c) mpz_pow_ui((a), (b), (c))
#define silc_mp_powm(a, b, c, d) mpz_powm((a), (b), (c), (d))
#define silc_mp_powm_ui(a, b, c, d) mpz_powm_ui((a), (b), (c), (d))
#define silc_mp_probab_prime_p(a, b) mpz_probab_prime_p((a), (b))
#define silc_mp_set(a, b) mpz_set((a), (b))
#define silc_mp_set_d(a, b) mpz_set_d((a), (b))
#define silc_mp_set_f(a, b) mpz_set_f((a), (b))
#define silc_mp_set_q(a, b) mpz_set_q((a), (b))
#define silc_mp_set_si(a, b) mpz_set_si((a), (b))
#define silc_mp_set_str(a, b, c) mpz_set_str((a), (b), (c))
#define silc_mp_set_ui(a, b) mpz_set_ui((a), (b))
#define silc_mp_setbit(a, b) mpz_setbit((a), (b))
#define silc_mp_size(a) mpz_size((a))
#define silc_mp_sizeinbase(a, b) mpz_sizeinbase((a), (b))
#define silc_mp_sqrt(a, b) mpz_sqrt((a), (b))
#define silc_mp_sqrtrem(a, b, c) mpz_sqrtrem((a), (b), (c))
#define silc_mp_sub(a, b, c) mpz_sub((a), (b), (c))
#define silc_mp_sub_ui(a, b, c) mpz_sub_ui((a), (b), (c))
#define silc_mp_tdiv_ui(a, b) mpz_tdiv_ui((a), (b))
#define silc_mp_tdiv_q(a, b, c) mpz_tdiv_q((a), (b), (c))
#define silc_mp_tdiv_q_2exp(a, b, c) mpz_tdiv_q_2exp((a), (b), (c))
#define silc_mp_tdiv_q_ui(a, b, c) mpz_tdiv_q_ui((a), (b), (c))
#define silc_mp_tdiv_qr(a, b, c, d) mpz_tdiv_qr((a), (b), (c), (d))
#define silc_mp_tdiv_qr_ui(a, b, c, d) mpz_tdiv_qr_ui((a), (b), (c), (d))
#define silc_mp_tdiv_r(a, b, c) mpz_tdiv_r((a), (b), (c))
#define silc_mp_tdiv_r_2exp(a, b, c) mpz_tdiv_r_2exp((a), (b), (c))
#define silc_mp_tdiv_r_ui(a, b, c) mpz_tdiv_r_ui((a), (b), (c))
#define silc_mp_tdiv_ui(a, b) mpz_tdiv_ui((a), (b))
#define silc_mp_ui_pow_ui(a, b, c) mpz_ui_pow_ui((a), (b), (c))
#define silc_mp_get_str(a, b, c) mpz_get_str((a), (b), (c))
#define silc_mp_out_str(a, b, c) mpz_out_str((a), (b), (c))

#else

/* SILC MP Library Interface. This interface defines the arbitrary
   precision arithmetic routines for SILC. Currently the actual routines
   are implemented separately, usually by some other MP library. The
   interface is generic but is mainly intended for crypto usage. This
   interface is used by SILC routines that needs big numbers, such as
   RSA implementation, Diffie-Hellman implementation etc. */

/* XXX Move this to implementation specific files */
#define SILC_MP_INT MP_INT

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
typedef SILC_MP_INT *SilcMPInt;
/***/

/****f* silcmath/SilcMPAPI/silc_mp_alloc
 *
 * SYNOPSIS
 *
 *    void silc_mp_init(SilcMPInt mp);
 *
 * DESCRIPTION
 *
 *    Initializes the SilcMPInt that is the actual MP Integer.
 *    This must be called before any of the silc_mp_ routines can be
 *    used. The integer is uninitialized with the silc_mp_uninit function.
 *
 ***/
void silc_mp_init(SilcMPInt mp);

/****f* silcmath/SilcMPAPI/silc_mp_free
 *
 * SYNOPSIS
 *
 *    void silc_mp_uninit(SilcMPInt mp);
 *
 * DESCRIPTION
 *
 *    Uninitializes the MP Integer.
 *
 ***/
void silc_mp_uninit(SilcMPInt mp);

/****f* silcmath/SilcMPAPI/silc_mp_abs
 *
 * SYNOPSIS
 *
 *    void silc_mp_abs(SilcMPInt src, SilcMPInt dst);
 *
 * DESCRIPTION
 *
 *    Assign the absolute value of `src' to `dst'.
 *
 ***/
void silc_mp_abs(SilcMPInt dst, SilcMPInt src);

/****f* silcmath/SilcMPAPI/silc_mp_add
 *
 * SYNOPSIS
 *
 *    void silc_mp_add(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Add two integers `mp1' and `mp2' and save the result to `dst'.
 *
 ***/
void silc_mp_add(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_add_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_add_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Add two integers `mp1' and unsigned word `ui' and save the result
 *    to `dst'.
 *
 ***/
void silc_mp_add_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_and
 *
 * SYNOPSIS
 *
 *    void silc_mp_and(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Logical and operator. The result is saved to `dst'.
 *
 ***/
void silc_mp_and(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_cmp
 *
 * SYNOPSIS
 *
 *    int silc_mp_cmp(SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Compare `mp1' and `mp2'. Returns posivite, zero, or negative
 *    if `mp1' > `mp2', `mp1' == `mp2', or `mp1' < `mp2', respectively.
 *
 ***/
int silc_mp_cmp(SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_cmp_si
 *
 * SYNOPSIS
 *
 *    int silc_mp_cmp_si(SilcMPInt mp1, int32 si);
 *
 * DESCRIPTION
 *
 *    Compare `mp1' and single word `si'. Returns posivite, zero, or negative
 *    if `mp1' > `si', `mp1' == `si', or `mp1' < `si', respectively.
 *
 ***/
int silc_mp_cmp_si(SilcMPInt mp1, int32 si);

/****f* silcmath/SilcMPAPI/silc_mp_cmp_ui
 *
 * SYNOPSIS
 *
 *    int silc_mp_cmp_ui(SilcMPInt mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Compare `mp1' and unsigned word `ui'. Returns posivite, zero, or 
 *    negative if `mp1' > `ui', `mp1' == `ui', or `mp1' < `ui', 
 *    respectively.
 *
 ***/
int silc_mp_cmp_ui(SilcMPInt mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_div
 *
 * SYNOPSIS
 *
 *    void silc_mp_div(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' and `mp2' and save the result to the `dst'. This
 *    is equivalent to dst = mp1 / mp2;
 *
 ***/
void silc_mp_div(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_div_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_div(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' and unsigned word `ui' and save the result to the
 *    `dst'. This is equivalent to dst = mp1 / ui;
 *
 ***/
void silc_mp_div_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_div_qr
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_qr(SilcMPInt q, SilcMPInt r, SilcMPInt mp1, 
 *                        SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' and `mp2' and save the quotient to the `q' and
 *    the remainder to the `r'.  This is equivalent to the q = mp1 / mp2, 
 *    r = mp1 mod mp2 (or mp1 = mp2 * q + r). If the `q' or `r' is NULL
 *    then the operation is omitted.
 *
 ***/
void silc_mp_div_qr(SilcMPInt q, SilcMPInt r, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_div_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_2exp(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' with 2 ** `exp' and save the result to `dst'.
 *    This is equivalent to dst = mp1 / (2 ^ exp).
 *
 ***/
void silc_mp_div_2exp(SilcMPInt dst, SilcMPInt mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_div_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_div_2exp(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Divide the `mp1' with 2 ** `exp' and save the quotient to `q' and
 *    the remainder to `r'. This is equivalent to q = mp1 / (2 ^ exp),
 *    r = mp1 mod (2 ^ exp). If the `q' or `r' is NULL then the operation
 *    is omitted.
 *
 ***/
void silc_mp_div_2exp_qr(SilcMPInt q, SilcMPInt r, SilcMPInt mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_gcd
 *
 * SYNOPSIS
 *
 *    void silc_mp_gcd(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Calculate the greatest common divisor of the integers `mp1' and `mp2'
 *    and save the result to `dst'.
 *
 ***/
void silc_mp_gcd(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_gcdext
 *
 * SYNOPSIS
 *
 *    void silc_mp_gcdext(SilcMPInt g, SilcMPInt s, SilcMPInt t, SilcMPInt mp1,
 *                        SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Calculate the extended greatest common divisor `g', `s' and `t' such
 *    that g = mp1 * s + mp2 * + t.
 *
 ***/
void silc_mp_gcdext(SilcMPInt g, SilcMPInt s, SilcMPInt t, SilcMPInt mp1,
		    SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_get_ui
 *
 * SYNOPSIS
 *
 *    uint32 silc_mp_get_ui(SilcMPInt mp);
 *
 * DESCRIPTION
 *
 *    Returns the least significant unsigned word from `mp'.
 *
 ***/
uint32 silc_mp_get_ui(SilcMPInt mp);

/****f* silcmath/SilcMPAPI/silc_mp_get_str
 *
 * SYNOPSIS
 *
 *    void silc_mp_get_str(char *str, SilcMPInt mp, int base);
 *
 * DESCRIPTION
 *
 *    Converts integer `mp' into a string of base `base'. The `str'
 *    must already have space allocated. The function returns the same
 *    as `str' or NULL on error.
 *
 ***/
char *silc_mp_get_str(char *str, SilcMPInt mp, int base);

/****f* silcmath/SilcMPAPI/silc_mp_or
 *
 * SYNOPSIS
 *
 *    void silc_mp_or(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Logical inclusive OR operator. The result is saved to `dst'.
 *
 ***/
void silc_mp_or(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_mod
 *
 * SYNOPSIS
 *
 *    void silc_mp_or(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Mathematical MOD function. Produces the remainder of `mp1' and `mp2'
 *    and saves the result to `dst'. This is equivalent to dst = mp1 mod mp2.
 *    The same result can also be get with silc_mp_div_qr as that function
 *    returns the remainder as well.
 *
 ***/
void silc_mp_mod(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_mod_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_mod_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);
 *
 * DESCRIPTION
 *
 *    Mathematical MOD function. Produces the remainder of `mp1' and 
 *    unsigned word `ui' and saves the result to `dst'. This is equivalent
 *    to dst = mp1 mod ui.
 *
 ***/
void silc_mp_mod_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mod_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_mod_2exp(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Computes the remainder of `mp1' with 2 ** `exp' and saves the
 *    result to `dst'. This is equivalent to dst = mp1 mod (2 ^ exp).
 *    The same result can also be get with silc_mp_div_2exp_qr as that
 *    function returns the remainder as well.
 *
 ***/
void silc_mp_mod_2exp(SilcMPInt dst, SilcMPInt mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mul
 *
 * SYNOPSIS
 *
 *    void silc_mp_mul(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Multiply two integers `mp1' and `mp2' and save the result to `dst'.
 *
 ***/
void silc_mp_mul(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);

/****f* silcmath/SilcMPAPI/silc_mp_mul_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_mul(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
 *
 * DESCRIPTION
 *
 *    Multiply integer `mp1' and unsigned word `ui' and save the result
 *    to `dst'.
 *
 ***/
void silc_mp_mul_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);

/****f* silcmath/SilcMPAPI/silc_mp_mul_2exp
 *
 * SYNOPSIS
 *
 *    void silc_mp_mul_2exp(SilcMPInt dst, SilcMPInt mp1, uint32 exp);
 *
 * DESCRIPTION
 *
 *    Multiply integers `mp1' with 2 ** `exp' and save the result to 
 *    `dst'. This is equivalent to dst = mp1 * (2 ^ exp).
 *
 ***/
void silc_mp_mul_2exp(SilcMPInt dst, SilcMPInt mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_neg
 *
 * SYNOPSIS
 *
 *    void silc_mp_neg(SilcMPInt dst, SilcMPInt src);
 *
 * DESCRIPTION
 *
 *    Negate `src' and save the result to `dst'.
 *
 ***/
void silc_mp_neg(SilcMPInt dst, SilcMPInt src);

/****f* silcmath/SilcMPAPI/silc_mp_pow
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow(SilcMPInt dst, SilcMPInt mp1, SilcMPInt exp);
 *
 * DESCRIPTION
 *
 *    Compute `mp1' ** `exp' and save the result to `dst'. This is
 *    equivalent to dst = mp1 ^ exp.
 *
 ***/
void silc_mp_pow(SilcMPInt dst, SilcMPInt mp1, SilcMPInt exp);

/****f* silcmath/SilcMPAPI/silc_mp_pow_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow_ui(SilcMPInt dst, SilcMPInt mp1, uint32 exp);
 *
 * DESCRIPTION
 *
 *    Compute `mp1' ** `exp' and save the result to `dst'. This is
 *    equivalent to dst = mp1 ^ exp.
 *
 ***/
void silc_mp_pow_ui(SilcMPInt dst, SilcMPInt mp1, uint32 exp);

/****f* silcmath/SilcMPAPI/silc_mp_pow_mod
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow_mod(SilcMPInt dst, SilcMPInt mp1, SilcMPInt exp, 
 *                         SilcMPInt mod);
 *
 * DESCRIPTION
 *
 *    Compute (`mp1' ** `exp') mod `mod' and save the result to `dst'.
 *    This is equivalent to dst = (mp1 ^ exp) mod mod.
 *
 ***/
void silc_mp_pow_mod(SilcMPInt dst, SilcMPInt mp1, SilcMPInt exp, 
		     SilcMPInt mod);

/****f* silcmath/SilcMPAPI/silc_mp_pow_mod_ui
 *
 * SYNOPSIS
 *
 *    void silc_mp_pow_mod_ui(SilcMPInt dst, SilcMPInt mp1, uint32 exp, 
 *                            SilcMPInt mod);
 *
 * DESCRIPTION
 *
 *    Compute (`mp1' ** `exp') mod `mod' and save the result to `dst'.
 *    This is equivalent to dst = (mp1 ^ exp) mod mod.
 *
 ***/
void silc_mp_pow_mod_ui(SilcMPInt dst, SilcMPInt mp1, uint32 exp, 
			SilcMPInt mod);

/****f* silcmath/SilcMPAPI/silc_mp_modinv
 *
 * SYNOPSIS
 *
 *    void silc_mp_modinv(SilcMPInt inv, SilcMPInt a, SilcMPInt n);
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
void silc_mp_modinv(SilcMPInt inv, SilcMPInt a, SilcMPInt n);

/****f* silcmath/SilcMPAPI/silc_mp_mp2bin
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_mp_mp2bin(SilcMPInt val, uint32 len, 
 *                                  uint32 *ret_len);
 *
 * DESCRIPTION
 *
 *    Encodes MP integer into binary data. Returns allocated data that
 *    must be free'd by the caller. If `len' is provided the destination
 *    buffer is allocated that large. If zero then the size is approximated.
 *
 ***/
unsigned char *silc_mp_mp2bin(SilcMPInt val, uint32 len, uint32 *ret_len);

/****f* silcmath/SilcMPAPI/silc_mp_mp2bin_noalloc
 *
 * SYNOPSIS
 *
 *    void silc_mp_mp2bin_noalloc(SilcMPAPI val, unsigned char *dst,
 *                                uint32 dst_len);
 *
 * DESCRIPTION
 *
 *    Same as silc_mp_mp2bin but does not allocate any memory.  The
 *    encoded data is returned into `dst' and it's length to the `ret_len'.
 *
 ***/
void silc_mp_mp2bin_noalloc(SilcMPAPI val, unsigned char *dst,
			    uint32 dst_len);

/****f* silcmath/SilcMPAPI/silc_mp_bin2mp
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

/****f* silcmath/SilcMPAPI/silc_mp_set
 *
 * SYNOPSIS
 *
 *    void silc_mp_set(SilcMPInt dst, SilcMPInt src);
 *
 * DESCRIPTION
 *
 *    Set `dst' integer from `src' integer.
 *
 ***/
void silc_mp_set(SilcMPInt dst, SilcMPInt src);

void silc_mp_set_ui(SilcMPInt dst, uint32 ui);
void silc_mp_set_ui64(SilcMPInt dst, uint64 ui);
void silc_mp_set_si(SilcMPInt dst, uint32 ui);
void silc_mp_set_si64(SilcMPInt dst, uint64 ui);
void silc_mp_set_str(SilcMPInt dst, const char *str, int base);
size_t silc_mp_size(SilcMPInt mp);
size_t silc_mp_sizeinbase(SilcMPInt mp, int base);
void silc_mp_sqrt(SilcMPInt dst, SilcMPInt src);
void silc_mp_sub(SilcMPInt dst, SilcMPInt mp1, SilcMPInt mp2);
void silc_mp_sub_ui(SilcMPInt dst, SilcMPInt mp1, uint32 ui);

#endif /* 1 */

#endif
