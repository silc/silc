/*

  silcmp.h

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

#ifndef SILCMP_H
#define SILCMP_H

#include "gmp.h"

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

#endif
