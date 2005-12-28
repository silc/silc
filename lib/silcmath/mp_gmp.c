/*

  mp_gmp.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include <gmp.h>

void silc_mp_init(SilcMPInt *mp)
{
  mpz_init(mp);
}

void silc_mp_uninit(SilcMPInt *mp)
{
  mpz_clear(mp);
}

size_t silc_mp_size(SilcMPInt *mp)
{
  return mpz_size(mp);
}

size_t silc_mp_sizeinbase(SilcMPInt *mp, int base)
{
  return mpz_sizeinbase(mp, base);
}

void silc_mp_set(SilcMPInt *dst, SilcMPInt *src)
{
  mpz_set(dst, src);
}

void silc_mp_set_ui(SilcMPInt *dst, SilcUInt32 ui)
{
  mpz_set_ui(dst, ui);
}

void silc_mp_set_si(SilcMPInt *dst, SilcInt32 si)
{
  mpz_set_si(dst, si);
}

void silc_mp_set_str(SilcMPInt *dst, const char *str, int base)
{
  mpz_set_str(dst, str, base);
}

SilcUInt32 silc_mp_get_ui(SilcMPInt *mp)
{
  return (SilcUInt32)mpz_get_ui(mp);
}

char *silc_mp_get_str(char *str, SilcMPInt *mp, int base)
{
  return mpz_get_str(str, base, mp);
}

void silc_mp_add(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_add(dst, mp1, mp2);
}

void silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mpz_add_ui(dst, mp1, ui);
}

void silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_sub(dst, mp1, mp2);
}

void silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mpz_sub_ui(dst, mp1, ui);
}

void silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_mul(dst, mp1, mp2);
}

void silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mpz_mul_ui(dst, mp1, ui);
}

void silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  mpz_mul_2exp(dst, mp1, exp);
}

void silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src)
{
  mpz_sqrt(dst, src);
}

void silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_div(dst, mp1, mp2);
}

void silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mpz_div_ui(dst, mp1, ui);
}

void silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  if (q && r)
    mpz_fdiv_qr(q, r, mp1, mp2);
  if (q && !r)
    mpz_div(q, mp1, mp2);
  if (!q && r)
    mpz_mod(r, mp1, mp2);
}

void silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  mpz_fdiv_q_2exp(dst, mp1, exp);
}

void silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
			 SilcUInt32 exp)
{
  if (q)
    mpz_fdiv_q_2exp(q, mp1, exp);
  if (r)
    mpz_fdiv_r_2exp(r, mp1, exp);
}

void silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_mod(dst, mp1, mp2);
}

void silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mpz_mod_ui(dst, mp1, ui);
}

void silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mpz_mod_2exp(dst, mp1, ui);
}

void silc_mp_pow(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp)
{
  SilcUInt32 uiexp = mpz_get_ui(exp);
  mpz_pow_ui(dst, mp1, uiexp);
}

void silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  mpz_pow_ui(dst, mp1, exp);
}

void silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp,
		     SilcMPInt *mod)
{
  mpz_powm(dst, mp1, exp, mod);
}

void silc_mp_pow_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp,
			SilcMPInt *mod)
{
  mpz_powm_ui(dst, mp1, exp, mod);
}

void silc_mp_gcd(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_gcd(dst, mp1, mp2);
}

void silc_mp_gcdext(SilcMPInt *g, SilcMPInt *s, SilcMPInt *t, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  mpz_gcdext(g, s, t, mp1, mp2);
}

int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2)
{
  return mpz_cmp(mp1, mp2);
}

int silc_mp_cmp_si(SilcMPInt *mp1, SilcInt32 si)
{
  return mpz_cmp_si(mp1, si);
}

int silc_mp_cmp_ui(SilcMPInt *mp1, SilcUInt32 ui)
{
  return mpz_cmp_ui(mp1, ui);
}

void silc_mp_abs(SilcMPInt *dst, SilcMPInt *src)
{
  mpz_abs(dst, src);
}

void silc_mp_neg(SilcMPInt *dst, SilcMPInt *src)
{
  mpz_neg(dst, src);
}

void silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_and(dst, mp1, mp2);
}

void silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_ior(dst, mp1, mp2);
}

void silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpz_xor(dst, mp1, mp2);
}
