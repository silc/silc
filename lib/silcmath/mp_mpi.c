/*

  mp_mpi.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"
#include "mpi.h"
#include "mplogic.h"

void silc_mp_init(SilcMPInt *mp)
{
  (void)mp_init(mp);
}

void silc_mp_uninit(SilcMPInt *mp)
{
  (void)mp_clear(mp);
}

size_t silc_mp_size(SilcMPInt *mp)
{
  return mp_raw_size(mp);
}

size_t silc_mp_sizeinbase(SilcMPInt *mp, int base)
{
  return mp_radix_size(mp, base) - 2; /* XXX This is actually wrong since
					 this might produce wrong balue.
					 But, it looks like MPI always returns
					 correct value plus one, whereas
					 GMP returns always the right value. */
}

void silc_mp_set(SilcMPInt *dst, SilcMPInt *src)
{
  (void)mp_copy(src, dst);
}

void silc_mp_set_ui(SilcMPInt *dst, uint32 ui)
{
  mp_set(dst, ui);
}

void silc_mp_set_si(SilcMPInt *dst, int32 si)
{
  (void)mp_set_int(dst, si);
}

void silc_mp_set_str(SilcMPInt *dst, const char *str, int base)
{
  (void)mp_read_variable_radix(dst, str, base);
}

uint32 silc_mp_get_ui(SilcMPInt *mp)
{
  return (uint32)MP_DIGIT(mp, 0);
}

char *silc_mp_get_str(char *str, SilcMPInt *mp, int base)
{
  if (mp_toradix(mp, str, base) != MP_OKAY)
    return NULL;
  return str;
}

void silc_mp_add(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_add(mp1, mp2, dst);
}

void silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui)
{
  mp_add_d(mp1, ui, dst);
}

void silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_sub(mp1, mp2, dst);
}

void silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui)
{
  (void)mp_sub_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_mul(mp1, mp2, dst);
}

void silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui)
{
  (void)mp_mul_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp)
{
  SilcMPInt tmp;
  silc_mp_init(&tmp);
  (void)mp_2expt(&tmp, (mp_digit)exp);
  (void)mp_mul(mp1, &tmp, dst);
  silc_mp_uninit(&tmp);
}

void silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src)
{
  (void)mp_sqrt(src, dst);
}

void silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_div(mp1, mp2, dst, NULL);
}

void silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui)
{
  (void)mp_div_d(mp1, (mp_digit)ui, dst, NULL);
}

void silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1, 
		    SilcMPInt *mp2)
{
  (void)mp_div(mp1, mp2, q, r);
}

void silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp)
{
  SilcMPInt tmp;
  silc_mp_init(&tmp);
  (void)mp_2expt(&tmp, (mp_digit)exp);
  (void)mp_div(mp1, &tmp, dst, NULL);
  silc_mp_uninit(&tmp);
}

void silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1, 
			 uint32 exp)
{
  if (q) {
    (void)mp_2expt(q, (mp_digit)exp);
    (void)mp_div(mp1, q, q, r);
  }
}

void silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_mod(mp1, mp2, dst);
}

void silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui)
{
  mp_digit uidst;
  (void)mp_mod_d(mp1, (mp_digit)ui, &uidst);
  mp_set(dst, uidst);
}

void silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, uint32 ui)
{
  SilcMPInt tmp;
  silc_mp_init(&tmp);
  (void)mp_2expt(&tmp, (mp_digit)ui);
  (void)mp_mod(mp1, &tmp, dst);
  silc_mp_uninit(&tmp);
}

void silc_mp_pow(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp)
{
  (void)mp_expt(mp1, exp, dst);
}

void silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp)
{
  (void)mp_expt_d(mp1, (mp_digit)exp, dst);
}

void silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp, 
		     SilcMPInt *mod)
{
  (void)mp_exptmod(mp1, exp, mod, dst);
}

void silc_mp_pow_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, uint32 exp, 
			SilcMPInt *mod)
{
  (void)mp_exptmod_d(mp1, (mp_digit)exp, mod, dst);
}

void silc_mp_gcd(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_gcd(mp1, mp2, dst);
}

void silc_mp_gcdext(SilcMPInt *g, SilcMPInt *s, SilcMPInt *t, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  (void)mp_xgcd(mp1, mp2, g, s, t);
}

int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2)
{
  return mp_cmp(mp1, mp2);
}

int silc_mp_cmp_si(SilcMPInt *mp1, int32 si)
{
  return mp_cmp_int(mp1, (long)si);
}

int silc_mp_cmp_ui(SilcMPInt *mp1, uint32 ui)
{
  return mp_cmp_d(mp1, ui);
}

void silc_mp_abs(SilcMPInt *dst, SilcMPInt *src)
{
  mp_abs(src, dst);
}

void silc_mp_neg(SilcMPInt *dst, SilcMPInt *src)
{
  mp_neg(src, dst);
}

void silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpl_and(mp1, mp2, dst);
}

void silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpl_or(mp1, mp2, dst);
}

void silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  mpl_xor(mp1, mp2, dst);
}
