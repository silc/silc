/*

  mp_tma.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

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
#include "mp_tma.h"

void silc_mp_init(SilcMPInt *mp)
{
  (void)mp_init(mp);
}

bool silc_mp_sinit(SilcStack stack, SilcMPInt *mp)
{
  /* XXX TODO */
  mp_init(mp);
  return TRUE;
}

void silc_mp_uninit(SilcMPInt *mp)
{
  mp_clear(mp);
}

size_t silc_mp_size(SilcMPInt *mp)
{
  return mp_unsigned_bin_size(mp);
}

size_t silc_mp_sizeinbase(SilcMPInt *mp, int base)
{
  int size = 0;
  mp_radix_size(mp, base, &size);
  if (size > 1)
    size--;
  return size;
}

void silc_mp_set(SilcMPInt *dst, SilcMPInt *src)
{
  (void)mp_copy(src, dst);
}

void silc_mp_set_ui(SilcMPInt *dst, SilcUInt32 ui)
{
  (void)mp_set_int(dst, ui);
}

void silc_mp_set_si(SilcMPInt *dst, SilcInt32 si)
{
  (void)mp_set_int(dst, si);
}

void silc_mp_set_str(SilcMPInt *dst, const char *str, int base)
{
  (void)mp_read_radix(dst, str, base);
}

SilcUInt32 silc_mp_get_ui(SilcMPInt *mp)
{
  return (SilcUInt32)mp_get_int(mp);
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

void silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mp_add_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_sub(mp1, mp2, dst);
}

void silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  (void)mp_sub_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_mul(mp1, mp2, dst);
}

void silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  (void)mp_mul_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  (void)mp_mul_2d(mp1, exp, dst);
}

void silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src)
{
  (void)mp_sqrt(src, dst);
}

void silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_div(mp1, mp2, dst, NULL);
}

void silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  (void)mp_div_d(mp1, (mp_digit)ui, dst, NULL);
}

void silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  (void)mp_div(mp1, mp2, q, r);
}

void silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  (void)mp_div_2d(mp1, exp, dst, NULL);
}

void silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
			 SilcUInt32 exp)
{
  (void)mp_div_2d(mp1, exp, q, r);
}

void silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_mod(mp1, mp2, dst);
}

void silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mp_digit d;
  (void)mp_mod_d(mp1, ui, &d);
  silc_mp_set_ui(dst, d);
}

void silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  (void)mp_mod_2d(mp1, ui, dst);
}

void silc_mp_pow(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp)
{
  SILC_NOT_IMPLEMENTED("silc_mp_pow");
  assert(FALSE);
}

void silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  (void)mp_expt_d(mp1, (mp_digit)exp, dst);
}

void silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp,
		     SilcMPInt *mod)
{
  (void)mp_exptmod(mp1, exp, mod, dst);
}

void silc_mp_pow_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp,
			SilcMPInt *mod)
{
  SilcMPInt tmp;
  silc_mp_init(&tmp);
  silc_mp_set_ui(&tmp, exp);
  silc_mp_pow_mod(dst, mp1, &tmp, mod);
  silc_mp_uninit(&tmp);
}

void silc_mp_gcd(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_gcd(mp1, mp2, dst);
}

void silc_mp_gcdext(SilcMPInt *g, SilcMPInt *s, SilcMPInt *t, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  (void)mp_exteuclid(mp1, mp2, s, t, g);
}

int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2)
{
  return mp_cmp(mp1, mp2);
}

int silc_mp_cmp_si(SilcMPInt *mp1, SilcInt32 si)
{
  return mp_cmp_d(mp1, si);
}

int silc_mp_cmp_ui(SilcMPInt *mp1, SilcUInt32 ui)
{
  return mp_cmp_d(mp1, ui);
}

void silc_mp_abs(SilcMPInt *dst, SilcMPInt *src)
{
  (void)mp_abs(src, dst);
}

void silc_mp_neg(SilcMPInt *dst, SilcMPInt *src)
{
  (void)mp_neg(src, dst);
}

void silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_and(mp1, mp2, dst);
}

void silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_or(mp1, mp2, dst);
}

void silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  (void)mp_xor(mp1, mp2, dst);
}
