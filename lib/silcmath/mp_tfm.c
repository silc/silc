/*

  mp_tfm.c

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
#include "mp_tfm.h"

void silc_mp_init(SilcMPInt *mp)
{
  fp_init(mp);
}

void silc_mp_uninit(SilcMPInt *mp)
{
  fp_zero(mp);
}

size_t silc_mp_size(SilcMPInt *mp)
{
  return fp_unsigned_bin_size(mp);
}

size_t silc_mp_sizeinbase(SilcMPInt *mp, int base)
{
  int size = 0;
  fp_radix_size(mp, base, &size);
  if (size > 1)
    size--;
  return size;
}

void silc_mp_set(SilcMPInt *dst, SilcMPInt *src)
{
  fp_copy(src, dst);
}

void silc_mp_set_ui(SilcMPInt *dst, SilcUInt32 ui)
{
  fp_set(dst, ui);
}

void silc_mp_set_si(SilcMPInt *dst, SilcInt32 si)
{
  fp_set(dst, si);
}

void silc_mp_set_str(SilcMPInt *dst, const char *str, int base)
{
  fp_read_radix(dst, str, base);
}

SilcUInt32 silc_mp_get_ui(SilcMPInt *mp)
{
  SILC_NOT_IMPLEMENTED("silc_mp_get_ui");
  assert(FALSE);
}

char *silc_mp_get_str(char *str, SilcMPInt *mp, int base)
{
  if (fp_toradix(mp, str, base) != MP_OKAY)
    return NULL;
  return str;
}

void silc_mp_add(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  fp_add(mp1, mp2, dst);
}

void silc_mp_add_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  mp_add_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_sub(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  fp_sub(mp1, mp2, dst);
}

void silc_mp_sub_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  fp_sub_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_mul(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  fp_mul(mp1, mp2, dst);
}

void silc_mp_mul_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  fp_mul_d(mp1, (mp_digit)ui, dst);
}

void silc_mp_mul_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  fp_mul_2d(mp1, exp, dst);
}

void silc_mp_sqrt(SilcMPInt *dst, SilcMPInt *src)
{
  fp_sqrt(src, dst);
}

void silc_mp_div(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  fp_div(mp1, mp2, dst, NULL);
}

void silc_mp_div_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  fp_div_d(mp1, (mp_digit)ui, dst, NULL);
}

void silc_mp_div_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  fp_div(mp1, mp2, q, r);
}

void silc_mp_div_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  fp_div_2d(mp1, exp, dst, NULL);
}

void silc_mp_div_2exp_qr(SilcMPInt *q, SilcMPInt *r, SilcMPInt *mp1,
			 SilcUInt32 exp)
{
  fp_div_2d(mp1, exp, q, r);
}

void silc_mp_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  fp_mod(mp1, mp2, dst);
}

void silc_mp_mod_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  fp_digit d;
  fp_mod_d(mp1, ui, &d);
  silc_mp_set_ui(dst, d);
}

void silc_mp_mod_2exp(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 ui)
{
  fp_mod_2d(mp1, ui, dst);
}

void silc_mp_pow(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp)
{
  SILC_NOT_IMPLEMENTED("silc_mp_pow");
  assert(FALSE);
}

void silc_mp_pow_ui(SilcMPInt *dst, SilcMPInt *mp1, SilcUInt32 exp)
{
  SILC_NOT_IMPLEMENTED("silc_mp_pow_ui");
  assert(FALSE);
}

void silc_mp_pow_mod(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *exp,
		     SilcMPInt *mod)
{
  fp_exptmod(mp1, exp, mod, dst);
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
  fp_gcd(mp1, mp2, dst);
}

void silc_mp_gcdext(SilcMPInt *g, SilcMPInt *s, SilcMPInt *t, SilcMPInt *mp1,
		    SilcMPInt *mp2)
{
  SILC_NOT_IMPLEMENTED("silc_mp_gcdext");
  assert(FALSE);
}

int silc_mp_cmp(SilcMPInt *mp1, SilcMPInt *mp2)
{
  return fp_cmp(mp1, mp2);
}

int silc_mp_cmp_si(SilcMPInt *mp1, SilcInt32 si)
{
  return fp_cmp_d(mp1, si);
}

int silc_mp_cmp_ui(SilcMPInt *mp1, SilcUInt32 ui)
{
  return fp_cmp_d(mp1, ui);
}

void silc_mp_abs(SilcMPInt *dst, SilcMPInt *src)
{
  fp_abs(src, dst);
}

void silc_mp_neg(SilcMPInt *dst, SilcMPInt *src)
{
  fp_neg(src, dst);
}

void silc_mp_and(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  SILC_NOT_IMPLEMENTED("silc_mp_and");
  assert(FALSE);
}

void silc_mp_or(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  SILC_NOT_IMPLEMENTED("silc_mp_or");
  assert(FALSE);
}

void silc_mp_xor(SilcMPInt *dst, SilcMPInt *mp1, SilcMPInt *mp2)
{
  SILC_NOT_IMPLEMENTED("silc_mp_xor");
  assert(FALSE);
}
