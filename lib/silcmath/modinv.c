/*

  modinv.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

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

/* Table for finding multiplicative inverse */
typedef struct {
  SilcMPInt x;
} ModInv;

#define plus1 	(i == 2 ? 0 : i + 1)
#define minus1 	(i == 0 ? 2 : i - 1)

/* Find multiplicative inverse using Euclid's extended algorithm.
   Computes inverse such that a * inv mod n = 1, where 0 < a < n.
   Algorithm goes like this:

   g(0) = n    v(0) = 0
   g(1) = a    v(1) = 1

   y = g(i-1) / g(i)
   g(i+1) = g(i-1) - y * g(i) = g(i)-1 mod g(i)
   v(i+1) = v(i-1) - y * v(i)

   do until g(i) = 0, then inverse = v(i-1). If inverse is negative then n,
   is added to inverse making it positive again. (Sometimes the algorithm
   has a variable u defined too and it behaves just like v, except that
   initalize values are swapped (i.e. u(0) = 1, u(1) = 0). However, u is
   not needed by the algorithm so it does not have to be included.)
*/

void silc_mp_modinv(SilcMPInt *inv, SilcMPInt *a, SilcMPInt *n)
{
  int i;
  SilcMPInt y;
  SilcMPInt x;

  ModInv g[3];
  ModInv v[3];

  /* init MP vars */
  silc_mp_init(&y);
  silc_mp_init(&x);
  silc_mp_init(&v[0].x);
  silc_mp_init(&v[1].x);
  silc_mp_set_ui(&v[0].x, 0L);	       	/* v(0) = 0 */
  silc_mp_set_ui(&v[1].x, 1L);	       	/* v(1) = 1 */
  silc_mp_init(&v[2].x);
  silc_mp_init(&g[0].x);
  silc_mp_init(&g[1].x);
  silc_mp_set(&g[0].x, n);     		/* g(0) = n */
  silc_mp_set(&g[1].x, a);	       	/* g(1) = a */
  silc_mp_init(&g[2].x);

  i = 1;
  while(silc_mp_cmp_ui(&g[i].x, 0) != 0) {
    silc_mp_div(&y, &g[minus1].x, &g[i].x);    	/* y = n / a */
    silc_mp_mod(&g[plus1].x, &g[minus1].x, &g[i].x); /* remainder */
    silc_mp_mul(&x, &y, &v[i].x);
    silc_mp_set(&v[plus1].x, &v[minus1].x);
    silc_mp_sub(&v[plus1].x, &v[plus1].x, &x);
    i = plus1;
  }

  /* set the inverse */
  silc_mp_set(inv, &v[minus1].x);

  /* if inverse is negative, add n to inverse */
  if (silc_mp_cmp_ui(inv, 0) < 0)
    silc_mp_add(inv, inv, n);

  /* clear the vars */
  memset(&g, 0, sizeof(g));
  memset(&v, 0, sizeof(v));
  silc_mp_uninit(&y);
  silc_mp_uninit(&x);
  silc_mp_uninit(&g[0].x);
  silc_mp_uninit(&g[1].x);
  silc_mp_uninit(&g[2].x);
  silc_mp_uninit(&v[0].x);
  silc_mp_uninit(&v[1].x);
  silc_mp_uninit(&v[2].x);
}
