/*

  silcdh.h 

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

/****h* silccrypt/SilcDH/silcdh.h
 *
 * DESCRIPTION
 *
 * PKCS #3 compliant Diffie Hellman key agreement protocol implementation.
 * This is used as part of SKE (SILC Key Exchange) protocol.
 *
 ***/

#ifndef SILCDH_H
#define SILCDH_H

#include "silcmp.h"

/****s* silccrypt/SilcDH/SilcDH
 *
 * NAME
 * 
 *    typedef struct SilcDHStruct *SilcDH;
 *
 * DESCRIPTION
 *
 *    This context is allocated by silc_dh_alloc and is given as argument
 *    to all silc_dh_* functions.  It is freed by silc_dh_free function.
 *
 ***/
typedef struct SilcDHStruct *SilcDH;

/* XXX Move to source file */
/* Diffie Hellman context. This includes the DH parameters including the
   negotiated key material. */
struct SilcDHStruct {
  SilcMPInt *g;		     /* Global base (generator) */
  SilcMPInt *p;		     /* Global prime (modulus, prime) */
  SilcMPInt *lpf;	     /* Largest prime factor (prime) */
  SilcMPInt *my_x;	     /* x, My private value (random) */
  SilcMPInt *my_y;	     /* y, My public value (y = g ^ x mod p) */
  SilcMPInt *your_y;	     /* y', Your public value (y' = g ^ x' mod p) */
  SilcMPInt *z;		     /* The computed secret key (z = y' ^ x mod p) */
};

/****f* silccrypt/SilcDH/silc_dh_alloc
 *
 * SYNOPSIS
 *    
 *    SilcDH silc_dh_alloc(SilcMPInt *g, SilcMPInt *p, SilcMPInt *lpf);
 * 
 * DESCRIPTION
 *
 *    Allocate SilcDH context. The `g' is the public base generator used
 *    in the negotiation, the `p' is the public prime used in the
 *    negotiation and the `lpf' is largest prime factor of p defined
 *    publicly as well. The `lpf' is optional and if it is not supplied
 *    then the private values generated satifies 0 < x < p - 1 instead
 *    of 0 < x < lpf. Returns NULL on error or allocated SilcDH context
 *    on success. 
 *
 ***/
SilcDH silc_dh_alloc(SilcMPInt *g, SilcMPInt *p, SilcMPInt *lpf);

/****f* silccrypt/SilcDH/silc_dh_free
 *
 * SYNOPSIS
 *
 *    void silc_dh_free(SilcDH dh);
 *
 * DESCRIPTION
 *
 *    Free the SilcDH context. Frees all the allocated data inside the 
 *    SilcDH context. 
 *
 ***/
void silc_dh_free(SilcDH dh);

/****f* silccrypt/SilcDH/silc_dh_generate_private
 *
 * SYNOPSIS
 *
 *    bool silc_dh_generate_private(SilcDH dh, const SilcMPInt **x);
 *
 * DESCRIPTION
 *
 *    Generates random private value `x' such that 0 < x < lpf at most of
 *    length of lpf. Returns FALSE if the random number could not be generated.
 *    Returns the generated value into `x' pointer sent as argument, unless
 *    the `x' is NULL. The returned `x' must not be freed by the caller. 
 *
 ***/
bool silc_dh_generate_private(SilcDH dh, const SilcMPInt **x);

/****f* silccrypt/SilcDH/silc_dh_compute_public
 *
 * SYNOPSIS
 *
 *    bool silc_dh_compute_public(SilcDH dh, const SilcMPInt **y);
 *
 * DESCRIPTION
 *
 *    Computes the public key y = g ^ x mod p, and returns it to the `y'
 *    pointer sent as argument, unless the `y' is NULL. Returns FALSE if
 *    the computation could not be performed. The returned `y' must not be
 *    freed by the caller. 
 *
 ***/
bool silc_dh_compute_public(SilcDH dh, const SilcMPInt **y);

/****f* silccrypt/SilcDH/silc_dh_remote_public
 *
 * SYNOPSIS
 *
 *    bool silc_dh_compute_public(SilcDH dh, SilcMPInt *y);
 *
 * DESCRIPTION
 *
 *    Sets the remote end's public value y' into the SilcDH context.
 *    This must be done before computing the secret key. Returns FALSE 
 *    on error. 
 *
 ***/
bool silc_dh_set_remote_public(SilcDH dh, SilcMPInt *y);

/****f* silccrypt/SilcDH/silc_dh_compute_key
 *
 * SYNOPSIS
 *
 *    bool silc_dh_compute_key(SilcDH dh, const SilcMPInt **z);
 *
 * DESCRIPTION
 *
 *    Computes the secret key z = y' ^ x mod p, and returns the key to the
 *    `z' pointer sent as argument, unless the `z' is NULL. Returns FALSE if
 *    the computation could not be performed. The returned `z' must not be
 *    freed by the caller. 
 *
 ***/
bool silc_dh_compute_key(SilcDH dh, const SilcMPInt **z);

/****f* silccrypt/SilcDH/silc_dh_remote_public
 *
 * SYNOPSIS
 *
 *    bool silc_dh_compute_key_data(SilcDH dh, unsigned char **z, 
 *                                  uint32 *z_len);
 *
 * DESCRIPTION
 *
 *    Same as above but returns the computed secret key as octet binary
 *    string.  The caller must free the returned binary string.
 *
 ***/
bool silc_dh_compute_key_data(SilcDH dh, unsigned char **z, 
			      uint32 *z_len);

#endif
