/*

  silcpkcs.h

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

#ifndef SILCPKCS_H
#define SILCPKCS_H

/* The default SILC PKCS (Public Key Cryptosystem) object to represent
   any PKCS in SILC. */
typedef struct SilcPKCSObjectStruct {
  unsigned char *name;
  void *data_context;

  int (*init)(void *, unsigned int, SilcRng);
  void (*clear_keys)(void *);
  unsigned char *(*get_public_key)(void *, unsigned int *);
  unsigned char *(*get_private_key)(void *, unsigned int *);
  int (*set_public_key)(void *, unsigned char *, unsigned int);
  int (*set_private_key)(void *, unsigned char *, unsigned int);
  unsigned int (*context_len)();
  unsigned int (*data_context_len)();
  int (*set_arg)(void *, void *, int, SilcInt);
  int (*encrypt)(void *, unsigned char *, unsigned int,
		 unsigned char *, unsigned int *);
  int (*decrypt)(void *, unsigned char *, unsigned int,
		 unsigned char *, unsigned int *);
  int (*sign)(void *, unsigned char *, unsigned int,
	      unsigned char *, unsigned int *);
  int (*verify)(void *, unsigned char *, unsigned int,
		unsigned char *, unsigned int);
} SilcPKCSObject;

/* The main SILC PKCS structure. Use SilcPKCS instead of SilcPKCSStruct.
   Also remember that SilcPKCS is a pointer. */
typedef struct SilcPKCSStruct {
  void *context;
  SilcPKCSObject *pkcs;
  unsigned int key_len;

  unsigned int (*get_key_len)(struct SilcPKCSStruct *);
} *SilcPKCS;

/* List of all PKCS in SILC. */
extern SilcPKCSObject silc_pkcs_list[];

/* Public and private key file headers */
#define SILC_PKCS_PUBLIC_KEYFILE_BEGIN "-----BEGIN SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PUBLIC_KEYFILE_END "\n-----END SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_BEGIN "-----BEGIN SILC PRIVATE KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_END "\n-----END SILC PRIVATE KEY-----\n"

/* Macros */

/* Macros used to implement the SILC PKCS API */

/* XXX: This needs slight redesigning. These needs to be made even
   more generic. I don't like that the actual prime generation is done
   in PKCS_API_INIT. The primes used in key generation should be sent
   as argument to the init function. By doing this we would achieve
   that PKCS could be used as SIM's. The only requirement would be
   that they are compiled against GMP (well, actually even that would
   not be a requirement, but the most generic case anyway). The new init 
   would look something like this:

   #define SILC_PKCS_API_INIT(pkcs) \
   inline int silc_##pkcs##_init(void *context, unsigned int keylen, \
                                 void *p1, void *p2)

   Now we wouldn't have to send the SilcRng object since the primes are 
   provided as arguments. To send them as void * they could actually be 
   used as in anyway for real (MP_INT (SilcInt) or even something else 
   (the pointer could be kludged to be something else in the module))
   (Plus, the SilcRng object management in prime generation would be
   simpler and better what it is now (in silcprimegen.c, that is)).
*/

#define SILC_PKCS_API_INIT(pkcs) \
int silc_##pkcs##_init(void *context, unsigned int keylen, \
		       SilcRng rng)
#define SILC_PKCS_API_CLEAR_KEYS(pkcs) \
void silc_##pkcs##_clear_keys(void *context)
#define SILC_PKCS_API_GET_PUBLIC_KEY(pkcs) \
unsigned char *silc_##pkcs##_get_public_key(void *context, \
                                            unsigned int *ret_len)
#define SILC_PKCS_API_GET_PRIVATE_KEY(pkcs) \
unsigned char *silc_##pkcs##_get_private_key(void *context, \
                                             unsigned int *ret_len)
#define SILC_PKCS_API_SET_PUBLIC_KEY(pkcs) \
int silc_##pkcs##_set_public_key(void *context, unsigned char *key_data, \
                                 unsigned int key_len)
#define SILC_PKCS_API_SET_PRIVATE_KEY(pkcs) \
int silc_##pkcs##_set_private_key(void *context, unsigned char *key_data, \
                                  unsigned int key_len)
#define SILC_PKCS_API_CONTEXT_LEN(pkcs) \
unsigned int silc_##pkcs##_context_len()
#define SILC_PKCS_API_DATA_CONTEXT_LEN(pkcs) \
unsigned int silc_##pkcs##_data_context_len()
#define SILC_PKCS_API_SET_ARG(pkcs) \
int silc_##pkcs##_set_arg(void *context, \
			  void *data_context, \
			  int argnum, \
			  SilcInt val)
#define SILC_PKCS_API_ENCRYPT(pkcs) \
int silc_##pkcs##_encrypt(void *context, \
			  unsigned char *src, \
			  unsigned int src_len, \
			  unsigned char *dst, \
			  unsigned int *dst_len)
#define SILC_PKCS_API_DECRYPT(pkcs) \
int silc_##pkcs##_decrypt(void *context, \
			  unsigned char *src, \
			  unsigned int src_len, \
			  unsigned char *dst, \
			  unsigned int *dst_len)
#define SILC_PKCS_API_SIGN(pkcs) \
int silc_##pkcs##_sign(void *context, \
		       unsigned char *src, \
		       unsigned int src_len, \
		       unsigned char *dst, \
		       unsigned int *dst_len)
#define SILC_PKCS_API_VERIFY(pkcs) \
int silc_##pkcs##_verify(void *context, \
			 unsigned char *signature, \
			 unsigned int signature_len, \
			 unsigned char *data, \
			 unsigned int data_len)

/* Prototypes */
int silc_pkcs_alloc(const unsigned char *name, SilcPKCS *new_pkcs);
void silc_pkcs_free(SilcPKCS pkcs);
int silc_pkcs_is_supported(const unsigned char *name);
char *silc_pkcs_get_supported();
unsigned int silc_pkcs_get_key_len(SilcPKCS self);
unsigned char *silc_pkcs_get_public_key(SilcPKCS pkcs, unsigned int *len);
unsigned char *silc_pkcs_get_private_key(SilcPKCS pkcs, unsigned int *len);
int silc_pkcs_set_public_key(SilcPKCS pkcs, unsigned char *pk, 
			     unsigned int pk_len);
int silc_pkcs_set_private_key(SilcPKCS pkcs, unsigned char *prv, 
			      unsigned int prv_len);
int silc_pkcs_save_public_key(SilcPKCS pkcs, char *filename,
			      unsigned char *pk, unsigned int pk_len);
int silc_pkcs_save_private_key(SilcPKCS pkcs, char *filename,
			       unsigned char *prv, unsigned int prv_len,
			       char *passphrase);
int silc_pkcs_load_public_key(char *filename, SilcPKCS *ret_pkcs);
int silc_pkcs_load_private_key(char *filename, SilcPKCS *ret_pkcs);

#endif
