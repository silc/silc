/*

  silcpkcs.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
  char *name;
  void *data_context;

  int (*init)(void *, uint32, SilcRng);
  void (*clear_keys)(void *);
  unsigned char *(*get_public_key)(void *, uint32 *);
  unsigned char *(*get_private_key)(void *, uint32 *);
  uint32 (*set_public_key)(void *, unsigned char *, uint32);
  int (*set_private_key)(void *, unsigned char *, uint32);
  uint32 (*context_len)();
  uint32 (*data_context_len)();
  int (*set_arg)(void *, void *, int, SilcInt);
  int (*encrypt)(void *, unsigned char *, uint32,
		 unsigned char *, uint32 *);
  int (*decrypt)(void *, unsigned char *, uint32,
		 unsigned char *, uint32 *);
  int (*sign)(void *, unsigned char *, uint32,
	      unsigned char *, uint32 *);
  int (*verify)(void *, unsigned char *, uint32,
		unsigned char *, uint32);
} SilcPKCSObject;

/* The main SILC PKCS structure. Use SilcPKCS instead of SilcPKCSStruct.
   Also remember that SilcPKCS is a pointer. */
typedef struct SilcPKCSStruct {
  void *context;
  SilcPKCSObject *pkcs;
  uint32 key_len;

  uint32 (*get_key_len)(struct SilcPKCSStruct *);
} *SilcPKCS;

/* List of all PKCS in SILC. */
extern SilcPKCSObject silc_pkcs_list[];

/* SILC style public key object. Public key is read from file to this
   object. Public keys received from network must be in this format as 
   well. */
typedef struct {
  uint32 len;
  char *name;
  char *identifier;
  unsigned char *pk;
  uint32 pk_len;
} *SilcPublicKey;

/* SILC style private key object. Private key is read from file to this
   object. */
typedef struct {
  char *name;
  unsigned char *prv;
  uint32 prv_len;
} *SilcPrivateKey;

/* Decoded SILC Public Key identifier. Note that some of the fields 
   may be NULL. */
typedef struct {
  char *username;
  char *host;
  char *realname;
  char *email;
  char *org;
  char *country;
} *SilcPublicKeyIdentifier;

/* Public and private key file headers */
#define SILC_PKCS_PUBLIC_KEYFILE_BEGIN "-----BEGIN SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PUBLIC_KEYFILE_END "\n-----END SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_BEGIN "-----BEGIN SILC PRIVATE KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_END "\n-----END SILC PRIVATE KEY-----\n"

/* Public and private key file encoding types */
#define SILC_PKCS_FILE_BIN 0
#define SILC_PKCS_FILE_PEM 1

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
   inline int silc_##pkcs##_init(void *context, uint32 keylen, \
                                 void *p1, void *p2)

   Now we wouldn't have to send the SilcRng object since the primes are 
   provided as arguments. To send them as void * they could actually be 
   used as in anyway for real (MP_INT (SilcInt) or even something else 
   (the pointer could be kludged to be something else in the module))
   (Plus, the SilcRng object management in prime generation would be
   simpler and better what it is now (in silcprimegen.c, that is)).
*/

#define SILC_PKCS_API_INIT(pkcs) \
int silc_##pkcs##_init(void *context, uint32 keylen, \
		       SilcRng rng)
#define SILC_PKCS_API_CLEAR_KEYS(pkcs) \
void silc_##pkcs##_clear_keys(void *context)
#define SILC_PKCS_API_GET_PUBLIC_KEY(pkcs) \
unsigned char *silc_##pkcs##_get_public_key(void *context, \
                                            uint32 *ret_len)
#define SILC_PKCS_API_GET_PRIVATE_KEY(pkcs) \
unsigned char *silc_##pkcs##_get_private_key(void *context, \
                                             uint32 *ret_len)
#define SILC_PKCS_API_SET_PUBLIC_KEY(pkcs) \
uint32 silc_##pkcs##_set_public_key(void *context, unsigned char *key_data, \
                                    uint32 key_len)
#define SILC_PKCS_API_SET_PRIVATE_KEY(pkcs) \
int silc_##pkcs##_set_private_key(void *context, unsigned char *key_data, \
                                  uint32 key_len)
#define SILC_PKCS_API_CONTEXT_LEN(pkcs) \
uint32 silc_##pkcs##_context_len()
#define SILC_PKCS_API_DATA_CONTEXT_LEN(pkcs) \
uint32 silc_##pkcs##_data_context_len()
#define SILC_PKCS_API_SET_ARG(pkcs) \
int silc_##pkcs##_set_arg(void *context, \
			  void *data_context, \
			  int argnum, \
			  SilcInt val)
#define SILC_PKCS_API_ENCRYPT(pkcs) \
int silc_##pkcs##_encrypt(void *context, \
			  unsigned char *src, \
			  uint32 src_len, \
			  unsigned char *dst, \
			  uint32 *dst_len)
#define SILC_PKCS_API_DECRYPT(pkcs) \
int silc_##pkcs##_decrypt(void *context, \
			  unsigned char *src, \
			  uint32 src_len, \
			  unsigned char *dst, \
			  uint32 *dst_len)
#define SILC_PKCS_API_SIGN(pkcs) \
int silc_##pkcs##_sign(void *context, \
		       unsigned char *src, \
		       uint32 src_len, \
		       unsigned char *dst, \
		       uint32 *dst_len)
#define SILC_PKCS_API_VERIFY(pkcs) \
int silc_##pkcs##_verify(void *context, \
			 unsigned char *signature, \
			 uint32 signature_len, \
			 unsigned char *data, \
			 uint32 data_len)

/* Prototypes */
int silc_pkcs_alloc(const unsigned char *name, SilcPKCS *new_pkcs);
void silc_pkcs_free(SilcPKCS pkcs);
int silc_pkcs_is_supported(const unsigned char *name);
char *silc_pkcs_get_supported();
uint32 silc_pkcs_get_key_len(SilcPKCS self);
unsigned char *silc_pkcs_get_public_key(SilcPKCS pkcs, uint32 *len);
unsigned char *silc_pkcs_get_private_key(SilcPKCS pkcs, uint32 *len);
uint32 silc_pkcs_public_key_set(SilcPKCS pkcs, SilcPublicKey public_key);
uint32 silc_pkcs_public_key_data_set(SilcPKCS pkcs, unsigned char *pk,
				     uint32 pk_len);
int silc_pkcs_private_key_set(SilcPKCS pkcs, SilcPrivateKey private_key);
int silc_pkcs_private_key_data_set(SilcPKCS pkcs, unsigned char *prv,
				   uint32 prv_len);
int silc_pkcs_encrypt(SilcPKCS pkcs, unsigned char *src, uint32 src_len,
		      unsigned char *dst, uint32 *dst_len);
int silc_pkcs_decrypt(SilcPKCS pkcs, unsigned char *src, uint32 src_len,
		      unsigned char *dst, uint32 *dst_len);
int silc_pkcs_sign(SilcPKCS pkcs, unsigned char *src, uint32 src_len,
		   unsigned char *dst, uint32 *dst_len);
int silc_pkcs_verify(SilcPKCS pkcs, unsigned char *signature, 
		     uint32 signature_len, unsigned char *data, 
		     uint32 data_len);
int silc_pkcs_sign_with_hash(SilcPKCS pkcs, SilcHash hash,
			     unsigned char *src, uint32 src_len,
			     unsigned char *dst, uint32 *dst_len);
int silc_pkcs_verify_with_hash(SilcPKCS pkcs, SilcHash hash, 
			       unsigned char *signature, 
			       uint32 signature_len, 
			       unsigned char *data, 
			       uint32 data_len);
char *silc_pkcs_encode_identifier(char *username, char *host, char *realname,
				  char *email, char *org, char *country);
SilcPublicKeyIdentifier silc_pkcs_decode_identifier(char *identifier);
void silc_pkcs_free_identifier(SilcPublicKeyIdentifier identifier);
SilcPublicKey silc_pkcs_public_key_alloc(char *name, char *identifier,
					 unsigned char *pk, 
					 uint32 pk_len);
void silc_pkcs_public_key_free(SilcPublicKey public_key);
SilcPrivateKey silc_pkcs_private_key_alloc(char *name, unsigned char *prv,
					   uint32 prv_len);
void silc_pkcs_private_key_free(SilcPrivateKey private_key);
unsigned char *
silc_pkcs_public_key_encode(SilcPublicKey public_key, uint32 *len);
unsigned char *
silc_pkcs_public_key_data_encode(unsigned char *pk, uint32 pk_len,
				 char *pkcs, char *identifier, 
				 uint32 *len);
int silc_pkcs_public_key_decode(unsigned char *data, uint32 data_len,
				SilcPublicKey *public_key);
unsigned char *
silc_pkcs_private_key_encode(SilcPrivateKey private_key, uint32 *len);
unsigned char *
silc_pkcs_private_key_data_encode(unsigned char *prv, uint32 prv_len,
				  char *pkcs, uint32 *len);
int silc_pkcs_private_key_decode(unsigned char *data, uint32 data_len,
				 SilcPrivateKey *private_key);
int silc_pkcs_save_public_key(char *filename, SilcPublicKey public_key,
			      uint32 encoding);
int silc_pkcs_save_public_key_data(char *filename, unsigned char *data,
				   uint32 data_len,
				   uint32 encoding);
int silc_pkcs_save_private_key(char *filename, SilcPrivateKey private_key, 
			       unsigned char *passphrase,
			       uint32 encoding);
int silc_pkcs_save_private_key_data(char *filename, unsigned char *data, 
				    uint32 data_len,
				    unsigned char *passphrase,
				    uint32 encoding);
int silc_pkcs_load_public_key(char *filename, SilcPublicKey *public_key,
			      uint32 encoding);
int silc_pkcs_load_private_key(char *filename, SilcPrivateKey *private_key,
			       uint32 encoding);

#endif
