/*

  silcpkcs.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCPKCS_H
#define SILCPKCS_H

/****h* silccrypt/SILC PKCS Interface
 *
 * DESCRIPTION
 *
 *    This is the interface for public key cryptosystems, and various
 *    utility functions related to public keys and private keys.  This
 *    interface also defines the actual PKCS objects, public keys and
 *    private keys.  The interface is generic PKCS interface, which has
 *    capability of supporting any kind of public key algorithm.  This
 *    interface also implements the SILC Public Key and routines for
 *    encoding and decoding SILC Public Key (as defined by the SILC
 *    protocol specification).  Interface or encrypting, decrypting,
 *    producing digital signatures and verifying digital signatures are
 *    also defined in this header.
 *
 ***/

/****s* silccrypt/SilcPKCSAPI/SilcPKCS
 *
 * NAME
 * 
 *    typedef struct SilcPKCSStruct *SilcPKCS;
 *
 * DESCRIPTION
 *
 *    This context is the actual PKCS context and is allocated
 *    by silc_pkcs_alloc and given as argument usually to all
 *    silc_pkcs _* functions.  It is freed by the silc_pkcs_free
 *    function.
 *
 ***/
typedef struct SilcPKCSStruct *SilcPKCS;

/* The default SILC PKCS (Public Key Cryptosystem) object to represent
   any PKCS in SILC. */
typedef struct SilcPKCSObjectStruct {
  char *name;
  int (*init)(void *, SilcUInt32, SilcRng);
  void (*clear_keys)(void *);
  unsigned char *(*get_public_key)(void *, SilcUInt32 *);
  unsigned char *(*get_private_key)(void *, SilcUInt32 *);
  SilcUInt32 (*set_public_key)(void *, unsigned char *, SilcUInt32);
  int (*set_private_key)(void *, unsigned char *, SilcUInt32);
  SilcUInt32 (*context_len)();
  int (*encrypt)(void *, unsigned char *, SilcUInt32,
		 unsigned char *, SilcUInt32 *);
  int (*decrypt)(void *, unsigned char *, SilcUInt32,
		 unsigned char *, SilcUInt32 *);
  int (*sign)(void *, unsigned char *, SilcUInt32,
	      unsigned char *, SilcUInt32 *);
  int (*verify)(void *, unsigned char *, SilcUInt32,
		unsigned char *, SilcUInt32);
} SilcPKCSObject;

/****s* silccrypt/SilcPKCSAPI/SilcPublicKey
 *
 * NAME
 * 
 *    typedef struct { ... } *SilcPublicKey;
 *
 * DESCRIPTION
 *
 *    SILC style public key object.  Public key is read from file to this
 *    object.  Public keys received from network must be in this format as 
 *    well.  The format is defined by the SILC protocol specification.
 *    This object is allocated by silc_pkcs_public_key_alloc and freed
 *    by silc_pkcs_public_key_free.  The object is given as argument to
 *    all silc_pkcs_public_key_* functions.
 *
 * SOURCE
 */
typedef struct {
  SilcUInt32 len;
  char *name;
  char *identifier;
  unsigned char *pk;
  SilcUInt32 pk_len;
} *SilcPublicKey;
/***/

/****s* silccrypt/SilcPKCSAPI/SilcPublicKeyIdentifier
 *
 * NAME
 * 
 *    typedef struct { ... } *SilcPublicKeyIdentifier;
 *
 * DESCRIPTION
 *
 *    Decoded SILC Public Key identifier.  Note that some of the fields 
 *    may be NULL.  This context is allcated by the function
 *    silc_pkcs_decode_identifier and freed by silc_pkcs_free_identifier.
 *    The identifier in SilcPublicKey is the 'identifier' field, which
 *    can be given as argument to silc_pkcs_decode_identifier.
 *
 * SOURCE
 */
typedef struct {
  char *username;
  char *host;
  char *realname;
  char *email;
  char *org;
  char *country;
} *SilcPublicKeyIdentifier;
/***/

/****s* silccrypt/SilcPKCSAPI/SilcPrivateKey
 *
 * NAME
 * 
 *    typedef struct { ... } *SilcPrivateKey;
 *
 * DESCRIPTION
 *
 *    SILC style private key object.  Public key is read from file to this
 *    object.  This object is allocated by silc_pkcs_private_key_alloc and
 *    freed by silc_pkcs_private_key_free.  The object is given as argument
 *    to all silc_pkcs_private_key_* functions.
 *
 ***/
typedef struct {
  char *name;
  unsigned char *prv;
  SilcUInt32 prv_len;
} *SilcPrivateKey;

/* Public and private key file headers */
#define SILC_PKCS_PUBLIC_KEYFILE_BEGIN "-----BEGIN SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PUBLIC_KEYFILE_END "\n-----END SILC PUBLIC KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_BEGIN "-----BEGIN SILC PRIVATE KEY-----\n"
#define SILC_PKCS_PRIVATE_KEYFILE_END "\n-----END SILC PRIVATE KEY-----\n"

/* Public and private key file encoding types */
#define SILC_PKCS_FILE_BIN 0
#define SILC_PKCS_FILE_PEM 1

/* Marks for all PKCS in silc. This can be used in silc_pkcs_unregister
   to unregister all PKCS at once. */
#define SILC_ALL_PKCS ((SilcPKCSObject *)1)

/* Static list of PKCS for silc_pkcs_register_default(). */
extern DLLAPI const SilcPKCSObject silc_default_pkcs[];

/* Default PKXS in the SILC protocol */
#define SILC_DEFAULT_PKCS "rsa"

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
   inline int silc_##pkcs##_init(void *context, SilcUInt32 keylen, \
                                 void *p1, void *p2)

   Now we wouldn't have to send the SilcRng object since the primes are 
   provided as arguments. To send them as void * they could actually be 
   used as in anyway for real (MP_INT (SilcMPInt) or even something else 
   (the pointer could be kludged to be something else in the module))
   (Plus, the SilcRng object management in prime generation would be
   simpler and better what it is now (in silcprimegen.c, that is)).
*/

#define SILC_PKCS_API_INIT(pkcs) \
int silc_##pkcs##_init(void *context, SilcUInt32 keylen, \
		       SilcRng rng)
#define SILC_PKCS_API_CLEAR_KEYS(pkcs) \
void silc_##pkcs##_clear_keys(void *context)
#define SILC_PKCS_API_GET_PUBLIC_KEY(pkcs) \
unsigned char *silc_##pkcs##_get_public_key(void *context, \
                                            SilcUInt32 *ret_len)
#define SILC_PKCS_API_GET_PRIVATE_KEY(pkcs) \
unsigned char *silc_##pkcs##_get_private_key(void *context, \
                                             SilcUInt32 *ret_len)
#define SILC_PKCS_API_SET_PUBLIC_KEY(pkcs) \
SilcUInt32 silc_##pkcs##_set_public_key(void *context, unsigned char *key_data, \
                                    SilcUInt32 key_len)
#define SILC_PKCS_API_SET_PRIVATE_KEY(pkcs) \
int silc_##pkcs##_set_private_key(void *context, unsigned char *key_data, \
                                  SilcUInt32 key_len)
#define SILC_PKCS_API_CONTEXT_LEN(pkcs) \
SilcUInt32 silc_##pkcs##_context_len()
#define SILC_PKCS_API_ENCRYPT(pkcs) \
int silc_##pkcs##_encrypt(void *context, \
			  unsigned char *src, \
			  SilcUInt32 src_len, \
			  unsigned char *dst, \
			  SilcUInt32 *dst_len)
#define SILC_PKCS_API_DECRYPT(pkcs) \
int silc_##pkcs##_decrypt(void *context, \
			  unsigned char *src, \
			  SilcUInt32 src_len, \
			  unsigned char *dst, \
			  SilcUInt32 *dst_len)
#define SILC_PKCS_API_SIGN(pkcs) \
int silc_##pkcs##_sign(void *context, \
		       unsigned char *src, \
		       SilcUInt32 src_len, \
		       unsigned char *dst, \
		       SilcUInt32 *dst_len)
#define SILC_PKCS_API_VERIFY(pkcs) \
int silc_##pkcs##_verify(void *context, \
			 unsigned char *signature, \
			 SilcUInt32 signature_len, \
			 unsigned char *data, \
			 SilcUInt32 data_len)

/* Prototypes */

/****f* silccrypt/SilcPKCSAPI/silc_pkcs_register
 *
 * SYNOPSIS
 *
 *    bool silc_pkcs_register(const SilcPKCSObject *pkcs);
 *
 * DESCRIPTION
 *
 *    Registers a new PKCS into the SILC.  This function is used
 *    at the initialization of the SILC.  All registered PKCSs
 *    should be unregistered with silc_pkcs_unregister.  The `pkcs' includes
 *    the name of the PKCS and member functions for the algorithm.  Usually
 *    this function is not called directly.  Instead, application can call
 *    the silc_pkcs_register_default to register all PKCSs that are
 *    builtin the sources.  Returns FALSE on error.
 *
 ***/
bool silc_pkcs_register(const SilcPKCSObject *pkcs);

bool silc_pkcs_unregister(SilcPKCSObject *pkcs);
bool silc_pkcs_register_default(void);
bool silc_pkcs_unregister_all(void);
bool silc_pkcs_alloc(const unsigned char *name, SilcPKCS *new_pkcs);
void silc_pkcs_free(SilcPKCS pkcs);
int silc_pkcs_is_supported(const unsigned char *name);
char *silc_pkcs_get_supported(void);
int silc_pkcs_generate_key(SilcPKCS pkcs, SilcUInt32 bits_key_len,
			   SilcRng rng);
SilcUInt32 silc_pkcs_get_key_len(SilcPKCS self);
const char *silc_pkcs_get_name(SilcPKCS pkcs);
unsigned char *silc_pkcs_get_public_key(SilcPKCS pkcs, SilcUInt32 *len);
unsigned char *silc_pkcs_get_private_key(SilcPKCS pkcs, SilcUInt32 *len);
SilcUInt32 silc_pkcs_public_key_set(SilcPKCS pkcs, SilcPublicKey public_key);
SilcUInt32 silc_pkcs_public_key_data_set(SilcPKCS pkcs, unsigned char *pk,
				     SilcUInt32 pk_len);
int silc_pkcs_private_key_set(SilcPKCS pkcs, SilcPrivateKey private_key);
int silc_pkcs_private_key_data_set(SilcPKCS pkcs, unsigned char *prv,
				   SilcUInt32 prv_len);
int silc_pkcs_encrypt(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		      unsigned char *dst, SilcUInt32 *dst_len);
int silc_pkcs_decrypt(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		      unsigned char *dst, SilcUInt32 *dst_len);
int silc_pkcs_sign(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		   unsigned char *dst, SilcUInt32 *dst_len);
int silc_pkcs_verify(SilcPKCS pkcs, unsigned char *signature, 
		     SilcUInt32 signature_len, unsigned char *data, 
		     SilcUInt32 data_len);
int silc_pkcs_sign_with_hash(SilcPKCS pkcs, SilcHash hash,
			     unsigned char *src, SilcUInt32 src_len,
			     unsigned char *dst, SilcUInt32 *dst_len);
int silc_pkcs_verify_with_hash(SilcPKCS pkcs, SilcHash hash, 
			       unsigned char *signature, 
			       SilcUInt32 signature_len, 
			       unsigned char *data, 
			       SilcUInt32 data_len);
char *silc_pkcs_encode_identifier(char *username, char *host, char *realname,
				  char *email, char *org, char *country);
SilcPublicKeyIdentifier silc_pkcs_decode_identifier(char *identifier);
void silc_pkcs_free_identifier(SilcPublicKeyIdentifier identifier);
SilcPublicKey silc_pkcs_public_key_alloc(const char *name, 
					 const char *identifier,
					 const unsigned char *pk, 
					 SilcUInt32 pk_len);
void silc_pkcs_public_key_free(SilcPublicKey public_key);
SilcPrivateKey silc_pkcs_private_key_alloc(const char *name,
					   const unsigned char *prv,
					   SilcUInt32 prv_len);
void silc_pkcs_private_key_free(SilcPrivateKey private_key);
unsigned char *
silc_pkcs_public_key_encode(SilcPublicKey public_key, SilcUInt32 *len);
unsigned char *
silc_pkcs_public_key_data_encode(unsigned char *pk, SilcUInt32 pk_len,
				 char *pkcs, char *identifier, 
				 SilcUInt32 *len);
int silc_pkcs_public_key_decode(unsigned char *data, SilcUInt32 data_len,
				SilcPublicKey *public_key);
bool silc_pkcs_public_key_compare(SilcPublicKey key1, SilcPublicKey key2);
SilcPublicKey silc_pkcs_public_key_copy(SilcPublicKey public_key);
unsigned char *
silc_pkcs_private_key_encode(SilcPrivateKey private_key, SilcUInt32 *len);
unsigned char *
silc_pkcs_private_key_data_encode(unsigned char *prv, SilcUInt32 prv_len,
				  char *pkcs, SilcUInt32 *len);
int silc_pkcs_private_key_decode(unsigned char *data, SilcUInt32 data_len,
				 SilcPrivateKey *private_key);
int silc_pkcs_save_public_key(char *filename, SilcPublicKey public_key,
			      SilcUInt32 encoding);
int silc_pkcs_save_public_key_data(char *filename, unsigned char *data,
				   SilcUInt32 data_len,
				   SilcUInt32 encoding);
int silc_pkcs_save_private_key(char *filename, SilcPrivateKey private_key, 
			       unsigned char *passphrase,
			       SilcUInt32 encoding);
int silc_pkcs_save_private_key_data(char *filename, unsigned char *data, 
				    SilcUInt32 data_len,
				    unsigned char *passphrase,
				    SilcUInt32 encoding);
int silc_pkcs_load_public_key(char *filename, SilcPublicKey *public_key,
			      SilcUInt32 encoding);
int silc_pkcs_load_private_key(char *filename, SilcPrivateKey *private_key,
			       SilcUInt32 encoding);

#endif /* SILCPKCS_H */
