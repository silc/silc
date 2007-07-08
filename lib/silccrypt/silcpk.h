/*

  silcpk.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccrypt/SILC Public Key Interface
 *
 * DESCRIPTION
 *
 * This interface implements the SILC protocol style public key, as defined
 * by the SILC protocol specification.
 *
 ***/

#ifndef SILCPK_H
#define SILCPK_H

/****s* silccrypt/SilcPubkeyAPI/SilcPublicKeyIdentifier
 *
 * NAME
 *
 *    typedef struct { ... } *SilcPublicKeyIdentifier,
 *                            SilcPublicKeyIdentifierStruct;
 *
 * DESCRIPTION
 *
 *    This structure contains the SILC Public Key identifier.  Note that
 *    some of the fields may be NULL.
 *
 * SOURCE
 */
typedef struct SilcPublicKeyIdentifierObject {
  char *username;
  char *host;
  char *realname;
  char *email;
  char *org;
  char *country;
  char *version;
} *SilcPublicKeyIdentifier, SilcPublicKeyIdentifierStruct;
/***/

/****s* silccrypt/SilcPubkeyAPI/SilcSILCPublicKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSILCPublicKey;
 *
 * DESCRIPTION
 *
 *    This structure defines the SILC protocol style public key.  User
 *    doesn't have to access this structure usually, except when access to
 *    the identifier is required.  The silc_pkcs_get_context for the
 *    PKCS type SILC_PKCS_SILC returns this context.
 *
 * SOURCE
 */
typedef struct SilcSILCPublicKeyStruct {
  SilcPublicKeyIdentifierStruct identifier;
  const SilcPKCSAlgorithm *pkcs;   /* PKCS algorithm */
  void *public_key;	           /* PKCS algorithm specific public key */
} *SilcSILCPublicKey;
/***/

/****s* silccrypt/SilcPubkeyAPI/SilcSILCPrivateKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSILCPrivateKey;
 *
 * DESCRIPTION
 *
 *    This structure defines the SILC protocol implementation specific
 *    private key.  This structure isn't usually needed by the user.
 *
 * SOURCE
 */
typedef struct SilcSILCPrivateKeyStruct {
  const SilcPKCSAlgorithm *pkcs;   /* PKCS algorithm */
  void *private_key;	           /* PKCS algorithm specific private key */
} *SilcSILCPrivateKey;
/***/

/****f* silccrypt/SilcPubkeyAPI/silc_pkcs_silc_generate_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_silc_generate_key(const char *algorithm,
 *                                         SilcUInt32 bits_key_len,
 *                                         const char *identifier,
 *                                         SilcRng rng,
 *                                         SilcPublicKey *ret_public_key,
 *                                         SilcPrivateKey *ret_private_key)
 *
 * DESCRIPTION
 *
 *    Generate a new SILC key pair of the algorithm type `algorithm' with
 *    the key length in bits of `bits_key_len'.  The `scheme' may be NULL.
 *    Returns FALSE if key generation failed.
 *
 * EXAMPLE
 *
 *    // Generate RSA key pair with 2048 bit key length
 *    silc_pkcs_silc_generate_key("rsa", 2048, ident_string, rng,
 *                                &public_key, &private_key);
 *
 ***/
SilcBool silc_pkcs_silc_generate_key(const char *algorithm,
				     SilcUInt32 bits_key_len,
				     const char *identifier,
				     SilcRng rng,
				     SilcPublicKey *ret_public_key,
				     SilcPrivateKey *ret_private_key);

/****f* silccrypt/SilcPubkeyAPI/silc_pkcs_silc_encode_identifier
 *
 * SYNOPSIS
 *
 *    char *silc_pkcs_silc_encode_identifier(char *username, char *host,
 *                                           char *realname, char *email,
 *                                           char *org, char *country,
 *                                           char *version);
 *
 * DESCRIPTION
 *
 *    Encodes and returns SILC public key identifier.  If some of the
 *    arguments are NULL those are not encoded into the identifier string.
 *    Protocol says that at least username and host must be provided.
 *    Caller must free the returned identifier string.
 *
 *    If `stack' is non-NULL the returned string is allocated from `stack'.
 *
 ***/
char *silc_pkcs_silc_encode_identifier(SilcStack stack,
				       char *username, char *host,
				       char *realname, char *email,
				       char *org, char *country,
				       char *version);

/****f* silccrypt/SilcPubkeyAPI/silc_pkcs_silc_decode_identifier
 *
 * SYNOPSIS
 *
 *    SilcBool silc_pkcs_silc_decode_identifier(const char *identifier,
 *                                              SilcPublicKeyIdentifier ident);
 *
 * DESCRIPTION
 *
 *    Decodes SILC protocol public key identifier `identifier' into the
 *    the `ident' structure.  Returns FALSE if the identifier is not valid
 *    identifier string.
 *
 ***/
SilcBool silc_pkcs_silc_decode_identifier(const char *identifier,
					  SilcPublicKeyIdentifier ident);

/****f* silccrypt/SilcPubkeyAPI/silc_pkcs_silc_public_key_version
 *
 * SYNOPSIS
 *
 *    int silc_pkcs_silc_public_key_version(SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Returns the verison of the SILC Public Key indicated by `public_key'.
 *    Returns -1 if the `public_key' is not a SILC Public Key and the
 *    version number otherwise.
 *
 ***/
int silc_pkcs_silc_public_key_version(SilcPublicKey public_key);

#endif /* SILCPK_H */
