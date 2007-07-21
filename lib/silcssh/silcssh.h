/*

  silcssh.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcssh/SILC SSH Interface
 *
 * DESCRIPTION
 *
 * SILC SSH Library provides SSH2 public key and private key support for
 * applications.  The SILC SSH Library has been integrated to the SILC Crypto
 * Toolkit allowing easy use of the SSH keys through the SILC PKCS API.  The
 * interface provides also a low level API to directly manipulate the SSH
 * keys.
 *
 * The library supports creation of new SSH2 key pairs, encryption, decryption,
 * signatures and verification.  Both RSA and DSS SSH2 keys are supported.
 * The library supports the standard SSH2 public key file format defined
 * in RFC 4716 and the OpenSSH public key file format.  The private key file
 * format support includes OpenSSH private key files.
 *
 * EXAMPLE
 *
 * SilcPublicKey public_key;
 * SilcPrivateKey private_key;
 * SilcSshPublicKey ssh_pubkey;
 * SilcSshPrivateKey ssh_privkey;
 *
 * // Generate new SSH2 key pair, RSA algorithm, 2048 bits
 * silc_ssh_generate_key("rsa", 2048, rng, "foo@example.com",
 *                       &public_key, &private_key);
 *
 * // Add (optional) headers to the key before saving to a file
 * ssh_pubkey = silc_pkcs_public_key_get_pkcs(SILC_PKCS_SSH2, public_key);
 * silc_ssh_public_key_set_type(ssh_pubkey, SILC_SSH_KEY_SSH2);
 * silc_ssh_public_key_add_field(ssh_pubkey, "Comment", "My own key");
 *
 * // Rest of the operations use standard SILC PKCS API
 *
 * // Save new key pair to file
 * silc_pkcs_save_public_key("pubkey.pub", public_key, SILC_PKCS_FILE_BASE64);
 * silc_pkcs_save_private_key("privkey.pub", private_key, passphrase,
 *                            passphrase_len, SILC_PKCS_FILE_BASE64, rng);
 *
 * // Load SSH2 key pair
 * silc_pkcs_load_public_key("pubkey.pub", SILC_PKCS_SSH2, &public_key);
 * silc_pkcs_load_private_key("privkey.pub", passphrase, passphrase_len,
 *                            SILC_PKCS_SSH2, &public_key);
 *
 * // Free public and private key. Frees automatically the underlaying SSH keys.
 * silc_pkcs_public_key_free(public_key);
 * silc_pkcs_private_key_free(private_key);
 *
 ***/
#ifndef SILCSSH_H
#define SILCSSH_H

/****d* silcssh/SilcSshAPI/SilcSshKeyType
 *
 * NAME
 *
 *    typedef enum { ... } SilcSshKeyType;
 *
 * DESCRIPTION
 *
 *    SSH2 public and private key types.  The default when new key pair
 *    is created is SILC_SSH_KEY_OPENSSH.
 *
 * SOURCE
 */
typedef enum {
  SILC_SSH_KEY_OPENSSH   = 1,	   /* OpenSSH public/private key (default) */
  SILC_SSH_KEY_SSH2      = 2,	   /* SSH2 public key, RFC 4716 */
} SilcSshKeyType;

/****s* silcssh/SilcSshAPI/SilcSshPublicKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSshPublicKey;
 *
 * DESCRIPTION
 *
 *    This structure defines the SSH2 public key.  This context can be
 *    retrieved from SilcPublicKey by calling silc_pkcs_public_key_get_pkcs
 *    for the PKCS type SILC_PKCS_SSH2.
 *
 * SOURCE
 */
typedef struct SilcSshPublicKeyStruct  {
  SilcHashTable fields;		   /* Public key headers */
  const SilcPKCSAlgorithm *pkcs;   /* PKCS Algorithm */
  void *public_key;		   /* PKCS Algorithm specific public key */
  SilcSshKeyType type;		   /* Public key type */
} *SilcSshPublicKey;
/***/

/****s* silcssh/SilcSshAPI/SilcSshPrivateKey
 *
 * NAME
 *
 *    typedef struct { ... } *SilcSshPrivateKey;
 *
 * DESCRIPTION
 *
 *    This structure defines the SSH2 private key.  This context can be
 *    retrieved from SilcPrivateKey by calling silc_pkcs_private_key_get_pkcs
 *    for the PKCS type SILC_PKCS_SSH2.
 *
 * SOURCE
 */
typedef struct SilcSshPrivateKeyStruct  {
  SilcHashTable fields;		   /* Private key headers */
  const SilcPKCSAlgorithm *pkcs;   /* PKCS Algorithm */
  void *private_key;		   /* PKCS Algorithm specific private key */
  SilcSshKeyType type;		   /* Private key type */
} *SilcSshPrivateKey;
/***/

/****f* silcssh/SilcSshAPI/silc_ssh_generate_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_ssh_generate_key(const char *algorithm,
 *                                   int bits_len, SilcRng rng,
 *                                   const char *subject,
 *                                   SilcPublicKey *ret_public_key,
 *                                   SilcPrivateKey *ret_private_key);
 *
 * DESCRIPTION
 *
 *    Generates new SSH2 key pair.  The `algorithm' is either rsa or dsa.
 *    The `bits_len' specify the key length in bits.  The `subject' is
 *    usually the email address of the user creating the key or some other
 *    similar subject name.  Returns FALSE on error.
 *
 * EXAMPLE
 *
 *    silc_ssh_generate_key("dsa", 1024, rng, "foo@example.com",
 *                          &pubkey, &privkey);
 *
 ***/
SilcBool silc_ssh_generate_key(const char *algorithm,
			       int bits_len, SilcRng rng,
			       const char *subject,
			       SilcPublicKey *ret_public_key,
			       SilcPrivateKey *ret_private_key);

/****f* silcssh/SilcSshAPI/silc_ssh_public_key_decode
 *
 * SYNOPSIS
 *
 *    int silc_ssh_public_key_decode(unsigned char *key, SilcUInt32 key_len,
 *                                   SilcSshPublicKey *ret_public_key);
 *
 * DESCRIPTION
 *
 *    Decodes SSH Public Key indicated by `key' of length of `key_len'
 *    bytes.  The decoded public key is returned into the `ret_public_key'
 *    which the caller must free by calling the silc_ssh_public_key_free
 *    function.  This function expects the public key to be in raw binary
 *    format, without any public key file markers or headers.
 *
 *    This decodes SSH2 protocol compliant raw public key.
 *
 *    This function returns the number of bytes decoded from the public
 *    key buffer or 0 on error.
 *
 ***/
int silc_ssh_public_key_decode(unsigned char *key, SilcUInt32 key_len,
			       SilcSshPublicKey *ret_public_key);

/****f* silcssh/SilcSshAPI/silc_ssh_public_key_encode
 *
 * SYNOPSIS
 *
 *    unsigned char *silc_ssh_public_key_encode(SilcStack stack,
 *                                              SilcSshPublicKey public_key,
 *                                              SilcUInt32 *ret_key_len);
 *
 * DESCRIPTION
 *
 *    Encodes SSH Public key and returns the encoded buffer.  Caller must
 *    free the returned buffer.
 *
 *    This encodes SSH2 protocol compliant raw public key.
 *
 *    If the `stack' is non-NULL the returned buffer is allocated from the
 *    `stack'.  This call will consume `stack' so caller should push the stack
 *    before calling and then later pop it.
 *
 ***/
unsigned char *silc_ssh_public_key_encode(SilcStack stack,
					  SilcSshPublicKey public_key,
					  SilcUInt32 *ret_key_len);

/****f* silcssh/SilcSshAPI/silc_ssh_public_key_free
 *
 * SYNOPSIS
 *
 *    void silc_ssh_public_key_free(SilcSshPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Frees the public key.  This need to be called only if you called
 *    silc_ssh_public_key_decode.  SSH public keys allocated through the
 *    SILC PKCS API can be freed by calling silc_pkcs_public_key_free.
 *
 ***/
void silc_ssh_public_key_free(SilcSshPublicKey public_key);

/****f* silcssh/SilcSshAPI/silc_ssh_public_key_get_field
 *
 * SYNOPSIS
 *
 *    const char *silc_ssh_public_key_get_field(SilcSshPublicKey public_key,
 *                                              const char *field);
 *
 * DESCRIPTION
 *
 *    Returns public key header field `field' value from the public key or
 *    NULL if such header field was not present in the public key.
 *
 * EXAMPLE
 *
 *    subject = silc_ssh_public_key_get_field(public_key, "Subject");
 *    comment = silc_ssh_public_key_get_field(public_key, "Comment");
 *
 ***/
const char *silc_ssh_public_key_get_field(SilcSshPublicKey public_key,
					  const char *field);

/****f* silcssh/SilcSshAPI/silc_ssh_public_key_add_field
 *
 * SYNOPSIS
 *
 *    SilcBool silc_ssh_public_key_add_field(SilcSshPublicKey public_key,
 *                                           const char *field,
 *                                           const char *value);
 *
 * DESCRIPTION
 *
 *    Add new public key header field and value to public key.  Returns
 *    FALSE if field could not be added or has been added already.
 *
 ***/
SilcBool silc_ssh_public_key_add_field(SilcSshPublicKey public_key,
				       const char *field,
				       const char *value);

/****f* silcssh/SilcSshAPI/silc_ssh_public_key_set_type
 *
 * SYNOPSIS
 *
 *    void silc_ssh_public_key_set_type(SilcSshPublicKey public_key,
 *                                      SilcSshKeyType type);
 *
 * DESCRIPTION
 *
 *    Set the type of the SSH public key.  This affects the format of the
 *    public key file when `public_key' is saved to a file.  If this is
 *    not called the default type is always SILC_SSH_KEY_OPENSSH.
 *
 ***/
void silc_ssh_public_key_set_type(SilcSshPublicKey public_key,
				  SilcSshKeyType type);

#include "silcssh_i.h"

#endif /* SILCSSH_H */
