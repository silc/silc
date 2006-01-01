/*

  silcapputil.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Application Utilities
 *
 * DESCRIPTION
 *
 * This interface provides utility functions for applications'
 * convenience.  It provides functions that may be used for example by
 * command line applications but also other applications may find some
 * routines helpful.  None of these routines are mandatory in any other
 * SILC routines or libraries, and are purely provided for convenience.
 * These routines for example provide simple public key and private key
 * pair generation, public key and private key file saving and loading
 * for application, and other similar routines.
 *
 ***/

#ifndef SILCAPPUTIL_H
#define SILCAPPUTIL_H

/****f* silcutil/SilcAppUtil/silc_create_key_pair
 *
 * SYNOPSIS
 *
 *    SilcBool silc_create_key_pair(const char *pkcs_name,
 *                                  SilcUInt32 key_len_bits,
 *                                  const char *pub_filename,
 *                                  const char *prv_filename,
 *                                  const char *pub_identifier,
 *                                  const char *passphrase,
 *                                  SilcPublicKey *return_public_key,
 *                                  SilcPrivateKey *return_private_key,
 *                                  SilcBool interactive);
 *
 * DESCRIPTION
 *
 *    This routine can be used to generate new public key and private key
 *    pair.  The `pkcs_name' is the name of public key algorithm, or if
 *    NULL it defaults to "rsa".  The `key_len_bits' is the key length
 *    in bits and if zero (0) it defaults to 2048 bits.  The `pub_filename'
 *    and `prv_filename' is the public key and private key filenames.
 *    The `pub_identifier' is the public key identifier (for example:
 *    "UN=foobar, HN=hostname"), or if NULL the routine generates it
 *    automatically.
 *
 *    The `passphrase' is the passphrase that is used to encrypt the
 *    private key file.  It is recommended that you would protect your
 *    private key file with a passphrase.
 *
 *    If the `interactive' is TRUE then this asks the user (by blocking
 *    the process for input) some questions about key generation (like
 *    public key algorithm, key length, filenames, etc).  If all
 *    arguments are provided to this function already then `interactive'
 *    has no effect.
 *
 * NOTES
 *
 *    Before calling this function the application must have initialized
 *    the crypto library by registering the public key algorithms with
 *    silc_pkcs_register_default function.
 *
 ***/
SilcBool silc_create_key_pair(const char *pkcs_name,
			      SilcUInt32 key_len_bits,
			      const char *pub_filename,
			      const char *prv_filename,
			      const char *pub_identifier,
			      const char *passphrase,
			      SilcPublicKey *return_public_key,
			      SilcPrivateKey *return_private_key,
			      SilcBool interactive);

/****f* silcutil/SilcAppUtil/silc_load_key_pair
 *
 * SYNOPSIS
 *
 *    SilcBool silc_load_key_pair(const char *pub_filename,
 *                                const char *prv_filename,
 *                                const char *passphrase,
 *                                SilcPublicKey *return_public_key,
 *                                SilcPrivateKey *return_private_key);
 *
 * DESCRIPTION
 *
 *    This routine can be used to load the public key and private key
 *    from files.  This retuns FALSE it either of the key could not be
 *    loaded.  This function returns TRUE on success and returns the
 *    public key into `return_public_key' pointer and private key into
 *    `return_private_key'.  The `passphrase' is the passphrase which
 *    will be used to decrypt the private key file.
 *
 ***/
SilcBool silc_load_key_pair(const char *pub_filename,
			    const char *prv_filename,
			    const char *passphrase,
			    SilcPublicKey *return_public_key,
			    SilcPrivateKey *return_private_key);

/****f* silcutil/SilcAppUtil/silc_show_public_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_show_public_key(const char *pub_filename);
 *
 * DESCRIPTION
 *
 *    This routine can be used to dump the contents of the public key
 *    in the public key file `pub_filename'.  This dumps the public key
 *    into human readable form into stdout.  Returns FALSE on error.
 *
 ***/
SilcBool silc_show_public_key(const char *pub_filename);

/****f* silcutil/SilcAppUtil/silc_change_private_key_passphrase
 *
 * SYNOPSIS
 *
 *    SilcBool silc_change_private_key_passphrase(const char *prv_filename,
 *                                                const char *old_passphrase,
 *                                                const char *new_passphrase);
 *
 * DESCRIPTION
 *
 *    This routine can be used to change the passphrase of the private
 *    key file, which is used to encrypt the private key.  If the old
 *    and new passphrase is not provided for this function this will
 *    prompt for them.
 *
 ***/
SilcBool silc_change_private_key_passphrase(const char *prv_filename,
					    const char *old_passphrase,
					    const char *new_passphrase);

#endif /* SILCAPPUTIL_H */
