/*

  silcapputil.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcapputil/SILC Application Utilities
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

/****f* silcapputil/SilcAppUtil/silc_create_key_pair
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
 *    automatically.  The `return_public_key' and `return_private_key' may
 *    be NULL.
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

/****f* silcapputil/SilcAppUtil/silc_load_key_pair
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

/****f* silcapputil/SilcAppUtil/silc_show_public_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_show_public_key(SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    This routine can be used to dump the SILC public key into human
 *    readable form into stdout.  Returns FALSE on error.
 *
 ***/
SilcBool silc_show_public_key(SilcPublicKey public_key);

/****f* silcapputil/SilcAppUtil/silc_show_public_key_file
 *
 * SYNOPSIS
 *
 *    SilcBool silc_show_public_key_file(const char *pub_filename);
 *
 * DESCRIPTION
 *
 *    This routine can be used to dump the contents of the public key
 *    in the public key file `pub_filename'.  This dumps the public key
 *    into human readable form into stdout.  Returns FALSE on error.
 *
 ***/
SilcBool silc_show_public_key_file(const char *pub_filename);

/****f* silcapputil/SilcAppUtil/silc_change_private_key_passphrase
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


/****f* silcapputil/SilcAppUtil/silc_identifier_check
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_identifier_check(const unsigned char *identifier,
 *                          SilcUInt32 identifier_len,
 *                          SilcStringEncoding identifier_encoding,
 *                          SilcUInt32 max_allowed_length,
 *                          SilcUInt32 *out_len);
 *
 * DESCRIPTION
 *
 *    Checks that the 'identifier' string is valid identifier string
 *    and does not contain any unassigned or prohibited character.  This
 *    function is used to check for valid nicknames, server names,
 *    usernames, hostnames, service names, algorithm names, other security
 *    property names, and SILC Public Key name.
 *
 *    If the 'max_allowed_length' is non-zero the identifier cannot be
 *    longer than that, and NULL is returned if it is.  If zero (0), no
 *    length limit exist.  For nicknames the max length must be 128 bytes.
 *    Other identifiers has no default limit, but application may choose
 *    one anyway.
 *
 *    Returns the validated string, that the caller must free.  Returns
 *    NULL if the identifier string is not valid or contain unassigned or
 *    prohibited characters.  Such identifier strings must not be used
 *    SILC protocol.  The returned string is always in UTF-8 encoding.
 *    The length of the returned string is in 'out_len'.
 *
 * NOTES
 *
 *    In addition of validating the identifier string, this function
 *    may map characters to other characters or remove characters from the
 *    original string.  This is done as defined in the SILC protocol.  Error
 *    is returned only if the string contains unassigned or prohibited
 *    characters.  The original 'identifier' is not modified at any point.
 *
 ***/
unsigned char *silc_identifier_check(const unsigned char *identifier,
				     SilcUInt32 identifier_len,
				     SilcStringEncoding identifier_encoding,
				     SilcUInt32 max_allowed_length,
				     SilcUInt32 *out_len);

/****f* silcapputil/SilcAppUtil/silc_identifier_verify
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_identifier_check(const unsigned char *identifier,
 *                          SilcUInt32 identifier_len,
 *                          SilcStringEncoding identifier_encoding,
 *                          SilcUInt32 max_allowed_length);
 *
 * DESCRIPTION
 *
 *    Checks that the 'identifier' string is valid identifier string
 *    and does not contain any unassigned or prohibited character.  This
 *    function is used to check for valid nicknames, server names,
 *    usernames, hostnames, service names, algorithm names, other security
 *    property names, and SILC Public Key name.
 *
 *    If the 'max_allowed_length' is non-zero the identifier cannot be
 *    longer than that, and NULL is returned if it is.  If zero (0), no
 *    length limit exist.  For nicknames the max length must be 128 bytes.
 *    Other identifiers has no default limit, but application may choose
 *    one anyway.
 *
 *    Returns TRUE if the string is valid and FALSE if it is prohibited.
 *
 ***/
SilcBool silc_identifier_verify(const unsigned char *identifier,
				SilcUInt32 identifier_len,
				SilcStringEncoding identifier_encoding,
				SilcUInt32 max_allowed_length);

/****f* silcapputil/SilcAppUtil/silc_channel_name_check
 *
 * SYNOPSIS
 *
 *    unsigned char *
 *    silc_channel_name_check(const unsigned char *identifier,
 *                            SilcUInt32 identifier_len,
 *                            SilcStringEncoding identifier_encoding,
 *                            SilcUInt32 max_allowed_length,
 *                            SilcUInt32 *out_len);
 *
 * DESCRIPTION
 *
 *    Checks that the 'identifier' string is valid channel name string
 *    and does not contain any unassigned or prohibited character.
 *
 *    If the 'max_allowed_length' is non-zero the identifier cannot be
 *    longer than that, and NULL is returned if it is.  If zero (0), no
 *    length limit exist.  For channel names the max length must be 256
 *    bytes.
 *
 *    Returns the validated string, that the caller must free.  Returns
 *    NULL if the identifier string is not valid or contain unassigned or
 *    prohibited characters.  Such identifier strings must not be used
 *    SILC protocol.  The returned string is always in UTF-8 encoding.
 *    The length of the returned string is in 'out_len'.
 *
 * NOTES
 *
 *    In addition of validating the channel name string, this function
 *    may map characters to other characters or remove characters from the
 *    original string.  This is done as defined in the SILC protocol.  Error
 *    is returned only if the string contains unassigned or prohibited
 *    characters.  The original 'identifier' is not modified at any point.
 *
 ***/
unsigned char *silc_channel_name_check(const unsigned char *identifier,
				       SilcUInt32 identifier_len,
				       SilcStringEncoding identifier_encoding,
				       SilcUInt32 max_allowed_length,
				       SilcUInt32 *out_len);

/****f* silcapputil/SilcAppUtil/silc_channel_name_verify
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_channel_name_veirfy(const unsigned char *identifier,
 *                             SilcUInt32 identifier_len,
 *                             SilcStringEncoding identifier_encoding,
 *                             SilcUInt32 max_allowed_length);
 *
 * DESCRIPTION
 *
 *    Checks that the 'identifier' string is valid channel name string
 *    and does not contain any unassigned or prohibited character.
 *
 *    If the 'max_allowed_length' is non-zero the identifier cannot be
 *    longer than that, and NULL is returned if it is.  If zero (0), no
 *    length limit exist.  For channel names the max length must be 256
 *    bytes.
 *
 *    Returns TRUE if the string is valid and FALSE if it is prohibited.
 *
 ***/
SilcBool silc_channel_name_verify(const unsigned char *identifier,
				  SilcUInt32 identifier_len,
				  SilcStringEncoding identifier_encoding,
				  SilcUInt32 max_allowed_length);

/****f* silcapputil/SilcAppUtil/silc_get_mode_list
 *
 * SYNOPSIS
 *
 *    SilcBool silc_get_mode_list(SilcBuffer mode_list,
 *                                SilcUInt32 mode_list_count,
 *                                SilcUInt32 **list);
 *
 * DESCRIPTION
 *
 *    Returns modes from list of 32 bit MSB first order values that are
 *    encoded one after the other in the `mode_list' into the `list'
 *    array.  The caller must free the returned list.  Return FALSE if
 *    there is error parsing the list.
 *
 ***/
SilcBool silc_get_mode_list(SilcBuffer mode_list, SilcUInt32 mode_list_count,
			    SilcUInt32 **list);

/****f* silcapputil/SilcAppUtil/silc_get_status_message
 *
 * SYNOPSIS
 *
 *    char *silc_get_status_message(SilcStatus status)
 *
 * DESCRIPTION
 *
 *    Returns status message string
 *
 ***/
const char *silc_get_status_message(unsigned char status);

/****f* silcapputil/SilcAppUtil/silc_get_packet_name
 *
 * SYNOPSIS
 *
 *    char *silc_get_packet_name(SilcPacketType type);
 *
 * DESCRIPTION
 *
 *    Returns the name corresponding packet type `type'.
 *
 ***/
const char *silc_get_packet_name(unsigned char type);

/****f* silcapputil/SilcAppUtil/silc_get_command_name
 *
 * SYNOPSIS
 *
 *    char *silc_get_command_name(SilcCommand command);
 *
 * DESCRIPTION
 *
 *    Returns the name corresponding SILC command `command'.
 *
 ***/
const char *silc_get_command_name(unsigned char command);

/****f* silcapputil/SilcAppUtil/silc_parse_version_string
 *
 * SYNOPSIS
 *
 *    SilcBool silc_parse_version_string(const char *version,
 *                                       SilcUInt32 *protocol_version,
 *                                       char **protocol_version_string,
 *                                       SilcUInt32 *software_version,
 *                                       char **software_version_string,
 *                                       char **vendor_version);
 *
 * DESCRIPTION
 *
 *    Parses SILC protocol style version string.
 *
 ***/
SilcBool silc_parse_version_string(const char *version,
				   SilcUInt32 *protocol_version,
				   char **protocol_version_string,
				   SilcUInt32 *software_version,
				   char **software_version_string,
				   char **vendor_version);

/****f* silcapputil/SilcAppUtil/silc_version_to_num
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_version_to_num(const char *version);
 *
 * DESCRIPTION
 *
 *    Converts version string x.x into number representation.
 *
 ***/
SilcUInt32 silc_version_to_num(const char *version);

/****f* silcapputil/SilcAppUtil/silc_client_chmode
 *
 * SYNOPSIS
 *
 *    char *silc_client_chmode(SilcUInt32 mode, const char *cipher,
 *                             const char *hmac);
 *
 * DESCRIPTION
 *
 *    Parses mode mask and returns the mode as string.
 *
 ***/
char *silc_client_chmode(SilcUInt32 mode, const char *cipher,
			 const char *hmac);

/****f* silcapputil/SilcAppUtil/silc_client_chumode
 *
 * SYNOPSIS
 *
 *    char *silc_client_chumode(SilcUInt32 mode);
 *
 * DESCRIPTION
 *
 *    Parses channel user mode mask and returns te mode as string.
 *
 ***/
char *silc_client_chumode(SilcUInt32 mode);

/****f* silcapputil/SilcAppUtil/silc_client_chumode_char
 *
 * SYNOPSIS
 *
 *    char *silc_client_chumode_char(SilcUInt32 mode);
 *
 * DESCRIPTION
 *
 *    Parses channel user mode and returns it as special mode character.
 *
 ***/
char *silc_client_chumode_char(SilcUInt32 mode);

/****f* silcutil/SilcUtilAPI/silc_id_render
 *
 * SYNOPSIS
 *
 *    char *silc_id_render(void *id, SilcIdType id_type);
 *
 * DESCRIPTION
 *
 *    Renders ID to suitable to print for example to log file.
 *
 ***/
char *silc_id_render(void *id, SilcIdType id_type);

#endif /* SILCAPPUTIL_H */
