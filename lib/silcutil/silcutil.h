/*

  silcutil.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Utilities
 *
 * DESCRIPTION
 *
 *    Utility functions.
 *
 ***/

#ifndef SILCUTIL_H
#define SILCUTIL_H

/****f* silcutil/SilcUtilAPI/silc_gets
 *
 * SYNOPSIS
 *
 *    int silc_gets(char *dest, int destlen, const char *src, int srclen,
 *                  int begin);
 *
 * DESCRIPTION
 *
 *    Gets line from a buffer. Stops reading when a newline or EOF occurs.
 *    This doesn't remove the newline sign from the destination buffer. The
 *    argument begin is returned and should be passed again for the function.
 *
 ***/
int silc_gets(char *dest, int destlen, const char *src, int srclen, int begin);

/****f* silcutil/SilcUtilAPI/silc_check_line
 *
 * SYNOPSIS
 *
 *    int silc_check_line(char *buf);
 *
 * DESCRIPTION
 *
 *    Checks line for illegal characters. Return -1 when illegal character
 *    were found. This is used to check for bad lines when reading data from
 *    for example a configuration file.
 *
 ***/
int silc_check_line(char *buf);

/****f* silcutil/SilcUtilAPI/silc_to_upper
 *
 * SYNOPSIS
 *
 *    SilcBool silc_to_upper(const char *string, char *dest,
 *                           SilcUInt32 dest_size);
 *
 * DESCRIPTION
 *
 *    Converts string to capital characters.
 *
 ***/
SilcBool silc_to_upper(const char *string, char *dest, SilcUInt32 dest_size);

/****f* silcutil/SilcUtilAPI/silc_to_lower
 *
 * SYNOPSIS
 *
 *    SilcBool silc_to_lower(const char *string, char *dest,
 *                           SilcUInt32 dest_size);
 *
 * DESCRIPTION
 *
 *    Converts string to capital characters.
 *
 ***/
SilcBool silc_to_lower(const char *string, char *dest, SilcUInt32 dest_size);

/****f* silcutil/SilcUtilAPI/silc_parse_userfqdn
 *
 * SYNOPSIS
 *
 *    int silc_parse_userfqdn(const char *string,
 *                            char *user, SilcUInt32 user_size,
 *                            char *fqdn, SilcUInt32 fqdn_size);
 *
 * DESCRIPTION
 *
 *    Parse userfqdn string which is in user@fqdn format.  Returns 0 on
 *    error, 1 if `user' was filled and 2 if both `user' and `fqdn'
 *    was filled.
 *
 ***/
int silc_parse_userfqdn(const char *string,
			char *user, SilcUInt32 user_size,
			char *fqdn, SilcUInt32 fqdn_size);

/****f* silcutil/SilcUtilAPI/silc_parse_command_line
 *
 * SYNOPSIS
 *
 *    void silc_parse_command_line(unsigned char *buffer,
 *                                 unsigned char ***parsed,
 *                                 SilcUInt32 **parsed_lens,
 *                                 SilcUInt32 **parsed_types,
 *                                 SilcUInt32 *parsed_num,
 *                                 SilcUInt32 max_args);
 *
 * DESCRIPTION
 *
 *    Parses command line. At most `max_args' is taken. Rest of the line
 *    will be allocated as the last argument if there are more than `max_args'
 *    arguments in the line. Note that the command name is counted as one
 *    argument and is saved.
 *
 ***/
void silc_parse_command_line(unsigned char *buffer,
			     unsigned char ***parsed,
			     SilcUInt32 **parsed_lens,
			     SilcUInt32 **parsed_types,
			     SilcUInt32 *parsed_num,
			     SilcUInt32 max_args);

/****f* silcutil/SilcUtilAPI/silc_format
 *
 * SYNOPSIS
 *
 *    char *silc_format(char *fmt, ...);
 *
 * DESCRIPTION
 *
 *    Formats arguments to a string and returns it after allocating memory
 *    for it. It must be remembered to free it later.
 *
 ***/
char *silc_format(char *fmt, ...);

/****f* silcutil/SilcUtilAPI/silc_hash_string
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_string(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Basic has function to hash strings. May be used with the SilcHashTable.
 *    Note that this lowers the characters of the string (with tolower()) so
 *    this is used usually with nicknames, channel and server names to provide
 *    case insensitive keys.
 *
 ***/
SilcUInt32 silc_hash_string(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_utf8_string
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_utf8_string(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Basic has function to hash UTF-8 strings. May be used with the
 *    SilcHashTable.  Used with identifier strings.  The key is
 *    expected to be casefolded.
 *
 ***/
SilcUInt32 silc_hash_utf8_string(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_uint
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_uint(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Basic hash function to hash integers. May be used with the SilcHashTable.
 *
 ***/
SilcUInt32 silc_hash_uint(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_ptr
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_ptr(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Basic hash funtion to hash pointers. May be used with the SilcHashTable.
 *
 ***/
SilcUInt32 silc_hash_ptr(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_id
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_id(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Hash a ID. The `user_context' is the ID type.
 *
 ***/
SilcUInt32 silc_hash_id(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_client_id_hash
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_client_id_hash(void *key, void *user_context)
 *
 * DESCRIPTION
 *
 *    Hash Client ID's hash.
 *
 ***/
SilcUInt32 silc_hash_client_id_hash(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_data
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_data(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Hash binary data. The `user_context' is the data length.
 *
 ***/
SilcUInt32 silc_hash_data(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_public_key
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_public_key(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    Hash public key of any type.
 *
 ***/
SilcUInt32 silc_hash_public_key(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_string_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_string_compare(void *key1, void *key2,
 *                                  void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares two strings. It may be used as SilcHashTable comparison
 *    function.
 *
 ***/
SilcBool silc_hash_string_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_id_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_id_compare(void *key1, void *key2,
 *                                  void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares two ID's. May be used as SilcHashTable comparison function.
 *    The Client ID's compares only the hash of the Client ID not any other
 *    part of the Client ID. Other ID's are fully compared.
 *
 ***/
SilcBool silc_hash_id_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_id_compare_full
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_id_compare_full(void *key1, void *key2,
 *                                       void *user_context)
 *
 * DESCRIPTION
 *
 *    Compares two ID's. May be used as SilcHashTable comparison function.
 *    To compare full ID's instead of only partial, like the
 *    silc_hash_id_compare does, use this function.
 *
 ***/
SilcBool silc_hash_id_compare_full(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_client_id_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_client_id_compare(void *key1, void *key2,
 *                                         void *user_context);
 *
 * DESCRIPTION
 *
 *    Compare two Client ID's entirely and not just the hash from the ID.
 *
 ***/
SilcBool silc_hash_client_id_compare(void *key1, void *key2,
				     void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_data_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_data_compare(void *key1, void *key2,
 *                                    void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares binary data. May be used as SilcHashTable comparison function.
 *
 ***/
SilcBool silc_hash_data_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_utf8_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_utf8_compare(void *key1, void *key2,
 *                                    void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares UTF-8 strings.  Casefolded and NULL terminated strings are
 *    expected.  May be used as SilcHashTable comparison function.
 *
 ***/
SilcBool silc_hash_utf8_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_public_key_compare
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_public_key_compare(void *key1, void *key2,
 *                                          void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares two SILC Public keys. It may be used as SilcHashTable
 *    comparison function.
 *
 ***/
SilcBool silc_hash_public_key_compare(void *key1, void *key2,
				      void *user_context);

/****f* silcutil/SilcUtilAPI/silc_fingerprint
 *
 * SYNOPSIS
 *
 *    char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Return a textual representation of the fingerprint in *data, the
 *    caller must free the returned string.
 *
 ***/
char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcUtilAPI/silc_string_is_ascii
 *
 * SYNOPSIS
 *
 *    SilcBool silc_string_is_ascii(const unsigned char *data,
 *                              SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Return TRUE if the `data' is ASCII string.
 *
 ***/
SilcBool silc_string_is_ascii(const unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcUtilAPI/silc_get_input
 *
 * SYNOPSIS
 *
 *    char *silc_get_input(const char *prompt, SilcBool echo_off);
 *
 * DESCRIPTION
 *
 *    Displays input prompt on command line and takes input data from user.
 *
 ***/
char *silc_get_input(const char *prompt, SilcBool echo_off);

/* System dependant prototypes */

/****f* silcutil/SilcUtilAPI/silc_get_username
 *
 * SYNOPSIS
 *
 *    char *silc_get_username();
 *
 * DESCRIPTION
 *
 *    Returns the username of the user. If the global variable LOGNAME
 *    does not exists we will get the name from the passwd file.  The
 *    caller must free the returned name.
 *
 *    This function is system dependant.
 *
 ***/
char *silc_get_username();

/****f* silcutil/SilcUtilAPI/silc_get_real_name
 *
 * SYNOPSIS
 *
 *    char *silc_get_real_name();
 *
 * DESCRIPTION
 *
 *    Returns the real name of ther user from the passwd file.  The
 *    caller must free the returned name.
 *
 *    This function is system dependant.
 *
 ***/
char *silc_get_real_name();

/****f* silcutil/SilcUtilAPI/silc_va_copy
 *
 * SYNOPSIS
 *
 *    void silc_va_copy(va_list dest, va_list src);
 *
 * DESCRIPTION
 *
 *    Copies variable argument list.  This must be called in case the
 *    variable argument list must be evaluated multiple times.  For each
 *    evaluation the list must be copied and va_end must be called for
 *    each copied list.
 *
 ***/
void silc_va_copy(va_list dest, va_list src);

#endif	/* !SILCUTIL_H */
