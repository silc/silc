/*

  silcutil.h

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

/****f* silcutil/SilcUtilAPI/silc_get_time
 *
 * SYNOPSIS
 *
 *    const char *silc_get_time(SilcUInt32 timeval)
 *
 * DESCRIPTION
 *
 *    Returns time as string.  If the the `timeval' is non-zero that
 *    value is returned as string.  If it is zero the current time of the
 *    local machine is returned.
 *
 ***/
const char *silc_get_time(SilcUInt32 timeval);

/****f* silcutil/SilcUtilAPI/silc_to_upper
 *
 * SYNOPSIS
 *
 *    bool silc_to_upper(const char *string, char *dest, SilcUInt32 dest_size);
 *
 * DESCRIPTION
 *
 *    Converts string to capital characters.
 *
 ***/
bool silc_to_upper(const char *string, char *dest, SilcUInt32 dest_size);

/****f* silcutil/SilcUtilAPI/silc_to_lower
 *
 * SYNOPSIS
 *
 *    bool silc_to_lower(const char *string, char *dest, SilcUInt32 dest_size);
 *
 * DESCRIPTION
 *
 *    Converts string to capital characters.
 *
 ***/
bool silc_to_lower(const char *string, char *dest, SilcUInt32 dest_size);

/****f* silcutil/SilcUtilAPI/silc_parse_userfqdn
 *
 * SYNOPSIS
 *
 *    bool silc_parse_userfqdn(const char *string, char **left, char **right);
 *
 * DESCRIPTION
 *
 *    Parse userfqdn string which is in user@fqdn format.
 *
 ***/
bool silc_parse_userfqdn(const char *string, char **left, char **right);

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

/****f* silcutil/SilcUtilAPI/silc_id_render
 *
 * SYNOPSIS
 *
 *    char *silc_id_render(void *id, SilcUInt16 type);
 *
 * DESCRIPTION
 *
 *    Renders ID to suitable to print for example to log file.
 *
 ***/
char *silc_id_render(void *id, SilcUInt16 type);

/****f* silcutil/SilcUtilAPI/silc_string_compare
 *
 * SYNOPSIS
 *
 *    int silc_string_compare(char *string1, char *string2);
 *
 * DESCRIPTION
 *
 *    Compares two strings. Strings may include wildcards '*' and '?'.
 *    Returns TRUE if strings match.
 *
 ***/
int silc_string_compare(char *string1, char *string2);

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
 *    Hashed SILC Public key.
 *
 ***/
SilcUInt32 silc_hash_public_key(void *key, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_string_compare
 *
 * SYNOPSIS
 *
 *    bool silc_hash_string_compare(void *key1, void *key2,
 *                                  void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares two strings. It may be used as SilcHashTable comparison
 *    function.
 *
 ***/
bool silc_hash_string_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_id_compare
 *
 * SYNOPSIS
 *
 *    bool silc_hash_id_compare(void *key1, void *key2, void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares two ID's. May be used as SilcHashTable comparison function.
 *    The Client ID's compares only the hash of the Client ID not any other
 *    part of the Client ID. Other ID's are fully compared.
 *
 ***/
bool silc_hash_id_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_client_id_compare
 *
 * SYNOPSIS
 *
 *    bool silc_hash_client_id_compare(void *key1, void *key2, void *user_context);
 *
 * DESCRIPTION
 *
 *    Compare two Client ID's entirely and not just the hash from the ID.
 *
 ***/
bool silc_hash_client_id_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_data_compare
 *
 * SYNOPSIS
 *
 *    bool silc_hash_data_compare(void *key1, void *key2, void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares binary data. May be used as SilcHashTable comparison function.
 *
 ***/
bool silc_hash_data_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_hash_public_key_compare
 *
 * SYNOPSIS
 *
 *    bool silc_hash_public_key_compare(void *key1, void *key2, void *user_context);
 *
 * DESCRIPTION
 *
 *    Compares two SILC Public keys. It may be used as SilcHashTable
 *    comparison function.
 *
 ***/
bool silc_hash_public_key_compare(void *key1, void *key2, void *user_context);

/****f* silcutil/SilcUtilAPI/silc_client_chmode
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

/****f* silcutil/SilcUtilAPI/silc_client_chumode
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

/****f* silcutil/SilcUtilAPI/silc_client_chumode_char
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

/****f* silcutil/SilcUtilAPI/silc_fingerprint
 *
 * SYNOPSIS
 *
 *    char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Creates fingerprint from data, usually used with SHA1 digests.
 *
 ***/
char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcUtilAPI/silc_string_is_ascii
 *
 * SYNOPSIS
 *
 *    bool silc_string_is_ascii(const unsigned char *data,
 *                              SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Return TRUE if the `data' is ASCII string.
 *
 ***/
bool silc_string_is_ascii(const unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcUtilAPI/silc_parse_version_string
 *
 * SYNOPSIS
 *
 *    bool silc_parse_version_string(const char *version,
 *                                   SilcUInt32 *protocol_version,
 *                                   char **protocol_version_string,
 *                                   SilcUInt32 *software_version,
 *                                   char **software_version_string,
 *                                   char **vendor_version);
 *
 * DESCRIPTION
 *
 *    Parses SILC protocol style version string.
 *
 ***/
bool silc_parse_version_string(const char *version,
			       SilcUInt32 *protocol_version,
			       char **protocol_version_string,
			       SilcUInt32 *software_version,
			       char **software_version_string,
			       char **vendor_version);

/****f* silcutil/SilcUtilAPI/silc_version_to_num
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

/****f* silcutil/SilcUtilAPI/silc_get_input
 *
 * SYNOPSIS
 *
 *    char *silc_get_input(const char *prompt, bool echo_off);
 *
 * DESCRIPTION
 *
 *    Displays input prompt on command line and takes input data from user.
 *
 ***/
char *silc_get_input(const char *prompt, bool echo_off);

/* System dependant prototypes */

/****f* silcutil/SilcUtilAPI/silc_gettimeofday
 *
 * SYNOPSIS
 *
 *    int silc_gettimeofday(struct timeval *p);
 *
 * DESCRIPTION
 *
 *    Return current time to struct timeval.
 *
 *    This function is system dependant.
 *
 ***/
int silc_gettimeofday(struct timeval *p);

/****f* silcutil/SilcUtilAPI/silc_string_regexify
 *
 * SYNOPSIS
 *
 *    char *silc_string_regexify(const char *string);
 *
 * DESCRIPTION
 *
 *    Inspects the `string' for wildcards and returns regex string that can
 *    be used by the GNU regex library. A comma (`,') in the `string' means
 *    that the string is list.
 *
 *    This function is system dependant.
 *
 ***/
char *silc_string_regexify(const char *string);

/****f* silcutil/SilcUtilAPI/silc_string_regex_match
 *
 * SYNOPSIS
 *
 *    int silc_string_regex_match(const char *regex, const char *string);
 *
 * DESCRIPTION
 *
 *    Matches the two strings and returns TRUE if the strings match.
 *
 *    This function is system dependant.
 *
 ***/
int silc_string_regex_match(const char *regex, const char *string);

/****f* silcutil/SilcUtilAPI/silc_string_match
 *
 * SYNOPSIS
 *
 *    int silc_string_match(const char *string1, const char *string2);
 *
 * DESCRIPTION
 *
 *    Do regex match to the two strings `string1' and `string2'. If the
 *    `string2' matches the `string1' this returns TRUE.
 *
 *    This function is system dependant.
 *
 ***/
int silc_string_match(const char *string1, const char *string2);

/****f* silcutil/SilcUtilAPI/silc_get_username
 *
 * SYNOPSIS
 *
 *    char *silc_get_username();
 *
 * DESCRIPTION
 *
 *    Returns the username of the user. If the global variable LOGNAME
 *    does not exists we will get the name from the passwd file.
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
 *    Returns the real name of ther user from the passwd file.
 *
 *    This function is system dependant.
 *
 ***/
char *silc_get_real_name();

/****f* silcutil/SilcUtilAPI/silc_get_mode_list
 *
 * SYNOPSIS
 *
 *    bool silc_get_mode_list(SilcBuffer mode_list, SilcUInt32 mode_list_count,
 *                            SilcUInt32 **list);
 *
 * DESCRIPTION
 *
 *    Returns modes from list of 32 bit MSB first order values that are
 *    encoded one after the other in the `mode_list' into the `list'
 *    array.  The caller must free the returned list.  Return FALSE if
 *    there is error parsing the list.
 *
 ***/
bool silc_get_mode_list(SilcBuffer mode_list, SilcUInt32 mode_list_count,
			SilcUInt32 **list);

/****f* silcutil/SilcUtilAPI/silc_get_status_message
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

/****f* silcutil/SilcUtilAPI/silc_get_packet_name
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

/****f* silcutil/SilcUtilAPI/silc_get_command_name
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

#endif	/* !SILCUTIL_H */
