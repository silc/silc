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

#ifndef SILCUTIL_H
#define SILCUTIL_H

/* Prototypes */
int silc_gets(char *dest, int destlen, const char *src, int srclen, int begin);
int silc_check_line(char *buf);
char *silc_get_time();
char *silc_to_upper(char *string);
char *silc_encode_pem(unsigned char *data, SilcUInt32 len);
char *silc_encode_pem_file(unsigned char *data, SilcUInt32 data_len);
unsigned char *silc_decode_pem(unsigned char *pem, SilcUInt32 pem_len,
			       SilcUInt32 *ret_len);
bool silc_parse_userfqdn(const char *string, char **left, char **right);
void silc_parse_command_line(unsigned char *buffer, 
			     unsigned char ***parsed,
			     SilcUInt32 **parsed_lens,
			     SilcUInt32 **parsed_types,
			     SilcUInt32 *parsed_num,
			     SilcUInt32 max_args);
char *silc_format(char *fmt, ...);
char *silc_id_render(void *id, SilcUInt16 type);
int silc_string_compare(char *string1, char *string2);
char *silc_string_regexify(const char *string);
int silc_string_regex_match(const char *regex, const char *string);
int silc_string_match(const char *string1, const char *string2);
char *silc_get_username();
char *silc_get_real_name();
SilcUInt32 silc_hash_string(void *key, void *user_context);
SilcUInt32 silc_hash_uint(void *key, void *user_context);
SilcUInt32 silc_hash_ptr(void *key, void *user_context);
SilcUInt32 silc_hash_id(void *key, void *user_context);
SilcUInt32 silc_hash_data(void *key, void *user_context);
SilcUInt32 silc_hash_public_key(void *key, void *user_context);
bool silc_hash_string_compare(void *key1, void *key2, void *user_context);
bool silc_hash_id_compare(void *key1, void *key2, void *user_context);
bool silc_hash_client_id_compare(void *key1, void *key2, void *user_context);
bool silc_hash_data_compare(void *key1, void *key2, void *user_context);
bool silc_hash_public_key_compare(void *key1, void *key2, void *user_context);
char *silc_client_chmode(SilcUInt32 mode, const char *cipher, 
			 const char *hmac);
char *silc_client_chumode(SilcUInt32 mode);
char *silc_client_chumode_char(SilcUInt32 mode);
int silc_gettimeofday(struct timeval *p);
char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len);
bool silc_string_is_ascii(const unsigned char *data, SilcUInt32 data_len);
bool silc_parse_version_string(const char *version,
			       SilcUInt32 *protocol_version,
			       char **protocol_version_string,
			       SilcUInt32 *software_version, 
			       char **software_version_string,
			       char **vendor_version);
SilcUInt32 silc_version_to_num(const char *version);
char *silc_get_input(const char *prompt, bool echo_off);

#endif
