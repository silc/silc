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
char *silc_encode_pem(unsigned char *data, uint32 len);
char *silc_encode_pem_file(unsigned char *data, uint32 data_len);
unsigned char *silc_decode_pem(unsigned char *pem, uint32 pem_len,
			       uint32 *ret_len);
bool silc_parse_userfqdn(const char *string, char **left, char **right);
void silc_parse_command_line(unsigned char *buffer, 
			     unsigned char ***parsed,
			     uint32 **parsed_lens,
			     uint32 **parsed_types,
			     uint32 *parsed_num,
			     uint32 max_args);
char *silc_format(char *fmt, ...);
char *silc_id_render(void *id, uint16 type);
int silc_string_compare(char *string1, char *string2);
char *silc_string_regexify(const char *string);
int silc_string_regex_match(const char *regex, const char *string);
int silc_string_match(const char *string1, const char *string2);
char *silc_get_username();
char *silc_get_real_name();
uint32 silc_hash_string(void *key, void *user_context);
uint32 silc_hash_uint(void *key, void *user_context);
uint32 silc_hash_ptr(void *key, void *user_context);
uint32 silc_hash_id(void *key, void *user_context);
uint32 silc_hash_data(void *key, void *user_context);
bool silc_hash_string_compare(void *key1, void *key2, void *user_context);
bool silc_hash_id_compare(void *key1, void *key2, void *user_context);
bool silc_hash_client_id_compare(void *key1, void *key2, void *user_context);
bool silc_hash_data_compare(void *key1, void *key2, void *user_context);
char *silc_client_chmode(uint32 mode, const char *cipher, const char *hmac);
char *silc_client_chumode(uint32 mode);
char *silc_client_chumode_char(uint32 mode);
int silc_gettimeofday(struct timeval *p);
char *silc_fingerprint(const unsigned char *data, uint32 data_len);

#endif
