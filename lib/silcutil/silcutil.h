/*

  silcutil.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCUTIL_H
#define SILCUTIL_H

/* Prototypes */
char *silc_file_read(const char *filename, int *return_len);
int silc_file_write(const char *filename, const char *buffer, int len);
int silc_file_write_mode(const char *filename, const char *buffer, 
			 int len, int mode);
int silc_gets(char *dest, int destlen, const char *src, int srclen, int begin);
int silc_check_line(char *buf);
char *silc_get_time();
char *silc_to_upper(char *string);
int silc_string_compare(char *string1, char *string2);
char *silc_encode_pem(unsigned char *data, unsigned int len);
char *silc_encode_pem_file(unsigned char *data, unsigned int data_len);
unsigned char *silc_decode_pem(unsigned char *pem, unsigned int pem_len,
			       unsigned int *ret_len);
int silc_parse_nickname(char *string, char **nickname, char **server,
			unsigned int *num);
void silc_parse_command_line(unsigned char *buffer, 
			     unsigned char ***parsed,
			     unsigned int **parsed_lens,
			     unsigned int **parsed_types,
			     unsigned int *parsed_num,
			     unsigned int max_args);
char *silc_format(char *fmt, ...);

#endif
