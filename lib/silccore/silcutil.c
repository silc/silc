/*

  silcutil.c

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
/*
 * These are general utility functions that doesn't belong to any specific
 * group of routines.
 */
/*
 * $Id$
 * $Log$
 * Revision 1.3  2000/07/10 05:34:40  priikone
 * 	Added PEM encoding/decoding functions.
 *
 * Revision 1.2  2000/07/05 06:06:12  priikone
 * 	Added file saving with specific mode.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

/* Reads a file to a buffer. The allocated buffer is returned. Length of
   the file read is returned to the return_len argument. */

char *silc_file_read(const char *filename, int *return_len)
{
  int fd;
  char *buffer;
  int filelen;

  fd = open(filename, O_RDONLY);
  if (fd < 0) {
    SILC_LOG_ERROR(("Cannot open file %s: %s", filename, strerror(errno)));
    return NULL;
  }

  filelen = lseek(fd, (off_t)0L, SEEK_END);
  if (filelen < 0)
    return NULL;
  if (lseek(fd, (off_t)0L, SEEK_SET) < 0)
    return NULL;

  if (filelen < 0) {
    SILC_LOG_ERROR(("Cannot open file %s: %s", filename, strerror(errno)));
    return NULL;
  }
  
  buffer = silc_calloc(filelen + 1, sizeof(char));
  
  if ((read(fd, buffer, filelen)) == -1) {
    memset(buffer, 0, sizeof(buffer));
    close(fd);
    SILC_LOG_ERROR(("Cannot read from file %s: %s", filename,
                    strerror(errno)));
    return NULL;
  }

  close(fd);
  buffer[filelen] = EOF;
  
  *return_len = filelen;
  return buffer;
}

/* Writes a buffer to the file. */

int silc_file_write(const char *filename, const char *buffer, int len)
{
  int fd;
        
  if ((fd = creat(filename, 0644)) == -1) {
    SILC_LOG_ERROR(("Cannot open file %s for writing: %s", strerror(errno)));
    return -1;
  }
  
  if ((write(fd, buffer, len)) == -1) {
    SILC_LOG_ERROR(("Cannot write to file %s: %s", strerror(errno)));
    return -1;
  }

  close(fd);
  
  return 0;
}

/* Writes a buffer to the file.  If the file is created specific mode is
   set to the file. */

int silc_file_write_mode(const char *filename, const char *buffer, 
			 int len, int mode)
{
  int fd;
        
  if ((fd = creat(filename, mode)) == -1) {
    SILC_LOG_ERROR(("Cannot open file %s for writing: %s", strerror(errno)));
    return -1;
  }
  
  if ((write(fd, buffer, len)) == -1) {
    SILC_LOG_ERROR(("Cannot write to file %s: %s", strerror(errno)));
    return -1;
  }

  close(fd);
  
  return 0;
}

/* Gets line from a buffer. Stops reading when a newline or EOF occurs.
   This doesn't remove the newline sign from the destination buffer. The
   argument begin is returned and should be passed again for the function. */

int silc_gets(char *dest, int destlen, const char *src, int srclen, int begin)
{
  static int start = 0;
  int i;
  
  memset(dest, 0, destlen);
  
  if (begin != start)
    start = 0;
  
  i = 0;
  for ( ; start <= srclen; i++, start++) {
    if (i > destlen)
      return -1;
    
    dest[i] = src[start];
    
    if (dest[i] == EOF) 
      return EOF;
    
    if (dest[i] == '\n') 
      break;
  }
  start++;
  
  return start;
}

/* Checks line for illegal characters. Return -1 when illegal character
   were found. This is used to check for bad lines when reading data from
   for example a configuration file. */

int silc_check_line(char *buf) 
{
  /* Illegal characters in line */
  if (strchr(buf, '#')) return -1;
  if (strchr(buf, '\'')) return -1;
  if (strchr(buf, '\\')) return -1;
  if (strchr(buf, '\r')) return -1;
  if (strchr(buf, '\a')) return -1;
  if (strchr(buf, '\b')) return -1;
  if (strchr(buf, '\f')) return -1;
  
  /* Empty line */
  if (buf[0] == '\n')
    return -1;
  
  return 0;
}

/* Returns current time as string. */

char *silc_get_time()
{
  time_t curtime;
  char *return_time;

  curtime = time(NULL);
  return_time = ctime(&curtime);
  return_time[strlen(return_time) - 1] = '\0';

  return return_time;
}

/* Converts string to capital characters */

char *silc_to_upper(char *string)
{
  int i;
  char *ret = silc_calloc(strlen(string) + 1, sizeof(char));

  for (i = 0; i < strlen(string); i++)
    ret[i] = toupper(string[i]);

  return ret;
}

/* Compares two strings. Strings may include wildcards * and ?.
   Returns TRUE if strings match. */

int silc_string_compare(char *string1, char *string2)
{
  int i;
  int slen1 = strlen(string1);
  int slen2 = strlen(string2);
  char *tmpstr1, *tmpstr2;

  if (!string1 || !string2)
    return FALSE;

  /* See if they are same already */
  if (!strncmp(string1, string2, strlen(string2)))
    return TRUE;

  if (slen2 < slen1)
    if (!strchr(string1, '*'))
      return FALSE;
  
  /* Take copies of the original strings as we will change them */
  tmpstr1 = silc_calloc(slen1 + 1, sizeof(char));
  memcpy(tmpstr1, string1, slen1);
  tmpstr2 = silc_calloc(slen2 + 1, sizeof(char));
  memcpy(tmpstr2, string2, slen2);
  
  for (i = 0; i < slen2; i++) {
    
    /* * wildcard. Only one * wildcard is possible. */
    if (tmpstr1[i] == '*')
      if (!strncmp(tmpstr1, tmpstr2, i)) {
	memset(tmpstr2, 0, slen2);
	strncpy(tmpstr2, tmpstr1, i);
	break;
      }
    
    /* ? wildcard */
    if (tmpstr1[i] == '?') {
      if (!strncmp(tmpstr1, tmpstr2, i)) {
	if (!(slen1 < i + 1))
	  if (tmpstr1[i + 1] != '?' &&
	      tmpstr1[i + 1] != tmpstr2[i + 1])
	    continue;
	
	if (!(slen1 < slen2))
	  tmpstr2[i] = '?';
      }
#if 0
    } else {
      if (strncmp(tmpstr1, tmpstr2, i))
	strncpy(tmpstr2, string2, slen2);
#endif
    }
  }
  
  /* if using *, remove it */
  if (strchr(tmpstr1, '*'))
    *strchr(tmpstr1, '*') = 0;
  
  if (!strcmp(tmpstr1, tmpstr2)) {
    memset(tmpstr1, 0, slen1);
    memset(tmpstr2, 0, slen2);
    silc_free(tmpstr1);
    silc_free(tmpstr2);
    return TRUE;
  }
  
  memset(tmpstr1, 0, slen1);
  memset(tmpstr2, 0, slen2);
  silc_free(tmpstr1);
  silc_free(tmpstr2);
  return FALSE;
}

unsigned char pem_enc[64] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encodes data into PEM encoding. Returns NULL terminated PEM encoded
   data string. Note: This is originally public domain code and is 
   still PD. */

char *silc_encode_pem(unsigned char *data, unsigned int len)
{
  int i, j;
  unsigned int bits, c, char_count;
  char *pem;

  char_count = 0;
  bits = 0;
  j = 0;

  pem = silc_calloc(((len * 8 + 5) / 6) + 5, sizeof(*pem));

  for (i = 0; i < len; i++) {
    c = data[i];
    bits += c;
    char_count++;

    if (char_count == 3) {
      pem[j++] = pem_enc[bits  >> 18];
      pem[j++] = pem_enc[(bits >> 12) & 0x3f];
      pem[j++] = pem_enc[(bits >> 6)  & 0x3f];
      pem[j++] = pem_enc[bits & 0x3f];
      bits = 0;
      char_count = 0;
    } else {
      bits <<= 8;
    }
  }

  if (char_count != 0) {
    bits <<= 16 - (8 * char_count);
    pem[j++] = pem_enc[bits >> 18];
    pem[j++] = pem_enc[(bits >> 12) & 0x3f];

    if (char_count == 1) {
      pem[j++] = '=';
      pem[j] = '=';
    } else {
      pem[j++] = pem_enc[(bits >> 6) & 0x3f];
      pem[j] = '=';
    }
  }

  return pem;
}

/* Same as above but puts newline ('\n') every 72 characters. */

char *silc_encode_pem_file(unsigned char *data, unsigned int data_len)
{
  int i, j;
  unsigned int len, cols;
  char *pem, *pem2;

  pem = silc_encode_pem(data, data_len);
  len = strlen(pem);

  pem2 = silc_calloc(len + (len / 72) + 1, sizeof(*pem2));

  for (i = 0, j = 0, cols = 1; i < len; i++, cols++) {
    if (cols == 72) {
      pem2[i] = '\n';
      cols = 0;
      len++;
      continue;
    }

    pem2[i] = pem[j++];
  }

  return pem2;
}

/* Decodes PEM into data. Returns the decoded data. Note: This is
   originally public domain code and is still PD. */

unsigned char *silc_decode_pem(unsigned char *pem, unsigned int pem_len,
			       unsigned int *ret_len)
{
  int i, j;
  unsigned int len, c, char_count, bits;
  unsigned char *data;
  static char ialpha[256], decoder[256];

  for (i = 64 - 1; i >= 0; i--) {
    ialpha[pem_enc[i]] = 1;
    decoder[pem_enc[i]] = i;
  }

  char_count = 0;
  bits = 0;
  j = 0;

  if (!pem_len)
    len = strlen(pem);
  else
    len = pem_len;

  data = silc_calloc(((len * 6) / 8), sizeof(*data));

  for (i = 0; i < len; i++) {
    c = pem[i];

    if (c == '=')
      break;

    if (c > 127 || !ialpha[c])
      continue;

    bits += decoder[c];
    char_count++;

    if (char_count == 4) {
      data[j++] = bits >> 16;
      data[j++] = (bits >> 8) & 0xff;
      data[j++] = bits & 0xff;
      bits = 0;
      char_count = 0;
    } else {
      bits <<= 6;
    }
  }

  switch(char_count) {
  case 1:
    silc_free(data);
    return NULL;
    break;
  case 2:
    data[j] = bits >> 10;
    break;
  case 3:
    data[j++] = bits >> 16;
    data[j] = (bits >> 8) & 0xff;
    break;
  }

  if (ret_len)
    *ret_len = j + 1;

  return data;
}
