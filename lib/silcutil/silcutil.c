/*

  silcutil.c 

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
/*
 * These are general utility functions that doesn't belong to any specific
 * group of routines.
 */
/* $Id$ */

#include "silcincludes.h"

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

static unsigned char pem_enc[64] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encodes data into PEM encoding. Returns NULL terminated PEM encoded
   data string. Note: This is originally public domain code and is 
   still PD. */

char *silc_encode_pem(unsigned char *data, SilcUInt32 len)
{
  int i, j;
  SilcUInt32 bits, c, char_count;
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

char *silc_encode_pem_file(unsigned char *data, SilcUInt32 data_len)
{
  int i, j;
  SilcUInt32 len, cols;
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

  silc_free(pem);
  return pem2;
}

/* Decodes PEM into data. Returns the decoded data. Note: This is
   originally public domain code and is still PD. */

unsigned char *silc_decode_pem(unsigned char *pem, SilcUInt32 pem_len,
			       SilcUInt32 *ret_len)
{
  int i, j;
  SilcUInt32 len, c, char_count, bits;
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
    data[j++] = bits >> 10;
    break;
  case 3:
    data[j++] = bits >> 16;
    data[j++] = (bits >> 8) & 0xff;
    break;
  }

  if (ret_len)
    *ret_len = j;

  return data;
}

/* Parse userfqdn string which is in user@fqdn format */

bool silc_parse_userfqdn(const char *string, char **left, char **right)
{
  SilcUInt32 tlen;

  if (!string)
    return FALSE;

  if (string[0] == '@') {
    if (left)
      *left = strdup(string);
    return TRUE;
  }

  if (strchr(string, '@')) {
    tlen = strcspn(string, "@");
    
    if (left) {
      *left = silc_calloc(tlen + 1, sizeof(char));
      memcpy(*left, string, tlen);
    }
    
    if (right) {
      *right = silc_calloc((strlen(string) - tlen) + 1, sizeof(char));
      memcpy(*right, string + tlen + 1, strlen(string) - tlen - 1);
    }
  } else {
    if (left)
      *left = strdup(string);
  }

  return TRUE;
}

/* Parses command line. At most `max_args' is taken. Rest of the line
   will be allocated as the last argument if there are more than `max_args'
   arguments in the line. Note that the command name is counted as one
   argument and is saved. */

void silc_parse_command_line(unsigned char *buffer, 
			     unsigned char ***parsed,
			     SilcUInt32 **parsed_lens,
			     SilcUInt32 **parsed_types,
			     SilcUInt32 *parsed_num,
			     SilcUInt32 max_args)
{
  int i, len = 0;
  int argc = 0;
  const char *cp = buffer;
  char *tmp;

  *parsed = silc_calloc(1, sizeof(**parsed));
  *parsed_lens = silc_calloc(1, sizeof(**parsed_lens));

  /* Get the command first */
  len = strcspn(cp, " ");
  tmp = silc_to_upper((char *)cp);
  (*parsed)[0] = silc_calloc(len + 1, sizeof(char));
  memcpy((*parsed)[0], tmp, len);
  silc_free(tmp);
  (*parsed_lens)[0] = len;
  cp += len;
  while (*cp == ' ')
    cp++;
  argc++;

  /* Parse arguments */
  if (strchr(cp, ' ') || strlen(cp) != 0) {
    for (i = 1; i < max_args; i++) {

      if (i != max_args - 1)
	len = strcspn(cp, " ");
      else
	len = strlen(cp);
      while (len && cp[len - 1] == ' ')
	len--;
      if (!len)
	break;
      
      *parsed = silc_realloc(*parsed, sizeof(**parsed) * (argc + 1));
      *parsed_lens = silc_realloc(*parsed_lens, 
				  sizeof(**parsed_lens) * (argc + 1));
      (*parsed)[argc] = silc_calloc(len + 1, sizeof(char));
      memcpy((*parsed)[argc], cp, len);
      (*parsed_lens)[argc] = len;
      argc++;

      cp += len;
      if (strlen(cp) == 0)
	break;
      else
	while (*cp == ' ')
	  cp++;
    }
  }

  /* Save argument types. Protocol defines all argument types but
     this implementation makes sure that they are always in correct
     order hence this simple code. */
  *parsed_types = silc_calloc(argc, sizeof(**parsed_types));
  for (i = 0; i < argc; i++)
    (*parsed_types)[i] = i;

  *parsed_num = argc;
}

/* Formats arguments to a string and returns it after allocating memory
   for it. It must be remembered to free it later. */

char *silc_format(char *fmt, ...)
{
  va_list args;
  static char buf[8192];

  memset(buf, 0, sizeof(buf));
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf) - 1, fmt, args);
  va_end(args);

  return strdup(buf);
}

/* Renders ID to suitable to print for example to log file. */

static char rid[256];

char *silc_id_render(void *id, SilcUInt16 type)
{
  char tmp[100];
  unsigned char tmps[2];

  memset(rid, 0, sizeof(rid));
  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id = (SilcServerID *)id;
      if (server_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct in6_addr ipv6;
	memmove(&ipv6, server_id->ip.data, sizeof(ipv6));
	if (!inet_ntop(AF_INET6, &ipv6, tmp, sizeof(tmp)))
	  strcat(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, server_id->ip.data, 4);
	strcat(rid, inet_ntoa(ipv4));
      }

      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp), ",%d,", ntohs(server_id->port));
      strcat(rid, tmp);
      SILC_PUT16_MSB(server_id->rnd, tmps);
      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp), "[%02x %02x]", tmps[0], tmps[1]);
      strcat(rid, tmp);
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = (SilcClientID *)id;
      if (client_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct in6_addr ipv6;
	memmove(&ipv6, client_id->ip.data, sizeof(ipv6));
	if (!inet_ntop(AF_INET6, &ipv6, tmp, sizeof(tmp)))
	  strcat(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, client_id->ip.data, 4);
	strcat(rid, inet_ntoa(ipv4));
      }

      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp), ",%02x,", client_id->rnd);
      strcat(rid, tmp);
      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp), "[%02x %02x %02x %02x...]", 
	       client_id->hash[0], client_id->hash[1],
	       client_id->hash[2], client_id->hash[3]);
      strcat(rid, tmp);
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = (SilcChannelID *)id;
      if (channel_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct in6_addr ipv6;
	memmove(&ipv6, channel_id->ip.data, sizeof(ipv6));
	if (!inet_ntop(AF_INET6, &ipv6, tmp, sizeof(tmp)))
	  strcat(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, channel_id->ip.data, 4);
	strcat(rid, inet_ntoa(ipv4));
      }

      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp), ",%d,", ntohs(channel_id->port));
      strcat(rid, tmp);
      SILC_PUT16_MSB(channel_id->rnd, tmps);
      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp), "[%02x %02x]", tmps[0], tmps[1]);
      strcat(rid, tmp);
    }
    break;
  }

  return rid;
}

/* Compares two strings. Strings may include wildcards * and ?.
   Returns TRUE if strings match. */

int silc_string_compare(char *string1, char *string2)
{
  int i;
  int slen1;
  int slen2;
  char *tmpstr1, *tmpstr2;

  if (!string1 || !string2)
    return FALSE;

  slen1 = strlen(string1);
  slen2 = strlen(string2);

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
  
  for (i = 0; i < slen1; i++) {
    
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

/* Basic has function to hash strings. May be used with the SilcHashTable. 
   Note that this lowers the characters of the string (with tolower()) so
   this is used usually with nicknames, channel and server names to provide
   case insensitive keys. */

SilcUInt32 silc_hash_string(void *key, void *user_context)
{
  char *s = (char *)key;
  SilcUInt32 h = 0, g;
  
  while (*s != '\0') {
    h = (h << 4) + tolower(*s);
    if ((g = h & 0xf0000000)) {
      h = h ^ (g >> 24);
      h = h ^ g;
    }
    s++;
  }
  
  return h;
}

/* Basic hash function to hash integers. May be used with the SilcHashTable. */

SilcUInt32 silc_hash_uint(void *key, void *user_context)
{
  return *(SilcUInt32 *)key;
}

/* Basic hash funtion to hash pointers. May be used with the SilcHashTable. */

SilcUInt32 silc_hash_ptr(void *key, void *user_context)
{
  return (SilcUInt32)key;
}

/* Hash a ID. The `user_context' is the ID type. */

SilcUInt32 silc_hash_id(void *key, void *user_context)
{
  SilcIdType id_type = (SilcIdType)(SilcUInt32)user_context;
  SilcUInt32 h = 0;
  int i;

  switch (id_type) {
  case SILC_ID_CLIENT:
    {
      SilcClientID *id = (SilcClientID *)key;
      SilcUInt32 g;
  
      /* The client ID is hashed by hashing the hash of the ID 
	 (which is a truncated MD5 hash of the nickname) so that we
	 can access the entry from the cache with both Client ID but
	 with just a hash from the ID as well. */

      for (i = 0; i < sizeof(id->hash); i++) {
	h = (h << 4) + id->hash[i];
	if ((g = h & 0xf0000000)) {
	  h = h ^ (g >> 24);
	  h = h ^ g;
	}
      }

      return h;
    }
    break;
  case SILC_ID_SERVER:
    {
      SilcServerID *id = (SilcServerID *)key;
      
      h = id->port * id->rnd;
      for (i = 0; i < id->ip.data_len; i++)
	h ^= id->ip.data[i];
      
      return h;
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *id = (SilcChannelID *)key;
      
      h = id->port * id->rnd;
      for (i = 0; i < id->ip.data_len; i++)
	h ^= id->ip.data[i];
      
      return h;
    }
    break;
  default:
    break;
  }

  return h;
}

/* Hash binary data. The `user_context' is the data length. */

SilcUInt32 silc_hash_data(void *key, void *user_context)
{
  SilcUInt32 len = (SilcUInt32)user_context, h = 0;
  unsigned char *data = (unsigned char *)key;
  int i;

  h = (data[0] * data[len - 1] + 1) * len;
  for (i = 0; i < len; i++)
    h ^= data[i];

  return h;
}

/* Compares two strings. May be used as SilcHashTable comparison function. */

bool silc_hash_string_compare(void *key1, void *key2, void *user_context)
{
  return !strcasecmp((char *)key1, (char *)key2);
}

/* Compares two ID's. May be used as SilcHashTable comparison function. 
   The Client ID's compares only the hash of the Client ID not any other
   part of the Client ID. Other ID's are fully compared. */

bool silc_hash_id_compare(void *key1, void *key2, void *user_context)
{
  SilcIdType id_type = (SilcIdType)(SilcUInt32)user_context;
  return (id_type == SILC_ID_CLIENT ? 
	  SILC_ID_COMPARE_HASH((SilcClientID *)key1, (SilcClientID *)key2) :
	  SILC_ID_COMPARE_TYPE(key1, key2, id_type));
}

/* Compare two Client ID's entirely and not just the hash from the ID. */

bool silc_hash_client_id_compare(void *key1, void *key2, void *user_context)
{
  return SILC_ID_COMPARE_TYPE(key1, key2, SILC_ID_CLIENT);
}

/* Compares binary data. May be used as SilcHashTable comparison function. */

bool silc_hash_data_compare(void *key1, void *key2, void *user_context)
{
  SilcUInt32 len = (SilcUInt32)user_context;
  return !memcmp(key1, key2, len);
}

/* Parses mode mask and returns the mode as string. */

char *silc_client_chmode(SilcUInt32 mode, const char *cipher, const char *hmac)
{
  char string[100];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_MODE_PRIVATE)
    strncat(string, "p", 1);

  if (mode & SILC_CHANNEL_MODE_SECRET)
    strncat(string, "s", 1);

  if (mode & SILC_CHANNEL_MODE_PRIVKEY)
    strncat(string, "k", 1);

  if (mode & SILC_CHANNEL_MODE_INVITE)
    strncat(string, "i", 1);

  if (mode & SILC_CHANNEL_MODE_TOPIC)
    strncat(string, "t", 1);

  if (mode & SILC_CHANNEL_MODE_ULIMIT)
    strncat(string, "l", 1);

  if (mode & SILC_CHANNEL_MODE_PASSPHRASE)
    strncat(string, "a", 1);

  if (mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_MODE_CIPHER)
    strncat(string, cipher, strlen(cipher));

  if (mode & SILC_CHANNEL_MODE_HMAC)
    strncat(string, hmac, strlen(hmac));

  /* Rest of mode is ignored */

  return strdup(string);
}

/* Parses channel user mode mask and returns te mode as string */

char *silc_client_chumode(SilcUInt32 mode)
{
  char string[4];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "o", 1);

  return strdup(string);
}

/* Parses channel user mode and returns it as special mode character. */

char *silc_client_chumode_char(SilcUInt32 mode)
{
  char string[4];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "*", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "@", 1);

  return strdup(string);
}

/* Creates fingerprint from data, usually used with SHA1 digests */

char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len)
{
  char fingerprint[64], *cp;
  int i;

  memset(fingerprint, 0, sizeof(fingerprint));
  cp = fingerprint;
  for (i = 0; i < data_len; i++) {
    snprintf(cp, sizeof(fingerprint), "%02X", data[i]);
    cp += 2;
    
    if ((i + 1) % 2 == 0)
      snprintf(cp++, sizeof(fingerprint), " ");

    if ((i + 1) % 10 == 0)
      snprintf(cp++, sizeof(fingerprint), " ");
  }
  i--;
  if ((i + 1) % 2 == 0)
    cp[-2] = 0;
  if ((i + 1) % 10 == 0)
    cp[-1] = 0;
  
  return strdup(fingerprint);
}
