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

/* Converts string to capital characters. */

bool silc_to_upper(const char *string, char *dest, SilcUInt32 dest_size)
{
  int i;

  if (strlen(string) > dest_size)
    return FALSE;

  for (i = 0; i < strlen(string); i++)
    dest[i] = toupper(string[i]);

  return TRUE;
}

/* Converts string to lower letter characters. */

bool silc_to_lower(const char *string, char *dest, SilcUInt32 dest_size)
{
  int i;

  if (strlen(string) > dest_size)
    return FALSE;

  for (i = 0; i < strlen(string); i++)
    dest[i] = tolower(string[i]);

  return TRUE;
}

/* Parse userfqdn string which is in user@fqdn format. */

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
  tmp = silc_calloc(strlen(cp) + 1, sizeof(*tmp));
  if (!tmp)
    return;
  silc_to_upper(cp, tmp, strlen(cp));
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
#define _PUT_STRING(__d__, __s__)					\
do {									\
  int __sp = sizeof(__d__) - 1 - strlen(__d__);				\
  if (__sp < strlen(__s__)) {						\
    if (__sp)								\
      strncat(__d__, __s__, (sizeof(__d__) - 1) - strlen(__d__));	\
  } else {								\
    strncat(__d__, __s__, strlen(__s__));				\
  }									\
} while(0)

char *silc_id_render(void *id, SilcUInt16 type)
{
  char tmp[100];
  unsigned char tmps[2];
  char *cp;

  memset(rid, 0, sizeof(rid));
  switch(type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id = (SilcServerID *)id;
      if (server_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ipv6.sin6_family = AF_INET6;
	memmove(&ipv6.sin6_addr, server_id->ip.data, sizeof(ipv6.sin6_addr));
	if (!getnameinfo((struct sockaddr *)&ipv6, sizeof(ipv6),
			 tmp, sizeof(tmp) - 1, NULL, 0, NI_NUMERICHOST))
	  _PUT_STRING(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, server_id->ip.data, 4);
	cp = inet_ntoa(ipv4);
	if (cp)
	  _PUT_STRING(rid, cp);
      }

      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp) - 1, ",%d,", ntohs(server_id->port));
      _PUT_STRING(rid, tmp);
      SILC_PUT16_MSB(server_id->rnd, tmps);
      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp) - 1, "[%02x %02x]", tmps[0], tmps[1]);
      _PUT_STRING(rid, tmp);
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = (SilcClientID *)id;
      if (client_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ipv6.sin6_family = AF_INET6;
	memmove(&ipv6.sin6_addr, client_id->ip.data, sizeof(ipv6.sin6_addr));
	if (!getnameinfo((struct sockaddr *)&ipv6, sizeof(ipv6),
			 tmp, sizeof(tmp) - 1, NULL, 0, NI_NUMERICHOST))
	  _PUT_STRING(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, client_id->ip.data, 4);
	cp = inet_ntoa(ipv4);
	if (cp)
	  _PUT_STRING(rid, cp);
      }

      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp) - 1, ",%02x,", client_id->rnd);
      _PUT_STRING(rid, tmp);
      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp) - 1, "[%02x %02x %02x %02x...]",
	       client_id->hash[0], client_id->hash[1],
	       client_id->hash[2], client_id->hash[3]);
      _PUT_STRING(rid, tmp);
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = (SilcChannelID *)id;
      if (channel_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ipv6.sin6_family = AF_INET6;
	memmove(&ipv6.sin6_addr, channel_id->ip.data, sizeof(ipv6.sin6_addr));
	if (!getnameinfo((struct sockaddr *)&ipv6, sizeof(ipv6),
			 tmp, sizeof(tmp) - 1, NULL, 0, NI_NUMERICHOST))
	  _PUT_STRING(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, channel_id->ip.data, 4);
	cp = inet_ntoa(ipv4);
	if (cp)
	  _PUT_STRING(rid, cp);
      }

      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp) - 1, ",%d,", ntohs(channel_id->port));
      _PUT_STRING(rid, tmp);
      SILC_PUT16_MSB(channel_id->rnd, tmps);
      memset(tmp, 0, sizeof(tmp));
      snprintf(tmp, sizeof(tmp) - 1, "[%02x %02x]", tmps[0], tmps[1]);
      _PUT_STRING(rid, tmp);
    }
    break;
  }

  return rid;
}
#undef _PUT_STRING

/* Compares two strings. Strings may include wildcards '*' and '?'.
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

      /* The client ID is hashed by hashing the hash of the ID
	 (which is a truncated MD5 hash of the nickname) so that we
	 can access the entry from the cache with both Client ID but
	 with just a hash from the ID as well. */
      return silc_hash_client_id_hash(id->hash, NULL);
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

/* Hash Client ID's hash. */

SilcUInt32 silc_hash_client_id_hash(void *key, void *user_context)
{
  int i;
  unsigned char *hash = key;
  SilcUInt32 h = 0, g;

  for (i = 0; i < CLIENTID_HASH_LEN; i++) {
    h = (h << 4) + hash[i];
    if ((g = h & 0xf0000000)) {
      h = h ^ (g >> 24);
      h = h ^ g;
    }
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

/* Hashed SILC Public key. */

SilcUInt32 silc_hash_public_key(void *key, void *user_context)
{
  SilcPublicKey pk = (SilcPublicKey)key;
  return (pk->len + silc_hash_string(pk->name, NULL) +
	  silc_hash_string(pk->identifier, NULL) +
	  silc_hash_data(pk->pk, (void *)pk->pk_len));
}

/* Compares two strings. It may be used as SilcHashTable comparison
   function. */

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

/* Compares two SILC Public keys. It may be used as SilcHashTable
   comparison function. */

bool silc_hash_public_key_compare(void *key1, void *key2, void *user_context)
{
  return silc_pkcs_public_key_compare(key1, key2);
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

  if (mode & SILC_CHANNEL_MODE_SILENCE_USERS)
    strncat(string, "m", 1);

  if (mode & SILC_CHANNEL_MODE_SILENCE_OPERS)
    strncat(string, "M", 1);

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

  if (mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES)
    strncat(string, "b", 1);

  if (mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS)
    strncat(string, "u", 1);

  if (mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS)
    strncat(string, "r", 1);

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

/* Return TRUE if the `data' is ASCII string. */

bool silc_string_is_ascii(const unsigned char *data, SilcUInt32 data_len)
{
  int i;

  for (i = 0; i < data_len; i++) {
    if (!isascii(data[i]))
      return FALSE;
  }

  return TRUE;
}

/* Parses SILC protocol style version string. */

bool silc_parse_version_string(const char *version,
			       SilcUInt32 *protocol_version,
			       char **protocol_version_string,
			       SilcUInt32 *software_version,
			       char **software_version_string,
			       char **vendor_version)
{
  char *cp, buf[32];
  int maj = 0, min = 0;

  if (!strstr(version, "SILC-"))
    return FALSE;

  cp = (char *)version + 5;
  if (!cp)
    return FALSE;

  /* Take protocol version */

  maj = atoi(cp);
  cp = strchr(cp, '.');
  if (cp) {
    min = atoi(cp + 1);
    cp++;
  }

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%d%d", maj, min);
  if (protocol_version)
    *protocol_version = atoi(buf);
  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%d.%d", maj, min);
  if (protocol_version_string)
    *protocol_version_string = strdup(buf);

  /* Take software version */

  maj = 0;
  min = 0;
  cp = strchr(cp, '-');
  if (!cp)
    return FALSE;

  maj = atoi(cp + 1);
  cp = strchr(cp, '.');
  if (cp)
    min = atoi(cp + 1);

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%d%d", maj, min);
  if (software_version)
    *software_version = atoi(buf);
  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%d.%d", maj, min);
  if (software_version_string)
    *software_version_string = strdup(buf);

  /* Take vendor string */

  cp++;
  if (cp) {
    cp = strchr(cp, '.');
    if (cp && cp + 1 && vendor_version)
      *vendor_version = strdup(cp + 1);
  }

  return TRUE;
}

/* Converts version string x.x into number representation. */

SilcUInt32 silc_version_to_num(const char *version)
{
  int maj = 0, min = 0;
  char *cp, buf[32];

  if (!version)
    return 0;

  cp = (char *)version;
  maj = atoi(cp);
  cp = strchr(cp, '.');
  if (cp)
    min = atoi(cp + 1);

  memset(buf, 0, sizeof(buf));
  snprintf(buf, sizeof(buf) - 1, "%d%d", maj, min);
  return (SilcUInt32)atoi(buf);
}

/* Displays input prompt on command line and takes input data from user */

char *silc_get_input(const char *prompt, bool echo_off)
{
#ifdef SILC_UNIX
  if (echo_off) {
    char *ret = NULL;
#ifdef HAVE_TERMIOS_H
    char input[2048];
    int fd;
    struct termios to;
    struct termios to_old;

    fd = open("/dev/tty", O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "silc: %s\n", strerror(errno));
      return NULL;
    }

    signal(SIGINT, SIG_IGN);

    /* Get terminal info */
    tcgetattr(fd, &to);
    to_old = to;

    /* Echo OFF */
    to.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(fd, TCSANOW, &to);

    memset(input, 0, sizeof(input));

    printf("%s", prompt);
    fflush(stdout);

    if ((read(fd, input, sizeof(input))) < 0) {
      fprintf(stderr, "silc: %s\n", strerror(errno));
      return NULL;
    }

    if (strlen(input) <= 1) {
      tcsetattr(fd, TCSANOW, &to_old);
      return NULL;
    }

    if (strchr(input, '\n'))
      *strchr(input, '\n') = '\0';

    /* Restore old terminfo */
    tcsetattr(fd, TCSANOW, &to_old);
    signal(SIGINT, SIG_DFL);

    ret = silc_calloc(strlen(input), sizeof(char));
    memcpy(ret, input, strlen(input));
    memset(input, 0, sizeof(input));
#endif /* HAVE_TERMIOS_H */
    return ret;
  } else {
    char input[2048];
    int fd;

    fd = open("/dev/tty", O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "silc: %s\n", strerror(errno));
      return NULL;
    }

    memset(input, 0, sizeof(input));

    printf("%s", prompt);
    fflush(stdout);

    if ((read(fd, input, sizeof(input))) < 0) {
      fprintf(stderr, "silc: %s\n", strerror(errno));
      return NULL;
    }

    if (strlen(input) <= 1)
      return NULL;

    if (strchr(input, '\n'))
      *strchr(input, '\n') = '\0';

    return strdup(input);
  }
#else
  return NULL;
#endif /* SILC_UNIX */
}

/* Return mode list */

bool silc_get_mode_list(SilcBuffer mode_list, SilcUInt32 mode_list_count,
			SilcUInt32 **list)
{
  int i;

  if (mode_list->len / 4 != mode_list_count)
    return FALSE;

  *list = silc_calloc(mode_list_count, sizeof(**list));

  for (i = 0; i < mode_list_count; i++) {
    SILC_GET32_MSB((*list)[i], mode_list->data);
    silc_buffer_pull(mode_list, 4);
  }

  silc_buffer_push(mode_list, mode_list->data - mode_list->head);

  return TRUE;
}

/* Status message structure. Messages are defined below. */
typedef struct {
  SilcStatus status;
  char *message;
} SilcStatusMessage;

#define STAT(x) SILC_STATUS_ERR_##x
const SilcStatusMessage silc_status_messages[] = {

  { STAT(NO_SUCH_NICK),      "There was no such nickname" },
  { STAT(NO_SUCH_CHANNEL),   "There was no such channel" },
  { STAT(NO_SUCH_SERVER),    "There was no such server" },
  { STAT(INCOMPLETE_INFORMATION),  "Incomplete registration information" },
  { STAT(NO_RECIPIENT),      "No recipient given" },
  { STAT(UNKNOWN_COMMAND),   "Unknown command" },
  { STAT(WILDCARDS),         "Wilcrads not allowed" },
  { STAT(NO_CLIENT_ID),      "No Client ID given" },
  { STAT(NO_CHANNEL_ID),     "No Channel ID given" },
  { STAT(NO_SERVER_ID),      "No Server ID given" },
  { STAT(BAD_CLIENT_ID),     "Bad Client ID" },
  { STAT(BAD_CHANNEL_ID),    "Bad Channel ID" },
  { STAT(NO_SUCH_CLIENT_ID), "There is no such client" },
  { STAT(NO_SUCH_CHANNEL_ID),"There is no such channel" },
  { STAT(NICKNAME_IN_USE),   "Nickname already exists" },
  { STAT(NOT_ON_CHANNEL),    "You are not on that channel" },
  { STAT(USER_NOT_ON_CHANNEL),"They are not on the channel" },
  { STAT(USER_ON_CHANNEL),   "User already on the channel" },
  { STAT(NOT_REGISTERED),    "You have not registered" },
  { STAT(NOT_ENOUGH_PARAMS), "Not enough parameters" },
  { STAT(TOO_MANY_PARAMS),   "Too many parameters" },
  { STAT(PERM_DENIED),       "Permission denied" },
  { STAT(BANNED_FROM_SERVER),"You are banned from this server" },
  { STAT(BAD_PASSWORD),      "Cannot join channel. Incorrect password" },
  { STAT(CHANNEL_IS_FULL),   "Cannot join channel. Channel is full" },
  { STAT(NOT_INVITED),     "Cannot join channel. You have not been invited" },
  { STAT(BANNED_FROM_CHANNEL), "Cannot join channel. You have been banned" },
  { STAT(UNKNOWN_MODE),    "Unknown mode" },
  { STAT(NOT_YOU),         "Cannot change mode for other users" },
  { STAT(NO_CHANNEL_PRIV), "Permission denied. You are not channel operator" },
  { STAT(NO_CHANNEL_FOPRIV),"Permission denied. You are not channel founder" },
  { STAT(NO_SERVER_PRIV),  "Permission denied. You are not server operator" },
  { STAT(NO_ROUTER_PRIV),  "Permission denied. You are not SILC operator" },
  { STAT(BAD_NICKNAME),    "Bad nickname" },
  { STAT(BAD_CHANNEL),     "Bad channel name" },
  { STAT(AUTH_FAILED),     "Authentication failed" },
  { STAT(UNKNOWN_ALGORITHM), "Unsupported algorithm" },
  { STAT(NO_SUCH_SERVER_ID), "No such Server ID" },
  { STAT(RESOURCE_LIMIT), "No more free resources" },
  { STAT(NO_SUCH_SERVICE), "Service doesn't exist" },
  { STAT(NOT_AUTHENTICATED), "You have not been authenticated" },
  { STAT(BAD_SERVER_ID), "Server ID is not valid" },
  { STAT(KEY_EXCHANGE_FAILED), "Key exchange failed" },
  { STAT(BAD_VERSION), "Bad version" },

  { 0, NULL }
};

/* Returns status message string */

char *silc_get_status_message(unsigned char status)
{
  int i;

  for (i = 0; silc_status_messages[i].message; i++) {
    if (silc_status_messages[i].status == status)
      break;
  }

  if (silc_status_messages[i].message == NULL)
    return "";

  return silc_status_messages[i].message;
}
