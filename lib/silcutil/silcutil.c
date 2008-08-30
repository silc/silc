/*

  silcutil.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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

#include "silc.h"

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

/* Converts string to capital characters. */

SilcBool silc_to_upper(const char *string, char *dest, SilcUInt32 dest_size)
{
  int i;

  if (strlen(string) > dest_size)
    return FALSE;

  for (i = 0; i < strlen(string); i++)
    dest[i] = (char)toupper((int)string[i]);

  return TRUE;
}

/* Converts string to lower letter characters. */

SilcBool silc_to_lower(const char *string, char *dest, SilcUInt32 dest_size)
{
  int i;

  if (strlen(string) > dest_size)
    return FALSE;

  for (i = 0; i < strlen(string); i++)
    dest[i] = (char)tolower((int)string[i]);

  return TRUE;
}

/* Parse userfqdn string which is in user@fqdn format. */

int silc_parse_userfqdn(const char *string,
			char *user, SilcUInt32 user_size,
			char *fqdn, SilcUInt32 fqdn_size)
{
  SilcUInt32 tlen;

  if (!user && !fqdn)
    return 0;

  if (user)
    memset(user, 0, user_size);
  if (user)
    memset(fqdn, 0, fqdn_size);

  if (!string)
    return 0;

  if (string[0] == '@') {
    if (user)
      silc_strncat(user, user_size, string, strlen(string));

    return 1;
  }

  if (strchr(string, '@')) {
    tlen = strcspn(string, "@");

    if (user)
      silc_strncat(user, user_size, string, tlen);

    if (fqdn)
      silc_strncat(fqdn, fqdn_size, string + tlen + 1,
		   strlen(string) - tlen - 1);

    return 2;
  }

  if (user)
    silc_strncat(user, user_size, string, strlen(string));

  return 1;
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
  char buf[8192];

  memset(buf, 0, sizeof(buf));
  va_start(args, fmt);
  silc_vsnprintf(buf, sizeof(buf) - 1, fmt, args);
  va_end(args);

  return strdup(buf);
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
    h = (h << 4) + tolower((int)*s);
    if ((g = h & 0xf0000000)) {
      h = h ^ (g >> 24);
      h = h ^ g;
    }
    s++;
  }

  return h;
}

/* Hash UTF-8 string */

SilcUInt32 silc_hash_utf8_string(void *key, void *user_context)
{
  unsigned char *s = (unsigned char *)key;
  SilcUInt32 h = 0, g;

  while (*s != '\0') {
    h = (h << 4) + *s;
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
  return SILC_PTR_TO_32(key);
}

/* Basic hash funtion to hash pointers. May be used with the SilcHashTable. */

SilcUInt32 silc_hash_ptr(void *key, void *user_context)
{
  return SILC_PTR_TO_32(key);
}

/* Hash a ID. The `user_context' is the ID type. */

SilcUInt32 silc_hash_id(void *key, void *user_context)
{
  SilcIdType id_type = (SilcIdType)SILC_PTR_TO_32(user_context);
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
  SilcUInt32 len = SILC_PTR_TO_32(user_context), h = 0;
  unsigned char *data = (unsigned char *)key;
  int i;

  h = (data[0] * data[len - 1] + 1) * len;
  for (i = 0; i < len; i++)
    h ^= data[i];

  return h;
}

/* Hash public key of any type. */

SilcUInt32 silc_hash_public_key(void *key, void *user_context)
{
  SilcPublicKey public_key = key;
  unsigned char *pk;
  SilcUInt32 pk_len;
  SilcUInt32 hash = 0;

  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk)
    return hash;

  hash = silc_hash_data(pk, SILC_32_TO_PTR(pk_len));
  silc_free(pk);

  return hash;
}

/* Compares two strings. It may be used as SilcHashTable comparison
   function. */

SilcBool silc_hash_string_compare(void *key1, void *key2, void *user_context)
{
  return !strcasecmp((char *)key1, (char *)key2);
}

/* Compares two ID's. May be used as SilcHashTable comparison function.
   The Client ID's compares only the hash of the Client ID not any other
   part of the Client ID. Other ID's are fully compared. */

SilcBool silc_hash_id_compare(void *key1, void *key2, void *user_context)
{
  SilcIdType id_type = (SilcIdType)SILC_PTR_TO_32(user_context);
  return (id_type == SILC_ID_CLIENT ?
	  SILC_ID_COMPARE_HASH((SilcClientID *)key1, (SilcClientID *)key2) :
	  SILC_ID_COMPARE_TYPE(key1, key2, id_type));
}

/* Compares two ID's. Compares full IDs. */

SilcBool silc_hash_id_compare_full(void *key1, void *key2, void *user_context)
{
  SilcIdType id_type = (SilcIdType)SILC_PTR_TO_32(user_context);
  return SILC_ID_COMPARE_TYPE(key1, key2, id_type);
}

/* Compare two Client ID's entirely and not just the hash from the ID. */

SilcBool silc_hash_client_id_compare(void *key1, void *key2,
				     void *user_context)
{
  return SILC_ID_COMPARE_TYPE(key1, key2, SILC_ID_CLIENT);
}

/* Compares binary data. May be used as SilcHashTable comparison function. */

SilcBool silc_hash_data_compare(void *key1, void *key2, void *user_context)
{
  SilcUInt32 len = SILC_PTR_TO_32(user_context);
  return !memcmp(key1, key2, len);
}

/* Compares UTF-8 string. */

SilcBool silc_hash_utf8_compare(void *key1, void *key2, void *user_context)
{
  int l1 = strlen((char *)key1);
  int l2 = strlen((char *)key2);
  if (l1 != l2)
    return FALSE;
  return !memcmp(key1, key2, l2);
}

/* Compares two SILC Public keys. It may be used as SilcHashTable
   comparison function. */

SilcBool silc_hash_public_key_compare(void *key1, void *key2,
				      void *user_context)
{
  return silc_pkcs_public_key_compare(key1, key2);
}

/* Creates fingerprint from data, usually used with SHA1 digests */

char *silc_fingerprint(const unsigned char *data, SilcUInt32 data_len)
{
  unsigned char *fingerprint, *cp;
  unsigned int len, blocks, i;

  if (!data || !data_len)
    return NULL;

  if (data_len >= 256)
    data_len = 255;

  /* Align and calculate total length */
  len = ((data_len + 19) / 20) * 20;
  blocks = (len / 10);
  len = (len * 2) + ((blocks - 1) * 2) + (4 * blocks) + 2 + 1;

  cp = fingerprint = silc_calloc(len, sizeof(*fingerprint));
  if (!cp)
    return NULL;

  for (i = 0; i < data_len; i++) {
    silc_snprintf(cp, len, "%02X", data[i]);
    cp += 2;
    len -= 2;

    if ((i + 1) % 2 == 0)
      silc_snprintf(cp++, len--, " ");
    if ((i + 1) % 10 == 0)
      silc_snprintf(cp++, len--, " ");
  }
  i--;
  if ((i + 1) % 10 == 0)
    *(--cp) = '\0';
  if ((i + 1) % 2 == 0)
    *(--cp) = '\0';

  return fingerprint;
}

/* Return TRUE if the `data' is ASCII string. */

SilcBool silc_string_is_ascii(const unsigned char *data, SilcUInt32 data_len)
{
  int i;

  for (i = 0; i < data_len; i++) {
    if (!isascii(data[i]))
      return FALSE;
  }

  return TRUE;
}

/* Displays input prompt on command line and takes input data from user */

char *silc_get_input(const char *prompt, SilcBool echo_off)
{
#ifdef SILC_UNIX
  int fd;
  char input[2048];

  if (echo_off) {
    char *ret = NULL;
#ifdef HAVE_TERMIOS_H
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

    /* Echo OFF, and assure we can prompt and get input */
    to.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    to.c_lflag |= ICANON;
    to.c_cc[VMIN] = 255;
    tcsetattr(fd, TCSANOW, &to);

    memset(input, 0, sizeof(input));

    printf("%s", prompt);
    fflush(stdout);

  read_again1:
    if ((read(fd, input, sizeof(input))) < 0) {
      if (errno == EAGAIN || errno == EINTR)
	goto read_again1;
      fprintf(stderr, "silc: %s\n", strerror(errno));
      signal(SIGINT, SIG_DFL);
      tcsetattr(fd, TCSANOW, &to_old);
      return NULL;
    }

    if (strlen(input) <= 1) {
      signal(SIGINT, SIG_DFL);
      tcsetattr(fd, TCSANOW, &to_old);
      return NULL;
    }

    if (strchr(input, '\n'))
      *strchr(input, '\n') = '\0';

    /* Restore old terminfo */
    tcsetattr(fd, TCSANOW, &to_old);
    signal(SIGINT, SIG_DFL);

    ret = silc_memdup(input, strlen(input));
    memset(input, 0, sizeof(input));
#endif /* HAVE_TERMIOS_H */
    return ret;
  } else {
    fd = open("/dev/tty", O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "silc: %s\n", strerror(errno));
      return NULL;
    }

    memset(input, 0, sizeof(input));

    printf("%s", prompt);
    fflush(stdout);

    signal(SIGINT, SIG_IGN);

  read_again2:
    if ((read(fd, input, sizeof(input))) < 0) {
      if (errno == EAGAIN || errno == EINTR)
	goto read_again2;
      fprintf(stderr, "silc: %s\n", strerror(errno));
      signal(SIGINT, SIG_DFL);
      return NULL;
    }

    signal(SIGINT, SIG_DFL);

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
