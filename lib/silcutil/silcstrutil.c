/*

  silcstrutil.c

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
/* $Id$ */

#include "silc.h"
#include "silcstrutil.h"

/* Concatenates the `src' into `dest'.  If `src_len' is more than the
   size of the `dest' (minus NULL at the end) the `src' will be
   truncated to fit. */

char *silc_strncat(char *dest, SilcUInt32 dest_size,
		   const char *src, SilcUInt32 src_len)
{
  int len;

  dest[dest_size - 1] = '\0';

  len = dest_size - 1 - strlen(dest);
  if (len < src_len) {
    if (len > 0)
      strncat(dest, src, len);
  } else {
    strncat(dest, src, src_len);
  }

  return dest;
}

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
  if (!strncmp(string1, string2, slen2) && slen2 == slen1)
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

/* Splits a string containing separator `ch' and returns an array of the
   splitted strings. */

char **silc_string_split(const char *string, char ch, int *ret_count)
{
  char **splitted = NULL, sep[1], *item, *cp;
  int i = 0, len;

  if (!string)
    return NULL;
  if (!ret_count)
    return NULL;

  splitted = silc_calloc(1, sizeof(*splitted));
  if (!splitted)
    return NULL;

  if (!strchr(string, ch)) {
    splitted[0] = silc_memdup(string, strlen(string));
    *ret_count = 1;
    return splitted;
  }

  sep[0] = ch;
  cp = (char *)string;
  while(cp) {
    len = strcspn(cp, sep);
    item = silc_memdup(cp, len);
    if (!item) {
      silc_free(splitted);
      return NULL;
    }

    cp += len;
    if (strlen(cp) == 0)
      cp = NULL;
    else
      cp++;

    splitted = silc_realloc(splitted, (i + 1) * sizeof(*splitted));
    if (!splitted)
      return NULL;
    splitted[i++] = item;
  }
  *ret_count = i;

  return splitted;
}

/* Inspects the `string' for wildcards and returns regex string that can
   be used by the GNU regex library. A comma (`,') in the `string' means
   that the string is list. */

char *silc_string_regexify(const char *string)
{
  int i, len, count;
  char *regex;

  if (!string)
    return NULL;

  len = strlen(string);
  count = 4;
  for (i = 0; i < len; i++) {
    if (string[i] == '*' || string[i] == '?')
      count++;			/* Will add '.' */
    if (string[i] == ',')
      count += 2;		/* Will add '|' and '^' */
  }

  regex = silc_calloc(len + count + 1, sizeof(*regex));
  if (!regex)
    return NULL;

  count = 0;
  regex[count++] = '(';
  regex[count++] = '^';

  for (i = 0; i < len; i++) {
    if (string[i] == '*' || string[i] == '?') {
      regex[count] = '.';
      count++;
    } else if (string[i] == ',') {
      if (i + 2 == len)
	continue;
      regex[count++] = '|';
      regex[count++] = '^';
      continue;
    }

    regex[count++] = string[i];
  }

  regex[count++] = ')';
  regex[count] = '$';

  return regex;
}

/* Combines two regex strings into one regex string so that they can be
   used as one by the GNU regex library. The `string2' is combine into
   the `string1'. */

char *silc_string_regex_combine(const char *string1, const char *string2)
{
  char *tmp;
  int len1, len2;

  if (!string1 || !string2)
    return NULL;

  len1 = strlen(string1);
  len2 = strlen(string2);

  tmp = silc_calloc(2 + len1 + len2, sizeof(*tmp));
  strncat(tmp, string1, len1 - 2);
  strncat(tmp, "|", 1);
  strncat(tmp, string2 + 1, len2 - 1);

  return tmp;
}

/* Matches the two strings and returns TRUE if the strings match. */

int silc_string_regex_match(const char *regex, const char *string)
{
  regex_t preg;
  int ret = FALSE;

  if (regcomp(&preg, regex, REG_NOSUB | REG_EXTENDED) != 0)
    return FALSE;

  if (regexec(&preg, string, 0, NULL, 0) == 0)
    ret = TRUE;

  regfree(&preg);

  return ret;
}

/* Do regex match to the two strings `string1' and `string2'. If the
   `string2' matches the `string1' this returns TRUE. */

int silc_string_match(const char *string1, const char *string2)
{
  char *s1;
  int ret = FALSE;

  if (!string1 || !string2)
    return ret;

  s1 = silc_string_regexify(string1);
  ret = silc_string_regex_match(s1, string2);
  silc_free(s1);

  return ret;
}
