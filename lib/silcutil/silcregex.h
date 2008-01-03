/*

  silcregex.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Regular Expression Interface
 *
 * DESCRIPTION
 *
 * SILC regular expression interface provides Unix and POSIX compliant
 * regular expression compilation and matching.
 *
 * The interface also provides many convenience functions to make the use
 * of regular expressions easier.  Especially the silc_regex allows very
 * simple way to match strings against regular expressions and get the
 * exact match or matches as a return.
 *
 * The regex syntax follows POSIX regex syntax:
 *
 * Expressions:
 *   ^        Match start of line/string
 *              '^a' matches 'ab' but not 'ba'
 *   $        Match end of line/string
 *              'a$' matches 'ba' but not 'ab'
 *   .        Match any single character (except new line (\n))
 *              '.a' matches 'ba' but not 'a'
 *   +        Preceding item is matched one or more times
 *              'a+b' matches 'aaab' but not 'b'
 *   *        Preceding item is matched zero or more times
 *              'a*b' matches 'ab', 'aab' and 'b'
 *   ?        Preceding item is matched zero or one time
 *              'ca?b' matches 'cb' and 'cab' but not 'caab'
 *   |        Joins two expressions and matches either of them (OR)
 *              'foo|bar' matches 'foo' or 'bar'
 *   {n}      Preceding item is matched exactly n times (n can be 0-255)
 *              'a{2}' matches 'aa' but not 'aaa'
 *   {n,}     Preceding item is matched n or more times
 *              'a{2,} matches 'aa' and 'aaaa' but not 'a'
 *   {n,m}    Preceding item is matched at least n times and at most m times
 *              'a{2,4}' matches 'aa', 'aaa' and 'aaaa' but not 'aaaaa'
 *   [ ]      Match any single character in the character list inside [ ]
 *              '[0123]' matches only '0', '1', '2' or '3'
 *   [ - ]    Match any single character in the specified range
 *              '[0-5]' matches digits 0-5.
 *   [^ ]     Match any character not in the character list or range
 *              '[^09]]' matches any other character except '0' and '9'
 *   ( )      Subexpression, grouping
 *
 * Escaping (C-language style, '\' is written as '\\'):
 *   \\       Considers following character literal ('\\{' is '{')
 *   \\\\     Matches literal \
 *   \a       Matches bell (BEL)
 *   \t       Matches horizontal tab (HT)
 *   \n       Matches new line (LF)
 *   \v       Matches vertical tab (VT)
 *   \f       Matches form feed (FF)
 *   \r       Matches carriage ret (CR)
 *   \\<      Match null string at the start of a word
 *   \\>      Match null string at the end of a word
 *   \\b      Match null string at the edge of a wrod
 *   \\B      Match null string when not at the edge of a word
 *
 * EXAMPLE
 *
 * SilcRegexStruct reg;
 *
 * // Compile regular expression
 * if (!silc_regex_compile(&reg, "foo[0-9]*", 0))
 *   error;
 *
 * // Match string against the compiled regex
 * if (!silc_regex_match(&reg, "foo20", 0, NULL, 0))
 *   no_match;
 *
 * // Free the compiled regular expression
 * silc_regex_free(&reg);
 *
 ***/

#ifndef SILCREGEX_H
#define SILCREGEX_H

/****s* silcutil/SilcRegexAPI/SilcRegex
 *
 * NAME
 *
 *    typedef struct { ... } *SilcRegex, SilcRegexStruct;
 *
 * DESCRIPTION
 *
 *    The regular expression context.  This context is given as argument
 *    to all silc_regex_* functions.  It is usually statically allocated
 *    but can be dynamically allocated by silc_malloc.
 *
 ***/
typedef struct SilcRegexObject {
  SilcStack rstack;	       /* Stack for fast allocations */
  unsigned char *buffer;       /* compiled pattern */
  char *fastmap;               /* fastmap[ch] is true if ch can start pattern */
  char *translate;	       /* translation to apply during comp/match */
  int allocated;	       /* allocated size of compiled pattern */
  int used;		       /* actual length of compiled pattern */
  int num_registers;	       /* number of registers used */
  char fastmap_accurate;       /* true if fastmap is valid */
  char can_be_null;	       /* true if can match empty string */
  char uses_registers;         /* registers used and need to be initialized */
  char anchor;		       /* anchor: 0=none 1=begline 2=begbuf */
} *SilcRegex, SilcRegexStruct;

/****s* silcutil/SilcRegexAPI/SilcRegexMatch
 *
 * NAME
 *
 *    typedef struct { ... } *SilcRegexMatch, SilcRegexMatchStruct;
 *
 * DESCRIPTION
 *
 *    The regular expression match context that provides information on the
 *    found match.  It provides the start offset and end offset of the
 *    found match.
 *
 * SOURCE
 */
typedef struct SilcRegexMatchObject {
  int start;		       /* Start offset of region */
  int end;		       /* End offset of region */
} *SilcRegexMatch, SilcRegexMatchStruct;
/***/

/****d* silcutil/SilcRegexAPI/SilcRegexFlags
 *
 * NAME
 *
 *    typedef enum { ... } SilcRegexFlags;
 *
 * DESCRIPTION
 *
 *    Regular expression feature flags.
 *
 * SOURCE
 */
typedef enum {
  SILC_REGEX_DEFAULT   = 0x00000000,

  /* The following flags can be used with silc_regex_match */

  /* The beginning-of-line (^) always fails to match.  This can be useful
     when beginning of a string should not be interpreted as the beginning
     of line. */
  SILC_REGEX_NOTBOL    = 0x00010000,

  /* The end-of-line ($) always fails to match. */
  SILC_REGEX_NOTEOL    = 0x00020000,
} SilcRegexFlags;
/***/

/****f* silcutil/SilcRegexAPI/silc_regex_compile
 *
 * SYNOPSIS
 *
 *    SilcBool silc_regex_compile(SilcRegex regexp, const char *regex,
 *                                SilcRegexFlags flags);
 *
 * DESCRIPTION
 *
 *    Compiles the regular expression string `regex'.  The `regexp' is a
 *    pre-allocated regular expression context.  The `flags' define
 *    various feature flags.  This function must be called before the
 *    silc_regex_match can be used to find matches.
 *
 *    Returns TRUE after the compilation is completed.  Returns FALSE on
 *    error and sets silc_errno.
 *
 ***/
SilcBool silc_regex_compile(SilcRegex regexp, const char *regex,
			    SilcRegexFlags flags);

/****f* silcutil/SilcRegexAPI/silc_regex_compile
 *
 * SYNOPSIS
 *
 *    SilcBool silc_regex_match(SilcRegex regexp, const char *string,
 *                              SilcUInt32 string_len, SilcUInt32 num_match,
 *                              SilcRegexMatch match, SilcRegexFlags flags);
 *
 * DESCRIPTION
 *
 *    Finds one or more matches from the `string' using the pre-compiled
 *    regular expression `regexp'.  It must be compiled by calling the
 *    silc_regex_compile before calling this function.  The `flags' defines
 *    various feature flags.
 *
 *    If only one match is needed the `num_match' may be set to 0 and the
 *    `match' is set to NULL.  If multiple matches (substrings) are needed the
 *    `num_match' defines the size of the `match' array, where each of the
 *    matches (with parenthesized regular expression) will be stored.  The
 *    `match' provides information on where the match was found in `string',
 *    providing the start offset and end offset of the match.  Unused entires
 *    in the array will have -1 as the offset values.
 *
 *    Returns TRUE if the string matched the regular expression or FALSE
 *    if it did not match or error occurred.  The silc_errno will indicate
 *    the error.  The silc_errno is set to SILC_ERR_NOT_FOUND if the regular
 *    expression did not match.
 *
 * EXAMPLE
 *
 *    // Find first match (check if string matches)
 *    if (!silc_regex_match(&reg, "foo20", 5, 0, NULL, 0))
 *      no_match;
 *
 *    // Find multiple matches, one by one
 *    SilcRegexMatchStruct match;
 *
 *    while (silc_regex_match(&reg, string, len, 1, &match, 0)) {
 *      match_string = silc_memdup(string + match.start,
 *                                 match.end - match.start);
 *      string += match.end;
 *    }
 *
 *    // Parse URI into its components, available in the match[] array
 *    SilcRegexStruct reg;
 *    SilcRegexMatchStruct match[7];
 *
 *    silc_regex_compile(&reg, "^(([^:]+)://)?([^:/]+)(:([0-9]+))?(/.*)", 0);
 *    silc_regex_match(&reg, "http://example.com/page.html", len, 7, match, 0);
 *
 ***/
SilcBool silc_regex_match(SilcRegex regexp, const char *string,
			  SilcUInt32 string_len, SilcUInt32 num_match,
			  SilcRegexMatch match, SilcRegexFlags flags);

/****f* silcutil/SilcRegexAPI/silc_regex_free
 *
 * SYNOPSIS
 *
 *    void silc_regex_free(SilcRegex regexp);
 *
 * DESCRIPTION
 *
 *    Free's the compiled regular expression context `regexp'.  This must
 *    be called even if `regexp' is statically allocated.  If the
 *    silc_regex_compile has been called this function must be called.
 *
 ***/
void silc_regex_free(SilcRegex regexp);

/****f* silcutil/SilcRegexAPI/silc_regex
 *
 * SYNOPSIS
 *
 *    SilcBool silc_regex(const char *string, const char *regex,
 *                        SilcBuffer match, ...);
 *
 * DESCRIPTION
 *
 *    Matches the `string' to the regular expression `regex'.  Returns TRUE
 *    if the `string' matches the regular expression or FALSE if it does not
 *    match.  The silc_errno is also set to SILC_ERR_NOT_FOUND.
 *
 *    The first (whole) match is returned to `match' buffer if it is non-NULL.
 *    The variable argument list are buffers where multiple matches are
 *    returned in case of group (parenthesized) regular expression.  The caller
 *    needs to know how many pointers to provide, in order to get all matches.
 *    If `match' is non-NULL the variable argument list must be ended with
 *    NULL.  The data in the `match' and in any other buffer is from `string'
 *    and must not be freed by the caller.
 *
 * EXAMPLE
 *
 *    // Simple match
 *    if (!silc_regex("foobar", "foo.", NULL))
 *      no_match;
 *
 *    // Get the pointer to the first match
 *    if (!silc_regex("foobar", ".bar", &match, NULL))
 *      no_match;
 *
 *    // Group match
 *    SilcBufferStruct match, sub1, sub2;
 *
 *    if (!silc_regex("Hello World", "(H..).(o..)", &match, &sub1, &sub2, NULL))
 *      no_match;
 *
 ***/
SilcBool silc_regex(const char *string, const char *regex,
		    SilcBuffer match, ...);

/****f* silcutil/SilcRegexAPI/silc_regex_buffer
 *
 * SYNOPSIS
 *
 *    SilcBool silc_regex_buffer(SilcBuffer buffer, const char *regex,
 *                               SilcBuffer match, ...);
 *
 * DESCRIPTION
 *
 *    Same as silc_regex but the string to match is in `buffer'.  Returns
 *    TRUE if the string matches and FALSE if it doesn't.  See examples and
 *    other information in silc_regex.  The `buffer' and `match' may be the
 *    same buffer.
 *
 ***/
SilcBool silc_regex_buffer(SilcBuffer buffer, const char *regex,
			   SilcBuffer match, ...);

/* Backwards support */
#define silc_string_regex_match(regex, string) silc_regex(string, regex, NULL)

#endif /* SILCREGEX_H */
