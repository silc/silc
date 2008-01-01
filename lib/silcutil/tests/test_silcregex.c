/* Regex tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcRegexStruct reg;
  SilcRegexMatchStruct match[10];
  int i, num_match = 10;
  char *regex, *string, *sub;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*regex*,*errno*");
  }

  regex = "(H..).(o..)";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "Hello World";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex_match(&reg, string, num_match, match, 0))
    goto err;
  for (i = 0; i < num_match; i++) {
    if (match[i].start != -1) {
      SILC_LOG_DEBUG(("Match start %d, end %d", match[i].start,
		      match[i].end));
      sub = silc_memdup(string + match[i].start, match[i].end - 
			match[i].start);
      SILC_LOG_DEBUG(("Match substring '%s'", sub));
      silc_free(sub);
    }
  }

  silc_regex_free(&reg);

  regex = "foo[0-9]*";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "foo";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex_match(&reg, string, 0, NULL, 0))
    goto err;

  string = "foo20";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex_match(&reg, string, 0, NULL, 0))
    goto err;

  string = "foo20, bar, foo100, foo";
  SILC_LOG_DEBUG(("Match all substrings in %s", string));
  while (silc_regex_match(&reg, string, 1, match, 0)) {
    SILC_LOG_DEBUG(("Match start %d", match[0].start));
    sub = silc_memdup(string + match[0].start, match[0].end - match[0].start);
    SILC_LOG_DEBUG(("Match substring '%s'", sub));
    silc_free(sub);
    string += match[0].end;
  }

  string = "foo20, bar, foo100, Foo, foo0";
  SILC_LOG_DEBUG(("Match all substrings at once in %s", string));
  if (!silc_regex_match(&reg, string, num_match, match, 0))
    goto err;

  for (i = 0; i < num_match; i++) {
    if (match[i].start != -1) {
      SILC_LOG_DEBUG(("Match start %d", match[i].start));
      sub = silc_memdup(string + match[i].start, match[i].end - 
			match[i].start);
      SILC_LOG_DEBUG(("Match substring '%s'", sub));
      silc_free(sub);
    }
  }

  silc_regex_free(&reg);

  regex = "^(([^:]+)://)?([^:/]+)(:([0-9]+))?(/.*)";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "http://silcnet.org:443/foobar/pelle.html";
  SILC_LOG_DEBUG(("Parse URI"));
  if (!silc_regex_match(&reg, string, num_match, match, 0))
    goto err;

  for (i = 0; i < num_match; i++) {
    if (match[i].start != -1) {
      SILC_LOG_DEBUG(("Match start %d", match[i].start));
      sub = silc_memdup(string + match[i].start, match[i].end - 
			match[i].start);
      SILC_LOG_DEBUG(("Match substring '%s'", sub));
      silc_free(sub);
    }
  }

  string = "http://silcnet.org/";
  SILC_LOG_DEBUG(("Parse URI"));
  if (!silc_regex_match(&reg, string, num_match, match, 0))
    goto err;

  for (i = 0; i < num_match; i++) {
    if (match[i].start != -1) {
      SILC_LOG_DEBUG(("Match start %d", match[i].start));
      sub = silc_memdup(string + match[i].start, match[i].end - 
			match[i].start);
      SILC_LOG_DEBUG(("Match substring '%s'", sub));
      silc_free(sub);
    }
  }

  silc_regex_free(&reg);

  regex = "((a)(b))";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "ab";
  SILC_LOG_DEBUG(("Match all substrings at once in %s", string));
  if (!silc_regex_match(&reg, string, num_match, match, 0))
    goto err;

  for (i = 0; i < num_match; i++) {
    if (match[i].start != -1) {
      SILC_LOG_DEBUG(("Match start %d", match[i].start));
      sub = silc_memdup(string + match[i].start, match[i].end - 
			match[i].start);
      SILC_LOG_DEBUG(("Match substring '%s'", sub));
      silc_free(sub);
    }
  }

  silc_regex_free(&reg);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}

