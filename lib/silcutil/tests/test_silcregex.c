/* Regex tests */

#include "silc.h"

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcRegexStruct reg;
  SilcRegexMatchStruct match[20];
  int i, num_match = 20;
  char *regex, *string, *sub;
  SilcBufferStruct bmatch;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*regex*,*errno*,*buffmt*");
  }

  string = silc_strdup("foobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/bar/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "barbar", 6))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar foobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/bar/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "barbar barbar", 13))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar foobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/bar/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "barbar foobar", 13))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar foobar\nfoobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "BARBARbar\nBARBARbar BARBARbar\nBARBARbar",
	 		  39))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar foobar\nfoobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/BARBAR/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "BARBARbar\nBARBARbar foobar\nBARBARbar",
	 		  36))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar foobar\nfoobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo//"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "bar\nbar foobar\nbar",
	 		  18))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar foobar\nfoobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/B/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "Bbar\nBbar Bbar\nBbar",
	 		  19))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar foobar\nfoobar");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/foo/B/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "Bbar\nBbar foobar\nBbar",
	 		  21))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nBfoobar foobar\nBfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "/^B/s/foo/B/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch, "foobar\nBBbar Bbar\nBBbar\nfoo",
	 		  27))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "/baz/s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nBARBARbar baz BARBARbar\nbazBARBARbar\nfoo",
	 		  47))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "/baz/s/foo/BARBAR/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nBARBARbar baz foobar\nbazBARBARbar\nfoo",
	 		  44))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "/baz/!s/foo/BARBAR/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "BARBARbar\nfoobar baz foobar\nbazfoobar\nBARBAR",
	 		  44))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "2s/foo/BARBAR/"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nBARBARbar baz foobar\nbazfoobar\nfoo",
	 		  41))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "2s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nBARBARbar baz BARBARbar\nbazfoobar\nfoo",
	 		  44))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "200s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nfoobar baz foobar\nbazfoobar\nfoo",
	 		  38))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "2!s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "BARBARbar\nfoobar baz foobar\nbazBARBARbar\nBARBAR",
	 		  47))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "/xxx/s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nfoobar baz foobar\nbazfoobar\nfoo",
	 		  38))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "!s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nfoobar baz foobar\nbazfoobar\nfoo",
	 		  38))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "$s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
			  "foobar\nfoobar baz foobar\nbazfoobar\nBARBAR",
	 		  41))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar baz foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "$!s/foo/BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
		"BARBARbar\nBARBARbar baz BARBARbar\nbazBARBARbar\nfoo",
	 		  50))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar /baz/ foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/\\//BARBAR/g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
		"foobar\nfoobar BARBARbazBARBAR foobar\nbazfoobar\nfoo",
	 		  50))
    goto err;
  silc_buffer_purge(&bmatch);

  string = silc_strdup("foobar\nfoobar /baz/ foobar\nbazfoobar\nfoo");
  SILC_LOG_DEBUG(("Replace %s", string));
  silc_buffer_set(&bmatch, string, strlen(string));
  if (!silc_subst(&bmatch, "s/\\//\\/\\//g"))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);
  if (!silc_buffer_memcmp(&bmatch,
		"foobar\nfoobar //baz// foobar\nbazfoobar\nfoo",
	 		  42))
    goto err;
  silc_buffer_purge(&bmatch);

  regex = ".{5}";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "abcdefghijklmn";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = ".....";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "abcdefghijklmn";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{0}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{0,}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "bbbb";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{0,}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaaaaaaa";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{0,0}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "a";
  SILC_LOG_DEBUG(("DO NOT Match %s", string));
  if (silc_regex(string, regex, &bmatch, NULL))
    goto err;

  regex = "^a{3}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaa";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{3}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaa";
  SILC_LOG_DEBUG(("DO NOT Match %s", string));
  if (silc_regex(string, regex, &bmatch, NULL))
    goto err;

  regex = "^a{3,5}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaa";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{3,5}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaa";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{3,5}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaaaa";
  SILC_LOG_DEBUG(("DO NOT Match %s", string));
  if (silc_regex(string, regex, &bmatch, NULL))
    goto err;

  regex = "^a{3,}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaa";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{3,}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaaaaaaaaaaa";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "^a{3,}$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aa";
  SILC_LOG_DEBUG(("DO NOT Match %s", string));
  if (silc_regex(string, regex, &bmatch, NULL))
    goto err;


  regex = "a*b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "b";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "a*b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "ab";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "a*b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaab";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);


  regex = "a+b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "ab";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "a+b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "aaaab";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "a+b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "b";
  SILC_LOG_DEBUG(("DO NOT Match %s", string));
  if (silc_regex(string, regex, &bmatch, NULL))
    goto err;


  regex = "ca?b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "cb";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "ca?b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "cab";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex(string, regex, &bmatch, NULL))
    goto err;
  silc_buffer_printf(&bmatch, TRUE);

  regex = "ca?b";
  SILC_LOG_DEBUG(("Regex %s", regex));
  string = "caab";
  SILC_LOG_DEBUG(("DO NOT Match %s", string));
  if (silc_regex(string, regex, &bmatch, NULL))
    goto err;

  regex = "(H..).(o..)";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "Hello World";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex_match(&reg, string, strlen(string), num_match, match, 0))
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
  if (!silc_regex_match(&reg, string, strlen(string), 0, NULL, 0))
    goto err;

  string = "foo20";
  SILC_LOG_DEBUG(("Match %s", string));
  if (!silc_regex_match(&reg, string, strlen(string), 0, NULL, 0))
    goto err;

  string = "foo20, bar, foo100, foo";
  SILC_LOG_DEBUG(("Match all substrings in %s", string));
  while (silc_regex_match(&reg, string, strlen(string), 1, match, 0)) {
    SILC_LOG_DEBUG(("Match start %d", match[0].start));
    sub = silc_memdup(string + match[0].start, match[0].end - match[0].start);
    SILC_LOG_DEBUG(("Match substring '%s'", sub));
    silc_free(sub);
    string += match[0].end;
  }

  string = "foo20, bar, foo100, Foo, foo0";
  SILC_LOG_DEBUG(("Match all substrings at once in %s", string));
  if (!silc_regex_match(&reg, string, strlen(string), num_match, match, 0))
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
  if (!silc_regex_match(&reg, string, strlen(string), num_match, match, 0))
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
  if (!silc_regex_match(&reg, string, strlen(string), num_match, match, 0))
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
  if (!silc_regex_match(&reg, string, strlen(string), num_match, match, 0))
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

  regex = "^a";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "a";
  SILC_LOG_DEBUG(("Test NOTBOL flag", string));
  if (silc_regex_match(&reg, string, strlen(string), 0, NULL,
		       SILC_REGEX_NOTBOL))
    goto err;
  if (silc_errno != SILC_ERR_NOT_FOUND)
    goto err;
  SILC_LOG_DEBUG(("Did not match (OK)"));

  silc_regex_free(&reg);

  regex = "a$";
  SILC_LOG_DEBUG(("Regex %s", regex));
  if (!silc_regex_compile(&reg, regex, 0))
    goto err;

  string = "a";
  SILC_LOG_DEBUG(("Test NOTEOL flag", string));
  if (silc_regex_match(&reg, string, strlen(string), 0, NULL,
		       SILC_REGEX_NOTEOL))
    goto err;
  if (silc_errno != SILC_ERR_NOT_FOUND)
    goto err;
  SILC_LOG_DEBUG(("Did not match (OK)"));

  silc_regex_free(&reg);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
