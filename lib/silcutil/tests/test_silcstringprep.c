/* Stringprep tests */

#include "silc.h"

typedef struct {
  const char *comment;
  const char *in;
  const char *out;
  int ret;
  int enc;
} test_st;

const test_st tests[] = {
  {"Prohibited *",
   "foo*", "", SILC_STRINGPREP_ERR_PROHIBITED},
  {"Prohibited ?",
   "?foo", "", SILC_STRINGPREP_ERR_PROHIBITED},
  {"Prohibited ,",
   "f,f", "", SILC_STRINGPREP_ERR_PROHIBITED},
  {"Prohibited !",
   "!", "", SILC_STRINGPREP_ERR_PROHIBITED},
  {"Prohibited @",
   "foo@faa", "", SILC_STRINGPREP_ERR_PROHIBITED},
  {"Normal casefold",
   "Foobbeli-BofJFlkJDF", "foobbeli-bofjflkjdf"},
  {"Nothing",
   "sauna.silcnet.org", "sauna.silcnet.org"},
  {"Nothing with #",
   "#silc", "#silc"},
  {"Locale test",
   "Päivää", "päivää", 0, SILC_STRING_LOCALE},
  {"Locale test2",
   "#öäöö/&#\\#(&(&#(.äöäÄÖäÄÖÄÖ^'", 
   "#öäöö/&#\\#(&(&#(.äöääöääöäö^'", 0, SILC_STRING_LOCALE},

  /* Some libidn tests */
  {"Map to nothing",
   "foo\xC2\xAD\xCD\x8F\xE1\xA0\x86\xE1\xA0\x8B"
   "bar" "\xE2\x80\x8B\xE2\x81\xA0" "baz\xEF\xB8\x80\xEF\xB8\x88"
   "\xEF\xB8\x8F\xEF\xBB\xBF", "foobarbaz"},
  {"Case folding ASCII U+0043 U+0041 U+0046 U+0045", "CAFE", "cafe"},
  {"Case folding 8bit U+00DF (german sharp s)", "\xC3\x9F", "ss"},
  {"Case folding U+0130 (turkish capital I with dot)",
   "\xC4\xB0", "i\xcc\x87"},
  {"ASCII space character U+0020", "\x20", "\x20",
   SILC_STRINGPREP_ERR_PROHIBITED},
  {"ASCII control characters U+0010 U+007F", "\x10\x7F", "\x10\x7F",
   SILC_STRINGPREP_ERR_PROHIBITED},
};

const test_st tests_norm[] = {
  {"Casefold 1",
   "Pekka Riikonen", "pekka riikonen"},
  {"Casefold 2",
   "PEKKA RIIKONEN", "pekka riikonen"},
  {"Casefold 3",
   "pekka riikonen", "pekka riikonen"},
  {"Casefold 4",
   "#ksPPPAA", "#kspppaa"},
  {"Normal casefold",
   "Foobbeli-BofJFlkJDF", "foobbeli-bofjflkjdf"},
  {"Nothing",
   "sauna.silcnet.org", "sauna.silcnet.org"},
  {"Locale test",
   "Päivää", "päivää", 0, SILC_STRING_LOCALE},
  {"Locale test2",
   "#öäöö/&#\\#(&(&#(.äöäÄÖäÄÖÄÖ^'", 
   "#öäöö/&#\\#(&(&#(.äöääöääöäö^'", 0, SILC_STRING_LOCALE},
};

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  int i, enc;
  unsigned char *out = NULL;
  SilcUInt32 out_len;
  SilcStringprepStatus ret;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_quick(TRUE);
    silc_log_set_debug_string("*stringprep*,*utf8*");
  }

  SILC_LOG_DEBUG(("--- Identifier string tests"));

  for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    SILC_LOG_DEBUG(("Test case %d", i));
    SILC_LOG_DEBUG((" %d: %s", i, tests[i].comment));
    SILC_LOG_DEBUG((" %d: in: %s", i, tests[i].in));
    SILC_LOG_DEBUG((" %d: out: %s", i, tests[i].out));
    SILC_LOG_DEBUG((" %d: ret: %d", i, tests[i].ret));

    if (!tests[i].enc)
      enc = SILC_STRING_UTF8;
    else
      enc = tests[i].enc;
    ret = silc_stringprep(tests[i].in, strlen(tests[i].in),
			  enc, SILC_IDENTIFIER_PREP, 0,
			  &out, &out_len, enc);
    if (ret != SILC_STRINGPREP_OK) {
      if (tests[i].ret != SILC_STRINGPREP_OK) {
        SILC_LOG_DEBUG((" %d: Expected ret %d", i, ret));
      } else {
        SILC_LOG_DEBUG(("%d: Error: %d", i, ret));
        goto err;
      }
    } else {
      SILC_LOG_DEBUG((" %d: prepared out: %s", i, out));
      SILC_LOG_HEXDUMP((" %d: prepared dump", i), out, out_len);
      if (memcmp(out, tests[i].out, out_len)) {
        SILC_LOG_DEBUG((" %d: Output mismatch", i));
        goto err;
      }
    }
    SILC_LOG_DEBUG((" %d: Output match", i));

    silc_free(out);
    out = NULL;
  }

  SILC_LOG_DEBUG(("--- Casefold tests"));

  for (i = 0; i < sizeof(tests_norm) / sizeof(tests_norm[0]); i++) {
    SILC_LOG_DEBUG(("Test case %d", i));
    SILC_LOG_DEBUG((" %d: %s", i, tests_norm[i].comment));
    SILC_LOG_DEBUG((" %d: in: %s", i, tests_norm[i].in));
    SILC_LOG_DEBUG((" %d: out: %s", i, tests_norm[i].out));
    SILC_LOG_DEBUG((" %d: ret: %d", i, tests_norm[i].ret));

    if (!tests_norm[i].enc)
      enc = SILC_STRING_UTF8;
    else
      enc = tests_norm[i].enc;
    ret = silc_stringprep(tests_norm[i].in, strlen(tests_norm[i].in),
			  enc, SILC_CASEFOLD_PREP, 0,
			  &out, &out_len, enc);
    if (ret != SILC_STRINGPREP_OK) {
      if (tests_norm[i].ret != SILC_STRINGPREP_OK) {
        SILC_LOG_DEBUG((" %d: Expected ret %d", i, ret));
      } else {
        SILC_LOG_DEBUG(("%d: Error: %d", i, ret));
        goto err;
      }
    } else {
      SILC_LOG_DEBUG((" %d: prepared out: %s", i, out));
      SILC_LOG_HEXDUMP((" %d: prepared dump", i), out, out_len);
      if (memcmp(out, tests_norm[i].out, out_len)) {
        SILC_LOG_DEBUG((" %d: Output mismatch", i));
        goto err;
      }
    }
    SILC_LOG_DEBUG((" %d: Output match", i));

    silc_free(out);
    out = NULL;
  }

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
