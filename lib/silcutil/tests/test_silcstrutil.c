/* UTF-8 decoding tests */
/* Other string util tests too */

#include "silc.h"

#define utf8fail(n, data, len)			\
const unsigned char u##n[] = (data);		\
int u##n##l = len;

#define utf8failc(n)							      \
do {									      \
  if (!silc_utf8_valid(u##n, u##n##l))					      \
    SILC_LOG_DEBUG(("%d: not valid UTF-8, correctly detected, no error", n)); \
  else {								      \
    SILC_LOG_DEBUG(("%d: parser did not detect malformed UTF-8, error", n));  \
    goto err;								      \
  }									      \
} while(0)

/* UTF-8 Test vectors that MUST fail */
utf8fail(1, "\x80", 1);
utf8fail(2, "\xbf", 1);
utf8fail(3, "\xfe", 1);
utf8fail(4, "\xff", 1);
utf8fail(5, "\xfe\xfe\xff\xff", 4);
utf8fail(6, "\xc0\xa0", 2);
utf8fail(7, "\xe0\x80\xaf", 3);
utf8fail(8, "\xf0\x80\x80\xaf", 4);
utf8fail(9, "\xf8\x80\x80\x80\xaf", 5);
utf8fail(10, "\xfc\x80\x80\x80\x80\xaf", 6);
utf8fail(11, "\xc0\x80", 2);
utf8fail(12, "\xe0\x80\x80", 3);
utf8fail(13, "\xf0\x80\x80\x80", 4);
utf8fail(14, "\xf8\x80\x80\x80\x80", 5);
utf8fail(15, "\xfc\x80\x80\x80\x80\x80", 6);
utf8fail(16, "\xc1\xbf", 2);
utf8fail(17, "\xe0\x9f\xbf", 3);
utf8fail(18, "\xf0\x8f\xbf\xbf", 4);
utf8fail(19, "\xf8\x87\xbf\xbf\xbf", 5);
utf8fail(20, "\xfc\x83\xbf\xbf\xbf\xbf", 6);
utf8fail(21, "\xed\xa0\x80", 3);
utf8fail(22, "\xed\xad\xbf", 3);
utf8fail(23, "\xed\xae\x80", 3);
utf8fail(24, "\xed\xaf\xbf", 3);
utf8fail(25, "\xed\xb0\x80", 3);
utf8fail(26, "\xed\xbe\x80", 3);
utf8fail(27, "\xed\xbf\xbf", 3);
utf8fail(28, "\xfc\x20\xfd\x20", 4);
utf8fail(29, "\xf8\xf9\xfa\xfb", 4);
utf8fail(30, "\xf0\x20\xf9\x20\xfa\x20\xfb\x20", 8);

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char *s1, *s2, *s3, *s4;
  int l, opt;

  while ((opt = getopt(argc, argv, "hVd")) != EOF) {
      switch(opt) {
        case 'h':
          printf("usage: test_silcstrutil\n");
	  exit(0);
          break;
        case 'V':
          printf("Secure Internet Live Conferencing\n");
          exit(0);
          break;
        case 'd':
          silc_log_debug(TRUE);
	  silc_log_debug_hexdump(TRUE);
	  silc_log_quick(TRUE);
          if (optarg)
            silc_log_set_debug_string(optarg);
	  else
	    silc_log_set_debug_string("*strutil*");
          break;
	default:
	  exit(1);
	  break;
      }
  }

  /* Failure tests */
  utf8failc(1);  utf8failc(2);
  utf8failc(3);  utf8failc(4);
  utf8failc(5);  utf8failc(6);
  utf8failc(7);  utf8failc(8);
  utf8failc(9);  utf8failc(10);
  utf8failc(11);  utf8failc(12);
  utf8failc(13);  utf8failc(14);
  utf8failc(15);  utf8failc(16);
  utf8failc(17);  utf8failc(18);
  utf8failc(19);  utf8failc(20);
  utf8failc(21);  utf8failc(22);
  utf8failc(23);  utf8failc(24);
  utf8failc(25);  utf8failc(26);
  utf8failc(27);  utf8failc(28);
  utf8failc(29);  utf8failc(30);

  /* LDAP DN simple test */
  s1 = "#&?*Pekka, \\Riikonen, <foobar@foobar.com>\xc4\x8d\\ ";
  SILC_LOG_DEBUG(("s1 = %s", s1));

  /* To LDAP DN */
  l = silc_utf8_decoded_len(s1, strlen(s1), SILC_STRING_LDAP_DN);
  if (!l)
    goto err;
  s3 = silc_calloc(l + 1, sizeof(*s3));
  silc_utf8_decode(s1, strlen(s1), SILC_STRING_LDAP_DN, s3, l);
  SILC_LOG_DEBUG(("ldapdn = %s", s3));

  /* To UTF-8 */
  l = silc_utf8_encoded_len(s3, strlen(s3), SILC_STRING_LDAP_DN);
  if (!l)
    goto err;  
  s4 = silc_calloc(l + 1, sizeof(*s4));
  silc_utf8_encode(s3, strlen(s3), SILC_STRING_LDAP_DN, s4, l);
  SILC_LOG_DEBUG(("utf8 = %s", s4));

  if (memcmp(s4, s1, strlen(s4))) {
    SILC_LOG_DEBUG(("UTF-8 mismatch"));
    goto err;
  }
  silc_free(s3);
  silc_free(s4);

  /* UTF-8 strcasecmp test */
  SILC_LOG_DEBUG(("silc_utf8_strcasecmp test"));
  s1 = "Päivää vuan Yrjö";
  s2 = "PÄIVÄÄ VUAN YRJÖ";
  l = silc_utf8_encoded_len(s1, strlen(s1), SILC_STRING_LOCALE);
  if (!l)
    goto err;  
  s3 = silc_calloc(l + 1, sizeof(*s3));
  silc_utf8_encode(s1, strlen(s1), SILC_STRING_LOCALE, s3, l);

  l = silc_utf8_encoded_len(s2, strlen(s2), SILC_STRING_LOCALE);
  if (!l)
    goto err;  
  s4 = silc_calloc(l + 1, sizeof(*s4));
  silc_utf8_encode(s2, strlen(s2), SILC_STRING_LOCALE, s4, l);

  SILC_LOG_DEBUG(("%s == %s", s3, s4));
  if (!silc_utf8_strcasecmp(s3, s4)) {
    SILC_LOG_DEBUG(("mismatch"));
    goto err;
  }
  SILC_LOG_DEBUG(("match"));

  silc_free(s3);
  silc_free(s4);

  /* Regex test */
  SILC_LOG_DEBUG(("Simple regex test"));
  s1 = "foo,bar,silc,com";
  SILC_LOG_DEBUG(("Find 'silc' from %s", s1));
  if (!silc_string_match(s1, "silc"))
    goto err;
  SILC_LOG_DEBUG(("Regex match"));
  SILC_LOG_DEBUG(("Find 'foobar' from %s", s1));
  if (silc_string_match(s1, "foobar"))
    goto err;
  SILC_LOG_DEBUG(("Regex not found (Ok)"));

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
