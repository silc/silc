/* Buffer formatting tests */

#include "silc.h"

int print(SilcStack stack, SilcBuffer buf, void *value, void *context)
{
  fwrite(silc_buffer_data(buf), 1, silc_buffer_len(buf), stdout);
  if (!silc_buffer_strchr(buf, '\n', TRUE))
    printf("\n");
  fflush(stdout);
  return silc_buffer_len(buf);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  char string[1024], *astring;
  SilcBufferStruct buf;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*buf*,*regex*,*errno*");
  }

  silc_snprintf(string, sizeof(string), "This is foobar");
  silc_buffer_set(&buf, string, strlen(string));
  SILC_LOG_DEBUG(("sed 's/foo/bar/'"));
  SILC_LOG_DEBUG(("string: %s", string));
  if (silc_buffer_format(&buf,
			 SILC_STR_REGEX("foo", 0),
			   SILC_STR_STRING("bar"),
			 SILC_STR_END,
			 SILC_STR_END) < 0)
    goto err;
  SILC_LOG_DEBUG(("string: %s", silc_buffer_data(&buf)));
  if (strcmp("This is barbar", silc_buffer_data(&buf)))
    goto err;

  silc_snprintf(string, sizeof(string), "This is foobar string!!");
  astring = silc_memdup(string, strlen(string));
  silc_buffer_set(&buf, astring, strlen(astring) + 1);
  SILC_LOG_DEBUG(("sed 's/foo/barbar/g'"));
  SILC_LOG_DEBUG(("string: %s", astring));
  if (silc_buffer_format(&buf,
			 SILC_STR_REGEX("foo", SILC_STR_REGEX_ALL |
					       SILC_STR_REGEX_INCLUSIVE),
			   SILC_STR_REPLACE("barbar", 6),
			 SILC_STR_END,
			 SILC_STR_END) < 0)
    goto err;
  silc_buffer_printf(&buf, TRUE);
  if (strcmp("This is barbarbar string!!", silc_buffer_data(&buf)))
    goto err;
  silc_buffer_purge(&buf);

  silc_snprintf(string, sizeof(string), "This is foobar string foo!!");
  astring = silc_memdup(string, strlen(string));
  silc_buffer_set(&buf, astring, strlen(astring) + 1);
  SILC_LOG_DEBUG(("sed 's/foo//g'"));
  SILC_LOG_DEBUG(("string: %s", astring));
  if (silc_buffer_format(&buf,
			 SILC_STR_REGEX("foo", SILC_STR_REGEX_ALL |
					       SILC_STR_REGEX_INCLUSIVE),
			   SILC_STR_REPLACE("", 0),
			 SILC_STR_END,
			 SILC_STR_END) < 0)
    goto err;
  silc_buffer_printf(&buf, TRUE);
  if (strcmp("This is bar string !!", silc_buffer_data(&buf)))
    goto err;
  silc_buffer_purge(&buf);

  silc_snprintf(string, sizeof(string), "This is foobar\n");
  silc_buffer_set(&buf, string, strlen(string));
  SILC_LOG_DEBUG(("sed 's/\\n/\\0/'"));
  SILC_LOG_DEBUG(("string: %s", string));
  if (silc_buffer_format(&buf,
			 SILC_STR_REGEX("\n", 0),
			   SILC_STR_UINT8(0),
			 SILC_STR_END,
			 SILC_STR_END) < 0)
    goto err;
  SILC_LOG_DEBUG(("string: %s", silc_buffer_data(&buf)));
  if (strcmp("This is foobar", silc_buffer_data(&buf)))
    goto err;

  silc_snprintf(string, sizeof(string), "foo\nfoobar\nbarfoofoo\nbar\n\nfoo");
  silc_buffer_set(&buf, string, strlen(string));
  SILC_LOG_DEBUG(("sed 's/foo/bar/g'"));
  SILC_LOG_DEBUG(("string: %s", string));
  if (silc_buffer_format(&buf,
			 SILC_STR_REGEX("foo", SILC_STR_REGEX_NL |
					       SILC_STR_REGEX_ALL),
			   SILC_STR_STRING("bar"),
			 SILC_STR_END,
			 SILC_STR_END) < 0)
    goto err;
  SILC_LOG_DEBUG(("string: %s", silc_buffer_data(&buf)));
  if (strcmp("bar\nbarbar\nbarbarbar\nbar\n\nbar", silc_buffer_data(&buf)))
    goto err;

  silc_snprintf(string, sizeof(string),
	"foo\nbazfoobar\nbarfoofoo\nbar\nbaz\nbazfoo");
  silc_buffer_set(&buf, string, strlen(string));
  SILC_LOG_DEBUG(("sed '/baz/s/foo/bar/"));
  SILC_LOG_DEBUG(("string: %s", string));
  if (silc_buffer_format(&buf,
                         SILC_STR_REGEX("baz", SILC_STR_REGEX_NL),
                           SILC_STR_REGEX("foo", SILC_STR_REGEX_ALL),
                             SILC_STR_STRING("bar"),
                           SILC_STR_END,
                         SILC_STR_END, SILC_STR_END) < 0)
    goto err;
  SILC_LOG_DEBUG(("string: %s", silc_buffer_data(&buf)));
  if (strcmp("foo\nbazbarbar\nbarfoofoo\nbar\nbaz\nbazbar",
	silc_buffer_data(&buf)))
    goto err;

  silc_snprintf(string, sizeof(string),
	"foo\nbazfoobar\nbarfoofoo\nbar\nbaz\nbazfoo");
  silc_buffer_set(&buf, string, strlen(string));
  SILC_LOG_DEBUG(("sed '/baz/!s/foo/bar/"));
  SILC_LOG_DEBUG(("string: %s", string));
  if (silc_buffer_format(&buf,
                         SILC_STR_REGEX("baz", SILC_STR_REGEX_NL |
					       SILC_STR_REGEX_NOT),
                           SILC_STR_REGEX("foo", SILC_STR_REGEX_ALL),
                             SILC_STR_STRING("bar"),
                           SILC_STR_END,
                         SILC_STR_END, SILC_STR_END) < 0)
    goto err;
  SILC_LOG_DEBUG(("string: %s", silc_buffer_data(&buf)));
  if (strcmp("bar\nbazfoobar\nbarbarbar\nbar\nbaz\nbazfoo",
	silc_buffer_data(&buf)))
    goto err;

  SILC_LOG_DEBUG(("Print all lines starting with 'R'"));
  silc_snprintf(string, sizeof(string),
	"Rfoo\nbazfoobar\nRbarfoofoo\nRbar\nbaz\nRbazfoo");
  silc_buffer_set(&buf, string, strlen(string));
  SILC_LOG_DEBUG(("string: %s", string));
  if (silc_buffer_unformat(&buf,
                           SILC_STR_REGEX("^R", SILC_STR_REGEX_NL),
			     SILC_STR_FUNC(print, NULL, NULL),
                           SILC_STR_END, SILC_STR_END) < 0)
    goto err;

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
