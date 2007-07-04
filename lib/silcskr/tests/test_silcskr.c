/* SILC SKR tests */

#include "silc.h"
#include "silcskr.h"

SilcBool found = TRUE;

static void skr_found(SilcSKR skr, SilcSKRFind find, SilcSKRStatus status,
		      SilcDList results, void *context)
{
  SilcSKRKey key;

  SILC_LOG_DEBUG(("Result status %d", status));
  if (status & SILC_SKR_OK) {
    SILC_LOG_DEBUG(("Found %d keys", silc_dlist_count(results)));

    while ((key = silc_dlist_get(results)) != SILC_LIST_END)
      SILC_LOG_DEBUG(("Key: %s", ((SilcPublicKey)key->key)->identifier));

    silc_dlist_uninit(results);
    found = TRUE;
  } else
    found = FALSE;
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcSchedule schedule;
  SilcSKR skr;
  SilcSKRFind find;
  SilcPublicKey pk;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*skr*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL, NULL);

  SILC_LOG_DEBUG(("Allocating SKR"));
  skr = silc_skr_alloc();
  if (!skr)
    goto err;

  SILC_LOG_DEBUG(("Adding public key to SKR"));
  pk = silc_calloc(1, sizeof(*pk));
  pk->len = 1;
  pk->pk_type = SILC_PKCS_SILC;
  pk->name = strdup("rsa");
  pk->pk = strdup("  ");
  pk->pk_len = 2;
  pk->identifier = silc_pkcs_encode_identifier("foo", "foo.com",
					       "Foo T. Bar", "foo@foo.com",
					       "ORG", "FI");
  silc_skr_add_public_key(skr, pk, 0, NULL);

  SILC_LOG_DEBUG(("Adding public key to SKR"));
  pk = silc_calloc(1, sizeof(*pk));
  pk->len = 1;
  pk->pk_type = SILC_PKCS_SILC;
  pk->name = strdup("rsa");
  pk->pk = strdup("  ");
  pk->pk_len = 2;
  pk->identifier = silc_pkcs_encode_identifier("bar", "bar.com",
					       "Bar T. Bar", "bar@foo.com",
					       "ORG", "FI");
  silc_skr_add_public_key(skr, pk, SILC_SKR_USAGE_IDENTIFICATION |
			  SILC_SKR_USAGE_AUTH, NULL);

  SILC_LOG_DEBUG(("Attempting to add key twice"));
  if (silc_skr_add_public_key(skr, pk, 0, NULL) == SILC_SKR_OK) {
    SILC_LOG_DEBUG(("Adding key twice not detected"));
    goto err;
  }

  SILC_LOG_DEBUG(("Finding public key by email"));
  find = silc_skr_find_alloc();
  silc_skr_find_set_email(find, "foo@foo.com");
  silc_skr_find(skr, schedule, find, skr_found, NULL);
  silc_skr_find_free(find);
  if (!found)
    goto err;

  SILC_LOG_DEBUG(("Finding public key by country"));
  find = silc_skr_find_alloc();
  silc_skr_find_set_country(find, "FI");
  silc_skr_find(skr, schedule, find, skr_found, NULL);
  silc_skr_find_free(find);
  if (!found)
    goto err;

  SILC_LOG_DEBUG(("Finding public key by country, ORG and hostname"));
  find = silc_skr_find_alloc();
  silc_skr_find_set_country(find, "FI");
  silc_skr_find_set_org(find, "ORG");
  silc_skr_find_set_host(find, "foo.com");
  silc_skr_find(skr, schedule, find, skr_found, NULL);
  silc_skr_find_free(find);
  if (!found)
    goto err;

  SILC_LOG_DEBUG(("Finding public key by SILC public key"));
  silc_skr_find_silc(skr, pk, skr_found, NULL);
  if (!found)
    goto err;

  SILC_LOG_DEBUG(("Finding public key by country and usage (must not find)"));
  find = silc_skr_find_alloc();
  silc_skr_find_set_country(find, "FI");
  silc_skr_find_set_usage(find, SILC_SKR_USAGE_ENC);
  silc_skr_find(skr, schedule, find, skr_found, NULL);
  silc_skr_find_free(find);
  if (found)
    goto err;

  SILC_LOG_DEBUG(("Finding public key by country and usage"));
  find = silc_skr_find_alloc();
  silc_skr_find_set_country(find, "FI");
  silc_skr_find_set_usage(find, SILC_SKR_USAGE_IDENTIFICATION);
  silc_skr_find(skr, schedule, find, skr_found, NULL);
  silc_skr_find_free(find);
  if (!found)
    goto err;

  silc_skr_free(skr);
  silc_schedule_uninit(schedule);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
