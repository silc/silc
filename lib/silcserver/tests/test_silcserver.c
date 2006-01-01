#include "silc.h"
#include "silcserver.h"

SilcSchedule schedule;

static void running(SilcServer server, void *context)
{
  SILC_LOG_DEBUG(("***** RUNNING"));
}

static void stopped(SilcServer server, void *context)
{
  SILC_LOG_DEBUG(("***** STOPPED"));
  silc_schedule_stop(schedule);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcServer server;
  SilcServerParams params;
  SilcServerParamServerInfo info;
  SilcServerParamInterface iface;
  SilcServerParamClient client_all;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*server*,*skr*,*ske*,*connauth*,*packet*,*stream*,*net*,*pkcs*,*asn1*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);

  silc_cipher_register_default();
  silc_pkcs_register_default();
  silc_hash_register_default();
  silc_hmac_register_default();

  SILC_LOG_DEBUG(("Allocating server params context"));
  params = silc_server_params_alloc();
  if (!params)
    goto err;

  SILC_LOG_DEBUG(("Creating server params"));

  info = silc_server_params_serverinfo_alloc();
  if (!info)
    goto err;
  info->server_name = strdup("test server");

  if (!silc_load_key_pair("test.pub", "test.prv", "",
			  &info->public_key,
			  &info->private_key)) {
    if (!silc_create_key_pair("rsa", 2048, "test.pub", "test.prv", NULL, "",
			      &info->public_key,
			      &info->private_key, FALSE)) {
      goto err;
    }
  }

  iface = silc_calloc(1, sizeof(*iface));
  if (!iface)
    goto err;
  iface->ip = strdup("127.0.0.1");
  iface->port = 1334;
  silc_server_params_serverinfo_add_iface(info, iface);
  silc_server_params_set_serverinfo(params, info);

  client_all = silc_calloc(1, sizeof(*client_all));
  if (!client_all)
    goto err;
  silc_server_params_add_client(params, client_all);

  params->use_threads = TRUE;

  SILC_LOG_DEBUG(("Allocating server context"));
  server = silc_server_alloc(NULL, params, schedule);
  if (!server) {
    SILC_LOG_DEBUG(("Error allocating server"));
    goto err;
  }

  SILC_LOG_DEBUG(("Running server"));
  silc_server_run(server, running, NULL);

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  silc_server_free(server);
  silc_server_params_free(params);
  silc_schedule_uninit(schedule);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
