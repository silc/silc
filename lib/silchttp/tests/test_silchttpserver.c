/* SilcHttpServer tests */
/* Actually this is almost a full-fledged HTTP server.  It can serve HTML
   and PHP pages pretty well.  In PHP the variables passed in URI with '?'
   work in PHP script, with this HTTPD of ours, only if $_REQUEST variable
   is used to fetch them (limitation in PHP command line version).  In other
   ways '?' in URI is not supported. */
/* Usage: ./test_silchttpserver [-d] [<htdocsdir>] */

#include "silc.h"
#include "../silchttpserver.h"
#include "../silchttpphp.h"

char *htdocs = ".";

/* Add proper content type to reply per URI */

static void http_content_type(SilcHttpServer httpd, SilcHttpConnection conn,
			      const char *uri)
{
  const char *type;

  type = silc_http_server_get_header(httpd, conn, "Content-Type");
  if (type)
    silc_http_server_add_header(httpd, conn, "Content-Type", type);
  else if (strstr(uri, ".jpg"))
    silc_http_server_add_header(httpd, conn, "Content-Type", "image/jpeg");
  else if (strstr(uri, ".gif"))
    silc_http_server_add_header(httpd, conn, "Content-Type", "image/gif");
  else if (strstr(uri, ".png"))
    silc_http_server_add_header(httpd, conn, "Content-Type", "image/png");
  else if (strstr(uri, ".css"))
    silc_http_server_add_header(httpd, conn, "Content-Type", "text/css");
  else if (strstr(uri, ".htm"))
    silc_http_server_add_header(httpd, conn, "Content-Type", "text/html");
  else if (strstr(uri, ".php"))
    silc_http_server_add_header(httpd, conn, "Content-Type", "text/html");
}

/* Serve pages */

static void http_callback_file(SilcHttpServer httpd, SilcHttpConnection conn,
			       const char *uri, const char *method,
			       SilcBuffer data, void *context)
{
  SilcBufferStruct page;
  SilcBuffer php;
  char *filedata, filename[256];
  SilcUInt32 data_len;
  SilcBool usephp = FALSE;

  if (!strcasecmp(method, "GET")) {
    if (strstr(uri, ".php"))
      usephp = TRUE;

    if (!strcmp(uri, "/"))
      snprintf(filename, sizeof(filename), "%s/index.html", htdocs);
    else
      snprintf(filename, sizeof(filename), "%s%s", htdocs, uri);

    if (strchr(filename, '?'))
      *strchr(filename, '?') = ' ';
    while (strchr(filename, '&'))
      *strchr(filename, '&') = ' ';

    SILC_LOG_DEBUG(("Filename: '%s'", filename));

    if (!usephp) {
      filedata = silc_file_readfile(filename, &data_len);
      if (!filedata) {
	silc_http_server_send_error(httpd, conn, "404 Not Found",
				    "<body><h1>404 Not Found</h1><p>The page you are looking for cannot be located</body>");
	return;
      }

      http_content_type(httpd, conn, uri);

      /* Send page */
      silc_buffer_set(&page, filedata, data_len);
      silc_http_server_send(httpd, conn, &page);
      silc_buffer_purge(&page);
    } else {
      php = silc_http_php_file(filename);
      if (!php) {
	silc_http_server_send_error(httpd, conn, "404 Not Found",
				    "<body><h1>404 Not Found</h1><p>The page you are looking for cannot be located</body>");
	return;
      }

      http_content_type(httpd, conn, uri);

      /* Send page */
      silc_http_server_send(httpd, conn, php);
      silc_buffer_free(php);
    }

    return;
  }

  silc_http_server_send_error(httpd, conn, "404 Not Found",
			      "<body><h1>404 Not Found</h1><p>The page you are looking for cannot be located</body>");
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcSchedule schedule;
  SilcHttpServer httpd;

  if (argc > 1) {
    if (!strcmp(argv[1], "-d")) {
      silc_log_debug(TRUE);
      silc_log_debug_hexdump(TRUE);
      silc_log_set_debug_string("*http*,*mime*");
      if (argc > 2)
	htdocs = argv[2];
    } else {
      htdocs = argv[1];
    }
  }

  signal(SIGPIPE, SIG_IGN);

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);
  if (!schedule)
    goto err;

  SILC_LOG_DEBUG(("Allocating HTTP server at 127.0.0.1:5000"));
  httpd = silc_http_server_alloc("127.0.0.1", 5000, schedule,
				 http_callback_file, NULL);
  if (!httpd)
    goto err;

  silc_schedule(schedule);

  silc_schedule_uninit(schedule);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
