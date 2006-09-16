/* SilcHttpServer tests */

#include "silc.h"
#include "../silchttpserver.h"

static void http_callback(SilcHttpServer httpd, SilcHttpConnection conn,
			  const char *uri, const char *method,
			  SilcBuffer data, void *context)
{
  SilcBufferStruct page;

  SILC_LOG_DEBUG(("HTTP data received, URI:%s, method:%s", uri, method));

  if (!strcasecmp(method, "GET")) {
    /* Send our default page */
    if (!strcmp(uri, "/") || !strcmp(uri, "/index.html")) {
      memset(&page, 0, sizeof(page));
      silc_buffer_strformat(&page,
			    "<html><head></head><body>",
			    silc_http_server_get_header(httpd, conn,
							"User-Agent"),
			    "<p>OUR DEFAULT PAGE IS THIS: ",
			    silc_time_string(silc_time()),
			    "<P><FORM action=\"/posttest\" method=\"post\"><P>"
			    "<LABEL>First name: </LABEL>"
			    "<INPUT type=\"text\" name=\"firstname\"><BR>"
			    "<INPUT type=\"radio\" name=\"sex\" value=\"Male\"> Male<BR>"
			    "<INPUT type=\"radio\" name=\"sex\" value=\"Female\"> Female<BR>"
			    "<INPUT type=\"submit\" value=\"Send\"> <INPUT type=\"reset\">"
			    "</P></FORM>"
			    "</body></html>",
			    SILC_STRFMT_END);
      silc_http_server_add_header(httpd, conn, "X-Date",
				  silc_time_string(silc_time()));
      silc_http_server_send(httpd, conn, &page);
      silc_buffer_purge(&page);
      return;
    }
  }

  if (!strcasecmp(method, "POST")) {
    if (strcmp(uri, "/posttest"))
      return;
    memset(&page, 0, sizeof(page));
    silc_buffer_strformat(&page,
			  "<html><head></head><body>",
			  "POST PROCESSED:",
			  silc_buffer_data(data),
			  "</body></html>",
			  SILC_STRFMT_END);
    silc_http_server_add_header(httpd, conn, "X-Date",
				silc_time_string(silc_time()));
    silc_http_server_send(httpd, conn, &page);
    silc_buffer_purge(&page);
    return;
  }

  silc_http_server_send_error(httpd, conn, "404 Not Found",
			      "<body><h1>404 Not Found: The page you are looking for cannot be located</h1></body>");
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcSchedule schedule;
  SilcHttpServer httpd;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*http*,*mime*");
  }

  signal(SIGPIPE, SIG_IGN);

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);
  if (!schedule)
    goto err;

  SILC_LOG_DEBUG(("Allocating HTTP server at 127.0.0.1:5000"));
  httpd = silc_http_server_alloc("127.0.0.1", 5000, 0, schedule,
				 http_callback, NULL);
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
