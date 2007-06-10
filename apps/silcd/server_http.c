/*

  server_http.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "serverincludes.h"
#include "server_internal.h"

/************************* Types and definitions ****************************/

#define HTTP_START1						\
"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\""		\
"\"http://www.w3.ohtml4/strict.dtd\">\n"			\
"<html>\n"							\
"<head>\n"							\
"<meta http-equiv=\"Content-Type\" content=\"text/html; "	\
"charset=iso-8859-1\">\n"					\
"<title>\n"

#define HTTP_START2				\
"</title>\n"					\
"</head>\n"					\
"<body>\n"

#define HTTP_END				\
"</body>\n"					\
"</html>\n"

#define HTTP_404 "404 Not Found"
#define HTTP_404_B "<body><h1>404 Not Found</h1><p>The page you are looking for cannot be located</body>"

#define STAT_OUTPUT(fmt, stat)					\
do {								\
  silc_snprintf(buf, sizeof(buf), fmt "<br>", (int)stat);	\
  silc_buffer_strformat(&page, buf, SILC_STRFMT_END);		\
} while(0)


/****************************** HTTP access *********************************/

/* HTTP server callback.  We serve pages here. */

static void silc_server_http_callback(SilcHttpServer httpd,
				      SilcHttpConnection conn,
				      const char *uri,
				      const char *method,
				      SilcBuffer data,
				      void *context)
{
  SilcServer server = context;
  SilcBufferStruct page;
  unsigned char buf[128];

  SILC_LOG_DEBUG(("HTTP callback: %s %s", method, uri));

  memset(&page, 0, sizeof(page));

  if (!strcasecmp(method, "GET")) {

    /* Index page */
    if (!strcmp(uri, "/") || !strcmp(uri, "/index.html")) {
      SILC_LOG_DEBUG(("Index"));

      silc_buffer_strformat(&page, HTTP_START1, SILC_STRFMT_END);
      silc_buffer_strformat(&page, "SILC ",
			    server->server_type == SILC_ROUTER ?
			    "Router " : "Server ", server->server_name,
			    SILC_STRFMT_END);
      silc_buffer_strformat(&page, HTTP_START2, SILC_STRFMT_END);

      silc_buffer_strformat(&page, "<h1>SILC ",
			    server->server_type == SILC_ROUTER ?
			    "Router " : "Server ", server->server_name,
			    "</h1><hr><p>",
			    SILC_STRFMT_END);

      silc_buffer_strformat(&page, "<b>Statistics:</b><p>", SILC_STRFMT_END);

      STAT_OUTPUT("Clients    : %d", server->stat.my_clients);
      STAT_OUTPUT("Servers    : %d", server->stat.my_servers);
      STAT_OUTPUT("Routers    : %d", server->stat.my_routers);
      STAT_OUTPUT("Channels   : %d", server->stat.my_channels);
      STAT_OUTPUT("Joined users   : %d", server->stat.my_chanclients);
      STAT_OUTPUT("Aways      : %d", server->stat.my_aways);
      STAT_OUTPUT("Detached clients : %d", server->stat.my_detached);
      STAT_OUTPUT("Server operators : %d", server->stat.my_server_ops);
      STAT_OUTPUT("Router operators : %d", server->stat.my_router_ops);

      silc_buffer_strformat(&page, "<p><b>Global Statistics:</b><p>",
			    SILC_STRFMT_END);
      STAT_OUTPUT("Cell clients  : %d", server->stat.cell_clients);
      STAT_OUTPUT("Cell servers  : %d", server->stat.cell_servers);
      STAT_OUTPUT("Cell channels : %d", server->stat.cell_channels);
      STAT_OUTPUT("Cell joined users : %d", server->stat.cell_chanclients);
      STAT_OUTPUT("All clients   : %d", server->stat.clients);
      STAT_OUTPUT("All servers   : %d", server->stat.servers);
      STAT_OUTPUT("All routers   : %d", server->stat.routers);
      STAT_OUTPUT("All channels  : %d", server->stat.channels);
      STAT_OUTPUT("All joined users  : %d", server->stat.chanclients);
      STAT_OUTPUT("All aways     : %d", server->stat.aways);
      STAT_OUTPUT("All detached clients : %d", server->stat.detached);
      STAT_OUTPUT("All server operators : %d", server->stat.server_ops);
      STAT_OUTPUT("All router operators : %d", server->stat.router_ops);

      silc_buffer_strformat(&page, "<p><b>Internal Statistics:</b><p>",
			    SILC_STRFMT_END);
      STAT_OUTPUT("Connection attempts : %d", server->stat.conn_attempts);
      STAT_OUTPUT("Connection failures : %d", server->stat.conn_failures);
      STAT_OUTPUT("Authentication attempts : %d", server->stat.auth_attempts);
      STAT_OUTPUT("Authentication failures : %d", server->stat.auth_failures);
      STAT_OUTPUT("Packets sent  : %d", server->stat.packets_sent);
      STAT_OUTPUT("Packets received  : %d", server->stat.packets_received);
      STAT_OUTPUT("Commands sent : %d", server->stat.commands_sent);
      STAT_OUTPUT("Commands received : %d", server->stat.commands_received);
      STAT_OUTPUT("Connections   : %d", server->stat.conn_num);

      silc_buffer_strformat(&page, HTTP_END, SILC_STRFMT_END);

      silc_http_server_send(httpd, conn, &page);
      silc_buffer_purge(&page);
      return;
    }
  }

  silc_http_server_send_error(httpd, conn, HTTP_404, HTTP_404_B);
}

void silc_server_http_init(SilcServer server)
{
  if (!server->config->httpd_ip)
    return;

  /* Allocate HTTP server */
  server->httpd = silc_http_server_alloc(server->config->httpd_ip,
					 server->config->httpd_port,
					 server->schedule,
					 silc_server_http_callback,
					 server);
}

void silc_server_http_uninit(SilcServer server)
{
  if (server->httpd)
    silc_http_server_free(server->httpd);
}
