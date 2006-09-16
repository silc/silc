/*

  silchttpserver.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silchttp/SILC HTTP Server Interface
 *
 * DESCRIPTION
 *
 * Very simple HTTP server interface.  This HTTP server supports basic HTTP
 * features.  All pages on the server are dynamically created by the caller
 * of this interface.  The server does not support plugins, modules, cgi-bin,
 * server-side includes or any other special features.
 *
 ***/

#ifndef SILCHTTPSERVER_H
#define SILCHTTPSERVER_H

typedef struct SilcHttpServerStruct *SilcHttpServer;
typedef struct SilcHttpConnectionStruct *SilcHttpConnection;

/****f* silchttp/SilcHTTPServer/SilcHttpServerCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcHttpServerCallback)(SilcHttpServer httpd,
 *                                           SilcHttpConnection conn,
 *                                           const char *uri,
 *                                           const char *method,
 *                                           SilcBuffer data,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    The HTTP request callback, that is called everytime a new HTTP request
 *    comes from a HTTP client.  The `uri' is the requested URI (web page),
 *    and the `method' is the HTTP request method (GET, POST, etc.).  The
 *    `data' is non-NULL only if the `method' is POST, and it includes the
 *    the POST data.
 *
 *    The requested web page must be returned to the HTTP client from this
 *    callback by calling silc_http_server_send or error is returned by
 *    calling silc_http_server_send_error.
 *
 *    The silc_http_server_get_header may be called to find a specific
 *    HTTP header from this request.  New headers may be added to the
 *    reply by calling silc_http_server_add_header.
 *
 ***/
typedef void (*SilcHttpServerCallback)(SilcHttpServer httpd,
				       SilcHttpConnection conn,
				       const char *uri,
				       const char *method,
				       SilcBuffer data,
				       void *context);

/****f* silchttp/SilcHTTPServer/silc_http_server_alloc
 *
 * SYNOPSIS
 *
 *    SilcHttpServer
 *    silc_http_server_alloc(const char *ip, SilcUInt16 port,
 *                           SilcUInt32 max_connections,
 *                           SilcSchedule schedule,
 *                           SilcHttpServerCallback callback, void *context);
 *
 * DESCRIPTION
 *
 *    Allocates HTTP server and binds it to the IP address `ip' on the
 *    `port'.  If `max_connections' is non-zero, that many connections
 *    are allowed to the HTTP server.  The `callback' with `context' will
 *    be called everytime a new HTTP request comes to the server from
 *    a HTTP client.  In that callback the caller must then reply with
 *    the requested Web page or with an error.
 *
 ***/
SilcHttpServer silc_http_server_alloc(const char *ip, SilcUInt16 port,
				      SilcUInt32 max_connections,
				      SilcSchedule schedule,
				      SilcHttpServerCallback callback,
				      void *context);

/****f* silchttp/SilcHTTPServer/silc_http_server_free
 *
 * SYNOPSIS
 *
 *    void silc_http_server_free(SilcHttpServer httpd);
 *
 * DESCRIPTION
 *
 *    Close HTTP server and free all resources.
 *
 ***/
void silc_http_server_free(SilcHttpServer httpd);

/****f* silchttp/SilcHTTPServer/silc_http_server_free
 *
 * SYNOPSIS
 *
 *    SilcBool silc_http_server_send(SilcHttpServer httpd,
 *                                   SilcHttpConnection conn,
 *                                   SilcBuffer data);
 *
 * DESCRIPTION
 *
 *    Send the HTTP data indicated by `data' buffer into the connection
 *    indicated by `conn'.  Returns TRUE after the data is sent, and FALSE
 *    if error occurred.  Usually the `data' would be the requested web page.
 *
 ***/
SilcBool silc_http_server_send(SilcHttpServer httpd,
			       SilcHttpConnection conn,
			       SilcBuffer data);

/****f* silchttp/SilcHTTPServer/silc_http_server_free
 *
 * SYNOPSIS
 *
 *    SilcBool silc_http_server_send_error(SilcHttpServer httpd,
 *                                         SilcHttpConnection conn,
 *                                         const char *error,
 *                                         const char *error_message);
 *
 * DESCRIPTION
 *
 *    Send HTTP error back to the connection indicated by `conn'.  The
 *    `error' is one of the 4xx or 5xx errors defined by the HTTP protocol.
 *    The `error_message' is the optional error message sent to the
 *    connection.  Returns FALSE if the error could not be sent.
 *
 *    Typical errors are: 400 Bad Request
 *                        403 Forbidden
 *                        404 Not Found
 *
 * EXAMPLE
 *
 *    silc_http_server_send_error(httpd, conn, "400 Bad Request",
 *                                "<body><h1>400 Bad Request!!</h1></body>");
 *
 ***/
SilcBool silc_http_server_send_error(SilcHttpServer httpd,
				     SilcHttpConnection conn,
				     const char *error,
				     const char *error_message);

/****f* silchttp/SilcHTTPServer/silc_http_server_get_header
 *
 * SYNOPSIS
 *
 *    const char *silc_http_server_get_header(SilcHttpServer httpd,
 *                                            SilcHttpConnection conn,
 *                                            const char *field);
 *
 * DESCRIPTION
 *
 *    Finds a header field indicated by `field' from the current HTTP
 *    request sent by the HTTP client.  Returns the field value or NULL
 *    if suchs header field does not exist.
 *
 ***/
const char *silc_http_server_get_header(SilcHttpServer httpd,
					SilcHttpConnection conn,
					const char *field);

/****f* silchttp/SilcHTTPServer/silc_http_server_add_header
 *
 * SYNOPSIS
 *
 *    SilcBool silc_http_server_add_header(SilcHttpServer httpd,
 *                                         SilcHttpConnection conn,
 *                                         const char *field,
 *                                         const char *value);
 *
 * DESCRIPTION
 *
 *    Adds a new header to the HTTP headers to be sent back to the
 *    HTTP client.  This may be called to add needed headers to the
 *    HTTP reply.
 *
 * EXAMPLE
 *
 *    silc_http_server_add_header(httpd, conn, "Content-Type", "image/jpeg");
 *
 ***/
SilcBool silc_http_server_add_header(SilcHttpServer httpd,
				     SilcHttpConnection conn,
				     const char *field,
				     const char *value);

#endif /* SILCHTTPSERVER_H */
