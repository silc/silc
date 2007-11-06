/*

  silchttpserver.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silchttpserver.h"

/************************** Types and definitions ***************************/

#define SILC_HTTP_SERVER_TIMEOUT  120   /* Connection timeout */
#define SILC_HTTP_SERVER_CONNS    2	/* Default number of connections */
#define SILC_HTTP_SERVER_BUFLEN   1024  /* Default data buffer length */
#define SILC_HTTP_SERVER_HEADER   "HTTP/1.1 200 OK\r\nServer: SILCHTTP/1.0\r\n"

/* HTTP server context */
struct SilcHttpServerStruct {
  SilcNetListener listener;	    /* Server listener */
  SilcSchedule schedule;	    /* Scheduler */
  SilcList allconns;		    /* All connections */
  SilcList conns;		    /* Connection free list */
  SilcHttpServerCallback callback;  /* Requset callback */
  void *context;		    /* Request callback context */
};

/* HTTP connection context */
struct SilcHttpConnectionStruct {
  struct SilcHttpConnectionStruct *next;
  struct SilcHttpConnectionStruct *next2;
  SilcHttpServer httpd;		    /* Server */
  SilcStream stream;		    /* Connection stream */
  SilcBuffer inbuf;		    /* Read data buffer */
  SilcBuffer outbuf;		    /* Write data buffer */
  SilcInt64 touched;		    /* Time last connection was touched */
  SilcMime curheaders;		    /* HTTP request headers */
  SilcMime headers;		    /* HTTP reply headers */
  unsigned char *hptr;		    /* Pointer to start of headers */
  char *method;			    /* Method */
  char *uri;			    /* URI */
  unsigned int keepalive    : 1;    /* Keep alive */
};

/************************ Static utility functions **************************/

/* Close HTTP connection */

static void silc_http_server_close_connection(SilcHttpConnection conn)
{
  if (conn->headers) {
    silc_mime_free(conn->headers);
    conn->headers = NULL;
  }
  if (conn->curheaders) {
    silc_mime_free(conn->curheaders);
    conn->curheaders = NULL;
  }
  silc_buffer_clear(conn->inbuf);
  silc_buffer_clear(conn->outbuf);
  silc_buffer_reset(conn->inbuf);
  silc_buffer_reset(conn->outbuf);
  conn->hptr = conn->method = conn->uri = NULL;

  if (conn->keepalive)
    return;

  SILC_LOG_DEBUG(("Closing HTTP connection %p", conn));

  silc_schedule_task_del_by_context(conn->httpd->schedule, conn);
  silc_stream_set_notifier(conn->stream, conn->httpd->schedule, NULL, NULL);
  silc_stream_destroy(conn->stream);
  conn->stream = NULL;

  /* Add to free list */
  silc_list_add(conn->httpd->conns, conn);
}

/* Parse HTTP data */

static SilcBool silc_http_server_parse(SilcHttpServer httpd,
				       SilcHttpConnection conn)
{
  SilcUInt32 data_len, cll;
  unsigned char *data, *tmp;
  const char *value, *cl;
  SilcBufferStruct postdata;
  int i;

  SILC_LOG_DEBUG(("Parsing HTTP data"));

  data = silc_buffer_data(conn->inbuf);
  data_len = silc_buffer_len(conn->inbuf);

  /* Check for end of headers */
  for (i = 0; i < data_len ; i++) {
    if (data_len - i >= 4 &&
	data[i    ] == '\r' && data[i + 1] == '\n' &&
	data[i + 2] == '\r' && data[i + 3] == '\n')
      break;
  }
  if (i == data_len)
    return TRUE;

  SILC_LOG_HEXDUMP(("HTTP data"), silc_buffer_data(conn->inbuf),
		   silc_buffer_len(conn->inbuf));

  if (!conn->method && !conn->uri) {
    tmp = memchr(data, '\n', data_len);
    if (!tmp || tmp[-1] != '\r') {
      if (data_len < SILC_HTTP_SERVER_BUFLEN)
	return TRUE;
      return FALSE;
    }
    *tmp = 0;

    /* Get method */
    if (strchr(data, ' '))
      *strchr(data, ' ') = 0;
    conn->method = data;
    SILC_LOG_DEBUG(("Method: '%s'", conn->method));

    /* Get URI */
    tmp = memchr(data, '\0', data_len);
    if (!tmp) {
      if (data_len < SILC_HTTP_SERVER_BUFLEN)
	return TRUE;
      return FALSE;
    }
    tmp++;
    if (strchr(tmp, ' '))
      *strchr(tmp, ' ') = 0;
    conn->uri = tmp;
    SILC_LOG_DEBUG(("URI: '%s'", conn->uri));

    /* Protocol version compatibility */
    tmp = ((unsigned char *)memchr(tmp, '\0', data_len - (tmp - data))) + 1;
    SILC_LOG_DEBUG(("Protocol: %s", tmp));
    if (strstr(tmp, "HTTP/1.0"))
      conn->keepalive = FALSE;
    if (strstr(tmp, "HTTP/1.1"))
      conn->keepalive = TRUE;
    if (strstr(tmp, "HTTP/1.2"))
      conn->keepalive = TRUE;

    /* Get HTTP headers */
    tmp = memchr(tmp, '\0', data_len - (tmp - data));
    if (!tmp) {
      if (data_len < SILC_HTTP_SERVER_BUFLEN)
	return TRUE;
      return FALSE;
    }
    if (data_len - (tmp - data) < 2) {
      if (data_len < SILC_HTTP_SERVER_BUFLEN)
	return TRUE;
      return FALSE;
    }
    conn->hptr = ++tmp;
  }

  /* Parse headers and data area */
  conn->curheaders = silc_mime_decode(NULL, conn->hptr,
				      data_len - (conn->hptr - data));
  if (!conn->curheaders)
    return FALSE;

  /* Check for persistent connection */
  value = silc_mime_get_field(conn->curheaders, "Connection");
  if (value && !strcasecmp(value, "close"))
    conn->keepalive = FALSE;

  /* Deliver request to caller */
  if (!strcasecmp(conn->method, "GET") || !strcasecmp(conn->method, "HEAD")) {
    httpd->callback(httpd, conn, conn->uri, conn->method,
		    NULL, httpd->context);

  } else if (!strcasecmp(conn->method, "POST")) {
    /* Get POST data */
    tmp = (unsigned char *)silc_mime_get_data(conn->curheaders, &data_len);
    if (!tmp)
      return FALSE;

    /* Check we have received all data */
    cl = silc_mime_get_field(conn->curheaders, "Content-Length");
    if (cl && sscanf(cl, "%lu", &cll) == 1) {
      if (data_len < cll) {
	/* More data to come */
	silc_mime_free(conn->curheaders);
	conn->curheaders = NULL;
	return TRUE;
      }
    }

    silc_buffer_set(&postdata, tmp, data_len);
    SILC_LOG_HEXDUMP(("HTTP POST data"), tmp, data_len);

    httpd->callback(httpd, conn, conn->uri, conn->method,
		    &postdata, httpd->context);
  } else {
    /* Send bad request */
    silc_http_server_send_error(httpd, conn, "400 Bad Request",
				"<body><h1>400 Bad Request</h1><body>");
    return TRUE;
  }

  return TRUE;
}

/* Send HTTP data to connection */

static SilcBool silc_http_server_send_internal(SilcHttpServer httpd,
					       SilcHttpConnection conn,
					       SilcBuffer data,
					       SilcBool headers)
{
  int ret;

  SILC_LOG_HEXDUMP(("HTTP data"), silc_buffer_data(data),
		   silc_buffer_len(data));

  /* Write the packet to the stream */
  while (silc_buffer_len(data) > 0) {
    ret = silc_stream_write(conn->stream, silc_buffer_data(data),
			    silc_buffer_len(data));
    if (ret == 0 || ret == - 2)
      return FALSE;

    if (ret == -1) {
      /* Cannot write now, write later. */
      if (silc_buffer_len(data) - ret >= silc_buffer_taillen(conn->outbuf))
	if (!silc_buffer_realloc(conn->outbuf,
				 silc_buffer_truelen(conn->outbuf) +
				 silc_buffer_len(data) - ret)) {
	  conn->keepalive = FALSE;
	  silc_http_server_close_connection(conn);
	  return FALSE;
	}
      silc_buffer_pull_tail(conn->outbuf, silc_buffer_len(data) - ret);
      silc_buffer_put(conn->outbuf, silc_buffer_data(data) + ret,
		      silc_buffer_len(data) - ret);
      return TRUE;
    }

    /* Wrote data */
    silc_buffer_pull(data, ret);
  }

  if (!headers) {
    /* Data sent, close connection */
    SILC_LOG_DEBUG(("Data sent %p", conn));
    silc_http_server_close_connection(conn);
  }

  return TRUE;
}

/* Allocate connection context */

static SilcHttpConnection silc_http_server_alloc_connection(void)
{
  SilcHttpConnection conn;

  conn = silc_calloc(1, sizeof(*conn));
  if (!conn)
    return NULL;

  conn->inbuf = silc_buffer_alloc(SILC_HTTP_SERVER_BUFLEN);
  if (!conn->inbuf) {
    silc_free(conn);
    return NULL;
  }

  conn->outbuf = silc_buffer_alloc(SILC_HTTP_SERVER_BUFLEN);
  if (!conn->outbuf) {
    silc_buffer_free(conn->inbuf);
    silc_free(conn);
    return NULL;
  }

  silc_buffer_reset(conn->inbuf);
  silc_buffer_reset(conn->outbuf);

  return conn;
}

/* Check if connection has timedout */

SILC_TASK_CALLBACK(silc_http_server_connection_timeout)
{
  SilcHttpConnection conn = context;
  SilcInt64 curtime = silc_time();

  if (curtime - conn->touched > SILC_HTTP_SERVER_TIMEOUT) {
    SILC_LOG_DEBUG(("Connection timeout %p", conn));
    conn->keepalive = FALSE;
    silc_http_server_close_connection(conn);
    return;
  }

  silc_schedule_task_add_timeout(conn->httpd->schedule,
				 silc_http_server_connection_timeout, conn,
				 SILC_HTTP_SERVER_TIMEOUT, 0);
}

/* Data I/O callback */

static void silc_http_server_io(SilcStream stream, SilcStreamStatus status,
				void *context)
{
  SilcHttpConnection conn = context;
  SilcHttpServer httpd = conn->httpd;
  int ret;

  switch (status) {
  case SILC_STREAM_CAN_READ:
    SILC_LOG_DEBUG(("Read HTTP data %p", conn));

    conn->touched = silc_time();

    /* Make sure we have fair amount of free space in inbuf */
    if (silc_buffer_taillen(conn->inbuf) < SILC_HTTP_SERVER_BUFLEN)
      if (!silc_buffer_realloc(conn->inbuf, silc_buffer_truelen(conn->inbuf) +
			       SILC_HTTP_SERVER_BUFLEN * 2)) {
	conn->keepalive = FALSE;
	silc_http_server_close_connection(conn);
	return;
      }

    /* Read data from stream */
    ret = silc_stream_read(conn->stream, conn->inbuf->tail,
			   silc_buffer_taillen(conn->inbuf));

    if (ret == 0 || ret == -2) {
      conn->keepalive = FALSE;
      silc_http_server_close_connection(conn);
      return;
    }

    if (ret == -1) {
      /* Cannot read now, do it later. */
      silc_buffer_pull(conn->inbuf, silc_buffer_len(conn->inbuf));
      return;
    }

    SILC_LOG_DEBUG(("Read %d bytes data", ret));

    /* Parse the data */
    silc_buffer_pull_tail(conn->inbuf, ret);
    if (!silc_http_server_parse(httpd, conn)) {
      conn->keepalive = FALSE;
      silc_http_server_close_connection(conn);
    }

    break;

  case SILC_STREAM_CAN_WRITE:
    SILC_LOG_DEBUG(("Write HTTP data %p", conn));

    conn->touched = silc_time();

    /* Write pending data to stream */
    while (silc_buffer_len(conn->outbuf) > 0) {
      ret = silc_stream_write(conn->stream, silc_buffer_data(conn->outbuf),
			      silc_buffer_len(conn->outbuf));

      if (ret == 0 || ret == -2) {
	conn->keepalive = FALSE;
	silc_http_server_close_connection(conn);
	return;
      }

      if (ret == -1)
	/* Cannot write now, write later. */
	return;

      /* Wrote data */
      silc_buffer_pull(conn->outbuf, ret);
    }

    /* Data sent, close connection */
    SILC_LOG_DEBUG(("Data sent"));
    silc_http_server_close_connection(conn);
    break;

  default:
    conn->keepalive = FALSE;
    silc_http_server_close_connection(conn);
    break;
  }
}

/* Accepts new connection */

static void silc_http_server_new_connection(SilcNetStatus status,
					    SilcStream stream,
					    void *context)
{
  SilcHttpServer httpd = context;
  SilcHttpConnection conn;
  const char *hostname = NULL, *ip = NULL;

  /* Get free connection */
  silc_list_start(httpd->conns);
  conn = silc_list_get(httpd->conns);
  if (!conn) {
    /* Add new connection */
    conn = silc_http_server_alloc_connection();
    if (!conn) {
      silc_stream_destroy(stream);
      return;
    }
    silc_list_add(httpd->allconns, conn);
  }
  silc_list_del(httpd->conns, conn);

  conn->httpd = httpd;
  conn->stream = stream;

  silc_socket_stream_get_info(stream, NULL, &hostname, &ip, NULL);
  SILC_LOG_INFO(("HTTPD: New connection %s (%s)", hostname, ip));
  SILC_LOG_DEBUG(("New connection %p", conn));

  /* Schedule the connection for data I/O */
  silc_stream_set_notifier(stream, httpd->schedule, silc_http_server_io, conn);

  /* Add connection timeout check */
  silc_schedule_task_add_timeout(httpd->schedule,
				 silc_http_server_connection_timeout, conn,
				 SILC_HTTP_SERVER_TIMEOUT, 0);
}


/******************************* Public API *********************************/

/* Allocate HTTP server */

SilcHttpServer silc_http_server_alloc(const char *ip, SilcUInt16 port,
				      SilcSchedule schedule,
				      SilcHttpServerCallback callback,
				      void *context)
{
  SilcHttpServer httpd;
  SilcHttpConnection conn;
  int i;

  SILC_LOG_DEBUG(("Start HTTP server at %s:%d", ip, port));

  if (!ip || !schedule || !callback)
    return FALSE;

  httpd = silc_calloc(1, sizeof(*httpd));
  if (!httpd)
    return NULL;

  /* Create server listener */
  httpd->listener =
    silc_net_tcp_create_listener(&ip, 1, port, TRUE, FALSE, schedule,
				 silc_http_server_new_connection, httpd);
  if (!httpd->listener) {
    SILC_LOG_ERROR(("Could not bind HTTP server at %s:%d", ip, port));
    silc_http_server_free(httpd);
    return NULL;
  }

  httpd->schedule = schedule;
  httpd->callback = callback;
  httpd->context = context;

  silc_list_init(httpd->conns, struct SilcHttpConnectionStruct, next);
  silc_list_init(httpd->allconns, struct SilcHttpConnectionStruct, next2);

  /* Allocate connections list */
  for (i = 0; i < SILC_HTTP_SERVER_CONNS; i++) {
    conn = silc_http_server_alloc_connection();
    if (!conn)
      break;
    silc_list_add(httpd->conns, conn);
    silc_list_add(httpd->allconns, conn);
    conn->httpd = httpd;
  }

  SILC_LOG_DEBUG(("HTTP Server started"));

  return httpd;
}

/* Free HTTP server */

void silc_http_server_free(SilcHttpServer httpd)
{
  SilcHttpConnection conn;

  silc_list_start(httpd->allconns);
  while ((conn = silc_list_get(httpd->allconns))) {
    conn->keepalive = FALSE;
    if (conn->httpd && conn->stream)
      silc_http_server_close_connection(conn);
    silc_buffer_free(conn->inbuf);
    silc_buffer_free(conn->outbuf);
    silc_free(conn);
  }

  if (httpd->listener)
    silc_net_close_listener(httpd->listener);

  silc_free(httpd);
}

/* Send HTTP data to connection */

SilcBool silc_http_server_send(SilcHttpServer httpd,
			       SilcHttpConnection conn,
			       SilcBuffer data)
{
  SilcBufferStruct h;
  unsigned char *headers, tmp[16];
  SilcUInt32 headers_len;
  SilcBool ret;

  SILC_LOG_DEBUG(("Sending HTTP data"));

  conn->touched = silc_time();

  /* Write headers */
  silc_buffer_set(&h, SILC_HTTP_SERVER_HEADER,
		  strlen(SILC_HTTP_SERVER_HEADER));
  ret = silc_http_server_send_internal(httpd, conn, &h, TRUE);
  if (!ret) {
    conn->keepalive = FALSE;
    silc_http_server_close_connection(conn);
    return FALSE;
  }

  if (!conn->headers) {
    conn->headers = silc_mime_alloc();
    if (!conn->headers) {
      conn->keepalive = FALSE;
      silc_http_server_close_connection(conn);
      return FALSE;
    }
  }

  silc_mime_add_field(conn->headers, "Last-Modified",
		      silc_time_string(conn->touched));
  silc_snprintf(tmp, sizeof(tmp), "%d", (int)silc_buffer_len(data));
  silc_mime_add_field(conn->headers, "Content-Length", tmp);
  if (conn->keepalive) {
    silc_mime_add_field(conn->headers, "Connection", "keep-alive");
    silc_snprintf(tmp, sizeof(tmp), "%d", (int)SILC_HTTP_SERVER_TIMEOUT);
    silc_mime_add_field(conn->headers, "Keep-alive", tmp);
  }

  headers = silc_mime_encode(conn->headers, &headers_len);
  if (headers) {
    silc_buffer_set(&h, headers, headers_len);
    if (!silc_http_server_send_internal(httpd, conn, &h, TRUE)) {
      conn->keepalive = FALSE;
      silc_http_server_close_connection(conn);
      return FALSE;
    }
    silc_free(headers);
  }

  /* Write the page data */
  return silc_http_server_send_internal(httpd, conn, data, FALSE);
}

/* Send error reply */

SilcBool silc_http_server_send_error(SilcHttpServer httpd,
				     SilcHttpConnection conn,
				     const char *error,
				     const char *error_message)
{
  SilcBool ret;
  SilcBufferStruct data;

  memset(&data, 0, sizeof(data));
  silc_buffer_strformat(&data,
			"HTTP/1.1 ", error, "\r\n\r\n", error_message,
			SILC_STRFMT_END);

  /* Send the message */
  ret = silc_http_server_send_internal(httpd, conn, &data, FALSE);

  silc_buffer_purge(&data);

  /* Close connection */
  conn->keepalive = FALSE;
  silc_http_server_close_connection(conn);

  return ret;
}

/* Get field */

const char *silc_http_server_get_header(SilcHttpServer httpd,
					SilcHttpConnection conn,
					const char *field)
{
  if (!conn->curheaders)
    return NULL;
  return silc_mime_get_field(conn->curheaders, field);
}

/* Add field */

SilcBool silc_http_server_add_header(SilcHttpServer httpd,
				     SilcHttpConnection conn,
				     const char *field,
				     const char *value)
{
  SILC_LOG_DEBUG(("Adding header %s:%s", field, value));

  if (!conn->headers) {
    conn->headers = silc_mime_alloc();
    if (!conn->headers) {
      silc_http_server_close_connection(conn);
      return FALSE;
    }
  }

  silc_mime_add_field(conn->headers, field, value);
  return TRUE;
}
