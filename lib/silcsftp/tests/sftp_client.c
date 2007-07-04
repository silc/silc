/*

  sftp_client.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* Tests:
   silc_sftp_client_start();
   silc_sftp_client_receive_process();
   silc_sftp_opendir();
   silc_sftp_readdir();
   silc_sftp_open();
   silc_sftp_read();
   silc_sftp_fstat();
   silc_sftp_lstat();
   silc_sftp_close();
*/

#include "silc.h"
#include "silcsftp.h"

typedef struct {
  SilcSchedule schedule;
  SilcStream stream;
  SilcSFTP sftp;
} *Client;

Client gclient;

char *dir;
char *file;
bool opendir;
SilcUInt64 offset;
bool success = FALSE;

static void sftp_name(SilcSFTP sftp, SilcSFTPStatus status,
		      const SilcSFTPName name, void *context);
static void sftp_handle(SilcSFTP sftp, SilcSFTPStatus status,
			SilcSFTPHandle handle, void *context);
static void sftp_data(SilcSFTP sftp, SilcSFTPStatus status,
		      const unsigned char *data, SilcUInt32 data_len,
		      void *context);
static void end_test(void);

static void sftp_status(SilcSFTP sftp, SilcSFTPStatus status,
			const char *message, const char *lang_tag,
			void *context)
{
  fprintf(stderr, "Status %d\n", status);
  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }

  success = TRUE;
  end_test();
}

static void sftp_attr(SilcSFTP sftp, SilcSFTPStatus status,
		      const SilcSFTPAttributes attrs, void *context)
{
  SilcSFTPHandle handle = (SilcSFTPHandle)context;
  int i;

  fprintf(stderr, "Status %d\n", status);
  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }


  SILC_LOG_DEBUG(("Attr.flags: %d", attrs->flags));
  SILC_LOG_DEBUG(("Attr.size: %lu", attrs->size));
  SILC_LOG_DEBUG(("Attr.uid: %d", attrs->uid));
  SILC_LOG_DEBUG(("Attr.gid: %d", attrs->gid));
  SILC_LOG_DEBUG(("Attr.permissions: %d", attrs->permissions));
  SILC_LOG_DEBUG(("Attr.atime: %d", attrs->atime));
  SILC_LOG_DEBUG(("Attr.mtime: %d", attrs->mtime));
  SILC_LOG_DEBUG(("Attr.extended count: %d", attrs->extended_count));
  for (i = 0; i < attrs->extended_count; i++) {
    SILC_LOG_HEXDUMP(("Attr.extended_type[i]:", i),
		     attrs->extended_type[i]->data,
		     silc_buffer_len(attrs->extended_type[i]));
    SILC_LOG_HEXDUMP(("Attr.extended_data[i]:", i),
		     attrs->extended_data[i]->data,
		     silc_buffer_len(attrs->extended_data[i]));
  }

  if (!file) {
    fprintf(stderr, "Closing file\n");
    silc_sftp_close(sftp, handle, sftp_status, context);
    return;
  }

  fprintf(stderr, "LStatting file %s\n", file);
  silc_sftp_lstat(sftp, file, sftp_attr, context);
  file = NULL;
}

static void sftp_data(SilcSFTP sftp, SilcSFTPStatus status,
		      const unsigned char *data, SilcUInt32 data_len,
		      void *context)
{
  SilcSFTPHandle handle = (SilcSFTPHandle)context;

  if (status != SILC_SFTP_STATUS_OK) {
    SilcSFTPAttributesStruct attrs;

    fprintf(stderr, "Status %d\n", status);

    if (status != SILC_SFTP_STATUS_EOF) {
      SILC_LOG_DEBUG(("Error status"));
      success = FALSE;
      end_test();
      return;
    }

    if (!strcmp(file, "/sftp/sftp_server.c")) {
      fprintf(stderr, "FStatting file handle %s\n", file);
      silc_sftp_fstat(sftp, handle, sftp_attr, context);
      return;
    }

    /* Open another file */
    opendir = FALSE;
    memset(&attrs, 0, sizeof(attrs));
    file = "/sftp/sftp_server.c";
    fprintf(stderr, "Opening file %s\n", file);
    offset = 0;
    silc_sftp_open(sftp, file, SILC_SFTP_FXF_READ,
		   &attrs, sftp_handle, gclient);
    return;
  }

  SILC_LOG_HEXDUMP(("data"), (unsigned char *)data, data_len);

  offset += data_len;

  /* Attempt to read more */
  fprintf(stderr, "Reading more of file %s\n", file);
  silc_sftp_read(sftp, handle, offset, 2048, sftp_data, handle);
}

static void sftp_name(SilcSFTP sftp, SilcSFTPStatus status,
		      const SilcSFTPName name, void *context)
{
  Client client = (Client)context;
  int i;

  SILC_LOG_DEBUG(("Name"));
  fprintf(stderr, "Status %d\n", status);

  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }

  fprintf(stderr, "Directory: %s\n", dir);
  for (i = 0; i < name->count; i++) {
    fprintf(stderr, "%s\n", name->long_filename[i]);
  }

  if (!strcmp(dir, "sftp")) {
    SilcSFTPAttributesStruct attrs;

    /* open */
    opendir = FALSE;
    memset(&attrs, 0, sizeof(attrs));
    file = "passwd";
    fprintf(stderr, "Opening file %s\n", file);
    offset = 0;
    silc_sftp_open(sftp, file, SILC_SFTP_FXF_READ,
		   &attrs, sftp_handle, client);
    return;
  }

  if (!strcmp(dir, "/"))
    dir = "sftp";

  fprintf(stderr, "Opening %s\n", dir);

  /* opendir */
  opendir = TRUE;
  silc_sftp_opendir(sftp, dir, sftp_handle, client);
}

static void sftp_handle(SilcSFTP sftp, SilcSFTPStatus status,
			SilcSFTPHandle handle, void *context)
{
  Client client = (Client)context;

  SILC_LOG_DEBUG(("Handle"));
  fprintf(stderr, "Status %d\n", status);
  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }

  if (opendir) {
    fprintf(stderr, "Reading %s\n", dir);
    /* Readdir */
    silc_sftp_readdir(sftp, handle, sftp_name, client);
  } else {
    fprintf(stderr, "Reading file %s\n", file);

    /* Read */
    silc_sftp_read(sftp, handle, 0, 2048, sftp_data, handle);
  }
}

static void sftp_version(SilcSFTP sftp, SilcSFTPStatus status,
			 SilcSFTPVersion version, void *context)
{
  Client client = (Client)context;
  fprintf(stderr, "Version: %d\n", (int)version);

  SILC_LOG_DEBUG(("Version"));
  fprintf(stderr, "Status %d\n", status);
  if (status != SILC_SFTP_STATUS_OK) {
    SILC_LOG_DEBUG(("Error status"));
    success = FALSE;
    end_test();
    return;
  }

  /* opendir */
  dir = "/";
  fprintf(stderr, "Opening %s\n", dir);
  opendir = TRUE;
  silc_sftp_opendir(sftp, dir, sftp_handle, client);
}

static void sftp_error(SilcSFTP sftp, SilcSFTPStatus status,
		       void *context)
{
  Client client = context;
  SILC_LOG_DEBUG(("Error %d", status));
  silc_stream_destroy(client->stream);
  success = FALSE;
  end_test();
}

static void connect_callback(SilcNetStatus status, SilcStream stream,
			     void *context)
{
  Client client = context;

  if (!stream) {
    SILC_LOG_DEBUG(("Connect error"));
    success = FALSE;
    end_test();
  }

  /* Start SFTP session */
  client->stream = stream;
  client->sftp = silc_sftp_client_start(stream, client->schedule, sftp_version,
					sftp_error, client);
  if (!client->sftp) {
    success = FALSE;
    end_test();
  }
}

int main(int argc, char **argv)
{
  Client client = silc_calloc(1, sizeof(*client));

  gclient = client;

  if (argc > 1) {
    if (!strcmp(argv[1], "-d"))
      silc_log_debug(TRUE);
    if (argc > 2 && !strcmp(argv[2], "-x"))
      silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*");
  }

  client->schedule = silc_schedule_init(0, NULL, NULL);
  if (!client->schedule)
    return -1;

  /* Connecto to server */
  silc_net_tcp_connect(NULL, "127.0.0.1", 5000, client->schedule,
		       connect_callback, client);

  silc_schedule(client->schedule);
  return 0;
}

static void end_test(void)
{
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");
  exit(success);
}
