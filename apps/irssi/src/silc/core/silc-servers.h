#ifndef __SILC_SERVER_H
#define __SILC_SERVER_H

#include "chat-protocols.h"
#include "servers.h"

/* returns SILC_SERVER_REC if it's SILC server, NULL if it isn't */
#define SILC_SERVER(server) \
	PROTO_CHECK_CAST(SERVER(server), SILC_SERVER_REC, chat_type, "SILC")

#define SILC_SERVER_CONNECT(conn) \
	PROTO_CHECK_CAST(SERVER_CONNECT(conn), SILC_SERVER_CONNECT_REC, \
			 chat_type, "SILC")

#define IS_SILC_SERVER(server) \
	(SILC_SERVER(server) ? TRUE : FALSE)

#define IS_SILC_SERVER_CONNECT(conn) \
	(SILC_SERVER_CONNECT(conn) ? TRUE : FALSE)

/* all strings should be either NULL or dynamically allocated */
/* address and nick are mandatory, rest are optional */
typedef struct {
#include "server-connect-rec.h"
} SILC_SERVER_CONNECT_REC;

#define STRUCT_SERVER_CONNECT_REC SILC_SERVER_CONNECT_REC
typedef struct {
#include "server-rec.h"
  /* Command sending queue */
  int cmdcount;		/* number of commands in `cmdqueue'. Can be more than
			   there actually is, to make flood control remember
			   how many messages can be sent before starting the
			   flood control */
  int cmd_last_split;	/* Last command wasn't sent entirely to server.
			   First item in `cmdqueue' should be re-sent. */
  GSList *cmdqueue;
  GTimeVal last_cmd;	/* last time command was sent to server */
  
  GSList *idles;	/* Idle queue - send these commands to server
			   if there's nothing else to do */
  
  gpointer chanqueries;
  SilcClientConnection conn;
} SILC_SERVER_REC;

SILC_SERVER_REC *silc_server_connect(SILC_SERVER_CONNECT_REC *conn);

/* Return a string of all channels in server in server->channels_join() 
   format */
char *silc_server_get_channels(SILC_SERVER_REC *server);
void silc_command_exec(SILC_SERVER_REC *server,
		       const char *command, const char *args);
void silc_server_init(void);
void silc_server_deinit(void);

#endif
