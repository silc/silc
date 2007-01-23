/* SILC Net API tests */

#include "silc.h"

SilcSchedule schedule;

typedef struct {
  SilcFSM fsm;
  SilcFSMEventStruct sema;
  SilcFSMThreadStruct thread;
  SilcNetListener server;
  SilcStream client_stream;
  SilcNetStatus client_status;
  SilcStream server_stream;
  SilcNetStatus server_status;
  SilcBool success;
} *Foo;

SILC_FSM_STATE(test_st_start);
SILC_FSM_STATE(test_st_second);
SILC_FSM_STATE(test_st_finish);

SILC_FSM_STATE(test_st_connect);
SILC_FSM_STATE(test_st_connected);

static void test_accept_connection(SilcNetStatus status, SilcStream stream,
				   void *context)
{
  Foo f = context;
  SILC_LOG_DEBUG(("Accepted new connection"));
  f->client_status = status;
  f->client_stream = stream;
  SILC_FSM_EVENT_SIGNAL(&f->sema);
}

static void test_connected(SilcNetStatus status, SilcStream stream,
			   void *context)
{
  Foo f = context;
  SILC_LOG_DEBUG(("Connected to server"));
  f->server_status = status;
  f->server_stream = stream;
  SILC_FSM_CALL_CONTINUE(&f->thread);
}

SILC_FSM_STATE(test_st_connect)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_st_connect"));
  SILC_LOG_DEBUG(("Connecting to server"));

  silc_fsm_next(fsm, test_st_connected);
  SILC_FSM_CALL(silc_net_tcp_connect(NULL, "localhost", 5000,
				     silc_fsm_get_schedule(fsm),
				     test_connected, f));
}

SILC_FSM_STATE(test_st_connected)
{
  Foo f = fsm_context;
  const char *host, *ip;
  SilcUInt16 port;

  SILC_LOG_DEBUG(("test_st_connected"));

  if (f->server_status != SILC_NET_OK) {
    SILC_LOG_DEBUG(("Creating connection failed"));
    return SILC_FSM_FINISH;
  }

  silc_socket_stream_get_info(f->server_stream, NULL, &host, &ip, &port);
  SILC_LOG_DEBUG(("Connected to server %s, %s:%d", host, ip, port));

  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(test_st_start)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_st_start"));

  SILC_LOG_DEBUG(("Creating network listener"));
  f->server = silc_net_tcp_create_listener(NULL, 0, 5000, TRUE, TRUE,
				     silc_fsm_get_schedule(fsm),
				     test_accept_connection, f);
  if (!f->server) {
    /** Creating network listener failed */
    SILC_LOG_DEBUG(("Listener creation failed"));
    silc_fsm_next(fsm, test_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /* Create thread to connect to the listener */
  silc_fsm_thread_init(&f->thread, fsm, f, NULL, NULL, FALSE);
  silc_fsm_start(&f->thread, test_st_connect);

  /** Start waiting connection */
  SILC_LOG_DEBUG(("Start waiting for incoming connections"));
  silc_fsm_event_init(&f->sema, fsm);
  silc_fsm_next(fsm, test_st_second);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(test_st_second)
{
  Foo f = fsm_context;
  const char *ip, *host;
  SilcUInt16 port;

  SILC_LOG_DEBUG(("test_st_second"));

  SILC_FSM_EVENT_WAIT(&f->sema);

  if (f->client_status != SILC_NET_OK) {
    /** Accepting new connection failed */
    SILC_LOG_DEBUG(("Accepting failed %d", f->client_status));
    silc_fsm_next(fsm, test_st_finish);
    return SILC_FSM_CONTINUE;
  }

  silc_socket_stream_get_info(f->client_stream, NULL, &host, &ip, &port);
  SILC_LOG_DEBUG(("Accepted new connection %s, %s:%d", host, ip, port));

  /** Wait thread to terminate */
  f->success = TRUE;
  silc_fsm_next(fsm, test_st_finish);
  SILC_FSM_THREAD_WAIT(&f->thread);
}

SILC_FSM_STATE(test_st_finish)
{
  Foo f = fsm_context;

  SILC_LOG_DEBUG(("test_st_finish"));

  if (f->server_stream) {
    silc_stream_close(f->server_stream);
    silc_stream_destroy(f->server_stream);
  }
  if (f->client_stream) {
    silc_stream_close(f->client_stream);
    silc_stream_destroy(f->client_stream);
  }

  SILC_LOG_DEBUG(("Closing network listener"));
  silc_net_close_listener(f->server);

  SILC_LOG_DEBUG(("Finish machine"));
  return SILC_FSM_FINISH;
}

static void destructor(SilcFSM fsm, void *fsm_context,
		       void *destructor_context)
{
  SILC_LOG_DEBUG(("FSM destructor, stopping scheduler"));
  silc_fsm_free(fsm);
  silc_schedule_stop(schedule);
}

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcFSM fsm;
  Foo f;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*net*,*stream*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);

  f = silc_calloc(1, sizeof(*f));
  if (!f)
    goto err;

  SILC_LOG_DEBUG(("Allocating FSM context"));
  fsm = silc_fsm_alloc(f, destructor, NULL, schedule);
  if (!fsm)
    goto err;
  silc_fsm_start(fsm, test_st_start);
  f->fsm = fsm;

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  if (!f->success)
    goto err;

  silc_schedule_uninit(schedule);
  silc_free(f);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
