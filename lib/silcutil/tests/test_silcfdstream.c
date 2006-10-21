/* SILC FD Stream tests */

#include "silc.h"

SilcBool success = FALSE;
SilcSchedule schedule;
SilcStream stream;
char buf1[10240];
int buf1_len = sizeof(buf1);

static void stream_notifier(SilcStream stream, SilcStreamStatus status,
			    void *context)
{
  SILC_LOG_DEBUG(("Notifier"));

  /* XXX we probably never get here with this test program */

  silc_fsm_continue(context);
}

static void stream_notifier2(SilcStream stream, SilcStreamStatus status,
			     void *context)
{
  SILC_LOG_DEBUG(("Notifier"));

  /* XXX we probably never get here with this test program */

  silc_fsm_continue(context);
}

SILC_FSM_STATE(st_end)
{
  unlink("/tmp/test_silcfdstream");
  unlink("/tmp/test_silcfdstream_copy");
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(st_readwrite)
{
  int ret, i, k, fd1, fd2;
  char *cp;

  SILC_LOG_DEBUG(("Opening two files, one for reading, one for writing"));

  SILC_LOG_DEBUG(("Open file /tmp/test_silcfdstream for reading"));
  fd1 = silc_file_open("/tmp/test_silcfdstream", O_RDONLY);
  if (fd1 < 0) {
    SILC_LOG_DEBUG(("Error opening file"));
    goto err;
  }

  SILC_LOG_DEBUG(("Open file /tmp/test_silcfdstream_copy for writing"));
  unlink("/tmp/test_silcfdstream_copy");
  fd2 = silc_file_open("/tmp/test_silcfdstream_copy", O_CREAT | O_WRONLY);
  if (fd2 < 0) {
    SILC_LOG_DEBUG(("Error opening file"));
    goto err;
  }

  SILC_LOG_DEBUG(("Creating FD stream (two fds)"));
  stream = silc_fd_stream_create2(fd1, fd2);
  if (!stream) {
    SILC_LOG_DEBUG(("Error creating stream"));
    goto err;
  }

  silc_stream_set_notifier(stream, schedule, stream_notifier2, fsm);

  /* Stream between the fiels */
  SILC_LOG_DEBUG(("Read/write 3 bytes at a time"));
  memset(buf1, 0, sizeof(buf1));
  while ((ret = silc_stream_read(stream, buf1, 3)) > 0) {
    k = ret;
    cp = buf1;
    while (k > 0) {
      i = silc_stream_write(stream, cp, k);

      if (i == 0) {
        SILC_LOG_DEBUG(("EOF"));
        goto err;
      }

      if (i == -1) {
        SILC_LOG_DEBUG(("Would block, write later"));
        silc_fsm_next(fsm, st_end);
        return SILC_FSM_WAIT;
      }

      if (i == -2) {
        SILC_LOG_DEBUG(("Error: %s", strerror(silc_fd_stream_get_error(stream))));
        goto err;
      }

      k -= i;
      cp += i;
    }
  }

  if (ret == -1) {
    SILC_LOG_DEBUG(("Would block, read later"));
    silc_fsm_next(fsm, st_end);
    return SILC_FSM_WAIT;
  }

  if (ret == -2) {
    SILC_LOG_DEBUG(("Error: %s", strerror(silc_fd_stream_get_error(stream))));
    goto err;
  }

  if (ret == 0) {
    SILC_LOG_DEBUG(("EOF, ok"));
    success = TRUE;
    SILC_LOG_DEBUG(("Closing stream"));
    silc_stream_close(stream);
    SILC_LOG_DEBUG(("Destroying stream"));
    silc_stream_destroy(stream);
  }

  silc_fsm_next(fsm, st_end);
  return SILC_FSM_CONTINUE;

 err:
  silc_fsm_next(fsm, st_end);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(st_write)
{
  int ret, i, k;
  char *cp;

  /* Simple writing example */
  SILC_LOG_DEBUG(("Open file /tmp/test_silcfdstream for writing"));
  SILC_LOG_DEBUG(("Creating FD stream"));
  unlink("/tmp/test_silcfdstream");
  stream = silc_fd_stream_file("/tmp/test_silcfdstream", FALSE, TRUE);
  if (!stream) {
    SILC_LOG_DEBUG(("Error creating stream"));
    goto err;
  }

  silc_stream_set_notifier(stream, schedule, stream_notifier, fsm);

  memset(buf1, 0, sizeof(buf1));
  for (i = 0; i < sizeof(buf1); i++)
    buf1[i] = i;

  SILC_LOG_DEBUG(("Writing data"));
  k = buf1_len;
  cp = buf1;
  while (k > 0) {
    ret = silc_stream_write(stream, cp, k);

    if (ret == 0) {
      SILC_LOG_DEBUG(("EOF"));
      goto err;
    }

    if (ret == -1) {
      SILC_LOG_DEBUG(("Would block, write later"));
      silc_fsm_next(fsm, st_readwrite);
      return SILC_FSM_WAIT;
    }

    if (ret == -2) {
      SILC_LOG_DEBUG(("Error: %s", strerror(silc_fd_stream_get_error(stream))));
      goto err;
    }

    k -= ret;
    cp += ret;
  }

  SILC_LOG_DEBUG(("Closing stream"));
  silc_stream_close(stream);

  SILC_LOG_DEBUG(("Destroying stream"));
  silc_stream_destroy(stream);

  SILC_LOG_DEBUG(("Continue to next state"));
  silc_fsm_next(fsm, st_readwrite);
  return SILC_FSM_CONTINUE;

 err:
  silc_fsm_next(fsm, st_end);
  return SILC_FSM_CONTINUE;
}

static void fsm_dest(SilcFSM fsm, void *fsm_context, void *context)
{
  silc_fsm_free(fsm);
  silc_schedule_stop(schedule);
}

int main(int argc, char **argv)
{
  SilcFSM fsm;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*fdstream*");
  }

  SILC_LOG_DEBUG(("Allocating scheduler"));
  schedule = silc_schedule_init(0, NULL);
  if (!schedule)
    goto err;

  SILC_LOG_DEBUG(("Allocating FSM"));
  fsm = silc_fsm_alloc(NULL, fsm_dest, NULL, schedule);
  if (!fsm)
    goto err;

  silc_fsm_start(fsm, st_write);

  SILC_LOG_DEBUG(("Running scheduler"));
  silc_schedule(schedule);

  if (!success)
    goto err;

  silc_schedule_uninit(schedule);
  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
