#include "module.h"
#include "silc-cmdqueue.h"

#include <stdarg.h>

GHashTable *cmd_queues;

void silc_queue_init(void)
{
  cmd_queues = g_hash_table_new(NULL, NULL);
}

static void cmd_list_remove_cb(char *cmd)
{
  silc_free(cmd);
}

static int cmd_queue_remove_cb(void *key, GSList *list)
{
  if ((list != NULL) && (list->next != NULL)) {
    g_slist_foreach(list, (GFunc) cmd_list_remove_cb, NULL);
    g_slist_free(list);
  }

  return TRUE;
}

void silc_queue_deinit(void)
{
  g_hash_table_foreach_remove(cmd_queues, (GHRFunc) cmd_queue_remove_cb, NULL);
  g_hash_table_destroy(cmd_queues);
}

void silc_queue_flush(SilcClientConnection conn)
{
  GSList *list = g_hash_table_lookup(cmd_queues, conn);

  if (list != NULL) {
    GSList *tmp;

    for (tmp = g_slist_next(list); tmp != NULL; tmp = g_slist_next(tmp)) 
      silc_client_command_call(silc_client, conn, tmp->data);

    g_slist_foreach(list, (GFunc) cmd_list_remove_cb, NULL);
    /* free all but the first element ... */
    g_slist_free(g_slist_remove_link(list, list));
  }
}

void silc_queue_enable(SilcClientConnection conn)
{
  GSList *list = g_hash_table_lookup(cmd_queues, conn);

  if (list == NULL)
    g_hash_table_insert(cmd_queues, conn, g_slist_alloc());
}

void silc_queue_disable(SilcClientConnection conn)
{
  GSList *list = g_hash_table_lookup(cmd_queues, conn);
 
   if (list != NULL) {
     silc_queue_flush(conn);
     g_slist_free(list);
     g_hash_table_remove(cmd_queues, conn);
   }
}

bool silc_queue_command_call(SilcClient client,
			SilcClientConnection conn,
			const char *command_line, ...)
{
  va_list ap;
  char *cmd = (char *) command_line;
  GSList *list = g_hash_table_lookup(cmd_queues, conn);
  bool need_free = FALSE;

  va_start(ap, command_line);

  if (command_line == NULL) {
    char *tmp = va_arg(ap, char *);

    need_free = TRUE;

    if (tmp == NULL) {
      va_end(ap);
      return FALSE;
    }

    cmd = g_strdup(tmp);

    for (tmp = va_arg(ap, char *); tmp != NULL; tmp = va_arg(ap, char *)) {
      char *old = cmd;

      cmd = g_strconcat(cmd, " ", tmp, NULL);
      g_free(old);
    }

  }

  va_end(ap);

  if (!silc_term_utf8()) {
    int len = silc_utf8_encoded_len(cmd, strlen(cmd), SILC_STRING_LANGUAGE);
    char *message = silc_calloc(len + 1, sizeof(*cmd));
    if (message == NULL) {

      if (need_free)
        g_free(cmd);

      g_error("file %s: line %d: assertion `message != NULL' failed.",
          	 __FILE__, __LINE__);

      return FALSE;
    }
    silc_utf8_encode(cmd, strlen(cmd), SILC_STRING_LANGUAGE,
		     message, len);

    if (need_free)
      g_free(cmd);

    need_free = TRUE;
    cmd = g_strdup(message);

    silc_free(message);
  }

  /* queueing disabled -> immediate execution */
  if (list == NULL) {
    bool result = silc_client_command_call(client, conn, cmd);

    if (need_free)
      g_free(cmd);

    return result;
  }

  g_hash_table_remove(cmd_queues, conn);
  g_hash_table_insert(cmd_queues, conn, g_slist_append(list, g_strdup(cmd)));

  if (need_free)
    g_free(cmd);

  return TRUE;
}

bool silc_queue_get_state(SilcClientConnection conn) {
  return g_hash_table_lookup(cmd_queues, conn) != NULL;
}
