/* SilcList tests */

#include "silcincludes.h"

struct foo {
  int i;
  struct foo *next;
};

int main(int argc, char **argv)
{
  bool success = FALSE;
  SilcList list;
  struct foo *f, *f1, *f2, *f3;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*list*");
  }

  silc_list_init(list, struct foo, next);
  f1 = silc_calloc(1, sizeof(*f1));
  if (!f1)
    goto err;
  f1->i = 1;
  f2 = silc_calloc(1, sizeof(*f2));
  if (!f2)
    goto err;
  f2->i = 2;
  f3 = silc_calloc(1, sizeof(*f3));
  if (!f3)
    goto err;
  f3->i = 3;

  silc_list_add(list, f1);
  silc_list_add(list, f2);
  silc_list_add(list, f3);

  SILC_LOG_DEBUG(("f1=%p", f1));
  SILC_LOG_DEBUG(("f2=%p", f2));
  SILC_LOG_DEBUG(("f3=%p", f3));

  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p", f->i, f, f->next));
  }

  silc_list_start(list);
  silc_list_del(list, f1);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p", f->i, f, f->next));
  }
  silc_list_del(list, f3);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p", f->i, f, f->next));
  }
  silc_list_del(list, f2);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p", f->i, f, f->next));
  }

  silc_list_add(list, f1);
  silc_list_add(list, f2);
  silc_list_add(list, f3);

  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p", f->i, f, f->next));
  }

  silc_list_del(list, f2);

  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p", f->i, f, f->next));
  }

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
