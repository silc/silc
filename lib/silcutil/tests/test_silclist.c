/* SilcList tests */

#include "silc.h"

struct foo {
  int i;
  struct foo *next;
  struct foo *prev;
};

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  SilcList list;
  struct foo *f, *f1, *f2, *f3, *f4;

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*list*");
  }

  silc_list_init_prev(list, struct foo, next, prev);
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
  f4 = silc_calloc(1, sizeof(*f4));
  if (!f4)
    goto err;
  f4->i = 4;

  SILC_LOG_DEBUG(("Add one entry"));
  silc_list_add(list, f1);
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }
  SILC_LOG_DEBUG(("Delete the entry"));
  silc_list_del(list, f1);  
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END)
    goto err;
  SILC_LOG_DEBUG(("head=%p", list.head));
  SILC_LOG_DEBUG(("Re-add the entry"));
  silc_list_add(list, f1);
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }
  SILC_LOG_DEBUG(("Delete the entry"));
  silc_list_del(list, f1);  
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END)
    goto err;

  SILC_LOG_DEBUG(("insert f4=%p at head"));
  silc_list_insert(list, NULL, f4);
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  SILC_LOG_DEBUG(("Deleting f4=%p", f4));
  silc_list_del(list, f4);

  SILC_LOG_DEBUG(("Add f1, f2, f3"));
  silc_list_add(list, f1);
  silc_list_add(list, f2);
  silc_list_add(list, f3);

  SILC_LOG_DEBUG(("f1=%p", f1));
  SILC_LOG_DEBUG(("f2=%p", f2));
  SILC_LOG_DEBUG(("f3=%p", f3));

  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  SILC_LOG_DEBUG(("insert f4=%p between f1=%p and f2=%p", f4, f1, f2));
  silc_list_insert(list, f1, f4);
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  SILC_LOG_DEBUG(("Deleting f4=%p", f4));
  silc_list_del(list, f4);

  SILC_LOG_DEBUG(("insert f4=%p between f3=%p and tail", f4, f3));
  silc_list_insert(list, f3, f4);
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  SILC_LOG_DEBUG(("Deleting f4=%p", f4));
  silc_list_del(list, f4);

  SILC_LOG_DEBUG(("insert f4=%p at head"));
  silc_list_insert(list, NULL, f4);
  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  silc_list_start(list);
  silc_list_del(list, f1);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }
  silc_list_del(list, f3);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }
  silc_list_del(list, f2);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  silc_list_add(list, f1);
  silc_list_add(list, f2);
  silc_list_add(list, f3);

  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  silc_list_del(list, f2);

  silc_list_start(list);
  while ((f = silc_list_get(list)) != SILC_LIST_END) {
    SILC_LOG_DEBUG(("entry %d, %p, next=%p, prev=%p", f->i, f, f->next, 
		   f->prev));
  }

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  return success;
}
